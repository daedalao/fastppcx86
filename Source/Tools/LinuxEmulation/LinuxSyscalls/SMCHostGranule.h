// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC/mtrack on a host page larger than the guest page   (64K port, stage S4c)
//
// mtrack write-protects the guest pages a block was compiled from and
// invalidates on the resulting write fault.  Every one of those protections is
// a host `mprotect`, so its quantum is the HOST page, not the guest's 4K.  On
// a 64K kernel one granule is 16 guest pages, and that changes the correctness
// argument:
//
//   *** Whatever range you unprotect, you must invalidate or re-arm every  ***
//   *** TRACKED guest page inside it.                                      ***
//
// Unprotecting a granule to service one 4K fault and leaving the 15 sibling
// pages' blocks live with their protection gone is silent SMC breakage: the
// guest can rewrite a sibling's code with no fault and no invalidation.
//
// This header is the whole of the extra bookkeeping.  It is deliberately
// self-contained inside the SMC subsystem: the granule *table* that the rest of
// the port needs (per-guest-page intended protection, per-granule materialised
// protection -- design Part 2 section 2) belongs to VMATracking and is owned by
// another writer.  See "HOOK WANTED" at the bottom for the one thing this code
// needs from it.
//
// 4K HOSTS
// --------
// Everything here is a no-op when FEXCore::HostPage::MatchesGuest():
//   * Cover() is the identity, so every mprotect keeps its exact old range,
//   * SiblingPolicy() is forced to Invalidate, whose granule == the guest page,
//   * the table is never written (Enabled() is false), so no map, no mutex and
//     no clock_gettime appear on the fault path.
// The 4K behaviour of the SMC subsystem is therefore byte-identical.
//
// SIGNAL SAFETY
// -------------
// NoteFault()/QueueRearm() run inside the SIGSEGV handler. The one signal that
// reaches them is a synchronous store fault raised by JIT'd guest code, which
// cannot interrupt host code holding this table's leaf mutex (NoteArmed and
// the S4b queries run under VMATracking, a signal-deferring section; the
// compile-side ValidateOnly() reads run inside CompileBlock, host code).  They never log and
// never allocate: NoteFault is a hash lookup plus scalar updates on an entry
// that arming already inserted, and the flip-rate *report* is a two-word
// mailbox that the non-signal mark path drains and prints.  QueueRearm inserts
// into a map, which is exactly what the established MarkSMCLazyDirtyPage does
// from the same handler, and it only runs under the opt-in Rearm policy.
// ===========================================================================

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>

#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/TypeDefines.h>

namespace FEX::HLE::SMCGranule {

// FEX_SMCGRANULEMIXED's default (flips per second; 0 = off). See the block
// comment above MixedFlipThreshold() and the 2026-09-14 smoke numbers in
// docs/PAGE_SIZE_64K_EXECUTION.md for why it sits where it does.
// Default OFF (0) since the 2026-09-14 frame-log A/B: on RimWorld's quicktest
// map, demoting the thrashing granules halved in-world fps (p50 4.2 -> 8.5 ms,
// 160-186 -> 100 fps, 2 laps each, counterbalanced). The per-instruction
// validation on the demoted code pages costs the main thread more than the
// fault storms it removes, which land mostly on worker threads. The 20 s
// perf-stat windows had pointed the other way ("2x instructions retired at
// higher IPC"): that was the guards themselves. Opt in with
// FEX_SMCGRANULEMIXED=<flips per second>.
inline constexpr uint32_t kMixedFlipThresholdDefault = 0;

// Guest pages per host granule: 1 on a 4K host, 16 on a 64K host.
[[nodiscard]]
inline size_t PagesPerGranule() {
  return FEXCore::HostPage::Size() >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
}

// True when a granule is more than one guest page, i.e. when any of this
// header's bookkeeping can possibly matter.
[[nodiscard]]
inline bool Enabled() {
  return !FEXCore::HostPage::MatchesGuest();
}

[[nodiscard]]
inline uint64_t Base(uint64_t Addr) {
  return FEXCore::HostPage::AlignDown(Addr);
}

// Bit index of a guest page within its granule.  Always 0 on a 4K host.
[[nodiscard]]
inline uint32_t PageBit(uint64_t Addr) {
  return static_cast<uint32_t>((Addr - Base(Addr)) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
}

struct Range {
  uint64_t Start;
  uint64_t Length;
};

// The host-granular cover of [Start, Start+Length).  THE one function every
// mtrack mprotect argument goes through.  Identity on a 4K host, so the
// short-circuit keeps the common build free of the two extra ALU ops and, more
// importantly, makes "did this change 4K behaviour?" answerable by inspection.
[[nodiscard]]
inline Range Cover(uint64_t Start, uint64_t Length) {
  if (!Enabled()) {
    return {Start, Length};
  }
  const uint64_t CoverBase = FEXCore::HostPage::AlignDown(Start);
  return {CoverBase, FEXCore::HostPage::AlignUp(Start + Length) - CoverBase};
}

// ---------------------------------------------------------------------------
// FEX_SMCGRANULEPOLICY -- what happens to the TRACKED SIBLINGS of a faulting
// guest page, i.e. the other 15 pages of the granule the fault forced open.
//
//   invalidate  (default)  The range handed to the invalidator is widened from
//                          the faulting guest page to the whole granule, so
//                          every block compiled from any page in it dies in the
//                          same exclusive CodeInvalidationMutex acquisition
//                          that was already being paid for.  Sound by
//                          construction and free of any new state: the
//                          invalidator's after_callback is the unprotect, so
//                          the "unprotect" and the "invalidate" ranges are
//                          literally the same argument.  Costs a recompile of
//                          the siblings -- or, with FEX_SMCSOFTINVALIDATE on,
//                          only a hash-validated relink for the siblings whose
//                          bytes did not actually change, which is why the
//                          soft path is preferred where it is available.
//
//   rearm                  Only the faulting guest page is invalidated now;
//                          the granule (which the kernel forced open anyway) is
//                          queued and soft-invalidated wholesale at the next
//                          SMC drain point -- syscall entry, guest signal
//                          delivery, or CompileBlock.  The soft invalidation
//                          erases the granule's pages from
//                          GuestToHostMap::CodePages, so the next compile or
//                          relink on any of them re-arms the protection through
//                          MarkGuestExecutableRange; that is the "re-arm after
//                          the write window" of the design, using the existing
//                          re-arm mechanism rather than a second one.
//
//                          *** UNSOUND BY CONSTRUCTION, exactly as
//                          FEX_SMCLAZYINVAL is: between the fault and the drain
//                          a sibling code page is live, unprotected and
//                          possibly stale. ***  It exists so the mixed
//                          code/data granule thrash that `invalidate` will show
//                          on Mono and on Wine PE sections can be measured
//                          against something.  Off by default, and forced off
//                          on a 4K host where it would be meaningless (a
//                          granule has no siblings there).
// ---------------------------------------------------------------------------
enum class SiblingPolicy {
  Invalidate,
  Rearm,
};

[[nodiscard]]
inline SiblingPolicy Policy() {
  static const SiblingPolicy Selected = [] {
    if (!Enabled()) {
      // No siblings exist; the two policies are the same thing. Pin the one
      // that is byte-identical to the pre-64K code.
      return SiblingPolicy::Invalidate;
    }
    const char* Env = ::getenv("FEX_SMCGRANULEPOLICY");
    if (Env && std::strcmp(Env, "rearm") == 0) {
      return SiblingPolicy::Rearm;
    }
    return SiblingPolicy::Invalidate;
  }();
  return Selected;
}

// FEX_SMCGRANULEFLIPLOG: faults per granule per second above which one
// rate-limited line is logged from the NEXT non-signal mtrack mark. 0 disables.
// Default 64: a granule flipping more often than that is a mixed code/data
// granule where mtrack is paying 16x for nothing, which is precisely the signal
// a later arming heuristic wants.
[[nodiscard]]
inline uint32_t FlipLogThreshold() {
  static const uint32_t Threshold = [] {
    const char* Env = ::getenv("FEX_SMCGRANULEFLIPLOG");
    return Env ? static_cast<uint32_t>(::strtoul(Env, nullptr, 0)) : 64u;
  }();
  return Threshold;
}

// ---------------------------------------------------------------------------
// FEX_SMCGRANULEMIXED -- the arming heuristic for MIXED code/data granules
// (execution plan open item 2, design Part 2 section 5's "anything clever").
//
// The shape it answers, measured on RimWorld (Mono) under mtrack on the 64K
// kernel, 2026-09-14: 170 granules flipping >= 64 times a second, 101 of them
// with exactly ONE of their 16 guest pages holding code and the other 15 being
// data the game writes constantly. Every flip is a granule-wide unprotect, an
// InvalidateCodeRangeIfNecessary across every thread, and a re-arm at the next
// compile; on a 4K host that granule would never flip at all, because the
// protection quantum would be the one code page.
//
// The heuristic: a granule that reaches N faults inside one window while
// holding at most M tracked pages is DEMOTED -- mtrack stops arming it for the
// rest of the granule's life (until the guest retires the whole granule, see
// Forget), and every block compiled from any of its guest pages from then on
// carries the per-instruction ValidateCode guard that SMCCHECKS=full wraps
// around every instruction (Core.cpp, Block.ForceFullSMCDetection's path).
// The guard compares the instruction's bytes against the snapshot the decoder
// consumed before the instruction runs and exits to recompile on a mismatch,
// so a demoted page is exactly as sound as SMCCHECKS=full is, which is the
// correctness fallback the design names -- applied to the pages that need it
// instead of to the whole process.
//
// SOUNDNESS ARGUMENT, in full, because the rule is non-negotiable:
//   invariant  an UNGUARDED block may be live on guest page P only while P's
//              granule is armed (write -> fault -> that block is invalidated).
//   demotion   happens inside NoteFault, i.e. on a fault whose service already
//              unprotects the granule AND invalidates every block on it (the
//              default policy; the handler forces the granule-wide
//              invalidation on the demoting fault under `rearm` and bypasses
//              FEX_SMCLAZYINVAL's deferral for it). That invalidation takes the
//              exclusive CodeInvalidationMutex, so it orders after every
//              compile that read "not demoted" (they run under the shared
//              lock and publish inside it) and kills the unguarded blocks they
//              published; every compile ordered after it reads "demoted" and
//              emits guards.
//   the three  fresh compile: Core.cpp asks GuestCodePageValidateOnly for
//   publishers every CodePage of the decode and guards the whole block if any
//              says yes. Soft relink (TryRelinkSoftInvalidatedBlock): a
//              retained block was compiled unguarded, so a retained block on a
//              demoted page is refused and recompiled. Code cache load: a
//              section whose code-page table touches a demoted granule is
//              rejected before any of its blocks is registered.
//   the arm    MarkGuestExecutableRange skips the mprotect for a page whose
//              granule is demoted, and never calls NoteArmed for it, so the
//              S4b table's Armed() stays false and its union keeps PROT_WRITE
//              (the granule IS writable, and must stay so).
//   NewPage    MarkGuestExecutableRange only runs for the first block on a
//   gating     page since its last invalidation, so a granule must not lose
//              its demoted bit while blocks may still be live on it: Forget
//              keeps a demoted entry when the retired range covers the granule
//              only partially, and drops it only when the whole granule goes
//              (whose munmap/mmap-over invalidation makes every page in it
//              NewPage again).
//
// Off means the pre-heuristic behaviour, byte for byte. Meaningless (and
// forced off) on a 4K host, where a granule is one page and has no siblings.
// ---------------------------------------------------------------------------

// FEX_SMCGRANULEMIXED: faults per granule per second at which a mixed granule is
// demoted. 0 disables the heuristic.
[[nodiscard]]
inline uint32_t MixedFlipThreshold() {
  static const uint32_t Threshold = [] {
    if (!Enabled()) {
      return 0u;
    }
    const char* Env = ::getenv("FEX_SMCGRANULEMIXED");
    return Env ? static_cast<uint32_t>(::strtoul(Env, nullptr, 0)) : kMixedFlipThresholdDefault;
  }();
  return Threshold;
}

// FEX_SMCGRANULEMIXEDMAXTRACKED: a granule with more tracked pages than this is
// never demoted however often it flips -- it is code, and per-instruction
// validation on all of it would cost more than the flips do. Default 4 of 16.
[[nodiscard]]
inline uint32_t MixedMaxTracked() {
  static const uint32_t Max = [] {
    const char* Env = ::getenv("FEX_SMCGRANULEMIXEDMAXTRACKED");
    return Env ? static_cast<uint32_t>(::strtoul(Env, nullptr, 0)) : 4u;
  }();
  return Max;
}

// ---------------------------------------------------------------------------
// The per-granule tracked-page table.
//
// Observability and policy input for the `invalidate`/`rearm` policies, whose
// correctness does NOT depend on it: the range they hand the invalidator IS the
// range they unprotect, whatever this table says. What the table adds is the
// per-granule tracked COUNT (how many of the 16 guest pages mtrack actually
// armed, i.e. how much of the granule is really code) and the flip rate --
// the two inputs of the FEX_SMCGRANULEMIXED demotion above, whose ValidateOnly
// bit IS correctness-bearing: it is what tells the compile paths to guard.
//
// LOCK ORDER: Mutex is a LEAF. It is taken only around scalar updates to one
// entry and is never held across any other lock, any syscall, or any callback.
// Nothing in FEX takes it, so it cannot participate in an inversion with
// VMATracking.Mutex, CodeInvalidationMutex or ThreadCreationMutex.
// ---------------------------------------------------------------------------
class GranuleTable final {
public:
  struct Entry {
    uint32_t TrackedMask {}; // bit i: guest page i of this granule is mtrack-armed
    uint32_t Flips {};       // faults serviced in the window starting at WindowStart
    uint64_t WindowStart {}; // CLOCK_MONOTONIC_COARSE nanoseconds
    bool ValidateOnly {};    // demoted by FEX_SMCGRANULEMIXED: never armed again, blocks on it carry ValidateCode guards
  };

  // Arming. NOT a signal path (MarkGuestExecutableRange, holding VMATracking
  // shared), so allocation is fine.
  void NoteArmed(uint64_t GranuleBase, uint32_t PageMask) {
    if (!Enabled() || PageMask == 0) {
      return;
    }
    std::lock_guard lk {Mutex};
    auto& Entry = Granules[GranuleBase];
    if (Entry.ValidateOnly) {
      // The mark path does not arm a demoted granule, so this is unreachable
      // in practice; keep the mask at zero regardless so Armed() can never
      // make the S4b table hold PROT_WRITE back from a granule nobody protects.
      return;
    }
    Entry.TrackedMask |= PageMask;
  }

  // A write fault forced this granule open. Returns the tracked mask as it was
  // and clears it: the protection is gone from the whole granule, so no page in
  // it is armed any more until MarkGuestExecutableRange re-installs it.
  //
  // SIGNAL PATH. No allocation (the entry was inserted by arming; a fault on a
  // granule with no entry simply finds nothing), no logging -- a flip rate over
  // the threshold is parked in the one-slot mailbox for the mark path to print.
  //
  // *Demoted is set when THIS fault tripped FEX_SMCGRANULEMIXED: the granule is
  // now ValidateOnly and the caller must make sure every block on it is
  // invalidated by the service of this fault (see the soundness argument
  // above MixedFlipThreshold).
  uint32_t NoteFault(uint64_t GranuleBase, bool* Demoted) {
    *Demoted = false;
    if (!Enabled()) {
      return 0;
    }
    uint32_t ReportFlips = 0;
    bool ReportDemoted = false;
    uint32_t Mask = 0;
    {
      std::lock_guard lk {Mutex};
      auto It = Granules.find(GranuleBase);
      if (It == Granules.end()) {
        return 0;
      }
      Mask = It->second.TrackedMask;
      It->second.TrackedMask = 0;

      if (FlipLogThreshold() != 0 || MixedFlipThreshold() != 0) {
        const uint64_t Now = CoarseNanoseconds();
        if (Now - It->second.WindowStart >= 1'000'000'000ull) {
          It->second.WindowStart = Now;
          It->second.Flips = 1;
        } else {
          ++It->second.Flips;
        }
        if (FlipLogThreshold() != 0 && It->second.Flips == FlipLogThreshold()) {
          ReportFlips = It->second.Flips;
        }
        // Demotion: N flips in the window, and few enough tracked pages that
        // guarding them beats protecting the granule. A granule whose mask is
        // already empty at this fault (a fault that raced the arm) carries no
        // tracked count to judge by; it is judged on the next one.
        if (MixedFlipThreshold() != 0 && !It->second.ValidateOnly && It->second.Flips >= MixedFlipThreshold() && Mask != 0 &&
            static_cast<uint32_t>(__builtin_popcount(Mask)) <= MixedMaxTracked()) {
          It->second.ValidateOnly = true;
          *Demoted = true;
          ReportDemoted = true;
          ReportFlips = It->second.Flips;
        }
      }
    }
    if (ReportFlips) {
      // Single-slot mailbox: a second hot granule in the same window simply
      // overwrites the first. Losing a report is free; blocking or allocating
      // in a SIGSEGV handler is not.
      // The tracked count travels with the report: the mask was just cleared
      // above, so the mark path cannot read it back from the table.
      PendingReportFlips.store(ReportFlips, std::memory_order_relaxed);
      PendingReportTracked.store(static_cast<uint32_t>(__builtin_popcount(Mask)), std::memory_order_relaxed);
      PendingReportDemoted.store(ReportDemoted ? 1u : 0u, std::memory_order_relaxed);
      PendingReportGranule.store(GranuleBase | 1, std::memory_order_release);
    }
    if (*Demoted) {
      DemotedCount.fetch_add(1, std::memory_order_relaxed);
    }
    return Mask;
  }

  // FEX_SMCGRANULEMIXED: has this granule been demoted, i.e. must every block
  // compiled from any of its guest pages carry per-instruction validation, and
  // must the arm path leave it alone. Read by the compile, relink and cache
  // load paths (all under CodeInvalidationMutex shared -- host code, where no
  // guest store fault can interrupt the holder of this leaf mutex) and by the
  // mark path.
  [[nodiscard]]
  bool ValidateOnly(uint64_t GranuleBase) {
    if (!Enabled() || DemotedCount.load(std::memory_order_relaxed) == 0) {
      // The common case for every run that never demotes: one relaxed load,
      // no lock, no lookup.
      return false;
    }
    std::lock_guard lk {Mutex};
    auto It = Granules.find(GranuleBase);
    return It != Granules.end() && It->second.ValidateOnly;
  }

  // Granules demoted so far in this process (monotonic: a Forget of a whole
  // demoted granule does not decrement it; the count gates the fast path
  // above and feeds the report).
  [[nodiscard]]
  uint32_t Demoted() const {
    return DemotedCount.load(std::memory_order_relaxed);
  }

  // How many guest pages of this granule mtrack currently has armed. The
  // number a later arming heuristic keys off; nothing reads it yet.
  // The two questions the S4b granule table (GranuleTable.h) asks when it
  // rematerialises a granule's host protection, see WantedProt() there:
  //   Armed -- mtrack currently holds PROT_WRITE back from this granule, so
  //            the materialised protection must not include it;
  //   Known -- mtrack has armed this granule at some point, so the raw
  //            mprotects the arm and fault paths issue may have moved the
  //            kernel's protection since the table last recorded it.
  // Both are leaf reads under this table's own mutex; VMATracking.Mutex may
  // be held by the caller (the order is VMATracking, then this mutex,
  // everywhere: NoteArmed runs under VMATracking shared, NoteFault under no
  // VMATracking lock at all).
  [[nodiscard]]
  bool Armed(uint64_t GranuleBase) {
    if (!Enabled()) {
      return false;
    }
    std::lock_guard lk {Mutex};
    auto It = Granules.find(GranuleBase);
    return It != Granules.end() && It->second.TrackedMask != 0;
  }
  [[nodiscard]]
  bool Known(uint64_t GranuleBase) {
    if (!Enabled()) {
      return false;
    }
    std::lock_guard lk {Mutex};
    return Granules.find(GranuleBase) != Granules.end();
  }
  [[nodiscard]]
  uint32_t TrackedCount(uint64_t GranuleBase) {
    if (!Enabled()) {
      return 0;
    }
    std::lock_guard lk {Mutex};
    auto It = Granules.find(GranuleBase);
    return It == Granules.end() ? 0 : static_cast<uint32_t>(__builtin_popcount(It->second.TrackedMask));
  }

  // Drain the flip-rate mailbox. NON-signal callers only (it is the caller that
  // then logs). Returns false when there is nothing to report.
  bool TakeFlipReport(uint64_t* GranuleBase, uint32_t* Flips, uint32_t* Tracked, bool* Demoted) {
    const uint64_t Slot = PendingReportGranule.exchange(0, std::memory_order_acquire);
    if (!Slot) {
      return false;
    }
    *GranuleBase = Slot & ~1ull;
    *Flips = PendingReportFlips.load(std::memory_order_relaxed);
    *Tracked = PendingReportTracked.load(std::memory_order_relaxed);
    *Demoted = PendingReportDemoted.load(std::memory_order_relaxed) != 0;
    return true;
  }

  // The granules covering [Start, Top) are gone (guest munmap/mremap/mmap-over).
  // Not a correctness requirement -- a stale mask only over-reports tracking to
  // the heuristic -- but it keeps the map from growing without bound across a
  // long session that churns mappings.
  //
  // Except a DEMOTED granule the range covers only partially: its live pages
  // may still hold blocks, and MarkGuestExecutableRange (NewPage-gated) will
  // not run again for them, so the demoted bit must outlive the retirement of
  // its siblings (soundness argument above MixedFlipThreshold). Such an entry
  // only drops the retired pages from its mask; the whole-granule case erases
  // as before, because the munmap/mmap-over invalidation of a whole granule
  // makes every page in it NewPage again.
  void Forget(uint64_t Start, uint64_t Top) {
    if (!Enabled()) {
      return;
    }
    std::lock_guard lk {Mutex};
    if (Granules.empty()) {
      return;
    }
    const uint64_t GranuleSize = FEXCore::HostPage::Size();
    for (uint64_t G = Base(Start); G < Top; G += GranuleSize) {
      auto It = Granules.find(G);
      if (It == Granules.end()) {
        continue;
      }
      const bool Whole = G >= Start && G + GranuleSize <= Top;
      if (Whole || !It->second.ValidateOnly) {
        Granules.erase(It);
        continue;
      }
      const uint64_t First = std::max(Start, G);
      const uint64_t Last = std::min(Top, G + GranuleSize);
      for (uint64_t Page = First; Page < Last; Page += FEXCore::Utils::FEX_GUEST_PAGE_SIZE) {
        It->second.TrackedMask &= ~(1u << PageBit(Page));
      }
    }
  }

private:
  static uint64_t CoarseNanoseconds() {
    struct timespec TS {};
    // CLOCK_MONOTONIC_COARSE: vDSO read of a cached value, no syscall, and
    // async-signal-safe. Millisecond resolution is far more than a per-second
    // window needs.
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &TS);
    return static_cast<uint64_t>(TS.tv_sec) * 1'000'000'000ull + static_cast<uint64_t>(TS.tv_nsec);
  }

  std::mutex Mutex;
  fextl::unordered_map<uint64_t, Entry> Granules;
  // Low bit is the "slot full" flag so a granule base of 0 is representable.
  std::atomic<uint64_t> PendingReportGranule {0};
  std::atomic<uint32_t> PendingReportFlips {0};
  std::atomic<uint32_t> PendingReportTracked {0};
  std::atomic<uint32_t> PendingReportDemoted {0};
  std::atomic<uint32_t> DemotedCount {0};
};

[[nodiscard]]
inline GranuleTable& Table() {
  static GranuleTable Instance;
  return Instance;
}

// ---------------------------------------------------------------------------
// FEX_SMCGRANULEPOLICY=rearm: granules whose siblings still owe an invalidation.
//
// LOCK ORDER: Mutex is a LEAF, drained by value before anything else is called,
// exactly like SMCLazyDirtyMutex. The drain itself then runs
// SoftInvalidateGuestCodeRange with no lock of ours held.
// ---------------------------------------------------------------------------
class RearmQueue final {
public:
  // SIGNAL PATH under the Rearm policy only. Allocates on insert, which is what
  // MarkSMCLazyDirtyPage already does from this same handler.
  void Add(uint64_t GranuleBase) {
    std::lock_guard lk {Mutex};
    Pending.insert(GranuleBase);
    Count.store(Pending.size(), std::memory_order_release);
  }

  [[nodiscard]]
  bool Empty() const {
    return Count.load(std::memory_order_acquire) == 0;
  }

  void Take(fextl::vector<uint64_t>& Out) {
    std::lock_guard lk {Mutex};
    Out.assign(Pending.begin(), Pending.end());
    Pending.clear();
    Count.store(0, std::memory_order_release);
  }

  // A hard invalidation of the range already did strictly more than the drain
  // would have, so drop the debt (mirrors ClearSMCLazyDirtyRange).
  void Drop(uint64_t Start, uint64_t Top) {
    if (Empty()) {
      return;
    }
    std::lock_guard lk {Mutex};
    auto First = Pending.lower_bound(Base(Start));
    auto Last = Pending.lower_bound(Top);
    Pending.erase(First, Last);
    Count.store(Pending.size(), std::memory_order_release);
  }

private:
  std::mutex Mutex;
  std::atomic<uint64_t> Count {0};
  fextl::set<uint64_t> Pending;
};

[[nodiscard]]
inline RearmQueue& Rearms() {
  static RearmQueue Instance;
  return Instance;
}

// ---------------------------------------------------------------------------
// The two granule tables (design Part 2 section 2), and how they stay in step
// ---------------------------------------------------------------------------
// This table (S4c) records which guest pages mtrack has armed, per granule.
// The VMATracking granule table (S4b, GranuleTable.h) records the guest's
// intended per-page protections and materialises their union with one host
// mprotect per granule. The arm and fault paths in SyscallsSMCTracking.cpp
// issue their own granule-wide mprotects (PROT_READ to arm, R+W to unprotect)
// without the VMATracking lock -- the fault path cannot take it (lock order
// against fork, see HandleSegfault) -- so S4b cannot be told about them.
//
// Instead S4b asks this table at the one moment it matters, rematerialisation
// (GranuleTable::WantedProt): while Armed(), PROT_WRITE is left out of the
// union so a sub-granule guest mprotect cannot silently undo the arm (a JIT
// engine mprotect(RWX)-ing a data page in a granule that also holds compiled
// code was the shape that did); and for a Known() granule the table's cached
// HostProt is not trusted to skip the syscall, because the raw arm/unprotect
// mprotects move the kernel's protection behind its back. The cost is one
// possibly redundant mprotect per sub-granule guest mprotect in a granule
// that has ever held code, which is rare (JIT engines protect whole regions).
//
// The remaining window is the fault path's unprotect racing a concurrent
// rematerialisation: the arm side cannot race it (it holds VMATracking
// shared, rematerialisation needs it unique), and the losing order on the
// fault side leaves the granule read-only with its armed mask already
// cleared, which the next guest store settles with one more (spurious but
// harmless) SMC fault: HandleSegfault unprotects and invalidates the granule.
//
// Cover() widens an mtrack mprotect to the granule. That is only SAFE if the
// whole granule is backed (`mprotect` over a hole returns ENOMEM, and the
// unprotect leg treats a failed mprotect as fatal, as it must). On a 64K
// kernel a mapping is 64K-granular by construction, and S4b never leaves a
// granule partially mapped: a granule with any live guest page is mapped in
// full (the permissive tier's union rule, and the private-backing conversion
// for sub-granule MAP_FIXED). So the invariant holds by construction and no
// GranuleFullyBacked() query is needed; both legs still report the errno of
// a widened mprotect if it ever fails, which is the failure handling the 4K
// code already has.

} // namespace FEX::HLE::SMCGranule
