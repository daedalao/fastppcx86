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
// NoteFault()/QueueRearm() run inside the SIGSEGV handler.  They never log and
// never allocate: NoteFault is a hash lookup plus scalar updates on an entry
// that arming already inserted, and the flip-rate *report* is a two-word
// mailbox that the non-signal mark path drains and prints.  QueueRearm inserts
// into a map, which is exactly what the established MarkSMCLazyDirtyPage does
// from the same handler, and it only runs under the opt-in Rearm policy.
// ===========================================================================

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
// The per-granule tracked-page table.
//
// Purely observability and policy input: correctness does NOT depend on it.
// The `invalidate` policy is sound because the range it hands the invalidator
// IS the range it unprotects, whatever this table says. What the table adds is
// the per-granule tracked COUNT (how many of the 16 guest pages mtrack actually
// armed, i.e. how much of the granule is really code) and the flip rate, which
// is what a future "this granule is not worth arming, hash it instead" heuristic
// needs and cannot get from the kernel.
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
  };

  // Arming. NOT a signal path (MarkGuestExecutableRange, holding VMATracking
  // shared), so allocation is fine.
  void NoteArmed(uint64_t GranuleBase, uint32_t PageMask) {
    if (!Enabled() || PageMask == 0) {
      return;
    }
    std::lock_guard lk {Mutex};
    Granules[GranuleBase].TrackedMask |= PageMask;
  }

  // A write fault forced this granule open. Returns the tracked mask as it was
  // and clears it: the protection is gone from the whole granule, so no page in
  // it is armed any more until MarkGuestExecutableRange re-installs it.
  //
  // SIGNAL PATH. No allocation (the entry was inserted by arming; a fault on a
  // granule with no entry simply finds nothing), no logging -- a flip rate over
  // the threshold is parked in the one-slot mailbox for the mark path to print.
  uint32_t NoteFault(uint64_t GranuleBase) {
    if (!Enabled()) {
      return 0;
    }
    uint64_t ReportFlips = 0;
    uint32_t Mask = 0;
    {
      std::lock_guard lk {Mutex};
      auto It = Granules.find(GranuleBase);
      if (It == Granules.end()) {
        return 0;
      }
      Mask = It->second.TrackedMask;
      It->second.TrackedMask = 0;

      if (FlipLogThreshold() != 0) {
        const uint64_t Now = CoarseNanoseconds();
        if (Now - It->second.WindowStart >= 1'000'000'000ull) {
          It->second.WindowStart = Now;
          It->second.Flips = 1;
        } else if (++It->second.Flips == FlipLogThreshold()) {
          ReportFlips = It->second.Flips;
        }
      }
    }
    if (ReportFlips) {
      // Single-slot mailbox: a second hot granule in the same window simply
      // overwrites the first. Losing a report is free; blocking or allocating
      // in a SIGSEGV handler is not.
      PendingReportFlips.store(static_cast<uint32_t>(ReportFlips), std::memory_order_relaxed);
      PendingReportGranule.store(GranuleBase | 1, std::memory_order_release);
    }
    return Mask;
  }

  // How many guest pages of this granule mtrack currently has armed. The
  // number a later arming heuristic keys off; nothing reads it yet.
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
  bool TakeFlipReport(uint64_t* GranuleBase, uint32_t* Flips) {
    const uint64_t Slot = PendingReportGranule.exchange(0, std::memory_order_acquire);
    if (!Slot) {
      return false;
    }
    *GranuleBase = Slot & ~1ull;
    *Flips = PendingReportFlips.load(std::memory_order_relaxed);
    return true;
  }

  // The granules covering [Start, Top) are gone (guest munmap/mremap/mmap-over).
  // Not a correctness requirement -- a stale mask only over-reports tracking to
  // the heuristic -- but it keeps the map from growing without bound across a
  // long session that churns mappings.
  void Forget(uint64_t Start, uint64_t Top) {
    if (!Enabled()) {
      return;
    }
    std::lock_guard lk {Mutex};
    if (Granules.empty()) {
      return;
    }
    for (uint64_t G = Base(Start); G < Top; G += FEXCore::HostPage::Size()) {
      Granules.erase(G);
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
// HOOK WANTED from the VMATracking granule table (design Part 2 section 2)
// ---------------------------------------------------------------------------
// Cover() widens an mtrack mprotect to the granule. That is unconditionally
// required by the kernel, but it is only SAFE if the whole granule is backed:
// `mprotect` over a range containing a hole returns ENOMEM, and the unprotect
// leg of the SMC fault path treats a failed mprotect as fatal (it must: a
// silent failure means the faulting store re-faults forever).
//
// On a 64K kernel the kernel itself has no sub-granule holes -- a mapping is
// 64K-granular by construction -- so the invariant holds as long as the guest
// syscall layer never leaves a granule PARTIALLY mapped. That is exactly what
// the S4b granule table enforces, and the one thing this file wants from it is
// that guarantee made checkable:
//
//     // True when every byte of the host granule containing `Addr` is mapped,
//     // i.e. a host mprotect over [Base(Addr), Base(Addr)+HostPage::Size())
//     // cannot fail with ENOMEM. Callable with VMATracking.Mutex held shared;
//     // must be lock-free or shared-lock-only, because the SMC fault path
//     // reads it after dropping that lock is not an option.
//     bool VMATracking::GranuleFullyBacked(uint64_t Addr) const;
//
// With it, the fault path can assert the invariant in debug builds and the
// arming path can decline to widen into an unbacked granule instead of taking
// an ENOMEM and degrading coverage. Until it exists both legs simply attempt
// the widened mprotect and report the errno they get, which is the same
// failure handling the 4K code already has.

} // namespace FEX::HLE::SMCGranule
