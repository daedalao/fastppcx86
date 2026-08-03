// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC Idea 3: sub-page code-granule bitmap
// ===========================================================================
//
// PROBLEM
// -------
// Every SMC store fast path has to answer one question before it may emulate a
// guest store instead of invalidating: "does [EA, EA+Width) overlap the guest
// source bytes of any COMPILED block?"  Today that question is answered by
// GuestToHostMap::RangeOverlapsCompiledCode, which
//   * takes the lookup-cache read lock,
//   * walks the std::map<page, vector<entry>> CodePages index,
//   * hash-looks-up every entry in BlockList, and
//   * chases BlockBegin -> JITCodeHeader -> JITCodeTail for each one.
//
// Measured on op4k with FEX_SMCSTOREBACKPATCH=1 running smcstorm/falseshare:
// the workload runs *correctly* but at 2250 stores/s, and perf attributes 55%
// of all CPU to RangeOverlapsCompiledCode + its LookupCache wrapper (~400us per
// call, dominated by the map walk under the lock).  The pwrite it gates is 3%.
// The same walk sits on the v1 SIGSEGV fast path in SyscallsSMCTracking.cpp.
//
// DESIGN
// ------
// A side structure that answers the *negative* of that question in a handful of
// loads and no lock:
//
//   one bit per 64-byte guest granule; 64 granules per 4KiB page; therefore
//   exactly one uint64_t per guest page.
//
// A bit is SET if some compiled block's guest source bytes (conservatively)
// live in that granule.  The structure is allowed FALSE POSITIVES (a set bit
// with no code behind it) and must never produce a FALSE NEGATIVE (a clear bit
// over live code).  Readers therefore use it only as a fast "provably clear"
// gate: clear => take the store-emulation fast path; anything else => fall
// through to the existing authoritative, locked query, whose result is final.
// If the feature is off, or the address is outside the tracked VA range, or the
// leaf was never allocated because the page never held code, the answer is
// simply "not provably clear" and the old path runs unchanged.
//
// STORAGE
// -------
// Sparse three-level radix over a 48-bit guest VA (FEX's 64-bit guests live in
// the low 47 bits; 32-bit guests occupy the first L0 slot).  Hashing was
// rejected: a hash collision makes two unrelated pages share a leaf, and the
// page-granular CLEAR below would then clear a live page's bits -- a false
// negative, i.e. silent guest corruption.  The radix aliases nothing.
//
//   Addr bits [47:35] -> L0 index (8192 entries, 64KiB, allocated once)
//   Addr bits [34:22] -> L1 index (8192 entries, 64KiB per node, 32GiB reach)
//   Addr bits [21:12] -> leaf index (1024 words, 8KiB per leaf, 4MiB reach)
//   Addr bits [11:6]  -> bit within the page's uint64_t
//
// A game mapping 2-4GiB of code pages costs ~4-8MiB of leaves.  Interior nodes
// and leaves are allocated on demand on the WRITER path only (which already
// holds the lookup-cache write lock) and are never freed while the owning
// GuestToHostMap lives -- ClearAll() zeroes the words instead of freeing, so a
// concurrent lock-free reader can never chase a dangling node.  Everything is
// released in the destructor, i.e. when the CodeBuffer dies.
//
// MAINTENANCE POINTS (all under GuestToHostMap's write lock)
// ----------------------------------------------------------
//   SET   GuestToHostMap::AddBlockExecutableRange  -- the single choke point
//         through which a guest page becomes a "code page", reached from
//         Core.cpp CompileBlock (fresh compile), Core.cpp
//         TryRelinkSoftInvalidatedBlock (SMC v3 relink) and CodeCache.cpp
//         LoadCacheFile (cache-loaded blocks).  Callers that know the block's
//         decoded guest extent pass it and get granule precision; callers that
//         do not (cache load, custom IR, GuestRangeLength==0) pass nothing and
//         get a conservative all-64-bits-set page.
//   CLEAR GuestToHostMap::InvalidateRange, GuestToHostMap::SoftInvalidateRange
//         -- both already clear the CodePages entries for whole pages, so the
//         leaves for those pages are zeroed in the same place.  Per-BLOCK bit
//         clearing is deliberately NOT attempted: several blocks share a
//         granule, so subtracting one block's bits could clear another's.
//         Page-level clear plus re-set on the next compile/relink is correct.
//   CLEAR GuestToHostMap::ClearCache -- BlockList is emptied there (CodeBuffer
//         swap / ClearCodeCache), so every bit must go.
//
// MEMORY ORDERING / SOUNDNESS
// ---------------------------
// See the long argument on ProvablyClear() below.  Read it before touching
// either the SET site or a reader.

#include <atomic>
#include <cstdint>
#include <cstddef>

#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/fextl/vector.h>

namespace FEXCore::SMC {

// Process-global enable. Set once from ContextImpl's constructor, before any
// CodeBuffer (and therefore any GuestToHostMap) exists, from the SAME config
// flags that consume the bitmap -- FEX_SMCSTOREEMULATION, FEX_SMCSTOREBACKPATCH
// and FEX_SMCSEMANTICPATCH. There is no separate flag. With all of them off
// nothing is allocated and no reader ever consults it.
//
// It is read only in GuestToHostMap's constructor, so a map can never be born
// with tracking off, acquire blocks, and then have tracking switched on
// underneath it (which would present an empty bitmap over live code).
extern std::atomic<bool> CodeGranuleTrackingEnabled;

class CodeGranuleBitmap final {
public:
  static constexpr uint32_t kGranuleShift = 6; // 64-byte granules
  static constexpr uint32_t kPageShift = 12;

  static constexpr uint32_t kLeafBits = 10; // pages per leaf
  static constexpr uint32_t kL1Bits = 13;
  static constexpr uint32_t kL0Bits = 13;

  static constexpr uint32_t kLeafShift = kPageShift;           // 12
  static constexpr uint32_t kL1Shift = kLeafShift + kLeafBits; // 22
  static constexpr uint32_t kL0Shift = kL1Shift + kL1Bits;     // 35

  // Everything at or above this is untracked and answers "not provably clear".
  static constexpr uint64_t kMaxAddress = 1ULL << (kL0Shift + kL0Bits); // 2^48

  // Plain PODs accessed through the __atomic builtins rather than std::atomic
  // members. The nodes are raw mmap'd pages that no constructor ever runs over,
  // so wrapping them in std::atomic<> would be a lifetime fiction; the builtins
  // give exactly the same lock-free 64-bit accesses without one. Same technique
  // as the backpatch page filter in LinuxSyscalls/SMCStoreBackpatch.cpp.
  struct Leaf {
    uint64_t Words[1u << kLeafBits];
  };
  struct L1Node {
    Leaf* Entries[1u << kL1Bits];
  };
  struct L0Node {
    L1Node* Entries[1u << kL0Bits];
  };

  CodeGranuleBitmap() = default;
  CodeGranuleBitmap(const CodeGranuleBitmap&) = delete;
  CodeGranuleBitmap& operator=(const CodeGranuleBitmap&) = delete;

  ~CodeGranuleBitmap() {
    // Only ever reached when the owning CodeBuffer/GuestToHostMap is destroyed,
    // at which point no reader can still reach us through it.
    for (auto* L : AllLeaves) {
      FEXCore::Allocator::VirtualFree(L, sizeof(Leaf));
    }
    for (auto* N : AllL1Nodes) {
      FEXCore::Allocator::VirtualFree(N, sizeof(L1Node));
    }
    if (auto* R = __atomic_load_n(&Root, __ATOMIC_RELAXED)) {
      FEXCore::Allocator::VirtualFree(R, sizeof(L0Node));
    }
  }

  // Called exactly once, from GuestToHostMap's constructor, before the map can
  // be reached by any other thread.
  void Enable() {
    if (Root) {
      return;
    }
    auto* R = static_cast<L0Node*>(AllocZeroed(sizeof(L0Node)));
    if (!R) {
      // Out of address space: stay disabled. Everything falls back to the
      // authoritative locked query, which is exactly today's behaviour.
      return;
    }
    __atomic_store_n(&Root, R, __ATOMIC_RELEASE);
  }

  bool Enabled() const {
    return __atomic_load_n(&Root, __ATOMIC_RELAXED) != nullptr;
  }

  // ---------------------------------------------------------------------
  // WRITER SIDE. Every entry point below requires GuestToHostMap's write
  // lock to be held, which makes the writer single-threaded with respect to
  // itself and to every other maintenance point. Plain relaxed/release stores
  // therefore suffice; no CAS is needed.
  // ---------------------------------------------------------------------

  // Set the granules covering [Start, Start+Length) that fall inside the single
  // page PageBase. If the intersection is empty the WHOLE page is set instead,
  // which keeps the "a registered code page always has at least the bits its
  // block needs" invariant even when a caller's notion of the block extent and
  // its code-page list disagree (multiblock across discontiguous pages).
  void SetPageRange(uint64_t PageBase, uint64_t Start, uint64_t Length) {
    Leaf* L = GetOrCreateLeaf(PageBase);
    if (!L) {
      return;
    }

    uint64_t Mask = ~0ULL;
    if (Length) {
      const uint64_t PageEnd = PageBase + (1ULL << kPageShift);
      const uint64_t Lo = Start > PageBase ? Start : PageBase;
      const uint64_t HiExcl = (Start + Length) < PageEnd ? (Start + Length) : PageEnd;
      if (Lo < HiExcl) {
        const uint32_t FirstBit = static_cast<uint32_t>((Lo - PageBase) >> kGranuleShift);
        const uint32_t LastBit = static_cast<uint32_t>((HiExcl - 1 - PageBase) >> kGranuleShift);
        Mask = BitRangeMask(FirstBit, LastBit);
      }
      // else: empty intersection -> conservative full page (Mask stays ~0).
    }

    uint64_t* Word = &L->Words[WordIndex(PageBase)];
    __atomic_store_n(Word, __atomic_load_n(Word, __ATOMIC_RELAXED) | Mask, __ATOMIC_RELEASE);
  }

  void ClearPage(uint64_t PageBase) {
    Leaf* L = FindLeaf(PageBase);
    if (!L) {
      return;
    }
    __atomic_store_n(&L->Words[WordIndex(PageBase)], uint64_t {0}, __ATOMIC_RELEASE);
  }

  // Zero every bit without freeing anything, so lock-free readers keep chasing
  // live nodes.
  void ClearAll() {
    for (auto* L : AllLeaves) {
      for (auto& W : L->Words) {
        __atomic_store_n(&W, uint64_t {0}, __ATOMIC_RELAXED);
      }
    }
    __atomic_thread_fence(__ATOMIC_RELEASE);
  }

  // ---------------------------------------------------------------------
  // READER SIDE. Lock-free. See the soundness argument below.
  // ---------------------------------------------------------------------

  // True IFF the bitmap can prove that no compiled block's guest bytes lie in
  // [Start, Start+Length). False means "overlaps, OR we do not know" and the
  // caller MUST fall through to the authoritative locked query.
  //
  // ===================== MEMORY-ORDERING SOUNDNESS =====================
  // The dangerous outcome is a reader that observes a stale CLEAR bit for
  // bytes that are (becoming) live code and, on the strength of it, pwrites
  // through /proc/self/mem into them -- silent guest corruption, because the
  // page stays protected and no block is invalidated.  Three facts make that
  // impossible, none of which depend on this structure's own ordering being
  // stronger than relaxed:
  //
  // (1) A reader only exists downstream of a WRITE FAULT on a guest page that
  //     mtrack has write-protected.  Protection is armed by
  //     SyscallHandler::MarkGuestExecutableRange, and Core.cpp CompileBlock and
  //     TryRelinkSoftInvalidatedBlock both call it AFTER
  //     LookupCache::AddBlockExecutableRange -- which is where the bits are
  //     set.  So for any page whose protection can produce a fault, the
  //     bit-SET for the block that caused the protection happened-before the
  //     mprotect(2) that armed it.  mprotect is a kernel-side full barrier
  //     with a TLB shootdown IPI to every CPU, and the faulting thread reaches
  //     the reader through a kernel entry/exit of its own; the SET is
  //     therefore globally visible before any fault the protection can raise.
  //     This is why the bits must be set at AddBlockExecutableRange and not,
  //     say, at AddBlockMapping.
  //
  // (2) The residual window is a SECOND block being compiled onto an ALREADY
  //     protected page: its bits are set while another thread is faulting on
  //     the same page.  The bitmap read is no weaker than the path it
  //     replaces.  Today's reader takes the lookup read lock and calls
  //     GuestToHostMap::RangeOverlapsCompiledCode, which walks CodePages and
  //     skips ("continue") every entry not yet present in BlockList.  Between
  //     AddBlockExecutableRange and AddBlockMapping -- exactly the window in
  //     question -- the new block IS in CodePages but is NOT in BlockList, so
  //     the current authoritative query already returns "no overlap" and the
  //     current code already pwrites into the bytes being compiled.  The
  //     bitmap's SET happens at the START of that window rather than at its
  //     end, so any reader that would have been told "clear" by the bitmap
  //     would have been told "clear" by the existing path too, and some are
  //     now correctly told "set".  Strictly stronger, never weaker.
  //
  // (3) Every CLEAR is page-granular and happens under the same write lock
  //     while the corresponding blocks are being erased from BlockList, and
  //     all of hard invalidate / soft invalidate / ClearCache hold
  //     ContextImpl::CodeInvalidationMutex EXCLUSIVELY, whereas CompileBlock
  //     holds it SHARED.  Compile and invalidate can therefore never
  //     interleave, so a SET can never be lost to a concurrent page CLEAR.
  //
  // Given (1)-(3) the loads below only need to be atomic (no tearing) and to
  // carry the dependency from a node pointer to the node's contents; they are
  // acquire on the pointers and relaxed on the word.  A stale-SET bit costs a
  // wasted fallback; a stale-CLEAR bit is excluded by (1)/(2).
  // =====================================================================
  bool ProvablyClear(uint64_t Start, uint64_t Length) const {
    const L0Node* R = __atomic_load_n(&Root, __ATOMIC_ACQUIRE);
    if (!R || !Length) {
      return false;
    }

    const uint64_t End = Start + Length;
    if (End < Start || End > kMaxAddress) {
      return false; // wrap or outside the tracked VA range: unknown.
    }

    const uint64_t FirstPage = Start >> kPageShift;
    const uint64_t LastPage = (End - 1) >> kPageShift;
    // Readers are single guest stores (<= 8 bytes, <= 2 pages). Refuse to walk
    // anything larger rather than growing an unbounded loop on this path.
    if (LastPage - FirstPage > 3) {
      return false;
    }

    for (uint64_t Page = FirstPage; Page <= LastPage; ++Page) {
      const uint64_t PageBase = Page << kPageShift;
      const Leaf* L = FindLeafFrom(R, PageBase);
      if (!L) {
        // No leaf means no code page here was ever registered under this
        // GuestToHostMap -- provably clear for this page.
        continue;
      }

      const uint64_t Word = __atomic_load_n(&L->Words[WordIndex(PageBase)], __ATOMIC_RELAXED);
      if (!Word) {
        continue;
      }

      const uint64_t PageEnd = PageBase + (1ULL << kPageShift);
      const uint64_t Lo = Start > PageBase ? Start : PageBase;
      const uint64_t HiExcl = End < PageEnd ? End : PageEnd;
      const uint32_t FirstBit = static_cast<uint32_t>((Lo - PageBase) >> kGranuleShift);
      const uint32_t LastBit = static_cast<uint32_t>((HiExcl - 1 - PageBase) >> kGranuleShift);
      if (Word & BitRangeMask(FirstBit, LastBit)) {
        return false;
      }
    }

    return true;
  }

private:
  static constexpr uint64_t BitRangeMask(uint32_t FirstBit, uint32_t LastBit) {
    // Inclusive [FirstBit, LastBit], both < 64.
    const uint32_t Count = LastBit - FirstBit + 1;
    const uint64_t Base = Count >= 64 ? ~0ULL : ((1ULL << Count) - 1);
    return Base << FirstBit;
  }

  static constexpr uint32_t L0Index(uint64_t Addr) {
    return static_cast<uint32_t>((Addr >> kL0Shift) & ((1u << kL0Bits) - 1));
  }
  static constexpr uint32_t L1Index(uint64_t Addr) {
    return static_cast<uint32_t>((Addr >> kL1Shift) & ((1u << kL1Bits) - 1));
  }
  static constexpr uint32_t WordIndex(uint64_t Addr) {
    return static_cast<uint32_t>((Addr >> kLeafShift) & ((1u << kLeafBits) - 1));
  }

  // Linux's FEXCore::Allocator::VirtualAlloc is a thin mmap wrapper, so a
  // failure comes back as MAP_FAILED rather than nullptr. Normalise it, since
  // every caller here treats null as "stay conservative".
  static void* AllocZeroed(size_t Size) {
    void* Ptr = FEXCore::Allocator::VirtualAlloc(Size, false);
    if (!Ptr || Ptr == reinterpret_cast<void*>(~uintptr_t {0})) {
      return nullptr;
    }
    return Ptr; // Anonymous mapping: already zero-filled.
  }

  static Leaf* FindLeafFrom(const L0Node* R, uint64_t Addr) {
    L1Node* N = __atomic_load_n(&R->Entries[L0Index(Addr)], __ATOMIC_ACQUIRE);
    if (!N) {
      return nullptr;
    }
    return __atomic_load_n(&N->Entries[L1Index(Addr)], __ATOMIC_ACQUIRE);
  }

  Leaf* FindLeaf(uint64_t Addr) const {
    const L0Node* R = __atomic_load_n(&Root, __ATOMIC_RELAXED);
    if (!R || Addr >= kMaxAddress) {
      return nullptr;
    }
    return FindLeafFrom(R, Addr);
  }

  // Writer-only; the caller holds GuestToHostMap's write lock, so no CAS.
  Leaf* GetOrCreateLeaf(uint64_t Addr) {
    L0Node* R = __atomic_load_n(&Root, __ATOMIC_RELAXED);
    if (!R || Addr >= kMaxAddress) {
      return nullptr;
    }

    L1Node** L0Slot = &R->Entries[L0Index(Addr)];
    L1Node* N = __atomic_load_n(L0Slot, __ATOMIC_RELAXED);
    if (!N) {
      N = static_cast<L1Node*>(AllocZeroed(sizeof(L1Node)));
      if (!N) {
        return nullptr;
      }
      AllL1Nodes.push_back(N);
      // Release: a reader that acquire-loads this pointer must see the zeroed
      // (or already populated) entries behind it.
      __atomic_store_n(L0Slot, N, __ATOMIC_RELEASE);
    }

    Leaf** L1Slot = &N->Entries[L1Index(Addr)];
    Leaf* L = __atomic_load_n(L1Slot, __ATOMIC_RELAXED);
    if (!L) {
      L = static_cast<Leaf*>(AllocZeroed(sizeof(Leaf)));
      if (!L) {
        return nullptr;
      }
      AllLeaves.push_back(L);
      __atomic_store_n(L1Slot, L, __ATOMIC_RELEASE);
    }
    return L;
  }

  L0Node* Root {nullptr};

  // Writer-only bookkeeping (write lock held) so ClearAll can zero everything
  // and the destructor can free everything. Never read by the reader path.
  fextl::vector<Leaf*> AllLeaves;
  fextl::vector<L1Node*> AllL1Nodes;
};

} // namespace FEXCore::SMC
