// SPDX-License-Identifier: MIT
/*
$info$
tags: glue|block-database
desc: Stores information about blocks, and provides C++ implementations to lookup the blocks
$end_info$
*/

#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"

namespace FEXCore {
namespace SMC {
  // SMC Idea 3. Written once by ContextImpl's constructor before any CodeBuffer
  // exists; read only by the GuestToHostMap constructor below.
  std::atomic<bool> CodeGranuleTrackingEnabled {false};
} // namespace SMC

GuestToHostMap::GuestToHostMap() {
  // SMC Idea 3: allocate the granule bitmap only if one of the SMC store fast
  // paths that consults it is enabled. Enabling it here and nowhere else is
  // load-bearing: a map that acquired blocks while untracked and then had
  // tracking switched on would present an empty (all-clear) bitmap over live
  // code, which is precisely the false negative the design forbids.
  if (SMC::CodeGranuleTrackingEnabled.load(std::memory_order_acquire)) {
    CodeGranules.Enable();
  }
}

LookupCache::LookupCache(FEXCore::Context::ContextImpl* CTX)
  : ctx {CTX} {

  TotalCacheSize = ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_GUEST_PAGE_SIZE * 8 + CODE_SIZE + MAX_L1_SIZE;

  // Block cache ends up looking like this
  // PageMemoryMap[VirtualMemoryRegion >> 12]
  //       |
  //       v
  // PageMemory[Memory & (VIRTUAL_PAGE_SIZE - 1)]
  //       |
  //       v
  // Pointer to Code
  //
  // Allocate a region of memory that we can use to back our block pointers
  // We need one pointer per page of virtual memory
  // At 64GB of virtual memory this will allocate 128MB of virtual memory space
  PagePointer = reinterpret_cast<uintptr_t>(FEXCore::Allocator::VirtualAlloc(TotalCacheSize, false, false));
  LOGMAN_THROW_A_FMT(PagePointer != -1ULL, "Failed to allocate PagePointer");

  // Disable THP across the whole reservation by default: the L2 *entry pool*
  // (the CODE_SIZE middle region) is bump-allocated sparsely and does not want
  // 2 MiB granularity. The two randomly-indexed tables re-enable it below.
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<const void*>(PagePointer), TotalCacheSize, FEXCore::Allocator::THPControl::Disable);

  FEXCore::Allocator::VirtualName("FEXMem_Lookup", reinterpret_cast<void*>(PagePointer),
                                  ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_GUEST_PAGE_SIZE * 8 + CODE_SIZE);
  CTX->SyscallHandler->MarkOvercommitRange(PagePointer, TotalCacheSize);

  // Allocate our memory backing our pages
  // We need 32KB per guest page (One pointer per byte)
  // XXX: We can drop down to 16KB if we store 4byte offsets from the code base
  // We currently limit to 128MB of real memory for caching for the total cache size.
  // Can end up being inefficient if we compile a small number of blocks per page
  PageMemory = PagePointer + ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_GUEST_PAGE_SIZE * 8;

  // L1 Cache
  L1Pointer = PageMemory + CODE_SIZE;
  FEXCore::Allocator::VirtualName("FEXMem_Lookup_L1", reinterpret_cast<void*>(L1Pointer), MAX_L1_SIZE);

  // THP hints for the two tables that are indexed by a *hash of the guest RIP*
  // rather than walked, so every lookup is an independent dTLB miss candidate.
  // Both are advisory: madvise failure (no THP in the kernel, THP set to
  // "never", MADV_HUGEPAGE unsupported) changes nothing but the miss rate,
  // and VirtualTHPControl is already a no-op when the allocator has no THP
  // hook. Neither call changes any address, size or access rule.
  //
  //  * L1: MAX_L1_ENTRIES * 16 == 16 MiB of reservation, indexed by
  //    (RIP & L1PointerMask). It is densely used from L1Pointer upwards --
  //    the mask only ever selects a prefix -- so THP costs at most one huge
  //    page of slack past the live prefix even at MIN_L1_ENTRIES.
  //  * L2 page-pointer array: one pointer per guest page over the whole
  //    VirtualMemSize (128 MiB at 64 GiB), indexed by guest page number. A
  //    single huge page covers 256K guest pages == 1 GiB of guest VA, so the
  //    resident set stays proportional to how far apart the guest's code
  //    mappings actually are.
  //
  // Interaction with MADV_DONTNEED (ScrubForLazySMC, the DynamicL1Cache resize
  // path, ClearL2Cache, ClearThreadLocalCaches): DONTNEED over a THP-backed
  // range is well defined -- the kernel zaps whole huge pages inside the range
  // and splits the PMD only for a huge page the range partially covers. The L1
  // scrubs always pass the *entire* MAX_L1_SIZE so they zap whole pages and
  // never split. Signal-safety of ScrubForLazySMC is unaffected either way: it
  // is still exactly one madvise() syscall with no userspace allocation, and
  // the memset fallback still works if it fails. The only behavioural change
  // is that the first touch after a scrub re-faults at huge-page granularity.
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<const void*>(L1Pointer), MAX_L1_SIZE, FEXCore::Allocator::THPControl::Enable);
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<const void*>(PagePointer),
                                        ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_GUEST_PAGE_SIZE * 8,
                                        FEXCore::Allocator::THPControl::Enable);

  VirtualMemSize = ctx->Config.VirtualMemSize;

  if (DynamicL1Cache()) {
    // Start at minimum size when dynamic.
    L1PointerMask = MIN_L1_ENTRIES - 1;
  } else {
    // Start at maximum instead.
    L1PointerMask = MAX_L1_ENTRIES - 1;
  }
}

LookupCache::~LookupCache() {
  FEXCore::Allocator::VirtualFree(reinterpret_cast<void*>(PagePointer), TotalCacheSize);
  ctx->SyscallHandler->UnmarkOvercommitRange(PagePointer, TotalCacheSize);

  // BlockLinks and its node pool are ordinary owning containers; their
  // destructors reclaim everything. (This used to be a raw pointer into a
  // monotonic buffer resource, hence the note that used to be here.)
}

void LookupCache::ClearL2Cache(const FEXCore::LookupCacheBaseLockToken& lk) {
  // Clear out the page memory
  // PagePointer and PageMemory are sequential with each other. Clear both at once.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer),
                                      ctx->Config.VirtualMemSize / FEXCore::Utils::FEX_GUEST_PAGE_SIZE * 8 + CODE_SIZE, false);
  AllocateOffset = 0;
}

void LookupCache::ClearThreadLocalCaches(const LookupCacheWriteLockToken&) {
  // Clear L1 and L2 by clearing the full cache.
  FEXCore::Allocator::VirtualDontNeed(reinterpret_cast<void*>(PagePointer), TotalCacheSize, false);
  CachedCodePages.clear();
  InvalidateCachedCodePagesMemo();
}

void LookupCache::ClearCache(const LookupCacheWriteLockToken& lk) {
  // Clear L1 and L2 by clearing the full cache.
  ClearThreadLocalCaches(lk);
  Shared->ClearCache(lk);
}

void GuestToHostMap::ClearCache(const LookupCacheWriteLockToken&) {
  // All code is gone, so every registered inbound link points at a host site in
  // a code buffer that is being retired. Drop them WITHOUT running any
  // delinker -- that is the pre-existing contract of this function, and
  // ContextImpl::ClearCodeCache traps if it is reached with a live code buffer
  // (Core.cpp, "live code buffer still contains patched callsites").
  // The pool keeps its capacity so the next generation of links refills it
  // without allocating; the nodes are trivially destructible, so this is a
  // pointer reset rather than a walk.
  BlockLinks.clear();
  BlockLinkPool.clear();
  BlockLinkFreeHead = BlockLinkInvalid;

  // All code is gone, clear the block list
  BlockList.clear();

  // SMC v3: retained (soft-invalidated) entries point at host code in the
  // CodeBuffer that is being retired here, so they must not survive it.
  RetainedBlocks.clear();
  RetainedCodePages.clear();

  // Defensive: ClearCache does not erase CodePages today, but the memo must
  // never outlive an entry it points at.
  InvalidateCodePagesMemo();

  // SMC Idea 3 CLEAR POINT (whole-cache). BlockList and RetainedBlocks are now
  // empty, so no granule anywhere is backed by a live block. Leaves are zeroed
  // rather than freed so a concurrent lock-free reader can never chase a
  // dangling node; the memory is reclaimed when the CodeBuffer dies.
  CodeGranules.ClearAll();
}

} // namespace FEXCore
