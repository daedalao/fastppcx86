// SPDX-License-Identifier: MIT
#include "Utils/Allocator/FlexBitSet.h"
#include "Utils/Allocator/HostAllocator.h"
#include "Utils/Allocator/IntrusiveArenaAllocator.h"
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXHeaderUtils/Syscalls.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/vector.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <new>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/user.h>
#include <type_traits>
#include <utility>

namespace Alloc::OSAllocator {

thread_local FEXCore::Core::InternalThreadState* TLSThread {};

class OSAllocator_64Bit final : public Alloc::HostAllocator {
public:
  OSAllocator_64Bit();
  OSAllocator_64Bit(fextl::vector<FEXCore::Allocator::MemoryRegion>& Regions);

  virtual ~OSAllocator_64Bit();
  void* AllocateSlab(size_t Size) override {
    return nullptr;
  }
  void DeallocateSlab(void* Ptr, size_t Size) override {}

  void* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) override;
  int Munmap(void* addr, size_t length) override;

  void LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) override {
    AllocationMutex.lock();
  }

  void UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child) override {
    if (Child) {
      AllocationMutex.StealAndDropActiveLocks();
    } else {
      AllocationMutex.unlock();
    }
  }

private:
  // Upper bound is the maximum virtual address space of the host processor
  uintptr_t UPPER_BOUND = (1ULL << 57);

  // Lower bound is the starting of the range just past the lower 32bits
  constexpr static uintptr_t LOWER_BOUND = 0x1'0000'0000ULL;

  uintptr_t UPPER_BOUND_PAGE = UPPER_BOUND / FEXCore::HostPage::Size();
  const uintptr_t LOWER_BOUND_PAGE = LOWER_BOUND / FEXCore::HostPage::Size();

  struct ReservedVMARegion {
    uintptr_t Base;
    // Could be number of pages if we want to pack this in to 12 bytes
    uint64_t RegionSize;
  };

  bool MergeReservedRegionIfPossible(ReservedVMARegion* Region, uintptr_t NextPtr, uint64_t NextSize) {
    constexpr uint64_t MaxReservedRegionSize = 64ULL * 1024 * 1024 * 1024; // 64GB
    uintptr_t RegionEnd = Region->Base + Region->RegionSize;
    uint64_t NewRegionSize = Region->RegionSize + NextSize;
    if (RegionEnd == NextPtr && NewRegionSize <= MaxReservedRegionSize) {
      // Append the contiguous region
      Region->RegionSize = NewRegionSize;
      return true;
    }
    return false;
  }

  struct LiveVMARegion {
    ReservedVMARegion* SlabInfo;
    uint64_t FreeSpace {};
    uint64_t NumManagedPages {};
    uint32_t LastPageAllocation {};
    bool HadMunmap {};

    // Align UsedPages so it pads to the next 4KB.
    // Necessary to take advantage of madvise zero page pooling.
    //
    // 64K port: this is deliberately a fixed 4096 and NOT the host page. It fixes
    // sizeof(LiveVMARegion), which the "FlexBitSet needs to be at the end" assert below
    // depends on, and growing it to 64K would cost 60KB per region on the 4K host for
    // nothing. What must be host-granular is the STRIDE the header occupies at the head
    // of the slab, and that comes from GetFEXManagedVMARegionSize's AlignUp below.
    using FlexBitElementType = uint64_t;
    alignas(FEXCore::Utils::FEX_GUEST_PAGE_SIZE) FEXCore::FlexBitSet<FlexBitElementType> UsedPages;

    // This returns the size of the LiveVMARegion in addition to the flex set that tracks the used data
    // The LiveVMARegion lives at the start of the VMA region which means on initialization we need to set that
    // tracked ranged as used immediately
    static size_t GetFEXManagedVMARegionSize(size_t Size) {
      // One element per page

      // 0x10'0000'0000 bytes
      // 0x100'0000 Pages
      // 1 bit per page for tracking means 0x20'0000 (Pages / 8) bytes of flex space
      // Which is 2MB of tracking
      const uint64_t NumElements = Size >> FEXCore::HostPage::Shift();
      return sizeof(LiveVMARegion) + FEXCore::FlexBitSet<FlexBitElementType>::SizeInBytes(NumElements);
    }

    static void InitializeVMARegionUsed(LiveVMARegion* Region, size_t AdditionalSize) {
      size_t SizeOfLiveRegion = FEXCore::HostPage::AlignUp(LiveVMARegion::GetFEXManagedVMARegionSize(Region->SlabInfo->RegionSize));
      size_t SizePlusManagedData = SizeOfLiveRegion + AdditionalSize;

      Region->FreeSpace = Region->SlabInfo->RegionSize - SizePlusManagedData;

      size_t NumManagedPages = SizePlusManagedData >> FEXCore::HostPage::Shift();
      size_t ManagedSize = NumManagedPages << FEXCore::HostPage::Shift();

      // Use madvise to set the full tracking region to zero.
      // This ensures unused pages are zero, while not having the backing pages consuming memory.
      //
      // 64K port: madvise wants a host-page-aligned address, and UsedPages sits at a fixed
      // 4096 into the slab, so the tail advice has to start at the next host page. The
      // length was already capable of underflowing for a tiny region (a page COUNT minus a
      // BYTE count -- pre-existing on 4K); clamp it rather than hand the kernel a ~2^64
      // length.
      const uintptr_t TailBase = FEXCore::HostPage::AlignUp(reinterpret_cast<uintptr_t>(Region->UsedPages.Memory) + ManagedSize);
      const size_t TrackingBytes = Region->SlabInfo->RegionSize >> FEXCore::HostPage::Shift();
      if (TrackingBytes > ManagedSize) {
        ::madvise(reinterpret_cast<void*>(TailBase), TrackingBytes - ManagedSize, MADV_DONTNEED);
      }

      // Use madvise to claim WILLNEED on the beginning pages for initial state tracking.
      // Improves performance of the following MemClear by not doing a page level fault dance for data necessary to track >170TB of used pages.
      ::madvise(reinterpret_cast<void*>(FEXCore::HostPage::AlignDown(reinterpret_cast<uintptr_t>(Region->UsedPages.Memory))), ManagedSize,
                MADV_WILLNEED);

      // Set our reserved pages
      Region->UsedPages.MemSet(NumManagedPages);
      Region->LastPageAllocation = NumManagedPages;
      Region->NumManagedPages = NumManagedPages;
    }
  };

  // Relaxed from "== a page": the header is a fixed 4096-byte object and the host page
  // may be larger. What matters is that it fits inside the host-page-aligned stride the
  // allocator reserves for it at the head of every slab.
  static_assert(sizeof(LiveVMARegion) <= FEXCore::Utils::FEX_GUEST_PAGE_SIZE, "Region header must fit its reserved stride");

  static_assert(std::is_trivially_copyable<LiveVMARegion>::value, "Needs to be trivially copyable");
  static_assert(offsetof(LiveVMARegion, UsedPages) == sizeof(LiveVMARegion), "FlexBitSet needs to be at the end");

  using ReservedRegionListType = fex_pmr::list<ReservedVMARegion*>;
  using LiveRegionListType = fex_pmr::list<LiveVMARegion*>;
  ReservedRegionListType* ReservedRegions {};
  LiveRegionListType* LiveRegions {};

  Alloc::ForwardOnlyIntrusiveArenaAllocator* ObjectAlloc {};
  FEXCore::ForkableUniqueMutex AllocationMutex;
  void DetermineVASize();

  LiveVMARegion* MakeRegionActive(ReservedRegionListType::iterator ReservedIterator, uint64_t UsedSize) {
    ReservedVMARegion* ReservedRegion = *ReservedIterator;

    ReservedRegions->erase(ReservedIterator);

    // mprotect the new region we've allocated
    size_t SizeOfLiveRegion = FEXCore::HostPage::AlignUp(LiveVMARegion::GetFEXManagedVMARegionSize(ReservedRegion->RegionSize));
    size_t SizePlusManagedData = UsedSize + SizeOfLiveRegion;

    auto Res = mprotect(reinterpret_cast<void*>(ReservedRegion->Base), SizePlusManagedData, PROT_READ | PROT_WRITE);
    // Checked unconditionally, not through LOGMAN_THROW_A_FMT: that compiles out with
    // ENABLE_ASSERTIONS=False, and a swallowed EINVAL here means the placement-new below
    // writes into still-PROT_NONE memory and the process dies with an illegible
    // SEGV_ACCERR instead of a diagnosis. (That is exactly what a misaligned Base did on
    // the 64K kernel.)
    if (Res == -1) {
      ERROR_AND_DIE_FMT("Couldn't mprotect region {:#x}+{:#x}: {} '{}'. Likely out of memory, at the maximum VMA count, "
                        "or the region base is not host-page aligned (host page {:#x})",
                        ReservedRegion->Base, SizePlusManagedData, errno, strerror(errno), FEXCore::HostPage::Size());
    }

    FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(ReservedRegion->Base), SizePlusManagedData);
    LiveVMARegion* LiveRange = new (reinterpret_cast<void*>(ReservedRegion->Base)) LiveVMARegion();

    // Copy over the reserved data
    LiveRange->SlabInfo = ReservedRegion;

    // Initialize VMA
    LiveVMARegion::InitializeVMARegionUsed(LiveRange, UsedSize);

    // Add to our active tracked ranges
    auto LiveIter = LiveRegions->emplace_back(LiveRange);
    return LiveIter;
  }

  void AllocateMemoryRegions(fextl::vector<FEXCore::Allocator::MemoryRegion>& Ranges);
  LiveVMARegion* FindLiveRegionForAddress(uintptr_t Addr, uintptr_t AddrEnd);
};

void OSAllocator_64Bit::DetermineVASize() {
  size_t Bits = FEXCore::Allocator::DetermineVASize();
  uintptr_t Size = 1ULL << Bits;

  UPPER_BOUND = Size;

#if ARCHITECTURE_x86_64 // Last page cannot be allocated on x86
  UPPER_BOUND -= FEXCore::HostPage::Size();
#endif

  UPPER_BOUND_PAGE = UPPER_BOUND / FEXCore::HostPage::Size();
}

OSAllocator_64Bit::LiveVMARegion* OSAllocator_64Bit::FindLiveRegionForAddress(uintptr_t Addr, uintptr_t AddrEnd) {
  LiveVMARegion* LiveRegion {};

  // Check active slabs to see if we can fit this
  for (auto it = LiveRegions->begin(); it != LiveRegions->end(); ++it) {
    uintptr_t RegionBegin = (*it)->SlabInfo->Base;
    uintptr_t RegionEnd = RegionBegin + (*it)->SlabInfo->RegionSize;

    if (Addr >= RegionBegin && AddrEnd < RegionEnd) {
      LiveRegion = *it;
      // Leave our loop
      break;
    }
  }

  // Couldn't find an active region that fit
  // Check reserved regions
  if (!LiveRegion) {
    // Didn't have a slab that fit this range
    // Check our reserved regions to see if we have one that fits
    for (auto it = ReservedRegions->begin(); it != ReservedRegions->end(); ++it) {
      ReservedVMARegion* ReservedRegion = *it;
      uintptr_t RegionEnd = ReservedRegion->Base + ReservedRegion->RegionSize;
      if (Addr >= ReservedRegion->Base && AddrEnd < RegionEnd) {
        // Found one, let's make it active
        LiveRegion = MakeRegionActive(it, 0);
        break;
      }
    }
  }

  return LiveRegion;
}

void* OSAllocator_64Bit::Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  if (addr != 0 && addr < reinterpret_cast<void*>(LOWER_BOUND)) {
    // If we are asked to allocate something outside of the 64-bit space
    // Then we need to just hand this to the OS
    return ::mmap(addr, length, prot, flags, fd, offset);
  }

  uint64_t Addr = reinterpret_cast<uint64_t>(addr);
  const bool FixedRequest = (flags & MAP_FIXED) || (flags & MAP_FIXED_NOREPLACE);
  if (!FixedRequest) {
    // Without MAP_FIXED the address is a HINT, and the kernel is free to round or
    // ignore it. Round it down to the host page rather than rejecting the request:
    // FEX's own internal placement hint (AllocatorHooks GetInternalPlacementHint) is
    // 4K-granular, and once the host page is 64K a strict check here turns every
    // internal VirtualAlloc into an EINVAL that the caller reads back as a non-null
    // pointer. (Unreachable on a 4K host: this allocator never engages there.)
    Addr = FEXCore::HostPage::AlignDown(Addr);
    addr = reinterpret_cast<void*>(Addr);
  }

  // Addr must be page aligned
  if (Addr & ~FEXCore::HostPage::Mask()) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  // If FD is provided then offset must also be page aligned
  if (fd != -1 && offset & ~FEXCore::HostPage::Mask()) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  // 64bit address overflow
  if (Addr + length < Addr) {
    return reinterpret_cast<void*>(-EOVERFLOW);
  }

  const bool Fixed = FixedRequest;
  length = FEXCore::HostPage::AlignUp(length);

  uint64_t AddrEnd = Addr + length;
  size_t NumberOfPages = length / FEXCore::HostPage::Size();

  // This needs a mutex to be thread safe
  auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(AllocationMutex, TLSThread);

  uint64_t AllocatedOffset {};
  LiveVMARegion* LiveRegion {};

  if (Fixed || Addr != 0) {
    LiveRegion = FindLiveRegionForAddress(Addr, AddrEnd);
  }

again:

  struct RangeResult final {
    LiveVMARegion* RegionInsertedInto;
    void* Ptr;
  };

  auto CheckIfRangeFits = [&AllocatedOffset](LiveVMARegion* Region, uint64_t length, int prot, int flags, int fd, off_t offset,
                                             uint64_t StartingPosition = 0) -> RangeResult {
    uint64_t AllocatedPage {~0ULL};
    uint64_t NumberOfPages = length >> FEXCore::HostPage::Shift();

    if (Region->FreeSpace >= length) {
      uint64_t LastAllocation =
        StartingPosition ? (StartingPosition - Region->SlabInfo->Base) >> FEXCore::HostPage::Shift() : Region->LastPageAllocation;
      size_t RegionNumberOfPages = Region->SlabInfo->RegionSize >> FEXCore::HostPage::Shift();


      if (Region->HadMunmap) {
        // Backward scan
        // We need to do a backward scan first to fill any holes
        // Otherwise we will very quickly run out of VMA regions (65k maximum)
        auto SearchResult = Region->UsedPages.BackwardScanForRange<true>(LastAllocation, NumberOfPages, Region->NumManagedPages);

        AllocatedPage = SearchResult.FoundElement;

        // If we didn't even have a one page free in the backward search, then unclaim HadMunmap.
        // Switching over to default forward search.
        if (SearchResult.FoundElement == ~0ULL && !SearchResult.FoundHole) {
          Region->HadMunmap = false;
        }
      }

      // Foward Scan
      if (AllocatedPage == ~0ULL) {
        auto SearchResult = Region->UsedPages.ForwardScanForRange<true>(LastAllocation, NumberOfPages, RegionNumberOfPages);
        AllocatedPage = SearchResult.FoundElement;
      }

      if (AllocatedPage != ~0ULL) {
        AllocatedOffset = Region->SlabInfo->Base + AllocatedPage * FEXCore::HostPage::Size();

        // We need to setup protections for this
        void* MMapResult = ::mmap(reinterpret_cast<void*>(AllocatedOffset), length, prot, (flags & ~MAP_FIXED_NOREPLACE) | MAP_FIXED, fd, offset);

        if (MMapResult == MAP_FAILED) {
          return RangeResult {Region, reinterpret_cast<void*>(-errno)};
        }
        return RangeResult {Region, MMapResult};
      }
    }

    return {};
  };

  if (Fixed) {
    // Found a region let's allocate to it
    if (LiveRegion) {
      // Found a slab that fits this
      if (flags & MAP_FIXED_NOREPLACE) {
        auto Fits = CheckIfRangeFits(LiveRegion, length, prot, flags, fd, offset, Addr);
        if (Fits.RegionInsertedInto && Fits.Ptr == reinterpret_cast<void*>(Addr)) {
          // We fit correctly
          AllocatedOffset = Addr;
        } else {
          // Intersected with something that already existed
          return reinterpret_cast<void*>(-EEXIST);
        }
      } else {
        // We need to mmap the file to this location
        void* MMapResult = ::mmap(reinterpret_cast<void*>(Addr), length, prot, (flags & ~MAP_FIXED_NOREPLACE) | MAP_FIXED, fd, offset);

        if (MMapResult == MAP_FAILED) {
          return reinterpret_cast<void*>(-errno);
        }

        AllocatedOffset = Addr;
      }
      // Fall through to live region tracking
    }
  } else {
    // Check our active slabs to see if we can fit the allocation
    // Slightly different than fixed since it doesn't need exact placement
    if (LiveRegion && Addr != 0) {
      // We found a LiveRegion that could hold this address. Let's try to place it
      // Check if this area is free
      auto Fits = CheckIfRangeFits(LiveRegion, length, prot, flags, fd, offset, Addr);
      if (Fits.RegionInsertedInto && Fits.Ptr == reinterpret_cast<void*>(Addr)) {
        // We fit correctly
        AllocatedOffset = Addr;
      } else {
        // Couldn't fit
        // We can continue past this point still
        LiveRegion = nullptr;
      }
    }

    if (!LiveRegion) {
      for (auto it = LiveRegions->begin(); it != LiveRegions->end(); ++it) {
        auto Fits = CheckIfRangeFits(*it, length, prot, flags, fd, offset);
        if (Fits.RegionInsertedInto && Fits.Ptr == reinterpret_cast<void*>(AllocatedOffset)) {
          // We fit correctly
          LiveRegion = Fits.RegionInsertedInto;
          break;
        }

        // Couldn't fit but mmap gave us an error
        if (!Fits.RegionInsertedInto && Fits.Ptr) {
          return Fits.Ptr;
        }

        // nullptr on both means no error and couldn't fit
      }
    }

    if (!LiveRegion) {
      // Couldn't find a fit in the live regions
      // Allocate a new reserved region
      size_t lengthOfLiveRegion = FEXCore::HostPage::AlignUp(LiveVMARegion::GetFEXManagedVMARegionSize(length));
      size_t lengthPlusManagedData = length + lengthOfLiveRegion;
      for (auto it = ReservedRegions->begin(); it != ReservedRegions->end(); ++it) {
        if ((*it)->RegionSize >= lengthPlusManagedData) {
          MakeRegionActive(it, 0);
          goto again;
        }
      }
    }
  }

  if (LiveRegion) {
    // Mark the pages as used
    uintptr_t RegionBegin = LiveRegion->SlabInfo->Base;
    uintptr_t MappedBegin = (AllocatedOffset - RegionBegin) >> FEXCore::HostPage::Shift();
    size_t PagesSet {};

    for (size_t i = 0; i < NumberOfPages; ++i) {
      PagesSet += LiveRegion->UsedPages.TestAndSet(MappedBegin + i) == false;
    }

    // Change our last allocation region
    LiveRegion->LastPageAllocation = MappedBegin + NumberOfPages;
    LiveRegion->FreeSpace -= PagesSet * FEXCore::HostPage::Size();
    LOGMAN_THROW_A_FMT(LiveRegion->FreeSpace <= LiveRegion->SlabInfo->RegionSize,
                       "Corrupt LiveRegion free space! 0x{:x} > 0x{:x}. After allocating 0x{:x} (0x{:x} overlapped)", LiveRegion->FreeSpace,
                       LiveRegion->SlabInfo->RegionSize, length, PagesSet);
  }

  if (!AllocatedOffset) {
    AllocatedOffset = -ENOMEM;
  }
  return reinterpret_cast<void*>(AllocatedOffset);
}

int OSAllocator_64Bit::Munmap(void* addr, size_t length) {
  if (addr < reinterpret_cast<void*>(LOWER_BOUND)) {
    // If we are asked to allocate something outside of the 64-bit space
    // Then we need to just hand this to the OS
    return ::munmap(addr, length);
  }

  uint64_t Addr = reinterpret_cast<uint64_t>(addr);

  if (Addr & ~FEXCore::HostPage::Mask()) {
    return -EINVAL;
  }

  if (length & ~FEXCore::HostPage::Mask()) {
    return -EINVAL;
  }

  if (Addr + length < Addr) {
    return -EOVERFLOW;
  }

  // This needs a mutex to be thread safe
  auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(AllocationMutex, TLSThread);

  length = FEXCore::HostPage::AlignUp(length);

  uintptr_t PtrBegin = reinterpret_cast<uintptr_t>(addr);
  uintptr_t PtrEnd = PtrBegin + length;
  // Walk all of the live ranges and find this slab then delete it
  for (auto it = LiveRegions->begin(); it != LiveRegions->end(); ++it) {
    uintptr_t RegionBegin = (*it)->SlabInfo->Base;
    uintptr_t RegionEnd = RegionBegin + (*it)->SlabInfo->RegionSize;

    if (RegionBegin <= PtrBegin && RegionEnd > PtrEnd) {
      // Live region fully encompasses slab range

      uint64_t FreedPages {};
      uint32_t SlabPageBegin = (PtrBegin - RegionBegin) >> FEXCore::HostPage::Shift();
      uint64_t PagesToFree = length >> FEXCore::HostPage::Shift();

      for (size_t i = 0; i < PagesToFree; ++i) {
        FreedPages += (*it)->UsedPages.TestAndClear(SlabPageBegin + i) ? 1 : 0;
      }

      if (FreedPages != 0) {
        // If we were contiuous freeing then make sure to give back the physical address space
        // If the region was locked then madvise won't remove the physical backing
        // This woul be a bug in the frontend application
        // So be careful with mlock/munlock
        ::madvise(addr, length, MADV_DONTNEED);
        ::mmap(addr, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      }

      (*it)->FreeSpace += FreedPages * FEXCore::HostPage::Size();

      // Set the last allocated page to the minimum of last page allocation or this slab
      // This will let us more quickly fill holes
      (*it)->LastPageAllocation = std::min((*it)->LastPageAllocation, SlabPageBegin);

      (*it)->HadMunmap = true;

      // XXX: Move region back to reserved list
      return 0;
    }
  }

  // If it didn't match at all then no error
  return 0;
}

void OSAllocator_64Bit::AllocateMemoryRegions(fextl::vector<FEXCore::Allocator::MemoryRegion>& Ranges) {
  // Need to allocate the ObjectAlloc up front. Find a region that is larger than our minimum size first.
  const size_t ObjectAllocSize = 64 * 1024 * 1024;

  for (auto& it : Ranges) {
    if (ObjectAllocSize > it.Size) {
      continue;
    }

    // Allocate up to 64 MiB the first allocation for an intrusive allocator
    mprotect(it.Ptr, ObjectAllocSize, PROT_READ | PROT_WRITE);

    // This enables the kernel to use transparent large pages in the allocator which can reduce memory pressure
    ::madvise(it.Ptr, ObjectAllocSize, MADV_HUGEPAGE);

    FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(it.Ptr), ObjectAllocSize);

    ObjectAlloc = new (it.Ptr) Alloc::ForwardOnlyIntrusiveArenaAllocator(it.Ptr, ObjectAllocSize);
    ReservedRegions = ObjectAlloc->new_construct(ReservedRegions, ObjectAlloc);
    LiveRegions = ObjectAlloc->new_construct(LiveRegions, ObjectAlloc);

    if (it.Size >= ObjectAllocSize) {
      // Modify region size
      it.Size -= ObjectAllocSize;
      (uint8_t*&)it.Ptr += ObjectAllocSize;
    }

    break;
  }

  if (!ObjectAlloc) {
    ERROR_AND_DIE_FMT("Couldn't allocate object allocator!");
  }

  for (auto [Ptr, AllocationSize] : Ranges) {
    // Skip using any regions that are <= two pages. FEX's VMA allocator requires two pages
    // for tracking data. So three pages are minimum for a single page VMA allocation.
    if (AllocationSize <= (FEXCore::HostPage::Size() * 2)) {
      continue;
    }

    ReservedVMARegion* Region = ObjectAlloc->new_construct<ReservedVMARegion>();
    Region->Base = reinterpret_cast<uint64_t>(Ptr);
    Region->RegionSize = AllocationSize;
    ReservedRegions->emplace_back(Region);
  }
}


OSAllocator_64Bit::OSAllocator_64Bit() {
  DetermineVASize();

  auto Ranges = FEXCore::Allocator::StealMemoryRegion(LOWER_BOUND, UPPER_BOUND);

  AllocateMemoryRegions(Ranges);
}

OSAllocator_64Bit::OSAllocator_64Bit(fextl::vector<FEXCore::Allocator::MemoryRegion>& Regions) {
  AllocateMemoryRegions(Regions);
}

OSAllocator_64Bit::~OSAllocator_64Bit() {
  // This needs a mutex to be thread safe
  auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(AllocationMutex, TLSThread);

  // Walk the pages and deallocate
  // First walk the live regions
  for (auto it = LiveRegions->begin(); it != LiveRegions->end(); ++it) {
    ::munmap(reinterpret_cast<void*>((*it)->SlabInfo->Base), (*it)->SlabInfo->RegionSize);
  }

  // Now walk the reserved regions
  for (auto it = ReservedRegions->begin(); it != ReservedRegions->end(); ++it) {
    ::munmap(reinterpret_cast<void*>((*it)->Base), (*it)->RegionSize);
  }
}

fextl::unique_ptr<Alloc::HostAllocator> Create64BitAllocator() {
  return fextl::make_unique<OSAllocator_64Bit>();
}

template<class T>
struct alloc_delete : public std::default_delete<T> {
  void operator()(T* ptr) const {
    if (ptr) {
      const auto size = sizeof(T);
      const auto MinPage = FEXCore::HostPage::AlignUp(size);

      std::destroy_at(ptr);
      ::munmap(ptr, MinPage);
    }
  }

  template<typename U>
  requires (std::is_base_of_v<U, T>)
  operator fextl::default_delete<U>() {
    return fextl::default_delete<U>();
  }
};

template<class T, class... Args>
requires (!std::is_array_v<T>)
fextl::unique_ptr<T> make_alloc_unique(FEXCore::Allocator::MemoryRegion& Base, Args&&... args) {
  const auto size = sizeof(T);
  // HOST: this carves a page off the FRONT of a stolen region and advances the region
  // pointer past it. Carving 4096 on a 64K kernel leaves every later region base 4K- but
  // not host-aligned, and every mprotect/mmap(MAP_FIXED) against it then returns EINVAL.
  const auto MinPage = FEXCore::HostPage::AlignUp(size);
  if (Base.Size < size || MinPage != FEXCore::HostPage::Size()) {
    ERROR_AND_DIE_FMT("Couldn't fit allocator in to page!");
  }

  auto ptr = ::mmap(Base.Ptr, MinPage, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (ptr == MAP_FAILED) {
    ERROR_AND_DIE_FMT("Couldn't allocate memory region");
  }

  FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(ptr), MinPage);

  // Remove the page from the base region.
  // Could be zero after this.
  Base.Size -= MinPage;
  Base.Ptr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(Base.Ptr) + MinPage);

  auto Result = ::new (ptr) T(std::forward<Args>(args)...);
  return fextl::unique_ptr<T, alloc_delete<T>>(Result);
}

fextl::unique_ptr<Alloc::HostAllocator> Create64BitAllocatorWithRegions(fextl::vector<FEXCore::Allocator::MemoryRegion>& Regions) {
  // This is a bit tricky as we can't allocate memory safely except from the Regions provided. Otherwise we might overwrite memory pages we
  // don't own. Scan the memory regions and find the smallest one.
  FEXCore::Allocator::MemoryRegion& Smallest = Regions[0];
  for (auto& it : Regions) {
    if (it.Size <= Smallest.Size) {
      Smallest = it;
    }
  }

  return make_alloc_unique<OSAllocator_64Bit>(Smallest, Regions);
}

} // namespace Alloc::OSAllocator

namespace FEXCore::Allocator {
void RegisterTLSData(FEXCore::Core::InternalThreadState* Thread) {
  Alloc::OSAllocator::TLSThread = Thread;
}

void UninstallTLSData(FEXCore::Core::InternalThreadState* Thread) {
  Alloc::OSAllocator::TLSThread = nullptr;
}
} // namespace FEXCore::Allocator
