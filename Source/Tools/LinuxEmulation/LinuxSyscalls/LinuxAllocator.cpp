// SPDX-License-Identifier: MIT

// ---------------------------------------------------------------------------
// Host page size (64K port, stage S2)
// ---------------------------------------------------------------------------
// The 32-bit allocator's bitmap is a *guest* concept: one bit per guest 4K page
// of the low 4GiB, and 32-bit guest addresses are a guest ABI quantity. The
// FEX_GUEST_PAGE_* names below are correct in that role.
//
// Stage S4 (design Part 2 section 4) splits that from the allocation side: every
// ::mmap/::munmap/::mremap/::shmat this file makes is now host-granular, while
// the bitmap keeps counting guest 4K pages. The two are bridged by GranulePages
// (host page / guest page, 1 on a 4K host) and by GranuleProt, which remembers
// the protection actually installed on each host granule so a sub-granule
// request can union rather than overwrite it.
//
// A guest request smaller than a host granule, or one that starts inside a
// granule another mapping already owns, is satisfied out of that existing
// mapping: the granule is only handed back to the kernel when nothing else in
// it is live. Freed sub-granule memory therefore stays resident, and a
// protection finer than the host page is tracked but not enforced. Those are
// the two documented relaxations of the permissive tier.
//
// Every one of these paths is guarded on GranulePages == 1 or on
// FEXCore::HostPage::MatchesGuest(), so the 4K build behaves exactly as before.
// ---------------------------------------------------------------------------

#include "Common/HostPageMapping.h"
#include "LinuxSyscalls/LinuxAllocator.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXHeaderUtils/Syscalls.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>

#include <algorithm>
#include <bitset>
#include <cstring>
#include <linux/mman.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/shm.h>

#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif

namespace FEX::HLE {
class MemAllocator32Bit final : public FEX::HLE::MemAllocator {
private:
  static constexpr uint64_t BASE_KEY = 16;
  const uint64_t TOP_KEY = 0xFFFF'F000ULL >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  const uint64_t TOP_KEY32BIT = 0x7FFF'F000ULL >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

public:
  MemAllocator32Bit() {
    // First 16 pages are taken by the Linux kernel
    for (size_t i = 0; i < 16; ++i) {
      MappedPages.set(i);
    }
    // Take the top page as well
    MappedPages.set(TOP_KEY);
    if (SearchDown) {
      LastScanLocation = TOP_KEY;
      LastKeyLocation = TOP_KEY;
      LastKeyLocation32Bit = TOP_KEY32BIT;
      FindPageRangePtr = &MemAllocator32Bit::FindPageRange_TopDown;
    } else {
      LastScanLocation = BASE_KEY;
      LastKeyLocation = BASE_KEY;
      FindPageRangePtr = &MemAllocator32Bit::FindPageRange;
    }
  }

  void* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) override;
  int Munmap(void* addr, size_t length) override;
  void* Mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) override;
  uint64_t Shmat(int shmid, const void* shmaddr, int shmflg, uint32_t* ResultAddress) override;
  uint64_t Shmdt(const void* shmaddr) override;
  static constexpr bool SearchDown = true;

  // ---- host granule helpers -------------------------------------------
  // GranulePages is 1 on a 4K host, so every one of these is the identity there
  // and the branches that test it fold away.

  [[nodiscard]]
  size_t AlignPagesUp(size_t Pages) const {
    return (Pages + GranulePages - 1) & ~(GranulePages - 1);
  }
  [[nodiscard]]
  uint64_t GranuleFloor(uint64_t Page) const {
    return Page & ~(GranulePages - 1);
  }
  [[nodiscard]]
  uint64_t GranuleCeil(uint64_t Page) const {
    return (Page + GranulePages - 1) & ~(GranulePages - 1);
  }

  // Caller must hold AllocMutex. True when any guest page of the granule
  // containing GranuleBase is mapped, ignoring [SkipBegin, SkipEnd).
  bool GranuleHasOtherLivePages(uint64_t GranuleBase, uint64_t SkipBegin, uint64_t SkipEnd) const {
    for (uint64_t Page = GranuleBase; Page < GranuleBase + GranulePages; ++Page) {
      if (Page >= SkipBegin && Page < SkipEnd) {
        continue;
      }
      if (Page < MappedPages.size() && MappedPages.test(Page)) {
        return true;
      }
    }
    return false;
  }

  // Caller must hold AllocMutex. Records the protection installed on the
  // granules covering [PageAddr, PageAddr + PagesLength). Reset replaces the
  // recorded value (the granule was just re-mapped and has no history);
  // otherwise it is unioned in, which is the permissive rule: nothing the guest
  // believes accessible may fault because a neighbour asked for less.
  void NoteGranuleProt(uint64_t PageAddr, size_t PagesLength, int prot, bool Reset) {
    if (GranulePages == 1) {
      return;
    }
    for (uint64_t G = GranuleFloor(PageAddr); G < GranuleCeil(PageAddr + PagesLength); G += GranulePages) {
      auto& Entry = GranuleProt[G];
      Entry = Reset ? prot : (Entry | prot);
    }
  }

  // Caller must hold AllocMutex. The protection a granule must end up with once
  // `prot` is added to it.
  int GranuleUnionProt(uint64_t GranuleBase, int prot) const {
    auto It = GranuleProt.find(GranuleBase);
    return It == GranuleProt.end() ? prot : (It->second | prot);
  }

  void* MmapSubGranule(uintptr_t Addr, size_t Length, int prot, int flags, int fd, off_t offset);

  // PageAddr is a page already shifted to page index
  // PagesLength is the number of pages
  void SetUsedPages(uint64_t PageAddr, size_t PagesLength) {
    // Set the range as mapped
    for (size_t i = 0; i < PagesLength; ++i) {
      MappedPages.set(PageAddr + i);
    }
  }

  void ReserveHostRange(uintptr_t Base, size_t Length) override {
    std::scoped_lock<std::mutex> lk {AllocMutex};
    const uint64_t PageAddr = Base >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
    const size_t PagesLength = FEXCore::AlignUp(Length, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
    for (size_t i = 0; i < PagesLength; ++i) {
      const uint64_t Page = PageAddr + i;
      if (Page >= HostReservedPages.size()) {
        break;
      }
      HostReservedPages.set(Page);
      // Also mark them used so the no-hint scan never proposes them.
      MappedPages.set(Page);
    }
  }

  // Caller must hold AllocMutex. PageAddr is a page index, PagesLength a count.
  //
  // Bounds-checked internally rather than at the call sites: Mremap validates
  // neither of its addresses before reaching here, and std::bitset::test
  // throws on an out-of-range index. A range outside the 32-bit space can
  // never overlap a reservation anyway.
  bool OverlapsHostReservation(uint64_t PageAddr, size_t PagesLength) const {
    for (size_t i = 0; i < PagesLength; ++i) {
      const uint64_t Page = PageAddr + i;
      if (Page >= HostReservedPages.size()) {
        break;
      }
      if (HostReservedPages.test(Page)) {
        return true;
      }
    }
    return false;
  }

  // PageAddr is a page already shifted to page index
  // PagesLength is the number of pages
  void SetFreePages(uint64_t PageAddr, size_t PagesLength) {
    // Set the range as unused
    for (size_t i = 0; i < PagesLength; ++i) {
      MappedPages.reset(PageAddr + i);
    }
  }

private:
  // Set that contains 4k mapped pages
  // This is the full 32bit memory range
  std::bitset<0x10'0000> MappedPages;
  // Subset of the above holding host-owned pages (thunk trampoline pools).
  // See MemAllocator::ReserveHostRange for why these need separate tracking.
  std::bitset<0x10'0000> HostReservedPages;
  fextl::map<uint32_t, int> PageToShm {};
  // Guest 4K pages per host page. 1 on a 4K host, 16 on a 64K one.
  const uint64_t GranulePages = FEXCore::HostPage::Size() >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  // Protection materialised on each host granule, keyed by the granule's first
  // guest page index. Only populated when GranulePages != 1.
  fextl::map<uint64_t, int> GranuleProt {};
  uint64_t LastScanLocation {};
  uint64_t LastKeyLocation {};
  uint64_t LastKeyLocation32Bit {};
  std::mutex AllocMutex {};
  uint64_t FindPageRange(uint64_t Start, size_t Pages) const;
  uint64_t FindPageRange_TopDown(uint64_t Start, size_t Pages) const;
  using FindHandler = uint64_t (MemAllocator32Bit::*)(uint64_t Start, size_t Pages) const;
  FindHandler FindPageRangePtr {};
};

uint64_t MemAllocator32Bit::FindPageRange(uint64_t Start, size_t Pages) const {
  // The result is handed to the kernel, so only host-granule boundaries are
  // proposable. GranuleCeil is the identity at 4K.
  Start = GranuleCeil(Start);
  // Linear range scan
  while (Start != TOP_KEY) {
    bool Free = true;
    if ((Start + Pages) > TOP_KEY) {
      return 0;
    }
    uint64_t Offset = 0;
    for (; Offset < Pages; ++Offset) {
      if (MappedPages.test(Start + Offset)) {
        Free = false;
        break;
      }
    }

    if (Free) {
      return Start;
    }
    Start = GranuleCeil(Start + Offset + 1);
  }

  return 0;
}

uint64_t MemAllocator32Bit::FindPageRange_TopDown(uint64_t Start, size_t Pages) const {
  // Start is the *highest* page of the candidate and the range returned is
  // [Start - Pages + 1, Start]. For that low end to be granule aligned, Start
  // has to be the last page of a granule and Pages a granule multiple (the
  // callers round it). Identity at 4K.
  Start = GranuleCeil(Start + 1) - 1;
  // Linear range scan
  while (Start >= BASE_KEY && Start <= TOP_KEY) {
    bool Free = true;

    uint64_t Offset = 0;
    for (; Offset < Pages; ++Offset) {
      if (MappedPages.test(Start - Offset)) {
        Free = false;
        break;
      }
    }

    if (Free) {
      // The pages tested free are [Start - Pages + 1, Start]; return the lowest.
      // Returning `Start - Offset` (== Start - Pages here) would hand back a
      // range shifted down one page, whose bottom page was never tested.
      return Start - (Pages - 1);
    }
    // Start - Offset is the page that blocked this candidate. Candidates are
    // granule-aligned blocks, so every block at or above that page's granule is
    // blocked too; resume at the last page of the granule below it. Identity at
    // 4K, where this is the old Start -= Offset + 1.
    const uint64_t Blocked = GranuleFloor(Start - Offset);
    if (Blocked == 0) {
      return 0;
    }
    Start = Blocked - 1;
  }

  return 0;
}

// Caller must hold AllocMutex.
//
// The guest asked for a MAP_FIXED range the host kernel cannot take verbatim:
// it starts or ends inside a host granule. Walk the granules it touches. One
// with nothing live outside the request is simply re-mapped; one with a live
// neighbour is left in place and written through, because re-mapping it would
// throw the neighbour away. Either way the bytes the guest asked for end up
// correct and the granule ends up with the union of every protection asked of
// it (design Part 2 section 4; the relaxation is that a protection finer than
// the granule is recorded but not enforced).
void* MemAllocator32Bit::MmapSubGranule(uintptr_t Addr, size_t Length, int prot, int flags, int fd, off_t offset) {
  const size_t HostSize = FEXCore::HostPage::Size();
  const uintptr_t End = Addr + Length;
  const bool Anonymous = (flags & MAP_ANONYMOUS) != 0;

  for (uintptr_t Granule = FEXCore::HostPage::AlignDown(Addr); Granule < End; Granule += HostSize) {
    const uintptr_t GranuleEnd = Granule + HostSize;
    const uintptr_t CoveredStart = std::max(Granule, Addr);
    const uintptr_t CoveredEnd = std::min(GranuleEnd, End);
    const uint64_t GranulePage = Granule >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

    const bool Preserve = GranuleHasOtherLivePages(GranulePage, CoveredStart >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT,
                                                   FEXCore::AlignUp(CoveredEnd, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >>
                                                     FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);

    if (!Preserve) {
      // Nothing in this granule needs keeping. Take it fresh, writable, so the
      // fill below can run whatever the guest asked for.
      void* Ptr = ::mmap(reinterpret_cast<void*>(Granule), HostSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
      if (Ptr == MAP_FAILED) {
        return reinterpret_cast<void*>(static_cast<int64_t>(-errno));
      }
      GranuleProt[GranulePage] = 0;
    } else if ((GranuleUnionProt(GranulePage, 0) & PROT_WRITE) == 0) {
      // Live neighbours, and the granule is not currently writable. Open a
      // window for the fill; the union below puts it back.
      ::mprotect(reinterpret_cast<void*>(Granule), HostSize, PROT_READ | PROT_WRITE);
    }

    if (Anonymous) {
      if (Preserve) {
        // A fresh granule is already zero; an existing one is not.
        memset(reinterpret_cast<void*>(CoveredStart), 0, CoveredEnd - CoveredStart);
      }
    } else if (!FEX::HostPageMapping::ReadFully(fd, reinterpret_cast<void*>(CoveredStart), CoveredEnd - CoveredStart,
                                                offset + (CoveredStart - Addr))) {
      return reinterpret_cast<void*>(static_cast<int64_t>(-errno));
    }

    const int Union = GranuleUnionProt(GranulePage, prot);
    GranuleProt[GranulePage] = Union;
    if (::mprotect(reinterpret_cast<void*>(Granule), HostSize, Union) != 0) {
      return reinterpret_cast<void*>(static_cast<int64_t>(-errno));
    }
  }

  // Whole granules were consumed, so mark them used: the scanner must not
  // propose anything inside them.
  const uint64_t FirstPage = GranuleFloor(Addr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
  const uint64_t LastPage = GranuleCeil(FEXCore::AlignUp(End, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
  SetUsedPages(FirstPage, LastPage - FirstPage);

  return reinterpret_cast<void*>(Addr);
}

void* MemAllocator32Bit::Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  std::scoped_lock<std::mutex> lk {AllocMutex};
  size_t PagesLength = FEXCore::AlignUp(length, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

  uintptr_t Addr = reinterpret_cast<uintptr_t>(addr);
  uintptr_t PageAddr = Addr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

  // Define MAP_FIXED_NOREPLACE ourselves to ensure we always parse this flag
  constexpr int FEX_MAP_FIXED_NOREPLACE = 0x100000;
  bool Fixed = ((flags & MAP_FIXED) || (flags & FEX_MAP_FIXED_NOREPLACE));

  // Both Addr and length must be page aligned
  if (Addr & ~FEXCore::Utils::FEX_GUEST_PAGE_MASK) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  // If we do have an fd then offset must be page aligned
  if (fd != -1 && offset & ~FEXCore::Utils::FEX_GUEST_PAGE_MASK) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  if (Addr + length > std::numeric_limits<uint32_t>::max()) {
    return reinterpret_cast<void*>(-EOVERFLOW);
  }

  // Check reserved range
  if (Fixed && PageAddr < 16) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  if (!Fixed) {
    // If we aren't mapping fixed the ignore the address input
    Addr = 0;
    PageAddr = 0;
  }

  // A shared file mapping at an offset the host page cannot represent cannot be
  // emulated by copying -- the guest would stop seeing other writers. Refuse.
  if (fd != -1 && !FEXCore::HostPage::IsAligned(offset) && (flags & (MAP_SHARED | MAP_SHARED_VALIDATE))) {
    return reinterpret_cast<void*>(-EINVAL);
  }

  // The kernel allocates in host granules whatever the guest asked for, so the
  // bitmap has to account for whole granules or a later allocation lands inside
  // one this request already consumed. Identity at 4K.
  const size_t HostPagesLength = AlignPagesUp(PagesLength);
  const size_t HostLength = HostPagesLength << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  // True when the file offset cannot be handed to the host kernel and the
  // content has to be pread into an anonymous reservation instead.
  const bool OffsetFallback = fd != -1 && !FEXCore::HostPage::IsAligned(offset);

  bool Map32Bit = flags & FEX::HLE::X86_64_MAP_32BIT;

  // Remove the MAP_32BIT flag if it exists now
  flags &= ~FEX::HLE::X86_64_MAP_32BIT;

  // FEX_A32_TRACE: stderr trace of every no-hint allocation failure and every
  // EEXIST collision recovery, for diagnosing 32-bit address-space issues.
  static const bool A32Trace = getenv("FEX_A32_TRACE") != nullptr;

  auto AllocateNoHint = [&]() -> void* {
    uint32_t Collisions = 0;
    uint64_t BottomPage = Map32Bit && (LastScanLocation >= LastKeyLocation32Bit) ? LastKeyLocation32Bit : LastScanLocation;
restart: {
  // Linear range scan
  uint64_t LowerPage = (this->*FindPageRangePtr)(BottomPage, HostPagesLength);
  if (LowerPage == 0) {
    // Try again but this time from the start
    BottomPage = Map32Bit ? LastKeyLocation32Bit : LastKeyLocation;
    LowerPage = (this->*FindPageRangePtr)(BottomPage, HostPagesLength);
  }

  uint64_t UpperPage = LowerPage + HostPagesLength;
  if (LowerPage == 0) {
    if (A32Trace) {
      char Buf[192];
      int N = snprintf(Buf, sizeof(Buf), "[A32] tid=%d ENOMEM len=0x%zx pages=0x%zx collisions=%u map32=%d\n", FHU::Syscalls::gettid(),
                       length, PagesLength, Collisions, Map32Bit ? 1 : 0);
      [[maybe_unused]] auto _ = write(2, Buf, N);
    }
    return reinterpret_cast<void*>(-ENOMEM);
  }
  {
    // Try and map the range
    void* const Target = reinterpret_cast<void*>(LowerPage << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
    void* MappedPtr;
    if (OffsetFallback) {
      // Reserve the granules anonymously and pread the file into them. The
      // reservation is private to this mapping, so the requested protection can
      // be applied to the whole of it.
      MappedPtr = ::mmap(Target, HostLength, PROT_READ | PROT_WRITE,
                         (flags & ~(MAP_SHARED | MAP_SHARED_VALIDATE | MAP_DENYWRITE)) | MAP_PRIVATE | MAP_ANONYMOUS | FEX_MAP_FIXED_NOREPLACE,
                         -1, 0);
      if (MappedPtr != MAP_FAILED) {
        if (!FEX::HostPageMapping::ReadFully(fd, MappedPtr, length, offset)) {
          const int Err = errno;
          ::munmap(MappedPtr, HostLength);
          return reinterpret_cast<void*>(static_cast<int64_t>(-Err));
        }
        if (prot != (PROT_READ | PROT_WRITE) && ::mprotect(MappedPtr, HostLength, prot) != 0) {
          const int Err = errno;
          ::munmap(MappedPtr, HostLength);
          return reinterpret_cast<void*>(static_cast<int64_t>(-Err));
        }
      }
    } else {
      MappedPtr = ::mmap(Target, HostLength, prot, flags | FEX_MAP_FIXED_NOREPLACE, fd, offset);
    }

    if (MappedPtr == MAP_FAILED && errno != EEXIST) {
      if (A32Trace) {
        char Buf[192];
        int N = snprintf(Buf, sizeof(Buf), "[A32] tid=%d mmap errno=%d len=0x%zx lower=0x%lx collisions=%u\n", FHU::Syscalls::gettid(), errno,
                         length, LowerPage << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, Collisions);
        [[maybe_unused]] auto _ = write(2, Buf, N);
      }
      return reinterpret_cast<void*>(-errno);
    } else if (MappedPtr == MAP_FAILED) {
      ++Collisions;
      // EEXIST: the host has a mapping in this range that MappedPages doesn't
      // know about. Probe the range and record the colliding pages so the next
      // scan skips them, rather than re-proposing overlapping ranges one page
      // at a time and eventually giving up with -EEXIST — an errno mmap can't
      // legally return, which guest allocators mishandle (steamrt libelf turns
      // it into a NULL elf_strptr and libcapsule crashes in strstr).
      bool MarkedAny = false;
      for (uint64_t Page = LowerPage; Page < UpperPage; ++Page) {
        unsigned char Vec;
        if (::mincore(reinterpret_cast<void*>(Page << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT), FEXCore::Utils::FEX_GUEST_PAGE_SIZE, &Vec) == 0) {
          MappedPages.set(Page);
          MarkedAny = true;
        }
      }
      if (!MarkedAny) {
        // Lost a race with a concurrent unmap; burn one page so every restart
        // makes forward progress and the scan is guaranteed to terminate.
        MappedPages.set(LowerPage);
      }
      goto restart;
    } else {
      if (SearchDown) {
        LastScanLocation = LowerPage;
      } else {
        LastScanLocation = UpperPage;
      }
      SetUsedPages(LowerPage, HostPagesLength);
      NoteGranuleProt(LowerPage, HostPagesLength, prot, true);
      if (A32Trace && Collisions != 0) {
        char Buf[192];
        int N = snprintf(Buf, sizeof(Buf), "[A32] tid=%d recovered len=0x%zx lower=0x%lx collisions=%u\n", FHU::Syscalls::gettid(), length,
                         LowerPage << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, Collisions);
        [[maybe_unused]] auto _ = write(2, Buf, N);
      }
      return MappedPtr;
    }
  }
}
  };

  // Find a region that fits our address
  if (Addr == 0) {
    return AllocateNoHint();
  } else {
    // The guest asked for a specific address and we are about to honour it
    // verbatim. If that would replace a host-owned trampoline pool, the host
    // would subsequently branch into guest-supplied bytes. Refuse instead.
    if (OverlapsHostReservation(PageAddr, PagesLength)) {
      return reinterpret_cast<void*>(-ENOMEM);
    }

    // The guest's address is 4K granular. If it or the length does not line up
    // with the host granule, or the file offset does not, the request cannot go
    // to the kernel as written and is emulated granule by granule instead.
    if (GranulePages != 1 && (!FEXCore::HostPage::IsAligned(Addr) || PagesLength != AlignPagesUp(PagesLength) || OffsetFallback)) {
      if ((flags & FEX_MAP_FIXED_NOREPLACE) && !(flags & MAP_FIXED)) {
        // The emulation below happily writes through an existing mapping, which
        // is what MAP_FIXED means and the opposite of what MAP_FIXED_NOREPLACE
        // means. Do the collision test the kernel would have done.
        for (size_t i = 0; i < PagesLength; ++i) {
          if (MappedPages.test(PageAddr + i)) {
            return reinterpret_cast<void*>(-EEXIST);
          }
        }
      }
      return MmapSubGranule(Addr, length, prot, flags, fd, offset);
    }

    void* MappedPtr = ::mmap(reinterpret_cast<void*>(PageAddr << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT),
                             PagesLength << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, prot, flags, fd, offset);

    if (MappedPtr != MAP_FAILED) {
      SetUsedPages(PageAddr, PagesLength);
      NoteGranuleProt(PageAddr, PagesLength, prot, true);
      return MappedPtr;
    } else {
      return reinterpret_cast<void*>(-errno);
    }
  }
  return 0;
}

int MemAllocator32Bit::Munmap(void* addr, size_t length) {
  std::scoped_lock<std::mutex> lk {AllocMutex};
  size_t PagesLength = FEXCore::AlignUp(length, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

  uintptr_t Addr = reinterpret_cast<uintptr_t>(addr);
  uintptr_t PageAddr = Addr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

  uintptr_t PageEnd = PageAddr + PagesLength;

  // Addr must be page aligned; length may be anything non-zero and is rounded
  // up to a page multiple, matching the kernel (mm/mmap.c: len = PAGE_ALIGN(len)).
  // Rejecting unaligned lengths here made every libelf ELF_C_READ_MMAP unmap
  // (raw file size) fail with EINVAL, silently leaking the whole file mapping.
  if (Addr & ~FEXCore::Utils::FEX_GUEST_PAGE_MASK) {
    return -EINVAL;
  }

  if (length == 0) {
    return -EINVAL;
  }

  if (Addr + length > std::numeric_limits<uint32_t>::max()) {
    return -EOVERFLOW;
  }

  // Check reserved range
  if (PageAddr < 16) {
    // Return success for these
    return 0;
  }

  // Never let the guest unmap a host trampoline pool out from under the host.
  // Report success without doing anything: the guest believes it owns this
  // range only because it was never told otherwise, and failing the unmap
  // would be more disruptive than leaking a page it was not using.
  if (OverlapsHostReservation(PageAddr, PagesLength)) {
    return 0;
  }

  if (GranulePages != 1) {
    // Host granularity: only a granule with nothing else live in it can go back
    // to the kernel. Drop the accounting first so the liveness test sees the
    // post-unmap state, then release the granules that emptied. A partly-freed
    // granule stays resident -- the documented relaxation -- but the guest
    // cannot observe it through the bitmap.
    for (uintptr_t Page = PageAddr; Page != PageEnd; ++Page) {
      MappedPages.reset(Page);
    }

    const uint64_t FirstGranule = GranuleFloor(PageAddr);
    const uint64_t LastGranule = GranuleCeil(PageEnd);
    for (uint64_t Granule = FirstGranule; Granule < LastGranule; Granule += GranulePages) {
      if (GranuleHasOtherLivePages(Granule, 0, 0)) {
        continue;
      }
      if (::munmap(reinterpret_cast<void*>(Granule << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT), FEXCore::HostPage::Size()) != 0) {
        return -errno;
      }
      GranuleProt.erase(Granule);
    }
    return 0;
  }

  // Unmap the whole range in a single syscall.
  //
  // This used to loop one page at a time, which is semantically identical -
  // munmap succeeds on ranges containing already-unmapped holes, and spans
  // multiple VMAs fine - but cost one syscall per page. A 32-bit guest routes
  // every munmap here (GuestMunmap dispatches on addr < 4GiB), so a glibc
  // free() of one mmap-threshold chunk became hundreds of syscalls, all under
  // AllocMutex and the caller's VMATracking lock. Measured on a 32-bit Unity
  // title: ~5000 munmap(4096) per second across 16 threads, serializing them.
  int Result = ::munmap(reinterpret_cast<void*>(PageAddr << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT),
                        PagesLength << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
  if (Result != 0) {
    return -errno;
  }

  // Bookkeeping only, no syscalls: drop the pages from the tracking bitset.
  while (PageAddr != PageEnd) {
    if (MappedPages.test(PageAddr)) {
      MappedPages.reset(PageAddr);
    }

    ++PageAddr;
  }

  return 0;
}

void* MemAllocator32Bit::Mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) {
  // Host granularity: the kernel moves and resizes whole granules, so the
  // bookkeeping counts them too. Identity at 4K. Plain grow/shrink/move works
  // because every address this allocator hands out is granule aligned; an
  // mremap of a guest range that is not is left to fail as the kernel fails it
  // (design Part 2 section 2 explicitly allows the exotic corners to EINVAL).
  size_t OldPagesLength = AlignPagesUp(FEXCore::AlignUp(old_size, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
  size_t NewPagesLength = AlignPagesUp(FEXCore::AlignUp(new_size, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);

  {
    std::scoped_lock<std::mutex> lk {AllocMutex};
    // Both ends matter: the source range would be moved (and unmapped) out
    // from under the host, and the destination range would be replaced.
    if (OverlapsHostReservation(reinterpret_cast<uintptr_t>(old_address) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, OldPagesLength) ||
        ((flags & MREMAP_FIXED) &&
         OverlapsHostReservation(reinterpret_cast<uintptr_t>(new_address) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, NewPagesLength))) {
      return reinterpret_cast<void*>(-ENOMEM);
    }

    if (flags & MREMAP_FIXED) {
      void* MappedPtr = ::mremap(old_address, old_size, new_size, flags, new_address);

      if (MappedPtr != MAP_FAILED) {
        if (!(flags & MREMAP_DONTUNMAP)) {
          // Unmap the old location
          uintptr_t OldAddr = reinterpret_cast<uintptr_t>(old_address);
          SetFreePages(OldAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, OldPagesLength);
        }

        // Map the new pages
        uintptr_t NewAddr = reinterpret_cast<uintptr_t>(MappedPtr);
        SetUsedPages(NewAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, NewPagesLength);
      } else {
        return reinterpret_cast<void*>(-errno);
      }
    } else {
      uintptr_t OldAddr = reinterpret_cast<uintptr_t>(old_address);
      uintptr_t OldPageAddr = OldAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

      if (NewPagesLength < OldPagesLength) {
        void* MappedPtr = ::mremap(old_address, old_size, new_size, flags & ~MREMAP_MAYMOVE);

        if (MappedPtr != MAP_FAILED) {
          // Clear the pages that we just shrunk
          size_t NewPagesLength = AlignPagesUp(FEXCore::AlignUp(new_size, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
          uintptr_t NewPageAddr = reinterpret_cast<uintptr_t>(MappedPtr) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
          SetFreePages(NewPageAddr + NewPagesLength, OldPagesLength - NewPagesLength);
          return MappedPtr;
        } else {
          return reinterpret_cast<void*>(-errno);
        }
      } else {
        // Scan the region forward from our first region's endd to see if it can be extended
        bool CanExtend {true};

        for (size_t i = OldPagesLength; i < NewPagesLength; ++i) {
          if (MappedPages[OldPageAddr + i]) {
            CanExtend = false;
            break;
          }
        }

        if (CanExtend) {
          void* MappedPtr = ::mremap(old_address, old_size, new_size, flags & ~MREMAP_MAYMOVE);

          if (MappedPtr != MAP_FAILED) {
            // Map the new pages
            size_t NewPagesLength = AlignPagesUp(FEXCore::AlignUp(new_size, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
            uintptr_t NewAddr = reinterpret_cast<uintptr_t>(MappedPtr);
            SetUsedPages(NewAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, NewPagesLength);
            return MappedPtr;
          } else if (!(flags & MREMAP_MAYMOVE)) {
            // We have one more chance if MAYMOVE is specified
            return reinterpret_cast<void*>(-errno);
          }
        }
      }
    }
  }

  // Flags can not contain MREMAP_FIXED at this point
  // Flags might contain MREMAP_MAYMOVE and/or MREMAP_DONTUNMAP
  // New Size is >= old size

  // First, try and allocate a region the size of the new size
  void* MappedPtr = this->Mmap(nullptr, new_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  std::scoped_lock<std::mutex> lk {AllocMutex};
  if (FEX::HLE::HasSyscallError(MappedPtr)) {
    // Couldn't find a region that fit our space
    return MappedPtr;
  }

  // Good news, we found a region
  // This will overwrite the previous mmap if it succeeds
  MappedPtr = ::mremap(old_address, old_size, new_size, flags | MREMAP_FIXED | MREMAP_MAYMOVE, MappedPtr);

  if (MappedPtr != MAP_FAILED) {
    if (!(flags & MREMAP_DONTUNMAP) && MappedPtr != old_address) {
      // If we have both MREMAP_DONTUNMAP not set and the new pointer is at a new location
      // Make sure to clear the old mapping
      uintptr_t OldAddr = reinterpret_cast<uintptr_t>(old_address);
      SetFreePages(OldAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, OldPagesLength);
    }

    // Map the new pages
    size_t FinalPagesLength = AlignPagesUp(FEXCore::AlignUp(new_size, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
    uintptr_t NewAddr = reinterpret_cast<uintptr_t>(MappedPtr);
    SetUsedPages(NewAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT, FinalPagesLength);
    return MappedPtr;
  }

  // Failed
  return reinterpret_cast<void*>(-errno);
}

uint64_t MemAllocator32Bit::Shmat(int shmid, const void* shmaddr, int shmflg, uint32_t* ResultAddress) {
  std::scoped_lock<std::mutex> lk {AllocMutex};

  if (shmaddr != nullptr) {
    // shmaddr must be valid
    uint64_t Result = reinterpret_cast<uint64_t>(::shmat(shmid, shmaddr, shmflg));
    if (Result != -1) {
      uint32_t SmallRet = Result >> 32;
      if (!(SmallRet == 0 || SmallRet == ~0U)) {
        LOGMAN_MSG_A_FMT("Syscall returning something with data in the upper 32bits! BUG!");
        return -ENOMEM;
      }

      uintptr_t NewAddr = reinterpret_cast<uintptr_t>(Result);
      uintptr_t NewPageAddr = NewAddr >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;

      // Add to the map
      PageToShm[NewPageAddr] = shmid;

      *ResultAddress = Result;

      // We must get the shm size and track it
      struct shmid_ds buf {};

      if (shmctl(shmid, IPC_STAT, &buf) == 0) {
        // Map the new pages
        size_t NewPagesLength = buf.shm_segsz >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
        SetUsedPages(NewPageAddr, NewPagesLength);
      }

      // Zero on working result
      Result = 0;
    } else {
      Result = -errno;
    }
    return Result;
  } else {
    // We must get the shm size and track it
    struct shmid_ds buf {};
    uint64_t PagesLength {};

    if (shmctl(shmid, IPC_STAT, &buf) == 0) {
      // Host granularity: shmat's address has to satisfy SHMLBA, which is the
      // host page, and the segment consumes whole granules. Identity at 4K.
      PagesLength = AlignPagesUp(FEXCore::AlignUp(buf.shm_segsz, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT);
    } else {
      return -EINVAL;
    }

    bool Wrapped = false;
    uint64_t BottomPage = LastScanLocation;
restart: {
  // Linear range scan
  uint64_t LowerPage = (this->*FindPageRangePtr)(BottomPage, PagesLength);
  if (LowerPage == 0) {
    // Try again but this time from the start
    BottomPage = LastKeyLocation;
    LowerPage = (this->*FindPageRangePtr)(BottomPage, PagesLength);
  }

  uint64_t UpperPage = LowerPage + PagesLength;
  if (LowerPage == 0) {
    return -ENOMEM;
  }
  {
    // Try and map the range
    void* MappedPtr = ::shmat(shmid, reinterpret_cast<const void*>(LowerPage << FEXCore::Utils::FEX_GUEST_PAGE_SHIFT), shmflg);

    if (MappedPtr == MAP_FAILED) {
      if (UpperPage == TOP_KEY) {
        BottomPage = LastKeyLocation;
        Wrapped = true;
        goto restart;
      } else if (Wrapped && LowerPage >= LastScanLocation) {
        // We linear scanned the entire memory range. Give up
        return -errno;
      } else {
        // Try again
        BottomPage += PagesLength;
        goto restart;
      }
    } else {
      if (SearchDown) {
        LastScanLocation = LowerPage;
      } else {
        LastScanLocation = UpperPage;
      }
      // Set the range as mapped
      SetUsedPages(LowerPage, PagesLength);

      *ResultAddress = reinterpret_cast<uint64_t>(MappedPtr);

      // Add to the map
      PageToShm[LowerPage] = shmid;

      // Zero on working result
      return 0;
    }
  }
}
  }
}
uint64_t MemAllocator32Bit::Shmdt(const void* shmaddr) {
  std::scoped_lock<std::mutex> lk {AllocMutex};

  uint32_t AddrPage = reinterpret_cast<uint64_t>(shmaddr) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  auto it = PageToShm.find(AddrPage);

  if (it == PageToShm.end()) {
    // Page wasn't mapped
    return -EINVAL;
  }

  int shmid = it->second;
  struct shmid_ds buf {};
  if (shmctl(shmid, IPC_STAT, &buf) == 0) {
    size_t PagesLength = FEXCore::AlignUp(buf.shm_segsz, FEXCore::Utils::FEX_GUEST_PAGE_SIZE) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
    SetFreePages(AddrPage, PagesLength);
  } else {
    LOGMAN_MSG_A_FMT("Failed to get shm size during shmdt");
  }

  uint64_t Result = ::shmdt(shmaddr);

  if (Result == 0) {
    PageToShm.erase(it);
  }

  SYSCALL_ERRNO();
}

class MemAllocatorPassThrough final : public FEX::HLE::MemAllocator {
public:
  void* Mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) override {
    uint64_t Result = (uint64_t)::mmap(addr, length, prot, flags, fd, offset);
    if (Result == ~0ULL) {
      return reinterpret_cast<void*>(-errno);
    }
    return reinterpret_cast<void*>(Result);
  }

  int Munmap(void* addr, size_t length) override {
    uint64_t Result = (uint64_t)::munmap(addr, length);
    SYSCALL_ERRNO();
  }

  void* Mremap(void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) override {
    uint64_t Result = (uint64_t)::mremap(old_address, old_size, new_size, flags, new_address);
    if (Result == ~0ULL) {
      return reinterpret_cast<void*>(-errno);
    }
    return reinterpret_cast<void*>(Result);
  }

  uint64_t Shmat(int shmid, const void* shmaddr, int shmflg, uint32_t* ResultAddress) override {
    uint64_t Result = (uint64_t)::shmat(shmid, reinterpret_cast<const void*>(shmaddr), shmflg);
    if (Result != ~0ULL) {
      *ResultAddress = Result;
      Result = 0;
    }
    SYSCALL_ERRNO();
  }

  uint64_t Shmdt(const void* shmaddr) override {
    uint64_t Result = ::shmdt(shmaddr);
    SYSCALL_ERRNO();
  }
};

fextl::unique_ptr<FEX::HLE::MemAllocator> Create32BitAllocator() {
  return fextl::make_unique<MemAllocator32Bit>();
}

fextl::unique_ptr<FEX::HLE::MemAllocator> CreatePassthroughAllocator() {
  return fextl::make_unique<MemAllocatorPassThrough>();
}

} // namespace FEX::HLE
