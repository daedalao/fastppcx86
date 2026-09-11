// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: Guest memory syscalls on a host page larger than the guest's
$end_info$
*/

#include "Common/HostPageMapping.h"

#include "LinuxSyscalls/GranuleMemory.h"
#include "LinuxSyscalls/GranuleTable.h"
#include "LinuxSyscalls/HostOwnedRanges.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iterator>
#include <sys/mman.h>
#include <unistd.h>

namespace FEX::HLE::Granule {
using FEX::HLE::VMATracking::GranuleTable;

namespace {
  constexpr uint64_t GuestPageSize = FEXCore::Utils::FEX_GUEST_PAGE_SIZE;
  constexpr uint64_t GuestPageMask = FEXCore::Utils::FEX_GUEST_PAGE_MASK;

  // Linux spells these in <linux/mman.h>, which we do not include here.
  constexpr int FEX_MREMAP_MAYMOVE = 1;
  constexpr int FEX_MREMAP_FIXED = 2;
  constexpr int FEX_MREMAP_DONTUNMAP = 4;

  bool HostAligned(uint64_t Value) {
    return FEXCore::HostPage::IsAligned(Value);
  }

  // One line per distinct unrepresentable corner, not one per occurrence: a
  // guest that retries in a loop must not be able to fill the log, but a corner
  // we have never seen in the wild must be impossible to miss the first time it
  // happens. Each call site owns its own flag.
  void LogOnce(std::atomic<bool>& Flag, const char* What, uint64_t Base, uint64_t Length) {
    bool Expected = false;
    if (!Flag.compare_exchange_strong(Expected, true)) {
      return;
    }
    LogMan::Msg::EFmt("64K granule emulation: refusing {} at [0x{:x}, 0x{:x}) with EINVAL. "
                      "The host page is {} and this request cannot be represented by copy. "
                      "See docs/PAGE_SIZE_64K_PLAN.md Part 2 §2. Reported once.",
                      What, Base, Base + Length, FEXCore::HostPage::Size());
  }

  std::atomic<bool> LoggedSharedMmap {false};
  std::atomic<bool> LoggedSharedConvert {false};
  std::atomic<bool> LoggedMremapCorner {false};

  struct Handler {
    static FEX::HLE::SyscallHandler* Get() {
      return FEX::HLE::_SyscallHandler;
    }
  };

  // Is any guest page of [GranuleBase, GranuleBase+HostSize) outside
  // [ExcludeBase, ExcludeEnd) something the guest still owns? Consults the
  // granule table first (authoritative once FEX has subdivided the granule) and
  // falls back to VMATracking (authoritative for a granule the guest mapped
  // whole and never subdivided).
  // - VMATracking::Mutex must be held.
  bool HasLiveSiblings(const FEX::HLE::VMATracking::VMATracking& Tracking, uint64_t GranuleBase, uint64_t ExcludeBase, uint64_t ExcludeEnd) {
    const uint64_t HostSize = FEXCore::HostPage::Size();
    const auto* Entry = Tracking.Granules.Find(GranuleBase);
    for (uint64_t Page = GranuleBase; Page < GranuleBase + HostSize; Page += GuestPageSize) {
      if (Page >= ExcludeBase && Page < ExcludeEnd) {
        continue;
      }
      if (Entry) {
        if (Entry->NibbleAt(GranuleTable::IndexOf(Page)) & GranuleTable::PageLive) {
          return true;
        }
        continue;
      }
      if (Tracking.FindVMAEntry(Page) != Tracking.VMAs.end()) {
        return true;
      }
    }
    return false;
  }

  // Copy what VMATracking knows about this granule into the granule table, for
  // every page that the table does not already describe. This is what makes the
  // first sub-granule operation on a granule the guest mapped whole not lose the
  // siblings' protections.
  // - VMATracking::Mutex must be unique_locked.
  void SeedGranuleFromVMAs(FEX::HLE::VMATracking::VMATracking& Tracking, uint64_t GranuleBase) {
    const uint64_t HostSize = FEXCore::HostPage::Size();
    auto& Entry = Tracking.Granules.FindOrCreate(GranuleBase);
    for (uint64_t Page = GranuleBase; Page < GranuleBase + HostSize; Page += GuestPageSize) {
      const uint64_t Index = GranuleTable::IndexOf(Page);
      if (Entry.NibbleAt(Index) & GranuleTable::PageLive) {
        continue;
      }
      auto VMA = Tracking.FindVMAEntry(Page);
      if (VMA == Tracking.VMAs.end()) {
        continue;
      }
      int Prot = PROT_NONE;
      if (VMA->second.Prot.Readable) {
        Prot |= PROT_READ;
      }
      if (VMA->second.Prot.Writable) {
        Prot |= PROT_WRITE;
      }
      if (VMA->second.Prot.Executable) {
        Prot |= PROT_EXEC;
      }
      Entry.SetNibbleAt(Index, GranuleTable::NibbleFromProt(Prot));
      // The kernel's protection for a granule the guest mapped whole is that
      // mapping's protection; record it so the first RematerialiseIfNeeded can
      // tell whether it needs a syscall at all.
      Entry.HostProt = static_cast<uint8_t>(static_cast<int>(Entry.HostProt) | Prot);
    }
  }

  // Does any VMA overlapping this granule have MAP_SHARED semantics? Such a
  // granule cannot be converted to a private anonymous mapping without silently
  // breaking the sharing, which is the one thing the permissive tier is not
  // allowed to do.
  // - VMATracking::Mutex must be held.
  bool GranuleHasSharedMapping(const FEX::HLE::VMATracking::VMATracking& Tracking, uint64_t GranuleBase) {
    const uint64_t HostSize = FEXCore::HostPage::Size();
    for (uint64_t Page = GranuleBase; Page < GranuleBase + HostSize; Page += GuestPageSize) {
      auto VMA = Tracking.FindVMAEntry(Page);
      if (VMA != Tracking.VMAs.end() && VMA->second.Flags.Shared) {
        return true;
      }
    }
    return false;
  }

  /**
   * Make [GranuleBase, GranuleBase+HostSize) a private anonymous mapping that
   * FEX owns, preserving the bytes of every guest page in it except
   * [ReplaceBase, ReplaceEnd).
   *
   * This is the primitive behind every sub-granule operation. Once a granule is
   * FEXBacked, FEX may mprotect it and write into it freely; before that, its
   * backing is whatever the guest's own host-aligned mapping put there.
   *
   * Returns 0 on success or a negative errno.
   * - VMATracking::Mutex must be unique_locked.
   */
  int64_t MakeGranuleFEXBacked(FEX::HLE::VMATracking::VMATracking& Tracking, uint64_t GranuleBase, uint64_t ReplaceBase, uint64_t ReplaceEnd) {
    const uint64_t HostSize = FEXCore::HostPage::Size();

    if (HostOwnedRanges::Overlaps(GranuleBase, HostSize)) {
      // A granule shared with one of FEX's own mappings. Refuse rather than
      // remap it: HostOwnedRanges is snapshotted before any guest mapping
      // exists, so nothing the guest legitimately owns is in it, and this is
      // the granularity case the table was widened to host pages for.
      HostOwnedRanges::ReportRefusal("sub-granule mmap", GranuleBase, HostSize);
      return -ENOMEM;
    }

    auto* Entry = Tracking.Granules.FindMutable(GranuleBase);
    if (Entry && Entry->FEXBacked) {
      // Already ours. Make sure we can write the new content into it; the union
      // protection is restored by the caller's RematerialiseIfNeeded.
      if (!(Entry->HostProt & PROT_WRITE)) {
        const int Want = FEX::HLE::HardwareTSO::ApplyGuestProt(Entry->HostProt | PROT_READ | PROT_WRITE);
        if (::mprotect(reinterpret_cast<void*>(GranuleBase), HostSize, Want) != 0) {
          return -errno;
        }
        Entry->HostProt = static_cast<uint8_t>(Entry->HostProt | PROT_READ | PROT_WRITE);
      }
      return 0;
    }

    const bool Preserve = HasLiveSiblings(Tracking, GranuleBase, ReplaceBase, ReplaceEnd);
    if (Preserve && GranuleHasSharedMapping(Tracking, GranuleBase)) {
      LogOnce(LoggedSharedConvert, "conversion of a MAP_SHARED granule to private backing", GranuleBase, HostSize);
      return -EINVAL;
    }

    // Seed the siblings' intended protections before the mapping under them
    // changes; after the mmap below, VMATracking still describes the guest's
    // view (which is the point) but the kernel no longer backs it the same way.
    if (Preserve) {
      SeedGranuleFromVMAs(Tracking, GranuleBase);
    }

    fextl::vector<uint8_t> Saved;
    if (Preserve) {
      Entry = Tracking.Granules.FindMutable(GranuleBase);
      const int Current = Entry ? static_cast<int>(Entry->HostProt) : PROT_READ;
      if (!(Current & PROT_READ)) {
        // Nothing in this granule is readable right now -- a guest that mapped
        // it PROT_NONE, or a write-only mapping. Add PROT_READ for the copy.
        // This window is visible to other guest threads; at the permissive tier
        // that is the same class of relaxation as the tier itself (a protection
        // stricter than the granule union is not enforced), so it costs no
        // guarantee we still make.
        if (::mprotect(reinterpret_cast<void*>(GranuleBase), HostSize, FEX::HLE::HardwareTSO::ApplyGuestProt(Current | PROT_READ)) != 0) {
          return -errno;
        }
      }
      Saved.resize(HostSize);
      std::memcpy(Saved.data(), reinterpret_cast<const void*>(GranuleBase), HostSize);
    }

    void* Mapped = ::mmap(reinterpret_cast<void*>(GranuleBase), HostSize, FEX::HLE::HardwareTSO::ApplyGuestProt(PROT_READ | PROT_WRITE),
                          MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Mapped == MAP_FAILED) {
      return -errno;
    }

    if (!Saved.empty()) {
      std::memcpy(reinterpret_cast<void*>(GranuleBase), Saved.data(), HostSize);
      // The replaced sub-range must not keep the old bytes; the caller fills it
      // (zeros for anonymous, file content for a file mapping) immediately
      // after, but zero it here so that a caller that fills nothing still gets
      // anonymous-mmap semantics.
      const uint64_t FillBase = std::max(ReplaceBase, GranuleBase);
      const uint64_t FillEnd = std::min(ReplaceEnd, GranuleBase + HostSize);
      if (FillEnd > FillBase) {
        std::memset(reinterpret_cast<void*>(FillBase), 0, FillEnd - FillBase);
      }
    }

    auto& NewEntry = Tracking.Granules.FindOrCreate(GranuleBase);
    NewEntry.FEXBacked = true;
    NewEntry.HostProt = PROT_READ | PROT_WRITE;
    return 0;
  }

  // pread [Base, End) from fd at FileOffset. Shares S4a's ReadFully (short
  // reads, EINTR, EOF-is-not-an-error), whose contract is that the destination
  // is already zero -- which MakeGranuleFEXBacked guarantees for exactly the
  // range we fill here.
  int64_t FillFromFile(uint64_t Base, uint64_t End, int fd, off_t FileOffset) {
    if (!FEX::HostPageMapping::ReadFully(fd, reinterpret_cast<void*>(Base), End - Base, static_cast<uint64_t>(FileOffset))) {
      return -errno;
    }
    return 0;
  }
} // namespace

bool Active() {
  return GranuleTable::Active();
}

bool Mmap(FEXCore::Core::InternalThreadState* Thread, bool Is64Bit, void* addr, size_t length, int prot, int flags, int fd, off_t offset,
          uint64_t* Result) {
  if (!Active() || !length) {
    return false;
  }

  uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  uint64_t GuestEnd = GuestBase + Size;
  const bool Anonymous = (flags & MAP_ANONYMOUS) != 0 || fd < 0;

  if (!(flags & MAP_FIXED)) {
    // The kernel picks the address, and it picks a host-aligned one, which is
    // 4K-aligned and therefore legal for the guest. The only thing that can
    // still be unrepresentable is a file offset the host cannot take.
    if (!FEX::HostPageMapping::RequiresFallback(GuestBase, static_cast<uint64_t>(offset), flags, fd)) {
      return false;
    }
  } else if (HostAligned(GuestBase) && HostAligned(GuestEnd) &&
             !FEX::HostPageMapping::RequiresFallback(GuestBase, static_cast<uint64_t>(offset), flags, fd)) {
    // Whole granules, representable offset: the normal path handles it, with
    // all of its SMC, HWTSO and code-cache bookkeeping intact.
    return false;
  } else if (!(GuestBase & ~GuestPageMask)) {
    // Fall through to the emulation below.
  } else {
    // MAP_FIXED at a non-4K-aligned address is EINVAL on any kernel.
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }

  if ((flags & MAP_SHARED) || (flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE) {
    // Emulating an unrepresentable mapping means copying its contents into a
    // private anonymous granule. A shared mapping's whole contract is that the
    // copy does not exist. Refuse loudly rather than silently desynchronise.
    // Survey (PAGE_SIZE_64K_PLAN §2): rare, because X SHM segments and GL
    // buffers arrive host-aligned -- FEX allocates them.
    LogOnce(LoggedSharedMmap, Anonymous ? "unaligned MAP_SHARED anonymous mmap" : "unaligned MAP_SHARED file mmap", GuestBase, Size);
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }

  auto* Hndl = Handler::Get();
  const uint64_t HostSize = FEXCore::HostPage::Size();

  if (!(flags & MAP_FIXED)) {
    // The guest let the kernel choose, and the only reason we are here is a file
    // offset the host cannot take. Reserve a granule-rounded private anonymous
    // span first and then treat the request as fixed at the address we got: the
    // kernel hands back a host-aligned address, which is 4K-aligned and so a
    // perfectly legal answer to a non-fixed mmap.
    void* Reserved = ::mmap(nullptr, FEXCore::AlignUp(Size, HostSize), FEX::HLE::HardwareTSO::ApplyGuestProt(PROT_READ | PROT_WRITE),
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Reserved == MAP_FAILED) {
      *Result = static_cast<uint64_t>(-errno);
      return true;
    }
    GuestBase = reinterpret_cast<uint64_t>(Reserved);
    GuestEnd = GuestBase + Size;
  }

  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);

  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;

    if (!(flags & MAP_FIXED)) {
      // Everything the reservation covers is ours now; record it so the loop
      // below does not try to preserve siblings that do not exist.
      for (uint64_t G = GranuleStart; G < GranuleEnd; G += HostSize) {
        auto& E = Tracking.Granules.FindOrCreate(G);
        E.FEXBacked = true;
        E.HostProt = PROT_READ | PROT_WRITE;
        E.SMCOverlay = PROT_NONE;
      }
    }

    for (uint64_t G = GranuleStart; G < GranuleEnd; G += HostSize) {
      const uint64_t SubBase = std::max(GuestBase, G);
      const uint64_t SubEnd = std::min(GuestEnd, G + HostSize);
      const bool WholeGranule = (SubBase == G) && (SubEnd == G + HostSize);
      const off_t FileOffset = Anonymous ? 0 : offset + static_cast<off_t>(SubBase - GuestBase);

      if (WholeGranule && (Anonymous || HostAligned(static_cast<uint64_t>(FileOffset)))) {
        // Representable on its own: let the kernel do it directly, exactly as
        // the normal path would have.
        if (HostOwnedRanges::Overlaps(G, HostSize)) {
          HostOwnedRanges::ReportRefusal("mmap", G, HostSize);
          *Result = static_cast<uint64_t>(-ENOMEM);
          return true;
        }
        void* M = ::mmap(reinterpret_cast<void*>(G), HostSize, FEX::HLE::HardwareTSO::ApplyGuestProt(prot), flags | MAP_FIXED,
                         Anonymous ? -1 : fd, FileOffset);
        if (M == MAP_FAILED) {
          *Result = static_cast<uint64_t>(-errno);
          return true;
        }
        Tracking.Granules.SetIntended(G, HostSize, prot);
        Tracking.Granules.NoteHostProt(G, prot);
        auto* E = Tracking.Granules.FindMutable(G);
        if (E) {
          E->FEXBacked = false;
          E->SMCOverlay = PROT_NONE;
        }
        continue;
      }

      const int64_t Prepared = MakeGranuleFEXBacked(Tracking, G, SubBase, SubEnd);
      if (Prepared < 0) {
        *Result = static_cast<uint64_t>(Prepared);
        return true;
      }

      if (!Anonymous) {
        const int64_t Filled = FillFromFile(SubBase, SubEnd, fd, FileOffset);
        if (Filled < 0) {
          *Result = static_cast<uint64_t>(Filled);
          return true;
        }
      } else {
        // MakeGranuleFEXBacked only zeroes the replaced range when it had
        // siblings to preserve; a granule it mapped fresh is already zero.
        // Zeroing again is cheap next to the mmap and makes the post-condition
        // unconditional.
        std::memset(reinterpret_cast<void*>(SubBase), 0, SubEnd - SubBase);
      }

      Tracking.Granules.SetIntended(SubBase, SubEnd - SubBase, prot);
      Tracking.Granules.RematerialiseIfNeeded(G);
    }

    // VMATracking keeps describing what the GUEST asked for, at guest
    // granularity. That is the fiction discipline of §7: the granule table is
    // the only place the host's coarser reality is recorded.
    std::optional<FEXCore::ExecutableFileSectionInfo> CachedSection;
    Hndl->TrackMmap(Thread, GuestBase, Size, prot, flags, fd, offset, CachedSection);
  }

  Hndl->InvalidateCodeRangeIfNecessary(Thread, GuestBase, Size);
  *Result = GuestBase;
  return true;
}

bool Munmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, uint64_t* Result) {
  if (!Active() || !length) {
    return false;
  }

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  if (GuestBase & ~GuestPageMask) {
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GuestEnd = GuestBase + Size;

  if (HostAligned(GuestBase) && HostAligned(GuestEnd)) {
    // Whole granules: the normal path unmaps exactly what the guest asked for.
    return false;
  }

  auto* Hndl = Handler::Get();
  const uint64_t HostSize = FEXCore::HostPage::Size();
  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);

  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;

    if (HostOwnedRanges::Overlaps(GranuleStart, GranuleEnd - GranuleStart)) {
      HostOwnedRanges::ReportRefusal("munmap", GuestBase, Size);
      *Result = static_cast<uint64_t>(-EINVAL);
      return true;
    }

    for (uint64_t G = GranuleStart; G < GranuleEnd; G += HostSize) {
      const uint64_t SubBase = std::max(GuestBase, G);
      const uint64_t SubEnd = std::min(GuestEnd, G + HostSize);

      // Record what the guest still owns in this granule before taking anything
      // away, or a granule it mapped whole would look empty after the first
      // partial munmap and be unmapped out from under its own live siblings.
      SeedGranuleFromVMAs(Tracking, G);
      Tracking.Granules.ClearIntended(SubBase, SubEnd - SubBase, nullptr);

      auto* Entry = Tracking.Granules.FindMutable(G);
      if (Entry && Entry->Empty()) {
        // The whole granule is dead: now, and only now, does the memory go back
        // to the kernel and the contents get scrubbed.
        if (::munmap(reinterpret_cast<void*>(G), HostSize) != 0) {
          *Result = static_cast<uint64_t>(-errno);
          return true;
        }
        Tracking.Granules.Forget(G);
        continue;
      }
      // A sibling is still live, so the granule stays mapped. The unmapped
      // pages' intended protection is now PROT_NONE (they are not live at all),
      // which drops out of the union; their contents stay resident until the
      // granule empties. That residency is the RSS cost §6 signs up for.
      Tracking.Granules.RematerialiseIfNeeded(G);
    }

    Hndl->TrackMunmap(Thread, addr, Size);
  }

  Hndl->InvalidateCodeRangeIfNecessary(Thread, GuestBase, Size);
  *Result = 0;
  return true;
}

bool Mprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, uint64_t* Result) {
  if (!Active() || !length) {
    return false;
  }

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  if (GuestBase & ~GuestPageMask) {
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GuestEnd = GuestBase + Size;

  if (HostAligned(GuestBase) && HostAligned(GuestEnd)) {
    auto* Hndl = Handler::Get();
    // Whole granules, but the granule table may still hold entries for them
    // (from an earlier sub-granule operation). Keep the table in step, then let
    // the normal path do the work and all of its SMC bookkeeping.
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;
    if (!Tracking.Granules.Empty()) {
      for (uint64_t G = GuestBase; G < GuestEnd; G += FEXCore::HostPage::Size()) {
        if (Tracking.Granules.Find(G)) {
          Tracking.Granules.SetIntended(G, FEXCore::HostPage::Size(), prot);
          Tracking.Granules.NoteHostProt(G, prot);
        }
      }
    }
    return false;
  }

  // The hot path: glibc arms a 4K PROT_NONE guard at the low end of every
  // pthread stack (PAGE_SIZE_64K_PLAN finding 8), so this runs at every
  // pthread_create under a threaded guest.
  auto* Hndl = Handler::Get();
  const uint64_t HostSize = FEXCore::HostPage::Size();
  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);

  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;

    if (HostOwnedRanges::Overlaps(GranuleStart, GranuleEnd - GranuleStart)) {
      const auto Hit = HostOwnedRanges::FindOverlap(GranuleStart, GranuleEnd - GranuleStart);
      HostOwnedRanges::ReportRefusal("mprotect", GuestBase, Size);
      *Result = static_cast<uint64_t>(Hit.MayWrite ? -ENOMEM : -EACCES);
      return true;
    }

    for (uint64_t G = GranuleStart; G < GranuleEnd; G += HostSize) {
      const uint64_t SubBase = std::max(GuestBase, G);
      const uint64_t SubEnd = std::min(GuestEnd, G + HostSize);

      // mprotect of a range with no mapping under it is ENOMEM on Linux. The
      // table cannot answer that for a granule it has never seen, so ask
      // VMATracking, which tracks every guest mapping.
      if (Tracking.FindVMAEntry(SubBase) == Tracking.VMAs.end() && !Tracking.Granules.LookupPage(SubBase, nullptr)) {
        *Result = static_cast<uint64_t>(-ENOMEM);
        return true;
      }

      SeedGranuleFromVMAs(Tracking, G);
      Tracking.Granules.SetIntended(SubBase, SubEnd - SubBase, prot);
      if (!Tracking.Granules.RematerialiseIfNeeded(G)) {
        *Result = static_cast<uint64_t>(-errno);
        return true;
      }
    }

    Hndl->TrackMprotect(Thread, addr, Size, prot);
  }

  Hndl->InvalidateCodeRangeIfNecessary(Thread, GuestBase, Size);
  *Result = 0;
  return true;
}

bool Mremap(FEXCore::Core::InternalThreadState* Thread, bool Is64Bit, void* old_address, size_t old_size, size_t new_size, int flags,
            void* new_address, uint64_t* Result) {
  if (!Active() || !new_size) {
    return false;
  }

  const uint64_t OldBase = reinterpret_cast<uint64_t>(old_address);
  const uint64_t OldSize = FEXCore::AlignUp(old_size, GuestPageSize);
  const uint64_t NewSize = FEXCore::AlignUp(new_size, GuestPageSize);
  const uint64_t NewBase = reinterpret_cast<uint64_t>(new_address);

  const bool OldRepresentable = HostAligned(OldBase) && (OldSize == 0 || HostAligned(OldSize));
  const bool NewRepresentable = HostAligned(NewSize);
  const bool FixedRepresentable = !(flags & FEX_MREMAP_FIXED) || HostAligned(NewBase);

  if (OldRepresentable && NewRepresentable && FixedRepresentable) {
    // Plain grow/shrink/move on granule boundaries: the kernel does it.
    return false;
  }

  // Everything else is decomposed into allocate-copy-free, which is the only
  // primitive that works when the source and destination disagree about
  // granules. The corners below cannot be expressed that way at all.
  if (flags & FEX_MREMAP_DONTUNMAP) {
    // MREMAP_DONTUNMAP requires the old mapping to survive with its pages
    // *moved*, which a copy does not do -- the guest would see two independent
    // copies where the kernel gives it one moved and one zero-filled. No
    // representation at sub-granule alignment.
    LogOnce(LoggedMremapCorner, "MREMAP_DONTUNMAP at sub-granule alignment", OldBase, OldSize);
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  if (OldSize == 0) {
    // old_size == 0 duplicates a MAP_SHARED mapping. Shared, so uncopyable.
    LogOnce(LoggedMremapCorner, "mremap(old_size=0) of a shared mapping", OldBase, NewSize);
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  if (!(flags & FEX_MREMAP_MAYMOVE)) {
    // We can only satisfy this by moving, and the guest forbade it.
    *Result = static_cast<uint64_t>(-ENOMEM);
    return true;
  }

  auto* Hndl = Handler::Get();
  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback<std::shared_lock>(Hndl->VMATracking.Mutex, Thread);
    auto VMA = Hndl->VMATracking.FindVMAEntry(OldBase);
    if (VMA == Hndl->VMATracking.VMAs.end()) {
      *Result = static_cast<uint64_t>(-EFAULT);
      return true;
    }
    if (VMA->second.Flags.Shared) {
      LogOnce(LoggedMremapCorner, "mremap of a shared mapping at sub-granule alignment", OldBase, OldSize);
      *Result = static_cast<uint64_t>(-EINVAL);
      return true;
    }
  }

  // Destination. MREMAP_FIXED at a sub-granule address goes through the granule
  // mmap path; otherwise let the kernel choose, which gives a host-aligned
  // (hence 4K-aligned, hence legal) address.
  const int DestFlags = MAP_PRIVATE | MAP_ANONYMOUS | ((flags & FEX_MREMAP_FIXED) ? MAP_FIXED : 0);
  void* DestHint = (flags & FEX_MREMAP_FIXED) ? new_address : nullptr;
  uint64_t Dest {};
  if (!Mmap(Thread, Is64Bit, DestHint, NewSize, PROT_READ | PROT_WRITE, DestFlags, -1, 0, &Dest)) {
    Dest = reinterpret_cast<uint64_t>(Hndl->GuestMmap(Thread, DestHint, NewSize, PROT_READ | PROT_WRITE, DestFlags, -1, 0));
  }
  if (FEX::HLE::HasSyscallError(Dest)) {
    *Result = Dest;
    return true;
  }

  std::memcpy(reinterpret_cast<void*>(Dest), reinterpret_cast<const void*>(OldBase), std::min(OldSize, NewSize));

  uint64_t Unmapped {};
  if (!Munmap(Thread, old_address, OldSize, &Unmapped)) {
    Unmapped = Hndl->GuestMunmap(Thread, old_address, OldSize);
  }
  if (FEX::HLE::HasSyscallError(Unmapped)) {
    LogMan::Msg::EFmt("64K granule emulation: mremap copied [0x{:x}, 0x{:x}) to 0x{:x} but could not free the source: {}", OldBase,
                      OldBase + OldSize, Dest, -static_cast<int64_t>(Unmapped));
  }

  Hndl->InvalidateCodeRangeIfNecessaryOnRemap(Thread, OldBase, Dest, OldSize, NewSize);
  *Result = Dest;
  return true;
}


///// Guest-visible reporting (PAGE_SIZE_64K_PLAN Part 2 §7) /////

namespace {
  std::atomic<bool> LoggedMadviseSkip {false};

  // Is this guest page something the guest currently owns? The granule table is
  // authoritative once FEX has subdivided the granule; VMATracking answers for
  // everything else.
  // - VMATracking::Mutex must be held.
  bool GuestPageLive(const FEX::HLE::VMATracking::VMATracking& Tracking, uint64_t Page) {
    const auto* Entry = Tracking.Granules.Find(GranuleTable::GranuleOf(Page));
    if (Entry) {
      return (Entry->NibbleAt(GranuleTable::IndexOf(Page)) & GranuleTable::PageLive) != 0;
    }
    return Tracking.FindVMAEntry(Page) != Tracking.VMAs.end();
  }
} // namespace

bool Mincore(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, uint8_t* vec, uint64_t* Result) {
  if (!Active()) {
    return false;
  }

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  if (GuestBase & ~GuestPageMask) {
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  if (!length) {
    *Result = 0;
    return true;
  }

  // The guest's vector is one byte per GUEST page. A raw passthrough asks the
  // host for one byte per HOST page and writes that many, so on a 64K host it
  // both under-fills the guest's buffer by 16x and EINVALs the moment the guest
  // hands it a 4K-aligned address. This is the whole reason the shim exists.
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GuestEnd = GuestBase + Size;
  const uint64_t GuestPages = Size >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  const uint64_t HostSize = FEXCore::HostPage::Size();
  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);
  const uint64_t Granules = (GranuleEnd - GranuleStart) / HostSize;

  fextl::vector<uint8_t> HostVec(Granules);
  if (::mincore(reinterpret_cast<void*>(GranuleStart), GranuleEnd - GranuleStart, HostVec.data()) != 0) {
    *Result = static_cast<uint64_t>(-errno);
    return true;
  }

  auto* Hndl = Handler::Get();
  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback<std::shared_lock>(Hndl->VMATracking.Mutex, Thread);
    for (uint64_t i = 0; i < GuestPages; ++i) {
      const uint64_t Page = GuestBase + i * GuestPageSize;
      if (!GuestPageLive(Hndl->VMATracking, Page)) {
        // Linux: a hole anywhere in the range is ENOMEM, and nothing is
        // written. A sub-granule hole exists only in the table -- the host's
        // own mincore cannot see it, because the granule is still mapped for
        // the sake of its live siblings.
        *Result = static_cast<uint64_t>(-ENOMEM);
        return true;
      }
      vec[i] = HostVec[(Page - GranuleStart) / HostSize];
    }
  }

  *Result = 0;
  return true;
}

bool Msync(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int flags, uint64_t* Result) {
  if (!Active()) {
    return false;
  }

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  if (GuestBase & ~GuestPageMask) {
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  if (HostAligned(GuestBase) && (!length || HostAligned(FEXCore::AlignUp(length, GuestPageSize)))) {
    return false;
  }
  if (!length) {
    *Result = 0;
    return true;
  }

  // Rounding a msync OUT to granules is safe in a way that rounding a madvise
  // out is not: msync writes dirty pages back, it never discards anything, so
  // the worst a sibling suffers is being flushed early. A granule FEX converted
  // to private anonymous backing has nothing to write back and msync on it
  // succeeds trivially.
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestBase + Size);
  if (::msync(reinterpret_cast<void*>(GranuleStart), GranuleEnd - GranuleStart, flags) != 0) {
    *Result = static_cast<uint64_t>(-errno);
    return true;
  }
  *Result = 0;
  return true;
}

bool Madvise(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int advice, uint64_t* Result) {
  if (!Active()) {
    return false;
  }

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  if (GuestBase & ~GuestPageMask) {
    *Result = static_cast<uint64_t>(-EINVAL);
    return true;
  }
  if (!length) {
    *Result = 0;
    return true;
  }
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GuestEnd = GuestBase + Size;
  if (HostAligned(GuestBase) && HostAligned(GuestEnd)) {
    return false;
  }

  // Destructive advices lose data. They may never be rounded OUT to granules:
  // that would discard a sibling page the guest still owns. Non-destructive
  // hints may, because the worst they cost a sibling is a readahead.
  const bool Destructive = advice == MADV_DONTNEED || advice == MADV_FREE || advice == MADV_REMOVE || advice == MADV_WIPEONFORK;

  const uint64_t HostSize = FEXCore::HostPage::Size();
  auto* Hndl = Handler::Get();

  if (!Destructive) {
    const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
    const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);
    if (::madvise(reinterpret_cast<void*>(GranuleStart), GranuleEnd - GranuleStart, advice) != 0) {
      *Result = static_cast<uint64_t>(-errno);
      return true;
    }
    Hndl->TrackMadvise(Thread, GuestBase, Size, advice);
    *Result = 0;
    return true;
  }

  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;

    const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
    const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);
    for (uint64_t G = GranuleStart; G < GranuleEnd; G += HostSize) {
      const uint64_t SubBase = std::max(GuestBase, G);
      const uint64_t SubEnd = std::min(GuestEnd, G + HostSize);
      if (SubBase == G && SubEnd == G + HostSize) {
        // A whole granule: the kernel can do exactly what the guest asked.
        if (::madvise(reinterpret_cast<void*>(G), HostSize, advice) != 0) {
          *Result = static_cast<uint64_t>(-errno);
          return true;
        }
        continue;
      }

      // A partial granule. For private anonymous memory MADV_DONTNEED means
      // "the next read sees zeroes", and FEX can deliver exactly that itself.
      auto VMA = Tracking.FindVMAEntry(SubBase);
      const auto* Entry = Tracking.Granules.Find(G);
      const bool PrivateAnon = (Entry && Entry->FEXBacked) ||
                               (VMA != Tracking.VMAs.end() && !VMA->second.Flags.Shared && VMA->second.Resource == nullptr);
      if (PrivateAnon && (advice == MADV_DONTNEED || advice == MADV_FREE)) {
        int Prot = PROT_NONE;
        const bool Known = Tracking.Granules.LookupPage(SubBase, &Prot);
        if (!Known || (Prot & PROT_WRITE)) {
          std::memset(reinterpret_cast<void*>(SubBase), 0, SubEnd - SubBase);
          continue;
        }
      }

      // Everything else -- private file mappings with dirty pages, shared
      // mappings, MADV_REMOVE -- would need the granule taken apart to honour
      // exactly. madvise is advisory, so not doing it is a legal answer; say so
      // once rather than silently discarding a sibling's data, which is the
      // failure this branch exists to avoid.
      LogOnce(LoggedMadviseSkip, "a destructive madvise on part of a granule it cannot take apart", SubBase, SubEnd - SubBase);
    }
    Hndl->TrackMadvise(Thread, GuestBase, Size, advice);
  }

  *Result = 0;
  return true;
}


///// /proc/self/maps and /proc/self/smaps (PAGE_SIZE_64K_PLAN §7) /////
//
// Synthesised from VMATracking and the granule table rather than passed
// through, for the same reason the CPU ids are densely remapped (c6b0180d3):
// every granularity the guest can observe must come from the fiction, not the
// host. The host's own maps file shows FEX's mappings, host page granularity,
// and -- decisively -- cannot show a sub-granule hole at all, because the
// granule is still mapped for the sake of its live siblings. Wine's PE loader
// and glibc both read maps at start-up.

namespace {
  struct MapRun {
    uint64_t Base;
    uint64_t End;
    int Prot;
    bool Shared;
    uint64_t Offset;
    const FEX::HLE::VMATracking::VMAEntry* VMA;
  };

  void EmitRun(fextl::string& Out, const MapRun& Run, bool Smaps) {
    uint64_t Dev = 0;
    uint64_t Inode = 0;
    const char* Path = "";
    if (Run.VMA && Run.VMA->Resource) {
      const auto& MRID = Run.VMA->Resource->Iterator->first;
      if (MRID.dev < FEX::HLE::VMATracking::SpecialDev::Anon) {
        Dev = MRID.dev;
        Inode = MRID.id;
      }
      if (Run.VMA->Resource->MappedFile) {
        Path = Run.VMA->Resource->MappedFile->Filename.c_str();
      }
    }

    fextl::fmt::format_to(std::back_inserter(Out), "{:012x}-{:012x} {}{}{}{} {:08x} {:02x}:{:02x} {}", Run.Base, Run.End,
                          (Run.Prot & PROT_READ) ? 'r' : '-', (Run.Prot & PROT_WRITE) ? 'w' : '-', (Run.Prot & PROT_EXEC) ? 'x' : '-',
                          Run.Shared ? 's' : 'p', Run.Offset, static_cast<unsigned>((Dev >> 8) & 0xFF),
                          static_cast<unsigned>(Dev & 0xFF), Inode);
    if (Path[0]) {
      fextl::fmt::format_to(std::back_inserter(Out), "{:<20}{}", "", Path);
    }
    Out += '\n';

    if (!Smaps) {
      return;
    }

    // A deliberately small but complete-enough smaps block. KernelPageSize and
    // MMUPageSize are the entire point of synthesising this file: the guest was
    // told AT_PAGESZ=4096 and every allocator that reads smaps must be told the
    // same thing here, or it sizes its arenas for a page the guest cannot
    // address.
    const uint64_t SizeKB = (Run.End - Run.Base) >> 10;
    fextl::fmt::format_to(std::back_inserter(Out),
                          "Size:           {:8} kB\n"
                          "KernelPageSize: {:8} kB\n"
                          "MMUPageSize:    {:8} kB\n"
                          "Rss:            {:8} kB\n"
                          "Pss:            {:8} kB\n"
                          "Private_Dirty:  {:8} kB\n"
                          "Swap:           {:8} kB\n"
                          "VmFlags:{}{}{}{}\n",
                          SizeKB, FEXCore::Utils::FEX_GUEST_PAGE_SIZE >> 10, FEXCore::Utils::FEX_GUEST_PAGE_SIZE >> 10, SizeKB, SizeKB,
                          Run.Shared ? 0 : SizeKB, 0, (Run.Prot & PROT_READ) ? " rd" : "", (Run.Prot & PROT_WRITE) ? " wr" : "",
                          (Run.Prot & PROT_EXEC) ? " ex" : "", Run.Shared ? " sh" : " mr mw me");
  }
} // namespace

fextl::string GenerateMaps(bool Smaps) {
  if (!Active()) {
    // On a 4K host the host's own file is already right about granularity, and
    // replacing it would be a behaviour change in the shipping build. Returning
    // empty tells the caller to fall back to the real file.
    return {};
  }

  auto* Hndl = Handler::Get();
  if (!Hndl) {
    return {};
  }

  fextl::string Out;
  auto lk = FEXCore::GuardSignalDeferringSectionWithFallback<std::shared_lock>(Hndl->VMATracking.Mutex, nullptr);
  const auto& Tracking = Hndl->VMATracking;
  if (Tracking.VMAs.empty()) {
    return {};
  }

  // Walk every tracked VMA one guest page at a time, coalescing runs that agree
  // about protection. The granule table overrides the VMA's own protection
  // wherever it has an entry, which is exactly where the guest did something
  // sub-granule -- a 4K guard page inside a live granule, or a hole left by a
  // partial munmap. Those are invisible in the host's file and are the reason
  // this function exists.
  for (const auto& [Base, VMA] : Tracking.VMAs) {
    MapRun Run {};
    bool Open = false;
    for (uint64_t Page = VMA.Base; Page < VMA.Base + VMA.Length; Page += GuestPageSize) {
      int Prot = PROT_NONE;
      bool Live = true;
      const auto* Entry = Tracking.Granules.Find(GranuleTable::GranuleOf(Page));
      if (Entry) {
        const uint64_t Nibble = Entry->NibbleAt(GranuleTable::IndexOf(Page));
        Live = (Nibble & GranuleTable::PageLive) != 0;
        Prot = GranuleTable::ProtFromNibble(Nibble);
      } else {
        if (VMA.Prot.Readable) {
          Prot |= PROT_READ;
        }
        if (VMA.Prot.Writable) {
          Prot |= PROT_WRITE;
        }
        if (VMA.Prot.Executable) {
          Prot |= PROT_EXEC;
        }
      }

      if (!Live) {
        // A sub-granule hole. It is a hole in the guest's address space even
        // though the granule under it is still mapped.
        if (Open) {
          EmitRun(Out, Run, Smaps);
          Open = false;
        }
        continue;
      }

      if (Open && Prot == Run.Prot && Page == Run.End) {
        Run.End += GuestPageSize;
        continue;
      }
      if (Open) {
        EmitRun(Out, Run, Smaps);
      }
      Run = MapRun {
        .Base = Page,
        .End = Page + GuestPageSize,
        .Prot = Prot,
        .Shared = VMA.Flags.Shared,
        .Offset = VMA.Offset + (Page - VMA.Base),
        .VMA = &VMA,
      };
      Open = true;
    }
    if (Open) {
      EmitRun(Out, Run, Smaps);
    }
  }

  return Out;
}

} // namespace FEX::HLE::Granule
