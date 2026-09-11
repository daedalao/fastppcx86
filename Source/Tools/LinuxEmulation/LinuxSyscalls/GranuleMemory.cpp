// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: Guest memory syscalls on a host page larger than the guest's
$end_info$
*/

#include "LinuxSyscalls/GranuleMemory.h"
#include "LinuxSyscalls/GranuleTable.h"
#include "LinuxSyscalls/HostOwnedRanges.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/fextl/vector.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace FEX::HLE::Granule {
using FEX::HLE::VMATracking::GranuleTable;

namespace {
  constexpr uint64_t GuestPageSize = FEXCore::Utils::FEX_GUEST_PAGE_SIZE;
  constexpr uint64_t GuestPageMask = FEXCore::Utils::FEX_GUEST_PAGE_MASK;


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

  // pread the whole of [Base, End) from fd at FileOffset, zero-filling whatever
  // the file does not provide. mmap of a file reads as zero past EOF inside the
  // last page, and a short read here must behave the same way.
  int64_t FillFromFile(uint64_t Base, uint64_t End, int fd, off_t FileOffset) {
    uint64_t Cursor = Base;
    off_t Offset = FileOffset;
    while (Cursor < End) {
      const ssize_t Read = ::pread(fd, reinterpret_cast<void*>(Cursor), End - Cursor, Offset);
      if (Read < 0) {
        if (errno == EINTR) {
          continue;
        }
        return -errno;
      }
      if (Read == 0) {
        break;
      }
      Cursor += static_cast<uint64_t>(Read);
      Offset += Read;
    }
    if (Cursor < End) {
      std::memset(reinterpret_cast<void*>(Cursor), 0, End - Cursor);
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

  const uint64_t GuestBase = reinterpret_cast<uint64_t>(addr);
  const uint64_t Size = FEXCore::AlignUp(length, GuestPageSize);
  const uint64_t GuestEnd = GuestBase + Size;
  const bool Anonymous = (flags & MAP_ANONYMOUS) != 0 || fd < 0;

  if (!(flags & MAP_FIXED)) {
    // The kernel picks the address, and it picks a host-aligned one, which is
    // 4K-aligned and therefore legal for the guest. The only thing that can
    // still be unrepresentable is a file offset the host cannot take.
    if (Anonymous || HostAligned(static_cast<uint64_t>(offset))) {
      return false;
    }
  } else if (HostAligned(GuestBase) && HostAligned(GuestEnd) && (Anonymous || HostAligned(static_cast<uint64_t>(offset)))) {
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
  const uint64_t GranuleStart = FEXCore::HostPage::AlignDown(GuestBase);
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(GuestEnd);

  {
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(Hndl->VMATracking.Mutex, Thread);
    auto& Tracking = Hndl->VMATracking;

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

} // namespace FEX::HLE::Granule
