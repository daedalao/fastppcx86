// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/HostOwnedRanges.h"

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <unistd.h>

namespace FEX::HLE {
namespace {
  // Written once by SnapshotSelf/Add under RangesLock, read lock-free from the
  // syscall fast path. Guest mmap/munmap/mprotect are already serialised
  // against each other by VMATracking.Mutex at every call site, and Add() is
  // only reachable from host setup code, so a mutex here is only for the
  // benefit of an out-of-band Add().
  std::mutex RangesLock;
  fextl::vector<HostOwnedRanges::Range> Ranges;
  std::atomic<bool> Snapshotted {false};
  std::atomic<size_t> RangeCount {0};

  void AddLocked(uint64_t Base, uint64_t End, bool MayWrite = true) {
    if (End <= Base) {
      return;
    }
    Ranges.push_back({Base, End, MayWrite});
  }

  void SortAndCoalesceLocked() {
    std::sort(Ranges.begin(), Ranges.end(), [](const auto& a, const auto& b) { return a.Base < b.Base; });
    size_t Out = 0;
    for (size_t i = 0; i < Ranges.size(); ++i) {
      const bool Overlapping = Out > 0 && Ranges[i].Base < Ranges[Out - 1].End;
      // Merely adjacent ranges only merge when they agree on MayWrite, so
      // [vvar] does not get absorbed into the vdso/library block behind it and
      // lose its EACCES marker. Genuinely overlapping ones (only possible via
      // Add()/the test hook) merge unconditionally with the flags ANDed —
      // CAUTION: an Add() range overlapping [vvar] therefore makes the whole
      // merged span answer EACCES to PROT_WRITE, not just the vvar pages.
      // Acceptable while Add() has no callers; revisit if that changes.
      const bool Adjacent = Out > 0 && Ranges[i].Base == Ranges[Out - 1].End && Ranges[i].MayWrite == Ranges[Out - 1].MayWrite;
      if (Overlapping || Adjacent) {
        Ranges[Out - 1].End = std::max(Ranges[Out - 1].End, Ranges[i].End);
        Ranges[Out - 1].MayWrite &= Ranges[i].MayWrite;
      } else {
        Ranges[Out++] = Ranges[i];
      }
    }
    Ranges.resize(Out);
    RangeCount.store(Ranges.size(), std::memory_order_release);
  }

  // Raw read of /proc/self/maps. Deliberately avoids stdio and the FEX
  // allocator hooks: this runs during early startup and must not perturb the
  // very heap it is about to record.
  //
  // SCOPE, and why it is not simply "every mapping that exists right now":
  //
  // FEX's own anonymous allocator regions (the 48-bit-bit reservations, the
  // rpmalloc arenas) CAN be released again, and the kernel is then free to hand
  // the same addresses to a plain guest mmap. Wine reserves large areas that
  // way and then MAP_FIXEDs its sections inside them, so protecting a
  // recyclable anonymous region would eventually refuse a request the guest
  // legitimately owns.
  //
  // What is recorded instead is the set of mappings that FEX never releases and
  // the guest can never legitimately obtain:
  //   * every file-backed mapping (FEX's own image, host .so files),
  //   * the kernel's named regions ([heap] -- pinned by
  //     SBRKAllocations::DisableSBRKAllocations -- [stack], [vdso], [vvar]),
  //   * anonymous mappings that begin exactly where one of the above ends,
  //     which is how .bss and the sbrk guard page appear.
  //
  // That is exactly the memory the ppc64le PIE-base collision destroys.
  bool ParseSelfMaps(fextl::vector<HostOwnedRanges::Range>& Out) {
    int FD = ::open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (FD == -1) {
      return false;
    }

    char Buf[65536];
    char Line[512];
    size_t LineLen = 0;
    ssize_t Read;
    bool Any = false;
    uint64_t PrevIncludedEnd = 0;

    const auto HandleLine = [&](char* L) {
      // "<start>-<end> <perms> <offset> <dev> <inode>[ <path>]"
      char* End = nullptr;
      const uint64_t Start = ::strtoull(L, &End, 16);
      if (!End || *End != '-') {
        return;
      }
      const uint64_t Stop = ::strtoull(End + 1, &End, 16);
      if (Stop <= Start) {
        return;
      }

      // Skip forward over perms/offset/dev/inode to the (optional) path.
      int Fields = 0;
      char* P = End;
      while (*P && Fields < 4) {
        while (*P == ' ') {
          ++P;
        }
        if (!*P) {
          break;
        }
        ++Fields;
        while (*P && *P != ' ') {
          ++P;
        }
      }
      while (*P == ' ') {
        ++P;
      }

      const bool Named = (*P != '\0');
      const bool ChainedAnon = !Named && Start == PrevIncludedEnd && PrevIncludedEnd != 0;

      if (!Named && !ChainedAnon) {
        // Free-standing anonymous mapping: recyclable, not recorded.
        return;
      }

      // [vvar] (and the split-off [vvar_vclock] on newer kernels) is the one
      // mapping whose VM_MAYWRITE the kernel keeps clear: mprotect(PROT_WRITE)
      // on it fails with EACCES for a native process, and the guest sees it in
      // /proc/self/maps. Everything else in the table is refused as if
      // unmapped. See Range::MayWrite.
      const bool MayWrite = ::strncmp(P, "[vvar", 5) != 0;

      Out.push_back({Start, Stop, MayWrite});
      PrevIncludedEnd = Stop;
      Any = true;
    };

    while ((Read = ::read(FD, Buf, sizeof(Buf))) > 0) {
      for (ssize_t i = 0; i < Read; ++i) {
        const char C = Buf[i];
        if (C != '\n') {
          if (LineLen + 1 < sizeof(Line)) {
            Line[LineLen++] = C;
          }
          continue;
        }
        Line[LineLen] = '\0';
        LineLen = 0;
        HandleLine(Line);
      }
    }

    ::close(FD);
    return Any;
  }
} // namespace

void HostOwnedRanges::SnapshotSelf() {
  bool Expected = false;
  if (!Snapshotted.compare_exchange_strong(Expected, true)) {
    // Already snapshotted; a second call would capture guest mappings.
    return;
  }

  std::lock_guard lk {RangesLock};
  fextl::vector<Range> Parsed;
  if (!ParseSelfMaps(Parsed)) {
    LogMan::Msg::EFmt("HostOwnedRanges: could not read /proc/self/maps; FEX's own image is unprotected "
                      "against guest MAP_FIXED. See docs/fex-teardown-crash.md.");
    return;
  }

  // Never record anything a 32-bit guest could address. GuestMprotect is shared
  // between the 32- and 64-bit paths, and the 32-bit path has its own
  // host-range mechanism (MemAllocator::ReserveHostRange) plus an allocator
  // that places every guest mapping itself. Nothing host-private lives below
  // 4 GiB on ppc64le anyway -- ELF_ET_DYN_BASE is 4 GiB, and the host libraries
  // and stack sit at 0x3fff'xxxx'xxxx -- so this costs no coverage and makes
  // the guard provably inert for a 32-bit guest, which is not otherwise
  // testable here (the available cross toolchain is x86_64-only).
  constexpr uint64_t FirstGuardedAddress = 0x1'0000'0000ULL;
  for (const auto& R : Parsed) {
    if (R.End <= FirstGuardedAddress) {
      continue;
    }
    AddLocked(std::max(R.Base, FirstGuardedAddress), R.End, R.MayWrite);
  }

  // TEST HOOK, off unless set: FEX_TEST_HOSTOWNED_ADD=<hexbase>-<hexend>[,...]
  // adds extra ranges to the table. Its only purpose is to make the ppc64le
  // PIE-base collision reproducible on demand -- pointing it at 0x140000000
  // makes every PE image reservation in a Wine session take the refusal path,
  // which is otherwise a ~0.7%-per-process event and therefore untestable.
  // It can only ever cause FEX to refuse MORE, never less.
  if (const char* Spec = ::getenv("FEX_TEST_HOSTOWNED_ADD")) {
    const char* P = Spec;
    while (*P) {
      char* End = nullptr;
      const uint64_t Start = ::strtoull(P, &End, 16);
      if (!End || *End != '-') {
        break;
      }
      const uint64_t Stop = ::strtoull(End + 1, &End, 16);
      AddLocked(Start, Stop);
      LogMan::Msg::IFmt("HostOwnedRanges: FEX_TEST_HOSTOWNED_ADD [0x{:x}, 0x{:x})", Start, Stop);
      if (*End != ',') {
        break;
      }
      P = End + 1;
    }
  }

  SortAndCoalesceLocked();
}

void HostOwnedRanges::Add(uint64_t Base, uint64_t Size) {
  if (!Size) {
    return;
  }
  std::lock_guard lk {RangesLock};
  AddLocked(Base & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::AlignUp(Base + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  SortAndCoalesceLocked();
}

HostOwnedRanges::Range HostOwnedRanges::FindOverlap(uint64_t Base, uint64_t Size) {
  if (RangeCount.load(std::memory_order_acquire) == 0 || !Size) {
    return {0, 0};
  }

  const uint64_t Start = Base & FEXCore::Utils::FEX_PAGE_MASK;
  const uint64_t End = FEXCore::AlignUp(Base + Size, FEXCore::Utils::FEX_PAGE_SIZE);
  if (End <= Start) {
    // Wrapped: an absurd length. Report an overlap so it is refused rather than
    // handed to the kernel. MayWrite stays true: the kernel's errno for an
    // absurd length is ENOMEM, never EACCES.
    return {Start, ~0ULL, true};
  }

  // Ranges is sorted and disjoint after SortAndCoalesceLocked.
  const auto& R = Ranges;
  auto it = std::upper_bound(R.begin(), R.end(), Start, [](uint64_t Value, const Range& Elem) { return Value < Elem.Base; });
  if (it != R.begin()) {
    --it;
    if (it->End > Start && it->Base < End) {
      return *it;
    }
    ++it;
  }
  if (it != R.end() && it->Base < End) {
    return *it;
  }
  return {0, 0};
}

bool HostOwnedRanges::Overlaps(uint64_t Base, uint64_t Size) {
  const auto Hit = FindOverlap(Base, Size);
  return Hit.End != 0;
}

void HostOwnedRanges::ReportRefusal(const char* Op, uint64_t Base, uint64_t Size) {
  // Bounded: a guest that retries in a loop must not be able to fill the disk.
  static std::atomic<uint32_t> Reported {0};
  constexpr uint32_t MaxReports = 16;
  const uint32_t N = Reported.fetch_add(1, std::memory_order_relaxed);
  if (N >= MaxReports) {
    return;
  }

  // Raw write(2) to stderr rather than LogMan alone. MEASURED: under Wine the
  // LogMan sink is routed to the FEXServer log (or silenced) for the emulated
  // child processes, so a LogMan-only report is invisible exactly where this
  // event matters and -- worse -- makes "no refusals were reported" look like
  // evidence when it is not. This event is rare, one line, and means the
  // emulator just avoided being destroyed; stderr is the right place for it.
  const auto Hit = FindOverlap(Base, Size);
  char Buf[320];
  const int Len = ::snprintf(Buf, sizeof(Buf),
                             "FEX: refusing guest %s of [0x%llx, 0x%llx): it overlaps FEX's own host mapping "
                             "[0x%llx, 0x%llx) and would destroy it (ppc64le PIE-base vs PE-ImageBase "
                             "collision).%s\n",
                             Op, (unsigned long long)Base, (unsigned long long)(Base + Size), (unsigned long long)Hit.Base,
                             (unsigned long long)Hit.End, (N + 1 == MaxReports) ? " Further reports suppressed." : "");
  if (Len > 0) {
    [[maybe_unused]] const auto Ignored = ::write(STDERR_FILENO, Buf, static_cast<size_t>(Len));
  }
}

const fextl::vector<HostOwnedRanges::Range>& HostOwnedRanges::GetRanges() {
  return Ranges;
}

} // namespace FEX::HLE
