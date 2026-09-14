// SPDX-License-Identifier: MIT
#pragma once
/*
$info$
tags: utils|memory
desc: Transparent huge page (THP) policy for FEX's own large anonymous allocations
$end_info$
*/

// Transparent huge pages for FEX's own reservations.
//
// On a POWER8 hash MMU THP exists only with a 64K base page, and the huge page
// is 16 MiB (hpage_pmd_size). The production 64K kernel runs with
// /sys/kernel/mm/transparent_hugepage/enabled = madvise, so nothing is huge
// unless it carries MADV_HUGEPAGE, and a hint only takes for a 16 MiB-aligned,
// 16 MiB-sized window that lies entirely inside one VMA. Every hint FEX ever
// issued was dead on the 4K box; on 64K it is live, so which reservations carry
// it, and whether they are placed so the hint can take, is now a knob.
//
// FEX_THP selects the sites (comma-separated names, or a numeric mask):
//   code      JIT code buffers (FEXMemJIT), 16 MiB-aligned when on
//   lookup    the per-thread L1 lookup table and the L2 page-pointer table
//             (FEXMem_Lookup / FEXMem_Lookup_L1), the reservation aligned and the
//             table padded to 16 MiB so both sit on a PMD boundary
//   alloc64   the 64-bit guest allocator's 64 MiB object arena (FEXMem_Misc)
//   rpmalloc  the bundled allocator's 256 MiB spans (FEXAllocator)
//   guest     the guest's own anonymous private mappings (Linux lane only; the
//             bridge lane's guest memory is Wine's)
//   all / none
// Default: code,alloc64 -- the two sites that were hinted before this knob
// existed and are dense. Everything else is a measurement, off until measured.
//
// FEX_THPLOG=1 prints AnonHugePages/Rss from /proc/self/smaps_rollup at exit
// (exit_group, the fatal-signal path, or the host's exit() -- the bridge lane);
// FEX_THPLOG=2 adds a per-VMA-name breakdown from /proc/self/smaps.
//
// Header-only on purpose: the sites span FEXCore, the bundled-allocator static
// library (AllocatorHooks.cpp), the Linux syscall layer and the bridge, and a
// header with inline variables has no link-order to get wrong. Nothing here
// allocates; the report path uses open/read only so it can run from the
// fatal-signal exit.
//
// On a 4K host, or any kernel without THP, PMDSize() is 0: no alignment, no
// padding, no size change -- the hint itself is the only thing issued, and the
// kernel ignores it, exactly as before.

#include <FEXCore/Utils/TypeDefines.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace FEXCore::Allocator::THP {

enum Site : uint32_t {
  Code = 1u << 0,
  Lookup = 1u << 1,
  Alloc64 = 1u << 2,
  RPMalloc = 1u << 3,
  Guest = 1u << 4,
  All = Code | Lookup | Alloc64 | RPMalloc | Guest,
};

constexpr uint32_t DefaultMask = Code | Alloc64;

struct SiteName {
  const char* Name;
  uint32_t Bit;
};

// Order matters for MaskToString: listed bits print in this order.
inline constexpr SiteName SiteNames[] = {
  {"code", Code}, {"lookup", Lookup}, {"alloc64", Alloc64}, {"rpmalloc", RPMalloc}, {"guest", Guest},
};

namespace Detail {
constexpr uint32_t Unresolved = ~0u;
inline std::atomic<uint32_t> MaskValue {Unresolved};
inline std::atomic<size_t> PMDValue {~size_t {0}};
inline std::atomic<int> LogValue {-1};
inline std::atomic<bool> Reported {false};
inline std::atomic<bool> AtExitInstalled {false};

// Read a small sysfs/procfs file into Buf. Returns bytes read (0 on any failure).
// open/read only: usable from the fatal-signal exit path.
inline size_t ReadSmallFile(const char* Path, char* Buf, size_t Cap) {
#ifdef _WIN32
  return 0;
#else
  const int FD = ::open(Path, O_RDONLY | O_CLOEXEC);
  if (FD < 0) {
    return 0;
  }
  size_t Total = 0;
  while (Total + 1 < Cap) {
    const ssize_t N = ::read(FD, Buf + Total, Cap - 1 - Total);
    if (N <= 0) {
      break;
    }
    Total += static_cast<size_t>(N);
  }
  ::close(FD);
  Buf[Total] = 0;
  return Total;
#endif
}

// "Key:   1234 kB" -> 1234. Returns false when Key is not in Text.
inline bool FindKB(const char* Text, const char* Key, uint64_t* Out) {
  const char* P = std::strstr(Text, Key);
  if (!P) {
    return false;
  }
  P += std::strlen(Key);
  while (*P == ' ' || *P == '\t') {
    ++P;
  }
  *Out = std::strtoull(P, nullptr, 10);
  return true;
}
} // namespace Detail

// Parses "code,alloc64", "all", "none", "0x5", "5". Unknown names are ignored
// (the rest of the list still applies) so a typo cannot silently disable the
// whole default. Empty/unset -> DefaultMask.
inline uint32_t ParseMask(const char* Text) {
  if (!Text || !*Text) {
    return DefaultMask;
  }
  if ((Text[0] >= '0' && Text[0] <= '9')) {
    return static_cast<uint32_t>(std::strtoul(Text, nullptr, 0)) & All;
  }
  uint32_t Mask = 0;
  const char* P = Text;
  while (*P) {
    while (*P == ',' || *P == ' ') {
      ++P;
    }
    const char* Start = P;
    while (*P && *P != ',' && *P != ' ') {
      ++P;
    }
    const size_t Len = static_cast<size_t>(P - Start);
    if (Len == 0) {
      continue;
    }
    if (Len == 3 && std::strncmp(Start, "all", 3) == 0) {
      Mask |= All;
      continue;
    }
    if (Len == 4 && std::strncmp(Start, "none", 4) == 0) {
      continue;
    }
    if (Len == 7 && std::strncmp(Start, "default", 7) == 0) {
      Mask |= DefaultMask;
      continue;
    }
    for (const auto& S : SiteNames) {
      if (std::strlen(S.Name) == Len && std::strncmp(Start, S.Name, Len) == 0) {
        Mask |= S.Bit;
        break;
      }
    }
  }
  return Mask;
}

// Explicit override (the interpreter applies the merged config layer through
// this once it is loaded; the bridge lane reads the environment raw).
inline void SetMask(uint32_t Mask) {
  Detail::MaskValue.store(Mask & All, std::memory_order_relaxed);
}

inline uint32_t Mask() {
  uint32_t Current = Detail::MaskValue.load(std::memory_order_relaxed);
  if (__builtin_expect(Current == Detail::Unresolved, 0)) {
    Current = ParseMask(::getenv("FEX_THP"));
    Detail::MaskValue.store(Current, std::memory_order_relaxed);
  }
  return Current;
}

inline bool Enabled(Site S) {
  return (Mask() & S) != 0;
}

// Writes "code,alloc64" (or "none") into Buf.
inline const char* MaskToString(uint32_t Mask, char* Buf, size_t Cap) {
  size_t Off = 0;
  Buf[0] = 0;
  for (const auto& S : SiteNames) {
    if (!(Mask & S.Bit)) {
      continue;
    }
    const int N = std::snprintf(Buf + Off, Cap - Off, "%s%s", Off ? "," : "", S.Name);
    if (N < 0 || static_cast<size_t>(N) >= Cap - Off) {
      break;
    }
    Off += static_cast<size_t>(N);
  }
  if (Off == 0) {
    std::snprintf(Buf, Cap, "none");
  }
  return Buf;
}

// The kernel's huge page size for anonymous memory, 0 when the kernel has no
// THP at all (the 4K POWER8 hash kernel). Cached after the first read.
inline size_t PMDSize() {
  size_t Current = Detail::PMDValue.load(std::memory_order_relaxed);
  if (__builtin_expect(Current == ~size_t {0}, 0)) {
    char Buf[64];
    Current = 0;
    if (Detail::ReadSmallFile("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", Buf, sizeof(Buf))) {
      Current = static_cast<size_t>(std::strtoull(Buf, nullptr, 10));
      // A PMD size that is not a power of two, or smaller than a host page, is
      // nonsense; treat it as "no THP" rather than align to it.
      if ((Current & (Current - 1)) != 0 || Current < FEXCore::HostPage::Size()) {
        Current = 0;
      }
    }
    Detail::PMDValue.store(Current, std::memory_order_relaxed);
  }
  return Current;
}

// The alignment a Size-byte reservation for site S should be placed at so the
// hint can take: the PMD size when the site is on, the kernel has THP and the
// reservation is at least one huge page; otherwise 0 (place it as before).
inline size_t AlignmentFor(Site S, size_t Size) {
  if (!Enabled(S)) {
    return 0;
  }
  const size_t PMD = PMDSize();
  return (PMD && Size >= PMD) ? PMD : 0;
}

// Issue the hint for site S (no-op when the site is off). Advisory only.
inline void Hint(const void* Ptr, size_t Size, Site S) {
#ifndef _WIN32
  if (Ptr && Size && Enabled(S)) {
    ::madvise(const_cast<void*>(Ptr), Size, MADV_HUGEPAGE);
  }
#endif
}

// Hint or explicitly refuse: sites that were MADV_NOHUGEPAGE before the knob
// existed keep the refusal when off, so an "enabled=always" kernel does not
// change their behaviour either.
inline void HintOrRefuse(const void* Ptr, size_t Size, Site S) {
#ifndef _WIN32
  if (Ptr && Size) {
    ::madvise(const_cast<void*>(Ptr), Size, Enabled(S) ? MADV_HUGEPAGE : MADV_NOHUGEPAGE);
  }
#endif
}

// FEX_THP=guest: hint a mapping the *guest* asked for, right after the host
// mmap that backs it succeeded. Only anonymous private memory qualifies (file
// and shared mappings cannot be anonymous-THP-backed). No length floor: the
// kernel uses a huge page only where an aligned window exists, and hinting
// every anonymous private VMA keeps them mergeable with each other so
// khugepaged can collapse a heap that grows in small steps. The guest's own
// madvise still passes through and wins (a later MADV_NOHUGEPAGE clears it).
// Linux lane only: in the bridge lane Wine maps guest memory itself.
inline void HintGuestMapping(void* Ptr, size_t Length, int Flags, int FD) {
#ifndef _WIN32
  if (!Enabled(Guest) || Ptr == MAP_FAILED || !Ptr || !Length) {
    return;
  }
  // MAP_SHARED_VALIDATE is MAP_SHARED|MAP_PRIVATE as a bit pattern, so test it
  // as a whole value: `Flags & MAP_SHARED_VALIDATE` would reject every private
  // mapping (the first cut did exactly that and hinted nothing).
  const bool Shared = (Flags & MAP_SHARED) || ((Flags & MAP_SHARED_VALIDATE) == MAP_SHARED_VALIDATE);
  if (!(Flags & MAP_ANONYMOUS) || Shared || FD != -1) {
    return;
  }
  ::madvise(Ptr, Length, MADV_HUGEPAGE);
#endif
}

// Trims an over-sized anonymous mapping [Base, Base+MappedSize) down to the
// first Align-aligned window of Size bytes inside it, unmapping the slack on
// both sides. The caller maps Size + Align bytes through whatever mapper keeps
// its placement policy, then calls this. Returns the aligned pointer; on a
// mapping that cannot hold such a window (MappedSize too small) returns
// nullptr with the mapping untouched so the caller can fall back.
inline void* TrimToAlignment(void* Base, size_t MappedSize, size_t Size, size_t Align) {
#ifdef _WIN32
  return nullptr;
#else
  if (!Base || Align == 0) {
    return nullptr;
  }
  const uintptr_t Raw = reinterpret_cast<uintptr_t>(Base);
  const uintptr_t Aligned = (Raw + Align - 1) & ~(Align - 1);
  if (Aligned + Size > Raw + MappedSize) {
    return nullptr;
  }
  if (Aligned > Raw) {
    ::munmap(Base, Aligned - Raw);
  }
  const uintptr_t End = Aligned + Size;
  const uintptr_t RawEnd = Raw + MappedSize;
  if (RawEnd > End) {
    ::munmap(reinterpret_cast<void*>(End), RawEnd - End);
  }
  return reinterpret_cast<void*>(Aligned);
#endif
}

// FEX_THPLOG level: 0 off, 1 rollup line, 2 rollup + per-VMA-name breakdown.
inline int LogLevel() {
  int Current = Detail::LogValue.load(std::memory_order_relaxed);
  if (__builtin_expect(Current < 0, 0)) {
    const char* Env = ::getenv("FEX_THPLOG");
    Current = Env ? static_cast<int>(std::strtol(Env, nullptr, 10)) : 0;
    if (Current < 0) {
      Current = 0;
    }
    Detail::LogValue.store(Current, std::memory_order_relaxed);
  }
  return Current;
}

inline void SetLogLevel(int Level) {
  Detail::LogValue.store(Level < 0 ? 0 : Level, std::memory_order_relaxed);
}

namespace Detail {
// Per-VMA-name aggregation over /proc/self/smaps. Fixed tables, open/read only.
struct NameRow {
  char Name[40];
  uint64_t AnonHuge;
  uint64_t Rss;
};

inline void ReportPerName(int FD) {
#ifndef _WIN32
  constexpr size_t MaxRows = 48;
  NameRow Rows[MaxRows];
  size_t RowCount = 0;
  int Current = -1;

  auto RowFor = [&](const char* Name) -> int {
    for (size_t i = 0; i < RowCount; ++i) {
      if (std::strcmp(Rows[i].Name, Name) == 0) {
        return static_cast<int>(i);
      }
    }
    if (RowCount == MaxRows) {
      return static_cast<int>(MaxRows - 1); // overflow bucket: the last row
    }
    auto& R = Rows[RowCount];
    std::snprintf(R.Name, sizeof(R.Name), "%s", Name);
    R.AnonHuge = 0;
    R.Rss = 0;
    return static_cast<int>(RowCount++);
  };

  auto HandleLine = [&](char* Line) {
    // A mapping header starts with a hex range "xxxx-xxxx "; a field line
    // starts with a capitalised key and a colon.
    const char* Dash = std::strchr(Line, '-');
    const char* Colon = std::strchr(Line, ':');
    const bool Header = Dash && (!Colon || Dash < Colon) && std::strchr(Line, ' ') && Dash < std::strchr(Line, ' ');
    if (Header) {
      // Name is the last whitespace-separated field, if there are more than five.
      char Name[40] = "[anon]";
      int Fields = 0;
      const char* P = Line;
      const char* Last = nullptr;
      while (*P) {
        while (*P == ' ' || *P == '\t') {
          ++P;
        }
        if (!*P || *P == '\n') {
          break;
        }
        Last = P;
        ++Fields;
        while (*P && *P != ' ' && *P != '\t' && *P != '\n') {
          ++P;
        }
      }
      if (Fields >= 6 && Last) {
        const char* E = Last;
        while (*E && *E != '\n') {
          ++E;
        }
        size_t Len = static_cast<size_t>(E - Last);
        // File-backed: keep only the basename so every libfoo.so page is one row.
        if (Last[0] == '/') {
          const char* Base = Last;
          for (const char* Q = Last; Q < E; ++Q) {
            if (*Q == '/') {
              Base = Q + 1;
            }
          }
          Len = static_cast<size_t>(E - Base);
          Last = Base;
        }
        if (Len >= sizeof(Name)) {
          Len = sizeof(Name) - 1;
        }
        std::memcpy(Name, Last, Len);
        Name[Len] = 0;
      }
      Current = RowFor(Name);
      return;
    }
    if (Current < 0) {
      return;
    }
    uint64_t V = 0;
    if (std::strncmp(Line, "AnonHugePages:", 14) == 0 && FindKB(Line, "AnonHugePages:", &V)) {
      Rows[Current].AnonHuge += V;
    } else if (std::strncmp(Line, "Rss:", 4) == 0 && FindKB(Line, "Rss:", &V)) {
      Rows[Current].Rss += V;
    }
  };

  char Buf[8192];
  size_t Fill = 0;
  bool Skipping = false; // a line longer than the buffer: drop it to its newline
  for (;;) {
    const ssize_t N = ::read(FD, Buf + Fill, sizeof(Buf) - 1 - Fill);
    if (N <= 0) {
      break;
    }
    Fill += static_cast<size_t>(N);
    Buf[Fill] = 0;
    size_t Start = 0;
    for (;;) {
      char* NL = static_cast<char*>(std::memchr(Buf + Start, '\n', Fill - Start));
      if (!NL) {
        break;
      }
      *NL = 0;
      if (!Skipping) {
        HandleLine(Buf + Start);
      }
      Skipping = false;
      Start = static_cast<size_t>(NL - Buf) + 1;
    }
    if (Start == 0 && Fill == sizeof(Buf) - 1) {
      // No newline in a full buffer: this line is longer than the buffer.
      Skipping = true;
      Fill = 0;
      continue;
    }
    std::memmove(Buf, Buf + Start, Fill - Start);
    Fill -= Start;
  }

  for (size_t i = 0; i < RowCount; ++i) {
    if (Rows[i].AnonHuge == 0 && Rows[i].Rss < 16384) {
      continue; // noise: small and not huge
    }
    char Line[160];
    const int L = std::snprintf(Line, sizeof(Line), "[FEX THP]   %-28s AnonHugePages=%9llu kB  Rss=%9llu kB\n", Rows[i].Name,
                                static_cast<unsigned long long>(Rows[i].AnonHuge), static_cast<unsigned long long>(Rows[i].Rss));
    if (L > 0) {
      [[maybe_unused]] auto _ = ::write(2, Line, static_cast<size_t>(L));
    }
  }
#endif
}
} // namespace Detail

// The FEX_THPLOG report. Once per process; every exit path may call it. Tag
// names the path ("exit_group", "signal", "atexit") so a log with several
// processes (Steam, wine) reads unambiguously.
inline void Report(const char* Tag) {
#ifndef _WIN32
  if (LogLevel() <= 0) {
    return;
  }
  if (Detail::Reported.exchange(true, std::memory_order_acq_rel)) {
    return;
  }

  char Rollup[4096];
  uint64_t AnonHuge = 0, Rss = 0;
  if (Detail::ReadSmallFile("/proc/self/smaps_rollup", Rollup, sizeof(Rollup))) {
    Detail::FindKB(Rollup, "AnonHugePages:", &AnonHuge);
    Detail::FindKB(Rollup, "Rss:", &Rss);
  }

  char EnabledBuf[96] = "?";
  if (Detail::ReadSmallFile("/sys/kernel/mm/transparent_hugepage/enabled", EnabledBuf, sizeof(EnabledBuf))) {
    // "always [madvise] never" -> "madvise"
    char* L = std::strchr(EnabledBuf, '[');
    char* R = L ? std::strchr(L, ']') : nullptr;
    if (L && R) {
      *R = 0;
      std::memmove(EnabledBuf, L + 1, static_cast<size_t>(R - L));
    } else if (char* NL = std::strchr(EnabledBuf, '\n')) {
      *NL = 0;
    }
  }

  char MaskBuf[64];
  char Line[320];
  const int L = std::snprintf(Line, sizeof(Line),
                              "[FEX THP] pid=%d exit=%s mask=%s(0x%x) pmd=%zu enabled=%s AnonHugePages=%llu kB Rss=%llu kB\n",
                              static_cast<int>(::getpid()), Tag ? Tag : "?", MaskToString(Mask(), MaskBuf, sizeof(MaskBuf)), Mask(),
                              PMDSize(), EnabledBuf, static_cast<unsigned long long>(AnonHuge), static_cast<unsigned long long>(Rss));
  if (L > 0) {
    [[maybe_unused]] auto _ = ::write(2, Line, static_cast<size_t>(L));
  }

  if (LogLevel() >= 2) {
    const int FD = ::open("/proc/self/smaps", O_RDONLY | O_CLOEXEC);
    if (FD >= 0) {
      Detail::ReportPerName(FD);
      ::close(FD);
    }
  }
#endif
}

namespace Detail {
inline void AtExitReport() {
  Report("atexit");
}
} // namespace Detail

// Arms the report for a host-side exit(): the bridge lane (Wine's exit runs the
// host's atexit chain) and the interpreter's own return from main. The guest's
// exit_group and the fatal-signal path call Report() directly, since neither
// runs atexit handlers.
inline void InstallReportAtExit() {
  if (LogLevel() <= 0) {
    return;
  }
  if (Detail::AtExitInstalled.exchange(true, std::memory_order_acq_rel)) {
    return;
  }
  std::atexit(Detail::AtExitReport);
}

} // namespace FEXCore::Allocator::THP
