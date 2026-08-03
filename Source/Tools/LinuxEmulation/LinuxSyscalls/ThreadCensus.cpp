// SPDX-License-Identifier: MIT
//
// ThreadCensus implementation. See ThreadCensus.h for the design intent.

#include "LinuxSyscalls/ThreadCensus.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <fmt/format.h>

#include <algorithm>
#include <bit>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#ifndef SCHED_BATCH
#define SCHED_BATCH 3
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif
#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif

namespace FEX::HLE::ThreadCensus {

namespace {
  // Config readers MUST NOT be at namespace scope -- the Getter constructor
  // touches FEXCore::Config's hash map, which is not yet initialized at C++
  // static-init time. Function-local statics are initialized lazily, on the
  // first guest syscall, which is long after FEX has loaded its config.

  // Opened once, on first use, and deliberately never closed: the census
  // outlives every guest thread and a leaked fd at exit is harmless. O_APPEND
  // makes each write(2) atomically land at the end of file, which is what lets
  // concurrent guest threads share the fd without a mutex (a single write per
  // line, and lines are far below PIPE_BUF/page granularity).
  //
  // -1 means "disabled or unopenable" and is the permanent fast-path answer.
  int CensusFD() {
    static const int FD = []() -> int {
      FEX_CONFIG_OPT(CensusPath, THREADCENSUS);
      const auto& Path = CensusPath();
      if (Path.empty()) {
        return -1;
      }

      const int Opened = ::open(Path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (Opened < 0) {
        LogMan::Msg::EFmt("ThreadCensus: couldn't open '{}' for append (errno {}). Census disabled.", Path.c_str(), errno);
        return -1;
      }
      return Opened;
    }();
    return FD;
  }

  uint64_t MonotonicMs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000ULL + uint64_t(ts.tv_nsec) / 1'000'000ULL;
  }

  // Emits exactly one line: "<monotonic-ms> tid=<n> event=<type>" followed by
  // whatever the caller formats (which must start with its own separator space)
  // and a trailing newline. Never allocates -- fmt::format_to_n writes into the
  // stack buffer and truncates rather than growing.
  template<typename... Args>
  void EmitLine(int64_t Tid, const char* Event, fmt::format_string<Args...> Fmt, Args&&... args) {
    const int FD = CensusFD();
    if (FD < 0) {
      return;
    }

    char Buffer[512];
    constexpr size_t MaxPayload = sizeof(Buffer) - 1; // Reserve one byte for the newline.

    const auto Head = fmt::format_to_n(Buffer, MaxPayload, "{} tid={} event={}", MonotonicMs(), Tid, Event);
    size_t Length = std::min(Head.size, MaxPayload);

    const auto Tail = fmt::format_to_n(Buffer + Length, MaxPayload - Length, Fmt, std::forward<Args>(args)...);
    Length += std::min(Tail.size, MaxPayload - Length);

    Buffer[Length] = '\n';
    ++Length;

    [[maybe_unused]] const auto Written = ::write(FD, Buffer, Length);
  }

  const char* PolicyName(int Policy) {
    if (Policy < 0) {
      return "n/a";
    }
    switch (Policy & ~SCHED_RESET_ON_FORK) {
    case SCHED_OTHER: return "SCHED_OTHER";
    case SCHED_FIFO: return "SCHED_FIFO";
    case SCHED_RR: return "SCHED_RR";
    case SCHED_BATCH: return "SCHED_BATCH";
    case SCHED_IDLE: return "SCHED_IDLE";
    case SCHED_DEADLINE: return "SCHED_DEADLINE";
    default: return "SCHED_UNKNOWN";
    }
  }

  const char* KindName(CloneKind Kind) {
    switch (Kind) {
    case CloneKind::Thread: return "thread";
    case CloneKind::Fork: return "fork";
    case CloneKind::RawClone: return "rawclone";
    default: return "unknown";
    }
  }

  // "passed through and the kernel accepted it" vs "passed through and the
  // kernel refused". FEX does not fake either of these syscalls, so the only
  // two dispositions are the two passthrough outcomes.
  const char* Disposition(int64_t GuestResult) {
    return GuestResult < 0 ? "passthrough-fail" : "passthrough-ok";
  }

  int64_t ResolveTID(int64_t TargetTID) {
    // A tid/pid argument of 0 means "the calling thread" for the whole sched_*
    // family, so resolve it to something a reader can correlate.
    return TargetTID == 0 ? static_cast<int64_t>(FHU::Syscalls::gettid()) : TargetTID;
  }
} // namespace

bool Enabled() {
  return CensusFD() >= 0;
}

void OnThreadCreate(CloneKind Kind, uint64_t GuestTID, uint64_t HostTID, uint64_t ParentTID, uint64_t GuestRIP, uint64_t CloneFlags) {
  if (!Enabled()) {
    return;
  }

  if (GuestTID == HostTID) {
    EmitLine(static_cast<int64_t>(GuestTID), "thread_create", " kind={} parent_tid={} rip={:#x} flags={:#x}", KindName(Kind), ParentTID,
             GuestRIP, CloneFlags);
  } else {
    EmitLine(static_cast<int64_t>(GuestTID), "thread_create", " kind={} host_tid={} parent_tid={} rip={:#x} flags={:#x}", KindName(Kind),
             HostTID, ParentTID, GuestRIP, CloneFlags);
  }
}

void OnSetName(const char* Name) {
  if (!Enabled()) {
    return;
  }

  // The kernel caps thread names at 16 bytes including the NUL, and this is
  // only reached after the host prctl succeeded, so Name is readable up to
  // that bound. Sanitize to keep the line single-token parseable.
  char Sanitized[17] {};
  size_t Length = Name ? ::strnlen(Name, sizeof(Sanitized) - 1) : 0;
  for (size_t i = 0; i < Length; ++i) {
    const unsigned char Char = static_cast<unsigned char>(Name[i]);
    Sanitized[i] = (Char > 0x20 && Char < 0x7F) ? static_cast<char>(Char) : '_';
  }
  Sanitized[Length] = 0;

  EmitLine(static_cast<int64_t>(FHU::Syscalls::gettid()), "set_name", " name={}", static_cast<const char*>(Sanitized));
}

void OnSchedSet(const char* Event, int64_t TargetTID, int Policy, int Priority, int64_t GuestResult) {
  if (!Enabled()) {
    return;
  }

  EmitLine(ResolveTID(TargetTID), Event, " caller_tid={} policy={} policy_raw={} prio={} disp={} ret={}", FHU::Syscalls::gettid(),
           PolicyName(Policy), Policy, Priority, Disposition(GuestResult), GuestResult);
}

void OnSetAffinity(int64_t TargetTID, const uint8_t* Mask, size_t MaskBytes, int64_t GuestResult) {
  if (!Enabled()) {
    return;
  }

  // Summary only, per the diagnostic contract: popcount plus the lowest and
  // highest set bit. Bound the read so an absurd cpusetsize can't walk us off
  // the end of the guest's buffer.
  MaskBytes = Mask ? std::min<size_t>(MaskBytes, 128) : 0;

  uint32_t Count = 0;
  int Lowest = -1;
  int Highest = -1;
  for (size_t i = 0; i < MaskBytes; ++i) {
    const uint8_t Byte = Mask[i];
    if (!Byte) {
      continue;
    }
    Count += static_cast<uint32_t>(std::popcount(Byte));
    if (Lowest < 0) {
      Lowest = static_cast<int>(i * 8 + static_cast<size_t>(std::countr_zero(Byte)));
    }
    Highest = static_cast<int>(i * 8 + 7 - static_cast<size_t>(std::countl_zero(Byte)));
  }

  EmitLine(ResolveTID(TargetTID), "sched_setaffinity", " caller_tid={} cpus={} lo={} hi={} bytes={} disp={} ret={}",
           FHU::Syscalls::gettid(), Count, Lowest, Highest, MaskBytes, Disposition(GuestResult), GuestResult);
}

void OnSchedBoost(int64_t TargetTID, const char* Step, int Policy, int Value, int64_t HostResult, int64_t GuestResult) {
  if (!Enabled()) {
    return;
  }

  EmitLine(ResolveTID(TargetTID), "sched_boost", " step={} policy={} val={} host_ret={} guest_ret={}", Step, PolicyName(Policy), Value,
           HostResult, GuestResult);
}

} // namespace FEX::HLE::ThreadCensus

namespace FEX::HLE::SchedPassthrough {

namespace {
  // setpriority(2) legitimately returns -1 as a successful new nice value, so
  // the errno-clearing dance is mandatory here.
  bool TryNice(pid_t Tid, int Target, int64_t& HostResult) {
    errno = 0;
    const int Result = ::setpriority(PRIO_PROCESS, static_cast<id_t>(Tid), Target);
    if (Result == -1 && errno != 0) {
      HostResult = -errno;
      return false;
    }
    HostResult = 0;
    return true;
  }
} // namespace

void OnSchedRequestRefused(int64_t TargetTID, int Policy, int Priority, int64_t GuestResult) {
  static FEX_CONFIG_OPT(DoSchedPassthrough, SCHEDPASSTHROUGH);
  if (!DoSchedPassthrough()) {
    return;
  }

  // The only refusal this can do anything about is a permission refusal on an
  // RT policy. Anything else (EINVAL, ESRCH, success) is left alone: FEX has
  // already forwarded the request verbatim and the host did what it did.
  if (GuestResult != -EPERM) {
    return;
  }

  const int BasePolicy = Policy & ~SCHED_RESET_ON_FORK;
  if (BasePolicy != SCHED_FIFO && BasePolicy != SCHED_RR) {
    return;
  }

  const pid_t Tid = TargetTID == 0 ? FHU::Syscalls::gettid() : static_cast<pid_t>(TargetTID);

  // Rung 1: SCHED_RR at the lowest priority the RT rlimit permits. If
  // RLIMIT_RTPRIO is 0 we'd only earn a second EPERM (a process with
  // CAP_SYS_NICE would not have been refused in the first place), so skip.
  {
    struct rlimit RTPrioLimit {};
    if (::getrlimit(RLIMIT_RTPRIO, &RTPrioLimit) == 0 && RTPrioLimit.rlim_cur != 0) {
      const int MinRR = ::sched_get_priority_min(SCHED_RR);
      if (MinRR >= 0) {
        struct sched_param Param {};
        Param.sched_priority = MinRR;

        errno = 0;
        const int Result = ::sched_setscheduler(Tid, SCHED_RR, &Param);
        const int64_t HostResult = Result == 0 ? 0 : -errno;
        FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "rr", SCHED_RR, MinRR, HostResult, GuestResult);
        if (Result == 0) {
          return;
        }
      }
    }
  }

  // Rung 2: niceness boost. Try -10 outright first — that succeeds outright
  // for a CAP_SYS_NICE process and for anyone whose RLIMIT_NICE allows it.
  {
    int64_t HostResult {};
    if (TryNice(Tid, -10, HostResult)) {
      FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "nice", -1, -10, HostResult, GuestResult);
      return;
    }
    FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "nice", -1, -10, HostResult, GuestResult);

    // Clamp to the rlimit: RLIMIT_NICE's soft limit expresses the ceiling as
    // 20 - rlim_cur, so that's the most negative nice we may request.
    struct rlimit NiceLimit {};
    if (::getrlimit(RLIMIT_NICE, &NiceLimit) == 0) {
      const int Floor = NiceLimit.rlim_cur >= 40 ? -20 : static_cast<int>(20 - static_cast<int64_t>(NiceLimit.rlim_cur));
      if (Floor < 0 && Floor > -10) {
        if (TryNice(Tid, Floor, HostResult)) {
          FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "nice-clamped", -1, Floor, HostResult, GuestResult);
          return;
        }
        FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "nice-clamped", -1, Floor, HostResult, GuestResult);
      }
    }
  }

  // Rung 3: nothing left to try. The guest still gets its original EPERM.
  FEX::HLE::ThreadCensus::OnSchedBoost(TargetTID, "giveup", BasePolicy, Priority, -EPERM, GuestResult);
}

} // namespace FEX::HLE::SchedPassthrough
