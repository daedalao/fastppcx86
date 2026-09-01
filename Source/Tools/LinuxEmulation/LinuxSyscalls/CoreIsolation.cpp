// SPDX-License-Identifier: MIT
//
// CoreIsolation implementation. See CoreIsolation.h and
// docs/CORE_ISOLATION_PLAN.md for the design; the short version:
//
//   sample 2Hz -> rank guest threads by CPU share -> vet the top thread's
//   voluntary-context-switch rate (spinner filter) -> require 4 stable
//   windows -> pin it to a reserved core and evict everyone else off that
//   core's SMT siblings -> release after 8 windows below the floor.
//
// Manager-thread discipline: everything here runs on one host thread with
// all signals blocked. It takes exactly one FEX lock (ThreadCreationMutex,
// non-blocking via TryForEachThread) for a tid snapshot and holds it for no
// syscalls. All /proc sampling and affinity application happens lock-free on
// plain host tids; a tid that exits between snapshot and use just yields
// ESRCH, which every consumer treats as "gone, skip".

#include "LinuxSyscalls/CoreIsolation.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/ThreadCensus.h"
#include "LinuxSyscalls/ThreadManager.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <sched.h>
#include <set>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <vector>

namespace FEX::HLE::CoreIsolation {

namespace {

  // --- tunables -----------------------------------------------------------
  constexpr uint64_t TickNs = 500'000'000; // 2Hz sampling.
  constexpr uint32_t EngageTicks = 4;      // Stable windows before pinning.
  constexpr uint32_t ReleaseTicks = 8;     // Weak windows before releasing.
  constexpr double ShareEngage = 0.55;     // Of one CPU, over the window.
  constexpr double ShareRelease = 0.35;
  // A busy render/game thread parks a few thousand times per second at most;
  // a futex-cycling spin-waiter shows one to two orders of magnitude more.
  constexpr uint64_t MaxVoluntarySwitchRate = 10'000; // per second
  // Presents older than this mean a loading screen / stalled swapchain:
  // freeze candidate churn rather than chase decompression workers.
  constexpr uint64_t PresentQuietNs = 2'000'000'000;

  // --- presenter notification (written from guest threads) ----------------
  std::atomic<uint32_t> PresenterTID {0};
  std::atomic<uint64_t> LastPresentNs {0};

  // --- manager state (manager thread only, after Start) -------------------
  FEX::HLE::SyscallHandler* Handler {nullptr};
  pid_t ManagerPID {0}; // Guards every entry point against forked children.

  std::mutex GuestOwnedMutex;
  std::set<uint32_t> GuestOwnedTids;

  bool IsGuestOwned(uint32_t Tid) {
    std::lock_guard lk(GuestOwnedMutex);
    return GuestOwnedTids.contains(Tid);
  }

  uint64_t NowNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1'000'000'000ULL + uint64_t(ts.tv_nsec);
  }

  template<typename... Args>
  void Decision(int64_t Tid, fmt::format_string<Args...> Fmt, Args&&... args) {
    char Buffer[384];
    const auto End = fmt::format_to_n(Buffer, sizeof(Buffer) - 1, Fmt, std::forward<Args>(args)...);
    const size_t Len = std::min(End.size, sizeof(Buffer) - 1);
    Buffer[Len] = 0;
    LogMan::Msg::IFmt("CoreIsolation: tid={} {}", Tid, Buffer);
    FEX::HLE::ThreadCensus::OnIsolationEvent(Tid, std::string_view(Buffer, Len));
  }

  // --- /proc readers ------------------------------------------------------

  // Whole-file read into a small stack buffer; -1 on any failure.
  ssize_t ReadSmallFile(const char* Path, char* Buffer, size_t Size) {
    const int FD = ::open(Path, O_RDONLY | O_CLOEXEC);
    if (FD < 0) {
      return -1;
    }
    const ssize_t Got = ::read(FD, Buffer, Size - 1);
    ::close(FD);
    if (Got < 0) {
      return -1;
    }
    Buffer[Got] = 0;
    return Got;
  }

  // /proc/self/task/<tid>/schedstat: "<runtime-ns> <waitqueue-ns> <slices>".
  bool ReadRuntimeNs(uint32_t Tid, uint64_t* RuntimeNs) {
    char Path[64];
    char Buffer[128];
    snprintf(Path, sizeof(Path), "/proc/self/task/%u/schedstat", Tid);
    if (ReadSmallFile(Path, Buffer, sizeof(Buffer)) <= 0) {
      return false;
    }
    *RuntimeNs = strtoull(Buffer, nullptr, 10);
    return true;
  }

  // voluntary_ctxt_switches from /proc/self/task/<tid>/status (last lines,
  // so read the whole thing — it is ~1.5KB).
  bool ReadVoluntarySwitches(uint32_t Tid, uint64_t* Count) {
    char Path[64];
    char Buffer[4096];
    snprintf(Path, sizeof(Path), "/proc/self/task/%u/status", Tid);
    if (ReadSmallFile(Path, Buffer, sizeof(Buffer)) <= 0) {
      return false;
    }
    const char* Line = strstr(Buffer, "voluntary_ctxt_switches:");
    if (!Line) {
      return false;
    }
    *Count = strtoull(Line + strlen("voluntary_ctxt_switches:"), nullptr, 10);
    return true;
  }

  // CPU the thread last ran on: field 39 of /proc/self/task/<tid>/stat,
  // counted after the last ')' (comm may contain spaces and parentheses).
  int ReadLastCPU(uint32_t Tid) {
    char Path[64];
    char Buffer[1024];
    snprintf(Path, sizeof(Path), "/proc/self/task/%u/stat", Tid);
    if (ReadSmallFile(Path, Buffer, sizeof(Buffer)) <= 0) {
      return -1;
    }
    const char* P = strrchr(Buffer, ')');
    if (!P) {
      return -1;
    }
    // ')' is the end of field 2; skip forward to field 39.
    int Field = 2;
    while (*P && Field < 39) {
      if (*P == ' ') {
        ++Field;
      }
      ++P;
    }
    return Field == 39 ? atoi(P) : -1;
  }

  // --- topology -----------------------------------------------------------

  struct Core {
    std::vector<uint32_t> CPUs; // All SMT siblings, primary first.
  };

  cpu_set_t AllowedMask;      // Initial mask (the cage cpuset).
  std::vector<Core> Cores;    // Only cores fully inside AllowedMask.

  // Parse "72-75,152" style lists.
  void ParseCPUList(const char* List, std::vector<uint32_t>* Out) {
    const char* P = List;
    while (*P && *P != '\n') {
      char* End;
      const unsigned long A = strtoul(P, &End, 10);
      if (End == P) {
        break;
      }
      unsigned long B = A;
      P = End;
      if (*P == '-') {
        B = strtoul(P + 1, &End, 10);
        P = End;
      }
      for (unsigned long C = A; C <= B; ++C) {
        Out->push_back(static_cast<uint32_t>(C));
      }
      if (*P == ',') {
        ++P;
      }
    }
  }

  void BuildTopology() {
    CPU_ZERO(&AllowedMask);
    if (::sched_getaffinity(0, sizeof(AllowedMask), &AllowedMask) != 0) {
      return;
    }
    std::set<uint32_t> Seen;
    for (uint32_t CPU = 0; CPU < CPU_SETSIZE; ++CPU) {
      if (!CPU_ISSET(CPU, &AllowedMask) || Seen.contains(CPU)) {
        continue;
      }
      char Path[128];
      char Buffer[256];
      snprintf(Path, sizeof(Path), "/sys/devices/system/cpu/cpu%u/topology/thread_siblings_list", CPU);
      if (ReadSmallFile(Path, Buffer, sizeof(Buffer)) <= 0) {
        continue;
      }
      Core C;
      ParseCPUList(Buffer, &C.CPUs);
      bool AllAllowed = !C.CPUs.empty();
      for (const uint32_t Sib : C.CPUs) {
        Seen.insert(Sib);
        AllAllowed &= Sib < CPU_SETSIZE && CPU_ISSET(Sib, &AllowedMask);
      }
      // Only a core we fully own is reservable — a sibling outside the cage
      // belongs to someone else (sunshine's cores on op4k) and vacating it
      // is not ours to promise.
      if (AllAllowed) {
        Cores.push_back(std::move(C));
      }
    }
  }

  // --- the manager --------------------------------------------------------

  struct Sample {
    uint64_t RuntimeNs {0};
    uint64_t VoluntarySwitches {0};
    bool HasSwitches {false};
  };

  struct ManagerState {
    // Previous-tick samples, keyed by tid (guest threads only).
    std::vector<std::pair<uint32_t, Sample>> Prev;
    uint64_t PrevTimeNs {0};

    uint32_t Candidate {0};
    uint32_t CandidateStreak {0};

    bool Engaged {false};
    uint32_t IsolatedTid {0};
    int ReservedCore {-1};
    uint32_t WeakStreak {0};
    // Tids we have ever evicted, to restore on release. Guest-owned tids are
    // never in here.
    std::set<uint32_t> Evicted;
  };

  Sample* FindPrev(ManagerState& S, uint32_t Tid) {
    for (auto& [T, Smp] : S.Prev) {
      if (T == Tid) {
        return &Smp;
      }
    }
    return nullptr;
  }

  cpu_set_t MaskOfCPUs(const std::vector<uint32_t>& CPUs) {
    cpu_set_t Set;
    CPU_ZERO(&Set);
    for (const uint32_t C : CPUs) {
      CPU_SET(C, &Set);
    }
    return Set;
  }

  cpu_set_t GeneralMask(int ReservedCore) {
    cpu_set_t Set = AllowedMask;
    if (ReservedCore >= 0) {
      for (const uint32_t C : Cores[ReservedCore].CPUs) {
        CPU_CLR(C, &Set);
      }
    }
    return Set;
  }

  int CoreOfCPU(int CPU) {
    if (CPU < 0) {
      return -1;
    }
    for (size_t i = 0; i < Cores.size(); ++i) {
      for (const uint32_t C : Cores[i].CPUs) {
        if (static_cast<int>(C) == CPU) {
          return static_cast<int>(i);
        }
      }
    }
    return -1;
  }

  // Move every thread in the process except IsolatedTid (and guest-owned
  // tids, which the guest placed deliberately) off the reserved core.
  void EvictOthers(ManagerState& S) {
    DIR* Dir = ::opendir("/proc/self/task");
    if (!Dir) {
      return;
    }
    const cpu_set_t General = GeneralMask(S.ReservedCore);
    while (struct dirent* Ent = ::readdir(Dir)) {
      const uint32_t Tid = static_cast<uint32_t>(strtoul(Ent->d_name, nullptr, 10));
      if (Tid == 0 || Tid == S.IsolatedTid || IsGuestOwned(Tid) || S.Evicted.contains(Tid)) {
        continue;
      }
      if (::sched_setaffinity(Tid, sizeof(General), &General) == 0) {
        S.Evicted.insert(Tid);
      }
      // ESRCH/EPERM: gone or not ours; skip silently.
    }
    ::closedir(Dir);
  }

  void Release(ManagerState& S, const char* Why) {
    Decision(S.IsolatedTid, "action=release reason={} evicted={}", Why, S.Evicted.size());
    for (const uint32_t Tid : S.Evicted) {
      ::sched_setaffinity(Tid, sizeof(AllowedMask), &AllowedMask);
    }
    if (S.IsolatedTid) {
      ::sched_setaffinity(S.IsolatedTid, sizeof(AllowedMask), &AllowedMask);
    }
    S.Evicted.clear();
    S.Engaged = false;
    S.IsolatedTid = 0;
    S.ReservedCore = -1;
    S.WeakStreak = 0;
    S.Candidate = 0;
    S.CandidateStreak = 0;
  }

  void Engage(ManagerState& S, uint32_t Tid, double Share) {
    // Prefer the core the thread already runs on (warm caches); any
    // reservable core otherwise. A guest-owned candidate is only isolatable
    // in place: if the guest pinned it to a single reservable core, vacate
    // that core's siblings and leave the thread untouched; a wide guest
    // mask means the guest wants spread — skip rather than second-guess.
    const bool GuestOwned = IsGuestOwned(Tid);
    int Target = CoreOfCPU(ReadLastCPU(Tid));
    if (GuestOwned) {
      cpu_set_t Current;
      if (::sched_getaffinity(Tid, sizeof(Current), &Current) != 0 || CPU_COUNT(&Current) != 1) {
        Decision(Tid, "action=skip reason=guest-owned-wide-mask share={:.2f}", Share);
        S.CandidateStreak = 0;
        return;
      }
      if (Target < 0) {
        Decision(Tid, "action=skip reason=guest-pin-outside-reservable share={:.2f}", Share);
        S.CandidateStreak = 0;
        return;
      }
    } else if (Target < 0) {
      Target = 0;
    }

    S.Engaged = true;
    S.IsolatedTid = Tid;
    S.ReservedCore = Target;
    S.WeakStreak = 0;

    if (!GuestOwned) {
      const cpu_set_t Primary = MaskOfCPUs({Cores[Target].CPUs.front()});
      ::sched_setaffinity(Tid, sizeof(Primary), &Primary);
    }
    EvictOthers(S);
    Decision(Tid, "action=engage core={} cpus={} share={:.2f} guest_owned={} evicted={}", Target,
             fmt::join(Cores[Target].CPUs, ","), Share, GuestOwned, S.Evicted.size());
  }

  void Tick(ManagerState& S) {
    const uint64_t Now = NowNs();
    const uint64_t WindowNs = S.PrevTimeNs ? Now - S.PrevTimeNs : 0;

    // Snapshot live guest tids without holding the lock across any syscall.
    std::vector<uint32_t> Tids;
    Tids.reserve(S.Prev.size() + 8);
    const bool Locked = Handler->TM.TryForEachThread([&](FEX::HLE::ThreadStateObject* Obj) {
      const uint32_t Tid = Obj->ThreadInfo.TID.load(std::memory_order_relaxed);
      if (Tid && !Obj->ThreadInfo.IsZombie.load(std::memory_order_relaxed)) {
        Tids.push_back(Tid);
      }
    });
    if (!Locked) {
      return; // Contended (fork/thread churn); try again next tick.
    }

    // Sample runtimes, compute shares against the previous tick.
    std::vector<std::pair<uint32_t, Sample>> Curr;
    Curr.reserve(Tids.size());
    uint32_t TopTid = 0;
    double TopShare = 0.0;
    uint64_t TopSwitchDelta = 0;
    bool TopSwitchValid = false;
    for (const uint32_t Tid : Tids) {
      Sample Smp;
      if (!ReadRuntimeNs(Tid, &Smp.RuntimeNs)) {
        continue;
      }
      Smp.HasSwitches = ReadVoluntarySwitches(Tid, &Smp.VoluntarySwitches);
      if (WindowNs) {
        if (const Sample* P = FindPrev(S, Tid)) {
          const double Share = double(Smp.RuntimeNs - P->RuntimeNs) / double(WindowNs);
          if (Share > TopShare) {
            TopShare = Share;
            TopTid = Tid;
            TopSwitchValid = Smp.HasSwitches && P->HasSwitches;
            TopSwitchDelta = TopSwitchValid ? Smp.VoluntarySwitches - P->VoluntarySwitches : 0;
          }
        }
      }
      Curr.emplace_back(Tid, Smp);
    }
    S.Prev = std::move(Curr);
    S.PrevTimeNs = Now;
    if (!WindowNs) {
      return;
    }

    // Loading gate: once a presenter exists, a quiet swapchain freezes all
    // state transitions — reservations persist, candidates don't churn. New
    // threads still get pushed off a reserved core.
    const uint64_t LastPresent = LastPresentNs.load(std::memory_order_relaxed);
    const bool PresentQuiet = LastPresent != 0 && Now - LastPresent > PresentQuietNs;
    if (S.Engaged) {
      EvictOthers(S);
    }
    if (PresentQuiet) {
      return;
    }

    if (S.Engaged) {
      // Existence + strength check on the isolated thread.
      uint64_t Dummy;
      if (!ReadRuntimeNs(S.IsolatedTid, &Dummy)) {
        Release(S, "thread-exited");
        return;
      }
      const bool Weak = S.IsolatedTid != TopTid || TopShare < ShareRelease;
      S.WeakStreak = Weak ? S.WeakStreak + 1 : 0;
      if (S.WeakStreak >= ReleaseTicks) {
        Release(S, "share-floor");
      }
      return;
    }

    // Candidate selection with the spinner filter.
    if (TopTid == 0 || TopShare < ShareEngage) {
      S.Candidate = 0;
      S.CandidateStreak = 0;
      return;
    }
    if (TopSwitchValid && TopSwitchDelta * 1'000'000'000ULL > MaxVoluntarySwitchRate * WindowNs) {
      Decision(TopTid, "action=veto reason=spinner share={:.2f} volsw_delta={}", TopShare, TopSwitchDelta);
      S.Candidate = 0;
      S.CandidateStreak = 0;
      return;
    }
    if (TopTid == S.Candidate) {
      if (++S.CandidateStreak >= EngageTicks) {
        Engage(S, TopTid, TopShare);
      }
    } else {
      Decision(TopTid, "action=candidate share={:.2f} presenter={}", TopShare, PresenterTID.load(std::memory_order_relaxed));
      S.Candidate = TopTid;
      S.CandidateStreak = 1;
    }
  }

  void* ManagerThread(void*) {
    pthread_setname_np(pthread_self(), "FEX:CoreIsolate");
    sigset_t All;
    sigfillset(&All);
    pthread_sigmask(SIG_BLOCK, &All, nullptr);

    Decision(-1, "action=start cores={} allowed_cpus={}", Cores.size(), CPU_COUNT(&AllowedMask));

    ManagerState S;
    struct timespec Delay {.tv_sec = 0, .tv_nsec = TickNs};
    while (true) {
      nanosleep(&Delay, nullptr);
      Tick(S);
    }
    return nullptr;
  }

} // anonymous namespace

void Start(FEX::HLE::SyscallHandler* SyscallHandler) {
  FEX_CONFIG_OPT(CoreIsolate, COREISOLATE);
  if (CoreIsolate() == 0) {
    return;
  }
  Handler = SyscallHandler;
  ManagerPID = ::getpid();
  BuildTopology();
  if (Cores.size() < 2) {
    // Isolation must leave at least one general-purpose core. A 1-core (or
    // unparseable) topology has nothing to give.
    LogMan::Msg::IFmt("CoreIsolation: {} reservable core(s) in the allowed mask; disabled", Cores.size());
    return;
  }
  pthread_t Thread;
  if (pthread_create(&Thread, nullptr, ManagerThread, nullptr) != 0) {
    LogMan::Msg::EFmt("CoreIsolation: manager thread creation failed (errno {}); disabled", errno);
    return;
  }
  pthread_detach(Thread);
}

void OnGuestSetAffinity(uint32_t TargetTID) {
  if (!Handler || ::getpid() != ManagerPID) {
    return;
  }
  std::lock_guard lk(GuestOwnedMutex);
  GuestOwnedTids.insert(TargetTID);
}

} // namespace FEX::HLE::CoreIsolation

// Called by host thunk libraries (64-bit VK: vkQueuePresentKHR) on the guest
// thread performing a present. Resolved lazily via dlsym(RTLD_DEFAULT) from
// the thunk side, so this must keep default visibility and C linkage.
extern "C" FEX_DEFAULT_VISIBILITY void FEX_NotifyGuestPresent() {
  FEX::HLE::CoreIsolation::PresenterTID.store(static_cast<uint32_t>(FHU::Syscalls::gettid()), std::memory_order_relaxed);
  FEX::HLE::CoreIsolation::LastPresentNs.store(FEX::HLE::CoreIsolation::NowNs(), std::memory_order_relaxed);
}
