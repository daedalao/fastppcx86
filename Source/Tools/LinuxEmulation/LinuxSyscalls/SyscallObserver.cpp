// SPDX-License-Identifier: MIT
//
// SyscallObserver implementation. See SyscallObserver.h for the design intent.

#include "Tools/LinuxEmulation/LinuxSyscalls/SyscallObserver.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <linux/futex.h>
#include <time.h>

namespace FEX::HLE::SyscallObserver {

namespace {
// Config readers MUST NOT be at namespace scope -- the Getter constructor
// touches FEXCore::Config's hash map, which is not yet initialized at C++
// static-init time. Move them to function-local statics so they are
// initialized lazily, on first call (which by then is after FEX has loaded
// its config). Otherwise we SIGSEGV on the first .find() in MetaLayer.
//

// Storm detector tunables. Set conservatively so legitimate brief bursts
// (a few retries during normal mutex acquisition) don't fire — only sustained
// patterns indicating true livelock get flagged.
constexpr uint32_t kStormStreakThreshold = 16;       // back-to-back EAGAINs
constexpr uint64_t kStormWindowNs = 10'000'000ULL;   // within 10 ms

// Cap the log rate once a storm is sustained — first crossing fires once,
// then re-fires every N additional EAGAINs to confirm "still stuck" without
// flooding the log.
constexpr uint32_t kStormLogRepeatEvery = 256;

struct ThreadObserver {
  // Per-thread storm detector for futex(FUTEX_WAIT, ...) returning EAGAIN.
  uintptr_t LastFutexAddr {0};
  uint32_t  LastFutexOp {0};
  uint32_t  LastFutexVal {0};
  uint32_t  LastFutexEAGAINStreak {0};
  uint64_t  LastFutexFirstEAGAINNs {0};
};

thread_local ThreadObserver State {};

inline uint64_t MonotonicNs() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return uint64_t(ts.tv_sec) * 1'000'000'000ULL + ts.tv_nsec;
}
} // namespace

FutexAction OnFutexReturn(uint64_t uaddr, uint64_t futex_op, uint64_t val, int64_t signed_result) {
  static FEX_CONFIG_OPT(SyscallObserve, SYSCALLOBSERVE);
  static FEX_CONFIG_OPT(FutexMitigate, FUTEXMITIGATE);

  // Hot-path: zero work when observer is disabled. One bool load + branch.
  if (!SyscallObserve()) {
    return FutexAction::JustReturn;
  }

  const int cmd = static_cast<int>(futex_op) & FUTEX_CMD_MASK;
  const bool is_wait = (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET);
  const bool is_eagain = (signed_result == -EAGAIN);

  if (!is_wait) {
    // Storm detection is only meaningful for WAIT operations — WAKE returning
    // 0 wakers is normal behavior on quiet futexes.
    return FutexAction::JustReturn;
  }

  if (!is_eagain) {
    // Successful wait (woke up) or timed out or interrupted — progress. Reset.
    if (State.LastFutexEAGAINStreak > 0) {
      State.LastFutexEAGAINStreak = 0;
      State.LastFutexAddr = 0;
    }
    return FutexAction::JustReturn;
  }

  // is_wait && is_eagain — kernel rejected the wait because *uaddr != val.
  // Track repeats.
  const bool same_call = (uaddr == State.LastFutexAddr &&
                          uint32_t(futex_op) == State.LastFutexOp &&
                          uint32_t(val) == State.LastFutexVal);

  if (!same_call) {
    State.LastFutexAddr = uaddr;
    State.LastFutexOp = uint32_t(futex_op);
    State.LastFutexVal = uint32_t(val);
    State.LastFutexEAGAINStreak = 1;
    State.LastFutexFirstEAGAINNs = MonotonicNs();
    return FutexAction::JustReturn;
  }

  ++State.LastFutexEAGAINStreak;
  const uint64_t now = MonotonicNs();
  const uint64_t elapsed = now - State.LastFutexFirstEAGAINNs;

  if (State.LastFutexEAGAINStreak < kStormStreakThreshold || elapsed > kStormWindowNs) {
    return FutexAction::JustReturn;
  }

  // Storm confirmed.
  if (State.LastFutexEAGAINStreak == kStormStreakThreshold ||
      (State.LastFutexEAGAINStreak % kStormLogRepeatEvery == 0)) {
    LogMan::Msg::IFmt("SyscallObserver: futex EAGAIN-storm "
                      "tid={} addr={:#x} op={:#x} val={:#x} streak={} elapsed_us={}",
                      FHU::Syscalls::gettid(),
                      uaddr, futex_op, val,
                      State.LastFutexEAGAINStreak, elapsed / 1000);
  }

  return FutexMitigate() ? FutexAction::ThenYield : FutexAction::JustReturn;
}

void OnTgkillCall(uint64_t tgid, uint64_t tid, uint64_t sig) {
  static FEX_CONFIG_OPT(SyscallObserve, SYSCALLOBSERVE);
  if (SyscallObserve()) {
    LogMan::Msg::IFmt("SyscallObserver: tgkill tgid={} tid={} sig={} from-tid={}",
                      tgid, tid, sig, FHU::Syscalls::gettid());
  }
}

} // namespace FEX::HLE::SyscallObserver
