// SPDX-License-Identifier: MIT
#pragma once
//
// SyscallObserver — per-thread instrumentation for pathology-prone syscalls.
//
// Design intent: the observer NEVER substitutes the syscall mechanism.
// Wrappers in Passthrough.cpp call the existing SyscallPassthrough<N> templates
// (which use inline `sc` + PPC64_SYSCALL_RESULT — byte-identical kernel ABI)
// and only consult the observer for *side-effects*: logging and an optional
// sched_yield() recommendation. Even with the observer buggy, the syscall
// return value to the guest stays correct.
//
// Runtime-toggleable via FEX_SYSCALLOBSERVE; mitigation gated separately by
// FEX_FUTEXMITIGATE. Both default false — zero cost when disabled.

#include <cstdint>

namespace FEX::HLE::SyscallObserver {

// What the futex wrapper should do AFTER calling the kernel.
enum class FutexAction : uint8_t {
  JustReturn,   // Default — return the syscall result to the guest.
  ThenYield,    // Storm detected; sched_yield() before returning (when FutexMitigate is on).
};

// Called after a futex syscall returns. Reads tunables, updates per-thread state,
// emits a log on storm detection.
// Args mirror the futex(2) prototype: addr, op, val are the first three; result
// is the kernel-style -errno-on-failure return value.
[[nodiscard]] FutexAction OnFutexReturn(uint64_t uaddr,
                                        uint64_t futex_op,
                                        uint64_t val,
                                        int64_t signed_result);

// Called before a tgkill syscall. Pure logging; no decision to return.
void OnTgkillCall(uint64_t tgid, uint64_t tid, uint64_t sig);

} // namespace FEX::HLE::SyscallObserver
