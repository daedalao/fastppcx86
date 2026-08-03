// SPDX-License-Identifier: MIT
#pragma once
//
// ThreadCensus — append-only census of guest thread lifecycle and scheduling
// requests, plus the (separately gated) host RT-scheduling passthrough that
// piggybacks on the same instrumentation points.
//
// Design intent mirrors SyscallObserver.h: the census NEVER substitutes the
// syscall mechanism and NEVER influences what the guest sees. Call sites run
// the pre-existing implementation (bare SyscallPassthrough<N> templates, or
// the existing prctl/clone handlers), hand the *already computed* result to
// the census, and return that same result. Even with everything here broken,
// guest-visible semantics are byte-identical.
//
// Feature 1 — FEX_THREADCENSUS=<path>: append one plain-text line per event to
// <path>. Unset (the default) means the file is never opened and every entry
// point short-circuits on a single int load.
//
// Feature 2 — FEX_SCHEDPASSTHROUGH=1: when the host kernel refuses a guest
// SCHED_FIFO/SCHED_RR request with EPERM, try progressively weaker real host
// scheduling boosts (SCHED_RR at the lowest permitted priority, then a
// niceness boost). The guest still receives the original EPERM. Off by
// default; inert unless the host actually refused.
//
// Line format (single write(2) to an O_APPEND fd, so lines never interleave):
//   <monotonic-ms> tid=<n> event=<type> <key=val>...
//
// Signal safety: every call site is a guest syscall handler, which FEX runs in
// normal thread context (the JIT calls into SyscallHandler::HandleSyscall on
// the guest thread's own host stack) — not from a signal handler. So the
// config getters, clock_gettime and open() used here are all fine.

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace FEX::HLE::ThreadCensus {

// Which flavour of thread/process creation produced the event.
enum class CloneKind : uint8_t {
  Thread,   // CLONE_THREAD — FEX-managed guest thread (CreateNewThread).
  Fork,     // fork/vfork/clone without CLONE_THREAD (ForkGuest).
  RawClone, // clone/clone3 with flags FEX can't emulate, forwarded to the host.
};

// Cheap gate. One function-local-static load; false unless FEX_THREADCENSUS
// names a file that opened successfully.
[[nodiscard]] bool Enabled();

// A new guest thread/process exists. GuestTID/HostTID are logged separately
// only when they differ. GuestRIP is the raw guest RIP of the clone caller
// (no module resolution — that would need the VMA tracking locks).
void OnThreadCreate(CloneKind Kind, uint64_t GuestTID, uint64_t HostTID, uint64_t ParentTID, uint64_t GuestRIP, uint64_t CloneFlags);

// prctl(PR_SET_NAME) — always names the calling thread. Only called after the
// host prctl succeeded, so Name is known-readable.
void OnSetName(const char* Name);

// One guest sched_set{scheduler,attr,param} request. Policy < 0 means "the
// request carried no policy" (sched_setparam). Priority < 0 means "not
// recoverable from the guest's struct". GuestResult is the kernel-style
// return value the guest is about to receive (0/-errno).
void OnSchedSet(const char* Event, int64_t TargetTID, int Policy, int Priority, int64_t GuestResult);

// One guest sched_setaffinity request. Mask/MaskBytes may be null/0 when the
// guest buffer wasn't safely readable; then only the result is logged.
void OnSetAffinity(int64_t TargetTID, const uint8_t* Mask, size_t MaskBytes, int64_t GuestResult);

// One rung of the Feature-2 degradation ladder. Value is a priority for the
// "rr" step and a nice level for the "nice" steps.
void OnSchedBoost(int64_t TargetTID, const char* Step, int Policy, int Value, int64_t HostResult, int64_t GuestResult);

} // namespace FEX::HLE::ThreadCensus

namespace FEX::HLE::SchedPassthrough {

// Feature 2 entry point. Called from the sched_setscheduler/sched_setattr
// wrappers *after* the pre-existing passthrough has run, with the result the
// guest is going to receive. Does nothing unless FEX_SCHEDPASSTHROUGH is set
// AND the host refused an RT policy with EPERM. Never returns anything: the
// caller's return value is untouched by construction.
void OnSchedRequestRefused(int64_t TargetTID, int Policy, int Priority, int64_t GuestResult);

} // namespace FEX::HLE::SchedPassthrough
