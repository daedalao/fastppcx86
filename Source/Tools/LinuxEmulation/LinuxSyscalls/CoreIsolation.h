// SPDX-License-Identifier: MIT
#pragma once
//
// CoreIsolation — give the critical guest thread a whole physical core.
//
// The emulation-tax decomposition showed the hot guest thread runs near the
// core's IPC ceiling: wall clock is emitted-instruction count times how much
// of a core the thread owns. On POWER8 a core whose SMT siblings are idle
// runs the remaining thread in effective-ST mode with the full issue width,
// so vacating the sibling of the render/main thread's core is direct
// single-thread performance. See docs/CORE_ISOLATION_PLAN.md.
//
// Off by default (FEX_COREISOLATE=0). When enabled, a host-side manager
// thread samples every guest thread's /proc/self/task/<tid>/schedstat at 2Hz,
// picks the sustained-top thread (vetted by voluntary-context-switch rate so
// futex-cycling spinners can't win), and after a stability window pins it to
// a reserved core while evicting every other thread in the process — host
// helpers included — to the remaining CPUs. Guest-issued sched_setaffinity
// always wins: tids the guest ever pinned are recorded and never moved.
//
// Everything here is advisory host-side scheduling. Guest-visible semantics
// (affinity masks it reads back, getcpu, /proc contents) are untouched: the
// guest reads affinity through the dense-remap wrappers, and a guest that
// never calls sched_setaffinity was already entitled to be run anywhere.

#include <cstdint>
#include <sched.h>

namespace FEX::HLE {
class SyscallHandler;
}

namespace FEX::HLE::CoreIsolation {

// Reads FEX_COREISOLATE and, when nonzero, launches the manager thread.
// Call once from the loader after the SyscallHandler and ThreadManager
// exist and before guest execution starts. Safe to call when disabled
// (single config load, no thread).
void Start(FEX::HLE::SyscallHandler* Handler);

// The guest issued a successful sched_setaffinity for TargetTID (already a
// host tid in FEX's 1:1 model; 0 was resolved to the caller by the wrapper).
// That tid becomes guest-owned: the manager never repins it and never
// shrinks its mask. Cheap no-op when the feature is off.
void OnGuestSetAffinity(uint32_t TargetTID);

// Preserve the affinity illusion for sched_getaffinity: a thread the guest
// never pinned must keep seeing the process's original allowed mask even
// while the manager has narrowed its host mask (games size thread pools
// from this). Returns true and writes that mask into HostSet when the
// override applies (feature active, tid not guest-owned); false leaves the
// caller's kernel-reported mask untouched.
bool ReportedAffinityOverride(uint32_t TargetTID, cpu_set_t* HostSet);

} // namespace FEX::HLE::CoreIsolation
