# Core isolation + profile-guided super-tier — plan

Date: 2026-08-31. Status: Stage 1 implementing.

## Motivation

The emulation-tax decomposition showed the critical guest thread runs at ~97.7%
of native IPC with better-than-native cache behaviour: wall clock is emitted
instruction count, times how much of a physical core the thread actually owns.
Two independent levers follow:

1. **Core isolation** (this doc, Stage 1): guarantee the critical thread a whole
   POWER8 core — SMT sibling vacated, so the core runs in effective-ST mode with
   full issue width. Games are render/main-thread bound ("many objects on
   screen" scaling), so one to two threads dominate.
2. **Profile-guided super-tier** (Stage 3): recompile the hottest blocks with
   expensive optimization (trace formation across block boundaries, cross-block
   flag elimination, trace-wide RA). Needs the same per-thread/per-block
   sampling Stage 1 introduces.

## Stage 1 — critical-thread identification + isolation (CoreIsolation)

New: `Source/Tools/LinuxEmulation/LinuxSyscalls/CoreIsolation.{h,cpp}`,
config `CoreIsolate` (uint32, default 0 = off; N = isolate up to N threads,
capped so at least half the allowed cores stay general-purpose).

### Identification signals

- **Utilization ranking**: a manager thread samples every guest thread's
  `/proc/self/task/<tid>/schedstat` runtime at 2 Hz. Candidate = top-ranked
  thread with sustained share ≥ 55% of a core over the window.
- **Spin discount**: candidates are vetted by voluntary context-switch rate
  (`/proc/self/task/<tid>/status`). A futex-cycling spinner shows tens of
  thousands of voluntary switches/s; a busy render/game thread shows few.
  Above threshold → demoted, next candidate vetted. (Future refinement: a
  per-thread counter bumped from the SpinCollapse budget-expiry slow path
  catches pure userspace pause-spinners the switch rate can't see.)
- **Presenter ground truth**: the 64-bit VK thunk's `vkQueuePresentKHR` now
  notifies FEX (`FEX_NotifyGuestPresent`, resolved via `dlsym` from the host
  thunk lib). Under DXVK the presenter is DXVK's queue thread — not the main
  bottleneck thread, so it is *not* auto-promoted; it provides phase detection
  (presents flowing = gameplay; quiet = loading screen, freeze candidate
  churn) and decision-log context. Under native wine, a later fexbridge hook
  can mark the dxgi Present caller, which *is* the game's render thread there.
- **Hysteresis**: engage only after the same candidate tops 4 consecutive
  windows; disengage after its share stays < 35% for 8 windows. No decisions
  while the presenter is quiet (loading) once a presenter has ever been seen.

### Placement

- Topology from `/sys/.../topology/thread_siblings_list`, restricted to the
  process's initial affinity mask (respects the op4k cage cpuset). Only cores
  with **all** siblings in the allowed mask are reservable.
- Engage = pin candidate to the reserved core's primary CPU, then evict every
  *other* thread in `/proc/self/task` (host helpers included — mangohud, audio,
  the manager itself) to `allowed − reserved`. New threads get evicted on the
  next tick.
- **Guest affinity always wins**: any tid the guest ever `sched_setaffinity`'d
  (recorded via a hook in the existing wrapper, which already does the dense
  guest↔host CPU remap) is never moved. If the candidate itself is
  guest-pinned to a single CPU, reserve *that* core instead (vacate siblings
  only); if guest-pinned wide, log and skip. Guest-pinned threads overlapping
  a reservation are logged, not fought.
- Disengage/exit restores the full allowed mask to every evicted tid.

### Observability

Every decision (candidate, scores, engage/evict/skip/disengage, conflicts)
appends an `event=isolate` line to the ThreadCensus file when
`FEX_THREADCENSUS` is set, and always goes to LogMan at INFO. Success metric
for validation runs: "during present-active windows, the candidate is the sole
occupant of its physical core" — verifiable from the census lines plus
`/proc/<pid>/task/*/stat` CPU fields.

### Validation plan

- ctest suite stays green (feature default-off; syscall wrappers unchanged in
  behaviour).
- op4k: W3 + CP2077 in-world A/B, `FEX_COREISOLATE=1` vs unset, scene-isolated
  stats, both TSO configs. Decision log reviewed for false engagements across
  the title library (target: no misidentification during gameplay windows;
  loading-screen churn suppressed by the presenter gate).
- COMPARABILITY: flipping this on changes thread placement — date the config
  book entry like the getcpu remap did.

## Stage 2 — shared sampler hardening (prereq for super-tier)

- Per-thread JIT block sample counter (signal-based or budget-slow-path hook)
  feeding both a spin discount that sees pure userspace spinners and a
  hot-block histogram per thread.
- Persist per-title hot-block sets next to the NCS code cache.

## Stage 3 — profile-guided super-tier (design sketch, not started)

- Input: hot-block histogram from Stage 2 (top ~50 blocks ≈ dominant cycles;
  cf. CP2077's 24% in 3 PCs).
- Recompile hot regions as superblocks/traces: inline the dominant successor
  chain, eliminate flag materialization across the trace, RA over the whole
  trace, loop-top alignment (the known ~6-7% fetch-group item).
- Tier output stored in the NCS cache keyed by (title, block set, JIT config
  hash) — same invalidation discipline as CodeCache today.
- Kill switch + hashed into cache id per the new-codegen-toggle rule.
