# Mono/Unity wedge census — one sweep, every title

Goal (user, 2026-08-04): unlock ALL Mono/Unity titles in one swoop. Method:
run each title with workarounds OFF and full instrumentation, classify every
wedge into a disease class, fix per class not per title. Diagnosis flags:

```
FEX_SPINLOOPCLAMP=disable FEX_SPINLOOPCLAMPAUTO=0 FEX_SIGTRACE=1 fexplay-smc <name>
```

Reference build: `build-smc` @ 77f86aed4. Playbook: an Opus agent per run —
verify env, poll for wedge (distinct-PC spread, not CPU%, decides
spin-vs-work), jitrip/ripwalk the hot block, register series, loop anatomy,
SIGTRACE correlation (NB Unity swallows fd1/2 into its own Player.log),
class verdict. Tripwires available: FEX_DECODEDUMP / FEX_SIGRIPWATCH /
FEX_ENTRYWATCH (ranges per title), FEX_FUTEX_TRACE (two-stage arming),
FEX_TRACE_CLONE.

## Disease classes

Policy (2026-08-04, user call): workarounds are SURGICAL, not structural.
`SpinLoopClampAuto` now defaults **off** (opt-in per launcher entry;
ziggurat arms it). Per-title `FEX_SPINLOOPCLAMP` ranges are the preferred
containment — "the special number the game wants a response to" — mirroring
upstream's own per-displacement Unity hack pattern rather than blanket
detection.

- **A — register injection under signal resume** (Ziggurat finalize spin):
  one thread; equality-exit induction loop in game text; compilation
  correct; induction restarts near 0 then misses the == exit once, in
  place; Mono GC signals active on the thread; dispatcher-entry ring clean;
  prime suspect INJIT RestoreThreadState resume. Workaround: SpinLoopClamp
  (manual exact + auto structural). Root fix: OPEN.
- **B — lost wakeup on guest sync object**: RETIRED 2026-08-04 — the sole
  exemplar (Hard West load spin) was re-diagnosed as class D below. The
  "flag never set" was a park gate that legitimately required zero
  concurrent workers; nothing was lost. No known title currently
  exhibits a true lost wakeup. Keep the definition in case one appears.
- **C — JIT flags clobber (CR0/NZCV)** (Hard West quiet startup wedge):
  non-flag-writing vector op (CMPSS/SD, ROUNDSS/SD, wide shifts) between a
  cmp/test and its jcc destroyed packed NZCV in CR0 → branch on garbage →
  loop entered past its init / equality exit overshot. One or few threads,
  low CPU, no syscalls, no signals; register state looks "impossible".
  Root fix: **LANDED eb1a4c858** (all VectorOps CR0-scratch → cr1) +
  regression test vector_scalar_flags_preserve.asm. Presents like A
  (skipped init) — every A-classified wedge must be retested on ≥eb1a4c858
  before the A verdict stands.
- **D — CPU-count-inflated spin-quiesce starvation** (Hard West load
  "wedge", root-caused 2026-08-04): emulated /proc/cpuinfo ignored the
  affinity cage (80 reported vs 16 usable), Unity sized its job pool from
  SystemInfo.processorCount → 79 workers on 16 hw threads; the park gate
  (lock cmpxchg [obj+0x74],0 — "no worker inside the steal window") is
  statistically unreachable at that oversubscription (measured occupancy
  20-51, never 0, in 13k samples/12s), so the pool never parks and starves
  the game to ~2 fps. NOT corruption — every guest value sane; the wrong
  number was the manufactured CPU count (79). Amplified by PPC64LE atomic
  window cost (2 barriers + LL/SC per lock add/sub vs one x86 uop).
  Root fix: **LANDED 9a0f8e1be** (CalculateNumberOfCPUs bounded by
  sched_getaffinity). Workaround: FEX_REPORTED_CPUS=N (verified live).
  Fingerprint: guest nproc != guest `grep -c ^processor /proc/cpuinfo`
  under taskset = pre-fix build; pool-size fields in the sync object frozen
  at (reported_cpus - 1).

## Special numbers — collected per title, analyzed for a pattern

The working theory (user): each wedge reduces to a specific site waiting
for a specific value — find every title's numbers, then look for the
pattern across engine versions instead of generalizing structurally.

| title | engine version | site (guest RIP) | wants | object/field | notes |
|---|---|---|---|---|---|
| ziggurat | Unity 4.x-era (2014, static player) | cmp @ 0x934d27 (loop 0x934d04-0x934d33, block 0x934a40) | RBX == 4 (R15) | loop bound in register, element count | value arrives via r15←r12; corruption class A |
| hardwest | Unity 5.x-era | cmpxchg park gate @ 0x84adb2 / loop 0x84ad40 | [obj+0x74] == 0 (park only when NO worker in steal window) | job-queue object (this run 0x1f33070): +0x70 shutdown flag, +0x74 live steal-window count, +0x28/+0x38/+0x40 pool size | the true special number was **79** = inflated cpuinfo count − 1; RESOLVED as class D (9a0f8e1be); earlier "flag +0x70 wants ==1" reading was the shutdown check misread as the gate |
| (upstream reference) | Unity 2015+ | n/a (decode-time hack) | force-TSO loads/stores | SPSC ringbuffer: cached ptrs/wait flags @ +0x80/+0x84/+0xC0/+0xC4 | Frontend.cpp IsKnownAtomicDisplacement — the prototype "special numbers" fix |
| shadowrunhk | Unity 4.x/5.x | (unresolved — JIT map died with the process; instrumented re-run needed) | | | wedged AT TITLE MENU (music line last in Player.log); ~68 cores / 182 threads; hot PCs 0x3fff96068xxx-0x3fff9606bxxx in perf-3636 capture |

Pattern candidates to test as rows accumulate: (1) the displacement set
drifts by Unity major version (0x70/74/78 ↔ 0x80/84/C0/C4?) — if Hard
West's offsets are the pre-2015 layout of the SAME object, widening
IsKnownAtomicDisplacement per-version is the upstream-shaped fix for
class B; (2) class A's "wants" are small loop bounds fed through a
register shuffle — the special number is the bound register's value at
entry, and the corruption window is the shuffle between xor and jmp.

## Census

| title | engine | run date | verdict | evidence |
|---|---|---|---|---|
| ziggurat | Unity (static player) / Mono | 2026-08-04 | **RECLASSIFIED A → C, confirmed by retest**: clamps fully off (manual + AUTO) on eb1a4c858, survived multiple dungeon loads — the finalize spin did not fire. Register-injection theory RETIRED; "class A" was the CR0/NZCV clobber. Perf slightly worse clamp-free: AUTO was short-circuiting ~1017 library spin loops — keep as opt-in PERF knob, no longer correctness-load-bearing | user live retest 2026-08-04 13:1x; docs/ZIGGURAT_FINALIZE_SPIN.md now historical |
| hardwest | Unity / Mono | 2026-08-04 | **BOTH DISEASES ROOT-CAUSED.** (1) quiet startup wedge = **Class C** (CR0/NZCV clobber, FIXED eb1a4c858); (2) loud load spin = **Class D** (79-worker pool vs 16-thread cage, park gate unreachable; FIXED 9a0f8e1be / FEX_REPORTED_CPUS). Displacement A/B answered: force-ordering 0x70/74/78 does NOT touch it (and adds drag — drop it) | Opus captures: /tmp/hwquiet/ + /tmp/hwcounter/ on op4k (long.py 13k-sample field census; spin.asm loop reconstruction); playability confirmation run in flight |
| rimworld | Unity 2019 / Mono | 2026-08-04 | **breakthrough on eb1a4c858+9a0f8e1be (caged SMT2)**: first time EVER through menu → worldgen → mapgen → colony UI, audio live; the historical load→UI crash (NULL+0x210, fired at the seam after the ~35min crawl) did NOT reproduce at its exact trigger. NEW EDGE CASE: "Quit to OS" hangs IDLE (cpu 0%, 43 threads parked, log clean) — shutdown join/wake never completes; unfingerprinted | watch data /tmp/rw_watch.out 12:2x-12:48; quit-hang is the inverse presentation of class D (park instead of spin) |
| shadowrunhk | Unity / Mono | 2026-08-04 | **TRANSFORMED by fixes, core wedge remains as class-E candidate**: morning run = 182 threads / 68 cores burning at title theme (that was class D dressing); fixed+caged run = 53 threads, 46 in futex_wait, ~0% CPU, SAME Player.log position (title music line) — an IDLE hang. 2x `Failed to wait on a semaphore (Interrupted system call)` in the log: EINTR leaks out of sem_wait despite SA_RESTART fixes; suspicion: EINTR-aborted wait breaks a handshake whose counterpart then never signals. Likely same family as the quit-to-OS idle hangs (rimworld, dex). Best repro for the idle-hang/EINTR class — wedges at title, no gameplay needed | fingerprints 12:5x: fault pages 0, SigPnd 0, wchan census 46x futex_wait; /tmp/srhk_watch2.out |
| moonlighter | Unity 2018 / Mono | 2026-08-04 | **runs (caged, fixed build)**; perf entity-count-bound — crowds cratered FPS. Recipe A/B: lazy > strict ≈ off; profile flat (raw guest math) EXCEPT ExitFunctionLink 7.3% top symbol under lazy → motivated FEX_SMCLAZYLINK (2691ec715). With lazylink: 0.10%, and user-confirmed feel improvement scaling with on-screen entity count (destroying containers = fewer block transitions/frame). First PERF win recorded by the census. AVX-off NOT a win here (user A/B) | /tmp/moon_slow.perf, /tmp/moon_off.perf, /tmp/moon_ll.perf on op4k |
| amongthesleep | Unity / Mono | 2026-08-04 | **runs on fixed build (caged)** — no wedge. Quality bugs: green artifacts in title video (video decode or GL-thunk path), audio stutter (known audio class), and erratic player MODEL behavior, user-identified as IK-flavored (limbs moving oddly, no crash) — IK solvers iterate scalar compares + sqrts + normalizes, prime candidate for a further scalar-SSE semantics bug (NaN/DAZ/rounding/compare edge), same neighborhood as today's CR0 fix but a silent failure mode | user live run 2026-08-04 13:2x |
| dex | Unity 5 / Mono, i386 | — | pending; NB 32-bit guest — SpinLoopClampAuto <4GB scope covers everything, review before enabling | taskset SMT2 tuning notes exist |
| stardew | .NET CoreCLR (not Mono) | — | out of scope for Mono gate (AUTO=1 won't arm); include as control later | startup wedge previously solved (AppConfig SMCChecks) |

Non-Mono titles (grimrock, ftl, zomboid, psychonauts, witcher2, stk) are
controls only; not part of the sweep.

## Rules of the sweep

1. One title at a time on op4k (captures need clean conditions; check for
   live FEX processes before perf — op4k-check-before-benchmarking).
2. Wedge → leave it running, capture first, kill after.
3. Every verdict lands in this table same-day, with the evidence pointer.
4. A fix for a class reruns every title previously assigned to that class,
   workarounds off.
