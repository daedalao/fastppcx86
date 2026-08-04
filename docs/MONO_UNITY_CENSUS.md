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
- **B — lost wakeup on guest sync object** (Hard West load spin): worker
  army atomically hammering one heap word; flag field never set; registers
  stationary; zero signals to spinners; futex-wait crowd. Clamp
  inapplicable. Next tool: FEX_FUTEX_TRACE. Root fix: OPEN.

## Special numbers — collected per title, analyzed for a pattern

The working theory (user): each wedge reduces to a specific site waiting
for a specific value — find every title's numbers, then look for the
pattern across engine versions instead of generalizing structurally.

| title | engine version | site (guest RIP) | wants | object/field | notes |
|---|---|---|---|---|---|
| ziggurat | Unity 4.x-era (2014, static player) | cmp @ 0x934d27 (loop 0x934d04-0x934d33, block 0x934a40) | RBX == 4 (R15) | loop bound in register, element count | value arrives via r15←r12; corruption class A |
| hardwest | Unity 5.x-era | cmpxchg spin @ 0x84adb2 / head 0x84ad50 | [obj+0x70] == 1 | sync object @ heap 0x1f3a220: flag +0x70, waiters +0x74, +0x78==1 | flag never written — class B; compare upstream's displacement set below |
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
| ziggurat | Unity (static player) / Mono | 2026-08-04 | **Class A** — wedges on load with workarounds off; playable with clamps on | docs/ZIGGURAT_FINALIZE_SPIN.md; entry ring clean; RBX restarts ~0, misses ==4 once |
| hardwest | Unity / Mono | 2026-08-04 | **Class B** — 40 spinners on word @0x1f3a220, flag +0x70 never →1, ~2m15s into load | hardwest-jit-spin-loop memory 2026-08-04 section; ranges 0x84ab90-0x84adee |
| rimworld | Unity / Mono | 2026-08-04 | healthy so far (ran with clamps ON, default config; ~long session pending) | SpinLoopClampAuto audit: 1017 flagged lib loops, zero misfires observed |
| shadowrunhk | Unity / Mono | 2026-08-04 | **wedged, class TBD** — title-menu wedge, ~68 cores hot across 182 threads for 25+ min, Player.log frozen at 10:12:05; `Failed to wait on a semaphore (Interrupted system call)` in Player.log despite SA_RESTART fixes present in build — EINTR-leak suspicion or third class; spin PCs unresolvable post-mortem (perf-3636.map gone) | /tmp/srhk1.perf + /tmp/srhk_poll.out on op4k (2026-08-04 10:15-10:37); needs instrumented re-run (BlockJITNaming + SIGTRACE) |
| moonlighter | Unity 2018 / Mono | — | pending | prior perf data exists (moonlighter_perf.data in repo root) |
| amongthesleep | Unity / Mono | — | pending | |
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
