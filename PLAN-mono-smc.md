# Actionable plan: Mono/Unity self-modifying code on fex-ppc64le

Written 2026-07-20 from a code audit of this branch (HEAD `0f17626ac`). No hardware was
available; everything below is from source + git history, with file:line receipts.

## TL;DR — the root cause is almost certainly a half-ported MonoHacks subsystem

Upstream FEX's answer to Mono/Unity SMC is **not** the generic mprotect/fault path — it is a
special *hook-based* scheme (config `MonoHacks`, default **on**):

1. Detect the mono runtime → `AreMonoHacksActive()` (`Context.h:360`).
2. On the first SMC fault caused by an **XCHG (0x87)** inside libmono's code, mark that guest
   block as "the mono backpatcher block" (`MarkMonoBackpatcherBlock`).
3. Recompile that one block so its XCHGs go through the `MonoBackpatcherWrite` IR op — an
   explicit write-then-invalidate helper (`Core.cpp:560`, `OpcodeDispatcher.cpp:1167`).
4. Then **disable mprotect-based SMC detection for RWX regions entirely**
   (`Source/Windows/Common/InvalidationTracker.cpp:192-240`, `DisableSMCDetection`).
   Tailcall patch sites are covered separately by per-block byte validation
   (`Frontend.cpp:1206 IsBranchMonoTailcall` → `ForceFullSMCDetection`, `Core.cpp:646`).

**Steps 2–4 exist only on Windows.** `MarkMonoBackpatcherBlock` has exactly one caller in the
tree: `Source/Windows/Common/InvalidationTracker.cpp:216`. On Linux, step 1 was wired locally
(`a37a65f17`, openat-based detection), the PPC64LE lowering of `MonoBackpatcherWrite` exists
(`JIT/PPC64LE/ALUOps.cpp:3149`), the frontend hacks (Unity ringbuffer FORCE_TSO, multiblock
truncation at calls, tailcall full-SMC) all activate — but the *core* of the scheme, the
backpatcher hook + fault-storm bypass, can never trigger. So every mono code patch on Linux
takes the worst path: mprotect fault → full-page invalidation → single-inst recompile
(`SyscallsSMCTracking.cpp:36-125`) → re-protect → next patch faults again. Under Mono's
patch-heavy startup (trampolines, inline caches, method JIT) this is a fault/invalidation
storm and interacts with every other marginal subsystem (futex visibility, LL/SC atomics,
lock contention) — consistent with the Ziggurat/Stardew "EAGAIN spin after cold JIT" symptom.

All the plumbing the port needs already exists and is arch-independent:
`RestoreRIPFromHostPC` / `GetGuestBlockEntry` (`Core.cpp:141,146`),
`QueryGuestExecutableRange` on Linux (`SyscallsSMCTracking.cpp:210`), and the PPC64LE
single-inst recovery path was fixed in `4373b676e`.

---

## Workstream 1 — Port the mono backpatcher hook to Linux (primary fix)

**1a. Record the mono library's guest mapping range.**
Windows keeps `MonoBase`/`MonoEnd` from PE module load. Linux equivalent: in `TrackMmap`
(`SyscallsSMCTracking.cpp:524-656`) we already have the mapped file's name for executable
file-backed mappings (ELF parse path). When the basename matches the existing mono prefix
list (factor it out of `MaybeDetectMonoFromPath`, `Syscalls.cpp:1293+`) and the mapping is
executable, record `[MonoBase, MonoEnd)` on the SyscallHandler (grow the range across the
lib's multiple PT_LOAD mappings). Also call `MarkMonoDetected()` here — it's a stronger
signal than openat (see 2b).

**1b. Detect the backpatcher block in `HandleSegfault`.**
In `SyscallsSMCTracking.cpp` after the invalidation call (~line 107), mirror
`InvalidationTracker::DetectMonoBackpatcherBlock` (`InvalidationTracker.cpp:192-220`):
if MonoHacks active && detection still pending && fault PC is in the JIT code buffer &&
`RestoreRIPFromHostPC(...)` lands inside `[MonoBase, MonoEnd)` && the byte at RIP or RIP+1 is
`0x87` (XCHG): take the code-invalidation lock, `MarkMonoBackpatcherBlock(GetGuestBlockEntry
(Thread))`, invalidate that block's page so it recompiles with the hook (Core.cpp:560 keys on
block entry RIP), and proceed to 1c. Keep the one-shot `MonoBackpatcherDetectionPending`
semantics.

**1c. Linux `DisableSMCDetection` equivalent.**
Windows reprotects all RWX intervals back to RWX and stops tracking them. Linux version:
add a flag on SyscallHandler; when set, `MarkGuestExecutableRange`
(`SyscallsSMCTracking.cpp:127-187`) skips write-protecting VMAs that are *both* writable and
executable (mono JIT arenas), and a one-time sweep re-`mprotect(RW|X)`s such VMAs that are
currently protected. Keep mtrack behavior for everything else (W^X libraries, the loader,
etc.) — that's a deliberately narrower scope than Windows and safer.
Correctness cover after the switch: backpatcher XCHGs → `MonoBackpatcherWrite`; tailcall
sites → `ForceFullSMCDetection` per-instruction byte validation; brand-new method bodies →
pages not yet executed aren't in the lookup cache, so first execution compiles fresh code.
That's the same invariant set Windows relies on.

**1d. Sanity-check the PPC64LE `MonoBackpatcherWrite` lowering under fire.**
`ALUOps.cpp:3108-3200` was written blind (nothing on Linux could ever reach it). Review the
mini-frame ABI + verify `ContextImpl::MonoBackpatcherWrite` invalidates translations before
returning (host icache is irrelevant — guest bytes are data to the host; what matters is
LookupCache invalidation ordering vs. the racing reader thread).

Acceptance: Ziggurat/Stardew startup no longer shows SMC fault storms
(`FEXCORE_PROFILE AccumulatedSMCCount`, or add a counter log); "Detected mono backpatcher
at" appears once in logs.

## Workstream 2 — Make sure detection actually fires per game

- **2a.** Add `libmonobdwgc-2.0.so` to the prefix list (modern Unity 2017+ name; current list
  covers sgen/boehm/`libmono.so`/`mono-2.0-bdwgc` but not this one). Ziggurat (Unity 4) ships
  `libmono.so` — covered.
- **2b. Stardew Valley problem:** MonoKickstart **statically links** mono into the game
  binary — no `libmono*.so` is ever opened, so openat detection and 1a's range capture both
  miss. Mitigations, in order: (i) detect via mono's data-file opens (`mscorlib.dll`,
  `machine.config`, `mono/4.5/` path fragments) to at least flip `MonoDetected`; (ii) for the
  backpatcher range, fall back to "main executable's range" when detection came via (i);
  (iii) add an explicit `FEX_FORCE_MONO_RANGE=base:end` / `FEX_FORCE_MONO_DETECT=1` override
  for experiments.
- **2c.** Log at INFO when `MarkMonoDetected` fires and when hacks activate — today it's
  silent, so you can't tell dormant-hacks from broken-hacks.

## Workstream 3 — Ground truth on hardware (first session when a machine is up)

1. **Run the SMC unit tests on POWER8** (never verified on this backend per git history):
   `unittests/FEXLinuxTests/tests/smc/` — priority order: `smc-mt-2` (cross-thread patch =
   exactly mono's trampoline race), `smc-shared-1/2` (aliased W/X mappings), `smc-mt-1`,
   `smc-1-dynamic`, `smc-2`. Any failure here is a prerequisite bug — fix before touching
   games.
2. **Add one new test**: cross-thread XCHG backpatch + futex handshake (thread A futex-waits
   on a word that thread B sets *after* patching code A will run) — models the exact
   mono-GC/trampoline shape, and exercises the `33e674d3d` signal-replay class too.
3. Run each smc test under both `FEX_SMCCHECKS=mtrack` and `full`.

## Workstream 4 — A/B the EAGAIN spins (cheap, decisive)

- **`FEX_SMCCHECKS=full` on Ziggurat/Stardew.** Slow but bypasses all mprotect machinery.
  Spin gone → mtrack invalidation is missing writes (focus WS1/WS3). Spin persists → it's
  not stale code; it's memory-ordering/atomics (LL/SC flags, TSO visibility) — pivot to the
  `694f81668` "atomic-visibility downstream" thread.
- Existing diagnostics, all opt-in and already landed: `FEX_SYSCALLOBSERVE=1
  FEX_FUTEXMITIGATE=1` (EAGAIN-storm detect + yield), `FEX_LOG_UNEXPECTED_FUTEX=1`, and the
  compile-time byte ring log (`cf17977e8`) to prove/disprove stale-compile on any frozen RIP.
- Note: futex is pure passthrough (`Passthrough.cpp:355-383`); a FUTEX_WAIT→EAGAIN spin means
  the futex word in memory keeps failing the kernel's value check — i.e. a store some other
  thread made (or should have made) isn't the expected value. That's either a lost/invisible
  store (ordering bug) or the waker never progressing (stale code / lock livelock).

## Workstream 5 — Page-size guardrails (don't chase ghosts on the 64K boot)

The entire SMC path hardcodes 4K straight into host `mprotect()` calls
(`SyscallsSMCTracking.cpp:76,97,99,104,174,180`; guest sees AT_PAGESZ=4096 from
`ELFCodeLoader.h:636`; zero host-page-size awareness anywhere in LinuxEmulation). On the 64K
boot (`op64k`/.155) a 4K-aligned-not-64K-aligned mprotect returns EINVAL → `AFmt` abort, and
even "working" cases degrade to 64K-granularity protection with re-protect races.
**Action now:** do all mono/SMC work on the 4K boot (.154), and add a startup check: if
`sysconf(_SC_PAGESIZE) != 4096` and SMCChecks==mtrack, log a loud warning (or refuse).
A real 64K shim (host-page shadow protection bookkeeping) is a separate, later project.

## Workstream 6 — Watch-list (not first-line, verify while in the area)

- **Single-inst recovery RIP precision:** `HandleSegfault` SpillSRAs and re-enters at
  `AbsoluteLoopTopAddressFillSRA` consuming `State.rip` — confirm what RIP a mid-block fault
  leaves there on PPC64LE (block entry vs. faulting instruction) and whether block-head
  replay of non-idempotent prefixes is possible. `smc-mt-2` + the new WS3 test should expose
  it if broken.
- **`ReleaseAllPendingSharedLocks` vs. concurrent guest-SIGSEGV** (Mono uses SIGSEGV for
  null checks): no test stresses guest sync-SEGV concurrent with an SMC fault on another
  thread. If Ziggurat crashes (rather than spins) after WS1, look here.
- **Perf, later:** PPC64LE `ExitFunctionLink` (`JIT/PPC64LE/JIT.cpp:1791-1865`) never
  registers block links — no direct-branch patching at all. Costs throughput, not
  correctness; irrelevant to the SMC bug but worth a line in the perf backlog.

## Suggested order

1. WS4 A/B runs + WS3 test suite (first hardware session, ~an hour, decides everything).
2. WS2a/2c logging (trivial, do alongside).
3. WS1 port (the real work, ~1-2 days; land behind `FEX_MONOHACKS` which is already default-on).
4. WS2b Stardew/MonoKickstart fallback once Ziggurat (the clean libmono.so case) works.
5. WS5 guardrail commit any time (10 lines).
