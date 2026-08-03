# Task queue — prioritised

Living document. Direction lives in `POWER9_PORT_PLAN.md`; current conversation lives in
`build-agent-notes.md`; the durable record is commit history. **This is the ordered work list.**

Last updated 2026-08-01, after the code-cache design cycle.

Each item: what, why it is where it is, size, gate, and what blocks it.

---

# ⭐ STANDING RULE — this is the `power9` branch

**Optimise for POWER9. Gate divergences as a courtesy. Never let POWER8 shape the design.**

`origin/smc-store-emulation`'s "all codegen must stay POWER8-legal" is **op4k's** rule for **op4k's**
branch. It has leaked into our reasoning more than once — read their docs for findings, not constraints.

- `HostFeatures.SupportsISA30` is a **real runtime check** (`HostFeatures.cpp:722`, `AT_HWCAP2 &
  PPC_FEATURE2_ARCH_3_00_`), consumed at emit time (`PPC64Emitter.cpp:440,450,534`).
- `ENABLE_DISABLE_OPTION(SupportsISA30, …)` at `HostFeatures.cpp:490` **forces ISA 3.0 off at runtime**, so
  the POWER8 fallback leg is testable here. Gate for any ISA-gated optimisation: run the set once with it
  disabled.
- **POWER9 has no CRC32C instruction** (`JIT/PPC64LE/ALUOps.cpp:3818`; guest SSE4.2 `CRC32` goes through a
  C helper). Any hash/checksum design ported from an ARM64 rationale is invalid here on that point alone.

---

# ⭐ NIMBUS — our SMC redesign. Design pass complete 2026-08-03. **Implementation gated on `U_page`.**

## The name

**Nimbus**, not "v3" — that is op4k's numbering and staying in it invites the assumption we are producing
their next version. Nimbus is POWER9's own silicon codename (scale-out; Cumulus is scale-up) and a nimbus
is a storm cloud. Named for the chip it targets and the fault storm it disperses. Use it in identifiers:
`NimbusHash`, `FEX_NIMBUS=1`.

## Mechanism, after a five-agent design pass and an alternatives bake-off

Hash the guest bytes each compile unit was built from; on re-entry, re-protect, re-hash, and relink
unchanged units instead of recompiling. **Chosen over store emulation, shadow-copy diffing, coarse-then-fine
and backpatch special-casing.** op4k independently converged on the same mechanism after measuring their own
store-emulation v1 as a regression (a contention benchmark to *timeout*, another 27× slower).

**Store emulation is refuted at the ISA level, not on effort.** FEX compiles the guest's aligned
`LOCK CMPXCHG` — 50–60 % of stores — into an inline `lwarx`/`stwcx.` loop, so the faulting instruction is a
*store-conditional*. Emulate it as success and you silently discard the reservation, losing another thread's
write; emulate it as failure and the guest's CAS loop retries, faults, and livelocks unless you unprotect —
which is legacy. There is no third option.

## The five corrections that reshaped the design

1. **The check cannot run at fault time.** All four design agents derived this independently. The write
   fault fires *before* the store retires, so guest bytes at fault time are unchanged by construction and a
   hash there is vacuous. Worse, re-protecting and resuming puts the same store back on a read-only page —
   a **livelock**, not a slowdown. Nimbus quarantines at fault and verifies at **re-entry**, before compile,
   where blocking is legal.
2. **Nimbus does not reduce the fault count** — it reduces cost per fault (~22 µs recompile → link walk plus
   a small hash). Any acceptance criterion written as "SMC fault count drops" will read as a failure.
3. **Retention starves the re-protect trigger.** Found independently by three agents. Re-protection fires
   only when a page has no registered blocks (`LookupCache.h:167` → `Core.cpp:1005`), and `CodePages` is
   emptied only by `InvalidateRange` (`:154`). Keep blocks and the page is **never re-protected — SMC
   tracking for it dies silently and permanently.** Nimbus must own its re-arm explicitly.
4. **Quarantine by moving rows out of `BlockList`, not by flagging them.** Two agents converged. Every
   present *and future* lookup then misses by construction; no call site needs auditing.
5. **Units are not page-sized and they overlap.** `MaxInst` is 5000 and `Multiblock` is on; a unit spans
   pages, and two units can cover the same bytes. Verifying one may require hashing pages that never
   faulted. Erase granularity is the whole `CompiledCode` — a clean sibling must never resurrect a stale one.

## Constraints for implementation

- Baseline hash from `DecodedInst::InstBytes` (landed, `e742fd761`); **verify-time comparand from live guest
  memory.** These are never the same code path — the "never re-read guest memory" rule applies to the
  baseline only.
- **Protect → hash → publish**, in that order, and the dirty-mark must precede the unprotect.
- `XXH3` from the vendored `External/xxhash`. Do not hand-roll: hashing 4 KB is ~1.6 % of one recompile, so
  no size exists at which a faster hash changes a decision. Per-process random seed closes the adversarial
  case — consequence: **Nimbus hashes can never be persisted into the code cache.**
- Ineligible: units whose decode hit invalid/partial/noexec instructions (their bytes are unrecorded, and
  guests patch invalid instructions in place — we would relink a permanent #UD).
- A **compile-epoch counter**: "same bytes ⇒ same code" is false today. Forced-TSO ranges, the Mono hook
  flag, the SMC mode and 32/64-bit mode all feed compilation without being guest bytes.
- Only `MAP_PRIVATE` (and in-process `MAP_SHARED|MAP_ANONYMOUS`) mappings are eligible. Shared file-backed
  mappings keep legacy behaviour — closes cross-process writes, kernel writeback, hole-punching and
  truncation structurally rather than by enumeration.
- **Must cover the misaligned-CAS helper path**, not just JIT-inline stores. Measured: every out-of-JIT
  writer HostPC on Dex (27 %) and Hard West (52 %) lands inside `PPC64_SplitLockEmulate`.
- Escalation is keyed on **fault frequency with hysteresis**, never on changed-byte extent — hashing is
  three orders of magnitude cheaper than the recompile it avoids. This is what killed op4k's v1.
- **Tier-3 escape hatch (inline `ValidateCode` / `ForceFullSMCDetection`) is NOT available.** It is the only
  mechanism structurally immune to block linking, but its emission has a known unfixed state-corruption bug
  (`3987be2db`, `SMCCHECKS=full` path truncation, no fix commit). Do not present it as a ready fallback.
- Ship gate: an **audit mode** that does the whole computation then invalidates anyway. Compare prediction
  against ground truth; **"hash says unchanged but bytes differ" is a false negative and any single
  occurrence blocks the feature.**

## ⛔ THE GATE — measure `U_page` before writing Nimbus code

RimWorld's ~42,000 faults over ~100 s at the measured 22 µs cycle is **0.92 s — under 1 % of wall time.**
That is not the major drag we have been treating this as. The cost is only real if each fault destroys many
units that are then rebuilt, and **units-per-page has never been measured.** It sets both the size of the
problem and the size of Nimbus's payoff: ~95 % of needless block destruction eliminated at `U_page`=32,
~75 % at 4, and **at ~2 the premise collapses** — for us *and* for op4k — and the answer becomes "make
recompiles cheaper" instead. The instrument already exists (`FEX_SMC_AUDIT_COMPILE`, `Core.cpp:1006-1008`).

**"The premise collapsed" is a success of the process, not a failure.**

---

# ⭐ QUEUED BATCH — SMC coverage gaps. Independent of Nimbus; all ship even if `U_page` cancels it.

**Gate for all of these: every gap test must FAIL on the current tree first.** A gap test that passes
beforehand proves nothing. No adversarial review needed — each is a few lines against a concrete defect.

1. **`mremap` never invalidates the destination — live bug, verified.** `Syscalls.h:297-312` invalidates
   only `(OldAddress, OldSize)`. With `MREMAP_FIXED` onto a mapping that held compiled code, those blocks
   survive while the bytes under them are replaced.
2. **`ptrace(POKETEXT/POKEDATA)` writes guest code with no invalidation — live bug, verified.**
   `Syscalls/Info.cpp:104-121` passes it straight through; the kernel writes through `PROT_READ`, so mtrack
   cannot see it even in principle. The passthrough comment says it exists so Wine can run the Ubisoft
   launcher — a debugger patching guest code is the *intended* workload.
3. **`mprotect` returns checked with a macro that vanishes in Release.** `SyscallsSMCTracking.cpp:117`,
   `:232`, `:251` call `LogMan::Throw::AFmt` directly (the function, not the macro — grepping for
   `LOGMAN_THROW_A_FMT` finds nothing). Realistic trigger: `ENOMEM` from `vm.max_map_count` under the VMA
   fragmentation ~23,000 invalidations per Dex session produces.
4. **`SeverLinks` — pure refactor.** Factor the delink walk out of `GuestToHostMap::Erase`
   (`LookupCache.h:131-141`) so a "delink but keep the block" primitive exists. Needed by any retention
   scheme including op4k's; harmless without one. Return the severed count — inbound fan-in per unit is
   unmeasured and the lazy-relink argument rests on it.
5. **8/16-bit XCHG hits `ERROR_AND_DIE_FMT`.** `OpcodeDispatcher.cpp:1166-1168` emits
   `_MonoBackpatcherWrite` for *any* `DestIsMem` XCHG including `86 /r`, while `IR.json:300-302` accepts
   only 32/64-bit and `Core.cpp:1174` is a live-in-Release abort. Gate the branch on size and fall through
   to `_AtomicSwap`. Dormant only because the detector never fires; lands on inspection, not on a test.

---

# ✅ CLOSED 2026-08-03 — the Mono backpatcher hook. Do not fix it; Nimbus subsumes it.

Settled by observation: armed 1/1/1, fired **0/0/0** across ~72,000 faults on Dex, RimWorld and Hard West
(`SyscallsSMCTracking.cpp:291` vs `:328`). The check requires byte `0x87` (XCHG) — a **Windows** Mono
signature ported verbatim, comment and all, from `Source/Windows/Common/InvalidationTracker.cpp:192`. Linux
Mono patches with `LOCK CMPXCHG` (`F0 [REX] 0F B1`), measured at 50–60 % of stores.

**Do not "just fix the signature" — it is a correctness regression.** `IsMonoBackpatcherBlock` has exactly
one consumer, `OpcodeDispatcher.cpp:1167` inside `XCHGOp`. `CMPXCHGOp` has no equivalent branch and emits a
bare `_CAS` that invalidates nothing. A firing detector calls `DisableSMCDetectionLocked`, unprotecting every
W+X VMA process-wide, while the backpatcher's writes stop invalidating — indefinite silent stale execution,
including Steam's overlay CEF/V8 and Wine RWX. It would also still be blind to 27–52 % of faults, which
never satisfy the `IsAddressInCodeBuffer` gate at `:303`.

---

## P0 — RESOLVED 2026-08-01. All four done; patches on branch, unpushed, awaiting review.

**P0.1 — ANSWERED: NEVER.** The probe fired zero times across a full RimWorld run to its ~90 s crash.
`DetectMonoBackpatcherBlock` is a **latent** bug, not the active cause. **Stop attributing RimWorld to
it.** Consequence: P1.1's justification changes — see P1.1.

**P0.2 / P0.3 / P0.4 — applied and verified.** Four files, diagnostic-only for P0.2 and P0.4, behavioural
for P0.3. **P0.3's gate passed: `apt update` succeeds without `APT::Sandbox::User=root`**, 15 index files,
zero `Unknown error` / `apt-key` / `ENOEXEC`. apt-key is closed.

**P0.4** removed ~40 lines: the LR-based disassembly loop in `DiagnoseSuspectGuestRIP` was dumping
dispatcher code and is gone; the `rip[-1]` LookupCache disassembly is retained. `HostLR` relabelled
`DispatcherRetAddr`.

## Staged low-hanging fruit — design pass done 2026-08-01, ordered by value ÷ effort

1. **Shebang crash + host fallback** (~40 lines, upstream). `Syscalls.cpp:155-158` indexes `[0]` on a
   possibly-empty vector — `#!\n` is 3 bytes so it passes the size guard. `FEXInterpreter.cpp:247` throws
   on the same input. And `Syscalls.cpp:162-168` hand-rolls `RootFSPath() + path`; **the correct idiom
   already exists 20 lines below at `:223-229`** — using `FM.GetEmulatedPath` closes three divergences at
   once (host fallback, thunk overlays, symlink following). Land together.
2. **SMC single-step safety** (~35 lines). Template is in the same file: `ExitFunctionLinker`
   (`PPC64Dispatcher.cpp:383-448`) has the right shape, and the `EmitDeferredSignalEnter/Exit` lambdas at
   `:364-381` are already in scope. **Do not `SpillStaticRegs` on the failure path** — SRA was already
   spilled by the handler and `FillStaticRegs` skipped, so host r7-r12 hold garbage; spilling would write
   it over live guest state. Branch to a forward label bound at `:516` instead.
   Correction to an earlier brief: the `SetArmReg` r4 mapping is **already fixed**, don't re-fix it. And
   removing `li(r4,0)` does *not* restore the argument — `PushCalleeSavedRegisters` clobbers r4 first.
3. **`CodeCache::Validate` de-ARM64-ing** (~60 lines + format bump). Cheaper than expected:
   **`CompiledCode` already carries `BlockBegin`** (`CPUBackend.h:115-121`), it is simply never
   propagated into `LookupCache::BlockEntry`. Doing so makes `:502` arithmetic-free and **deletes** the
   AArch64 `ADR` decode at `:573-575` rather than adding a second arch case. Note `:576` is fine on its
   own now that `667b59685` backpatches `OffsetToBlockTail`.
   **Separate blocker found:** `PPC64LE/JIT.cpp:2489` stores `Tail->RIP` as a plain value where ARM64
   emits a relocatable literal — ppc64le cached code is not relocatable across runs. Fixing `Validate`
   unblocks the *gate*, not the *feature*.
4. **Shebang parser kernel semantics + 8 tests** (~30 lines, upstream). Tab is not a separator; `\r` is
   never stripped (**CRLF scripts are the likeliest real-world hit** — they fail `Exists()` → `-ENOEXEC`);
   no 2-argument cap. **Land separately from item 1** — the cap changes argv for working scripts and could
   regress `env`-based shebangs; the crash fixes must not wait on it.

### CORRECTED: ASN.1 DST — FEX is probably innocent, and the blast radius was overstated
Mechanism located, and it is in **OpenSSL's own test helper**: `test/testutil/helper.c:83-84` does
`mktime(local) - timezone`, broken by construction (`mktime` honours DST, `timezone` is the standard
offset). The recipe pins no `TZ`, so the result depends on ambient timezone.

**My earlier "X.509 certificate validity" claim was wrong.** `X509_cmp_time` / `ASN1_TIME_compare` use
OpenSSL's own julian-day math with no libc TZ involvement; that `mktime` construct appears only in the
test helper. Re-ranked down accordingly.

Not fully closed: observed is **+3600** where this host's zone (America/Edmonton) predicts **−3600**, so
it does not cleanly fit the ambient-TZ story either. A ~25-line reproducer printing `tzname`, `timezone`,
`daylight`, `readlink(/etc/localtime)`, and `mktime` with `tm_isdst` forced to −1/0/1 — run natively, then
as a guest with `TZ` pinned, then with `TZ` unset — settles it. Host-vs-guest disagreement with identical
`TZ` would be a real FEX bug in a 25-line file with debug info.

### CORRECTED: flush-to-zero — recommend NOT implementing
`FPSCR[NI]` is the nearest bit, but the semantics do not match in three ways, and the third is decisive:
**the backend emits both VSX and VMX float ops** (`VectorOps.cpp`, 8 VSX sites and 6 VMX). VSX honours
`FPSCR[NI]`; VMX honours `VSCR[NJ]`, a different register set by `mtvscr`. Setting only NI gives
**inconsistent denormal behaviour between two SSE ops in the same guest block**, depending on which family
the backend picked — worse than the current uniform no-op.

Also: NI fuses FTZ and DAZ, which x86 keeps separate (`MXCSR.FZ` bit 15 output-only, `MXCSR.DAZ` bit 6
input-only), and the ISA declares NI's effect implementation-defined.

**Keep `c04687fc4` and leave the gap.** If it is ever wanted, the prerequisite is empirically
characterising NI and `VSCR[NJ]` on POWER9 — not an implementation task.

### RECHECK NEEDED: P0.5 — `FEX_OUTPUTLOG` silently ignores absolute paths
**Size:** small. **Found:** while doing P0.1.

**The stated root cause probably does not hold.** `ExpandPath` (`Config.cpp:255-303`) does return `{}`
for an absolute path with no `ContainerPrefix` — but `ExpandPathIfExists` (`:339-344`) then merely skips
the `Set`, which is a **no-op**: the user's path is already in the Meta layer from `Meta->Load()`, so
`Get(CONFIG_OUTPUTLOG)` still returns it. It does not revert to `"server"`. Init order is fine too.

**Five-minute recheck on the POWER9 box before any code is written:**
`FEX_OUTPUTLOG=/tmp/fexlog.txt FEXLoader … /bin/true; ls -la /tmp/fexlog.txt`. If the file appears, close
this item. If not, the cause is elsewhere — `SilentLog`, the FEXServer log-FD path, or `open()` failing.

**Two genuine defects found in that code regardless, independent of the above:**
- `Config.cpp:261-280` — a *relative* `FEX_OUTPUTLOG` that does not yet exist fails both the
  `Absolute`+`Exists` and the `Exists` checks, so it is never expanded and the file lands relative to the
  guest's cwd at `open()` time rather than the shell's. A log file legitimately does not exist yet.
- `FEXInterpreter.cpp:130` — `open(…, O_CREAT|O_CLOEXEC|O_WRONLY)` with neither `O_TRUNC` nor `O_APPEND`,
  so re-running leaves stale trailing bytes from a longer previous log. One word.

`ExpandPath` has exactly five call sites, all in `ReloadMetaLayer` — small blast radius.

Workarounds: `FEX_OUTPUTLOG=stderr` (special-cased earlier) or a `~/`-relative path. Real fix: let
`ExpandPath` return absolute paths unchanged when there is no container prefix. Upstream code.

### New: P0.6 — RimWorld crash needs its own investigation
**Blocked by:** nothing. **No longer explained by the Mono backpatcher theory.**

`Player.log` shows fatal signal 11 at ~90 s during "initializing interface", in `mono_runtime_invoke`.
Starting points, in order: the `FEX_SMCCHECKS=none|mtrack|full` three-way (Mono is a JIT-under-JIT and
`mtrack` uses SIGSEGV page-protection, while Mono *also* uses SIGSEGV for null checks on an altstack —
two consumers of one signal); then `strace`; then P1.1 if better crash RIPs would help.

---

## Historical: the original P0 items

### P0.1 — One RimWorld run to confirm or kill the Mono theory — ANSWERED, NEVER FIRES
**Size:** one launch. **Blocks:** nothing. **Blocked by:** nothing.

`DetectMonoBackpatcherBlock` may be firing with a block RIP of 0, which would switch off fault-based SMC
detection for every W+X mapping (Mono's JIT arenas) *and* fail to install the replacement write hook —
leaving Mono-generated code with no invalidation mechanism at all. Coherent explanation for
RimWorld-class failures.

**The trigger is probabilistic and unproven.** It needs a `0x87` byte at the block-entry RIP, ~1-in-128
per fault. The code already logs it — `SyscallsSMCTracking.cpp:319-321`, *"Detected mono backpatcher at
{:#x}"*.

- Line appears with `0x0` → confirmed, and P1.1 becomes the fix.
- Line never appears → latent bug, not the active one. Stop attributing RimWorld to it.

Do this before any RimWorld debugging. It costs a launch and decides where the effort goes.

### P0.2 — Un-`#ifdef` the RootFS diagnostic
**Size:** 1 line. **Gate:** builds. **Blocked by:** nothing.

`FEXInterpreter.cpp:507-514` prints "This is likely due to a misconfigured x86-64 RootFS / Current RootFS
path set to '{}'" only under `#ifdef ARCHITECTURE_arm64`. On ppc64le we get the bare "Invalid or
Unsupported elf file."

This cost hours on 2026-07-31: 306 OpenSSL test files failed and the log would have said
`Current RootFS path set to ''` three hundred times. Change to `#ifndef ARCHITECTURE_x86_64`.

### P0.3 — Stop FEXServer clobbering ROOTFS with an empty path
**Size:** ~4 lines, two files. **Gate:** OpenSSL re-run (P1.4), apt under a uid change. **Blocked by:** nothing.

**This is the root cause of both the OpenSSL 306-failure run and the `apt-key` failures.** One bug, two
symptoms:

- `Source/Common/FEXServerClient.cpp:233-236` — comment says "if everything has passed" but there is **no
  check**. `RequestRootFSPath` returns `{}` silently on write failure, short recv, wrong packet type, or
  zero length; the result is written straight into `CONFIG_ROOTFS`.
- `Source/Tools/FEXServer/ProcessPipe.cpp:540` — sends `.Length = MountFolder.size() + 1`, so an **empty**
  MountFolder still ships `Length == 1`, defeating the `Length > 0` guard at `FEXServerClient.cpp:395`.

With `ROOTFS` empty, `ELFWasLoaded()` fails for any guest ELF *and* `Syscalls.cpp:163` looks for
interpreters on the ppc64le host, returning `-ENOEXEC` for every `#!` script. Both observed symptoms.

**Why apt-key hits it:** `GetServerSocketName()` keys the FEXServer socket on `getuid()`. When apt drops
to `_apt`, the child connects to a *different* FEXServer running as `_apt`, which has no config, so
`SquashFS.cpp:237` sets `MountFolder = LDPath() = ""` and hands back an empty path the client accepts.

Fix: guard the empty case and keep the configured value; send `Length = 0` for an empty MountFolder.

### P0.4 — Fix the `HostLR` mislabel in the crash diagnostic
**Size:** comment + one decision. **Blocked by:** nothing.

`JIT/PPC64LE/JIT.cpp:1622` labels `HostLR` as "JIT block tail that called us". It is not — it is
`__builtin_return_address(0)` taken inside `ExitFunctionLink`, whose only caller is the dispatcher stub.
It is a **fixed dispatcher address** (hence every capture sharing low bits `0x3cc`/`0x3d0`), so the
disassembly dump at `:1643` has been showing **dispatcher code, not the faulting block**, throughout the
`probe_thread_spawn` investigation.

Either fix the label and drop the disassembly, or find the real caller address. Anything derived from
that dump so far should be re-examined.

---

## P1 — the main line of work.

### P1.1 — `JITCodeHeader` emission + `InlineJITBlockHeader` store
**Size:** small. **Gate:** Factorio (checksums + cpu-frame), FTL, RimWorld. **Blocked by:** nothing.

ppc64le never writes `InlineJITBlockHeader`, so `GetFrameBlockInfo` always returns null and four functions
silently degrade: `RestoreRIPFromHostPC`, `GetGuestBlockEntry`, `IsAddressInCurrentBlock`,
`IsCurrentBlockSingleInst`.

**Key finding from review: ppc64le already emits a fully-populated `JITCodeTail`** (`JIT.cpp:2424-2434`) —
`RIP`, `GuestSize`, `Size`, `SingleInst` are all correct. The tail is merely orphaned. The missing piece
is 4 bytes of header plus one store.

Consequences (**justification revised 2026-08-01 after P0.1 came back NEVER**):
- ~~Fixes the Mono bug~~ — it fixes the *latent* backpatcher defect, but that path does not fire on
  RimWorld. **This is no longer a RimWorld fix and must not be sold as one.**
- Gives real guest-RIP reconstruction for crash diagnosis. Still the main near-term value, and still
  useful for P0.6 — but as better instrumentation, not as a cure.
- Closes the inline-SMC hole: `IsAddressInCurrentBlock` is unconditionally false today, so a block that
  writes its own page keeps executing stale translations. See P2.4 before enabling that path.
- Necessary but **not sufficient** for the code cache — see P3.3.

**Honest priority after P0.1:** this drops from "fixes the active bug" to "removes a real defect and
improves diagnostics". Still worth doing, no longer urgent.

Implementation notes from review:
- **Use `bcl 20,31,$+4; mflr`, not `addpcis`.** The link-stack objection against `bcl` is backwards — that
  exact encoding is the one POWER does *not* push, which is why GCC emits it for PIC. It works on POWER8,
  removes the ISA-3.0 gate, removes the absolute-address fallback, and avoids hand-encoding a DX-form
  instruction. LR is verified dead at ppc64le block entry.
- If `addpcis` is used anyway: the ±32 KB range **breaks on large blocks**, which `MAXINST=500` (mandatory
  for MonoHacks) readily produces. Needs the `ha16`/`lo16` split. Add an emitter unit test asserting
  `addpcis r5,0x1234 == 0x4cba1204`, `addpcis r3,0x7fff == 0x4c7f7fc5`, `addpcis r4,-1 == 0x4c9fffc5`, and
  note the base is **NIA (CIA+4)**, not CIA.
- **One-line change makes the split non-regressive:** in `Core.cpp`, when `NumberOfRIPEntries == 0`, fall
  through to `Frame->State.rip` rather than returning block-entry RIP. Without it, syscall-site RIP
  precision degrades and `SeccompEmulator.cpp:344` gets a worse answer than today.
- **Do not enable the single-step SMC path in this commit** — see P2.4.
- Alignment padding is optional. The justification offered for it was wrong on both legs (ppc64le has no
  block linking; block starts already alternate 0/8 mod 16). Cheap insurance, not a requirement.

### P1.2 — d-form `ld` for the FABI pointer loads
**Size:** ~8 lines. **Gate:** ctest, instruction-count delta, regression set. **Blocked by:** nothing.

`JIT.cpp:1061-1064` and `X87Ops.cpp:432-435` use `LoadImm32` + `ldx` where a single d-form `ld` works.
These are the **only two** such sites in the backend; everything else already uses `ld`.

Value is not the two instructions — it is removing a `TMP2` serialisation in front of `mtctr`/`bctrl`,
and removing a silent `uint32_t`→`int16_t` narrowing whose only assert checks alignment, not range.
Expect **no measurable wall-time change**; do not claim one.

Correction to earlier framing: `X87Ops.cpp EmitFABICall` is **not** per-x87-instruction — it is the
stack-form slow path taken when `x87StackOptimizationPass` bails. The per-instruction path is
`Op_Unhandled` at `JIT.cpp:1058-1064`.

### P1.3 — Build and test the two committed-but-unbuilt fixes
**Size:** build + gate. **Blocked by:** nothing.

- `c04687fc4` — `SetRoundingMode` out-of-bounds read. `Src` is 0–7, not 0–3 (`_Bfe` width 3), so guest
  MXCSR flush-to-zero indexes past a 4-byte table and can set FPSCR **NI (non-IEEE mode)**. Live bug,
  reachable by any game calling `_MM_SET_FLUSH_ZERO_MODE`. Needs an FP/MXCSR regression pass.
- `5bf6e5073` — revert of the DQ-form vector spill. Already measured as performance-neutral and
  crash-inducing; the revert just needs to build clean.

### New: P1.5 — ASN.1 time parsing is off by exactly one DST hour
**Size:** unknown. **Found:** by the clean OpenSSL sweep. **Blocked by:** nothing.

`90-test_asn1_time.t` fails with an **exact 3600 s offset**, every case on **2021-03-28** — the day
Europe/UK moved to summer time. It fails identically on the explicit `+0100` / `+0200` forms, so it is
not about which zone the test expects: FEX's guest-side conversion is applying a DST-crossing hour where
the ASN.1 parser wants an offset relative to UTC. Suspect the `mktime` / `localtime_r` / `timegm` shim
path and `TZ` semantics.

**Blast radius is larger than a unit test.** ASN.1 time parsing is how X.509 certificate validity windows
are checked. An hour of skew across a DST boundary could affect TLS certificate acceptance near expiry —
worth weighing against the Steam/TLS work, though 32-bit TLS handshakes were verified working.

Not caused by any P0 patch (no failure of this shape in the pre-P0 truncated run). **Expect this test red
until fixed — do not mistake it for a crypto-helper regression.**

### P1.4 — Re-run OpenSSL clean, for crypto coverage — **DONE 2026-08-01**
**Size:** one run. **Blocked by:** P0.3. **Blocks:** P2.1 — now unblocked.

**Result: 306 failures → 1.** `HARNESS_JOBS=8`, rootfs pinned, ~35 min wall. Files=343, Tests=3997.
All three gates green: zero "Invalid or Unsupported elf file", zero 248 exits, 344 `test-runs/`
directories versus the previous 38. Full `20`–`99` range covered — EVP, provider, cipher, ML-KEM,
SLH-DSA, X509, TLS, fuzz. Sole failure is P1.5 above, unrelated.

**Crypto gate for per-change use (target 3–5 min at jobs=8):**
```
15-test_sha.t  05-test_hmac.t  05-test_cmac.t  30-test_aesgcm.t
30-test_evp.t  30-test_evp_extra.t  30-test_evp_kdf.t  20-test_kdf.t  20-test_mac.t
```
`30-test_aesgcm.t` exercises the GHASH/PCLMUL path; `30-test_evp.t` drives the bulk AES/SHA/HMAC/HKDF
vector files. **Excluded as too slow for iteration:** `20-test_enc.t` (~285 s), `20-test_dgst.t` (~66 s),
`20-test_speed.t` (a benchmark, not a correctness test). Keep those in the occasional full sweep.

### Superseded: original P1.4 text

The 2026-07-31 run gave **essentially zero crypto coverage** — the 38 recipes that ran are the `00`–`03`
internal tests; every provider, EVP and cipher test is among the 306 that never launched.

Re-run with nothing else touching the rootfs, `FEX_ROOTFS` pinned explicitly, `HARNESS_JOBS` at 1. Gate
on two greps: zero files exiting 248, zero "Invalid or Unsupported elf file" lines. `test-runs/` should
contain ~344 directories, not 38 — that count is a cheap coverage assertion.

**The 2026-07-31 collapse was probably an environment collision:** the rootfs `.sqsh` has
ctime == mtime == 12:00:51, 22 seconds after the failures began. A rootfs fetch or repack was very likely
running concurrently with `make tests`.

---

## P2 — enablement work. Correctness, not performance.

### P2.1 — Route baked helper addresses through thread state
**Size:** 6 commits. **Gate:** OpenSSL (P1.4), ASM crypto tests, regression set. **Blocked by:** P1.4 for the crypto half.

32 emitter sites bake absolute host addresses into JIT block code, which breaks under PIE for the code
cache. Full design and site table in the redesign; commit sequence C2–C6 there.

**Frame this as correctness/enablement, not performance.** All 32 sites sit inside a full
`SpillForABICall`; the change is unmeasurable by design. Success criterion is the correctness suites,
not a stopwatch.

Key constraints found by review:
- **`CpuStateFrame` has exactly zero headroom** — `384 + 3712 = 4096` fills page 1 of a 2-page
  `InternalThreadState` to the byte. Adding any inline array fails both asserts. Use **one `uint64_t*`**
  placed in the existing pad after `PauseCount` (offset 1544) — proven by compilation to cost zero frame
  growth and leave ARM64 byte-identical.
- **Do not reuse the seven `F64*Handler` slots.** `F64F2XM1Impl` deliberately diverges from the upstream
  handler (`expm1(x*ln2)` vs `exp2(src)-1.0`, which is off by >1 ULP on 44.6% of inputs) — that
  divergence exists to fix `D9_F0_02_F64`. Reusing the slot re-breaks it.
- `Ptrs.LUDIV`/`LDIV` are vestigial on ppc64le (no reader). Separate 4-line deletion.

### P2.2 — Fix the shebang handler divergences
**Size:** small, several files. **Blocked by:** nothing. **Priority:** low — these did **not** cause the
OpenSSL failure (P0.3 did), but they are real and upstream.

- `Syscalls.cpp:160-168` is RootFS-only with no host fallback, unlike `FEXInterpreter.cpp:219-222`.
- Empty shebang line is UB at `Syscalls.cpp:155-158` and throws at `FEXInterpreter.cpp:247`.
- `StringArgumentParser.h` splits on space only; Linux uses space **and tab**, passes at most **one**
  argument after the interpreter, and strips trailing whitespace.
- Neither handler routes through `FileManager::GetEmulatedPath`, so both miss thunk overlays.

All upstream code, untouched by the port — ARM64 users are exposed too. Worth sending upstream.

### P2.3 — Implement guest flush-to-zero
**Size:** unknown. **Blocked by:** nothing.

ppc64le has **no FTZ handling at all**. ARM64 writes `FPCR.FZ` from `Src` bit 2; after `c04687fc4` we
correctly ignore that bit rather than corrupting FPSCR with it, but guest FTZ remains unimplemented. Real
behavioural difference from x86 for any game setting `_MM_SET_FLUSH_ZERO_MODE`.

### P2.4 — Make the single-step SMC path safe before enabling it
**Size:** two fixes. **Blocked by:** nothing. **Blocks:** relying on inline SMC.

`IsAddressInCurrentBlock` is unconditionally false today, so `SyscallsSMCTracking.cpp:146` has **never
executed** — inline SMC is entirely unhandled on ppc64le. P1.1 makes it live. Before that:

1. **Null `bctr` on compile failure.** `CompileSingleStep` returns 0 on failure; the ppc64le tail
   (`PPC64Dispatcher.cpp:486-492`) branches to it with no zero check. Inherited from ARM64, but ARM64's is
   exercised and ours never has been.
2. **No `EmitSignalGuardedRegion`** around the C call, unlike ARM64. Highest-risk divergence given this
   port's history with signals during JIT.
3. Minor: `li(r4,0)` at `PPC64Dispatcher.cpp:182` unconditionally destroys the `SingleInst` argument.
   Inert today; the backends now differ semantically.

---

## CODE CACHE — NOT PARKED. Non-negotiable. Correction recorded 2026-08-01.

Research recommended measuring JIT-compile time as a fraction of wall time before committing to the
cache, and I relayed that as a gate. **That was the wrong framing and the decision is reversed.**

**Why it was wrong:** the ceiling was computed as a fraction of *aggregate* wall time. Stutter is not an
aggregate — it is a tail. A 40 ms compile arriving at the wrong moment is an audible glitch and a dropped
frame, and it is invisible in a mean and nearly invisible at p95. The research's own Factorio section
predicted the effect would appear in **max and p99.9** and not at p95, which should have been the tell
that the aggregate number answers a different question than the one that matters.

**The measurement's own data already argued against my reading.** Every Factorio launch spawns FEXServer
and thunk-helper subprocesses, and those measured at **~75% JIT** (`blocks=427`). That is the `perl -e0`
case (82.6%) happening dozens of times per session. Games are not one long-lived process; they are a
long-lived process surrounded by a constant churn of short-lived ones, and the short-lived ones are
almost entirely compilation. That churn is where hitches and audio glitches come from.

**Standing position:** the cache work proceeds. The P5.1 numbers remain useful as a **baseline** — they
tell us what the absolute JIT cost is per workload (perl 0.135 s, Factorio 5.37 s per launch) so we can
tell a working cache from a broken one later. They are not a go/no-go gate.

**What still stands from the research**, because it is about correctness rather than value:
- Landing order: fixed-width constant emission (without a config flag) → offset-base + `TakeRelocations`
  rebasing together → relocation emission + `Tail->RIP` together → I-cache flush → then the invalidation
  work. There is no useful intermediate state; a partially-correct relocation set patches real code at
  wrong offsets.
- `CodeCache::Validate` must land first — it is the only detector for the rest, and it is being fixed now
  as S3.
- Validation is blind to the block-mapping table. Add the structural header/tail check.
- `ComputeCodeMapId` hashes only the path string and ignores the FD it is handed — `apt upgrade` inside
  the rootfs silently poisons every cache for every upgraded library. Must be fixed before the cache is
  left enabled.
- `CodeCacheConfigId` is hardcoded `0`, so codegen-affecting options do not invalidate. Fix before
  benchmarking, or you will measure a cache built from different codegen.

**Measurement, when the time comes:** report max, p99.9 and p99 on the first ~300 ticks separately from
the remainder, with `--benchmark-runs 1` and never pooled — the benchmark warms itself, so pooling 8000
frames buries the compile cost. Also time-to-first-frame and time-to-initialised, which are plain
wall-clock numbers where a startup cache should show its clearest win.

---

## PRIORITY RESET — 2026-08-01

**Foundational implements first: proper tracing, then the code cache.** Stop diagnosing the engine
through the exhaust pipe. Symptom-chasing (RimWorld, `probe_thread_spawn`, Factorio's load crash) waits
until the tools exist to look at it directly.

The order is now: **P3.1 → P2.1 → P3.2 → P3.3.** Everything else is parked.

### Pre-registered decision — inline L1 dispatch probe (`c6c8d8dde`, `7f5e92bbb`)

**Recorded 2026-08-01, before the measurement exists, so we are not arguing with a result we have grown
attached to.**

The criterion: *keep a change if it simplifies the execution pipeline and reduces error surface — that is
worth more than performance. If it is riskier AND does not improve performance, it is worthless.*

**This change does not get the simplification defence.** It **adds** structural complexity: two linker
entry points where there was one, an address-dependency idiom that needs explaining, and signal-critical
reachability that must now be reasoned about per path. So it has to pay on performance.

- **Measures meaningfully faster** → keep. 84 → 14 instructions on the L1 hit path, and it removes a
  double-spill (the old miss path spilled in both `ExitFunction` and `ExitFunctionLinker`).
- **Measures flat** → **revert**, same as the vector spill, for the same reason. Salvage separately: the
  load-ordering fix (`c6c8d8dde`) is a standalone bug fix to existing dispatcher code and should survive
  independently, and the double-spill finding is worth its own small commit.
- **Measures worse** → revert immediately, no discussion.

> ### ⚠ DO NOT `git revert 7f5e92bbb` — the revert must be SURGICAL
>
> S2's SMC single-step work was **co-committed into `7f5e92bbb`**. A subagent committed while the build
> agent had uncommitted changes to the same file (`PPC64Dispatcher.cpp`); "stage only your own files"
> does not help when two actors edit one file. Six hunks of S2 work are inside that commit and its
> message describes none of them.
>
> **Reverting the commit would silently take out:** the `EmitDeferredSignal{Enter,Exit}` guard around
> `CompileSingleStepLabel`, the `r3 == 0` compile-failure check, and `ThreadStopNoSpillLabel`. Those are
> correctness fixes to a path that had never executed, and they must survive.
>
> **A revert must remove only:** the `BranchOps.cpp` inlining of the L1 probe, and the
> `ExitFunctionLinker` split into spilling/non-spilling entries in `PPC64Dispatcher.cpp`. Leave the
> `CompileSingleStepLabel` rewrite untouched.
>
> History was deliberately not rewritten to fix this — the build agent had already committed
> `357973731` on top, and rewriting shared history while another actor is working in the same tree is
> how work gets lost.
>
> **Process fix applied:** code-writing subagents are now instructed to refuse to commit when the tree
> is dirty with files they did not author, and to report rather than sweep the changes up. A `git
> worktree` per subagent would be stronger but adds setup; revisit if this recurs.

Contrast with P2.1, which earned its place on simplification alone: it removed 22 baked host addresses,
made block code position-independent, and shrank the fixed-width work from ~37 sites to ~5, at zero
measured performance. That is a change worth keeping regardless of the stopwatch. This one is not.

Measurement: Factorio graphics benchmark, cpu-frame median, SMT2 node 0, against the §E cell (24.427 ms).
Note the bench cannot resolve ~3.7%, so if the result is ambiguous use `perf stat` instruction-count
deltas — deterministic and noise-free, which is how the vector spill was settled in two runs.

### New: P4.1 — block linking. Probably the largest remaining performance item, and it was dropped.

ppc64le has **no block linking at all**. Every guest block exit runs a full `SpillStaticRegs`, branches to
`DispatcherLoopTop`, does an L1 lookup, and refills. ARM64 backpatches a direct branch between blocks, and
for returns pops a `<GuestRIP, HostPC>` pair off a `REG_CALLRET_SP` shadow stack in ~3 instructions,
skipping the lookup entirely.

Original estimate from the thunk-overhead research: **~125 instructions and 792 bytes per block
transition** — larger than everything else in that report combined. It was shelved as "structural, high
risk", and then we spent a night proving that **block transitions are exactly where cost lives**: 23
instructions removed from that path was worth 35%.

**The open question the design must answer honestly:** the 23 instructions that bought 35% included
stores to *contended, process-global* cachelines. Block linking removes spill/fill traffic to
*thread-private* STATE. Those are different cost buckets, and the 32-pure-ALU experiment that bought 0%
is the cautionary case. Do not assume the magnitude transfers.

Known complications: SRA must stay live across a link or you still spill and fill (this may be the real
blocker, not the branch mechanics); backpatching executable code that another thread may be running, on a
host with non-coherent split I/D caches; and a linked branch that skips the entry-point prologue would
skip the `InlineJITBlockHeader` store that `667b59685` just added, leaving the header stale.

Design in progress. Adversarial review before any implementation.

### New: P4.2 — does FEX's GdbServer work on ppc64le?

**Queued, not urgent. Potentially makes a chunk of planned tooling unnecessary.**

We can now reconstruct a per-instruction guest RIP, but turning one into a symbol is still manual:
find the mapping in `/proc/<pid>/maps`, subtract the base, correct for the ELF load bias, then
`addr2line` against the guest binary from inside the rootfs. And for RimWorld the harder half is that
Mono JITs into **anonymous mappings** — a RIP landing in a JIT arena has no ELF and no symbol table.

FEX ships a GdbServer (`Source/Tools/LinuxEmulation/LinuxSyscalls/GdbServer.cpp`, plus
`Source/Tools/FEXGDBReader`). If it works here, attaching gdb gives module resolution, symbols, memory
inspection and backtraces natively — and the maps-dump-plus-resolver-script plan below becomes
unnecessary.

**Investigate, in order:**
1. Does it work at all on ppc64le? Find the config option that enables it and try it against something
   trivial before a game.
2. If it works: does it resolve guest symbols, and does it see into Mono JIT arenas or stop at the
   mapping boundary?
3. If it does not work: what is broken? It reads guest state through paths this port has repeatedly
   found bugs in — note that `5685fc55a` (P1.6) just fixed the flag reconstruction it uses, so its flag
   display may have been wrong until today and may now be correct.

**Fallback if the GdbServer is not viable** (a couple of hours, permanently useful):
- Dump `/proc/self/maps` at fault time from FEX's crash handler — the address is unresolvable after the
  process dies, and the handler already knows it is crashing.
- A ~20-line resolver script: RIP + maps file → module and load-bias-corrected offset. Removes the
  arithmetic error from every future investigation.
- For Mono specifically, enable Mono's `/tmp/perf-<pid>.map` so JIT-arena addresses resolve to managed
  method names. That is the difference between debugging RimWorld and staring at it.

### Testing gap being closed: x87 workload
Quake 2 (id Tech 2, 1997, pre-SSE, float-heavy, `timedemo 1` with `demo1.dm2`) is being brought into the
pipeline. Build `-m32 -mfpmath=387` and verify with `objdump -d | grep -c 'fsin\|fpatan\|fyl2x'` before
trusting it — a build that turned out to be SSE throughout would measure nothing and we would not know.
Needed before P2.1's hot half means anything.

### Process: directives must carry the design
Anything sent to the build agent needs the design or implementation plan **inline**, not a pointer to a
document. It runs a smaller model; it should be executing a plan, not making architectural judgement
calls or reconstructing context. P3.1's directive does this correctly; P2.1's currently points at this
file and must be expanded before it is released.

Both P3.1 and the caching chain sat in the deferred pile. That was a misjudgement: "we don't yet know the
full implications" was a good reason to scope them, and stopped being a reason once the scoping and
adversarial reviews were done. Deferring the *implements* while chasing the *symptoms* is backwards —
the implements are what make the symptoms tractable.

---

## P3 — deferred. Real work, no near-term payoff.

### P3.1 — RIP-entry table (`vl64pair`) — **PROMOTED TO TOP PRIORITY**

**This is the half of P1.1 that pays out.** As landed, P1.1 is plumbing: `RestoreRIPFromHostPC` still
short-circuits to `Frame->State.rip` because ppc64le emits zero RIP entries, so signal frames and crash
reports still carry block-entry granularity. Of the four functions P1.1 revived, `GetGuestBlockEntry`,
`IsAddressInCurrentBlock` and `IsCurrentBlockSingleInst` work — but the one that reconstructs a guest RIP
from a host PC does not.

P3.1 is what turns "somewhere in this block" into "at this guest instruction".

**Small, because most of it exists:** the arch-neutral frontend already emits `_GuestOpcode` markers for
every instruction that can fault (`Core.cpp:654-656`, gated on `CanHaveSideEffects`), the `vl64pair`
encoder already exists, and `DEF_OP(GuestOpcode)` on ppc64le is a literal empty stub
(`PPC64LE/ALUOps.cpp:3403`). We are discarding data we already generate. Body for the stub, one
`push_back` per entry point, ~20 lines emitting the array, and extend `BlockHeadroom`.

Keep the `Core.cpp` guard — it stops short-circuiting once `NumberOfRIPEntries > 0` and remains correct
for blocks emitting none.

### P3.2 — Fixed-width constant emission
`LoadConstant` emits 1–5 instructions by value; relocation patch sites need fixed width. Design and
adversarial review are done — four must-change items, chiefly that `SaveData` patches with `DOPAD` while
the JIT emits with `AUTOPAD`, and `FEXOfflineCompiler` never sets `ENABLECODECACHINGWIP`, so it writes 5
words over a possibly-1-word site.

**Do P2.1 first** — it removes 32 constants from the population, shrinking this from ~37 sites to 5.

### P3.3 — Relocation subsystem
Offset base fix (relocations are recorded block-relative, consumed buffer-relative — confirmed
independently by two reviews), `TakeRelocations` rebasing, and the four missing emission sites including
`JITCodeTail::RIP`.

Also: **`CodeCache::Validate` is ARM64-shaped end to end** — it assumes a header 4 bytes before the first
entry point (ppc64le's is ~252 bytes in, after `FillStaticRegs`) and decodes an ARM64 `ADR`. The
validation gate the plan recommends is itself broken; `POWER9_PORT_PLAN.md:401-403` needs correcting.

### P3.4 — i386 Steam / threaded TLS probe
32-bit TLS verified working in isolation. Untested difference: our probe is single-threaded, Steam's
manifest fetch is not. Queued for the build agent.

---

## Closed this cycle

- **`36299af03`** — gated dispatcher RIP-trace instrumentation. **35–57% on Factorio**, checksum-verified,
  pushed. The single largest performance change of the port.
- **`01851d724`** — r2/TOC preservation across the cross-DSO thunk `bctrl`. ELFv2 conformance, measured
  inert, pushed.
- **`695b3e681` → reverted as `5bf6e5073`** — DQ-form vector spill. Took effect (−26.9B instructions) and
  bought nothing (wall +0.11%). Crashed 2 of 3 runs. **The finding is the value:** on this backend,
  memory traffic to contended cache lines costs; ALU instruction count does not convert to wall time.
- **Dynamic register spill filter** — cancelled before being written. At 5,000–6,500 thunk calls per frame
  it was worth ~0.3–0.5% of `cpu-render`, 50–90× below one standard deviation.
- **32-bit TLS** — all five permutations pass against Steam's exact bundled OpenSSL 1.1.1i with a matched
  64-bit control. Not a FEX defect.
- **`ENABLE_CLANG_THUNKS`** — confirmed as the GL regression cause by 2×2 isolation plus a fresh-rootfs
  replication.
