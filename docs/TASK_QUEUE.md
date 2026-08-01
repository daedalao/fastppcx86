# Task queue — prioritised

Living document. Direction lives in `POWER9_PORT_PLAN.md`; current conversation lives in
`build-agent-notes.md`; the durable record is commit history. **This is the ordered work list.**

Last updated 2026-08-01, after the code-cache design cycle.

Each item: what, why it is where it is, size, gate, and what blocks it.

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

### New: P0.5 — `FEX_OUTPUTLOG` silently ignores absolute paths
**Size:** small. **Found:** while doing P0.1.

`FEXCore/Source/Interface/Config/Config.cpp:393-395` calls `ExpandPathIfExists(CONFIG_OUTPUTLOG, ...)`;
`ExpandPath` (`:255`) falls through to `return {}` for an absolute path with no `ContainerPrefix`. The
empty result makes `ExpandPathIfExists` skip the `Set`, so `CONFIG_OUTPUTLOG` silently stays at its
default `"server"` and no file is created.

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

## P3 — deferred. Real work, no near-term payoff.

### P3.1 — RIP-entry table (`vl64pair`)
Gives sub-block guest-RIP reconstruction. Small (markers and encoder already exist;
`DEF_OP(GuestOpcode)` is an empty stub on ppc64le) but **not required** for P1.1 given the one-line
`Core.cpp` guard. Land separately and measure.

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
