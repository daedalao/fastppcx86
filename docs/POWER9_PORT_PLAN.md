# FEX-PPC64LE — POWER9 Port Plan

Status: **planning document, no code changes yet.** Branch `power9-support`, forked from `main` at `0f17626ac`.

This document records an audit of the existing POWER8 port and a plan for POWER9 (ISA v3.0) support.
Every ISA-level claim below was adjudicated against the primary sources listed in
[Sources and method](#sources-and-method); claims that could not be confirmed are marked as such
rather than dropped.

The audit's headline conclusion is deliberately unflattering:

> **POWER9 does not clear the port's blocker table.** The dominant remaining problems — cross-arch
> callback dispatch, libxshmfence heap corruption, Steam, the SIGABRT on exit — are ELFv2/ABI and
> plumbing issues that are byte-identical on POWER9. What POWER9 *does* buy is (a) a plausible fix
> for the entire Mono/managed-runtime failure class, via 4 KB Radix pages, and (b) a substantial
> set of ISA 3.0 codegen wins. Both are worth having. Neither is what the branch was originally
> imagined to be.

A second, more actionable conclusion: **a significant fraction of the identified wins are not
POWER9 features at all.** They are POWER8-legal facilities (ISA 2.01–2.07) that the backend simply
never learned to emit. Those should land on `main` first, against the existing POWER8 hardware,
before anything is gated behind a POWER9 check.

---

## Contents

- [Tier 0 — the page-size / SMC defect](#tier-0--the-page-size--smc-defect)
- [Tier 1 — wins available on POWER8 today](#tier-1--wins-available-on-power8-today)
- [Tier 2 — POWER9-gated wins](#tier-2--power9-gated-wins)
- [Negative results](#negative-results--do-not-budget-for-these)
- [Traps and invariants](#traps-and-invariants)
- [Hardware probe checklist](#hardware-probe-checklist)
- [Mono debug plan](#mono-debug-plan)
- [Instruction availability tables](#instruction-availability-tables)
- [Open questions needing hardware](#open-questions-needing-hardware)
- [Sources and method](#sources-and-method)

---

## Tier 0 — the page-size / SMC defect

**This is the only finding that plausibly unblocks a currently-failing game.**

### Mechanism

`SyscallHandler::MarkGuestExecutableRange` write-protects guest code pages so that guest writes
fault and trigger re-translation. That is how FEX detects self-modifying code. It calls `mprotect`
at **4 KB-aligned** boundaries, because `FEX_PAGE_SIZE` is hardcoded:

- `FEXCore/include/FEXCore/Utils/TypeDefines.h:9-10` — `FEX_PAGE_SIZE = 4096`, `FEX_PAGE_SHIFT = 12`
- `Source/Tools/LinuxEmulation/LinuxSyscalls/SyscallsSMCTracking.cpp:174-182` — the `mprotect` calls

The return value of every one of those `mprotect` calls is passed to `LogMan::Throw::AFmt`, which
in a non-assertions build is defined as (`FEXCore/include/FEXCore/Utils/LogManager.h`):

```c
static inline void AFmt(bool, const char*, ...) {}
```

An empty function. Assertions are enabled **only** for `CMAKE_BUILD_TYPE=DEBUG`
(`CMakeLists.txt:186-192`), while the project's own build instructions specify
`-DCMAKE_BUILD_TYPE=Release`.

Therefore, on a host kernel with 64 KB base pages — the default on essentially every ppc64le
distribution — `mprotect` of a 4 K-aligned-but-not-64 K-aligned address returns `EINVAL`, **and the
failure is discarded silently**. Write-protection never arms, write faults never fire,
`InvalidateGuestCodeRange` never runs, and code the guest generates or backpatches keeps executing
its **stale translation indefinitely**.

`SMCChecks` defaults to `mtrack` (`FEXCore/Source/Interface/Config/Config.json.in:420-431`), so this
is the live path, not a dormant one.

### Why this presents as "a Mono bug"

Ahead-of-time compiled games (FTL and friends) never self-modify, so a dead SMC path costs them
nothing. Mono generates and backpatches x86 code continuously at runtime. The reported symptom —
"main thread spins on `FUTEX_WAIT`→`EAGAIN` **after cold JIT**" — matches precisely: the spin begins
right after Mono's compile-and-patch burst.

It also explains the futex symptom without any futex bug. Futex is a straight passthrough to the
host kernel (`LinuxSyscalls/Syscalls/Passthrough.cpp`); there is no address translation and no flag
remapping. `EAGAIN` means the host kernel compared guest memory and found the expected value absent.
POWER cache coherence guarantees a plain reload eventually observes new *data*, so data staleness
cannot sustain an infinite spin — but a stale *translation* of a Mono-patched wait loop can, forever.

Corroborating evidence that the original author was circling this without naming it:

- `ForceFullSMCDetection` for Mono tailcalls — `FEXCore/Source/Interface/Core/Frontend.cpp:1648`
- `MonoBackpatcherBlock` — `FEXCore/Source/Interface/Core/Core.cpp:560`
- Multiblock truncation past `CALL` "because calls are always backpatched" — `Frontend.cpp:1138-1143`
- `MonoHacks` defaulting to **true**, with hardcoded FORCE_TSO on Unity ringbuffer offsets
  0x80/0x84/0xC0/0xC4 — `Frontend.cpp:1107-1121`, `a37a65f17`
- Commit `cf17977e8` — "compile-time byte log for **stale-compile diagnosis**"

The README's conclusion that the Ziggurat spin is "not a general FEX bug" is probably wrong in an
interesting way: it *is* a general FEX bug on this host configuration, which only Mono-class
workloads exercise.

### What POWER9 changes

POWER9 Radix supports 4 KB pages natively (POWER9 UM §4.10.4.1 Table 4-17: 4 KB, 64 KB, 2 MB, 1 GB
are the only supported sizes). A Radix 4 K kernel restores the `FEX_PAGE_SIZE == host page size`
invariant and the mechanism simply starts working.

**Caveat:** if the POWER8 box was *already* running a 4 K kernel, this entire theory dies and the
residual is invalidation-scope logic, which POWER9 does not change. One command settles it — see
[Hardware probe checklist](#hardware-probe-checklist).

### Fixes to land regardless of the probe result

1. Startup assertion that `sysconf(_SC_PAGESIZE) == FEX_PAGE_SIZE`, failing loudly.
2. Check the `mprotect` return values in release builds. A silently-ignored `mprotect` is a bad
   failure mode on any host. (Three call sites: `SyscallsSMCTracking.cpp:79`, `:174`, `:180`.)

---

## Tier 1 — wins available on POWER8 today

None of these require POWER9. All are ISA 2.01–2.07 facilities the backend does not currently use.
**Land these on `main` first** — they are correctness-neutral or correctness-improving, they
exercise the existing 11213-case ASM differential suite, and they establish a working test loop
before anything becomes POWER9-conditional.

| # | Change | Current cost | New cost | Evidence |
|---|---|---|---|---|
| 1 | `isel` for `CMOVcc` / branch-free selects | 3 insns + branch, 25 `bc` sites in `ALUOps.cpp` | 1 insn (lat 2, +3 CR-forwarding) | `isel` is **v2.03**; emitter has no encoding for it at all |
| 2 | `vbpermq` + `mfvsrd` for `PMOVMSKB` | dispatcher-generated chain | 2 insns | `vbpermq` is **v2.07**, already encoded in `Emitter.h`, never emitted |
| 3 | Hardware AES / PCLMUL / SHA | FABI software helper calls, ~50+ insns with spill/fill | 1–3 insns | `vcipher`, `vncipher`, `vpmsumd/w`, `vshasigmaw/d` all **v2.07** |
| 4 | `xvcvspdp` / `xvcvdpsp` for CVTPS2PD/PD2PS | 9–12 insn per-lane stack loop (`VectorOps.cpp:4513-4551`) | 2–3 insns | **v2.06**, absent from emitter |
| 5 | `mfocrf` / `mtocrf` in hot flag paths | `mfcr` = 3-iop crack | uncracked, lat 2 | **v2.01**. UM §4.1.5.6: "software should use the single-field variants" |
| 6 | `VExtr` N<16 → single `vsldoi` | 13-insn stack-materialised perm control | 1 insn | `vsldoi` is v2.03; this is pure oversight |
| 7 | Restripe split-lock mutex table at 128 B | `addr >> 6` false-shares adjacent stripes | — | UM §4.6.1 / §4.6.2.12: coherence block **and** reservation granule are 128 B |
| 8 | Fix `HostFeatures.DCacheLineSize` fallback (64 → 128) | wrong on all POWER | — | UM Table 4-3 |
| 9 | Route misaligned `CMPXCHG8B` through the split-lock helper | plain **non-atomic** ld/cmp/std | mutex-atomic | `AtomicOps.cpp:743-755`, comment admits it |

### 10. The PAUSE regression — root cause identified

Commit `60718954e` introduced an SMT priority hint for x86 `PAUSE`; it hung every SDL2/Vulkan game
and was backed out in `88d1c4f7b`, leaving only a counter-gated `sched_yield`.

The POWER9 UM explains why (power9um §5, PPR discussion):

> "Hardware typically does not change the thread priority value in the PPR, unless an `mtPPR` or one
> of the priority changing NOP instructions is committed."

Thread priority is **never automatically restored**. The hint dropped priority permanently. The
async-interrupt boost the UM describes is internal and "does not affect the actual architected
thread priority value."

The fix is the hint plus an **explicit restore**: `or 31,31,31` (very low) or `or 1,1,1` (low),
followed by `or 2,2,2` (medium/normal) at the end of the spin block. Problem-state-legal nop forms
per UM Table 5-4: `or 31,31,31`, `or 1,1,1`, `or 6,6,6`, `or 2,2,2`. (`or 5,5,5` requires PSPB≠0;
`or 3,3,3` and `or 7,7,7` are privileged.)

This is a POWER8-and-POWER9 fix — the PPR behaviour is not new in v3.0.

---

## Tier 2 — POWER9-gated wins

Gate all of these behind `getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_3_00` so the POWER8 box remains
a valid regression baseline.

**Prerequisite:** there is currently **no host feature detection for PPC at all**
(`Source/Common/HostFeatures.cpp:787-788` leaves ARM defaults; no `AT_HWCAP` / `AT_HWCAP2` read, no
`/proc/cpuinfo` model parse). POWER8 and POWER9 are indistinguishable at runtime today. Adding that
probe is the natural first commit on this branch, since everything below keys off it.

### 2.1 `lxvx` / `stxvx` — 7 instructions to 1

The single largest codegen win in the port. Every 128-bit vector load and store currently performs a
red-zone bounce (`PPC64Emitter.cpp:285-318`, `LoadUnalignedV128` / `StoreUnalignedV128`): two `ld`s,
two `std`s to a stack slot, then `lvx`. Sub-16-byte FPR loads run ~9 instructions
(`LoadFPRSized`, `:365-401`). This guarantees a store-forwarding stall on *every SSE memory
operation*. The ARM64 backend emits one `ldr q`.

**Why the bounce exists:** `lvx` masks the effective address to a 16-byte boundary
(ISA Book I §6.7.1 p.241: `VRT ← MEM(EA & 0xFFFF_FFFF_FFFF_FFF0, 16)`) and therefore silently loads
the *wrong* quadword for an unaligned address, with no fault.

**Verified equivalence.** The `ld/ld → std/std` pair is a byte-exact 16-byte copy, so
`slot[i] = m[i]`; `lvx` on the aligned slot then yields VRT byte `15−i = m[i]`. A single `lxvx` on
the original, arbitrary, possibly-unaligned address yields byte `15−i = m[i]` — **bit-for-bit
identical**. Confirmed against the worked example on ISA p.497.

Consequences:

- `lxvx` / `stxvx` (**v3.0**) replace the bounce directly, for any EA.
- `lxv` / `stxv` (**v3.0**, DQ-form) work where a **multiple-of-16 displacement** fits (±32 KiB);
  the EA itself may still be unaligned. Useful for context/stack slots, killing the
  `LoadImm32`+`lvx` pairs in register save/restore (`PPC64Emitter.cpp:273-274`).
- `lxvd2x` (v2.06, POWER8) yields the **doubleword-swapped** image and needs an `xxpermdi` fixup —
  this is the classic POWER8 pattern, and is the fallback if a P8 path is ever wanted.
- `lxvb16x` yields the fully byte-reversed image. `lxvw4x` / `lxvh8x` yield per-element images.
  None of these three match without a fixup.

**Blocking prerequisite:** two comments in the tree describe contradictory byte models —
`VectorOps.cpp:3145` (`VInsGPR`) states `phys[i] = mem[ea+15-i]`, while `VectorOps.cpp:212`
(`LoadNamedVectorConstant`) states byte 0 maps to physical byte 0. The code works, so one comment is
simply wrong. Resolve and correct the comments *before* touching the load path.

### 2.2 Delete the shift-left-32 duplication for 32-bit flags

The backend currently emulates x86 32-bit carry/overflow by shifting **both operands left by 32 and
redoing the operation** so that CA/OV land at the 32-bit boundary
(`ALUOps.cpp:1509-1546`, `:1600-1609`, `:1627-1671`).

ISA 3.0 makes this unnecessary. Book I §3.3.9:

> "addic, addic., subfic, addc, subfc, adde, subfe, addme, subfme, addze, and subfze always set CA
> … **These instructions also always set CA32 to reflect the carry out of bit 32.**"

and §3.2.2 (XER): OV32 "is set whenever OV is implicitly set", with "OV32 reflects overflow of the
low-order 32-bit result independent of the mode".

Carry out of bit 32 (BE numbering) depends only on the low 32 bits plus carry-in, so garbage in the
upper halves is harmless. **Sound for ADD, SUB, ADC and SBB at 32-bit width.**

Extraction is via `mcrxrx` (**v3.0**), which copies `OV, OV32, CA, CA32` into a CR field in that
exact order → `(LT, GT, EQ, SO)`. UM Table A-1: plain ALU op, CR destination, latency 2, not
cracked — cheaper than `mfspr XER` (cracked C2, latency 3). This replaces `ProjectXERToCR1()`
(`JIT.cpp:1303-1307`) on every carry/overflow-involving `Jcc`, `SETcc` and `CMOVcc`.

Given 27 `mfspr` and 21 `mtspr` sites in `ALUOps.cpp` alone, this is the largest scalar win.

### 2.3 Three-instruction icache flush

POWER9 UM §4.6.2.2:

> "instead of requiring the instruction sequence specified by the Power ISA to be executed on a
> **per cache-line basis**, software must only execute a **single sequence of three instructions**:
> `sync`, `icbi` (to any address), `isync`."

(`icbi` is converted to a NOP after translation on POWER9.)

FEX currently loops over the range stepping **32 bytes**, with a full `sync` + `isync` *inside* each
iteration (`PPC64Dispatcher.cpp:643-645`). That is architecturally safe but pathological: the stride
is 4× redundant even on POWER8 (128 B cache blocks), and the interior barriers are unnecessary. ISA
Book II §1.8 gives the correct general form — all `dcbst`, one `sync`, all `icbi`, one `isync`.

This lands directly on the Mono path: every translation flush pays it.

### 2.4 Remaining ISA 3.0 codegen items

| Instruction | Replaces | Current cost | Notes |
|---|---|---|---|
| `modsd` / `modud` | `divd` + `mulld` + `subf` for DIV/IDIV remainder | 3 insns, serially dependent | Runs in parallel with the divide. 12–24 cyc (UM Table A-1). **Word forms leave `RT[0:31]` undefined**; use doubleword forms |
| `cnttzd` / `cnttzw` | `neg;and;cntlz;li;subf` (BSF) | 5 insns | `cnttzw` returns **32** on zero input, matching the TZCNT contract exactly; `cnttzd` returns 64 |
| `setb` | `li 0; bc; li 1` (SETcc) | 3 insns + branch | Examines **only LT and GT** of the CR field, yields −1/0/1. 1 insn if the condition sits in GT; 2 if in LT (`setb`+`neg`); EQ/SO need a `crmove` fixup first |
| `darn` | full spill / C-call / fill PRNG helper | ~30 insns | L=0 32-bit, L=1 64-bit conditioned, L=2 raw. `0xFFFF_FFFF_FFFF_FFFF` = error; ISA says retry, "ten attempts should be adequate", then fall back to software |
| `addex` | ADCX/ADOX dual carry chains | currently suppressed in CPUID | Uses **OV** as an independent carry chain, never touches CA, and never pollutes SO. **v3.0B**, not v3.0 base — but UM Table A-1 confirms POWER9 implements it |
| `extswsli` | `extsw` + `sldi` | 2 insns | SH range 0–63, no CA side effect |
| `mtvsrdd` / `mfvsrld` | 6-insn stack bounce for dword splat; `vsldoi`+`mfvsrd` for extract | 6 / 2 insns | `mtvsrdd v,rs,rs` = 1-insn dword splat. **`RA=0` means literal zero** — cannot splat from r0. `mfvsrld` reads `dword[1]` = guest low qword |
| `xxbrq` / `xxbrd` / `xxbrw` / `xxbrh` | vperm-based byte reversal with materialised control | ~14 insns | Endian-agnostic register-to-register |
| `vpermr` | `vperm` + XOR-0x0F index fixup in PSHUFB | 6 insns | Uses byte element `31-index`, performing the LE index flip inherently. Note: high-bit-set⇒zero is **not** provided; the zeroing select is still needed |
| `xxspltib` | multi-insn immediate splat | varies | Full 8-bit immediate 0–255, vs `vspltisb`'s ±16 |
| `xxinsertw` / `xxextractuw`, `vinsertb/h/w/d`, `vextu[bhw][lr]x` | 13–17 insn stack-materialised perm control for PINSR/PEXTR/INSERTPS | 13–17 insns | **Two footguns — see [Traps and invariants](#traps-and-invariants)** |
| `xscvhpdp` / `xscvdphp` / `xvcvhpsp` / `xvcvsphp` | F16C via FABI helper | 30+ insns | Not drop-in: sparse hword-1,3,5,7 layout needs pack/unpack; VCVTPS2PH's imm8 static rounding must be emulated via FPSCR.RN |
| `cmprb` / `cmpeqb` | byte-range / byte-equal tests | — | Result lands in GT (setb-friendly). **Undefined in 32-bit mode** |
| `addpcis` | PC-relative address materialisation | `LoadImm64` up to 5 insns | `lnia Rx` is an **extended mnemonic** for `addpcis Rx,0`. Deferred: `RELOC_NAMED_THUNK_MOVE` patching assumes the 5-insn shape (`JIT.cpp:1231-1245`) |

---

## Negative results — do not budget for these

Confirmed against the ISA. Recording these explicitly so they are not re-investigated later.

1. **ISA 3.0 does not relax alignment for any atomic.** All `larx`/`stcx.` forms require natural
   alignment (Book II §4.6.2); the AMOs additionally require the accessed portion of `mem(EA-4,12)`
   to lie within an aligned 32-byte block, and invoke the alignment error handler otherwise
   (§4.5.1 p.862, §4.5.2 p.864). **The entire split-lock / SIGBUS apparatus must survive onto
   POWER9 intact.**

2. **There is no compare-and-swap-EQUAL atomic memory operation.** The FC table provides only
   *Compare and Swap Not Equal* (FC 10000). x86 `CMPXCHG` cannot lower to a single AMO; `larx`/`stcx.`
   remains required. (Full FC table in [Instruction availability tables](#instruction-availability-tables).)

3. **AMOs are word/doubleword only** — no byte or halfword forms exist. 8- and 16-bit x86 `LOCK` ops
   stay on `lbarx`/`lharx` loops.

4. **AMOs carry no acquire/release semantics** (§4.5 intro p.859) — the surrounding `hwsync`/`isync`
   brackets must remain, which substantially shrinks the AMO opportunity. Whether AMOs beat an
   L1-hit `larx`/`stcx.` loop when *uncontended* is unmeasured; they execute near the coherence
   point, so they may well be slower. Benchmark before adopting.

5. **`wait` is unusable as a PAUSE lowering.** WC=0b00 resumes only on "an exception, an event-based
   branch exception, or a platform notify" (Book II §4.6.4 p.878). No memory-change wake, no
   timeout — a thread could stall until the next timer tick. It *is* problem-state legal, which is
   the tempting part. Use the PPR nop idiom instead (Tier 1 item 10).

6. **`copy` / `paste.` are not a general memcpy primitive.** "if the `paste.` specifies normal
   storage, the data storage error handler is invoked" (Book II §4.4 p.857). They address
   accelerators via VAS, require 128-byte alignment, and are irrelevant to `REP MOVS`.

7. **No CA-free arithmetic right shift exists in ISA 3.0.** `sraw`/`srawi`/`srad`/`sradi` all alter
   CA and CA32; §3.3.14 confirms algebraic right shifts are the sole shift exception. The only new
   3.0 shift is `extswsli`, a *left* shift. The up-to-10-instruction SAR emulation
   (`ALUOps.cpp:834-912`) stands. Mitigation is limited to cheaper CA *reads* via `mcrxrx`; restoring
   still requires `mtxer`.

8. **"POWER8 trapped on unaligned accesses, POWER9 does not" is unsupported** by either document.
   The UM states most unaligned accesses execute in hardware (§4.1.5), but contains no POWER8
   comparison, and POWER8 also handled most unaligned accesses in hardware. Only the enumerated
   cases trap on POWER9: natural-alignment violations on `larx`/`stcx.`/AMOs, quadword ops
   (`lq`/`stq`/`lqarx`/`stqcx.`), `copy`/`paste.` (128 B), LE-mode `lmw`/`stmw`/string ops, and any
   unaligned access to caching-inhibited storage.

9. **`lqarx` / `stqcx.` are ISA 2.07**, already in use for `CMPXCHG16B` (`AtomicOps.cpp:809`, `:822`).
   No POWER9 delta.

10. **The 128 TB address-space figure is Linux mm policy, not architecture.** Book III §6.7.10
    requires support for Radix configurations mapping **52-bit effective addresses** (4 PB). The
    128 TB default `TASK_SIZE` is a kernel choice, extensible via mmap hint.

11. **Timebase is 512 MHz on both POWER8 and POWER9** — the `rdtsc` scaling in `a331160bb` carries
    over unchanged.

Additionally, from the archaeology pass: every cross-arch thunk/callback item, the libxshmfence heap
corruption, the Steam TLS/vfork/UAF cluster, the SIGABRT on exit, the 31 skipped tests
(`cb3851cb4`, a cross-sysroot toolchain gap) and the 6 SSSE3 PSIGN diffs are **architecture-neutral**.
POWER9 changes none of them.

---

## Traps and invariants

Things that will silently break a POWER9 rewrite.

### Latent SIGILL: `vabsdub` / `vabsduh` / `vabsduw`

These are **v3.0-only** (ISA pp.296-297) but are **already encoded in `CodeEmitter/PPC64LE/Emitter.h`**
and never emitted. Any future code path that starts emitting them will take an
illegal-instruction interrupt on POWER8. Gate before use.

### `xsmincdp` / `xsmaxcdp` are not drop-in replacements for MINSD/MAXSD

Value semantics match exactly — every QNaN/SNaN row and every signed-zero cross-cell yields
`T(src2)`, and the raw src2 doubleword is forwarded so NaN payloads pass through unquieted
(ISA p.592, Table 76 p.593). But:

- **Exception behaviour differs.** `xsmincdp` raises VXSNAN only for **SNaN** inputs. x86 signals
  #IA for SNaN *and* QNaN sources. Guest `MXCSR.IE` emulation will under-report. (Under-reporting
  is the safer direction, but it is a divergence.)
- **`dword[1]` is zeroed**; `MINSD` preserves the upper destination bits. A merge is still required.
- **`FPSCR.VE` must be 0**, or a trap-enabled invalid operation suppresses the write entirely
  ("If a trap-enabled Invalid Operation occurs, VSR[XT] is not modified").
- **`xsminjdp` / `xsmaxjdp` use the opposite NaN convention** ("If src1 is a NaN, result is src1")
  and do **not** match x86. Easy to grab the wrong one.

### Two independent footguns in the insert/extract family

1. **`UIM` is always the big-endian byte-element number.** There is no little-endian
   reinterpretation. Under the `lxvx` register image, guest word *w* (w=0 = lowest) occupies byte
   elements `12−4w .. 15−4w`, so **`UIM = 12−4w`**. ISA: "If the value of UIM is greater than 12,
   the results are undefined."
2. **The implicit data lane is not element 0.** `xxinsertw`/`xxextractuw` use word element **1**
   (bits 32:63). `vinsertb`/`h`/`w`/`d` use byte element 7 / halfword element 3 / word element 1 /
   dword element 0 respectively.

Also: `vextubrx` (right-indexed, "byte element 15-index") is the guest-index-friendly form;
`vextublx` is not.

### Codegen shape dependencies

- `RELOC_NAMED_THUNK_MOVE` patching assumes `LoadConstant`'s exact **5-instruction** form
  (`JIT.cpp:1231-1245`). Any shortening breaks relocation.
- Explicit CR0/XER preservation contracts are documented at `ALUOps.cpp:2552-2554` and
  `BranchOps.cpp:121-129`. Any instruction substitution with an `Rc` or CA side effect can violate
  them silently.
- CR0 is the canonical spilled-NZCV; comparisons deliberately target CR7 (`BranchOps.cpp:90-141`)
  and CR2 for FPR loads (`MemoryOps.cpp:676-683`). Do not repurpose those fields.
- `r0` is an invariant zero for `ldx`/`stdx` indexing, re-established after every C call
  (`BranchOps.cpp:277-280`, `ALUOps.cpp:2973`), and must never be used as a discard destination.
- Guest RSP is pinned to **r11**, the ELFv2 static-chain / small-TOC register — the root cause of
  the callback trouble that `62ea24ce4` routed around via TLS. Do not assume r11 survives a PLT stub.
- `mfcr` writes r4 = TMP2 = the incoming RIP argument in `PushCalleeSavedRegisters`; this was the
  `State.rip=0xC0` keystone bug (`b21ee0205`). The stash-via-r0/r7 workaround must be preserved.

### `mfocrf` zeroing caveat

ISA 3.0C changed `mfocrf` so non-selected bits are zeroed, but **pre-3.0C processors, including
POWER8 and POWER9, leave them undefined or only partially zeroed**. Do not rely on the zeroing.

---

## Hardware probe checklist

Run on the POWER9 box before writing any code. The first command is also worth running on the
**POWER8** box — it is the single experiment that confirms or kills the Tier 0 theory.

```bash
# ---- THE decisive one. Run on BOTH boxes. 65536 on the P8 box confirms Tier 0. ----
getconf PAGESIZE                                  # POWER9 must print 4096

# ---- CPU / MMU identification ----
grep -E 'cpu|MMU|platform|revision' /proc/cpuinfo  # expect POWER9, MMU: Radix
dmesg | grep -i -E 'radix|hash-mmu'                # confirm radix at boot

# ---- auxv: feature bits and cache geometry ----
LD_SHOW_AUXV=1 /bin/true | grep -E 'HWCAP|DCACHEBSIZE|ICACHEBSIZE'
#   AT_HWCAP2 must contain arch_3_00
#   AT_DCACHEBSIZE expected 128  (HostFeatures currently falls back to 64 — wrong)
python3 -c "import ctypes; l=ctypes.CDLL(None); print(hex(l.getauxval(26)))"
#   AT_HWCAP2 = 26; PPC_FEATURE2_ARCH_3_00 = 0x00800000
#   (Confirm the constant against arch/powerpc/include/uapi/asm/cputable.h — it is a Linux
#    ABI value, defined in neither the ISA nor the UM.)

# ---- address space / mm policy ----
cat /proc/sys/vm/mmap_min_addr                     # 32-bit guest low-VA mapping
cat /sys/kernel/mm/transparent_hugepage/enabled    # THP vs SMC mprotect churn
grep MemTotal /proc/meminfo; ulimit -v

# ---- empirical: 4K-but-not-64K-aligned fixed mapping must succeed ----
cat > /tmp/pgtest.c <<'EOF'
#include <sys/mman.h>
#include <stdio.h>
int main(void) {
  void *p = mmap((void*)0x10001000, 4096, PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
  printf("mmap -> %p\n", p);
  if (p != MAP_FAILED) {
    printf("mprotect -> %d\n", mprotect(p, 4096, PROT_READ));
  }
  return 0;
}
EOF
gcc -O0 -o /tmp/pgtest /tmp/pgtest.c && /tmp/pgtest
```

Also worth capturing once the branch is live: the `g_SplitLockDetectedCount` telemetry counter
(`FEXCore/Source/Utils/ArchHelpers/PPC64.cpp:64`) and `AccumulatedSIGBUSCount` under a real workload,
to size the actual split-lock exposure before optimising that path.

---

## Mono debug plan

Ordered. Stop as soon as a step gives a clear answer.

1. **`getconf PAGESIZE` on the POWER8 box.** `65536` → Tier 0 trigger confirmed immediately.
   Ensure the POWER9 kernel is Radix 4 K before comparing anything.
2. **Rebuild with `-DCMAKE_BUILD_TYPE=Debug`** (or otherwise define `ASSERTIONS_ENABLED=1`) so
   `LogMan::Throw::AFmt` actually fires. Any failing SMC `mprotect` becomes loud instantly.
3. **Run Ziggurat / Stardew with `FEX_SMCCHECKS=full`.** Spin disappears (at heavy slowdown) →
   stale translations confirmed. Spin persists → Tier 0 is dead for this symptom; pivot to step 6.
4. **Watch `AccumulatedSMCCount` / `AccumulatedSIGBUSCount`** while Mono JITs. Mono active with SMC
   count pinned at zero means invalidation is never firing.
5. **`FEX_LOG_UNEXPECTED_FUTEX=1`** (from `c031b7657`) — note that as shipped it deliberately
   **ignores `EAGAIN`**, so it is blind to this exact symptom. A ~2-line patch to log `EAGAIN` with
   `uaddr` and `val` makes it useful: an identical stale `val` every iteration indicates stale code;
   a moving `val` indicates a livelock elsewhere. Also enable the `cf17977e8` stale-compile byte log.
6. **If step 3 failed:** investigate the guest-signal absorber stubs. `PPC64Dispatcher.cpp:488-522`
   spills and `blr`s for SIGILL/SIGTRAP/SIGSEGV without delivering to the guest — the comments admit
   this is temporary. Genuine hardware faults *do* reach guest handlers via
   `SignalDelegator.cpp:1224-1230` → `HandleGuestSignal`, so Mono's null-check and GC-poll diet is
   served; but guest `ud2` / `int3` / `int imm8` / `into` / `hlt` are swallowed. Mono embeds
   `ud2`-class traps as unreachable markers and for some runtime checks.
7. **`strace -f -e trace=futex,mprotect,mmap`**, diffed against a working title — look for missing
   `PROT_READ` re-arms after Mono's `mmap(PROT_EXEC)` and code writes.
8. **`gdb` the spinning thread**, dump the translation at PC against the current guest bytes
   (`FEX_X86DISASSEMBLE`). A mismatch is the smoking gun regardless of which path leaked it.

### Minimal reproducer

Does not require Unity or Mono. A ~50-line **static x86-64** binary:

- Thread A: `mmap` RWX; emit a small stub; execute it; **patch the stub in place**; execute again and
  assert the new behaviour is observed.
- Thread B: `FUTEX_WAIT` on a word that only the *patched* stub updates.

Under broken mtrack this spins on `EAGAIN` exactly as the games do, in a few hundred lines of total
system state rather than a whole game engine.

---

## Instruction availability tables

Gate = `PPC_FEATURE2_ARCH_3_00` unless marked POWER8-legal.

### Vector / VSX

| POWER8-legal (≤ v2.07) | POWER9-only (v3.0) |
|---|---|
| `lvx`/`stvx` (2.03), `vperm` (2.03), `vsldoi` (2.03) | `lxvx`, `stxvx`, `lxv`, `stxv`, `lxvb16x`, `stxvb16x`, `lxvh8x`, `stxvh8x`, `lxvl`, `lxvll`, `stxvl`, `stxvll` |
| `lxvd2x`, `stxvd2x`, `lxvw4x`, `stxvw4x` (2.06) | `mtvsrdd`, `mfvsrld`, `mtvsrws` |
| `mtvsrd`, `mfvsrd`, `mfvsrwz`, `mtvsrwa`, `mtvsrwz` (2.07) | `xxbrq`, `xxbrd`, `xxbrw`, `xxbrh` |
| `xvcvspdp`, `xvcvdpsp` (2.06) | `xxinsertw`, `xxextractuw`, `vinsertb/h/w/d`, `vextublx/brx`, `vextuhlx/hrx`, `vextuwlx/wrx` |
| `vcipher`, `vcipherlast`, `vncipher`, `vncipherlast` (2.07) | `xsmincdp`, `xsmaxcdp`, `xsminjdp`, `xsmaxjdp` |
| `vpmsumd`, `vpmsumw`, `vshasigmaw`, `vshasigmad` (2.07) | `vpermr`, `xxspltib`, `vabsdub/h/w` |
| `vbpermq` (2.07) | `xscvhpdp`, `xscvdphp`, `xvcvhpsp`, `xvcvsphp`, `vbpermd`, `vslv`, `vsrv` |

### Scalar

| POWER8-legal | POWER9-only (v3.0) |
|---|---|
| `isel` (**2.03**) | `mcrxrx`, CA32/OV32 semantics |
| `mfocrf`, `mtocrf` (2.01) | `modsw`, `moduw`, `modsd`, `modud` |
| `sraw`, `srad`, `srawi`, `sradi`, `addic`, `subfic` (P1) | `cnttzw`, `cnttzd`, `setb`, `darn` |
| `lqarx`, `stqcx.`, `lq`, `stq` (2.07, problem-state since 2.07) | `extswsli`, `addpcis`/`lnia`, `cmprb`, `cmpeqb` |
| | `addex` (**v3.0B**, not v3.0 base; UM Table A-1 confirms POWER9 implements it) |

### Atomic Memory Operation function codes (ISA Book II §4.5, Fig. 3–4)

`lwat`/`ldat` (s = 4 or 8):

| FC | Operation |
|---|---|
| 00000 | Fetch and Add |
| 00001 | Fetch and XOR |
| 00010 | Fetch and OR |
| 00011 | Fetch and AND |
| 00100 / 00101 | Fetch and Maximum Unsigned / Signed |
| 00110 / 00111 | Fetch and Minimum Unsigned / Signed |
| 01000 | Swap |
| 10000 | **Compare and Swap Not Equal** |
| 11000 / 11001 | Fetch and Increment Bounded / Equal |
| 11100 | Fetch and Decrement Bounded |

`stwat`/`stdat`: 00000 Store Add, 00001 Store XOR, 00010 Store OR, 00011 Store AND,
00100/00101 Store Max Unsigned/Signed, 00110/00111 Store Min Unsigned/Signed, 11000 Store Twin.

"Function codes not listed in this table are considered invalid" — an invalid FC invokes the system
data storage error handler (DSISR bit 61).

**Note the absence of a compare-and-swap-EQUAL.**

### Other confirmed constants

- Reservation granule: **128 bytes**; coherence block: **128 bytes** (UM §4.6.1, §4.6.2.12).
  "There is at most one reservation per thread."
- POWER9 Radix supported page sizes: **4 KB, 64 KB, 2 MB, 1 GB** — and only those
  (UM §4.10.4.1 Table 4-17).
- DSISR store-vs-load discrimination: ISA bit 38 = mask **0x02000000**. FEX's mask is **correct**
  (`MContext_ppc64le.h:189-197`). Nuance: also set for `dcbz` and for Load Atomic.
- `EH` on load-and-reserve is a **hint only**, no semantic effect. ISA programming note: EH=1 for
  lock acquisition, EH=0 for fetch-and-op emulation. Every current call site passes `eh=0`
  (`Emitter.h:1311-1314`, `:1325`).
- Aligned quadword `lq`/`stq`/`lqarx`/`stqcx.` are guaranteed single-copy atomic (Book II §1.4
  p.817) and problem-state legal ("In versions of the architecture prior to V. 2.07, this
  instruction was privileged").

---

## Open questions needing hardware

1. **Does the POWER8 box run a 64 KB kernel?** Decides whether Tier 0 is a real historical
   root-cause or a non-event. One command.
2. **AMO latency/throughput vs `larx`/`stcx.` loops**, uncontended and contended. AMOs execute near
   the coherence point and may lose to an L1-hit reservation loop when uncontended. Neither document
   gives figures.
3. **Unaligned `lxvx` penalty boundaries** (64 B / 128 B / page crossings). The UM gives throughput
   ("one unaligned 8-byte load and one unaligned 8-byte store per cycle per LS-slice pair",
   §25.1.7.9) but not crossing penalties. Measure before removing any alignment fast path.
4. **Does `xsmincdp` on real silicon forward SNaN payloads raw?** The pseudocode says raw
   (`result ← VSR[XB].dword[0]`), but the prose table contains a known typo mislabelling src2's
   source register. One test vector settles it.
5. **NaN payload width / denormal (DAZ-like) behaviour of `xscvdphp` / `xvcvsphp`** vs x86 F16C.
6. **Whether ISA 2.07B's `lq`/`stq` LE wording** matches the "restriction lifted in 3.0C" narrative.
   2.07B was not among the consulted sources; the delta is inferred from its absence in 3.0C plus
   3.0C's explicit LE definition (Book I §3.3.4 p.56).
7. **`PPC_FEATURE2_ARCH_3_00`'s value** — a Linux HWCAP2 ABI constant, defined in neither document.
   Confirm against `arch/powerpc/include/uapi/asm/cputable.h`.

---

## Sources and method

Primary sources, in `docs/` (git-ignored; ~16 MB, not committed):

- `PowerISA_public.v3.0C.pdf` — Power ISA Version 3.0C
- `POWER9_um_OpenPOWER_v20GA_09APR2018_pub.pdf` — POWER9 Processor User's Manual, OpenPOWER v2.0 GA

Method: nine agent passes. Five subsystem audits of the existing port (atomics/memory model,
VSX/SIMD, scalar ALU/flags, runtime/dispatcher/MMU, and commit archaeology), one targeted
investigation of the Mono failure class, and three adjudication passes that re-checked every
ISA-level claim from the audits against the documents above, marking each CONFIRMED / REFUTED /
NUANCED / NOT-IN-DOCS with a citation.

Claims corrected during adjudication — recorded here because the original versions are plausible
and may otherwise be rediscovered:

- `isel` is **v2.03**, not v2.06 (conclusion unchanged, but it has been available even longer).
- `vbpermq` is **v2.07**, not a POWER9 feature — the `PMOVMSKB` win needs no branch gate.
- `addex` is **v3.0B**, not v3.0 base.
- `setb` examines **only LT and GT**, not any CR bit — it is not a general condition materialiser.
- `modsw`/`moduw` leave `RT[0:31]` **undefined**; modulo and divide never trap on divide-by-zero or
  signed overflow, they produce undefined results (x86 #DE checks must remain explicit).
- `mfspr XER` on POWER9 is cracked but *cheap* (latency 3), not a hard serialisation — `mcrxrx`
  still wins at latency 2, uncracked.
- Reservation granule is **128 B**, not the 64 B the split-lock striping assumes.
- The icache flush situation is *better* than first assessed: POWER9 needs one three-instruction
  sequence for any range, not a per-line loop.
- The "POWER8 took alignment interrupts where POWER9 does not" premise is **unsupported**.
- The 128 TB VA figure is **Linux policy**, not an architectural limit (hardware: 52-bit EA, 4 PB).

### Provenance warning

The port's history is a squashed snapshot (`e1f83d4c4`, "bank port state as of 2026-05-11 (POWER8
snapshot)", 63 files, +24 304 lines) on top of upstream FEX at `098c4c57b`, plus ~151 follow-up
commits from a single 8-day sprint (11–19 May 2026). The commit messages are unusually detailed and
are the **primary surviving design documentation**.

Several commit bodies reference the original author's private analysis notes —
`project_stardew_main_thread_spin`, `project_vfork_clone_vm.md`,
`project_steam_manifest_tls_handshake.md`, `project_ftl_grimrock_renderpath` — **none of which are
in this repository**. `d91959d2f` also references a WIP `stash@{0}` that no longer exists. Assume
that analysis is lost.

Note also that `README.md` line 25 still advertises `c8dab0af3` (dladdr-based host-vs-guest pointer
discrimination) as a headline win, but it was **reverted 11 minutes later** by `439f8fe4e` with no
reason recorded. The README is stale on that point.
