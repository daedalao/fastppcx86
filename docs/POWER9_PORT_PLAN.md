# FEX-PPC64LE — POWER9 Port Plan

Status: **planning document, no code changes yet.** Branch `power9-support`, forked from `main` at `0f17626ac`.

Revision 2. Every claim in revision 1 was put through an adversarial review pass whose reviewers
were instructed to refute rather than confirm. **One headline finding was destroyed, two rankings
were materially corrected, and three "negative results" were overturned in our favour.** Revision 1's
errors are recorded in [Refuted and corrected](#refuted-and-corrected) rather than quietly deleted,
so they are not rediscovered and re-believed later.

Headline conclusions, post-review:

> **POWER9 does not clear the port's blocker table.** Cross-arch callback dispatch, libxshmfence,
> Steam and the SIGABRT on exit are ELFv2/ABI and plumbing problems, byte-identical on POWER9. This
> verdict survived a dedicated attempt to overturn it.
>
> **The Mono theory of revision 1 was wrong.** A 64 KB host page size cannot be the cause, because
> FEX cannot run *any* dynamically-linked guest on a 64 KB host at all. See
> [Tier 0](#tier-0--smc-hardening-theory-refuted).
>
> **The largest wins are POWER8-legal and available today**, on the existing hardware, ungated. Two
> of them were missed entirely in revision 1 and were found only by the adversarial pass: the
> `lqarx` containment transform for misaligned atomics, and a two-instruction CA save/restore that
> replaces XER SPR traffic.

---

## Contents

- [Tier 0 — SMC hardening (theory refuted)](#tier-0--smc-hardening-theory-refuted)
- [Tier 1 — POWER8-legal, available today](#tier-1--power8-legal-available-today)
- [Tier 2 — POWER9-gated wins](#tier-2--power9-gated-wins)
- [The graphics path (architecture-neutral)](#the-graphics-path-architecture-neutral)
- [Bugs found in the current backend](#bugs-found-in-the-current-backend)
- [Negative results](#negative-results)
- [Additional opportunities](#additional-opportunities)
- [Traps and invariants](#traps-and-invariants)
- [Refuted and corrected](#refuted-and-corrected)
- [Hardware probe checklist](#hardware-probe-checklist)
- [Mono / spin debug plan](#mono--spin-debug-plan)
- [Instruction availability tables](#instruction-availability-tables)
- [Open questions needing hardware](#open-questions-needing-hardware)
- [Sources and method](#sources-and-method)

---

## Tier 0 — SMC hardening (theory refuted)

### What revision 1 claimed, and why it is wrong

Revision 1 argued that FEX's self-modifying-code tracking `mprotect`s at 4 KB granularity
(`SyscallsSMCTracking.cpp:174-182`, `FEX_PAGE_SIZE = 4096`), discards the return value
(`LogMan::Throw::AFmt` is an empty function unless `ASSERTIONS_ENABLED`, which is `DEBUG`-only per
`CMakeLists.txt:186-192`), and therefore fails silently on a 64 KB-page host — leaving Mono's
backpatched code running stale translations forever.

**The mechanism is internally coherent but unreachable.** FEX reports `AT_PAGESZ = FEX_PAGE_SIZE =
4096` to the guest unconditionally (`Source/Tools/FEXInterpreter/ELFCodeLoader.h:636`), and guest
`mmap`/`mprotect` are passed verbatim to the host kernel, returning `-errno`
(`SyscallsSMCTracking.cpp:303`, `:425`). On a 64 KB-page host, guest `ld.so` would fail its
`PT_GNU_RELRO` `mprotect` at a 4 K-aligned address; glibc treats that as fatal. **Every
dynamically-linked guest would die in the dynamic linker.** FTL runs to gameplay for minutes, so the
POWER8 host is a 4 KB kernel and these `mprotect` calls were never failing.

This matches upstream FEX's posture: 4 KB hosts are a prerequisite, not a preference (the same
reason upstream cannot run on Asahi's 16 KB kernels). FEX-on-64K is not degraded; it is non-booting.

Revision 1 also committed a logic error worth naming: it argued "coherence rules out data staleness,
therefore the cause must be code staleness." That is a false dichotomy — a stale translation still
contains a real load instruction reading current memory. A persistent `EAGAIN` means the `val`
argument the guest *computed* mismatches memory at syscall time, every iteration, which points at
codegen or memory ordering, not at executing old code.

### What is still worth doing

These are defensive-engineering items, not a fix for any known failure. On the current host the
assert will succeed trivially.

1. Startup assertion that `sysconf(_SC_PAGESIZE) == FEX_PAGE_SIZE`, failing loudly with a clear
   message. Converts an unreachable-but-catastrophic configuration into a diagnosable one.
2. Check the three SMC `mprotect` return values in release builds
   (`SyscallsSMCTracking.cpp:79`, `:174`, `:180`). A silently-ignored `mprotect` is a bad failure
   mode on any host.
3. **Optional, arch-neutral, and not required here:** round SMC `mprotect` ranges to
   `sysconf(_SC_PAGESIZE)` rather than to `FEX_PAGE_SIZE`, making the tracker correct on a 64 KB
   host at the cost of false-positive retranslations.

   A 4 KB Radix kernel is non-default on most mainstream ppc64le distributions, so this would
   normally be a real decision. **It is not one for this project: the target POWER9 box already runs
   a 4 KB kernel**, required by the GPU drivers (`amdgpu`'s TTM/GTT paths do not cope with 64 KB
   pages, which is why 4 K is standard on Talos II / Blackbird graphics setups). FEX's implicit
   4 KB-host prerequisite is therefore satisfied by a constraint that already exists for unrelated
   reasons — and the same is very likely true of the original POWER8 machine, which independently
   corroborates the refutation above. Item 3 is worth doing only as upstream-friendliness, not for
   this deployment.

### Rival explanations for the Mono/Stardew spins, ranked

1. **Memory-ordering or width bug in the emulated wait loop** (glibc condvar `__wseq`/`g_signals`,
   or Mono's coop-suspend). The port has documented history in exactly this class — upstream needed
   acquire/release forcing on plain MOVs for these workloads. PPC64LE's weak ordering plus
   incomplete TSO emulation can sustain a `val`/memory mismatch indefinitely.
2. **SMC re-arming gap, page-size independent.** `MarkGuestExecutableRange` runs only when a page
   *newly* contains code (`Core.cpp:934-936`). After a write fault unprotects a page
   (`SyscallsSMCTracking.cpp:79`), whether it is ever re-protected depends on LookupCache
   bookkeeping. Worth auditing; POWER9 does not affect it.
3. **Thunk/cross-arch pointer corruption** clobbering the futex word, given the port's admitted live
   bugs there (libxshmfence heap corruption; revert `439f8fe4e`).

---

## Tier 1 — POWER8-legal, available today

None of these need POWER9. **Land them on `main`, against the existing POWER8 box**, before anything
becomes POWER9-conditional: they establish a working test loop against the 11213-case ASM
differential suite. Ordered by value.

### 1.1 `lqarx`/`stqcx.` containment for misaligned atomics — **the biggest miss of revision 1**

Revision 1 recorded "ISA 3.0 relaxes no alignment requirement for atomics, so the split-lock
apparatus must survive intact" and treated that as a dead end. It is only half true.

Any misaligned k-byte LOCK RMW **whose bytes lie within one aligned 16-byte block** can be done
entirely in hardware:

```
EA_q = EA & ~15
lqarx  on EA_q                  # aligned by construction — no alignment interrupt
extract / modify the k bytes    # shifts + mask-insert
stqcx. the whole quadword       # retry on failure
```

Soundness:

- `lqarx`/`stqcx.` on `EA_q` is aligned by construction, so no alignment interrupt (Book II §4.6.2),
  and is single-copy atomic across all 16 bytes (Book II §1.4 p.817).
- Writing back the **unmodified neighbour bytes** is safe under reservation semantics: any
  intervening store anywhere in the 128-byte reservation granule (UM §4.6.1) kills the reservation
  and fails the `stqcx.`, so no lost update. This is precisely how RISC-V lowers sub-word AMOs onto
  `lr.w`/`sc.w`.
- The same transform applies one level down: a misaligned halfword or word contained in an aligned
  word/doubleword can use `lwarx`/`ldarx` on the container.

Coverage under uniform offsets: misaligned 2-byte **15/16**, 4-byte **9/12**, 8-byte **7/14**. Only
accesses crossing an aligned 16-byte boundary still need the mutex helper. Real packed-struct
misalignment clusters at small offsets, so practical coverage is higher.

**This is a correctness fix, not only a performance one.** `PPC64_SplitLockEmulate` is atomic only
against other mutex users — it does not compose with a concurrent *aligned* `larx` RMW touching the
same bytes from another thread (admitted at `FEXCore/include/FEXCore/Utils/ArchHelpers/PPC64.h:37-39`).
The `lqarx` container path is coherent with aligned hardware atomics through the reservation
granule. It also properly fixes the non-atomic misaligned `CMPXCHG8B` (`AtomicOps.cpp:743-755`): a
misaligned-but-contained 8-byte CAS becomes a real `lqarx`/`stqcx.` CAS with no mutex at all.

Cost: the inline alignment tests already exist, so this substitutes ~8–12 inline instructions for a
spill + C-helper call. `lqarx` on POWER9 is cracked C2, latency ~6 (UM Table A-1).

**`lqarx`/`stqcx.` are v2.07 — this is POWER8 work, ungated.**

### 1.2 Two-instruction CA save/restore

Revision 1 stated that restoring XER.CA "still requires `mtxer`". False. CA round-trips through a
GPR in two base-ISA ALU instructions, no SPR access:

```
addze  Rt, r0          # save:    Rt = CA   (r0 is the port's invariant zero)
addic  Rscratch, Rt, -1 # restore: CA = (Rt != 0)
```

For `Rt ∈ {0,1}`: `1 + 0xFFFF…F` carries (CA=1); `0 − 1` does not (CA=0). This beats both the
`mfspr`/`mtspr XER` round-trip (cracked, latency 3) and `mcrxrx` (which can read CA but never
restore it). It applies anywhere the backend brackets a CA-clobbering instruction with XER traffic —
there are 27 `mfspr` and 21 `mtspr` sites in `ALUOps.cpp` alone. **Base ISA; Tier 1.**

### 1.3 Scalar-into-VSR load family

§2.1's `lxvx` fix addresses only the 16-byte path. `LoadFPRSized` (`PPC64Emitter.cpp:365-401`) burns
~9 instructions for 1/2/4/8-byte FPR loads, and the TSO FPR load path (`MemoryOps.cpp:678`) pays it
on every guest `movsd`/`movss`. `lxsdx`/`lxsiwzx` are **v2.06/2.07** and usable now;
`lxsd`/`lxssp`/`lxsibzx`/`lxsihzx` are v3.0 and extend the coverage.

### 1.4 Remaining Tier 1 items

| # | Change | Current cost | Notes |
|---|---|---|---|
| a | `isel` for `CMOVcc` / selects | 3 insns + branch, 25 `bc` sites | **v2.03**; emitter has no encoding at all. **Not unconditionally free** — see below |
| b | Hardware AES / PCLMUL / SHA | FABI helper, ~50 insns with spill/fill | **v2.07**. Realistic cost **3–8 insns**, not 1–3 — see below |
| c | `vbpermq` + `mfvsrd` for `PMOVMSKB` | dispatcher's 16-iteration extract/shift/or chain | **v2.07**, already encoded, never emitted. **3+ insns and needs a new IR op** — see below |
| d | `xvcvspdp` / `xvcvdpsp` for CVTPS2PD/PD2PS | 9–12 insn per-lane stack loop (`VectorOps.cpp:4513-4551`) | **v2.06**, absent from emitter |
| e | `mfocrf` / `mtocrf` in hot flag paths | `mfcr` is a 3-iop crack | **v2.01**. UM §4.1.5.6 recommends the single-field variants. **See the zeroing trap below** |
| f | `VExtr` N<16 → single `vsldoi` | 13-insn stack-materialised perm control | v2.03; pure oversight |
| g | Restripe split-lock mutex table at 128 B | `addr >> 6` false-shares adjacent stripes | UM §4.6.1/§4.6.2.12: coherence block and reservation granule are both 128 B |
| h | Fix `HostFeatures.DCacheLineSize` fallback 64 → 128 | wrong on all POWER | UM Table 4-3 |

Qualifications the adversarial pass forced:

- **(a) `isel` is not unconditionally free.** UM Table A-1: latency 2 **plus 3 cycles additional
  latency for the CR source**, so `cmp → isel` is ~7 cycles on the dependent chain, while a
  correctly-predicted `bc` resolves off the critical path. With P9's ~16-cycle redirect penalty,
  break-even is roughly a 25–30% mispredict rate. `isel` wins for genuinely unpredictable selects —
  which guest `CMOVcc` usually is — and shrinks code, but lengthens the chain for predictable ones.
  Microbenchmark before converting all 25 sites. Note `isel`'s `RA=0` reads literal zero, which is
  coincidentally consistent with the port's r0-is-zero convention; assert it.
- **(b) AES is 3–8 instructions, not 1–3.** FEX's register image holds guest byte *j* at BE element
  15−*j*, i.e. the block byte-reversed. `SubBytes` commutes with reversal; `ShiftRows` and
  `MixColumns` do not, so each op needs reversal fixups (`xxbrq` on P9; `vperm` with a materialised
  constant on P8). `vncipher` adds the key **before** `InvMixColumns` where AESDEC adds it after, so
  AESDEC needs a MixColumns-transformed key (`MixColumns(k) = vcipher(vncipherlast(k,0),0)`, or
  cache per key). AESIMC has no direct instruction; AESKEYGENASSIST has no counterpart. Still a
  large win over a ~50-instruction helper call. PCLMULQDQ via `vpmsumd` needs ~3 instructions
  (`vpmsumd` is a *sum* of two 64×64 products, so the unselected doubleword must be zeroed) and
  requires no byte swap. **CRC32 is 8–12 instructions** — the Barrett reduction dominates
  per-instruction, and the classic `vpmsum` win is bulk folding, which FEX's instruction-at-a-time
  model cannot exploit.
- **(c) `vbpermq` needs plumbing.** The correct sequence is `vbpermq` with a BE-order index constant
  `{0,8,16,…,120}`, then `mfvsrd` (result lands in bits 48:63 of doubleword 0) — **3+ instructions**
  once the constant is materialised. More importantly **there is no `MoveMask` IR op**; PMOVMSKB
  reaches the backend as the dispatcher's generic 16-iteration chain
  (`OpcodeDispatcher/Vector.cpp:785-833`). This needs a new IR op or dispatcher hook, not a
  backend-local patch.
- **(e) `mfocrf` collides with its own trap.** Pre-3.0C processors — **including both POWER8 and
  POWER9** — leave non-selected bits undefined or only partially zeroed. Naive substitution in hot
  flag paths is a latent corruption bug. Cross-reference
  [Traps and invariants](#traps-and-invariants).

### 1.5 The PAUSE / PPR regression — root cause identified, **highest regression risk**

`60718954e` introduced an SMT priority hint for x86 `PAUSE`; it hung every SDL2/Vulkan game and was
backed out in `88d1c4f7b`. The POWER9 UM explains why:

> "Hardware typically does not change the thread priority value in the PPR, unless an `mtPPR` or one
> of the priority changing NOP instructions is committed."

Priority is **never automatically restored**; the hint dropped it permanently. The fix is the hint
plus an explicit restore — `or 31,31,31` (very low) or `or 1,1,1` (low), then `or 2,2,2`
(medium/normal) at the end of the spin block. Problem-state-legal forms per UM Table 5-4:
`or 31,31,31`, `or 1,1,1`, `or 6,6,6`, `or 2,2,2`. (`or 5,5,5` needs PSPB≠0; `or 3,3,3` and
`or 7,7,7` are privileged.)

**Land this behind a config flag, defaulting off.** The restore-fix is a theory built on one UM
paragraph; if the real hang mechanism was something else, reintroducing the hint regresses FTL — the
only fully working configuration the port has.

---

## Tier 2 — POWER9-gated wins

Gate behind `getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_3_00`.

**Prerequisite:** there is **no host feature detection for PPC at all** today
(`Source/Common/HostFeatures.cpp:787-788`); POWER8 and POWER9 are indistinguishable at runtime.
Adding that probe, plus `AT_DCACHEBSIZE`, is the first commit on this branch.

### 2.1 `lxvx` / `stxvx` — 7 instructions to 1

Every 128-bit vector load/store performs a red-zone bounce (`PPC64Emitter.cpp:285-318`): two `ld`s,
two `std`s to a stack slot, then `lvx`. The ARM64 backend emits one `ldr q`.

**Why the bounce exists:** `lvx` masks EA to a 16-byte boundary
(`VRT ← MEM(EA & 0xFFFF_FFFF_FFFF_FFF0, 16)`, Book I §6.7.1 p.241) and silently loads the *wrong*
quadword for an unaligned address, with no fault.

**Equivalence, independently re-derived twice.** `lxvx` in LE places `mem[EA+i]` into byte element
`15−i` — so `phys[15−i] = m[i]`, EA arbitrary. The `ld/ld → std/std` pair is a byte-exact copy
(`slot[i] = m[i]`); `lvx` on the aligned slot gives `phys[15−i] = slot[i] = m[i]`. **Identical
register images.** Confirmed against the worked example on ISA p.497. The reviewer also *proved* the
stack slot is 16-byte aligned — every `r1` adjustment in the backend is a multiple of 16
(`PPC64Emitter.cpp:183`, `:244`, `:266`; `BranchOps.cpp:219`; `AtomicOps.cpp:89`; `JIT.cpp:1055`) and
ELFv2 guarantees 16-byte SP alignment on entry — so the baseline is not itself buggy. Red-zone
signal safety is also fine: ELFv2 defines a 288-byte protected zone and Linux/ppc64 enforces 512.

**Fault reporting — measured on hardware 2026-07-28, caveat resolved.**

The concern was that DAR is only required to be "an effective address *associated with*" the access
(Book III §7.2.3), so a 16-byte `stxvx` crossing a page boundary might report `si_addr` in the
*first* page when only the second is protected. FEX's SMC handler unprotects
`AlignDown(si_addr, PAGE)` (`SyscallsSMCTracking.cpp:37`, `:76`), so an imprecise DAR would unprotect
the wrong page and refault forever.

**Measured: precise for the case tested — but the first measurement covered only one of the three
protection patterns that matter.** `build-probes/probe_dar.c` straddled a page boundary with 8 bytes
in a writable page and 8 in a `PROT_READ` page:

| Form | `si_addr` | Page |
|---|---|---|
| A. two `std` (current bounce) | `0x…9000` | protected |
| B. **`stxvx`** | `0x…9000` | **protected** |
| C. `stxv` (D-form) | `0x…9000` | protected |
| D. control, `std` inside page 2 | `0x…9000` | protected |
| E. `lxvx` (load) | `0x…9000` | protected |
| F. control, `ld` inside page 2 | `0x…9000` | protected |

Both harness controls behaved, and `stxvx` reported identically to the `std` bounce it would replace.

That case alone was necessary but not sufficient. FEX unprotects `AlignDown(si_addr, PAGE)` and
re-executes, so the handler must also behave when the *first* page is protected, and must *converge*
when both are — the retry after unprotecting the named page has to fault on the *other* page, not the
same one, or the handler livelocks. `build-probes/probe_dar2.c` covers all of it, and **all cases
pass**:

| Case | Result |
|---|---|
| B — second page protected | `si_addr` names page 2 ✓ |
| B′ — first page protected | `si_addr` names page 1 ✓ |
| B″ — both protected, first fault | names page 1 |
| B″ — retry after unprotecting page 1 | names **page 2** ✓ — converges, no livelock |
| E — `lxvx`, second page protected | page 2 ✓ |
| E′ — `lxvx`, first page protected | page 1 ✓ |
| D, F — harness controls | page 2 ✓ |

**Conclusion: `si_addr` identifies the faulting page in every protection pattern, and the
unprotect-and-retry loop converges.** Both the load and store paths can move from the
7-instruction bounce to a single `lxvx`/`stxvx` with no change to the SMC fault handler.

**Scope limit.** DAR content is an implementation property, not an architectural guarantee — Book III
§7.2.3 requires only "an effective address associated with the storage access". A clean result on
this machine does not transfer to other POWER implementations, to HPT mode, or under a hypervisor.
Any adoption should be gated on a runtime probe or a per-platform switch rather than on a
measurement taken once.

One sub-question remains open but is not blocking: Book II Ch. 2 permits a faulting load to have
partially altered registers, and real x86 leaves the destination unmodified on `#PF`. The bounce
writes the guest VR only in the final `lvx`, so it is provably clean on fault; `lxvx` may legally
partially write VRT. The probe's attempt to measure this (probe E's register dump) is **inconclusive** —
the compiler placed the destination in `vs0` and the value survived a trip through a signal handler
and `siglongjmp`, which more likely reflects a stack spill slot than the architectural register. A
sound measurement would read the VSX save area out of `ucontext` inside the handler rather than after
returning. Low priority: this is an x86-fidelity nuance, not a correctness blocker for the guest.

`lxv`/`stxv` (DQ-form) also work where a **multiple-of-16 displacement** fits (12-bit DQ, ±32 KiB);
the save/restore offsets at `PPC64Emitter.cpp:273-274` are well within range.

**Expected impact, tempered.** The mechanism is stronger than a mere stall: UM §25.1.7.6 states
forwarding "from more than one store per LS slice" cannot happen, so the load "must wait for an
overlapping store to drain from the STQ … and be written to and read from the cache hierarchy" —
a pipeline drain the bounce hits on every execution. But every TSO vector load *also* pays the
cmp/bc/isync acquire idiom (`MemoryOps.cpp:664-684`) and stores pay `lwsync`, neither of which
`lxvx` removes; and the gain scales with vector-memory-op density. **Expect 5–20% on SSE-heavy
titles, far less elsewhere.** A 7→1 instruction ratio does not translate to 7× anything.

### 2.2 `mcrxrx` for carry/overflow extraction

`ProjectXERToCR1()` (`JIT.cpp:1303-1307`) is `mfspr XER; rlwinm; mtcrf` — 3 instructions, 4 iops
(`mtcrf` is itself cracked). `mcrxrx` is 1 iop, uncracked, latency 2, no dispatch rule (UM Table
A-1), against `mfspr_xer`'s cracked C2 latency 3. Both pay the same +3 CR/XER-source forwarding
penalty, so that is a wash; the win is 3 iops and one cycle of chain.

**Silent-corruption hazard — must be handled in the same commit.** The pseudocode is
`CR[4×BF+32:35] ← OV || OV32 || CA || CA32`, i.e. LT=OV, GT=**OV32**, EQ=CA, SO=CA32. The current
CR1 layout is LT=SO, GT=**OV**, EQ=CA (`JIT.cpp:1295-1300`). CA stays in EQ by luck, but every
overflow-consuming condition in `MapNZCVCC` reads bit 5 (GT) and would silently receive **OV32
instead of OV** — wrong for every 64-bit operation. The bit indices must move 5→4 alongside the
substitution.

### 2.3 Three-instruction icache flush

UM §4.6.2.2: `icbi` is converted to a NOP after translation, and

> "instead of requiring the instruction sequence specified by the Power ISA to be executed on a
> **per cache-line basis**, software must only execute a **single sequence of three instructions**:
> `sync`, `icbi` (to any address), `isync`."

FEX loops over the range stepping **32 bytes**, with a full `sync` + `isync` *inside* each iteration
(`PPC64Dispatcher.cpp:643-645`). The stride is 4× redundant even on POWER8 (128 B blocks) and the
interior barriers are unnecessary. ISA Book II §1.8 gives the correct general form: all `dcbst`, one
`sync`, all `icbi`, one `isync`.

### 2.4 Remaining ISA 3.0 codegen items

| Instruction | Replaces | Notes |
|---|---|---|
| `modsd` / `modud` | `divd` + `mulld` + `subf` for the DIV/IDIV remainder | **Conditional win.** POWER9 has a DIV engine per superslice and the UM recommends pairing such instructions, so `divd`/`modsd` overlap **only when scheduled to different superslices**; same-superslice they serialize on an 8-cycle busy offset, giving parity. Each is dispatch-rule E (consumes both slots), so the pair costs 4 dispatch slots vs 3 iops today. Best case ~7 dependent cycles saved; worst case a wash. **Word forms leave `RT[0:31]` undefined**; use doubleword forms. Never traps — x86 `#DE` checks stay explicit |
| `cnttzd` / `cnttzw` | `neg;and;cntlz;li;subf` (BSF) | 5 insns → 1. `cnttzw` returns **32** on zero, matching TZCNT exactly; `cnttzd` returns 64 |
| `setb` | `li 0; bc; li 1` (SETcc) | Reads **only LT and GT**, yields −1/0/1. Against `MapNZCVCC`'s 20 conditions: **4/20** get 1 insn, **5/20** need `setb`+`neg`, **11/20** need a cr-logical first (2–3 insns). Real value is branch elimination, not instruction count |
| `darn` | spill / C-call / fill PRNG helper | L=0 32-bit, L=1 64-bit conditioned, L=2 raw. `0xFFFF…FF` = error; retry, "ten attempts should be adequate", then software fallback |
| `mtvsrdd` / `mfvsrld` | 6-insn stack bounce for dword splat; `vsldoi`+`mfvsrd` for extract | `mtvsrdd v,rs,rs` = 1-insn dword splat. **`RA=0` means literal zero** — cannot splat from r0. `mfvsrld` reads `dword[1]` = guest low qword |
| `xxbrq` / `xxbrd` / `xxbrw` / `xxbrh` | vperm byte reversal with materialised control | Endian-agnostic; also the enabler for cheap AES state reversal |
| `vpermr` | `vperm` + XOR-0x0F index fixup in PSHUFB | Uses byte element `31-index`. High-bit⇒zero is **not** provided; the zeroing select remains |
| `xxspltib` | multi-insn immediate splat | Full 8-bit immediate 0–255 vs `vspltisb`'s ±16 |
| `xxinsertw`/`xxextractuw`, `vinsertb/h/w/d`, `vextu[bhw][lr]x` | 13–17 insn perm-control materialisation for PINSR/PEXTR/INSERTPS | **Two footguns** — see [Traps and invariants](#traps-and-invariants) |
| `xscvhpdp` / `xvcvsphp` etc. | F16C via FABI helper | Not drop-in: sparse hword-1,3,5,7 layout needs pack/unpack; VCVTPS2PH's imm8 static rounding needs FPSCR.RN manipulation (see `mffscrn` below) |
| `extswsli` | `extsw` + `sldi` | SH 0–63, no CA side effect |
| `cmprb` / `cmpeqb` | byte-range / byte-equal tests | Result lands in GT (setb-friendly). **Undefined in 32-bit mode** |
| `addex` | ADCX/ADOX dual carry chains | Uses OV as an independent chain, never touches CA, exempt from SO. **v3.0B**, not v3.0 base; UM Table A-1 confirms POWER9 implements it. **Does not fix why ADX is suppressed** — see below |
| `addpcis` / `lnia` | PC-relative materialisation | `lnia Rx` is an extended mnemonic for `addpcis Rx,0`. Deferred: `RELOC_NAMED_THUNK_MOVE` assumes `LoadConstant`'s 5-insn shape (`JIT.cpp:1231-1245`) |

**`addex` does not address the ADX suppression.** Commit `39f664bd9` places that bug in the
*frontend* `OpDispatchBuilder::ADXOp` fallback (the CFInverted × OldNZCV re-injection), reproduced by
OpenSSL's `x25519_fe64_mul`. `addex` helps only if a native backend ADX path is plumbed through
HostFeatures to bypass that fallback. Also note the OV chain is destroyed by **any** OE=1
instruction, and this backend emits `addco_`/`subfco_`/`addeo_`/`subfeo_` for nearly every
flag-producing op. It is safe only because real ADX sequences generate no intervening flag ops —
correct but fragile; document the invariant explicitly.

---

## The graphics path (architecture-neutral)

This section is not POWER9 work. It is here because it is **the highest-value open problem in the
repository**, because it gates the Proton/Vulkan use case, and because until now it existed only
inside one commit message (`d91959d2f`) — and this project has already lost most of its design notes
that way.

### Why this matters more than the OpenGL blockers

Proton renders through Vulkan: DXVK for D3D9/10/11, VKD3D-Proton for D3D12. Native OpenGL titles are
a shrinking minority. The port's per-game OpenGL callback grind (Grimrock's `glXChooseVisual`, the
libGL unpacker registrations) is real work, but it is not on the critical path for a Proton-oriented
goal. **The Vulkan WSI callback bug is.**

### Established state (crash matrix, 2026-05-18, at `ff80fcc8a`)

| Test | WSI | Outcome |
|---|---|---|
| vkcube | XCB | works, 30 frames |
| vkmark --winsys xcb | XCB | works, score 7245 |
| glxgears | libGL | 60 FPS (callback never fired) |
| SuperTuxKart --render-driver=vulkan | Xlib | SEGV, PC=0 in XSync callback |
| vkmark (auto → wayland) | Wayland | SEGV, PC=0 in `wl_listener` |

**Vulkan itself works.** A vkmark score of 7245 means guest x86_64 → thunk → native ppc64le
RADV → GPU is a functioning pipeline. This is not a "Vulkan is unsupported" situation; it is a single
defect in one code path.

### Root cause as recorded

`X11Manager::GuestToHostDisplay` → `CallbackUnpack::CallGuestPtr` → `InstanceInfo.CallCallback`
(`FEX::HLE::CallCallback`) sets guest RIP from `InstanceInfo.GuestUnpacker`, which contains a **host
VA** (0x3fff… range, inside `libvulkan-host.so`) rather than a guest x86_64 address. The JIT fetches
from unmapped memory and lands at PC=0.

libGL and libvulkan store identical-pattern garbage in their `GuestUnpacker`/`GuestTarget` slots, so
**one bug is shared across thunk libraries**. The author's conclusion, which the eliminations below
support: *the trampoline template is structurally correct and mirrors ARM64; the corruption is in the
data flow at registration time, not the dispatch mechanism.*

XCB survives only because it never registers a guest callback through
`MakeHostTrampolineForGuestFunctionAt` — its sole cross-arch translation is `GuestToHostConnection`
(an opaque `xcb_connection_t*`), which is data, not a callable address. **XCB is not "the WSI that
works"; it is the WSI that never exercises the bug.**

### Registration data flow

Guest side (`ThunkLibs/libvulkan/Guest.cpp:113-115`) passes two plain guest VAs:

```c
fexfn_pack_Vulkan_SetGuestXSync((uintptr_t)dlsym(libx11, "XSync"),
                                (uintptr_t)CallbackUnpack<decltype(XSync)>::Unpack);
```

Host side (`ThunkLibs/libvulkan/Host.cpp:67-77`, mirrored at `ThunkLibs/libGL/libGL_Host.cpp:82-94`)
receives them and calls `MakeHostTrampolineForGuestFunctionAt`
(`ThunkLibs/include/common/Host.h:821`), which forwards to
`FEX::HLE::MakeHostTrampolineForGuestFunction` (`Source/Tools/LinuxEmulation/Thunks.cpp:389`) with
`HostPacker = &CallbackUnpack<FuncType>::CallGuestPtr`.

**Note the coincidence that makes this diagnosable:** `HostPacker` is *legitimately* a host VA inside
the host thunk library — exactly the value pattern observed in the `GuestUnpacker` slot. Any
off-by-one-field read, or any argument-order error, would present precisely this symptom.

### Hypotheses eliminated (2026-07-28)

The author's parting note proposed two candidates. Both are now excluded, along with a third that
suggested itself:

1. **`host_layout<uintptr_t>` mangles the values in transit — ELIMINATED.** The primary
   `host_layout<T>` template (`ThunkLibs/include/common/Host.h:251-279`) is a plain value copy
   (`data {from.data}`) for integral types. Pointer translation lives only in the `host_layout<T*>`
   specialisations (`:304`, `:346`, `:365`), which `uintptr_t` does not select. The values are not
   transformed by the layout machinery.
2. **Argument-order / aggregate-init error in the trampoline construction — ELIMINATED.**
   `TrampolineInstanceInfo` (`Thunks.cpp:145-150`) is populated with *designated* initialisers
   (`Thunks.cpp:454-455`), so the fields cannot be transposed. The nearby
   `GuestcallInfo gci = {GuestUnpacker, GuestTarget}` (`Thunks.cpp:394`) looks like a two-initialiser
   aggregate against the four-field `GuestcallInfo` in `Host.h:78`, but it is a **different, local
   two-field struct** (`Thunks.cpp:176-181`) used only as a dedup map key. Not a bug; do not "fix" it.
3. **The hardcoded PPC64LE `InstanceInfo` offset is wrong — ELIMINATED.** `GetInstanceInfo`
   (`Thunks.cpp:94-112`) hardcodes offset 40 on PPC64LE because assembler padding makes the
   `Length - sizeof(info)` derivation invalid (the bug `f34dbdb9d` fixed). The asm is 10 instructions
   × 4 bytes = 40, and `addi r11, r12, 32` with `r12` = label1 = template+8 lands exactly on the
   `.quad` at +40. Consistent. *(The comment at `Thunks.cpp:84` saying "12 insns = 48 bytes of code"
   is stale — the arithmetic that matters is right, the prose is not. Worth correcting so the next
   reader does not chase it.)*

### Remaining candidates, ranked

1. **A stale or ABI-mismatched `libvulkan-guest.so` in the rootfs.** The guest stubs cross-compile to
   x86_64, and the README records that the cross-sysroot is incomplete, so guest stubs are "typically
   built on a native x86_64 host and copied back." If the deployed guest stub predates a signature or
   packing change on the host side, the two `uintptr_t` arguments could be unpacked from the wrong
   offsets, yielding exactly this garbage. **Check first — it is the cheapest to falsify:** rebuild
   the guest stubs from the current tree and confirm the deployed `.so` matches.
2. **The TLS side-channel is written per-dispatch and read later.** On PPC64LE the trampoline writes
   `&InstanceInfo` into `__fex_callback_guestcall_ptr` (`Thunks.cpp:68-76`, commit `62ea24ce4`) before
   `bctr`, and the host thunk library reads it back through the exported
   `FEX_GetCallbackGuestcallPtr` getter — one PLT call later. Between the `std` and that read, the
   host packer runs and itself calls PLT-resolved functions. **Any nested or reentrant trampoline
   dispatch in that window overwrites the TLS slot**, and the outer callback then reads the inner
   callback's `InstanceInfo`. This is a structural difference from x86/ARM, which pass the pointer in
   a register (r11/x11) with no shared mutable state. It does not obviously produce a *host* VA in
   the `GuestUnpacker` field, but it is a real reentrancy hazard on this path and should be ruled out.
3. **The values are already wrong on the guest side**, i.e. `dlsym`/`&CallbackUnpack<...>::Unpack` in
   the guest stub resolve to something unexpected under the thunked libX11.

### Recommended next step

Breakpoint `fexfn_impl_libvulkan_Vulkan_SetGuestXSync` (`ThunkLibs/libvulkan/Host.cpp:71`) at entry
and print both `uintptr_t` arguments. That single observation partitions the search:

- **Already host VAs at entry** → the defect is guest-side or in the generated unpacking
  (`ThunkLibs/HostLibs/gen_64/thunkgen_host_libvulkan.inl:fexfn_unpack_*`); candidate 1 or 3.
- **Correct guest VAs at entry** → the defect is downstream, in trampoline construction or in the TLS
  side-channel; candidate 2.

Then dump `GetInstanceInfo(trampoline)` immediately after `MakeHostTrampolineForGuestFunction`
returns, and again at first dispatch, to see whether the slot is correct at construction and
corrupted later.

### Why this is worth doing before the POWER9 work

It is one defect, shared across libGL and libvulkan, with a functioning Vulkan pipeline already
demonstrated behind it. Fixing it plausibly unblocks Xlib WSI, Wayland WSI, and a substantial share
of the per-game OpenGL callback registrations simultaneously. Note that Wine's `winex11.drv` requests
Xlib surfaces for `winevulkan` (**verify against the target Proton build**) — if that holds, the Xlib
WSI is not an alternative path but *the* path for Proton.

Independent of this bug, Steam carries its own deferred blocker cluster: TLS handshake failure on its
bundled OpenSSL 1.1, a `ThreadStateObject` UAF in `DestroyThread` currently mitigated by a deliberate
leak (`f78e0613d`), and NoExec waves. Those are separate problems from WSI.

## Bugs found in the current backend

Discovered incidentally during the audit. None are POWER9-related.

1. **Stale `XER.OV` on 64-bit inline-immediate arithmetic.** `AddWithFlags` (`ALUOps.cpp:1526`),
   `SubWithFlags` (`:1580`, `:1591`), `AddNZCV` (`:1645`) and `SubNZCV` (`:1686`) take an
   `addic_`/`subfic` fast path for small constants, which sets CA but **not OV** — the comment says
   so — and at 64-bit width there is no redo to fix it. The 32-bit paths are rescued by the shifted
   `addco_` redo; 64-bit is exposed. Repro:
   `mov rax,0x7FFFFFFFFFFFFFFF; add rax,1; jo` should take the branch but will read whatever set OV
   previously. No existing test appears to cover this. **Unverified on hardware** — this checkout is
   on aarch64.
2. **Factually wrong comment justifying the software crypto path.** `JIT.cpp:88-92` states "POWER8
   lacks AES, SHA, CRC32C, and PMULL128 instructions (these arrived in POWER9…)". Wrong for three of
   four: `vcipher`, `vshasigmaw/d` and `vpmsumw/d` are all **ISA 2.07 — POWER8**. Only CRC32C is
   genuinely absent. The entire FABI software fallback path exists because of this misconception.
3. **SMC `si_addr` imprecision window.** A single 8-byte `std` spanning a page boundary into a
   write-protected page may report a first-page DAR, causing the handler to unprotect the wrong
   page. Narrow today; §2.1's `stxvx` would widen it to every crossing.
4. Minor: `SbbWithFlags`-32's manual CF extraction (`ALUOps.cpp:1886-1888`) duplicates what
   `subfe`'s own CA-out already provides. Harmless, wasteful. The comment at `:1601` claiming the
   32-bit sub redo is needed for CA is also wrong — only OV needs it.

---

## Negative results

Post-review. Three items from revision 1 were overturned; those now appear in
[Tier 1](#tier-1--power8-legal-available-today) and [Additional opportunities](#additional-opportunities).

**Still standing:**

1. **No compare-and-swap-EQUAL AMO exists.** Only *Compare and Swap Not Equal* (FC 10000). Every
   attempted inversion fails: setting the comparand to the desired new value makes it an
   unconditional swap that stores even when memory ≠ expected, which CMPXCHG forbids and no retry
   can repair — the wrong store already happened. `larx`/`stcx.` stands. The AMOs also lack
   acquire/release (§4.5 p.859), so this is doubly safe.
2. **AMOs are word/doubleword only, strictly aligned, with no ordering semantics.** 8/16-bit x86
   `LOCK` ops stay on `lbarx`/`lharx`; barriers stay. Whether AMOs beat an L1-hit `larx`/`stcx.`
   loop when uncontended is unmeasured — they execute near the coherence point and may lose.
3. **Cross-arch thunk/callback blockers are architecture-neutral.** A dedicated attempt to find any
   ISA 3.0 facility touching ELFv2, r2/TOC, or the r11 static-chain hazard found nothing. One minor
   performance note: the UM's 32-entry count cache means a single shared `bctr` dispatch trampoline
   with many live targets will mispredict chronically — an argument for per-callback inline-target
   trampolines, but that is performance, not the blocker.
4. **`copy`/`paste.` are not a general memcpy primitive** — "if the `paste.` specifies normal
   storage, the data storage error handler is invoked" (Book II §4.4 p.857). Accelerator/VAS only.
5. **`lqarx`/`stqcx.` are ISA 2.07, not a POWER9 delta** — but see Tier 1.1: that is an argument for
   using them *now*, not for ignoring them.
6. **Timebase is 512 MHz on both POWER8 and POWER9**; the `rdtsc` scaling in `a331160bb` carries over.
7. **"POWER8 trapped on unaligned accesses where POWER9 does not" is unsupported** by either
   document. Both handle most unaligned access in hardware; only the enumerated cases trap.
8. **The 128 TB address-space figure is Linux mm policy**, not architecture (hardware: 52-bit EA,
   4 PB, Book III §6.7.10).
9. **HTM is not an option** for misaligned atomics — POWER9 TM is errata-laden, deprecated, and
   disabled on most kernels.

---

## Additional opportunities

Found by the adversarial sweep of the v3.0 opcode list; not evaluated in revision 1. Ranked.

| # | Facility | ISA | Use |
|---|---|---|---|
| 1 | `xsaddqp`/`xsmulqp`/`xsdivqp` binary128 | v3.0 | Hardware quad float for x87 80-bit. Far faster than softfloat helpers, more accurate than the reduced-precision float64 mode. **Not bit-exact** (113→64-bit double rounding; exactness needs ≥130 bits) — an intermediate fidelity/speed mode. Latencies 12/24/56–58 (UM Table A-1) |
| 2 | `mffscrn` / `mffscrni` / `mffsl` | v3.0 | Lightweight rounding-mode read-modify without full FPSCR serialization. Directly services the F16C imm8-rounding problem and guest MXCSR.RC switches |
| 3 | `vcmpneb[.]` / `vcmpnezb[.]` | v3.0 | "Not equal or zero" is purpose-built for null-terminated scans — accelerates `PPC64_VPCMPISTRX` (`VectorOps.cpp:3570`) and REP SCAS/CMPS |
| 4 | `maddld` / `maddhd` / `maddhdu` | v3.0 | Fused 64×64+64: IMUL+ADD chains, address arithmetic, 128-bit multiply-accumulate |
| 5 | `xststdcdp` / `xvtstdcsp/dp` | v3.0 | One-instruction NaN/Inf/denorm/zero classification → x87 `FXAM`, DAZ/FTZ, NaN canonicalization |
| 6 | `xscmpeqdp` / `xscmpgtdp` / `xscmpgedp` | v3.0 | Scalar CMPSD/CMPSS mask in a register, no CR traffic, no full-vector op |
| 7 | `lxvwsx`, `xxperm`, `vextsb2w/d`, `vextsh2w/d` | v3.0 | VBROADCASTSS-style splats; copy-free permutes; PMOVSX assists |
| 8 | `lxvl` / `stxvl` | v3.0 | Length-governed 0–16-byte vector ops: REP MOVS tails, page-boundary-safe partial loads |
| 9 | EBB-bounded `wait` | v3.0 | See negative-result reversal below — high engineering cost |

**`wait` is not strictly unusable.** Revision 1 called it useless for PAUSE because it resumes only
on "an exception, an event-based branch exception, or a platform notify". But the **EBB facility is
problem-state**: with `MMCR0[PMCC]` configured via Linux `perf_event_open` EBB events (supported
since POWER8), userspace owns a PMC and the `BESCR`/`EBBHR`/`EBBRR` SPRs. A bounded pause is
therefore constructible entirely in problem state — program a cycle-counting PMC to overflow in ~N
cycles, `wait`, take the EBB, `rfebb`. Unlike the PPR nop idiom, `wait` actually stops dispatch and
cedes SMT resources. Caveats: per-thread perf-fd setup, an EBB handler in the dispatcher, conflicts
with any profiling of the process, unknown re-arm cost. **Verdict: usable only with an EBB timeout
harness; high engineering cost; the PPR idiom remains the default.**

Considered and rejected: `stop` (privileged), DFP/BCD/`vmul10*` (no x86 analogue worth wiring),
`scv` (the backend emits no raw `sc`; glibc ≥2.33 already uses it).

---

## Traps and invariants

### Latent SIGILL: `vabsdub` / `vabsduh` / `vabsduw`

**v3.0-only** (ISA pp.296-297) but **already encoded** in `CodeEmitter/PPC64LE/Emitter.h:1093-1095`
and never emitted. Confirmed zero emission sites, so nothing reaches them today — but any future
path that does will take an illegal-instruction interrupt on POWER8. Gate before use.

### `xsmincdp` / `xsmaxcdp` are not drop-in MINSD/MAXSD

Values match exactly — every QNaN/SNaN row and signed-zero cross-cell yields `T(src2)`, with raw
payload forwarding (ISA p.592, Table 76 p.593). But:

- **Exception behaviour differs**: `xsmincdp` raises VXSNAN only for **SNaN**; x86 signals `#IA` for
  SNaN *and* QNaN sources. Guest `MXCSR.IE` emulation under-reports.
- **`dword[1]` is zeroed**; MINSD preserves upper destination bits. A merge is still required.
- **`FPSCR.VE` must be 0**, or a trap-enabled invalid operation suppresses the write entirely.
- **`xsminjdp`/`xsmaxjdp` use the opposite NaN convention** and do **not** match x86.

### Two footguns in the insert/extract family

1. **`UIM` is always the big-endian byte-element number** — no LE reinterpretation. Under the `lxvx`
   image, guest word *w* occupies byte elements `12−4w .. 15−4w`, so **`UIM = 12−4w`**. Results are
   undefined for `UIM > 12`.
2. **The implicit data lane is not element 0**: `xxinsertw`/`xxextractuw` use word element **1**
   (bits 32:63); `vinsertb/h/w/d` use byte element 7 / halfword 3 / word 1 / dword 0.

`vextubrx` (right-indexed) is the guest-index-friendly form; `vextublx` is not.

### `mfocrf` zeroing

ISA 3.0C changed `mfocrf` so non-selected bits are zeroed, but **pre-3.0C processors — including
POWER8 and POWER9 — leave them undefined or only partially zeroed.** Do not rely on the zeroing.

### Codegen shape dependencies

- `RELOC_NAMED_THUNK_MOVE` assumes `LoadConstant`'s exact **5-instruction** form (`JIT.cpp:1231-1245`).
- CR0/XER preservation contracts documented at `ALUOps.cpp:2552-2554`, `BranchOps.cpp:121-129`. Any
  substitution with an `Rc` or CA side effect can violate them silently.
- CR0 is the canonical spilled-NZCV; comparisons deliberately target CR7 (`BranchOps.cpp:90-141`),
  CR2 for FPR loads (`MemoryOps.cpp:676-683`). Do not repurpose.
- `r0` is an invariant zero for `ldx`/`stdx` indexing, re-established after every C call
  (`BranchOps.cpp:277-280`, `ALUOps.cpp:2973`); never a discard destination.
- Guest RSP is pinned to **r11**, the ELFv2 static-chain / small-TOC register — the root of the
  callback trouble `62ea24ce4` routed around via TLS. Repicking r11 is arch-neutral remediation
  worth considering on its own merits.
- `mfcr` writes r4 = TMP2 = the incoming RIP argument in `PushCalleeSavedRegisters` — the
  `State.rip=0xC0` keystone bug (`b21ee0205`). Preserve the stash-via-r0/r7 workaround.
- **`Ashr` is already CA-free** (`ALUOps.cpp:834-912`), using only `rldic*`/`rlwinm`/`srd`/`srw`/
  `neg`/`or_`/`sldi`. Do not "optimize" it back onto `sraw`/`srad`.

---

## Refuted and corrected

Revision 1 claims that did not survive review. Recorded so they are not rediscovered.

| Claim (rev 1) | Verdict | Correction |
|---|---|---|
| 64 KB host pages break SMC tracking and explain the Mono spins | **REFUTED** | FEX reports `AT_PAGESZ=4096` unconditionally and passes guest `mprotect` through; a 64 KB host breaks every dynamically-linked guest in `ld.so`. The host is 4 KB and the mechanism never fired |
| Mono-specific workarounds corroborate the SMC theory | **REFUTED** | `ForceFullSMCDetection`, the Unity ringbuffer FORCE_TSO offsets and `MonoBackpatcherBlock` are **upstream commits by Billy Laws** (2025) targeting ARM64/Wine. Only Mono *detection* (`a37a65f17`) is the port author's. `MonoBackpatcherBlock`'s only caller is Windows-side — inert on Linux |
| "Coherence rules out data staleness, so it must be code staleness" | **REFUTED** | False dichotomy. A stale translation still contains a real load. Persistent `EAGAIN` indicates a wrong computed `val` — codegen or ordering |
| CA32/OV32 let the shift-left-32 duplication be **deleted** | **REFUTED** | Values are correct, but consumers are width-agnostic (`MapNZCVCC` reads CA with no knowledge of producer width, and after a 64-bit op CA32 ≠ CF); hardware carry-in consumes CA, never CA32; CA32 goes stale at all 48 manual XER patch sites; and ADC/SBB never used the shift trick anyway. Adoption would require a produce-time normalization redesign, not a deletion. *Smaller real finding inside it:* for subtract-family on zero-extended operands, 64-bit CA already equals the 32-bit no-borrow, so the redo is needed only for OV |
| "Restoring CA still requires `mtxer`" | **OVERTURNED** | `addze Rt,r0` / `addic Rs,Rt,-1` — two base-ISA ALU instructions. Now Tier 1.2 |
| "The 10-instruction SAR emulation stands" | **STALE** | `Ashr` is already CA-free at ~4–8 instructions |
| "The split-lock apparatus must survive intact" | **PARTIALLY OVERTURNED** | True only for accesses crossing an aligned 16-byte boundary. The `lqarx` containment transform covers the rest — now Tier 1.1 |
| "`wait` is unusable as a PAUSE lowering" | **PARTIALLY OVERTURNED** | Usable with a problem-state EBB timeout harness; high cost, PPR idiom still preferred |
| `vbpermq`+`mfvsrd` = 2 instructions | **CORRECTED** | 3+, and needs a new IR op — no `MoveMask` IR exists |
| Hardware AES/PCLMUL/SHA = 1–3 instructions | **CORRECTED** | 3–8 with byte-order fixups; AESDEC needs a transformed key; AESIMC/AESKEYGENASSIST need synthesis; CRC32 is 8–12 |
| `isel` is a free branch-free win | **CORRECTED** | +3-cycle CR-source latency; break-even ≈ 25–30% mispredict rate |
| `modsd` runs in parallel with the divide | **CORRECTED** | Only across superslices; same-superslice serializes to parity |
| `setb` gives SETcc in 1–2 instructions | **CORRECTED** | 4/20 conditions in 1; 5/20 in 2; 11/20 need a cr-logical first |
| `mcrxrx` is a drop-in for `ProjectXERToCR1` | **CORRECTED** | Requires remapping `MapNZCVCC` bit 5→4, else every overflow condition silently reads OV32 |
| `lxvx` "can replace the bounce directly for any EA" | **CORRECTED** | True on the success path; `stxvx` cross-page DAR imprecision can break SMC `si_addr` targeting, and `lxvx` may partially write VRT on fault |
| Tier 1 items are uniformly correctness-neutral | **CORRECTED** | The PAUSE/PPR item is the highest-regression-risk change in the plan; `mfocrf` collides with its own zeroing trap |

---

## Confirmed on target hardware

Measured 2026-07-28 on the target machine (build agent task T1; raw output in
`docs/build-agent-notes.md`). These close several items previously marked "needs hardware".

**Machine:** Witherspoon / AC922, 2-socket **POWER9 rev 2.2** (pvr 004e 1202), 3.3 GHz, 128 threads,
~472 GiB RAM, PowerNV. Arch POWER, kernel 7.2.0-rc2, gcc 16.1.1, clang 22.1.8, cmake 4.4.0,
ninja 1.13.2.

| Fact | Value | Consequence |
|---|---|---|
| `getconf PAGESIZE` | **4096** | FEX's implicit 4 KB-host prerequisite is satisfied. Tier 0's startup assert will pass trivially |
| MMU | **Radix** | Confirmed. Kernel advertises 4 K / 64 K / 2 M / 1 G, matching UM Table 4-17 |
| `AT_DCACHEBSIZE` | **128** | **Confirms the bug.** `HostFeatures`'s 64-byte fallback is wrong here, as is the `addr >> 6` split-lock striping |
| `AT_ICACHEBSIZE` | **128** | Same; also confirms the 32-byte stride in the icache flush loop is 4× redundant |
| `AT_HWCAP2` | **0xbef00000** | Decoded below |
| `AT_HWCAP` | 0xdc0065c2 | Not yet decoded; altivec + VSX present |
| `mmap_min_addr` | 4096 | Guest low-VA region starts at page 1 |
| x86_64 cross toolchain | **absent** | No `x86_64-linux-gnu-*`. Guest thunk stubs cannot currently be rebuilt on this host — see [The graphics path](#the-graphics-path-architecture-neutral) |

### `AT_HWCAP2` decode — several plan items confirmed live

Set bits: 31, 29, 28, 27, 26, 25, 23, 22, 21, 20. Against the standard Linux `PPC_FEATURE2_*`
definitions (high confidence, but these are Linux ABI constants — worth confirming against this
kernel's `arch/powerpc/include/uapi/asm/cputable.h`):

- **`ARCH_3_00` (0x00800000) — set.** The POWER9 gate every Tier 2 change keys off. This machine
  passes it.
- **`VEC_CRYPTO` (0x02000000) — set.** Hardware AES / SHA / `vpmsum` are present, confirming Tier 1
  item (b) is live on this box. (They are ISA 2.07, so this was expected, but it is now measured.)
- **`ISEL` (0x08000000) — set.** Confirms Tier 1 item (a).
- **`DARN` (0x00200000) — set.** Hardware RNG available for the `RDRAND` lowering.
- **`EBB` (0x10000000) — set.** **Upgrades the `wait` opportunity**: the problem-state
  event-based-branch timeout harness described in [Additional opportunities](#additional-opportunities)
  is actually constructible on this hardware, rather than theoretical.
- **`HAS_IEEE128` (0x00400000) — set.** Makes the binary128-for-x87 idea viable.
- **`HTM` (0x40000000) — clear.** Confirms negative result 9: hardware transactional memory is not
  an option for misaligned atomics on this machine.
- **`ARCH_3_1` (0x00040000) and `MMA` (0x00020000) — clear.** Correct for POWER9; no POWER10 facilities.

## Hardware probe checklist

Run on the POWER9 box. Note that the first item is **no longer decisive** — it is a sanity check, not
an experiment.

```bash
getconf PAGESIZE                                   # expect 4096 (custom kernel on most distros)
grep -E 'cpu|MMU|platform|revision' /proc/cpuinfo  # expect POWER9, MMU: Radix
dmesg | grep -i -E 'radix|hash-mmu'

LD_SHOW_AUXV=1 /bin/true | grep -E 'HWCAP|DCACHEBSIZE|ICACHEBSIZE'
#   AT_HWCAP2 must contain arch_3_00; AT_DCACHEBSIZE expected 128 (code assumes 64 — wrong)
python3 -c "import ctypes; l=ctypes.CDLL(None); print(hex(l.getauxval(26)))"
#   AT_HWCAP2 = 26; PPC_FEATURE2_ARCH_3_00 = 0x00800000
#   Confirm the constant against arch/powerpc/include/uapi/asm/cputable.h — it is a Linux ABI
#   value, defined in neither the ISA nor the UM.

cat /proc/sys/vm/mmap_min_addr
cat /sys/kernel/mm/transparent_hugepage/enabled
```

**Experiments that actually decide something:**

1. **`stxvx` cross-page DAR precision** (gates §2.1's store half). `mprotect` the second of two
   adjacent pages read-only; execute a 16-byte `stxvx` straddling the boundary; catch SIGSEGV and
   print `si_addr`. If it reports the *first* page, the store path cannot move to `stxvx` without
   reworking the SMC fault handler.
2. **Faulting `lxvx` destination preservation**: same setup for a load into a known-valued VR;
   check whether the VR was partially written.
3. **`isel` vs `bc` microbenchmark** at 0 / 5 / 30 / 50% mispredict rates, before converting 25 sites.
4. **AMO vs `larx`/`stcx.`**, uncontended and 4-thread contended, to decide Tier 2 AMO adoption.
5. **`lqarx` containment prototype** (Tier 1.1): correctness first via a two-thread test mixing a
   misaligned contained RMW against an aligned hardware atomic on overlapping bytes — the case the
   mutex helper gets wrong today.
6. **The stale-OV bug**: `mov rax,0x7FFFFFFFFFFFFFFF; add rax,1; jo`.
7. `g_SplitLockDetectedCount` (`PPC64.cpp:64`) and `AccumulatedSIGBUSCount` under a real workload, to
   size split-lock exposure before optimising it.

---

## Mono / spin debug plan

The page-size theory is dead; this is the replacement, ordered.

1. **Run Ziggurat / Stardew with `FEX_SMCCHECKS=full`.** Full mode byte-compares before every
   instruction (`Core.cpp:646-667`), bypassing mprotect/mtrack arming entirely. **If the spin
   persists, every stale-translation theory dies in one run** — pivot to ordering/codegen. If it
   disappears, SMC invalidation *scope* is implicated (not page size).
2. **Log `val` against `*uaddr` at each `EAGAIN`.** The hook exists at
   `LinuxSyscalls/Syscalls/Passthrough.cpp:355-383` (`FEX_LOG_UNEXPECTED_FUTEX`) but **as shipped it
   deliberately ignores `EAGAIN`** — a ~2-line patch makes it useful. A constant `val` against a
   changing `*uaddr` indicates a hoisted or stale *register value*, i.e. codegen. A moving `val`
   indicates livelock elsewhere.
3. **Audit SMC re-arming.** `MarkGuestExecutableRange` runs only when a page newly contains code
   (`Core.cpp:934-936`); after a fault unprotects a page (`SyscallsSMCTracking.cpp:79`), confirm it
   is ever re-protected. Page-size independent, POWER9-independent.
4. **Audit the emulated wait loop's ordering.** Given upstream needed acquire/release forcing on
   plain MOVs for these workloads, check the TSO lowering of the glibc condvar sequence-word
   accesses specifically.
5. `strace -f -e trace=futex,mprotect,mmap` diffed against a working title.
6. `gdb` the spinning thread; dump the translation at PC against current guest bytes
   (`FEX_X86DISASSEMBLE`).

**Minimal reproducer** (no Unity needed) — a ~50-line **static x86-64** binary: thread A `mmap`s RWX,
emits a stub, executes it, patches it in place, re-executes and asserts the new behaviour; thread B
`FUTEX_WAIT`s on a word only the patched stub updates. Under broken invalidation this spins on
`EAGAIN` exactly as the games do.

---

## Instruction availability tables

Gate = `PPC_FEATURE2_ARCH_3_00` unless marked POWER8-legal.

### Vector / VSX

| POWER8-legal (≤ v2.07) | POWER9-only (v3.0) |
|---|---|
| `lvx`/`stvx`, `vperm`, `vsldoi` (2.03) | `lxvx`, `stxvx`, `lxv`, `stxv`, `lxvb16x`, `lxvh8x`, `lxvl`, `lxvll`, `stxvl`, `stxvll`, `lxvwsx` |
| `lxvd2x`, `stxvd2x`, `lxvw4x`, `stxvw4x` (2.06) | `mtvsrdd`, `mfvsrld`, `mtvsrws` |
| `mtvsrd`, `mfvsrd`, `mfvsrwz`, `mtvsrwa`, `mtvsrwz` (2.07) | `xxbrq`, `xxbrd`, `xxbrw`, `xxbrh` |
| `xvcvspdp`, `xvcvdpsp` (2.06) | `xxinsertw`, `xxextractuw`, `vinsertb/h/w/d`, `vextu[bhw][lr]x` |
| `lxsdx` (2.06), `lxsiwzx` (2.07) | `lxsd`, `lxssp`, `lxsibzx`, `lxsihzx`, `stxsibx`, `stxsihx` |
| `vcipher`, `vcipherlast`, `vncipher`, `vncipherlast` (2.07) | `xsmincdp`, `xsmaxcdp`, `xsminjdp`, `xsmaxjdp` |
| `vpmsumd`, `vpmsumw`, `vshasigmaw`, `vshasigmad` (2.07) | `vpermr`, `xxspltib`, `vabsdub/h/w`, `xxperm` |
| `vbpermq` (2.07) | `xscvhpdp`, `xscvdphp`, `xvcvhpsp`, `xvcvsphp`, `vbpermd`, `vslv`, `vsrv` |
| `lqarx`, `stqcx.`, `lq`, `stq` (2.07, problem-state) | `xsaddqp`/`xsmulqp`/`xsdivqp`, `xststdc*`, `xscmpeqdp` family, `vcmpneb`/`vcmpnezb`, `vextsb2w/d`, `vextsh2w/d` |

### Scalar

| POWER8-legal | POWER9-only (v3.0) |
|---|---|
| `isel` (**2.03**) | `mcrxrx`, CA32/OV32 semantics |
| `mfocrf`, `mtocrf` (2.01) | `modsw`, `moduw`, `modsd`, `modud` |
| `addze`, `addic` (base — the CA round-trip) | `cnttzw`, `cnttzd`, `setb`, `darn` |
| `sraw`, `srad`, `srawi`, `sradi`, `addic`, `subfic` (P1) | `extswsli`, `addpcis`/`lnia`, `cmprb`, `cmpeqb` |
| | `maddld`, `maddhd`, `maddhdu`, `mffscrn`, `mffscrni`, `mffsl` |
| | `addex` (**v3.0B**; POWER9 implements it per UM Table A-1) |

### AMO function codes (Book II §4.5, Fig. 3–4)

`lwat`/`ldat` (s = 4 or 8): 00000 Fetch and Add · 00001 Fetch and XOR · 00010 Fetch and OR ·
00011 Fetch and AND · 00100/00101 Fetch and Max Unsigned/Signed · 00110/00111 Fetch and Min
Unsigned/Signed · 01000 Swap · **10000 Compare and Swap Not Equal** · 11000/11001 Fetch and Increment
Bounded/Equal · 11100 Fetch and Decrement Bounded.

`stwat`/`stdat`: 00000 Store Add · 00001 Store XOR · 00010 Store OR · 00011 Store AND ·
00100/00101 Store Max Unsigned/Signed · 00110/00111 Store Min Unsigned/Signed · 11000 Store Twin.

"Function codes not listed in this table are considered invalid" — invalid FC invokes the system data
storage error handler (DSISR bit 61). **Note the absence of a compare-and-swap-EQUAL.**

### Other confirmed constants

- Reservation granule **128 bytes**; coherence block **128 bytes** (UM §4.6.1, §4.6.2.12). At most
  one reservation per thread.
- POWER9 Radix supported page sizes: **4 KB, 64 KB, 2 MB, 1 GB**, and only those (UM Table 4-17).
- DSISR store-vs-load: ISA bit 38 = mask **0x02000000** — FEX's mask is correct
  (`MContext_ppc64le.h:189-197`). Also set for `dcbz` and Load Atomic.
- `EH` on load-and-reserve is a **hint only**. Programming note: EH=1 for lock acquisition, EH=0 for
  fetch-and-op. All current call sites pass `eh=0` (`Emitter.h:1311-1314`).
- Aligned quadword `lq`/`stq`/`lqarx`/`stqcx.` are single-copy atomic (Book II §1.4 p.817) and
  problem-state legal since 2.07.

---

## Open questions needing hardware

1. ~~**`stxvx` cross-page DAR precision**~~ — **ANSWERED 2026-07-28, all patterns pass** (§2.1),
   including both-protected convergence. Subject only to the stated scope limit: gate adoption on a
   runtime check rather than this measurement. Residual, non-blocking: whether a faulting `lxvx`
   partially writes VRT — the first attempt to measure this was unsound (`siglongjmp` restores
   callee-saved VRs and the compiler may spill a volatile one, so neither answer is trustworthy); a
   valid measurement reads the VSX save area from `ucontext` inside the handler.
2. **AMO latency/throughput vs `larx`/`stcx.`**, contended and uncontended.
3. **Unaligned `lxvx` penalty boundaries** (64 B / 128 B / page crossings). The UM gives throughput
   (§25.1.7.9) but not crossing penalties.
4. **`isel` vs predicted-branch break-even** on real silicon.
5. **Does `xsmincdp` forward SNaN payloads raw?** Pseudocode says yes; the prose table has a known
   typo mislabelling src2's source register.
6. **NaN payload width / denormal behaviour of `xscvdphp`/`xvcvsphp`** vs x86 F16C.
7. **The stale-OV bug** (repro above) — needs a POWER8 or POWER9 run to confirm.
8. **`PPC_FEATURE2_ARCH_3_00`'s value** — Linux ABI, defined in neither document.
9. **Whether ISA 2.07B's `lq`/`stq` LE wording** matches the "restriction lifted in 3.0C" narrative;
   2.07B was not consulted.

---

## Sources and method

Primary sources, in `docs/` (git-ignored; ~16 MB, not committed):

- `PowerISA_public.v3.0C.pdf` — Power ISA Version 3.0C
- `POWER9_um_OpenPOWER_v20GA_09APR2018_pub.pdf` — POWER9 Processor User's Manual, OpenPOWER v2.0 GA

Method, thirteen agent passes in four rounds:

1. **Audit** — five subsystem passes over the existing port: atomics/memory model, VSX/SIMD, scalar
   ALU/flags, runtime/dispatcher/MMU, and commit archaeology.
2. **Targeted investigation** — one pass on the Mono/managed-runtime failure class.
3. **Adjudication** — three passes re-checking every ISA-level claim against the primary sources,
   marking each CONFIRMED / REFUTED / NUANCED / NOT-IN-DOCS with citation.
4. **Adversarial review** — four passes instructed to *refute* rather than confirm, defaulting to
   "refuted" on ambiguous evidence: one attacking the page-size theory, one attacking the VSX and
   availability claims, one attacking the flag rework, and one attacking the document's pessimism
   from the opposite direction (hunting missed opportunities and overturned negative results).

Round 4 destroyed the revision-1 headline, corrected roughly half the Tier 1/2 rankings, found two
significant missed opportunities, and surfaced four bugs in the existing backend. See
[Refuted and corrected](#refuted-and-corrected).

### Provenance warning

The port's history is a squashed snapshot (`e1f83d4c4`, "bank port state as of 2026-05-11 (POWER8
snapshot)", 63 files, +24 304 lines) on top of upstream FEX at `098c4c57b`, plus ~151 follow-up
commits from a single 8-day sprint (11–19 May 2026). The commit messages are unusually detailed and
are the **primary surviving design documentation**.

Several commit bodies reference the original author's private analysis notes —
`project_stardew_main_thread_spin`, `project_vfork_clone_vm.md`,
`project_steam_manifest_tls_handshake.md`, `project_ftl_grimrock_renderpath` — **none of which are in
this repository**. `d91959d2f` also references a WIP `stash@{0}` that no longer exists. Assume that
analysis is lost.

`README.md` line 25 still advertises `c8dab0af3` (dladdr-based host-vs-guest pointer discrimination)
as a headline win; it was **reverted 11 minutes later** by `439f8fe4e` with no reason recorded. The
README is stale on that point.

Note also that upstream FEX commits present in this tree (e.g. Billy Laws' Mono/Unity work from
2025) are easily mistaken for port-author work when reading `git log` without `--author`. Revision 1
made exactly that error.
