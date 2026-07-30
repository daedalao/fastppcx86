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

- [Applicability ledger — keeping POWER8 recoverable](#applicability-ledger--keeping-power8-recoverable)
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

## Baseline — ASM differential suite

Established 2026-07-28 on the target, at `9bb4fd525` + the `Allocator.cpp` include fix. **This is the
reference for every codegen change from here on.** Full build is ~1 m 45 s, full suite 38.5 s at
`-j128`, so the edit-build-test loop is about two minutes.

| | Count |
|---|---:|
| ctest cases | **7011** — 2224 unique `.asm` × 3 JIT modes (`jit_1`, `jit_500`, `jit_500_m`), + 273 CodeEmitter + 66 misc unit tests |
| Passed | **6978** |
| Failed | **9** — 3 unique files × 3 modes |
| Skipped at ctest runtime | **24** — 8 unique files × 3 modes, all registry-driven |
| Excluded at cmake configure | 31 — `Test_verify_LinuxSyscalls` + `ThunkGen.*` per `cb3851cb4` |

### The three failing files

| File | Tag | Status |
|---|---|---|
| `FEX_bugs/add_sub_inline_imm_of.asm` | `power8+power9` | **Ours, expected.** Reproduces the stale `XER.OV` defect — see below |
| `FEX_bugs/32bit_syscall.asm` | `any-host` | Upstream capture test (`4f028b861`) for a genuinely unimplemented path: "Trying to execute 32-bit syscall from a 64-bit process". Not in `Known_Failures`, so it presents as a live failure. **Leave it visible** — it is a real gap, and this document is a better place to remember it than a registry entry that diverges from upstream |
| `X87_F64/D9_F0_02_F64.asm` | `power8+power9` | 2-ULP divergence, not a codegen defect — see below |

### The PSIGN baseline no longer reproduces

`README.md:36` claims 11213 diffs clean on POWER8 "except 6 SSSE3 PSIGN cases (tracked, deferred)".
**All PSIGN cases now pass** — the SSSE3 and VEX variants alike. Either POWER9 fixed them or they
were fixed in-tree since the README was written; distinguishing the two is not on the critical path.
Either way the README's figure is stale and should not be used as a comparison point.

Note also that the README's "31 skipped" and the suite's 24 runtime skips are **different
mechanisms** — 31 are excluded at cmake configure time by `cb3851cb4` and never become ctest cases;
24 are runtime skips driven by `unittests/ASM/Disabled_Tests` and friends. Both figures are correct
and they do not overlap.

### `D9_F0_02_F64` — a calibration divergence, not a bug

The failure is `0x3fda827999fcef34` against an expected `0x3fda827999fcef32` — **exactly 2 ULP** in
the mantissa. Cause: PPC64LE does **not** JIT-inline this operation. `DEF_OP(F64F2XM1)`
(`VectorOps.cpp:5005`) calls out to the C helper `F64F2XM1Impl` (`:4872`), which is
`std::exp2(x) - 1.0` — i.e. glibc's `exp2` on ppc64le. The expected value was calibrated against
ARM64's lowering. Both results are equally valid approximations.

The framing matters: `X87_F64` is *by definition* the reduced-precision x87 mode, a deliberate
accuracy trade. Demanding bit-exact agreement across ISAs in a mode whose premise is approximation
is the wrong bar. Treat as expected-divergent and leave it. If it ever becomes noisy, the fix is a
tolerance in the harness or a per-host expected value — **not** backend work.

### Confirmed: stale `XER.OV` on i64 inline-immediate arithmetic

`add_sub_inline_imm_of.asm` reproduces cleanly and unambiguously across all three JIT modes:

| Probe | Expected | Measured | |
|---|---|---|---|
| R8 — i64 inline-imm ADD must set OF | 1 | **0** | fail |
| R9 — i64 inline-imm ADD must clear OF | 0 | **1** | fail |
| R10 — i64 inline-imm SUB must set OF | 1 | **0** | fail |
| R11 — i64 inline-imm CMP must set OF | 1 | **0** | fail |
| R12 — i64 inline-imm SUB must clear OF | 0 | **1** | fail |
| R13 — CONTROL, register-operand ADD | 1 | 1 | **pass** |
| RAX — CONTROL, 32-bit inline-imm ADD | 1 | 1 | **pass** |

Both controls pass, so the harness is sound and the defect is localised to the i64 inline-immediate
path. **The measured pattern is precisely "OF passes through unchanged":** every probe primed to
OF=0 read 0, every probe primed to OF=1 read 1. That characterisation is only available because the
priming survives optimisation — the `seto` after each priming add, added on adversarial review, is
what makes the result diagnostic rather than merely red.

Fix: give the i64 inline-immediate paths in `AddWithFlags` / `SubWithFlags` (and the `AddNZCV` /
`SubNZCV` equivalents, which are untested here but share the shape) an OV update, mirroring what the
i32 path already does with its `addco_` redo.

## Realistic throughput ceiling, and what it implies

Confirmed against the POWER9 UM §25 and §1:

- "Execution across **two execution superslices, that each provide 128-bit dataflow**… each
  superslice is composed of a pair of slices."
- "Each slice can perform one FX or **VSX operation per cycle**."
- "**Two 16-byte load and two 16-byte store** operations are supported for VMX and VSX operations
  per cycle."

So the core sustains **2 × 128-bit VSX ops per cycle** = 8 DP FLOP/cycle. A Skylake core with two
256-bit FMA units sustains 16. **POWER9 tops out near 50% of Skylake on FP-dense kernels before any
emulation overhead**, and clock speeds are close enough that nothing papers over it. That is an
architectural ceiling, not a tuning target. Plan accordingly: FP-throughput-bound guest code will not
reach parity, and effort spent chasing it has a hard limit.

**The useful corollary: FEX's AVX-128 decomposition costs nothing here.** A native 256-bit unit
retires one YMM FMA per cycle; POWER9 retires two 128-bit FMAs per cycle — *the same throughput*.
The decomposition is not a compromise on this hardware, it is exactly what the machine would do
internally anyway. The gap versus Skylake is Skylake having twice the execution units, not anything
about how FEX splits YMM operations. So:

- Do **not** treat AVX-128 decomposition as technical debt to be removed. There is nothing to gain.
- Do treat the **load/store path** as worth optimising, because 2 × 16-byte loads and 2 × 16-byte
  stores per cycle is real bandwidth that the current 7-instruction red-zone bounce
  (`PPC64Emitter.cpp:285-318`) cannot get anywhere near. `lxvx`/`stxvx` is what makes the ceiling
  reachable.
- Prioritise **correctness, latency and instruction count** over FP throughput generally. The ranked
  items in Tier 1 and Tier 2 are mostly of that character already; this is a reason to keep them
  ranked that way.

### Measurement recipe — use this for every perf comparison from here on

Established 2026-07-29 by a 3×-per-configuration sweep. **Use this configuration for any codegen or
thunk performance work; numbers taken any other way are not comparable and mostly not meaningful.**

```
sudo ppc64_cpu --smt=2
numactl --cpunodebind=0 --membind=0 FEX <workload>
```

vkmark medians, 3 runs each, node-pinned throughout:

| SMT | CPUs | Median | Spread |
|---|---:|---:|---:|
| 4 | 64 | 8348 | 2579 (31%) |
| **2** | **32** | **8730** | **5 (0.06%)** |
| 1 | 16 | 3503 | 854 (24%) |

NUMA variants at SMT2:

| Config | Median | Spread |
|---|---:|---:|
| unpinned | 2997 | 811 (27%) |
| `--membind=0` only | 4022 | 779 (19%) |
| `--interleave=all` | 3842 | 1958 (51%) |
| **`--cpunodebind=0 --membind=0`** | **8730** | **5 (0.06%)** |

**Three things worth extracting.**

**1. The 0.06% spread is the most valuable number here.** It means a 1% codegen change is
measurable. Most emulation work is done on platforms where benchmark noise swamps individual
optimisations; on this box, correctly configured, it does not. That makes the whole Tier 1/Tier 2
ranking empirically checkable rather than argued.

**2. Pinning both CPU and memory to one socket beats using both sockets**, and by a factor of ~2.9
against unpinned. Node distance is 10/40, so cross-socket is 4×; with everything on one node the
L2/L3 and memory paths are uniform and the scheduler has nothing to migrate. Halving the CPU pool
from 64 to 32 threads costs far less than that migration was costing. This was initially dismissed
as a confounded measurement — halving cores *and* localising memory at once — which was reasonable
a priori and wrong empirically.

**3. Single runs on this workload are actively misleading.** An earlier unpinned-SMT2 reading of
5985 briefly looked like a stable result; that configuration's true median is 2997. The spread on
badly-configured runs reaches 51%.

**4. Low spread is not low error, and this is the trap that has cost the most time.** The 0.06%
above is variance *within* a configuration. It says nothing about whether two configurations are
comparable. During the `NZCVSelect` investigation every individual number was reproducible to
0.1–0.3% across repeated runs and pad sweeps, and the cross-build comparison was still wrong, three
times running: a dispatcher-round-trip theory, a jitter theory, and a data-placement theory were all
built on internally-consistent numbers and all refuted. Tight spreads make a wrong comparison look
authoritative rather than making it right.

Two defences, both cheap, both now standing practice:

- **A control case that should not move.** `bench_select` carries one, and prints its own stop-rule
  at `bench_select.c:280`: if control moves between builds the comparison is contaminated and no
  other line can be believed until that is explained. It fired correctly and was nearly talked past.
- **A predictable-data twin of every data-dependent case.** Running the same guest instruction
  sequence over predictable and unpredictable data separates *branch behaviour* from *codegen
  quality* for free, with no `perf` counters and no host-side tooling. This is what identified the
  branchy-select regression as mispredicts: the predictable twin was the only case that did not
  regress. On a JIT, where most interesting codegen questions are branchless-versus-branchy, this is
  the single highest-value control available.

The general rule: **a negative result that kills a hypothesis is worth more than a measurement that
confirms one**, because confirmation under a contaminated methodology is indistinguishable from
noise agreeing with you. Prefer checks that can refute.

**On the POWER8 comparison:** at 8730 the machine now exceeds the bank note's POWER8 figure of 7245,
where the first badly-configured measurement (4694) looked like a 35% regression. Still not a clean
CPU-to-CPU comparison — different GPUs, different Mesa, different rootfs, an Xwayland hop — but the
apparent regression was entirely a configuration artefact.

**Why SMT2 specifically** (mechanism, consistent with the data but not yet isolated): POWER9's SMT4
core has four slices paired into two superslices, each providing 128-bit dataflow. At SMT2 each
thread owns a full superslice — exactly one XMM register's width, with no sibling contention — which
lines up with what an x86 SSE guest actually issues. At SMT4 two threads share each 128-bit
datapath; at SMT1 a single guest thread cannot fill both superslices and three quarters of the
machine's threads are discarded. Guest software is also tuned for 2-way SMT topologies, so thread
pools and spin-backoff heuristics see a shape they were designed for. **Testable prediction:** the
SMT2 advantage should be larger for vector-heavy guest code than scalar-heavy. Not yet measured.

### Using a 44-core machine well — AOT ahead, dedicated cores behind

Vector units are core-private and there is no path to borrow another core's VSU: operands and
results would have to cross L2/L3 at ~50-100+ cycles against 2-7 cycles for the VSX op itself, so
instruction-level work-stealing loses by one to two orders of magnitude. The cores are not usable
that way. They *are* usable two other ways, and both are `any-host` config work rather than codegen.

**1. Compile ahead of time, on all of them.** `Source/Tools/FEXOfflineCompiler/` already implements
this upstream — `GenerateSingleCache()` produces a persistent code cache from a block list, with
`SetupCompileThread()` driving compilation outside of any guest execution. The shape is: run once to
collect executed blocks, AOT-compile them across the machine, then subsequent runs are largely cache
hits rather than JIT work. `EnableCodeCacheValidation` (`Config.json.in:26`) controls how expensively
caches are checked on load.

**Untested on this backend — treat as a real question, not a given.** The code cache persists *host*
code, so it is backend-specific, and nothing in the port's history suggests the PPC64LE path has ever
been exercised through it. If it works, it removes most JIT latency from repeat runs on a machine
that can afford to compile at scale. If it does not, that is a bug worth knowing about early rather
than discovering later. Cheap to test once the smoke ladder is up.

**2. Give the guest dedicated cores, and consider *lowering* SMT.** SMT4 does not multiply vector
throughput — four threads share the same two superslices. For a guest that is effectively 1-4 threads,
SMT2 or SMT1 gives each thread a larger share of issue queues, reservation stations and L1.
`ppc64_cpu --smt=N` switches at runtime, making it a cheap A/B against FTL or vkmark. Expectation is
that lower SMT wins for single-threaded guest workloads; worth measuring rather than assuming.

Pair it with pinning: with 176 hardware threads there is room to keep guest execution and JIT
compilation off each other's cores entirely.

**3. NUMA — this is a 2-socket machine.** Witherspoon/AC922 has two sockets, so cross-socket memory
access is a real cost for a latency-sensitive workload. Pinning guest threads and their memory to a
single node (`numactl --cpunodebind=0 --membind=0`) is a one-command experiment that plausibly
matters more than several of the codegen items in Tier 2. Worth running early for the same reason
the SMT sweep is: it costs minutes and calibrates everything measured afterwards.

**4. Guest-visible core count is a hazard at this scale, in two distinct ways.** FEX reports host
core count through CPUID (`1ea60a763` counts `/sys/devices/system/cpu/online`), so a guest sees
**logical** CPUs — 176 on this machine.

*Oversubscription:* engines routinely size thread pools or allocate per-core structures from that
number, and some behave badly at 176 — excessive memory, thrashing, occasional outright failure.

*The subtler and more likely one — asking for cores and receiving threads.* A guest that requests 8
"cores" can be placed on 8 SMT siblings occupying **2 physical cores**, taking a quarter of the
execution resources it believes it has while 42 physical cores idle. Linux's scheduler is SMT-aware
and prefers idle physical cores first, so the pathological packing is not the default — but it is not
guaranteed under load, and nothing makes it visible when it happens.

**This penalises FEX more than native code.** SMT pays off when threads stall on memory and siblings
fill each other's dead cycles. JIT-emitted code is more instruction-dense per unit of guest work, so
siblings contend on issue queues, reservation stations and rename resources instead — the regime
where SMT gives least.

Mitigations, cheapest first:

- **Run at SMT1.** This makes the topology honest: 44 logical CPUs = 44 physical cores, every guest
  thread lands on a full core, and no affinity work is needed. For a game, 44 real cores is not the
  binding constraint. This is the recommended default until measurement says otherwise.
- **Or pin one thread per physical core.** `/sys/devices/system/cpu/cpuN/topology/thread_siblings_list`
  gives the grouping; pin to one sibling from each. More flexible, more fiddly, only worth it if the
  guest genuinely wants more threads than there are physical cores.
- **Consider what FEX advertises.** Reporting *physical* rather than logical core count on
  high-SMT hosts would let naive `sysconf(_SC_NPROCESSORS_ONLN)`-style sizing produce a sane answer
  by itself. Accurately reporting topology (44 cores × 4 threads) is the more correct fix, but only
  helps guests that read topology rather than a flat count — which many do not. Worth deciding
  deliberately rather than inheriting the logical count by default.

Recorded so none of this is mistaken for a JIT defect.

### QEMU TCG as a reference — useful, with a hard licensing boundary

QEMU 7.2 added TCG support for AVX, AVX2, F16C, FMA3 and VAES, and TCG has a ppc64 vector backend
that lowers onto VSX. That makes it the only other codebase solving the same instruction-selection
problem — x86 SIMD onto VSX — and therefore a genuinely useful sanity check on choices like which
permute primitive to use for `PSHUFB`, or how to handle the `MINSD`/`MAXSD` NaN asymmetry.

**Licensing constraint, and it is not a formality.** QEMU is **GPLv2**; FEX is **MIT**. Those are
incompatible for code reuse — incorporating GPL code would force the combined work to GPL, which
conflicts with FEX's licence and would poison any attempt to upstream the work. Practically:

- **Reading it to understand what is possible is fine.** Facts and algorithms are not the
  copyrightable part; a specific expression of them is.
- **Copying or closely paraphrasing code is not.** "It picks `xxperm` for this" is a fact worth
  knowing. Transcribing its lowering function is not something to do.
- If anything from this work is ever upstreamed to FEX, provenance matters — upstream would be
  right to reject a GPL-derived contribution.

Treat it as a reference for *what the hardware can be made to do*, then implement independently. Not
legal advice; if a specific borrowing ever looks tempting, that is the point to stop and ask someone
qualified.

## Inherited assumptions to re-examine

The port was written by mirroring the ARM64 backend, and upstream FEX's disabled-test registry and
CPUID suppressions were calibrated on ARM64 hosts. **POWER9 has hardware ARM64 does not**, so a
constraint inherited from that lineage is not evidence of a constraint here. Each item below is an
assumption worth testing rather than adopting.

### 1. The backend uses half the vector register file — `power8+power9`

ISA 3.0C: "a set of **64** Vector-Scalar Registers (VSRs)" (Book I §6.2), with "the VRs mapped to
VSRs 32-63" and the FPRs occupying doubleword 0 of VSRs 0-31.

`FEXCore/Source/Interface/Core/JIT/PPC64LE/PPC64Emitter.h` allocates only VMX `v0`–`v31`
(= VSR32–63): 16 `SRAFPR` for guest XMM0-15, 14 `RAFPR` dynamic (`v16`–`v29`), and `VTMP1`/`VTMP2` =
`v30`/`v31`. **VSR0–31 are not used for vector work at all.** That is the ARM64 backend's 32-register
NEON layout transplanted onto a 64-register machine.

Consequences currently attributed to hardware that are actually this:

- `// TODO: add Newton step once we have a third scratch VR available.` (`VectorOps.cpp:524`) —
  reciprocal/rsqrt accuracy left on the table for want of a scratch register.
- "only 2 free vector temps on POWER8" (`VSQSHL`, `VectorOps.cpp:1480`) — the PSIGN-adjacent cluster.
- The per-lane scalar GPR loops in `VMul` i8 (~70 instructions, `:2386`) and `VSRSHR` (~160,
  `:1416`), which fall back to scalar partly because there is nowhere to keep intermediates.

**`xxperm` is what makes this exploitable, and it is POWER9-only.** `vperm` is a VMX-form
instruction and can only address VR0–31. Before ISA 3.0 there was no byte-granular permute reaching
VSR0–31 at all, so any arbitrary shuffle forced its operands into the VR subset — which is exactly
why a 32-register layout was the path of least resistance for the original port. `xxperm` /
`xxpermr` (v3.0) permute at byte granularity across the whole 64-register file and remove that
constraint.

**Tag nuance:** the *registers* are `power8+power9` (VSX since POWER7), but *using them for
shuffle-heavy vector code* is effectively `power9-only`. On POWER8 the available cross-file
primitives are `xxpermdi` (doubleword granularity only) and `xxlor`-style moves, which is enough for
scratch/spill traffic but not for the shuffle lowerings that hurt most. Plan accordingly: extending
the scratch pool helps both, extending the *allocation* pool for shuffle-heavy work is a POWER9 win.

**Other caveat.** VSR0–31 alias the FPRs, so availability depends on what the x87/scalar-float path
holds live. Even a partial win — four more scratch registers — unblocks the Newton step and the
worst of the scalar-loop fallbacks.

**Next step:** audit which FPRs the x87 and scalar-float paths actually hold live across vector
codegen, then extend `RAFPR`/`VTMP` into the free part of VSR0–31.

### 2. x87 could be *better* on POWER9 than on ARM64 — `power9-only`

`AT_HWCAP2` confirms `HAS_IEEE128` on the target. POWER9 has hardware binary128
(`xsaddqp`/`xsmulqp`/`xsdivqp`); **ARM64 has no hardware quad-precision at all.** So the current
choice — softfloat (accurate, slow) or the `X87_F64` reduced-precision mode (fast, 53-bit mantissa) —
is an ARM64-shaped dilemma that POWER9 does not necessarily share.

**Representation is exact; only rounding needs hand-rolling.** binary128 has a 113-bit mantissa
against x87 double-extended's 64, so **a binary128 holds any double-extended value exactly**. The
work is not representation but the rounding step: results must be rounded to a 64-bit mantissa
explicitly, and doing that correctly in every case is the classic double-rounding problem
(guaranteeing correct rounding in general wants ≥130 bits). That is a bounded, well-understood piece
of work — and vastly closer to correct than the 53-bit F64 path while remaining hardware-fast.

Irrelevant to AVX/SSE; this is purely an x87 play.

This also reframes two inherited registry entries: `unittests/ASM/Disabled_Tests` disables
`Test_X87/D9_F8.asm` with the comment "Relies on rounding correctness", and `D9_F2`/`D9_F9` with
"Relies on undefined behaviour". Those were judged on hosts without hardware quad-precision.
**Re-run them on a binary128 x87 path before assuming they must stay disabled.**

### 3. Suppressed guest CPUID features — `unknown, needs re-examination`

`VAES` is advertised false and `ADX` is suppressed (`CPUID.cpp:716`). The ADX suppression traces to
a *frontend* bug (`39f664bd9`), not a missing facility. Neither suppression has been re-evaluated
against POWER9. Similarly, AES/SHA/PCLMUL/CRC32 are advertised as supported but implemented via
software helpers — on the strength of a comment (`JIT.cpp:88-92`) that is factually wrong about
POWER8 lacking the hardware.

### 4. The 5-register dynamic GPR pool — `power8+power9`

x64-mode dynamic allocation is 5 GPRs (`r24`–`r26`, `r30`, `r31`; `PPC64Emitter.h:60-62`) against 32
architectural GPRs, most of the rest being SRA-pinned or reserved. Whether that split is optimal for
POWER9's dispatch width, or inherited from ARM64's register budget, has not been examined. The
heavy-spill anecdote in `JITClass.h:90-94` suggests it is worth a look.

### Method note — binding rule

When something is disabled, suppressed, or routed to a software helper, establish **why** before
accepting it. The reasons so far have divided into three kinds: real ISA limits (which stand),
ARM64-era assumptions (which may not), and factual errors in comments (`JIT.cpp:88-92` on POWER8
crypto; `README.md:36` on PSIGN). Only the first kind is binding.

**A code comment is not evidence.** It is a claim with an author and a date, and on this port a
material fraction of them have been wrong, stale, or about a different host. Neither is an upstream
disabled-test entry, a CPUID suppression, or a figure in the original author's notes. Each is a lead
to verify, and until verified it must not be load-bearing for a design decision. The cost of ignoring
this has been measured: three separate hypotheses in the `NZCVSelect` investigation alone were
believed on the strength of plausible reasoning and then refuted, each after real work.

**The corollary is that we root-cause rather than inherit.** Where a claim can be settled by reading
code, read it and cite file:line. Where it needs the machine, measure it — with a control that should
not move, and a falsifiable prediction stated *before* the run. Prefer checks that can refute over
checks that can confirm; confirmation under an unvalidated method is indistinguishable from noise
agreeing with you.

### Assumption register — what is still taken on faith

Load-bearing inherited claims, with status. **Anything `UNVERIFIED` must not be designed around
without saying so explicitly.**

| Inherited claim | Source | Status |
|---|---|---|
| Making the `Break` op a real fault "breaks the worker pool init" (Steam) | stub comment near `PPC64Dispatcher.cpp:501-522` | **UNSUPPORTED** — not refuted. The commit that added it (`f78e0613d`) is a pure comment diff whose own message calls it "exploration that got reverted to a clean `blr`", so no code ever implemented or tested the claim. But the first-pass verdict of *refuted* over-reached: a `Break` reached under `CallbackPtr` returns into the C++ thunk caller and execution genuinely continues, which is literal silent absorption, so the comment's premise is not false — merely undemonstrated. Treat as an untested hypothesis, not a disproved one |
| Mono spins are caused by SMC/page-size tracking | rev 1 of this plan (mine) | **REFUTED.** Host is 4 KB; `AT_PAGESZ` is reported unconditionally; mechanism never fired |
| Mono-specific workarounds in-tree corroborate an SMC theory | port lineage | **REFUTED.** Upstream ARM64/Wine commits by another author; one is Windows-only and inert on Linux |
| "only 2 free vector temps on POWER8" | `VectorOps.cpp:1480` | **REFUTED as a hardware limit.** It is the transplanted ARM64 32-register layout; VSR0–31 are unused for vector work |
| POWER8 lacks AES/SHA/PCLMUL hardware | `JIT.cpp:88-92` | **FACTUALLY WRONG.** Software helpers are therefore unjustified by this reason |
| `Test_X87/D9_F8.asm` must stay disabled ("relies on rounding correctness") | upstream `Disabled_Tests` | **UNTESTED on POWER9.** Judged on hosts without hardware binary128 |
| `ADX` must be suppressed | `CPUID.cpp:716` | **MISATTRIBUTED.** Traces to a frontend bug (`39f664bd9`), not a missing facility. Never re-evaluated |
| POWER8 trapped on unaligned accesses where POWER9 does not | port lineage | **UNSUPPORTED** by either ISA document. Both handle most unaligned access in hardware |
| The 5-GPR dynamic allocation pool is right-sized | `PPC64Emitter.h:60-62` | **UNEXAMINED.** May be an ARM64 register budget |
| POWER8 vkmark baseline of 7245 is a comparison we should beat | original author's notes | **NOT A VALID COMPARISON.** Different GPU, Mesa, rootfs, and an Xwayland hop. Our 8730 exceeds it, but the earlier apparent 35% regression was purely a configuration artefact |
| `mfocrf`/`mtocrf` being uncracked is why the flag path got faster | my own earlier attribution | **REVISED by measurement.** Secondary; branchless replacement of mispredicted branches dominates |
| The two `PPC64Emitter.cpp` / `CodeEmitter/PPC64LE/ALUOps.cpp` files are live code | tree layout | **FALSE — neither is compiled.** Has misled analysis three times; one holds an unconverted `mtcrf(0xFF)` `FillStaticRegs` now divergent from the live copy |

## Applicability ledger — keeping POWER8 recoverable

This branch targets POWER9, but **most of the work identified is not POWER9-specific.** Restoring
POWER8 support later is not a current goal and is not on the critical path — but it is much cheaper
to keep recoverable than to reconstruct, so every change carries an applicability tag from here on.

### Tag convention

Every commit that changes behaviour gets a trailer:

```
Applies-to: any-host | power8+power9 | power9-only
```

- **`any-host`** — nothing POWER-specific at all. Toolchain hygiene, upstream bugs, thunk/ABI
  plumbing. Upstreamable to FEX as-is.
- **`power8+power9`** — correct on both. Uses only facilities at ISA 2.07 or below, or fixes a
  defect present on both. **This is the bulk of the work.** A POWER8 bring-up inherits all of it.
- **`power9-only`** — requires ISA 3.0; must sit behind the `PPC_FEATURE2_ARCH_3_00` runtime gate so
  a POWER8 host takes the existing path rather than a SIGILL.

The same tag applies to entries in this document and to build-agent findings.

**Design consequence:** because `power9-only` items are runtime-gated rather than compiled out, a
POWER8 bring-up is mostly a matter of confirming the gate is honoured on every path, not of reverting
anything. Keep it that way — prefer a runtime branch over `#ifdef` for ISA 3.0 facilities.

### Ledger as it stands

| Item | Tag | Note |
|---|---|---|
| `Allocator.cpp` include fix (`3c6877e31`) | **any-host** | Toolchain hygiene; not even POWER-specific |
| Startup page-size assert, checked `mprotect` returns | **any-host** | Tier 0 hardening |
| SMC `mprotect` rounding to host page size | **any-host** | Optional; only matters on a 64 K host |
| Cross-arch thunk / Vulkan WSI callback work | **any-host** | ELFv2 and marshalling; identical on both |
| Stale `XER.OV` on i64 inline-immediate arithmetic | **power8+power9** | The `addic_` path exists on both |
| `HostFeatures.DCacheLineSize` 64 → 128 | **power8+power9** | Both have 128 B lines |
| Split-lock mutex striping `addr >> 6` → 128 B | **power8+power9** | Reservation granule is 128 B on both |
| icache flush loop: 32 B stride → 128 B, barriers out of the loop | **power8+power9** | The stride and interior-barrier fixes |
| icache flush collapsed to one `sync; icbi; isync` for any range | **power9-only** | UM §4.6.2.2, `icbi`-as-NOP behaviour |
| PAUSE / PPR hint with explicit `or 2,2,2` restore | **power8+power9** | PPR semantics not new in v3.0 |
| `isel` for `CMOVcc` / selects | **power8+power9** | ISA 2.03 |
| `vbpermq` + `mfvsrd` for `PMOVMSKB` | **power8+power9** | ISA 2.07 |
| Hardware AES / PCLMUL / SHA (`vcipher`, `vpmsum*`, `vshasigma*`) | **power8+power9** | ISA 2.07 |
| `xvcvspdp` / `xvcvdpsp` for CVTPS2PD/PD2PS | **power8+power9** | ISA 2.06 |
| `mfocrf` / `mtocrf` over `mfcr` / `mtcrf` | **power8+power9** | ISA 2.01 |
| `VExtr` N<16 → single `vsldoi` | **power8+power9** | ISA 2.03 |
| `lqarx` / `stqcx.` containment for misaligned atomics | **power8+power9** | ISA 2.07 — the largest single win, and it is *not* POWER9 work |
| CA save/restore via `addze` / `addic` | **power8+power9** | Base ISA |
| Misaligned `CMPXCHG8B` routed through the split-lock helper | **power8+power9** | Correctness fix |
| Scalar VSR loads `lxsdx` / `lxsiwzx` | **power8+power9** | ISA 2.06 / 2.07 |
| Scalar VSR loads `lxsd` / `lxssp` / `lxsibzx` / `lxsihzx` | **power9-only** | Extends the above |
| HWCAP2 host feature detection | **power8+power9** | The detection works on both; it is what *enables* gating |
| `lxvx` / `stxvx` replacing the 7-instruction bounce | **power9-only** | The largest POWER9-gated win |
| `mcrxrx`, CA32/OV32 flag rework | **power9-only** | |
| `modsd`/`modud`, `cnttzd`/`cnttzw`, `setb`, `darn`, `extswsli`, `addex`, `cmprb`/`cmpeqb` | **power9-only** | |
| `mtvsrdd`/`mfvsrld`, `xxbrq`, `vpermr`, `xxspltib`, insert/extract family, F16C converts | **power9-only** | |
| binary128 for x87, `mffscrn`, `vcmpnezb`, `maddld`, `xststdc*`, EBB-bounded `wait` | **power9-only** | From [Additional opportunities](#additional-opportunities) |

### How the gate should be built

FEX already has the machinery; the PPC side simply never used it. Follow the existing convention
rather than inventing anything.

**1. Add the feature flag.** `FEXCore/include/FEXCore/Core/HostFeatures.h` is a flat struct of
`Supports*` bools consumed by the backend. Add `bool SupportsISA30 {};`. Name it by **ISA level, not
by chip** — `PPC_FEATURE2_ARCH_3_00` is also set on POWER10, so `SupportsISA30` stays correct where
`SupportsPOWER9` would not.

**2. Detect it.** `Source/Common/HostFeatures.cpp` currently leaves ARM defaults in place for PPC
(`:787-788`) — there is no PPC detection at all. Add a ppc64le branch reading
`getauxval(AT_HWCAP2) & PPC_FEATURE2_ARCH_3_00`, and while there, take `DCacheLineSize` and
`ICacheLineSize` from `AT_DCACHEBSIZE` / `AT_ICACHEBSIZE` rather than the wrong 64-byte fallback
(measured 128 on the target — see [Confirmed on target hardware](#confirmed-on-target-hardware)).

**3. Wire the override.** `Config.json.in:33` defines a `HostFeatures` strenum of `ENABLEX`/`DISABLEX`
pairs, consumed by the `ENABLE_DISABLE_OPTION` macro at `HostFeatures.cpp:470-498`. Add
`ENABLEISA30` / `DISABLEISA30` and one line:

```cpp
ENABLE_DISABLE_OPTION(SupportsISA30, ISA30, ISA30);
```

**4. Branch at emit time, not at run time.** FEX is a JIT, so the alternate path is selected while
*generating* code:

```cpp
if (HostFeatures.SupportsISA30) {
  lxvx(Dst, 0, Addr);                    // 1 instruction
} else {
  lxvd2x(Dst, 0, Addr);                  // 2 instructions, ISA 2.06
  xxpermdi(Dst, Dst, Dst, 2);
}
```

The emitted code contains no branch and pays nothing — the specialisation happens once per compiled
instruction, not once per execution.

**Why the override matters more than it looks.** `FEX_HOSTFEATURES=disableisa30` makes the POWER9
machine emit the POWER8 path. That is the only reason "keep POWER8 recoverable" is a real claim
rather than an aspiration: **there is no POWER8 hardware in this setup**, so without a force-off
switch the neutral paths would bit-rot the moment they were written and nobody would know until a
POWER8 bring-up years later.

Concretely, it makes the ASM differential suite double as POWER8 coverage: run it once normally and
once with `disableisa30`, and both paths at every overlap site are exercised on every change. That
should be the standing regression procedure for anything in the table below, and it costs one extra
suite run. `HostFeatures` also carries an `IsInstCountCI` flag, so `unittests/InstructionCountCI` can
lock in the expected instruction count for *each* path and catch a silent regression to the slow one.

### Overlap sites — implement once, gated, not twice

Several code sites have **both** a `power8+power9` improvement and a better `power9-only` one. These
should be written as a single runtime-gated function with two or three paths, not fixed twice.
Listing them because doing the neutral fix first and the POWER9 one later means touching the same
code twice and re-testing it twice.

| Site | `power8+power9` path | `power9-only` path |
|---|---|---|
| `LoadUnalignedV128` / `StoreUnalignedV128` (`PPC64Emitter.cpp:285-318`) | `lxvd2x` + `xxpermdi` — **2 instructions** (ISA 2.06) vs the current 7 | `lxvx` — **1 instruction**, no fixup |
| `LoadFPRSized` sub-16-byte (`PPC64Emitter.cpp:365-401`) | `lxsdx` / `lxsiwzx` (2.06 / 2.07) vs the current ~9 | adds `lxsd` / `lxssp` / `lxsibzx` / `lxsihzx` for full width coverage |
| icache flush loop (`PPC64Dispatcher.cpp:643-645`) | 128 B stride, barriers hoisted out of the loop | one `sync; icbi; isync` for any range (UM §4.6.2.2) |
| SETcc / CMOVcc lowering | `isel`, branch-free (ISA 2.03) | `setb` where the condition sits in LT/GT |
| `RDRAND` | software PRNG helper (status quo) | `darn` |
| AES / SHA / PCLMUL | `vcipher` / `vshasigma*` / `vpmsumd` (2.07), with `vperm`-based byte-order fixups | same instructions, but `xxbrq` replaces the `vperm` fixups |

**The `lxvd2x` finding is the notable one.** The plan previously framed the 7-instruction bounce as
having no POWER8 remedy, which was wrong: `lxvd2x` is ISA 2.06 and yields the doubleword-swapped
image, so `lxvd2x` + `xxpermdi` reproduces the required register image in **2 instructions**. That
recovers most of the win on POWER8 hardware, and makes the eventual `lxvx` change a one-instruction
refinement of an already-good path rather than a cliff.

**The observation worth drawing from the table above:** the two largest wins are split across the divide.
`lxvx`/`stxvx` is POWER9-only, but `lqarx` containment — which fixes a real atomicity hole as well as
removing a mutex from the hot path — is ISA 2.07 and would work on POWER8 today. A POWER8 bring-up
would inherit that, the crypto work, `isel`, `vbpermq`, and every correctness fix in the ledger.

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

### Status 2026-07-29: the entire `d91959d2f` crash matrix was an artefact. All three WSIs work.

| WSI | `d91959d2f` (POWER8) | Now | What it actually was |
|---|---|---|---|
| xcb | works | works | — |
| Xlib | SEGV, PC=0 in XSync cb | **works**, `vkcube --wsi xlib` renders | thunk halves built separately, out of ABI sync |
| Wayland | SEGV, PC=0 in `wl_listener` | **works**, 16 surface formats enumerated | `WaylandClient` thunk simply not enabled |

Neither was a marshalling or codegen defect. Both were configuration and build provenance.

**One root cause plausibly explains the whole matrix.** The bank note's own reasoning for why xcb
survived is the key: *"XCB WSI never registers a guest callback through
`MakeHostTrampolineForGuestFunctionAt`; its only cross-arch translation is `GuestToHostConnection`,
which is opaque-pointer data, not a callable address."* If guest-callback registration was broken —
because the guest stub and host thunk disagreed about layout — then **exactly the WSI that avoids
callbacks would work, and the two that use them would not.** That is the observed matrix, and it
falls out of a single defect rather than three.

Fix the provenance and all three work. Measured, not inferred:

```
[X11Manager] GuestToHostDisplay(0x4094e0) #1  GuestXSync=0x3fffb70c8000
        surface=0x3fffb642c500          <- host VA
        device[0] AMD Radeon RX 7900 XTX (RADV NAVI31)  present-capable: YES

W2: wl_display=0x3fff8d4a7a80            <- host VA, was 0x42b290 (guest heap)
W7: vkGetPhysicalDeviceSurfaceFormatsKHR -> 16 surface formats  (previously a core dump)
```

**Implication for the rest of the README's status table.** SuperTuxKart, Legend of Grimrock and the
per-game callback-signature grind (`58973e69e`, `017ebd9f8`, `3caaf4a6e`, `0f17626ac`) were all
diagnosed under the same conditions — mismatched thunk halves, and in some cases thunks not enabled
at all. **Those entries should be re-tested before any of them is treated as a real defect.** The
"open-ended per-game signature registration grind" described in the archaeology may be substantially
smaller than recorded, or may not exist.

Two deployment requirements that produced these symptoms, both easy to miss and neither of which
errors when absent:

1. **Guest stubs and host thunks must be built from the same commit.** `README.md:59` describes
   building guest stubs on a separate x86_64 machine and copying them back — that workflow's
   characteristic failure is exactly this.
2. **`ThunksDB.json` must exist in the FEX config directory**, and the specific thunk must be
   enabled. Without the file nothing is overlaid at all; without the entry, that library runs
   guest-native and passes raw guest pointers to host drivers.

### Superseded: the Xlib WSI failure does not reproduce with same-commit thunks

**With guest and host thunk halves built together from one commit, `vkCreateXlibSurfaceKHR`
succeeds and the cross-arch guest-callback path executes correctly.** Verified rather than inferred:

```
[X11Manager] GuestToHostDisplay(0x4094e0) #1  GuestXSync=0x3fffb70c8000
             GuestXDisplayString=0x3fffb70c80a8  GuestXGetVisualInfo=0x3fffb70c8054
Opening host-side X11 display: 0x4094e0 -> 0x3fffb6543000 (name=:1)
        surface=0x3fffb642c500
        device[0] AMD Radeon RX 7900 XTX (RADV NAVI31)  present-capable(qf0): YES
```

`GuestXSync` is non-null and holds a host trampoline VA — the correct wrapping, not the raw
host-VA-in-`GuestUnpacker` shape `d91959d2f` describes. `GuestToHostDisplay` fires exactly once, for
the one Xlib call the probe makes, and returns. The surface handle is a host VA.

**Leading explanation: build provenance, not marshalling.** `README.md:59` records guest stubs being
built on a separate x86_64 machine and copied back. That workflow's characteristic failure is the
two halves drifting out of ABI sync — which is exactly what produces garbage in `GuestUnpacker`.
Building both from one commit fixes it. This is now better supported than any of the marshalling
hypotheses, and it retroactively explains why three plausible code-level candidates were all
eliminated by reading.

**Not yet established.** The probe creates a surface and queries presentation support; it does not
build a swapchain, acquire an image, or present a frame. SuperTuxKart failed further along than
this. Treat as "the first crossing is clean", not "Xlib WSI is fixed". Confirming needs a render
loop, or STK itself.

### Deployment prerequisite that cost a day: `ThunksDB.json`

The thunk overlay requires **`ThunksDB.json` in the FEX config directory** (`Data/ThunksDB.json` is
the source; read at `FileManagement.cpp:55`). `Config.json`'s own `ThunksDB` section carries only
enable/disable flags — the schema mapping `"Vulkan"` to `libvulkan-guest.so` and its overlay paths
lives in that separate file.

**Without it, nothing fails.** `ThunkOverlays` stays empty, no `dlopen` is intercepted, and the
guest silently loads the rootfs's own x86_64 Mesa, which FEX JITs natively. Since the amdgpu kernel
interface is architecture-blind, that path enumerates the real GPU and creates working surfaces —
producing output almost identical to a working thunk chain.

Two probe results were initially recorded as milestones on this basis and were wrong. The tells that
distinguish them, worth checking on any future thunk work:

| Signal | Thunks active | Thunks bypassed |
|---|---|---|
| Handle shape | host VA, `0x3fff…` | guest heap, e.g. `0x4b1cf0` |
| Devices enumerated | AMD only | AMD **and** llvmpipe (rootfs ships an x86_64 llvmpipe ICD; the host loader does not) |
| `FEX_X11MANAGER_DEBUG=1` | `[X11Manager]` lines | silence |

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

## Confirmed defect: guest `int3`/`ud2`/`hlt` silently **kills the thread**

Previously characterised in this document as "silent absorbers" — the dispatcher's guest-signal
stubs swallowing `SIGILL`/`SIGTRAP`/`SIGSEGV` without delivering to the guest. That was too
generous. Verified mechanism:

1. Guest executes `int3`, `ud2`, `int imm8`, `into` or `hlt`. All lower to `Break`
   (`OpcodeDispatcher.cpp:4739-4771`).
2. `DEF_OP(Break)` (`BranchOps.cpp:143-189`) jumps to `GuestSignal_SIGILL/SIGTRAP/SIGSEGV_Address`.
3. Those stubs (`PPC64Dispatcher.cpp:501-522`) are `SpillStaticRegs; PopCalleeSavedRegisters; blr` —
   **the dispatcher's epilogue.** Control returns out of `ExecuteThread`.
4. `Syscalls/Thread.cpp:88-99` then runs `ReleaseAllPendingSharedLocks`, `UninstallTLSState`,
   `DestroyThread`, and returns `nullptr`. The pthread exits.

**So the thread dies, silently, mid-execution.** FEX's own shared locks are swept, but *guest*-side
locks the thread held are not — they stay held forever, and any peer waiting on them waits forever.
No guest signal handler runs; no unwind happens; nothing is logged.

The in-tree comment believes the behaviour is "silently NOPing", which is what pre-fix FEX did. It
is not what this code does.

**Why this is a strong Mono candidate.** Mono embeds breakpoint opcodes for runtime checks and
unreachable markers; a plain C++/SDL game like FTL does not — which fits the "Mono-specific"
framing exactly. A Mono thread dying mid-handshake leaves the coop-suspend protocol waiting on a
peer that will never answer, and Mono's timed retry loops can turn that into a spin rather than a
clean block. It also fits "after cold JIT", when Mono's compile and backpatch traffic peaks.

**It is a defect regardless of whether it explains the Mono spin.** Silently terminating a guest
thread is never correct behaviour.

**Confirmed at runtime**, not merely read: the probe classified both `int3` and `ud2` as
THREAD-KILLED, and the probe then hung — peers of the destroyed threads waited forever, exactly as
predicted. `hlt` was never reached. The same run eliminated the two competing hypotheses: 1M
contended `cmpxchg` operations were all honest, and 200k raw-futex plus 50k condvar round-trips
produced no EAGAIN storm, so neither a CAS codegen bug nor the futex layer is implicated.

### Fixing it: design plus two adversarial reviews

**Phase 1 is NOT safe as first specified.** Both reviewers independently found the same blocker, and
it was then confirmed directly.

**Blocker — FEX never installs a host SIGTRAP handler.** Host thunks are installed only for SIGILL
(`SignalDelegator.cpp:1229`, `Required=true`), SIGSEGV (`:1230`), SIGBUS (`:1255`, plus a
ppc64-specific `SigbusHandlerPPC64` at `:1303`) and the pause signal (`:1306`). The all-signals loop
at `:1309-1311` calls `RegisterHostSignalHandlerForGuest`, which at `:1394-1397` assigns only
`GuestHandler` and **never calls `InstallHostThunk`**. So a SIGTRAP-producing instruction reaches FEX
only if the guest itself called `sigaction(SIGTRAP, …)`. Otherwise the process dies on the host
default disposition, bypassing FEX entirely — no `CleanupForExit`, no telemetry, NIP inside the
dispatcher `mmap`. If the guest sets `SIG_IGN`, `UpdateHostThunk:1080-1084` propagates that to the
*host* and the result is an uninterceptable refault loop. Fix: register SIGTRAP with
`Required=true`, which blocks both downgrades exactly as it does for SIGILL.

**This is already a live bug, independent of any Break work.** `X87Ops.cpp:322` emits `0x7FE00008`
(`trap`) today for unsupported `fstp` conversion paths, while the comment at `:314` promises "a clear
SIGILL". With no host SIGTRAP thunk that path core-dumps instead of failing loudly, and it is
reachable by any guest doing `fstp dword`/`fstp qword` from a non-80-bit stack value. Registering
SIGTRAP fixes the Break work and this together.

**Our verification would have given a false green.** `probe_jit_futex.c:449-451` installs handlers for
SIGILL/SIGTRAP/SIGSEGV before every step-6 case, so the probe only ever exercises the path that
works and cannot detect the missing thunk. `GdbServer.cpp:100` registers all signals, so running
under gdbserver masks it too.

**And the ctest baseline does not cover this at all.** All 2224 ASM tests — 6672 of the 7011 cases —
terminate on `hlt` → `Break(SIGSEGV)`; **zero** contain `ud2` or `int3`. A green 6/7011 proves only
that the dispatcher still assembles. Both build caches carry `BUILD_FEX_LINUX_TESTS:BOOL=OFF` and
`ENABLE_ASSERTIONS:BOOL=OFF`, so `unittests/FEXLinuxTests/tests/signal/invalid_*` — the only
functional coverage that exists for this path — is not built. A third build directory is a
prerequisite for verifying any of this, not an optional extra.

**Other findings that revise the design:**

- **The FTL negative control is invalid.** Main-thread `ud2`/`int3` today produces an *orderly
  shutdown and exit 0* (`FEXInterpreter.cpp:629-660`), because the teardown runs on `ExecuteThread`
  returning. Only the clone'd-thread path shows the destructive behaviour, so "FTL reaches Running
  Game!" says nothing about this defect.
- **SIGILL with `SIG_IGN` is a 100%-CPU hang, not a death.** SIGILL is `Required`, so the `SIG_IGN`
  downgrade at `:1080` is skipped, FEX's thunk stays installed, and `HandleGuestSignal:951-953`
  returns without touching the ucontext — NIP never advances and it refaults forever.
- **`SignalHandlerReturnAddressRT` is aliased to the non-RT address** (`PPC64Dispatcher.cpp:1097-1098`,
  `:111-112`), so `SignalDelegator.cpp:647-650` always selects `TYPE_REALTIME`. `RestoreThreadState`
  then reads `ContextBackup` from the wrong guest-stack offset and `memcpy`s 48 `gp_regs` — including
  r1 and `PPC_PT_NIP` — out of guest-writable memory. This must be fixed **with** Phase 1 rather than
  filed separately, because Phase 1 makes `int3`, the commonest 32-bit trap, into its trigger.
- **`UD2` and `UnimplementedOp` emit byte-identical `BreakDefinition`s** (`OpcodeDispatcher.cpp:4757-4762`
  against `:5043-5050`), with no logging at either site. The backend cannot distinguish a deliberate
  guest trap from a FEX codegen gap, so after this change an unimplemented op silently becomes a guest
  SIGILL. Separating them needs a new IR field.
- **`State.rip` is stale for `MOV CS,r`** — `OpcodeDispatcher.cpp:1273` bypasses `BreakOp`.
- The `tw` helper already exists at `CodeEmitter/PPC64LE/Emitter.h:1432`; `tw(31, r0, r0)` emits
  exactly `0x7FE00008`, verified by assembling with the in-tree `powerpc64le-linux-gnu-as`. No
  hand-assembled word is needed.

**Applicability:** `power8+power9` — every host instruction involved is base Power ISA.

**Testable:** `build-probes/probe_jit_futex.c` step 6 classifies each opcode as
DELIVERED / NOPED / THREAD-KILLED — but see the false-green caveat above; it needs a
no-handler-installed variant before it can verify a fix.

## Diagnostic tooling that already exists and was never documented

`FEX_SYSCALLOBSERVE=1` (`Config.json.in:458`) enables a per-thread **futex EAGAIN-storm detector**
(`SyscallObserver.cpp:27-46`): tracks address, op and **value**, fires after 16 back-to-back EAGAINs
within a 10 ms window, then rate-limits to every 256 to confirm "still stuck" without flooding.

Tracking `val` is what makes it decisive — it separates *the same stale expectation recomputed
forever* (codegen or stale-read defect) from *a value that is churning* (a livelock or pacing
problem). That is precisely the discrimination the Stardew and Ziggurat diagnoses lacked.

`FEX_FUTEXMITIGATE=1` (`:472`) is its companion, adding a yield-based mitigation once a storm is
detected — useful for testing whether the spin is a pacing livelock.

Neither appears in `README.md`. The tool for this bug was built and, as far as the record shows,
never pointed at it.

**Consequence:** the two-line patch to `FEX_LOG_UNEXPECTED_FUTEX` proposed earlier in this document
is unnecessary and should not be done. `SYSCALLOBSERVE` is strictly better — streak-deduplicated
rather than a per-call firehose.

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

## Validation strategy — three layers, and the rule that stops them scattering

Settled 2026-07-30 after two measurement campaigns were voided. The layers exist because each one checks a
different failure mode, and the third checks *us*.

**Layer 1 — tiered tests we write.** Graduated so the first failing tier localises the defect by itself:
same-block → across a branch → across a call → across an indirect call → across a signal return → with
`PAUSE` interleaved → multi-threaded. Small enough to audit by reading in a minute, duplication preferred
over a shared engine, and each carrying a dated baseline with the config it was taken under. These *localise*.

**Layer 2 — a SIMD/FP correctness reference.** `checkasm` (dav1d is the cheap start, FFmpeg the breadth
option) validates each kernel against its own C implementation and has a `--bench` mode, so one tool gives
per-kernel correctness *and* per-kernel throughput. A failure is a named function, not a crash. Berkeley
TestFloat plays the same role for x87. These *prove*, at function granularity.

**Layer 3 — known-good off-the-shelf workloads, as calibration.** **`stress-ng`** primarily —
`vecmath`, `memcpy`, `matrix`, `pointer`, `cpu --cpu-method all` — because it has per-stressor pass/fail plus
bogo-ops/sec, is packaged everywhere, and is explicitly built to break things. **`openssl speed` plus its
self-tests** as a stretch goal, chosen deliberately: this port implements AES, SHA, PCLMUL and CRC32 as
*software helpers* on the strength of a comment that is factually wrong about POWER8 lacking the hardware, so
that workload leans directly on the code we most suspect and has published throughput expectations.

**Layer 3's real job is to validate layers 1 and 2.** If a known-good workload fails where all our tests
pass, our tests are blind. That is the only external check we have against the failure mode already hit twice:
a probe running 1M single-address `cmpxchg` operations that could not detect ordering by construction, and a
litmus suite whose opportunity metric was inverted in three tests. Both would have reported clean.

### The triage rule — read this before acting on a wall of failures

`stress-ng` will likely fail in many places at once, and chasing them in discovery order is how a day
disappears. So:

1. **Record the complete result as a baseline first.** Every stressor, pass or fail, with the config. No
   fixing during discovery.
2. **For each failure, ask whether a layer-1 or layer-2 test explains it.** If nothing does, that gap is the
   finding — write the missing test before touching FEX.
3. **Then rank by whether the fix is general**, not by how interesting the failure looks. Host-neutral and
   guest-arch defects outrank ppc64le-specific ones; anything affecting one workload only goes last.
4. **Ask what a fix nets the larger goal before pulling the thread.** Running x86 software on POWER9 is the
   goal. A defect that no realistic workload reaches is a note in this register, not a cycle of work.

Rule 4 is the one that was missing today. We debugged `mcs` — a C# *compiler*, which no real target workload
invokes, since shipped managed games ship precompiled assemblies — because the workload was chosen for
convenience rather than derived from the goal. It produced a real, general, upstream-affecting fix
incidentally, but at retail cost.

## Open defect register — as of 2026-07-30

Consolidated so nothing lives only in the build-agent log. Ordered by my judgement of value.

| # | Defect | Status | Notes |
|---|---|---|---|
| 0 | **fd-relative path resolution never consults the RootFS** | Diagnosed, unfixed | **Structural, not an unguarded fallback.** `GetEmulatedFDPath` (`FileManagement.cpp:503-507`) returns `NoEntry` when the path is relative, when it is exactly `"/"`, or when `dirfd != AT_FDCWD` — so RootFS redirection applies **only to absolute paths other than root itself**. Every `openat(dirfd, "relative", …)` walk therefore resolves against the *host* filesystem. FEX keeps no guest-dirfd → RootFS-path mapping, so it cannot scope the walk. See the write-up below |
| 0b | **Mono `CS2001` is not a filesystem bug** | Root-caused, unfixed | An strace shows `mcs` **never opens the source file** — the path appears once, in the `write(2)` emitting the error. Preceded by repeated failed `dlopen` of **`libSystem.Native.so`**, absent from the hand-assembled rootfs. Note classic Mono ships `libmono-native.so` while `libSystem.Native.so` is the .NET Core name, so this may be a **mismatched assembly graph** rather than a plain omission. The 40+ SIGSEGVs alongside it are expected Mono behaviour — `mono --version` reports `SIGSEGV: altstack`, i.e. hardware null checks — and are not a defect |
| 1 | ~~**`readlink` returns EACCES for rootfs-view paths**~~ | **FIXED** — `ce7f0fd1c` | Root cause was not what I predicted. `OpenPathInRootFS` *succeeds*; `readlinkat(fd, "")` then fails with **ENOENT**, not EINVAL, because `fs/stat.c do_readlinkat` does `error = empty ? -ENOENT : -EINVAL`. The EINVAL "not a symlink" early return was therefore **dead code** for every rootfs file and control always reached an unguarded host fallback, which answered out of the host's mode-700 `/root`. **The fix I originally proposed — guard the fallback on ENOENT — would have fixed nothing**, since ENOENT is the trigger; it needed the guard *and* an ENOENT→EINVAL translation scoped to where the fd resolved. Verified 14/14 with value assertions, ctest held 6/7011. Host-neutral, so upstream ARM64 has the same defect — **upstream candidate** |
| 1b | *(superseded row, kept for the record)* | | | `probe_file_lookup.c` isolates it: `stat`/`statx`/path-based `open`/`access` all succeed, `readlink` and `realpath` fail. Root cause almost certainly the **EXDEV-only fallback** at `FileManagement.cpp:604-625` combined with callers propagating any non-`ENOENT` errno as fatal. **Recommended next fix** — see the instrument note below |
| 2 | **TSO-path "memory corruption"** | **Entire matrix invalidated — re-measure from scratch** | Every one of the ~240 runs died early on the missing `libmono-native.so`, diagnosed later, so the whole campaign measured crash behaviour on an error path. Six hypotheses were refuted against an instrument that could not have shown the truth. The `lwsync` change stands on architectural grounds only; see the note below. **Nothing in the old matrix should be cited** |
| 3 | **Guest `int3`/`ud2` silently destroy the thread** | Designed + adversarially reviewed, **not landed** | Phase 1 as designed would core-dump on the missing host SIGTRAP thunk. `trap_flag.64` is its acceptance test |
| 4 | **Mono HANG class** | Untouched | `LOCKONLYTSO=1` floors it at 10%; every other config 37–63%. Last thing between the port and Mono |
| 5 | **NoExec entry-block forensic abort** | Unfixed | One root cause, four FEXLinuxTests symptoms: `sigill_flags.64`, `smc-exec-stack.64`, `smc-missing-gnustack.64`, `smc-unexec-stack.64` |
| 6 | `execveat_memfd.64` dies with signal 5 | Unfixed | FEXLinuxTests |
| 7 | `cpu_count.64` — 16 max addressable IDs vs 128 `hw_concurrency` | Unfixed | POWER9 topology; may be an x86 semantic difference rather than a bug |
| 8 | **Perf cost of the landed TSO fix** | Unmeasured | vkmark 1364 at SMT4 is not recipe-comparable. Blocked on the SMT2 flip (user action) |
| 9 | `r0` zero-on-entry residual | Unchecked | ELFv2 makes `r0` volatile; `PushCalleeSavedRegisters` touches it. One code read |
| 10 | README:11 SIGABRT-on-exit in FTL | Never reproduced | Both play sessions were SIGKILLed, so the natural exit path never ran |
| 11 | `syscalls_efault.64` | **Not a defect** | Expected-fail test that unexpectedly passes — metadata mismatch |

### Defect 0 in full: fd-relative walks escape the RootFS

Worth writing out because the symptom (one EACCES in a probe) badly understates it, and because
filesystem gaps that lie in wait are expensive.

**The gate.** `FileManagement.cpp:498-507`:

```cpp
if (pathname[0] == '/') {
  dirfd = AT_FDCWD;          // absolute paths ignore dirfd
}
if (pathname[0] != '/' ||    // If relative
    pathname[1] == 0 ||      // If we are getting root
    dirfd != AT_FDCWD) {     // If dirfd isn't special FDCWD
  return NoEntry;
}
```

`NoEntry` means "no RootFS translation", and every caller then falls through to the host path. So the
translation applies to **absolute paths only, excluding `"/"` itself.** Note the first clause makes the
third unreachable for absolute paths, so in practice the gate is: *relative path, or bare root → host.*

**Why it matters more than the symptom suggests.** Open-a-directory-then-walk-relative is the modern,
recommended idiom — it is what `fts`, `openat`-based traversal, and glibc's own internals use, precisely
because it is immune to TOCTOU races on the parent path. Under emulation that idiom currently gets **host
filesystem semantics**, which is both a containment breach and a correctness hazard: a host file at the
same relative position answers for a guest file that should have come from the RootFS. It goes largely
unnoticed because ordinary programs pass absolute paths.

**Why a fix is not trivial.** FEX has no guest-dirfd → RootFS-relative-path mapping, so it cannot rebuild
an absolute path to re-scope the walk. Two shapes worth evaluating:

1. **Track dirfds.** Record, per guest fd, whether it was produced by a RootFS-scoped open, and if so its
   RootFS-relative path. Then fd-relative calls can be re-expressed as a scoped `openat2` against
   `RootFSFD`. Costs bookkeeping on every open/close/dup and has to survive `fork`/`exec`.
2. **Trust the fd.** A dirfd that FEX itself produced from a RootFS open *already points inside the RootFS
   tree*, so passing it to the host `openat` should resolve correctly without any mapping. This is much
   cheaper and may be most of the answer — it would explain why `openat(fd_of_/, "root", …)` succeeded in
   the probe while the next level down did not. If it is nearly right, the remaining question is only
   which fds are trustworthy.

**The open question, and it is one cheap command.** The probe's EACCES may not be a FEX bug at all: an
extracted Ubuntu rootfs normally has `/root` at mode 700 owned by root, and we run as a normal user. If
`<rootfs>/root` is 700, the host-side walk legitimately fails and the "defect" at that path is a
permissions artifact sitting on top of the real structural gap. **Check `ls -ld <rootfs>/root
<rootfs>/root/csharp` before designing anything.** That also explains the asymmetry with the path-based
route only if the two take different code paths, so if the modes are permissive the structural reading
stands alone.

### The TSO matrix is void. Kept only as a methodology record.

**Do not cite any number below.** The workload every one of these runs used — Mono's `mcs` — never
reached real work: it failed early on a missing `libmono-native.so`, which was not diagnosed until after
the campaign ended. So the matrix measures how FEX crashes while unwinding from a library-load failure.
Six hypotheses were refuted against it, which was effort spent characterising an artifact.

The `lwsync` change in `DEF_OP(LoadMemTSO)` is retained on **architectural** grounds: it is the plainest
correct load-acquire on POWER and the simpler of two valid constructs. It is not a verified fix, it did
not verifiably repair a defect, and its performance cost is unmeasured because SMT was misconfigured for
every attempt at a comparable number. The source comment states this. Re-measurement is owed on all three
counts.

**What actually survives from the campaign** is process, not findings:

- Barrier *strength* was indistinguishable (`lwsync` versus full `sync`) — but on the void instrument.
- The sample-size rule: 15 trials cannot establish a zero at a double-digit rate; 30 rules out only ~10%.
- The preflight rule, which exists because this campaign is what it would have prevented.

The table below is retained solely so nobody re-runs it thinking it is new information.

### The old matrix, for the record only

| Load barrier | Store barrier | Corruption | HANG | Sample |
|---|---|---:|---:|---:|
| none | none | 3.3% | 46.7% | 30 |
| `lwsync` | `lwsync` (landed) | 13.3% | 56.7% | 30 |
| 4×`nop` | 4×`nop` | 13.3% | 63.3% | 30 |
| **none** | **`lwsync`** | **40.0%** | 36.7% | 30 |
| `lwsync` | none | 16.7% | 56.7% | 30 |
| *bypassed* (`LOCKONLYTSO=1`) | *bypassed* | **0.0%** | **10.0%** | 30 |

**Established:** barrier *strength* is irrelevant (`lwsync` and `sync` measure identically); `nop`s
behave like barriers, so this is not about ordering; **mismatched sides are far worse than either
matched configuration.**

**Not established:** any mechanism. Six hypotheses have been refuted by measurement — dose-response on
word count, code-buffer overflow past `kBlockHeadroom`, the ARM64 unaligned handler, an
`HandleUnalignedAtomicSIGBUS` mis-parse, the four-outcome load/store isolation table, and a discarded
`[[nodiscard]]` on `GetEmptyCodeBuffer`. That refutation rate is itself the finding: the mechanism is
somewhere we do not currently have visibility, and the next step should add instrumentation rather than
another hypothesis.

**A correction to record.** I earlier concluded that IR op identity "contributes nothing measurable,"
from the corruption column alone (1/30 against 0/30). The **HANG** column contradicts that — 46.7%
against 10% at n=30 each, on configurations whose emitted code is supposedly byte-identical. Either the
emission is not identical or op identity matters. One column was compared and the conclusion
generalised.

**The one structural divergence worth investigating next.** `JIT.cpp:1987-1988` records that PPC64
**emits directly into the shared `CurrentCodeBuffer`**, where Arm64JITCore stages into a per-thread
`TempCodeBuffer` and copies under the lock. Combined with `CPUBackend.h:199` ("old CodeBuffer generations
required to be valid until returning from signal handlers") and buffer swaps via
`GetEmptyCodeBuffer`/`StartLargerCodeBuffer`, that is a plausible neighbourhood for size-sensitive
corruption: inflating every block makes buffer exhaustion and swaps more frequent. Flagged as a lead, not
a finding — and given the refutation record above, it needs instrumentation before belief.

### Why the instrument is the real problem

**Every `mcs` run in all 240+ trials failed with `CS2001` because of defect 1.** So the entire TSO matrix
measures crash behaviour on an *error path*, never on real compilation, in a workload that carries at
least two other unfixed defects. The HANG rate swinging 10–63% across supposedly near-equivalent
configurations is consistent with that.

**Fix defect 1 first.** It is the most tractable, it is independent of the others, and it converts `mcs`
from a degenerate error-path exerciser into a workload that actually compiles something. Re-measure TSO
against that. Continuing to bisect against the current instrument risks several more cycles
characterising an artifact.

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
10. **Do not make `NZCVSelect`'s constant form branchy.** Tried in `8bf8123c3` on the theory that
    `NZCVSelect(cond, 1, 0)` is the SETcc archetype, where a branch keeps `isel`'s latency off the
    dependent chain that consumes the 0/1. Restored to `isel` in `28e34964c` after measuring a net
    **5.7 ns/op loss**: cmov-unpredictable +69 %, control +60 %, adc-chain +26 %, against the
    intended setcc −54 %.

    The premise was the error. `SETccOp` is *one* caller of `_NZCVSelect01`; the dominant caller is
    per-flag-bit materialisation in `OpcodeDispatcher.h` — the `!NZCVDirty` path reconstructing a
    single RFLAGS bit (CF/OF/ZF) into a GPR — plus `ConvertNZCVToX87`. An IR dump of the benchmark's
    `main` found **15 constant-form against 3 register-form**, the constant-form conditions being
    `UGE`/`ULT`/`SGT` clustered around the compare sites. `UGE`/`ULT` is CF. Flag reconstruction
    selects on a *data-dependent* condition and feeds pure dataflow, which is precisely where an
    unpredictable branch is worst and where branchless codegen earns its keep.

    Capturing the real setcc win needs a **distinct IR op emitted only from `SETccOp`**, because at
    the backend both arrive as `NZCVSelect(cond, 1, 0)` and are indistinguishable. Any fix
    conditioned on *operand shape* is doomed for that reason; the condition has to come from the
    frontend. Open, unscheduled.

---

## Additional opportunities

Found by the adversarial sweep of the v3.0 opcode list; not evaluated in revision 1. Ranked.

| # | Facility | ISA | Use |
|---|---|---|---|
| 1 | `xsaddqp`/`xsmulqp`/`xsdivqp` binary128 | v3.0 | Hardware quad float for x87 80-bit. Far faster than softfloat helpers, more accurate than the reduced-precision float64 mode. **Not bit-exact** (113→64-bit double rounding; exactness needs ≥130 bits) — an intermediate fidelity/speed mode. Latencies 12/24/56–58 (UM Table A-1) |
| 2 | `mffscrn` / `mffscrni` / `mffsl` | v3.0 | Lightweight rounding-mode read-modify without full FPSCR serialization. Directly services the F16C imm8-rounding problem and guest MXCSR.RC switches |
| 3 | `vcmpneb[.]` / `vcmpnezb[.]`, plus **`vclzlsbb` / `vctzlsbb`** and the vector CLZ/CTZ family | v3.0 | String and `memcmp` primitives. "Not equal or zero" is purpose-built for null-terminated scans; `vclzlsbb`/`vctzlsbb` count leading/trailing zero least-significant bytes, which is the natural way to turn a compare mask into an index. Together these accelerate `PPC64_VPCMPISTRX` (`VectorOps.cpp:3570`), REP SCAS/CMPS, and the `strlen`/`memchr` chains the code comments repeatedly cite |
| 4 | `maddld` / `maddhd` / `maddhdu` | v3.0 | Fused 64×64+64: IMUL+ADD chains, address arithmetic, 128-bit multiply-accumulate |
| 5 | `xststdcdp` / `xvtstdcsp/dp` | v3.0 | One-instruction NaN/Inf/denorm/zero classification → x87 `FXAM`, DAZ/FTZ, NaN canonicalization |
| 6 | `xscmpeqdp` / `xscmpgtdp` / `xscmpgedp` | v3.0 | Scalar CMPSD/CMPSS mask in a register, no CR traffic, no full-vector op |
| 7 | `lxvwsx`, `xxperm`, `vextsb2w/d`, `vextsh2w/d` | v3.0 | VBROADCASTSS-style splats; copy-free permutes; PMOVSX assists |
| 8 | `lxvl` / `stxvl` | v3.0 | Load/store vector **with length** — emulate masked loads/stores at buffer boundaries **without faulting**, which is the hard part of doing them safely. REP MOVS tails, page-boundary-safe partial access. Higher value than first assessed |
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

## Repo hazard: two source files in this tree are never compiled

**Neither of these is in the build. Editing either is a silent no-op.**

| File | Size | Why it is dead |
|---|---:|---|
| `FEXCore/Source/Interface/Core/JIT/PPC64LE/PPC64Emitter.{cpp,h}` | 16 KB + 6 KB | `CMakeLists.txt:40` builds `Interface/Core/ArchHelpers/PPC64Emitter.cpp` instead; every consumer includes the ArchHelpers header, and the stale file includes it too |
| `CodeEmitter/PPC64LE/ALUOps.cpp` | **113 KB** | `CodeEmitter/CMakeLists.txt` declares an `INTERFACE` library — headers only, no sources. Only `Emitter.h` and `Registers.h` are consumed |

Both date from the `e1f83d4c4` snapshot. **The live files are
`FEXCore/Source/Interface/Core/ArchHelpers/PPC64Emitter.{cpp,h}` and
`CodeEmitter/PPC64LE/Emitter.h`.**

Deleting them is the obvious fix, deliberately deferred so a build break does not land in the same
test cycle as a codegen change and confound it.

### This has already cost real effort twice

Line citations in §2.1 and the overlap-sites table were taken against the stale emitter, as was an
adversarial reviewer's analysis "proving" the red-zone stack slot at `r1-16` was 16-byte aligned.
The live code had already moved that bounce to `STATE+JITScratch`, because the `r1` red-zone
approach faulted at stack-mapping boundaries.

The *conclusions* survive — the live bounce also faults on the guest EA via `ld`/`std`, so the DAR
measurements still apply — but every line number in this document referring to
`JIT/PPC64LE/PPC64Emitter.cpp` should be read as `ArchHelpers/PPC64Emitter.cpp`.

## Superseded: there are two `PPC64Emitter.cpp` and one of them is dead

**`FEXCore/Source/Interface/Core/JIT/PPC64LE/PPC64Emitter.{cpp,h}` is not compiled.**
`FEXCore/Source/CMakeLists.txt:40` builds `Interface/Core/ArchHelpers/PPC64Emitter.cpp`, and every
consumer — `JITClass.h`, `PPC64Dispatcher.h`, and the stale file itself — includes the ArchHelpers
header. The `JIT/PPC64LE` pair is a duplicate from the `e1f83d4c4` snapshot that has never been part
of the build.

**This has already cost real effort twice.** Line citations in §2.1 and the overlap-sites table were
taken against the stale copy, as was an adversarial reviewer's analysis "proving" the red-zone stack
slot at `r1-16` was 16-byte aligned. The live code had already moved that bounce to
`STATE+JITScratch`, because the `r1` red-zone approach faulted at stack-mapping boundaries — ELFv2
has no red zone in the sense that code assumed.

The *conclusions* survive (the live bounce also faults on the guest EA via `ld`/`std`, so the DAR
measurements still apply) but every line number in this document referring to
`JIT/PPC64LE/PPC64Emitter.cpp` should be read as `ArchHelpers/PPC64Emitter.cpp`.

**Editing the stale file is a silent no-op.** Anyone modifying the PPC64 emitter must confirm they
are in `ArchHelpers/`. Deleting the duplicate is the obvious fix, deliberately deferred so it does
not land in the same test cycle as the first codegen changes — a build break and a codegen change
arriving together would confound each other.

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
