# Scalar lowering fixes: reg-reg movss/blendps and cvttss2si sentinel dedup

**Session 2026-08-30 — implementation of the two build-ready proposals from
[scalar-fp-lowering.md](../../../../../../powerpc64le-ports/hangover-ppc64le/wine-upstream/ppc64le/docs/sessions/2026-08-29/scalar-fp-lowering.md)
§6.2/§6.3 (wine-upstream `b0b58acd0c2`, companion `x86-vector-in-the-wild.md`
`24700818666`). Both fixes are live in `fastppcx86` branch `power9team`, HEAD
commit `5b3576d23` before this work. No games or benchmarks were run.**

## Summary — before/after, measured from real translated blocks

All four numbers below are read directly off `gdb`-disassembled host code at
the addresses named in a live `FEX_BLOCKJITNAMING=1` perf map
(`/tmp/perf-<pid>.map`), for a hand-built static ELF64 guest binary compiled
with `FEX_MULTIBLOCK=0` so each guest op landed in its own compiled unit.
Counts exclude the fixed per-block prologue (RIP-check trampoline, state
flags store) and the block-exit dispatch stub (guest-RIP-constant load +
block-cache lookup + link/dispatch branch) — the same convention
scalar-fp-lowering.md uses — leaving only the instructions the target op
itself emits.

| site | before | after | mechanism |
|---|---:|---:|---|
| `movss xmm,xmm` (reg-reg) | 14 | **2** | `vperm` + inline 2×64-bit control build → `xxsldwi` pair |
| `blendps xmm,xmm,0x8` (reg-reg, DestIdx=SrcIdx=3) | 14 | **2** | same, new symmetric fast-path case |
| `cvttss2si eax,xmm` | 26 | **12** | dispatcher `MaxF/MaxI/_Select` wrapper deleted; backend op used directly |

The "before" column was captured by `git stash`-ing just the two changed
files, rebuilding, and re-running the identical guest binary — not
transcribed from the prior report — so it is a direct A/B measurement, not a
citation.

## Fix 1 — reg-reg `movss`/`blendps`: generic `VInsElement` → `xxsldwi` pair

### What changed

`FEXCore/Source/Interface/Core/JIT/PPC64LE/VectorOps.cpp`,
`DEF_OP(VInsElement)`: added a fast path before the generic vperm-with-inline-control
strategy, for `ElemSz == i32Bit && DestIdx == SrcIdx && (DestIdx == 0 ||
DestIdx == 3)`.

Derivation (LE element `E` ↔ BE word index `W` via `W = 3-E`, the same
mapping the pre-existing `i64Bit` case in this function documents for
doublewords): `xxsldwi(T,A,B,s)` takes 4 consecutive BE words from the
8-word concatenation `[A.w0..A.w3, B.w0..B.w3]` starting at word `s`. A
window of length 4 starting at `s=1` or `s=3` is the only place a 4-word
window holds exactly one word from one operand and three from the other —
i.e. exactly the two ends of the concatenation, which are LE element 3
(`W=0`) and LE element 0 (`W=3`). Middle elements (LE 1, 2) have no such
2-instruction form; they keep using the untouched generic path.

```
DestIdx=SrcIdx=0: xxsldwi(VTMP1, SrcVec, DestVec, 3); xxsldwi(Dst, VTMP1, VTMP1, 1)
DestIdx=SrcIdx=3: xxsldwi(VTMP1, DestVec, SrcVec, 1); xxsldwi(Dst, VTMP1, VTMP1, 3)
```

Both write `Dst` only after fully consuming `DestVec`/`SrcVec` into the
scratch register, so `Dst` may alias either source — proven by the
self-aliasing rows in the differential test below, not just asserted.

Two dispatcher call sites hit this automatically, with no dispatcher change
needed: `MOVScalarOpImpl`/`VMOVScalarOpImpl` (`movss`/`movsd`/`vmovss`
reg-reg, `OpcodeDispatcher/Vector.cpp:198`) emit `VInsElement(i32, 0, 0)` for
the SS case, and `VectorBlend`'s `blendps` imm8 bit-0 and bit-3 selectors
(`Vector.cpp:3851`, `:3901`) emit the `(0,0)` and `(3,3)` cases respectively.
`movsd` reg-reg (`i64Bit`) already had a 1-instruction `xxpermdi` special
case and was not touched.

### Why not generalize to the middle lanes

Checked and rejected: `blendps` imm8 bit-1 (`DestIdx=SrcIdx=1`) and bit-2
(`DestIdx=SrcIdx=2`) go through the same generic `VInsElement` byte-perm
path today. The `xxsldwi`-window argument above shows there is no 2-instruction
form for them — any 4-word window that isn't at a concatenation boundary
mixes 2+2 words from each operand, which a single subsequent self-rotate
cannot untangle into "3 unchanged + 1 replaced." These stay on the
untouched generic path; the differential test's XMM5/XMM6 rows exist
specifically to prove the new condition's `(DestIdx == 0 || DestIdx == 3)`
guard didn't also (mis-)catch them.

## Fix 2 — `cvttss2si`/`cvttsd2si`/`cvtss2si`/`cvtsd2si` sentinel dedup

### What changed

`FEXCore/Source/Interface/Core/OpcodeDispatcher/Vector.cpp`,
`CVTFPR_To_GPRImpl`: added a `#ifdef ARCHITECTURE_ppc64le` early return before
the `SupportsFRINTTS`/else split, calling the backend op directly:

```cpp
return HostRoundingMode ? _Float_ToGPR_S(GPRSize, SrcElementSize, Src)
                        : _Float_ToGPR_ZS(GPRSize, SrcElementSize, Src);
```

`HostFeatures.SupportsFRINTTS` (`FEXCore/include/FEXCore/Core/HostFeatures.h:53`)
defaults false and is only ever set from ARM ISAR1 feature detection
(`Source/Common/HostFeatures.cpp:329`); it is never set on ppc64le. So this
backend always fell through to the `!SupportsFRINTTS` branch — the "ARM
lacks a saturating-to-x86-sentinel convert" fallback — wrapping the backend's
own convert in a redundant `LoadAndCacheNamedVectorConstant` +
`_Select(CondClass::FGT, ...)`.

This applies to all four sentinel-producing paths that share
`CVTFPR_To_GPRImpl`: `cvttss2si`/`cvttsd2si` (`HostRoundingMode=false`,
truncating, → `Float_ToGPR_ZS`) and `cvtss2si`/`cvtsd2si`
(`HostRoundingMode=true`, host-rounding, → `Float_ToGPR_S`) — both `si`
(32-bit dest) and `si` with REX.W (64-bit dest), both `ss` and `sd` sources.
There is no separate unsigned (`ui`) family in this dispatcher; x86 has no
legacy SSE `cvttss2usi`, only an AVX-512 form this backend does not target,
so "check the `ui` variant" turned up nothing to change.

### Exactness proof (why the wrapper is provably dead code here)

`Float_ToGPR_ZS` (`ALUOps.cpp:4200`) promotes the source to f64 (exact: every
f32 and every value in x86's convert range is exact in f64), compares it
against the f64-exact bound (`2^31` or `2^63`, both exactly representable in
f64) via `xscmpudp` into `cr1`, then runs `xscvdpsxws`/`xscvdpsxds` — POWER's
saturating round-to-zero convert — and overwrites the result with the x86
integer-indefinite sentinel (`0x80000000`/`0x8000000000000000`) whenever
`cr1.LT` is *not* set (i.e. `Src >= bound` or unordered). Enumerating every
case x86's `CVTTSS2SI` defines (SDM Vol. 1 §4.8.3, `CVTTSS2SI` in Vol. 2):

| case | POWER's `xscvdpsxws`/`ds` alone gives | x86 wants | fixup needed? |
|---|---|---|---|
| in range, finite | truncated value | same | no — passthrough is correct |
| exact boundary (`INT_MIN`, in range) | saturates to `INT_MIN` bit pattern | same bits (coincidentally == sentinel) | no |
| positive overflow (`>= bound`, finite) | saturates to `INT_MAX` (`0x7FFFFFFF`) | sentinel (`0x80000000`) | **yes — this is the only case that changes anything** |
| negative overflow (`< -bound`) | saturates to `INT_MIN` bit pattern | sentinel (same bits) | no — POWER's own negative saturation already matches |
| NaN (quiet or signaling) | ISA: convert-from-NaN saturates to most-negative | sentinel (same bits) | no |
| ±0.0 (incl. `-0.0`) | 0 | 0 | no |
| denormal | truncates to 0 (in range) | 0 | no |

So the `cr1.LT`-gated overwrite the backend op already does is *exactly* the
one case (positive overflow) where POWER's native saturation and x86's
sentinel disagree — the wrapper's `MaxF/MaxI/_Select` can only ever recompute
the same `cr1.LT`-equivalent comparison a second time and select between
values that are already equal in every case but that one, which the backend
op already handles. This is reasoning from the ISA semantics, not trust —
it's also why the differential test below specifically targets the
positive-overflow rows (`1e30f`, `2^31`-as-f64, `2^63`-as-f64): those are the
only rows that would go *silently* wrong (return a plausible-looking
`INT_MAX` instead of the sentinel) if this analysis were mistaken.

## Differential test

New project-native ASM tests (nasm + `TestHarnessRunner`, the same convention
as `unittests/ASM/FEX_bugs/xvcv_convert_edges.asm`), all under
`unittests/ASM/FEX_bugs/`, each row's expected value computed with Python
`struct.pack`/`int()` against the documented x86 semantics, not hand-derived:

- `cvttss2si_sentinel_edges.asm` — 12 checks: normal truncation (`3.75`,
  `-3.75`), QNaN, SNaN, ±Inf, huge finite overflow (`1e30f`/`-1e30f`, both
  dest sizes), `-0.0`, min denormal, in-range 64-bit dest.
- `cvttsd2si_boundary_edges.asm` — 10 checks: the exact `±2^31`/`±2^63`
  boundaries from both sides (in-range vs. one-ULP-out, at both integer
  widths — doubles have enough mantissa to hit these exactly, no rounding
  ambiguity in the test vectors themselves), NaN, `-0.0`.
- `cvt_hostround_sentinel.asm` — 6 checks: the `HostRoundingMode` (`cvtss2si`/
  `cvtsd2si`, round-to-nearest-even) path — confirms the `Float_ToGPR_S`
  branch of the new ternary and its independent fixup are equally exact,
  and that rounding direction (`2.5→2`, `3.5→4`) is unaffected.
- `movss_blendps_vinselement.asm` — 8 XMM-state checks: `movss` reg-reg
  (dest≠src and self-aliased), `blendps 0x1`/`0x8` (dest≠src and, for `0x8`,
  self-aliased), `blendps 0x2`/`0x4` (untouched generic-path regression
  check), `movsd` reg-reg (untouched `i64Bit` path, sanity).

Results, `ctest -R` on all three JIT test variants the suite runs
(`jit_1`/`FEX_MAXINST=1`, `jit_500`, `jit_500_m`/multiblock):

```
100% tests passed, 12/12 (the four new files x 3 variants)
```

Full existing regression suite (all 2268 non-skipped `jit_500` ASM tests,
`ctest -R 'jit_500/.*\.asm$'`): **100% passed**, same 9 pre-existing skips as
before this change (`Known_Failures`/`Disabled_Tests`-listed, unrelated to
these two ops). Re-run with `FEX_HOSTFEATURES=disableisa30` (this backend's
existing runtime gate for forcing the POWER8 codegen selection even on this
POWER9 host — see POWER8 legality below): **100% passed**, identical result.

### Negative controls

Both fixes were deliberately broken, confirmed to fail exactly the rows the
mechanism should affect, then reverted and re-confirmed green — proving the
test suite can actually detect a regression in what was just changed, not
just that it happens to pass:

1. **Fix 1**: changed the `DestIdx==0` case's second shift from `xxsldwi(Dst,
   VTMP1, VTMP1, 1)` to `..., 2)`. Result: `movss_blendps_vinselement.asm`
   failed on exactly `XMM0`, `XMM1`, `XMM2` (the three `(0,0)` rows —
   dest≠src, self-alias, and the `blendps 0x1` call site) while `XMM3`
   through `XMM7` (the `(3,3)`, untouched-generic, and `i64Bit` rows)
   remained correct. Reverted; all rows green again.
2. **Fix 2**: changed the ternary to unconditionally call `_Float_ToGPR_ZS`
   regardless of `HostRoundingMode`. Result: `cvt_hostround_sentinel.asm`
   failed on exactly the rounding-direction row (`3.5f` truncated to `3`
   instead of rounding to `4`; `2.5f` happened to still read `2` either way,
   since round-to-even and truncate agree there) while the other three test
   files (sentinel edge cases, unaffected by which backend op is called)
   stayed green. Reverted; all rows green again.

## POWER8 legality

Both fixes emit **only `xxsldwi`** as new instructions (Fix 2 emits no new
instructions at all — it deletes the wrapper's `LoadAndCacheNamedVectorConstant`/
compare/`_Select` sequence). `xxsldwi` (VSX Vector Shift Left Double by Word
Immediate) is listed in the POWER ISA v3.0C reference at
`powerpc64le-ports/flap-standalone/docs/power9/isa/PowerISA_public.v3.0C.pdf`
(via `pdftotext`) as:

```
111100 ..... ..... ..... 0..00 010...   XX3   I   781   xxsldwi   v2.06   VSX Vector Shift Left Double by Word Immediate
```

`v2.06` is POWER7 — a strict subset of POWER8's ISA 2.07 — so it needs no
version gate. This is also load-bearing evidence, not just a spec citation:
`xxsldwi` is already the instruction the pre-existing, shipping
`DEF_SCALAR_INSERT` scalar-merge sequence in the same file uses (the "sitting
a page away" 2-instruction pair scalar-fp-lowering.md §6.3 pointed at), which
the analysis it cites already measured running correctly on the POWER8
co-developer box. No `#ifdef ARCHITECTURE_ppc64le` / `SupportsISA30` gate was
added because none was needed — confirmed directly, not just inferred, by
re-running the full ASM suite (and the four new differential tests) with
`FEX_HOSTFEATURES=disableisa30`, this backend's actual runtime mechanism for
forcing the pre-ISA-3.0 codegen path on a POWER9 host (`HostFeatures.h:65`,
`HostFeatures.cpp:490`; see also the `SupportsISA30`-gated paths already
present elsewhere in `VectorOps.cpp`/`ALUOps.cpp` for other ops, which this
change does not touch). Result: 100% pass, identical to the ISA30-enabled
run — if either fix had depended on a POWER9-only instruction, this run
would have `SIGILL`'d or produced a wrong count on a real POWER8 box, and it
did not need to, since neither fix reads or branches on `SupportsISA30` at
all.

## Commits

- Companion analysis (read, not modified): wine-upstream `b0b58acd0c2`
  (`scalar-fp-lowering.md`), `24700818666` (`x86-vector-in-the-wild.md`).
- `fastppcx86` branch `power9team`, prior HEAD `5b3576d23`. This work: see
  the commit introducing this file and the `VectorOps.cpp`/`Vector.cpp`
  changes plus the four new `unittests/ASM/FEX_bugs/*.asm` files, same
  branch, not pushed (per ground rules — local commit only).

## What was NOT changed, and why

- The generic `VInsElement` vperm path for all other `(DestIdx, SrcIdx)`
  combinations and element sizes: no 2-instruction form exists for them (see
  Fix 1's derivation); untouched.
- The register-residency/splat-domain scalar-arithmetic lowering
  scalar-fp-lowering.md already found correct and deliberate: not touched,
  per that report's explicit "what not to do."
- No unsigned (`ui`) convert variants exist in this dispatcher to fix.
- No POWER9-only instruction was introduced, so no POWER8 fallback needed to
  be written — the user's standing offer to build both an ISA-3.0 path and a
  gated POWER8 fallback wasn't needed here, but stays the right move if a
  future op in this family turns out to need it.
