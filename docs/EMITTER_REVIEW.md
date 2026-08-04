# Adversarial review: PPC64LE emitter + backend emission patterns

Reviewer: Claude Fable, 2026-08-04, tree at 33bc66759. Method: instruction
inventory vs ISA, caller counts for powerful-but-idle instructions, reading
the hot DEF_OPs adversarially, and hardware facts from tonight's agent work.
Discipline note: one early "finding" (isel unused) was FALSE — the Select
lowering uses it with measured justification ("5.7 ns/op loss" for the
branchy alternative, marked SETTLED). Verify every negative.

MACHINE FACT (verified /proc/cpuinfo): op4k is POWER8 (PVR 004d 2.0).
Agent reports calling it POWER9 were wrong. Consequences: the vcmp fusion's
1.3%-slower measurement IS the POWER8 number (off-by-default stands, its
"re-measure on P8" caveat is void); any ISA 3.0 emission is for the
co-dev's machine only, behind runtime gating.

## STATUS (2026-08-04, tree ecaf17103): findings 1, 2(staging), 5, 6 DONE;
## finding 3 closed as FALSE LEAD both halves (splats already 1-insn incl.
## the P8 vspltd gap via xxpermdi; loads already size-dispatched, small
## offsets collapse to li). Full ctest + regression battery: only the
## pre-existing ssse3-psign baseline failures. Remaining open: finding
## 2(a) per-block constant pool for the perm controls that still need
## LoadConstant pairs (now stall-free via mtvsrd but still 10+ insns for
## arbitrary 128-bit ctrls); finding 4 (P9 tier, co-dev's machine);
## VTESTPS record-form treatment (same as PTEST but sign-bit semantics);
## AVX-256 scan shape; co-dev's shuffle dispatcher gate.

## ERRATA applied (2026-08-04, from the co-dev's response)
- Finding 4 UPGRADE: the staging-pattern kill did NOT need the P9 tier —
  mtvsrd(2.07)+xxpermdi(2.06) are P8-legal and were already in the emitter.
  Implemented across the tree the same night (stages 3-4); the dm-selector
  and byte-order were validated by the full ASM suite rather than derived
  alone. The P9 tier note now covers only lxv/stxv/mfvsrld/xxperm/setb/
  maddld/mtvsrdd-as-single-insn.
- Finding 7 CORRECTED per their measured counterexample (ExitFunction = 50%
  of emitted bytes, 0.55% of runtime): byte-ranking surfaces large-but-cold
  ops and hides small-but-hot ones (C-helper calls look free). The size
  profile is authoritative for per-op expansion and buffer-capacity
  questions ONLY. For "what to fix next": weight by EXECUTION (perf cycles
  per symbol/region), and treat compile-count fields as compile counts.
- Finding 1, 64-bit path: answered by code shape — the i64 loaders never
  had the reverse vperm (their comments predate this review and say "no
  byte-reverse needed"); only the 128-bit path carried it, and only it was
  deleted. The probe + full suite cover the deletion; no 64-bit gap exists.

## Ranked findings

1. **[HARDWARE-PROVEN, unfixed] LoadNamedVectorConstant's byte-reverse vperm
   is an identity permute** — ~14 wasted instructions on EVERY 128-bit
   named-constant load, across many ops. Proven by lnvc_probe.c (agent 1,
   2026-08-03). Deletion is small but touches broad codegen — was left as
   the co-dev's call. HIGHEST measured-value item in this review.

2. **[VERIFIED shape] Per-emission construction of vector control constants.**
   VAddP (VectorOps.cpp:1804) builds TWO 128-bit perm controls per emission
   via 2×(LoadImm64 5-insn + std) + addi + lvx ≈ 30 insns; the same pattern
   recurs in shuffle lowerings. Systemic fix candidates, in order:
   (a) per-block (or per-code-buffer) constant pool with a dedicated pool
   base register — controls become 1×lvx after first use; (b) lvsl-generated
   controls where the pattern allows (proven tonight: lvsl performs no load,
   is NOT LE-byte-reversed, needs no pool); (c) at minimum, dedupe identical
   controls within a block. Note the co-dev's related dispatcher finding:
   Single128Bit4ByteVectorShuffle's ~44 ARM64-tuned cases assume 1-insn
   zip/rev/ext and select IR that costs MORE than the generic path here —
   their fix (fewer IR ops selected on POWER) composes with this one.

3. **[VERIFIED gaps, P8-legal] Missing ISA 2.06/2.07 forms in the emitter:**
   lxvw4x (word-arranged VSX load), xxspltw (splat word, 1 insn — current
   splats go through longer sequences; check DEF_OP(VDupElement)), cnttzd is
   ISA 3.0 (skip). Each is a small add; payoff depends on caller sites —
   measure with FEX_JITOPSIZEPROFILE before/after.

4. **[INVENTORY, P9-gated tier for co-dev's machine] Absent ISA 3.0 forms
   worth runtime-gating:** mtvsrdd (GPR pair→VSR in 1 insn — replaces the
   std+std+lvx staging pattern wholesale), lxv/stxv D-form, mfvsrld, xxperm
   (2-src permute without the VRT=VC copy dance), setb, maddld, addpcis.
   The staging-pattern kill (mtvsrdd) is the big one: grep std.*lvx staging
   sequences; every one is 4+ insns → 1 on P9.

5. **[LEAD, unmeasured] Record-form coverage now exists (Rc twins from the
   fusion work) but only vcmpequ*. PTEST/VPTEST-style guest idioms and
   any "compare then branch on all/none" IR could use CR6 directly without
   the fusion machinery — audit PTest lowering.

6. **[LEAD] VRev64 = 15 instructions** (per co-dev). On P8, xxpermdi +
   vperm-with-cached-control should be ≤3 with finding 2's pool; on P9,
   xxbrd is 1 (gated). Blocked on finding 2 for the cheap form.

7. **[PROCESS] The JITOpSizeProfile infrastructure exists (build-gated,
   FEX_JITOPSIZEPROFILE) and is the right tool for prioritizing: run it on
   a real game session, rank total bytes by IR op, attack the top. Tonight's
   wins (VAddP relocation, PMADDWD) were found exactly this way by the
   agents. A standing "top-10 by emitted bytes" measurement per title
   belongs in the perf workflow.

## Finding 5 implementation design (PTest via record-form) — IN PROGRESS

Current PTestOpImpl (Vector.cpp:4121): VAnd + VAndn + 2×VUMaxV(horizontal!)
+ 2×VExtractToGPR + To01 → ~30+ insns, two VSU→FXU crossings.
Plan: new IR op `GPR = VAnyNonZero V:$Vector` (JITDispatch:false,
hand-registered like VExtractSignBits). ppc64le lowering:
  vspltisb VTMP1, 0
  vcmpequb_rc VTMP2, Src, VTMP1     (Rc twin exists)
  mfocrf TMP, 0x02                  (CR6 field; check emitter has mfocrf)
  rlwinm TMP, TMP, 25, 31, 31      (CR6 bit0 "all lanes equal"=all-zero → LSB)
  xori   Dst, TMP, 1               (→ any-nonzero 0/1)
Dispatcher: #ifdef ARCHITECTURE_ppc64le in PTestOpImpl:
  T1 = VAnyNonZero(VAnd(Dest,Src)); T2 = VAnyNonZero(VAndn(Src,Dest));
  SetNZ_ZeroCV(i32, T1) (0/1: Z iff zero, N always clear — semantics
  preserved); SetCFInverted(T2) directly (already 0/1, To01 skipped);
  ZeroPF_AF(). AVX 256-bit path (AVX_128.cpp): VOr halves first, same ops.
Validate: ASM suite ptest/vtestps cases + full jit subset.

## Next steps (continuation)
- Measure: JITOpSizeProfile a Ziggurat session on 33bc66759; rank.
- Read PTest/VDupElement/VInsElement/shuffle lowerings adversarially (the
  remaining unread hot vector ops).
- Prototype finding 2(a) constant pool: scope = emitter helper + block
  prologue; measure on the profile's top shuffle-heavy ops.
- Hand findings 1 (approval) + 4 (P9 tier) + dispatcher-gate item to co-dev.
