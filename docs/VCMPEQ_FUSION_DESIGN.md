# Vector-scan fusion: `pcmpeqb ; pmovmskb ; test ; jcc` → `vcmpequb. ; bc`

PPC64LE (POWER8) backend. Status: implemented, gated by `FEX_VCMPFUSION` (default on).

---

## 1. The problem

Every string primitive in glibc — `strlen`, `strchr`, `strrchr`, `memchr`, `strcmp`,
`strstr`, `rawmemchr` — has the same inner loop:

```asm
L(loop):
    movdqa   (%rax), %xmm0
    pcmpeqb  %xmm1, %xmm0        ; xmm1 = the byte we are hunting (often zero)
    pmovmskb %xmm0, %edx         ; one bit per byte lane
    test     %edx, %edx
    jnz      L(found)
    add      $16, %rax
    jmp      L(loop)
```

On x86 that is four instructions and the `pmovmskb` is a single-cycle-ish move.
On POWER8 there is no `pmovmskb`. FEX lowers it as a *reduction*:

| IR op | POWER8 expansion |
| --- | --- |
| `VCMPLTZ` (sign bits) | `vspltisb`/`vcmpgtsb` |
| `VAnd` with `NAMED_VECTOR_MOVMASKB` | constant materialisation (`lvx`/`xxspltib`+shifts) + `vand` |
| `VAddP` ×3 (pairwise adds, 128→64→32) | POWER8 has no pairwise add: each is a `vperm`/`vpkudum`-style shuffle **plus** an add, and the permute control vectors themselves have to be materialised |
| `VExtractToGPR` | `mfvsrd` (or a stack round-trip on the pre-ISA-3.0 path) |

The other team measured the whole block at **~105 host instructions**. Worse than
the count: `VExtractToGPR` is a **VSU→FXU transfer**. On POWER8 that is a
long-latency crossing, and it sits directly in the loop-carried dependency of
the branch — the loop cannot resolve `jnz` until the mask has crossed units.

POWER8 already answers this question in hardware. The record form of the VMX
integer compares (`vcmpequb.`, `vcmpequh.`, `vcmpequw.`, `vcmpequd.`) writes
condition register field 6:

```
CR6[0]  (CR bit 24) = 1  iff EVERY lane compared equal
CR6[1]  (CR bit 25) = 0
CR6[2]  (CR bit 26) = 1  iff NO lane compared equal
CR6[3]  (CR bit 27) = 0
```

`bc` reads CR bits directly. So the entire idiom is expressible as:

```asm
    vcmpequb. v30, vA, vB       ; v30 = VTMP1, discarded
    bc 4, 26, L(found)          ; branch if CR6[2] clear == some lane matched
```

Two instructions, no GPR involved, no VSU→FXU crossing on the loop back edge.

---

## 2. Constraints, verified

Each of the four constraints handed over from the other team was checked against
this tree (base `15b130fde`).

**(a) `EmitVX` always writes Rc=0 — CONFIRMED, but it is not a code defect.**
`CodeEmitter/PPC64LE/Emitter.h:1694` is

```cpp
void EmitVX(uint32_t vrt, uint32_t vra, uint32_t vrb, uint32_t xo) {
  Emit32((4u << 26) | (vrt << 21) | (vra << 16) | (vrb << 11) | xo);
}
```

`xo` is spliced in as the low **11** bits. In VC-form the 10-bit XO sits at
bits 22..31 with Rc at bit 21 — i.e. immediately above XO — so the record form
is just `XO | 0x400`. `EmitVX` needed no change at all; only the mnemonic
wrappers (`vcmpequb(...)` passes `6`) hard-code Rc=0. Added record-form twins
`vcmpequb_`/`vcmpequh_`/`vcmpequw_`/`vcmpequd_` rather than an `Rc` parameter on
`EmitVX`, because every one of `EmitVX`'s ~120 other callers wants Rc=0 and a
defaulted parameter would make the record form the thing you get by *forgetting*
something.

**(b) No IR op for "vector compare → flags" — CONFIRMED.** `IR.json` has
`VCMPEQ`/`VCMPGT`/`VCMPEQZ`/... all of which produce an `FPR`. Nothing in the IR
lets a *branch* consume a vector comparison. There is also no "any lane set"
reduction op. This is genuine multi-op fusion.

**(c) The mask has consumers beyond the test+jcc — CONFIRMED, and it is worse
than "may have".** The mask register is architecturally visible. Even in the
loop, `%edx` is a guest register: FEX's register cache will store it to
`CPUState.gregs` at any flush. Eliding it is therefore *never* a pure
use-count question — an SSA use-count of 1 does not make the guest register
write disappear. Section 5 explains how it is elided soundly anyway.

**(d) Precedents — CONFIRMED.**
* `OpcodeDispatcher/Vector.cpp:VectorXOROp` is the xor-zero peephole: it
  inspects `Op->Dest`/`Op->Src[0]` of the *same* instruction. Single-op, and
  therefore no help for the structural problem here (lookahead).
* `Core.cpp::GenerateIR` already runs per-instruction hooks against
  `DecodedInfo` — the `FEX_SMCSEMANTICPATCH` mov-imm work calls
  `SetPatchableImmSite()` before `std::invoke(Fn, ...)`. Same shape as the
  lookahead window added here.
* `IR.json` `OP_CONSTANT`'s trailing defaulted `PatchSite` field shows that
  growing an existing op is safe and cheap.

---

## 3. Chosen design

### 3.1 IR: grow `CondJump`, do not add an op

```
CondJump SSA:$Cmp1, SSA:$Cmp2, SSA:$TrueBlock, SSA:$FalseBlock,
         CondClass:$Cond{NEQ}, OpSize:$CompareSize{iInvalid}, i1:$FromNZCV{false},
         OpSize:$VCmpElementSize{iInvalid}
```

`VCmpElementSize != iInvalid` selects a third mode (alongside plain compare and
`FromNZCV`): `Cmp1`/`Cmp2` are **FPR-class** values, compared lane-wise for
equality at that element size, and the branch is taken on

* `Cond == NEQ` → **any** lane matched → `TrueBlock`
* `Cond == EQ` → **no** lane matched → `TrueBlock`

`NEQ`/`EQ` are not arbitrary: they are exactly the conditions the guest
`test %edx,%edx ; jnz/jz` expresses, so the frontend passes the guest condition
straight through with no inversion table.

**Why not a new op** (`CondJumpVCmp`, or the suggested
`GPR = VAnyLaneEQ` + existing `CondJump`)?

The IR's control-flow ops are special-cased by name in five places:

| site | what it does |
| --- | --- |
| `IREmitter.cpp:IsBlockExit` | terminator classification |
| `Passes/IRValidation.cpp:172` | builds `Successors` / `Predecessors` |
| `Passes/RedundantFlagCalculationElimination.cpp:708` | builds the CFG for global flag liveness |
| same file `:540` | seeds `FlagsRead` from the successors' flag sets |
| same file `:750` | `FoldBranch` |

A new op means five edits, each of which fails *silently and non-locally* if
missed — a block whose terminator the dead-flag pass does not recognise gets
`FlagsRead = FLAG_ALL` (harmless) or, at `:708`, no CFG edges at all (not
harmless: flag writes upstream of the branch become eligible for deletion). By
reusing `CondJump` all five keep working untouched, and the *only* code that
must notice the new mode is the one backend that lowers it. That is the
difference between "the pass needs to be taught" and "the pass cannot tell".

Verified interactions of piggy-backing on `CondJump`:

* `"Inline": ["", "AddSub"]` makes the generated `_CondJump` call
  `Cmp2 = InlineAddSub(OpSize::i64Bit, Cmp2)`. `DEF_INLINE` only fires when
  `IsValueConstant(...)`, which an FPR-defined value never is. No-op.
* `RAOverride: 2` → `GetRAArgs(OP_CONDJUMP) == 2`, so args 0/1 are ordinary RA
  uses. Register *class* comes from each arg's defining op
  (`WalkFindRegClass`), so FPR args get FPR registers with no further work.
  This is the single reason the reuse is possible at all.
* `FoldBranch` (which would rewrite args 0/1 out from under us) is guarded by
  `if ((FlagsOut & FLAG_NZCV) == 0 && Op->FromNZCV)`. Our op has
  `FromNZCV == false`, so it is never reached. **No edit needed — but this is a
  latent trap**: if someone ever relaxes that guard, `FoldBranch` will happily
  replace our two vector operands with a compare's GPR operands. Noted in
  §8 as a follow-up (an explicit `VCmpElementSize == iInvalid` assertion in
  `FoldBranch` is cheap insurance).
* `HasSideEffects: true` already prevents DCE.

**Why not `GPR = VAnyLaneEQ` feeding an existing `CondJump`?** Because that
design *reintroduces the thing we are removing*. Lowering it needs
`vcmpequb. ; mfocrf rX, 0x02 ; rlwinm rX, rX, ...` and then the existing
`CondJump` emits `cmpldi cr7, rX, 0 ; bc`. That is 4–5 instructions instead of
2, and `mfocrf` after a vector compare is *precisely* the VSU→CR→FXU crossing
whose latency motivated the whole exercise. It is only attractive if you want
the boolean as a value (e.g. for `sete`), which no part of this idiom does.
(`setbc` would make it 3 instructions and is POWER10 — not an option.)
A `VAnyLaneEQ` op remains the right shape for a *future* `pcmpeqb ; pmovmskb ;
cmp $0xffff` / `setz` idiom; it is not the right shape for a branch.

### 3.2 Backend lowering

`FEXCore/Source/Interface/Core/JIT/PPC64LE/BranchOps.cpp::DEF_OP(CondJump)`
grows a leading arm:

```cpp
if (Op->VCmpElementSize != IR::OpSize::iInvalid) {
  const auto V1 = GetVReg(Op->Cmp1);
  const auto V2 = GetVReg(Op->Cmp2);
  switch (Op->VCmpElementSize) {
  case i8Bit:  vcmpequb_(VTMP1, V1, V2); break;
  ...
  }
  CC = (Op->Cond == NEQ) ? Cond{4, 26} : Cond{12, 26};
}
```

then falls into the existing `bc InvertCond(CC), &Skip; b True; Skip: b False`
tail, so long-branch handling, backward-edge suspend pokes and block linking are
all inherited rather than re-implemented.

* `VTMP1` (`v30`) absorbs the VRT the ISA forces us to write. All FEX vector
  values on this backend live in VMX-addressable `v0..v31`
  (`x64::SRAFPR`/`x64::RAFPR`), so no VSX→VMX shuffling is needed to feed
  `vcmpequ*.`.
* `BI = 26` is CR6's "no lane matched" bit (CR field 6 = CR bits 24..27,
  field-relative bit 2). `BO = 4` branches when the bit is *clear*, i.e. some
  lane matched.
* **CR6 is otherwise unused by this backend** — verified by grep: the JIT uses
  CR0 for the packed-NZCV side channel and CR7 for scratch compares. So the
  record form clobbers nothing.

### 3.3 Backend gating

`HostFeatures::SupportsVCmpFlagBranch`, set `true` only inside the
`#ifdef ARCHITECTURE_ppc64le` block of `Source/Common/HostFeatures.cpp`. The
frontend refuses to emit the mode without it, and
`CondJumpVCmpAnyLaneEQ()` carries a `LOGMAN_THROW_A_FMT` on it. It is a
*backend capability* flag, not a CPU feature — record-form VMX compares are ISA
2.03, i.e. present on every POWER part FEX can run on, so there is nothing to
probe. Deliberately **not** wired into `FEX_HOSTFEATURES`: one A/B knob
(`FEX_VCMPFUSION`) is better than two that can disagree.

---

## 4. Matching window

Four **contiguous** instructions inside **one decoded block**:

```
  i+0   pcmpeq{b,w,d} xmmSrc, xmmDst      <- the handler being dispatched
  i+1   pmovmskb      r32,    xmmDst
  i+2   test          r32,    r32
  i+3   jz | jnz      rel                 <- necessarily the block's last insn
```

**Why four and not more or fewer.** Four is the whole idiom and the window
cannot usefully be shorter: the payoff only exists if the *branch* consumes the
comparison, so the `jcc` must be inside it. It cannot usefully be longer either
— the `jcc` terminates the decoded block by construction, so there is nothing
after it to absorb. Contiguity is required because anything between `pcmpeqb`
and the `jcc` could read the mask register or clobber a source vector, and
proving otherwise means a dataflow analysis that a 4-slot structural match does
not need. The window is a straight line with no memory operands after slot 0,
so there is no fault or side effect to preserve ordering against.

**How the window is obtained.** `ContextImpl::GenerateIR` calls
`Thread->OpDispatcher->SetDecodeWindow(&Block, i)` immediately before
`std::invoke(Fn, ...)` — same hook point as the existing
`SetPatchableImmSite()` SMC call. The handler reads
`Block.DecodedInstructions[i+1..i+3]` directly. After dispatch, `GenerateIR`
calls `ConsumeFusedInstructionCount()` (destructive read, so a stale count can
never be applied twice) and, if non-zero, advances `i`,
`BlockInstructionsLength`, `TotalInstructionsLength` and `TotalInstructions`
over the swallowed instructions and re-points `DecodedInfo` at the *last* one,
because the loop tail uses it for `FinishOp`'s next-RIP.

**Identification is by bound handler, not by opcode bytes:**

```cpp
Handler(MovMsk) == &OpDispatchBuilder::MOVMSKOpOne
Handler(Test)   == &OpDispatchBuilder::Bind<&OpDispatchBuilder::TESTOp, 0>
Handler(Jcc)    == &OpDispatchBuilder::CondJUMPOp
```

This is exact — it cannot be fooled by a prefix combination that reaches a
different table entry, and it tracks table edits automatically. Re-decoding
opcode bytes would have to duplicate the decoder's prefix/escape logic.

### Every bail-out

| # | Condition | Why |
| --- | --- | --- |
| 1 | `!VCmpFusion()` | `FEX_VCMPFUSION=0` escape hatch / A-B switch. |
| 2 | `!HostFeatures.SupportsVCmpFlagBranch` | Backend cannot lower the mode; another backend would treat two FPR values as GPRs and mis-compile. |
| 3 | `DecodeWindowBlock == nullptr` | `GenerateIR` withholds the window in two modes (see below). |
| 4 | `!Is64BitMode` | 32-bit guests need `CondJUMPOp`'s 4GB target-wrap arithmetic; duplicating it means a second, differently-tested path for a case whose payoff (x86-64 glibc) is elsewhere. Coverage loss, documented. |
| 5 | `RegisterSize != i128Bit` | Rejects the MMX form (which shares `MOVMSKOpOne`) and the 256-bit AVX form. See §7. |
| 6 | `!Op->Dest.IsGPR()` | The PCMPEQ destination must be a register so we can name it when matching the PMOVMSKB source. |
| 7 | `&Block.DecodedInstructions[Index] != Op` | Self-check that the window and the dispatched instruction are in step. Cheap insurance against `GenerateIR` and the dispatcher drifting apart. |
| 8 | `Index + 3 >= Block.NumInstructions` | The idiom is split across blocks; there is nothing to fuse. |
| 9 | handler mismatch at `i+1`, `i+2`, `i+3` | Not the idiom. Also rejects `TableInfo->Type != TYPE_INST` (union member `Indirect` would otherwise be read as a member-function pointer). |
| 10 | `FLAG_LOCK`/`FLAG_REP_PREFIX`/`FLAG_REPNE_PREFIX` on any follower | We are reimplementing these three by hand; a prefix we are not modelling would change semantics we would then get wrong. |
| 11 | PMOVMSKB source `!= ` PCMPEQ dest XMM, or either is not a register | Not the idiom / mask is not derived from our comparison. |
| 12 | `OpSizeFromSrc(MovMsk) != i128Bit` | MMX `movmskb` (64-bit source) shares the handler. |
| 13 | `MaskGPR.HighBits` | `%ah`-style encodings never arise here; refuse rather than reason about them. |
| 14 | TEST is not reg-reg on exactly the mask GPR | A different register, a memory operand, or a partial-width test means the flags we synthesise would not match. |
| 15 | `OpSizeFromDst(Test) != i32Bit \|\| OpSizeFromSrc(Test) != i32Bit` | An 8/16-bit test would see only part of the mask; a 64-bit test differs in SF. Only the 32-bit self-test is provably equivalent to "any lane matched". |
| 16 | `(Jcc.OP & 0xF)` not 4 or 5 | JZ/JNZ are the only conditions that read nothing but ZF, i.e. the only ones expressible as "did any lane match". `jle` after `test` also reads SF/OF and is not. |
| 17 | `!Jcc.Src[0].IsLiteral()` | Indirect/relocated branch target. |
| 18 | **`TargetRIP <= Jcc.PC`** (backward taken edge) | **The subtle one.** See §5.3. |

And two bail-outs enforced on the `GenerateIR` side by simply not handing over
the window (bail-out 3):

| | Condition | Why |
| --- | --- | --- |
| 19 | `Config.SMCChecks == CONFIG_SMC_FULL \|\| Block.ForceFullSMCDetection` | That mode wraps **every** instruction in a `_ValidateCode` guard + `CondJump`. A swallowed instruction silently loses its guard, so a guest that rewrote the `pmovmskb` in place would keep executing the old semantics forever. This one is easy to miss and would have been a real correctness hole. |
| 20 | `ExtendedDebugInfo` | That mode asks for a `_GuestOpcode` marker per instruction; swallowed instructions would not get one, degrading RIP reconstruction and IR dumps exactly when someone is trying to debug. |

---

## 5. Soundness: eliding the mask

### 5.1 The two designs, and which one is implemented

**Design A — "prove the mask is dead in-block, then drop it."** Rejected.
It is not sufficient. The PMOVMSKB destination is a *guest architectural
register*: even with zero IR uses, FEX's register cache writes it back to
`CPUState.gregs` at every flush, and a signal delivered anywhere downstream
must see the correct value. An SSA use-count of 1 does not license deleting a
guest register write. Design A is only sound for a value that is both
IR-dead and re-defined before any observable point — which nothing here is.

**Design B — "fuse the branch, materialise the mask on the edge that consumes
it."** Implemented. And it is better than the brief suggested, because of one
observation:

> On the **no-match** edge the mask is not merely unused, it is **known**.
> Reaching that edge is exactly the proposition `mask == 0` — that is what
> `test`/`jz` decided.

So:

* **before** the fused branch: store the constant `0` into the mask GPR, and
  set the flags `test $0,$0` would leave. Both are constants; the store folds
  to an `li` into the SRA register for `%rdx`, and the flag write folds to a
  constant NZCV. Neither touches the vector unit, neither is on the branch's
  dependency chain.
* **no-match edge**: nothing at all. It jumps straight to its real successor.
  This is the hot edge — the loop back edge — and it costs *zero* extra
  instructions.
* **match edge**: a synthesised IR block that recomputes the real mask from the
  PCMPEQ result (which we still emit, because `xmm0` is guest-visible too),
  stores it, re-derives the flags from it, and then goes wherever the guest
  `jcc` would have gone. This is the loop *exit*, taken once per call.

Guest state is therefore exactly right on both edges, at both edges' first
instruction, and the ~105-instruction reduction has been moved off the loop
entirely and onto a path taken once.

The `xmm` destination of the `pcmpeqb` is *not* elided. It could be by the same
argument (on the no-match edge the compare result is all-zero, one `vxor`), but
it costs a single `vcmpequb` that dual-issues with the record-form compare, and
leaving it alone keeps the fusion's blast radius to one guest register instead
of two. Noted in §8.

### 5.2 Flags

`TESTOp` with `Dest == Src` reduces to `SetNZP_ZeroCV(Size, Src); InvalidateAF()`.
The fusion calls exactly that — with `_Constant(0)` before the branch and with
the real mask on the match edge — so the flag semantics are not re-derived, they
are the same two lines of code applied to the two provable values. `PF` of zero
is 1, `ZF` is 1, `SF`/`CF`/`OF` are 0; all of that falls out of
`SetNZP_ZeroCV(i32Bit, Constant(0))` with no special reasoning.

### 5.3 The signal-delivery hazard, and bail-out 18

Between the constant-zero store and the match edge's real store there is exactly
one point in the emitted host code: the `bc` itself. Normally nothing observable
happens there. But `DEF_OP(CondJump)` emits `EmitSuspendInterruptCheck()` — a
byte store that faults when a deferred signal is pending — on any leg whose
target label is already **bound**, i.e. a **backward** edge:

```cpp
auto TrueTarget = JumpTarget(Op->TrueBlock);
if (TrueTarget->bound) { EmitSuspendInterruptCheck(); }
b(TrueTarget);
```

If a signal were delivered there, the guest would observe `%edx == 0` while the
RIP says the `pmovmskb` has already retired — a wrong architectural register at
a signal boundary. That is a real, if rare, miscompile.

Rather than complicate the lowering, the frontend refuses to fuse when the taken
edge goes backward (`TargetRIP <= Jcc.PC`). The fallthrough edge is forward by
construction, so this guarantees no suspend poke is emitted inside a fused
branch. **This costs nothing where it matters**: glibc's scans branch *forward*
to their exit path and close the loop with a separate unconditional `jmp`, which
is a plain `OP_JUMP` and carries its own drain point as usual. Loops shaped
`... ; test ; jz L(loop)` with a backward conditional are simply not fused.
That is a coverage decision, not a correctness compromise, and it is one line to
revisit if such loops turn out to matter (the fix would be to also emit the
constant-zero store *and* accept that the match edge is taken — i.e. to fall
back to Design A's mask materialisation before the branch on backward edges).

### 5.4 Cross-block SSA

The match block uses `CompareResult` (the `_VCMPEQ` SSA defined in the
predecessor). FEX's IR is whole-function SSA and RA handles cross-block
liveness; `ForeachDirection()` in `OpcodeDispatcher.h` already emits exactly
this shape (values defined before a `CondJump` and used in blocks created after
it). No new capability is being relied on.

### 5.5 Code cache identity

`FEX_VCMPFUSION` changes block *shape* (three guest instructions swallowed, one
extra IR block grown on the match edge), so it is hashed into the code-cache
identity via `HASH_OPT(VCMPFUSION)` in `CodeCache.cpp`, next to the SMC options
that are there for the same reason. Without this, an A/B run would silently
reuse the other configuration's cached code and measure nothing.

---

## 6. Expected host code

Loop back edge, `FEX_VCMPFUSION=1`:

```asm
    lvx/lxvd2x  vA, ...            ; movdqa (%rax), %xmm0        [unchanged]
    vcmpequb    vD, vA, vB         ; pcmpeqb -> guest %xmm0      [unchanged]
    li          rDX, 0             ; provable mask on this edge
    vcmpequb.   v30, vA, vB        ; the fused comparison -> CR6
    bc          12, 26, +8         ; InvertCond: skip if no lane matched
    b           L(match)
    b           L(loop_body)
```

versus `FEX_VCMPFUSION=0`, where the `li` is replaced by the ~10-IR-op /
~100-host-instruction `VCMPLTZ; VAnd; VAddP×3; VExtractToGPR` reduction plus
`cmpwi cr7 / bc`.

Measured before/after counts are in §9.

---

## 7. Extending to AVX (known gap)

This port advertises `SupportsAVX = true` (see the comment at
`Source/Common/HostFeatures.cpp` — AVX-128 decomposition makes it viable on
128-bit hardware, and it lets glibc IFUNCs pick their AVX paths). **That means
glibc will typically select `__strlen_avx2`, whose loop is
`vpcmpeqb %ymm ; vpmovmskb %r32,%ymm ; test ; jnz`, and the fusion as
implemented will not fire on it.** This is the single largest caveat in this
work and it is why §9's numbers are taken from a microbench that pins the SSE2
path as well as from the AVX path.

The extension is designed but not implemented:

* **VEX.128** (`vpcmpeqb %xmm`): trivial. `AVX128_VectorALU` produces
  `Result.Low` from `Src1.Low`/`Src2.Low`; the same `TryFuseVectorScan` call
  applies verbatim with `AVX128_MOVMSKB` as the slot-`i+1` handler.
* **VEX.256** (`vpcmpeqb %ymm`): the dispatcher has already split the operands
  into `Low`/`High` 128-bit halves, so there are four vectors and `CondJump`
  has two SSA slots. Rather than widen the op, use the identity that the
  PCMPEQ results are lane-wise `0x00`/`0xFF`:

  ```
  Diff = VOr(ResultLow, ResultHigh)              ; one vor
  CondJump(Diff, AllOnesVector, VCmpElementSize = i8Bit, NEQ)
  ```

  "any lane matched" ⟺ "any byte of `Diff` is `0xFF`" ⟺ "any byte lane of
  `Diff` equals the all-ones vector" — which is exactly the op's existing
  semantics, at 8-bit granularity regardless of the guest element size. Cost:
  `vor` + `vspltisb v31,-1` + `vcmpequb.` + `bc` ≈ 4, against a *doubled*
  (~210-instruction) unfused reduction plus an `Orlshl` to splice the two
  16-bit halves. The match-edge block reuses `AVX128_MOVMSKB`'s body unchanged.
  Bail-out 5 becomes `RegisterSize > i256Bit`.

The IR mode was deliberately specified as "any lane of Cmp1 == Cmp2" rather than
"any lane of Cmp1 is non-zero" precisely so that the 256-bit recipe needs no new
IR — only a different pair of operands.

---

## 8. Follow-ups / accepted risk

1. `FoldBranch` is safe only by accident (`FromNZCV == false`). Add an explicit
   `LOGMAN_THROW_A_FMT(Op->VCmpElementSize == iInvalid)` there.
2. The guest `xmm` destination of the `pcmpeqb` could be elided by the same
   provable-value argument (all-zero on the no-match edge). One instruction.
3. 32-bit guests (bail-out 4) and backward conditional edges (bail-out 18) are
   unfused coverage gaps, both reversible.
4. AVX-256, §7. This is the one that decides whether the feature matters in
   production rather than in a microbench.

---

## 9. Measurements

See the report accompanying this branch. Method: `FEX_VCMPFUSION=0` vs `=1` on
the same binary, same `FEXOfflineCompiler` disassembly for the instruction
counts, `smcstorm`/`movchk` and the ASM differential suite for regressions.
