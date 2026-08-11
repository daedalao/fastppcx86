// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
desc: Fuses a flag-setting SubWithFlags into the CondJump that consumes it
$end_info$
*/

#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes.h"

#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/vector.h>

namespace FEXCore::IR {

// ---------------------------------------------------------------------------
// Compare-and-branch fusion.
//
// x86 `cmp a,b ; jcc` reaches the backend as
//     %n = SubWithFlags i32 a, b            # writes packed NZCV
//     CondJump %Invalid, %Invalid, ..., UGT, FromNZCV=1
// The PPC64LE lowering of a FromNZCV CondJump has to reconstruct C and V out of
// XER, because that is where subfco. leaves them: MapNZCVCC emits
// mfxer + rlwinm + mtocrf (+ a crandc/crxor/crnor composite for the two-flag
// conditions) before the bc. mfxer serialises on POWER8 and this sits on every
// hot loop backedge.
//
// The same DEF_OP(CondJump) already has a direct-compare arm for CondJumps that
// carry real Cmp1/Cmp2 with FromNZCV=0: EmitCompare into cr7 plus MapCC, i.e.
// cmpw/cmpd(+i) and a bc, no XER traffic at all. This pass rewrites the first
// form into the second when the flags the branch reads provably come from an
// immediately preceding SubWithFlags in the same block.
//
// Nothing is deleted here. The SubWithFlags stays; if its flag write is now
// dead, DeadFlagCalculationElimination (which runs after this pass) rewrites it
// to a plain Sub, and drops it entirely if the difference is unused as well.
//
// ---------------------------------------------------------------------------
// CORRECTNESS: the two lowering arms must agree on what each CondClass means.
//
// FEX's packed NZCV is ARM-sense, and so is the CondClass enum: SubNZCV's own
// IR.json description says "Carry flag uses arm64 definition, inverted x86".
// The x86 CF inversion therefore lives entirely upstream, in the frontend's
// choice of CondClass for a given jcc; it is identical for both arms and this
// rewrite does not touch it. What has to be checked is only that
// "Cond evaluated against the NZCV of a-b" == "Cond evaluated against a compare
// of a and b".
//
// After SubWithFlags(Size, a, b) the PPC backend (ALUOps.cpp) emits subfco.
// (on operands pre-shifted left by 64-Size for Size < 64, so every flag sits at
// the operand-size boundary), giving
//     Z = (a - b == 0 at Size)         <=> a == b
//     N = sign bit of (a - b) at Size
//     C = carry out of (~b + a + 1)    <=> a >=u b     (NOT borrow, ARM sense)
//     V = signed overflow of a - b at Size
// MapNZCVCC decodes the branch conditions from exactly those, and EmitCompare +
// MapCC decode them from cmpw/cmpd (signed) or cmplw/cmpld (unsigned):
//
//   EQ   Z              <=> a == b        cmp + CC_EQ          identical
//   NEQ  !Z             <=> a != b        cmp + CC_NE          identical
//   UGE  C              <=> a >=u b       cmpl + CC_GE         identical
//   ULT  !C             <=> a <u  b       cmpl + CC_LT         identical
//   UGT  C && !Z        <=> a >u  b       cmpl + CC_GT         identical
//   ULE  !(C && !Z)     <=> a <=u b       cmpl + CC_LE         identical
//   SLT  N != V         <=> a <s  b       cmp  + CC_LT         identical
//   SGE  N == V         <=> a >=s b       cmp  + CC_GE         identical
//   SGT  (N==V) && !Z   <=> a >s  b       cmp  + CC_GT         identical
//   SLE  !((N==V)&&!Z)  <=> a <=s b       cmp  + CC_LE         identical
//
// (The N!=V / N==V identities are the textbook signed-compare-from-subtract
// ones; they are what makes the pre-shift in SubWithFlags load-bearing at
// Size < 64, since N and V must be the operand-size ones.)
//
// EXCLUDED conditions, all because the two arms do NOT agree:
//   MI / PL   read N alone. MapCC maps them onto CC_LT / CC_GE, which after a
//             cmp is the *signed compare* N!=V -- the two differ exactly when
//             the subtraction overflows. Not an identity.
//   VS / VC   read V. A cmp does not produce V at all; MapCC sends them to
//             CR0.SO, which after cmp is XER.SO, a sticky bit unrelated to this
//             subtract's overflow.
//   FLU/FGE/FLEU/FGT/FU/FNU  are FP / integer-overflow codes, never produced
//             against an integer SubWithFlags.
//   TSTZ/TSTNZ read Cmp2 as a bit position rather than a value; they have their
//             own arm in the backend and no NZCV meaning.
//   AL        unconditional; nothing to fuse.
//
// Size: SubWithFlags is validated to i32Bit/i64Bit only (IR.json), which is
// also the range EmitCompare's integer path handles exactly -- cmpw/cmplw
// compare bits 32:63 with the correct extension, matching the 32-bit boundary
// the shifted subfco. used, and dirty upper bits are ignored by both. We assert
// rather than silently skipping, since a new size would need both sides
// re-checked.
//
// Operands: EmitCompare requires Cmp1 in a register (it calls GetReg on it
// unconditionally) and handles a constant only in Cmp2, where it covers the
// full 64-bit range (16-bit immediate forms, else LoadConstant into TMP4). So a
// constant Src2 is fusable as-is and a constant Src1 -- SubWithFlags inlines a
// zero there via InlineSubtractZero -- is not.
// ---------------------------------------------------------------------------

namespace {
  bool IsFusableCond(CondClass Cond) {
    switch (Cond) {
    case CondClass::EQ:
    case CondClass::NEQ:
    case CondClass::UGE:
    case CondClass::ULT:
    case CondClass::UGT:
    case CondClass::ULE:
    case CondClass::SGE:
    case CondClass::SLT:
    case CondClass::SGT:
    case CondClass::SLE: return true;
    default: return false;
    }
  }

  // EmitCompare's Cmp1 must be a real register value.
  bool IsRegisterOperand(IRListView& IR, OrderedNodeWrapper Arg) {
    if (Arg.IsInvalid() || Arg.IsImmediate()) {
      return false;
    }

    auto Op = IR.GetOp<IROp_Header>(Arg)->Op;
    return Op != OP_INLINECONSTANT && Op != OP_INLINEENTRYPOINTOFFSET;
  }

  bool IsUsableOperand(IRListView& IR, OrderedNodeWrapper Arg) {
    if (Arg.IsInvalid() || Arg.IsImmediate()) {
      return false;
    }

    // InlineEntrypointOffset is a constant the compare path does not decode
    // (only InlineConstant is), so it must be in a register there too.
    auto Op = IR.GetOp<IROp_Header>(Arg)->Op;
    return Op != OP_INLINEENTRYPOINTOFFSET;
  }
} // namespace

class CompareBranchFusion final : public FEXCore::IR::Pass {
public:
  void Run(IREmitter* IREmit) override;
};

// Is Producer a SubWithFlags whose operands the direct-compare arms can take?
static bool IsFusableProducer(IRListView& IR, IROp_Header* Producer) {
  if (!Producer || Producer->Op != OP_SUBWITHFLAGS) {
    return false;
  }

  if (Producer->Size != OpSize::i32Bit && Producer->Size != OpSize::i64Bit) {
    LOGMAN_MSG_A_FMT("SubWithFlags with an unexpected size {}", static_cast<uint32_t>(Producer->Size));
    return false;
  }

  return IsRegisterOperand(IR, Producer->Args[0]) && IsUsableOperand(IR, Producer->Args[1]);
}

void CompareBranchFusion::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::CmpBranchFusion");

  auto CurrentIR = IREmit->ViewIR();

  // NZCVSelect rewrites recorded during the scan and applied afterwards, so
  // the forward iteration never walks over nodes the pass itself inserted.
  struct SelectRewrite {
    Ref Node;
    IROp_Header* Producer;
  };
  fextl::vector<SelectRewrite> SelectRewrites;

  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    // Forward walk, tracking the most recent NZCV writer. Readers (setcc,
    // NZCVSelect) are walked over: they keep the SubWithFlags' flag write
    // alive but do not change it, and DFCE sees each reader independently.
    IROp_Header* Producer {};

    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (IROp->Op == OP_NZCVSELECT) {
        auto SelOp = IROp->CW<IROp_NZCVSelect>();
        if (IsFusableCond(SelOp->Cond) && IsFusableProducer(CurrentIR, Producer)) {
          // DEF_OP(Select) materialises inline-constant True/False values via
          // a bare 16-bit `li`; anything wider would silently truncate, so
          // only fuse when both fit (covers the 0/1/-1 flag-materialisation
          // selects, which are the bulk).
          auto FitsLi = [&](OrderedNodeWrapper Arg) {
            if (Arg.IsInvalid()) {
              return false;
            }
            auto Hdr = CurrentIR.GetOp<IROp_Header>(Arg);
            if (Hdr->Op == OP_INLINEENTRYPOINTOFFSET) {
              return false;
            }
            if (Hdr->Op == OP_INLINECONSTANT) {
              int64_t V = static_cast<int64_t>(Hdr->C<IROp_InlineConstant>()->Constant);
              return V >= -32768 && V <= 32767;
            }
            return true;
          };
          if (FitsLi(SelOp->TrueVal) && FitsLi(SelOp->FalseVal)) {
            SelectRewrites.push_back({CodeNode, Producer});
          }
        }
      } else if (IROp->Op == OP_CONDJUMP) {
        auto CondOp = IROp->CW<IROp_CondJump>();
        if (CondOp->FromNZCV && IsFusableCond(CondOp->Cond) && IsFusableProducer(CurrentIR, Producer)) {
          // FromNZCV and the vector-compare mode are mutually exclusive today,
          // and the rewrite would reinterpret FPR-class Cmp1/Cmp2 as GPRs.
          LOGMAN_THROW_A_FMT(CondOp->VCmpElementSize == OpSize::iInvalid, "FromNZCV CondJump cannot also be a vector-compare CondJump");
          // In-place rewrite; the SubWithFlags is left alone -- DFCE decides
          // whether its flag write (and its result) are still needed.
          IREmit->ReplaceNodeArgument(CodeNode, 0, CurrentIR.GetNode(Producer->Args[0]));
          IREmit->ReplaceNodeArgument(CodeNode, 1, CurrentIR.GetNode(Producer->Args[1]));
          CondOp->CompareSize = Producer->Size;
          CondOp->FromNZCV = false;
        }
      }

      if (IROpWritesNZCV(IROp)) {
        Producer = IROp;
      }
    }
  }

  // NZCVSelect -> Select. Legal mid-flag-region ONLY because ppc64le's
  // DEF_OP(Select) compares into cr7 on every arm and thus clobbers neither
  // CR0 nor XER (see the comment there, which points back here); the declared
  // IR-level ImplicitFlagClobber is a frontend-emission concern that DFCE
  // never consults. The producing SubWithFlags again stays for DFCE to judge.
  for (const auto& RW : SelectRewrites) {
    auto IROp = CurrentIR.GetOp<IROp_Header>(RW.Node);
    auto SelOp = IROp->CW<IROp_NZCVSelect>();

    IREmit->SetWriteCursorBefore(RW.Node);
    Ref NewSelect = IREmit->_Select(IROp->Size, RW.Producer->Size, SelOp->Cond,
                                    CurrentIR.GetNode(RW.Producer->Args[0]),
                                    CurrentIR.GetNode(RW.Producer->Args[1]),
                                    CurrentIR.GetNode(SelOp->TrueVal),
                                    CurrentIR.GetNode(SelOp->FalseVal));
    IREmit->ReplaceUsesWithAfter(RW.Node, NewSelect, RW.Node);
    IREmit->Remove(RW.Node);
  }
}

fextl::unique_ptr<FEXCore::IR::Pass> CreateCompareBranchFusion() {
  return fextl::make_unique<CompareBranchFusion>();
}

} // namespace FEXCore::IR
