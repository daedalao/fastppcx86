// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
desc: Marks chained scalar-FP inserts whose upper elements nobody observes
$end_info$
*/

#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes.h"

#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <stddef.h>

namespace FEXCore::IR {

// ---------------------------------------------------------------------------
// Scalar splat chains.
//
// A guest scalar-SSE float chain (movss load; subss; mulss; movss store)
// reaches the backend as
//     %1 = LoadMem FPR, ..., i32              # {val, 0, 0, 0}
//     %2 = VFSubScalarInsert %0, %1, ZUB=0    # lane0 = %0.l0 - %1.l0, l123 = %0.l123
//     %3 = VFMulScalarInsert %2, %x, ZUB=0
//          StoreMem FPR, %3, ..., i32         # lane0 only
//
// The PPC64LE lowering of one VF*ScalarInsert (VectorOps.cpp, DEF_SCALAR_INSERT)
// is, for f32:
//     xxspltw(T1, Vec1, 3) ; xxspltw(T2, Vec2, 3) ; xv{add,sub,mul,div}sp(T1, T1, T2)
//     xxsldwi(T2, T1, Vec1, 3) ; xxsldwi(Dst, T2, T2, 1)     <- lane-0 merge
// i.e. five instructions, and the next link in the chain immediately splats the
// merged result apart again.
//
// The observation this pass exists to exploit: xv*sp applied to two FULLY
// SPLATTED operands produces a result that is itself already splatted in all
// four elements. So for a chain-internal op both the merge (2 instructions) and
// the consumer's re-splat of that operand (1 instruction) are pure waste -- as
// long as nothing can ever look at the upper elements.
//
// This pass computes exactly that "nothing can look" property and records it in
// the IR as VF*ScalarInsert::SplatResult. The flag is a PERMISSION granted to
// the backend, never an obligation: a backend that ignores it and produces the
// architectural value is still correct, which is why adding it cannot break any
// other target.
//
// ---------------------------------------------------------------------------
// MARKING RULE
//
// A node R = VF{Add,Sub,Mul,Div}ScalarInsert(Vector1, Vector2, ZeroUpperBits=0)
// with Header.Size == 128-bit and ElementSize in {32, 64} may be marked iff
// EVERY use of R is one of:
//
//   (a) the Vector1 (destination) operand of another VF{Add,Sub,Mul,Div}-
//       ScalarInsert of the SAME ElementSize in the same block that is ITSELF
//       marked. Such a consumer reads Vector1's element 0 for the arithmetic
//       (correct: a splat holds the right value there) and would otherwise
//       propagate Vector1's upper elements into its own result -- which is only
//       acceptable because the consumer's own result is likewise non-
//       architectural above element 0. Hence the mutual requirement, resolved
//       by the fixpoint below.
//
//   (b) the Vector2 (source) operand of a VF{Add,Sub,Mul,Div,Min,Max}-
//       ScalarInsert of the SAME ElementSize in the same block. Every one of
//       those lowerings derives its element 0 solely from Vector1's and
//       Vector2's element 0, and copies its upper elements from Vector1 only --
//       Vector2's upper elements are never read. No requirement on the
//       consumer's own marking.
//
//   (c) the Value operand of a StoreMem with Class == FPR in the same block
//       whose store size is <= the element size. See the store note below.
//
// Anything else disqualifies: StoreRegister (guest-XMM writeback), StoreContext,
// any full-width vector op, a 16-byte store, VStoreVectorElement, a use in
// another block, a use by a ScalarInsert of a DIFFERENT element size, ...
//
// The ElementSize match in (a)/(b) is load-bearing, not tidiness. An f32 splat
// has element 0's word in all four words, so its doubleword 1 reads
// {val, val}; the architectural doubleword 1 of that same value is
// {Vector1.word2, val}. An f64 consumer of an f32 splat would therefore read a
// wrong 64-bit element 0. Same argument mirrored the other way.
//
// "Use in another block" is caught without any cross-block dataflow: uses are
// counted while walking the block, and the total is compared against
// OrderedNode::GetUses(), which IREmitter maintains exactly (AddUse on every
// SSA argument at emission, and Replace*/Remove keep it in step). If the two
// disagree, something outside this block -- or something the walk did not
// classify -- holds a reference, and R is left alone.
//
// ---------------------------------------------------------------------------
// WHY StoreRegister IS THE WHOLE OF THE SRA STORY
//
// The high-risk question is whether an SSA value can become architectural guest
// XMM state WITHOUT appearing as an operand of an IR op this pass can see --
// i.e. whether the register allocator silently writes the last def of a guest
// XMM back into its static register.
//
// It does not. Guest register state is cached by the FRONTEND (OpcodeDispatcher
// RegCache) and every flush is an explicit IR op: OpcodeDispatcher.h's
// FlushRegisterCache emits `_StoreRegister(Value, VectorSize)` for cache indices
// FPR0..FPR15 (and _StoreContext* for the AVX-high/MMX/x87 indices), all before
// this pass runs. RegisterAllocationPass then merely ASSIGNS the SRA register:
// its DecodeSRANode/DecodeSRAReg read OP_STOREREGISTER's existing Value operand,
// and the PPC64LE DEF_OP(StoreRegister) is a plain vmr into StaticFPRegisters.
// There is no RA-invented writeback. So an architectural guest-XMM value is
// always the operand of a StoreRegister/StoreContext node, both of which this
// pass treats as disqualifying.
//
// The two things RA does add after this pass are harmless to the analysis:
//   * SpillRegister/FillRegister for an FPR value are a full-width stvx/lvx
//     pair (MemoryOps.cpp), so a splat-form value round-trips through a spill
//     slot bit-identically and stays splat-form.
//   * A fill (or any RA-inserted copy) replaces the operand of a consumer with
//     a different defining node, at which point the backend's "is my operand
//     already splatted?" test simply fails and it emits the splat it would have
//     emitted anyway. Re-splatting an already-splatted value is idempotent, so
//     the conservative direction is the only direction that failure can take.
//
// ---------------------------------------------------------------------------
// THE STORE CASE
//
// PPC64LE lowers `StoreMem FPR, size 4` through PPC64EmitterBase::StoreFPRSized
// (ArchHelpers/PPC64Emitter.cpp), whose 4/8-byte fast path is
//     xxpermdi(T, src, src, 2) ; stxsiwx/stxsdx(T, ea, r0)
// -- the permute moves the guest value out of doubleword 1 (LE element 0) into
// doubleword 0, which is where the scalar-VSX stores read from. Sizes 1/2 fall
// back to a stvx bounce through JITScratch and read the low `size` bytes of
// doubleword 1. Both paths read ONLY bits inside element 0, which a splat holds
// correctly; that is why any store of size <= ElementSize is a legal use, and
// also why leaving such a store completely alone would already be correct.
// The backend additionally skips the permute for the 4/8-byte case, since in
// splat form doubleword 0 already equals doubleword 1.
//
// StoreMemTSO is deliberately NOT accepted: its lowering is a separate op with
// its own barrier sequencing and was not audited here.
// ---------------------------------------------------------------------------

namespace {
  // Producers this pass may mark. Restricted to the four arithmetic ops whose
  // lowering is the DEF_SCALAR_INSERT macro in VectorOps.cpp -- the splat-both-
  // operands + single xv* + merge shape the transform reasons about.
  bool IsSplattableProducer(IROps Op) {
    switch (Op) {
    case OP_VFADDSCALARINSERT:
    case OP_VFSUBSCALARINSERT:
    case OP_VFMULSCALARINSERT:
    case OP_VFDIVSCALARINSERT: return true;
    default: return false;
    }
  }

  // Ops that read Vector2's element 0 and nothing else of Vector2. The four
  // arithmetic ones by the macro above; Min/Max by inspection of their
  // DEF_OP bodies, which compute a full-width vcmpgtfp/vsel (or the f64
  // xvcmpgtdp/xxsel) but then keep only element 0 of that select and take every
  // other element from Vector1.
  bool ReadsOnlyElement0OfVector2(IROps Op) {
    switch (Op) {
    case OP_VFMINSCALARINSERT:
    case OP_VFMAXSCALARINSERT: return true;
    default: return IsSplattableProducer(Op);
    }
  }

  bool IsEligible(const IROp_Header* IROp) {
    if (!IsSplattableProducer(IROp->Op)) {
      return false;
    }

    // 256-bit forms and the AVX zero-upper semantic are not what the PPC64LE
    // lowering implements today; stay on the 128-bit SSE shape only.
    if (IROp->Size != OpSize::i128Bit) {
      return false;
    }
    if (IROp->ElementSize != OpSize::i32Bit && IROp->ElementSize != OpSize::i64Bit) {
      return false;
    }

    // All four ops share the ZeroUpperBits field at the same place.
    return !IROp->C<IROp_VFAddScalarInsert>()->ZeroUpperBits;
  }

  void SetSplatResult(IROp_Header* IROp) {
    // Same field offset in all four; the op was validated by IsEligible.
    IROp->CW<IROp_VFAddScalarInsert>()->SplatResult = true;
  }
} // namespace

class ScalarSplatChain final : public FEXCore::IR::Pass {
public:
  void Run(IREmitter* IREmit) override;

private:
  struct Candidate {
    Ref Node {};
    IROp_Header* IROp {};
    // Uses of this node seen inside its own block, of any kind.
    uint32_t SeenUses {};
    // Cleared by any use that is not one of the three allowed forms.
    bool Allowed {true};
    bool Marked {};
    // Consumers using this node as their Vector1 operand; each must itself be
    // marked for this node to stay marked.
    fextl::vector<uint32_t> DestConsumers;
  };

  // SSA id -> index into Candidates, or kNoCandidate. Allocated once for the
  // whole IR and cleared entry-by-entry between blocks.
  static constexpr uint32_t kNoCandidate = ~0U;
  fextl::vector<uint32_t> CandidateOf;
  fextl::vector<Candidate> Candidates;
};

void ScalarSplatChain::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::ScalarSplatChain");

  auto CurrentIR = IREmit->ViewIR();

  CandidateOf.clear();
  CandidateOf.resize(CurrentIR.GetSSACount(), kNoCandidate);

  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    Candidates.clear();

    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      if (IsEligible(IROp)) {
        CandidateOf[CurrentIR.GetID(CodeNode).Value] = static_cast<uint32_t>(Candidates.size());
        Candidates.emplace_back(Candidate {.Node = CodeNode, .IROp = IROp});
      }
    }

    if (!Candidates.empty()) {
      // Classify every use that lives in this block.
      for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
        const uint8_t NumArgs = IR::GetArgs(IROp->Op);
        for (uint8_t i = 0; i < NumArgs; ++i) {
          const auto Arg = IROp->Args[i];
          if (Arg.IsInvalid() || Arg.IsImmediate()) {
            continue;
          }

          const uint32_t Idx = CandidateOf[Arg.ID().Value];
          if (Idx == kNoCandidate) {
            continue;
          }

          auto& C = Candidates[Idx];
          ++C.SeenUses;

          // (a)/(b): a ScalarInsert consumer of the same element size.
          if (IROp->ElementSize == C.IROp->ElementSize) {
            if (i == IROp_VFAddScalarInsert::Vector1_Index && IsEligible(IROp)) {
              C.DestConsumers.push_back(CandidateOf[CurrentIR.GetID(CodeNode).Value]);
              continue;
            }
            if (i == IROp_VFAddScalarInsert::Vector2_Index && ReadsOnlyElement0OfVector2(IROp->Op)) {
              continue;
            }
          }

          // (c): a narrow FPR store of the value.
          if (IROp->Op == OP_STOREMEM && i == IROp_StoreMem::Value_Index &&
              IROp->C<IROp_StoreMem>()->Class == RegClass::FPR &&
              IR::OpSizeToSize(IROp->Size) <= IR::OpSizeToSize(C.IROp->ElementSize)) {
            continue;
          }

          C.Allowed = false;
        }
      }

      // Optimistic seed, then shrink. A candidate whose in-block use count does
      // not account for every use it has is referenced from somewhere this walk
      // could not see, so it must stay architectural.
      for (auto& C : Candidates) {
        C.Marked = C.Allowed && C.SeenUses == C.Node->GetUses();
      }

      // Greatest fixpoint over rule (a). Uses always follow their def in list
      // order today, so this converges in one iteration, but the loop does not
      // depend on that holding.
      for (bool Changed = true; Changed;) {
        Changed = false;
        for (auto& C : Candidates) {
          if (!C.Marked) {
            continue;
          }
          for (uint32_t Consumer : C.DestConsumers) {
            if (!Candidates[Consumer].Marked) {
              C.Marked = false;
              Changed = true;
              break;
            }
          }
        }
      }

      for (auto& C : Candidates) {
        if (C.Marked) {
          SetSplatResult(C.IROp);
        }
      }
    }

    for (auto& C : Candidates) {
      CandidateOf[CurrentIR.GetID(C.Node).Value] = kNoCandidate;
    }
  }
}

fextl::unique_ptr<FEXCore::IR::Pass> CreateScalarSplatChain() {
  return fextl::make_unique<ScalarSplatChain>();
}

} // namespace FEXCore::IR
