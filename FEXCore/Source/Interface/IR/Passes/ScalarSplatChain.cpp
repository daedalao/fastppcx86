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
#include "Interface/IR/RegisterAllocationData.h"

#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <stddef.h>

namespace FEXCore::IR {

// ---------------------------------------------------------------------------
// Scalar splat chains.
//
// A guest scalar-SSE float chain (movss load; mulss; addss; movss store)
// reaches the PPC64LE backend as a run of VF*ScalarInsert ops, each lowered
// (VectorOps.cpp, DEF_SCALAR_INSERT) for f32 as
//     xxspltw(T1, Vec1, 3) ; xxspltw(T2, Vec2, 3) ; xv{add,sub,mul,div}sp(T1, T1, T2)
//     xxsldwi(T2, T1, Vec1, 3) ; xxsldwi(Dst, T2, T2, 1)     <- lane-0 merge
// -- five instructions, and the next link then splats the merged result apart
// again. But xv*sp over two FULLY SPLATTED operands yields a result that is
// itself already splatted in all four elements, so for a chain-internal op the
// merge and the consumer's re-splat are both dead work, PROVIDED nothing can
// observe the upper elements.
//
// This pass proves that per node and records it as VF*ScalarInsert::SplatResult
// (and LoadRegister::SplatElementSize, see the register-cache section). Both are
// PERMISSIONS granted to the backend, never obligations: a backend that ignores
// them and produces the architectural value stays correct, which is why they
// cannot break any other target.
//
// ---------------------------------------------------------------------------
// THE REGISTER CACHE IS THE WHOLE PROBLEM
//
// The obvious form of this analysis -- "follow the SSA edges between the
// ScalarInserts" -- finds NOTHING in this tree, because those edges do not
// exist. Core.cpp:851 calls FlushRegisterCache(true) before EVERY guest
// instruction ("a blunt heuristic to make the register cache less aggressive,
// as the current RA generates bad code in common cases with tied registers
// otherwise ... it makes our exception handling behaviour more predictable").
// So each guest XMM def is written straight back out and re-read:
//
//     %2 = LoadRegister FPR0                 # movss xmm0, [rsi+rax*4]
//     ...
//     %4 = VFMulScalarInsert %2, %3          # mulss xmm0, xmm2
//          StoreRegister %4 -> FPRFixed[0]   <- %4's ONLY SSA use
//     %6 = LoadRegister FPR0                 # addss xmm1, xmm0
//     %7 = VFAddScalarInsert %5, %6
//          StoreRegister %7 -> FPRFixed[1]
//
// (The IRDumper hides this: it prints the operands as bare "V0"/"R1" tags, which
// reads like a direct SSA edge.) Every candidate therefore has exactly one use,
// a StoreRegister, and a naive rule set rejects all of them.
//
// So the pass models the register cache itself, per block:
//   * LoadRegister FPR<n> is treated as an ALIAS of whatever node was last
//     StoreRegister'd to FPRFixed[n] in this block. Uses of the alias are
//     classified as uses of that underlying candidate; the alias node itself is
//     transparent.
//   * A StoreRegister of a candidate no longer disqualifies outright -- see the
//     next section.
//
// The alias is sound at the machine level because the SRA registers are a
// dedicated, disjoint register file: PPC64Emitter.h gives SRAFPR = v0..v15 and
// RAFPR = v16..v29, so the ONLY things that write an SRA vector register are
// DEF_OP(StoreRegister)'s vmr (tracked here) and the SpillStaticRegs /
// FillStaticRegs pair around exits, which round-trips all 16 bytes and so
// preserves splat form exactly.
//
// ---------------------------------------------------------------------------
// ACCEPTED IMPRECISION -- READ THIS BEFORE TOUCHING THE RULES
//
// Letting a splat-form value be StoreRegister'd means the guest XMM's upper
// elements hold the replicated element 0 instead of their architectural
// contents for a window inside the block. Consequences:
//
//   * A synchronous fault in that window, or an asynchronous signal taken
//     there, builds a guest signal frame whose upper elements read as the
//     splat. A guest handler that saves or inspects the whole XMM sees the
//     wrong upper elements. This is the residual exposure and it is accepted.
//   * A mid-block syscall/thunk/break would spill SRA to CPUState.xmm the same
//     way. That one is NOT accepted -- SpillsSRA() below lists those ops and
//     rule (d) refuses to leave a splat live across them.
//
// This is a REDUCTION in precision relative to today. The per-instruction flush
// quoted above deliberately keeps guest register state exact at every
// instruction boundary, and its own comment calls that "potentially correctness
// bearing ... but that is a side effect here". What this pass gives up is
// strictly narrower than that flush's own caveat: only the upper elements of a
// scalar-float XMM, only between two guest instructions inside one block, and
// only where the register is provably rewritten again before the block ends
// (see the StoreRegister rule) so that no imprecision ever survives to a block
// boundary. GPRs are unaffected -- they are flushed by the same call, and this
// pass never touches a GPR-class value.
//
//     FEX_DISABLESCALARSPLATCHAIN=1
// turns the pass off and restores exact upper elements everywhere.
//
// ---------------------------------------------------------------------------
// MARKING RULE
//
// A node R = VF{Add,Sub,Mul,Div}ScalarInsert(Vector1, Vector2, ZeroUpperBits=0)
// with Header.Size == 128-bit and ElementSize in {32, 64} may be marked iff
// EVERY use of R -- and every use of every LoadRegister aliasing R -- is one of:
//
//   (a) the Vector1 (destination) operand of another eligible ScalarInsert of
//       the SAME ElementSize in the same block that is ITSELF marked. Such a
//       consumer reads Vector1's element 0 for the arithmetic (a splat holds
//       the right value there) but would otherwise propagate Vector1's upper
//       elements into its own result -- acceptable only because the consumer's
//       own result is likewise non-architectural above element 0. Hence the
//       mutual requirement, resolved by the fixpoint below.
//
//   (b) the Vector2 (source) operand of a VF{Add,Sub,Mul,Div,Min,Max}-
//       ScalarInsert of the SAME ElementSize in the same block. Every one of
//       those lowerings derives element 0 solely from element 0 of Vector1 and
//       Vector2, and copies its upper elements from Vector1 only. No
//       requirement on the consumer's own marking.
//
//   (c) the Value operand of a StoreMem with Class == FPR in the same block
//       whose store size is <= the element size (see the store note below).
//
//   (d) the Value operand of a StoreRegister to FPRFixed[n] -- ONLY IF a LATER
//       StoreRegister to that same FPRFixed[n] supersedes it before the block
//       ends AND with no SRA-spilling op (SpillsSRA) in between. That later
//       store is what keeps the splat from reaching architectural state.
//
//       Note the rule is evaluated per use against that store's own position,
//       so the LAST write to a register is never eligible. Combined with (a),
//       a chain whose tail value is left live in an XMM at block end unwinds
//       completely and marks nothing -- which is why an accumulator like the
//       `addss xmm1, ...` of a DSP loop never marks, while a scratch register
//       reloaded later in the block (an unrolled loop's `movss xmm0, [m+k]`,
//       or any register the guest reuses) does.
//
// Anything else disqualifies: StoreContext, any full-width vector op, a 16-byte
// store, VStoreVectorElement, a use in another block, a use by a ScalarInsert
// of a DIFFERENT element size, ...
//
// The ElementSize match in (a)/(b) is load-bearing, not tidiness. An f32 splat
// has element 0's word in all four words, so its doubleword 1 reads
// {val, val}; the architectural doubleword 1 of that same value is
// {Vector1.word2, val}. An f64 consumer of an f32 splat would therefore read a
// wrong 64-bit element 0. Same argument mirrored the other way.
//
// "Use in another block" is caught without any cross-block dataflow: uses of
// every tracked node (candidates AND their aliases) are counted while walking
// the block, and each total is compared against OrderedNode::GetUses(), which
// IREmitter maintains exactly (AddUse on every SSA argument at emission;
// Replace*/Remove keep it in step). Any discrepancy means something outside this
// block -- or something the walk did not classify -- holds a reference, and the
// candidate is left alone.
//
// ---------------------------------------------------------------------------
// WHY StoreRegister IS THE WHOLE OF THE SRA STORY
//
// The analysis only works if an SSA value can become architectural guest XMM
// state exclusively by appearing as an operand of an IR op this pass can see.
// It can:
//
//   1. OpcodeDispatcher.h:1338-1349 -- the frontend RegCache flush emits
//      `Ref R = _StoreRegister(Value, VectorSize); R->Reg =
//      PhysicalRegister(RegClass::FPRFixed, Index - FPR0Index).Raw;` for cache
//      indices FPR0..FPR15, and _StoreContext* for the AVX-high/MMX/x87 ones.
//   2. RegisterAllocationPass.cpp:225-266 -- DecodeSRANode/DecodeSRAReg READ
//      that existing Value operand and that Reg byte. RA assigns the register;
//      it does not create the writeback.
//   3. MemoryOps.cpp:422 -- DEF_OP(StoreRegister) is a bare
//      vmr(StaticFPRegisters[Reg], GetVReg(Op->Value)).
//
// So rule (d) plus the StoreContext exclusion covers every path to architectural
// state. The two things RA adds after this pass are harmless:
//   * SpillRegister/FillRegister for an FPR are a full-width stvx/lvx pair
//     (MemoryOps.cpp:349-402), so splat form round-trips bit-identically. They
//     also introduce new uses after the analysis ran -- harmless for the same
//     reason.
//   * A fill or copy replaces a consumer's operand with a different defining
//     node, at which point the backend's splat-form test simply fails and it
//     emits the splat it would have emitted anyway. Re-splatting an
//     already-splatted value is idempotent, so that failure is one-directional.
//
// ---------------------------------------------------------------------------
// THE STORE CASE
//
// PPC64LE lowers `StoreMem FPR` through PPC64EmitterBase::StoreFPRSized
// (ArchHelpers/PPC64Emitter.cpp:511), whose 4/8-byte fast path is
//     xxpermdi(T, src, src, 2) ; stxsiwx/stxsdx(T, ea, r0)
// -- the permute moves the guest value out of doubleword 1 (LE element 0) into
// doubleword 0, where the scalar-VSX stores read. Sizes 1/2 fall back to a stvx
// bounce through JITScratch and read the low `size` bytes of doubleword 1. Both
// paths read ONLY bits inside element 0, which a splat holds correctly; that is
// why any store of size <= ElementSize is a legal use, and why leaving such a
// store alone would already be correct. The backend additionally skips the
// permute for the 4/8-byte case, since in splat form doubleword 0 already
// equals doubleword 1.
//
// StoreMemTSO is deliberately NOT accepted: separate op, own barrier
// sequencing, not audited here.
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
  // arithmetic ones by the macro above; Min/Max by inspection of their DEF_OP
  // bodies, which compute a full-width vcmpgtfp/vsel (or the f64
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

  // Number of guest XMMs held in static vector registers (SRAFPR = v0..v15).
  constexpr uint32_t kNumSRAFPRs = 16;

  // Which FPRFixed register does this StoreRegister write? The frontend stamps
  // it into the node's Reg byte rather than into the op struct, which is the
  // same place RegisterAllocationPass::DecodeSRAReg reads it from. Returns -1
  // for anything that is not an FPR static-register writeback. The bounds check
  // is defensive: the field is 5 bits wide and only 16 of those are SRA FPRs.
  int FPRStoreTarget(Ref Node, const IROp_Header* IROp) {
    if (IROp->Op != OP_STOREREGISTER) {
      return -1;
    }
    const auto Reg = PhysicalRegister(Node);
    if (Reg.AsRegClass() != RegClass::FPRFixed || Reg.Reg >= kNumSRAFPRs) {
      return -1;
    }
    return Reg.Reg;
  }

  // Ops whose PPC64LE lowering copies the SRA registers out to CPUState in the
  // middle of a block (BranchOps.cpp: SpillStaticRegs at :19, :574, :630, and
  // the Thunk path). A splat left in an SRA register across one of these would
  // be written into architectural CPUState.xmm, so they close the window that
  // rule (d) opens.
  //
  // Block TERMINATORS deliberately are not listed: rule (d) requires a LATER
  // store to the same register, and the frontend flushes the register cache
  // before emitting any terminator, so the last store always precedes them and
  // a candidate stored there is already rejected.
  //
  // If a future op grows an SRA spill without being added here, the failure
  // mode is the accepted imprecision documented at the top of this file (a
  // signal frame with splatted upper elements), not memory corruption or a
  // wrong arithmetic result.
  bool SpillsSRA(IROps Op) {
    switch (Op) {
    case OP_SYSCALL:
    case OP_THUNK:
    case OP_BREAK:
    case OP_CALLBACKRETURN: return true;
    default: return false;
    }
  }

  int FPRLoadSource(const IROp_Header* IROp) {
    if (IROp->Op != OP_LOADREGISTER) {
      return -1;
    }
    const auto* Op = IROp->C<IROp_LoadRegister>();
    if (Op->Class != RegClass::FPR || Op->Reg >= kNumSRAFPRs) {
      return -1;
    }
    return Op->Reg;
  }
} // namespace

class ScalarSplatChain final : public FEXCore::IR::Pass {
public:
  void Run(IREmitter* IREmit) override;

private:
  static constexpr uint32_t kNone = ~0U;

  struct Candidate {
    Ref Node {};
    IROp_Header* IROp {};
    // Cleared by any use that is not one of the four allowed forms, or by a
    // tracked node whose in-block use count does not account for all its uses.
    bool Allowed {true};
    bool Marked {};
    // Consumers using this node (directly or through an alias) as their
    // Vector1 operand; each must itself be marked for this node to stay marked.
    fextl::vector<uint32_t> DestConsumers;
    // LoadRegister nodes that read this value back out of its SRA register.
    fextl::vector<Ref> Aliases;
  };

  // One entry per node whose uses must be accounted for: the candidate itself
  // and every LoadRegister aliasing it.
  struct Tracked {
    Ref Node {};
    uint32_t CandIdx {};
    uint32_t Seen {};
  };

  // SSA id -> index into Trackeds, or kNone. Allocated once for the whole IR
  // and cleared entry-by-entry between blocks.
  fextl::vector<uint32_t> TrackedOf;
  fextl::vector<Tracked> Trackeds;
  fextl::vector<Candidate> Candidates;
};

void ScalarSplatChain::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::ScalarSplatChain");

  auto CurrentIR = IREmit->ViewIR();

  TrackedOf.clear();
  TrackedOf.resize(CurrentIR.GetSSACount(), kNone);

  // Per-position verdict for rule (d): is the splat this StoreRegister puts
  // into its SRA register provably overwritten again, by another store to the
  // same register, before either the block ends or anything spills SRA to
  // CPUState? Indexed by the same ordinal the main walk counts.
  fextl::vector<uint8_t> StoreIsSuperseded;
  // Index into StoreIsSuperseded of the most recent not-yet-superseded store to
  // each SRA register.
  uint32_t PendingStore[kNumSRAFPRs];

  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    Candidates.clear();
    Trackeds.clear();

    {
      // Forward pre-walk: resolve rule (d) for every StoreRegister at once. A
      // store is superseded exactly when the next event touching its register
      // is another store to it -- a barrier in between clears the pending
      // entry, and anything still pending at the end of the block survives to
      // the block boundary.
      bool AnyCandidate = false;
      StoreIsSuperseded.clear();
      for (size_t i = 0; i < kNumSRAFPRs; ++i) {
        PendingStore[i] = kNone;
      }
      for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
        const uint32_t Pos = static_cast<uint32_t>(StoreIsSuperseded.size());
        StoreIsSuperseded.push_back(0);

        AnyCandidate |= IsEligible(IROp);

        if (SpillsSRA(IROp->Op)) {
          for (size_t i = 0; i < kNumSRAFPRs; ++i) {
            PendingStore[i] = kNone;
          }
          continue;
        }

        const int Reg = FPRStoreTarget(CodeNode, IROp);
        if (Reg >= 0) {
          if (PendingStore[Reg] != kNone) {
            StoreIsSuperseded[PendingStore[Reg]] = 1;
          }
          PendingStore[Reg] = Pos;
        }
      }
      if (!AnyCandidate) {
        continue;
      }
    }

    // Which candidate's value currently sits in each SRA vector register.
    uint32_t CurSRA[kNumSRAFPRs];
    for (size_t i = 0; i < kNumSRAFPRs; ++i) {
      CurSRA[i] = kNone;
    }

    auto Track = [&](Ref Node, uint32_t CandIdx) {
      TrackedOf[CurrentIR.GetID(Node).Value] = static_cast<uint32_t>(Trackeds.size());
      Trackeds.emplace_back(Tracked {.Node = Node, .CandIdx = CandIdx});
    };

    // Resolve an operand to the candidate it carries the value of, following
    // the register-cache alias, without counting the use.
    auto CandidateOfArg = [&](OrderedNodeWrapper Arg) -> uint32_t {
      if (Arg.IsInvalid() || Arg.IsImmediate()) {
        return kNone;
      }
      const uint32_t T = TrackedOf[Arg.ID().Value];
      return T == kNone ? kNone : Trackeds[T].CandIdx;
    };

    uint32_t Pos = 0;
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      // Register a candidate BEFORE classifying its operands, so that a
      // Vector1 use recorded below can name this node as the consumer it must
      // wait on. A node is never its own operand, so this cannot self-count.
      if (IsEligible(IROp)) {
        const uint32_t Idx = static_cast<uint32_t>(Candidates.size());
        Candidates.emplace_back(Candidate {.Node = CodeNode, .IROp = IROp});
        Track(CodeNode, Idx);
      }

      // --- classify this op's uses of anything tracked -------------------
      const uint8_t NumArgs = IR::GetArgs(IROp->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        const auto Arg = IROp->Args[i];
        if (Arg.IsInvalid() || Arg.IsImmediate()) {
          continue;
        }

        const uint32_t TIdx = TrackedOf[Arg.ID().Value];
        if (TIdx == kNone) {
          continue;
        }

        ++Trackeds[TIdx].Seen;
        auto& C = Candidates[Trackeds[TIdx].CandIdx];

        // (a)/(b): a ScalarInsert consumer of the same element size.
        if (IROp->ElementSize == C.IROp->ElementSize) {
          if (i == IROp_VFAddScalarInsert::Vector1_Index && IsEligible(IROp)) {
            // The consumer was tracked as a candidate at the top of this
            // iteration, so it always has an index here.
            C.DestConsumers.push_back(Trackeds[TrackedOf[CurrentIR.GetID(CodeNode).Value]].CandIdx);
            continue;
          }
          if (i == IROp_VFAddScalarInsert::Vector2_Index && ReadsOnlyElement0OfVector2(IROp->Op)) {
            continue;
          }
        }

        // (c): a narrow FPR store of the value.
        if (IROp->Op == OP_STOREMEM && i == IROp_StoreMem::Value_Index && IROp->C<IROp_StoreMem>()->Class == RegClass::FPR &&
            IR::OpSizeToSize(IROp->Size) <= IR::OpSizeToSize(C.IROp->ElementSize)) {
          continue;
        }

        // (d): a static-register writeback that a later store to the same
        // register supersedes before the block ends or SRA is spilled. If the
        // splat could survive to either, it is the guest XMM's architectural
        // value there and must stay exact.
        if (i == IROp_StoreRegister::Value_Index && FPRStoreTarget(CodeNode, IROp) >= 0 && StoreIsSuperseded[Pos]) {
          continue;
        }

        C.Allowed = false;
      }

      // --- then update the register-cache model --------------------------
      // Order matters: a StoreRegister's own operand is classified above
      // against the state BEFORE the store, and the alias it establishes is
      // visible only to later LoadRegisters.
      if (const int SReg = FPRStoreTarget(CodeNode, IROp); SReg >= 0) {
        // Propagates through movaps-style register copies too: the stored
        // value may itself be an alias, and resolving it means a later read of
        // the destination register still points at the originating candidate.
        CurSRA[SReg] = CandidateOfArg(IROp->Args[IROp_StoreRegister::Value_Index]);
      } else if (const int LReg = FPRLoadSource(IROp); LReg >= 0 && CurSRA[LReg] != kNone) {
        const uint32_t Idx = CurSRA[LReg];
        Candidates[Idx].Aliases.push_back(CodeNode);
        Track(CodeNode, Idx);
      }

      ++Pos;
    }

    // A tracked node whose in-block use count does not account for every use it
    // has is referenced from somewhere this walk could not see.
    for (const auto& T : Trackeds) {
      if (T.Seen != T.Node->GetUses()) {
        Candidates[T.CandIdx].Allowed = false;
      }
    }

    for (auto& C : Candidates) {
      C.Marked = C.Allowed;
    }

    // Greatest fixpoint over rule (a). A Vector1 consumer is always an eligible
    // ScalarInsert and so is a candidate in its own right.
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
      if (!C.Marked) {
        continue;
      }
      C.IROp->CW<IROp_VFAddScalarInsert>()->SplatResult = true;
      // Let the backend see splat form through the register cache: a consumer's
      // operand is the LoadRegister, not the producer. Recording the element
      // size rather than a bare flag keeps the f32/f64 distinction the marking
      // rule depends on available at the use site.
      for (Ref Alias : C.Aliases) {
        CurrentIR.GetOp<IROp_Header>(Alias)->CW<IROp_LoadRegister>()->SplatElementSize = C.IROp->ElementSize;
      }
    }

    for (const auto& T : Trackeds) {
      TrackedOf[CurrentIR.GetID(T.Node).Value] = kNone;
    }
  }
}

fextl::unique_ptr<FEXCore::IR::Pass> CreateScalarSplatChain() {
  return fextl::make_unique<ScalarSplatChain>();
}

} // namespace FEXCore::IR
