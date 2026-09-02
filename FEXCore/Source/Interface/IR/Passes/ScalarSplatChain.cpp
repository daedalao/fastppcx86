// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
desc: Splits scalar-FP inserts into a splat-domain op plus an explicit lane merge, forwarding splat form between chain links
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
// Scalar splat chains, sound form (2026-09-01 rework).
//
// A guest scalar-SSE float chain (movss load; mulss; addss; movss store)
// reaches the PPC64LE backend as a run of VF*ScalarInsert ops, each lowered
// (VectorOps.cpp, DEF_SCALAR_INSERT) for f32 as
//     xxspltw(T1, Vec1, 3) ; xxspltw(T2, Vec2, 3) ; xv{add,sub,mul,div}sp(T1, T1, T2)
//     xxsldwi(T2, T1, Vec1, 3) ; xxsldwi(Dst, T2, T2, 1)     <- lane-0 merge
// -- five instructions, and the next link then splats the merged result apart
// again. xv*sp over two fully splatted operands yields a result that is itself
// splatted in every element, so between two links the merge-then-resplat round
// trip moves no information at all.
//
// THE PREDECESSOR OF THIS PASS AND WHY IT WAS OFF BY DEFAULT.  The original
// pass let the splat-form value become the guest XMM's stored state whenever a
// later store provably overwrote it in the same block ("rule (d)").  That is
// unsound under mid-block fault resume: a guest fault inside the window spills
// the splat-form register, execution resumes at the fault RIP in a FRESH block,
// and the superseding store of the original block never runs -- the splatted
// upper elements become architectural and propagate.  Two reproducible
// Witcher 3 save-load crashes (2026-08-11) traced to exactly that; the pass
// shipped default-off ever since, which made it worth zero instructions in
// practice.
//
// THIS FORM NEVER LETS SPLAT STATE BECOME ARCHITECTURAL.  For every eligible
// ScalarInsert %R the pass:
//
//   1. sets SplatResult, so the backend emits the xv* and STOPS -- %R is the
//      splat-form value, one instruction (plus operand splats when its inputs
//      are not already splat form);
//
//   2. emits %M = VInsElement(ElementSize, DestIdx=0, SrcIdx=0,
//      DestVector=<%R's original Vector1>, SrcVector=%R) immediately after %R
//      -- the exact architectural value, upper elements from Vector1, element
//      0 from the splat.  This is the same merge DEF_SCALAR_INSERT used to
//      emit inline (VInsElement's i32 boundary-lane path is the 2-insn
//      xxsldwi pair; the i64 path is 1 xxpermdi), only now it is a separate
//      SSA value;
//
//   3. rewrites %R's uses: element-0-only readers (the next link's operands, a
//      narrow FPR StoreMem) keep or gain %R -- the backend sees SplatResult on
//      the defining op and skips the re-splat -- while EVERYTHING ELSE,
//      including the per-instruction StoreRegister flush writeback, gets %M.
//
// The stored guest register therefore holds the exact architectural value at
// every guest instruction boundary, exactly as with the pass disabled.  A
// fault or asynchronous signal anywhere sees perfect state; there is no
// accepted-imprecision window, no rule about superseding stores, no concern
// about SRA spills mid-chain.  What the transform saves is purely the dead
// half of the round trip: a chain-interior f32 link costs
//     xv* (1) + merge (2)                       = 3   (was 5)
// and f64
//     xv* (1) + xxpermdi merge (1)              = 2   (was 4)
// with the consumer-side splats gone because consumers read %R.  A lone
// (chain-less) op costs exactly what it did before -- the merge moved from the
// macro into the VInsElement, same instruction count -- so marking every
// eligible op is never a regression.
//
// THE FMA FAMILY (added 2026-09-01, second pass of the sprint).  The four
// VF{,N}ML{A,S}ScalarInsert ops join both sides of the transform.  As
// PRODUCERS they follow the same contract with one layout difference: their
// merge lineage is the dedicated Upper operand rather than Vector1, so %M's
// DestVector comes from Upper and all three math operands (Vector1, Vector2,
// Addend) stay on the splat side.  As CONSUMERS their three math operands are
// element-0-only reads REGARDLESS of the consumer's own marking -- the
// backend splats each from element 0 (or passes an already-splat-form value
// through), unlike an arith consumer's Vector1 whose inline merge reads upper
// elements when unmarked.  A chain-interior f32 FMA link drops from 6 host
// instructions (three operand splats + xv*a + 2-insn merge) to 2-3 (the
// destructive accumulator's copy-splat + xv*a, plus an xxlor only when the
// destination register aliases a pass-through source); f64 likewise sheds its
// operand permutes and merge.
//
// ---------------------------------------------------------------------------
// THE REGISTER CACHE, still the load-bearing detail
//
// Core.cpp:851 flushes the register cache before every guest instruction, so
// chain links are connected through StoreRegister/LoadRegister pairs on the
// guest XMM's static register (SRAFPR = v0..v15, disjoint from the dynamic
// pool), not through SSA edges:
//
//     %4 = VFMulScalarInsert %2, %3          # mulss xmm0, xmm2
//          StoreRegister %4 -> FPRFixed[0]
//     %6 = LoadRegister FPR0                 # addss xmm1, xmm0
//     %7 = VFAddScalarInsert %5, %6
//
// The pass models that cache per block: a LoadRegister of FPR<n> is an ALIAS
// of whatever was last StoreRegister'd to FPRFixed[n] in this block.  A
// consumer's operand that is such an alias of a marked candidate is retargeted
// to the candidate node itself (%R, splat form) when the use reads only
// element 0; alias uses this pass cannot classify are simply left pointing at
// the register, which holds %M -- the exact value -- so an unclassified use is
// never wrong, only unoptimized.  Cross-block consumers load the register in
// their own block, where no alias mapping exists, and likewise read %M.
//
// Uses are accounted against OrderedNode::GetUses() for the candidate itself:
// a candidate whose in-block classified uses do not cover every use it has
// (e.g. a multiblock SSA edge from another block) is left unmarked entirely.
//
// ---------------------------------------------------------------------------
// UPPER-ELEMENT LINEAGE FOR THE MERGE
//
// %M's DestVector must be the ARCHITECTURAL previous value of the guest
// register, i.e. merged form.  Through the register cache that is exactly the
// consumer's original Vector1 operand (an alias LoadRegister, reading the
// previous link's %M out of the register).  The one special case is a DIRECT
// SSA edge between two candidates (no flush in between): there the Vector1
// operand is the producer's %R -- splat form -- and using it as DestVector
// would forge the upper elements.  For that case the pass substitutes the
// producer's own %M, which is the same architectural value the register would
// have carried.  The arithmetic operand keeps %R either way (element 0 of
// splat and merged form agree by construction).
//
// FPSCR fidelity is unchanged: operands reach the xv* in splat form exactly as
// before (the backend splats any operand not already splat form), so every
// lane computes the same value and the sticky bits match one real computation.
//
//     FEX_DISABLESCALARSPLATCHAIN=1
// turns the pass off. The option is hashed into the code cache id
// (CodeCache.cpp HASH_OPT), so cached translations never cross the toggle.
// ---------------------------------------------------------------------------

namespace {
  // Producers this pass may mark: the four arithmetic ops whose lowering is
  // the DEF_SCALAR_INSERT macro in VectorOps.cpp, and the four FMA ops
  // (DEF_FMA_SCALAR_INSERT) -- both are the splat-operands + single xv* +
  // merge shape the transform reasons about. The families differ in operand
  // layout: arith merges its result over Vector1 (which is also a math
  // operand), FMA carries a dedicated Upper operand for the merge and its
  // three math operands (Vector1, Vector2, Addend) are elem0-only reads.
  bool IsArithProducer(IROps Op) {
    switch (Op) {
    case OP_VFADDSCALARINSERT:
    case OP_VFSUBSCALARINSERT:
    case OP_VFMULSCALARINSERT:
    case OP_VFDIVSCALARINSERT: return true;
    default: return false;
    }
  }

  bool IsFMAProducer(IROps Op) {
    switch (Op) {
    case OP_VFMLASCALARINSERT:
    case OP_VFMLSSCALARINSERT:
    case OP_VFNMLASCALARINSERT:
    case OP_VFNMLSSCALARINSERT: return true;
    default: return false;
    }
  }

  bool IsSplattableProducer(IROps Op) {
    return IsArithProducer(Op) || IsFMAProducer(Op);
  }

  // Which operand supplies the upper elements of the architectural result --
  // the DestVector of the explicit VInsElement merge this pass emits.
  uint8_t LineageArgIdx(IROps Op) {
    return IsFMAProducer(Op) ? IROp_VFMLAScalarInsert::Upper_Index : IROp_VFAddScalarInsert::Vector1_Index;
  }

  // SplatResult sits at different struct offsets in the two families.
  void SetSplatResult(IROp_Header* IROp) {
    if (IsFMAProducer(IROp->Op)) {
      IROp->CW<IROp_VFMLAScalarInsert>()->SplatResult = true;
    } else {
      IROp->CW<IROp_VFAddScalarInsert>()->SplatResult = true;
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

    // FMA ops have no ZeroUpperBits field: the AVX zero-upper semantic is
    // encoded by the frontend through the Upper operand itself, which this
    // pass carries into the merge unchanged.
    if (IsFMAProducer(IROp->Op)) {
      return true;
    }

    // The four arithmetic ops share the ZeroUpperBits field at the same place.
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
    // The merge node (%M), created in the apply phase.
    Ref Merge {};
    bool Marked {true};
    // Every classified use is either a splat-forward (reads element 0 only,
    // retarget to %R) or a merge use (needs the architectural value, retarget
    // to %M). Only DIRECT uses of the candidate node need merge retargeting;
    // alias uses left alone already read %M through the register.
  };

  struct Forward {
    Ref User {};
    uint8_t ArgIdx {};
    uint32_t CandIdx {};
  };
  struct MergeUse {
    Ref User {};
    uint8_t ArgIdx {};
    uint32_t CandIdx {};
  };

  // One entry per node whose value this pass understands: the candidate itself
  // and every LoadRegister aliasing it through the register cache.
  struct Tracked {
    Ref Node {};
    uint32_t CandIdx {};
    bool IsAlias {};
  };

  // SSA id -> index into Trackeds, or kNone. Allocated once for the whole IR
  // and cleared entry-by-entry between blocks.
  fextl::vector<uint32_t> TrackedOf;
  fextl::vector<Tracked> Trackeds;
  fextl::vector<Candidate> Candidates;
  fextl::vector<Forward> Forwards;
  fextl::vector<MergeUse> MergeUses;
  fextl::vector<uint32_t> CandUsesSeen;
};

void ScalarSplatChain::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::ScalarSplatChain");

  auto CurrentIR = IREmit->ViewIR();

  TrackedOf.clear();
  TrackedOf.resize(CurrentIR.GetSSACount(), kNone);

  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    Candidates.clear();
    Trackeds.clear();
    Forwards.clear();
    MergeUses.clear();
    CandUsesSeen.clear();

    // Which candidate's value currently sits in each SRA vector register.
    uint32_t CurSRA[kNumSRAFPRs];
    for (size_t i = 0; i < kNumSRAFPRs; ++i) {
      CurSRA[i] = kNone;
    }

    auto Track = [&](Ref Node, uint32_t CandIdx, bool IsAlias) {
      TrackedOf[CurrentIR.GetID(Node).Value] = static_cast<uint32_t>(Trackeds.size());
      Trackeds.emplace_back(Tracked {.Node = Node, .CandIdx = CandIdx, .IsAlias = IsAlias});
    };

    // Resolve an operand to the tracked entry carrying its value, following
    // the register-cache alias. The bounds check matters: merge nodes emitted
    // for EARLIER blocks have SSA ids past TrackedOf's initial sizing, and a
    // multiblock argument may name one.
    auto TrackedOfArg = [&](OrderedNodeWrapper Arg) -> uint32_t {
      if (Arg.IsInvalid() || Arg.IsImmediate() || Arg.ID().Value >= TrackedOf.size()) {
        return kNone;
      }
      return TrackedOf[Arg.ID().Value];
    };
    auto CandidateOfArg = [&](OrderedNodeWrapper Arg) -> uint32_t {
      const uint32_t T = TrackedOfArg(Arg);
      return T == kNone ? kNone : Trackeds[T].CandIdx;
    };

    // ------------------------------------------------------------------
    // Analysis walk: no mutation. Collect candidates, the register-cache
    // alias map, and a classification of every use of a tracked node.
    // ------------------------------------------------------------------
    for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
      // Register a candidate BEFORE classifying its operands, so a use
      // recorded below can name this node as its consumer. A node is never
      // its own operand, so this cannot self-count.
      if (IsEligible(IROp)) {
        const uint32_t Idx = static_cast<uint32_t>(Candidates.size());
        Candidates.emplace_back(Candidate {.Node = CodeNode, .IROp = IROp});
        CandUsesSeen.push_back(0);
        Track(CodeNode, Idx, false);
      }

      // --- classify this op's uses of anything tracked -------------------
      const uint8_t NumArgs = IR::GetArgs(IROp->Op);
      for (uint8_t i = 0; i < NumArgs; ++i) {
        const auto Arg = IROp->Args[i];
        if (Arg.IsInvalid() || Arg.IsImmediate()) {
          continue;
        }

        const uint32_t TIdx = TrackedOfArg(Arg);
        if (TIdx == kNone) {
          continue;
        }

        const auto& T = Trackeds[TIdx];
        const uint32_t CandIdx = T.CandIdx;
        auto& C = Candidates[CandIdx];
        if (!T.IsAlias) {
          ++CandUsesSeen[CandIdx];
        }

        // Element-0-only readers of the same element size take splat form.
        //   * an arith ScalarInsert's Vector1 (the arithmetic reads element 0;
        //     the consumer's own merge takes its upper elements from its
        //     ORIGINAL operand, handled in the apply phase);
        //   * an element-0-only reader's Vector2;
        //   * an FMA ScalarInsert's Vector1/Vector2/Addend -- the backend
        //     splats each from element 0 (or passes a splat-form value
        //     through) regardless of the consumer's own marking; its Upper
        //     operand is merge lineage, NOT an element-0 read, and falls
        //     through to the merge-use classification below;
        //   * a narrow FPR StoreMem (both store paths read only bits inside
        //     element 0, and the backend skips its positioning permute for a
        //     splat-form operand).
        if (IROp->ElementSize == C.IROp->ElementSize) {
          const bool Fwd = IsFMAProducer(IROp->Op) ?
            (i == IROp_VFMLAScalarInsert::Vector1_Index || i == IROp_VFMLAScalarInsert::Vector2_Index ||
             i == IROp_VFMLAScalarInsert::Addend_Index) :
            ((i == IROp_VFAddScalarInsert::Vector1_Index && IsEligible(IROp)) ||
             (i == IROp_VFAddScalarInsert::Vector2_Index && ReadsOnlyElement0OfVector2(IROp->Op)));
          if (Fwd) {
            Forwards.push_back(Forward {.User = CodeNode, .ArgIdx = i, .CandIdx = CandIdx});
            continue;
          }
        }
        if (IROp->Op == OP_STOREMEM && i == IROp_StoreMem::Value_Index && IROp->C<IROp_StoreMem>()->Class == RegClass::FPR &&
            IR::OpSizeToSize(IROp->Size) <= IR::OpSizeToSize(C.IROp->ElementSize)) {
          Forwards.push_back(Forward {.User = CodeNode, .ArgIdx = i, .CandIdx = CandIdx});
          continue;
        }

        // Anything else: a DIRECT use of the candidate must be retargeted to
        // the merge (%M) so it keeps seeing the architectural value. An alias
        // use needs nothing -- the register it read already holds %M.
        if (!T.IsAlias) {
          MergeUses.push_back(MergeUse {.User = CodeNode, .ArgIdx = i, .CandIdx = CandIdx});
        }
      }

      // --- then update the register-cache model --------------------------
      // Order matters: a StoreRegister's own operand is classified above
      // against the state BEFORE the store, and the alias it establishes is
      // visible only to later LoadRegisters. Propagates through movaps-style
      // register copies too: the stored value may itself be an alias.
      if (const int SReg = FPRStoreTarget(CodeNode, IROp); SReg >= 0) {
        CurSRA[SReg] = CandidateOfArg(IROp->Args[IROp_StoreRegister::Value_Index]);
      } else if (const int LReg = FPRLoadSource(IROp); LReg >= 0 && CurSRA[LReg] != kNone) {
        Track(CodeNode, CurSRA[LReg], true);
      }
    }

    // A candidate whose directly-classified uses do not account for every use
    // it has is referenced from somewhere this walk could not see (a
    // multiblock SSA edge from another block, an op shape not modeled here).
    // Such a use would keep reading splat form after marking, so the
    // candidate is left alone entirely.
    for (uint32_t CandIdx = 0; CandIdx < Candidates.size(); ++CandIdx) {
      if (CandUsesSeen[CandIdx] != Candidates[CandIdx].Node->GetUses()) {
        Candidates[CandIdx].Marked = false;
      }
    }

    // A Vector1 forward is only sound when BOTH sides are marked: the
    // producer for splat form to exist, the consumer because an unmarked
    // consumer's inline merge reads Vector1's upper elements. Vector2 and
    // StoreMem forwards need only the producer. Drop the rest.
    // (Consumer lookup: the user of a Vector1 forward is itself eligible and
    // therefore a candidate in this block's list.)
    auto CandidateIndexOfNode = [&](Ref Node) -> uint32_t {
      const uint32_t ID = CurrentIR.GetID(Node).Value;
      if (ID >= TrackedOf.size()) {
        return kNone;
      }
      const uint32_t T = TrackedOf[ID];
      return (T == kNone || Trackeds[T].IsAlias) ? kNone : Trackeds[T].CandIdx;
    };

    // ------------------------------------------------------------------
    // Apply phase 1: create every marked candidate's merge node. Reads each
    // candidate's CURRENT lineage operand (arith: Vector1, FMA: Upper), so
    // this must run before any operand retargeting. A direct-edge lineage
    // operand (producer candidate node) is substituted with that producer's
    // %M -- the architectural value -- which exists because phase 1 runs in
    // program order.
    // ------------------------------------------------------------------
    for (auto& C : Candidates) {
      if (!C.Marked) {
        continue;
      }
      auto V1Wrap = C.IROp->Args[LineageArgIdx(C.IROp->Op)];
      Ref V1 = CurrentIR.GetNode(V1Wrap);
      if (const uint32_t TIdx = TrackedOfArg(V1Wrap); TIdx != kNone && !Trackeds[TIdx].IsAlias) {
        const uint32_t PIdx = Trackeds[TIdx].CandIdx;
        // Direct SSA edge between candidates: the operand is splat form; its
        // architectural counterpart is the producer's merge. An unmarked
        // producer has no merge and its value IS architectural -- keep it.
        if (Candidates[PIdx].Marked) {
          V1 = Candidates[PIdx].Merge;
        }
      }

      IREmit->SetWriteCursor(C.Node);
      C.Merge = IREmit->_VInsElement(OpSize::i128Bit, C.IROp->ElementSize, 0, 0, V1, C.Node);
      SetSplatResult(C.IROp);
    }

    // ------------------------------------------------------------------
    // Apply phase 2: retarget uses.
    // ------------------------------------------------------------------
    for (const auto& M : MergeUses) {
      auto& C = Candidates[M.CandIdx];
      if (!C.Marked) {
        continue;
      }
      IREmit->ReplaceNodeArgument(M.User, M.ArgIdx, C.Merge);
    }

    for (const auto& F : Forwards) {
      auto& C = Candidates[F.CandIdx];
      if (!C.Marked) {
        continue;
      }
      const auto* UserOp = CurrentIR.GetOp<IROp_Header>(F.User);
      // The both-marked rule applies only to an ARITH consumer's Vector1: an
      // unmarked arith consumer's inline merge reads Vector1's upper
      // elements. FMA math operands are elem0-only regardless of the
      // consumer's marking (its lineage is the separate Upper operand), so
      // they need only the producer -- same as Vector2/StoreMem forwards.
      if (F.ArgIdx == IROp_VFAddScalarInsert::Vector1_Index && IsArithProducer(UserOp->Op)) {
        const uint32_t ConsumerIdx = CandidateIndexOfNode(F.User);
        if (ConsumerIdx == kNone || !Candidates[ConsumerIdx].Marked) {
          // Dropped forward. An ALIAS arg still reads %M through the register
          // and needs nothing; but a DIRECT SSA edge already names the
          // candidate -- splat form -- and the unmarked consumer's inline
          // merge would read its forged upper elements. Point it at %M.
          if (CurrentIR.GetNode(UserOp->Args[F.ArgIdx]) == C.Node) {
            IREmit->ReplaceNodeArgument(F.User, F.ArgIdx, C.Merge);
          }
          continue;
        }
      }
      IREmit->ReplaceNodeArgument(F.User, F.ArgIdx, C.Node);
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
