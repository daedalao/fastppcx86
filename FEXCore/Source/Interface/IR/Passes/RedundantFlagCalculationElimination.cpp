// SPDX-License-Identifier: MIT
/*
$info$
tags: ir|opts
$end_info$
*/

#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/Passes.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/deque.h>
#include <FEXCore/fextl/vector.h>

#include <cstdlib>

// Flag bit flags
#define FLAG_V (1U << 0)
#define FLAG_C (1U << 1)
#define FLAG_Z (1U << 2)
#define FLAG_N (1U << 3)
#define FLAG_P (1U << 4)
#define FLAG_A (1U << 5)

#define FLAG_ZCV (FLAG_Z | FLAG_C | FLAG_V)
#define FLAG_NZCV (FLAG_N | FLAG_ZCV)
#define FLAG_ALL (FLAG_NZCV | FLAG_A | FLAG_P)

namespace FEXCore::IR {

struct FlagInfoUnpacked {
  // Set of flags read by the instruction.
  unsigned Read;

  // Set of flags written by the instruction. Happens AFTER the reads.
  unsigned Write;

  // If true, the instruction can be be eliminated if its flag writes can all be
  // eliminated.
  bool CanEliminate;

  // If set, the opcode can be replaced with Replacement if its flag writes can
  // all be eliminated, or ReplacementNoWrite if its register write can be
  // eliminated.
  IROps Replacement;
  IROps ReplacementNoWrite;

  // Needs speical handling
  bool Special;
};

struct FlagInfo {
  uint64_t Raw;

  static constexpr struct FlagInfo Pack(struct FlagInfoUnpacked F) {
    uint64_t R = F.Read | (F.Write << 8) | (F.CanEliminate << 16) | (((uint64_t)F.Replacement) << 32) |
                 ((uint64_t)F.ReplacementNoWrite << 48) | (F.Special ? (1ull << 63) : 0);
    return {.Raw = R};
  }

  bool Trivial() const {
    return Raw == 0;
  }

  unsigned Read() const {
    return Bits(0, 8);
  }

  unsigned Write() const {
    return Bits(8, 8);
  }

  bool CanEliminate() const {
    return Bits(16, 1);
  }

  bool Special() const {
    return Bits(63, 1);
  }

  IROps Replacement() const {
    return (IROps)Bits(32, 16);
  }

  IROps ReplacementNoWrite() const {
    return (IROps)Bits(48, 16);
  }

private:
  unsigned Bits(unsigned Start, unsigned Count) const {
    return (Raw >> Start) & ((1u << Count) - 1);
  }
};

struct BlockInfo {
  fextl::vector<uint32_t> Predecessors;
  Ref Node;
  uint8_t Flags;
  bool InWorklist;
};

struct ControlFlowGraph {
  fextl::vector<BlockInfo> BlockMap;
  IRListView& IR;

  void Init(fextl::deque<uint32_t>& Worklist, uint32_t BlockCount) {
    BlockMap.resize(BlockCount);

    for (unsigned ID = 0; ID < BlockCount; ++ID) {
      // Add the block with conservative flags and already in the worklist.
      auto Info = BlockInfo {{}, nullptr, FLAG_ALL, true};

      // Add some initial capacity
      Info.Predecessors.reserve(2);

      BlockMap[ID] = std::move(Info);
      Worklist.push_back(ID);
    }
  }

  BlockInfo* Get(uint32_t Block) {
    return &BlockMap[Block];
  }

  BlockInfo* Get(IROp_CodeBlock* Block) {
    return &BlockMap[Block->ID];
  }

  BlockInfo* Get(OrderedNodeWrapper Block) {
    return Get(IR.GetOp<IR::IROp_CodeBlock>(Block));
  }

  void RecordEdge(uint32_t From, OrderedNodeWrapper To) {
    auto Info = Get(To);
    Info->Predecessors.push_back(From);
  }

  void AddWorklist(fextl::deque<uint32_t>& Worklist, uint32_t Block) {
    auto Info = Get(Block);
    if (!Info->InWorklist) {
      Info->InWorklist = true;
      Worklist.push_front(Block);
    }
  }
};

class DeadFlagCalculationEliminination final : public FEXCore::IR::Pass {
public:
  void Run(IREmitter* IREmit) override;

private:
  FEX_CONFIG_OPT(DisableDFCEStoreElim, DISABLEDFCESTOREELIM);
  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);

public:
  // Stateless, and shared with CompareBranchFusion via IROpWritesNZCV below.
  static FlagInfo Classify(IROp_Header* Node);
  static unsigned FlagsForCondClassType(CondClass Cond);

private:
  bool EliminateDeadCode(IREmitter* IREmit, Ref CodeNode, IROp_Header* IROp);
  void FoldBranch(IREmitter* IREmit, IRListView& CurrentIR, IROp_CondJump* Op, Ref CodeNode);
  CondClass X86ToArmFloatCond(CondClass X86);
  bool ProcessBlock(IREmitter* IREmit, IRListView& CurrentIR, Ref Block, ControlFlowGraph& CFG);
  void OptimizeParity(IREmitter* IREmit, IRListView& CurrentIR, ControlFlowGraph& CFG);
};

unsigned DeadFlagCalculationEliminination::FlagsForCondClassType(CondClass Cond) {
  switch (Cond) {
  case CondClass::AL: return 0;

  case CondClass::MI:
  case CondClass::PL: return FLAG_N;

  case CondClass::EQ:
  case CondClass::NEQ: return FLAG_Z;

  case CondClass::UGE:
  case CondClass::ULT: return FLAG_C;

  case CondClass::VS:
  case CondClass::VC:
  case CondClass::FU:
  case CondClass::FNU: return FLAG_V;

  case CondClass::UGT:
  case CondClass::ULE: return FLAG_Z | FLAG_C;

  case CondClass::SGE:
  case CondClass::SLT:
  case CondClass::FLU:
  case CondClass::FGE: return FLAG_N | FLAG_V;

  case CondClass::SGT:
  case CondClass::SLE:
  case CondClass::FLEU:
  case CondClass::FGT: return FLAG_N | FLAG_Z | FLAG_V;

  default: LOGMAN_THROW_A_FMT(false, "unknown cond class type"); return FLAG_NZCV;
  }
}

constexpr FlagInfo ClassifyConst(IROps Op) {
  switch (Op) {
  case OP_ANDWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_AND,
      .ReplacementNoWrite = OP_TESTNZ,
    });

  case OP_ADDWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_ADD,
      .ReplacementNoWrite = OP_ADDNZCV,
    });

  case OP_SUBWITHFLAGS:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .Replacement = OP_SUB,
      .ReplacementNoWrite = OP_SUBNZCV,
    });

  case OP_ADCWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_ADC,
      .ReplacementNoWrite = OP_ADCNZCV,
    });

  case OP_ADCZEROWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_ADCZERO,
    });

  case OP_SBBWITHFLAGS:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .Replacement = OP_SBB,
      .ReplacementNoWrite = OP_SBBNZCV,
    });

  case OP_SHIFTFLAGS:
    // _ShiftFlags conditionally sets NZCV+PF, which we model here as a
    // read-modify-write. Logically, it also conditionally makes AF undefined,
    // which we model by omitting AF from both Read and Write sets (since
    // "cond ? AF : undef" may be optimized to "AF").
    return FlagInfo::Pack({
      .Read = FLAG_NZCV | FLAG_P,
      .Write = FLAG_NZCV | FLAG_P,
      .CanEliminate = true,
    });

  case OP_ROTATEFLAGS:
    // _RotateFlags conditionally sets CV, again modeled as RMW.
    return FlagInfo::Pack({
      .Read = FLAG_C | FLAG_V,
      .Write = FLAG_C | FLAG_V,
      .CanEliminate = true,
    });

  case OP_RDRAND: return FlagInfo::Pack({.Write = FLAG_NZCV});

  case OP_ADDNZCV:
  case OP_SUBNZCV:
  case OP_TESTNZ:
  case OP_FCMP:
  case OP_STORENZCV:
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_AXFLAG:
    // Per the Arm spec, axflag reads Z/V/C but not N. It writes all flags.
    return FlagInfo::Pack({
      .Read = FLAG_ZCV,
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_FCMPX86:
    // Fused FCmp+AXFLAG: writes final x86-layout NZCV from its float inputs.
    // PF rides out through the op's GPR result (a normal SSA def consumed by
    // a StoreRegister the pass tracks separately), so NOT eliminable here —
    // deleting the node would orphan that use even when the NZCV write is
    // dead.
    return FlagInfo::Pack({
      .Write = FLAG_NZCV,
      .CanEliminate = false,
    });

  case OP_CMPPAIRZ:
    return FlagInfo::Pack({
      .Write = FLAG_Z,
      .CanEliminate = true,
    });

  case OP_CARRYINVERT:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_C,
      .CanEliminate = true,
    });

  case OP_SETSMALLNZV:
    return FlagInfo::Pack({
      .Write = FLAG_N | FLAG_Z | FLAG_V,
      .CanEliminate = true,
    });

  case OP_LOADNZCV: return FlagInfo::Pack({.Read = FLAG_NZCV});

  case OP_ADC:
  case OP_ADCZERO:
  case OP_SBB: return FlagInfo::Pack({.Read = FLAG_C});

  case OP_ADCNZCV:
  case OP_SBBNZCV:
    return FlagInfo::Pack({
      .Read = FLAG_C,
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });

  case OP_LOADPF: return FlagInfo::Pack({.Read = FLAG_P});
  case OP_LOADAF: return FlagInfo::Pack({.Read = FLAG_A});
  case OP_STOREPF: return FlagInfo::Pack({.Write = FLAG_P, .CanEliminate = true});
  case OP_STOREAF: return FlagInfo::Pack({.Write = FLAG_A, .CanEliminate = true});

  case OP_NZCVSELECT:
  case OP_NZCVSELECTV:
  case OP_NZCVSELECTINCREMENT:
  case OP_NEG:
  case OP_CONDJUMP:
  case OP_CONDSUBNZCV:
  case OP_CONDADDNZCV:
  case OP_RMIFNZCV:
  case OP_INVALIDATEFLAGS: return FlagInfo::Pack({.Special = true});
  default: return FlagInfo::Pack({});
  }
}

constexpr auto FlagInfos = std::invoke([] {
  std::array<FlagInfo, OP_LAST> ret = {};

  for (unsigned i = 0; i < OP_LAST; ++i) {
    ret[i] = ClassifyConst((IROps)i);
  }

  return ret;
});

FlagInfo DeadFlagCalculationEliminination::Classify(IROp_Header* IROp) {
  FlagInfo Info = FlagInfos[IROp->Op];
  if (!Info.Special()) {
    return Info;
  }

  switch (IROp->Op) {
  case OP_NZCVSELECT:
  case OP_NZCVSELECTINCREMENT: {
    auto Op = IROp->CW<IR::IROp_NZCVSelect>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_NZCVSELECTV: {
    auto Op = IROp->CW<IR::IROp_NZCVSelectV>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_NEG: {
    auto Op = IROp->CW<IR::IROp_Neg>();
    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_CONDJUMP: {
    auto Op = IROp->CW<IR::IROp_CondJump>();
    if (!Op->FromNZCV) {
      return FlagInfo::Pack({});
    }

    return FlagInfo::Pack({.Read = FlagsForCondClassType(Op->Cond)});
  }

  case OP_CONDSUBNZCV:
  case OP_CONDADDNZCV: {
    auto Op = IROp->CW<IR::IROp_CondAddNZCV>();
    return FlagInfo::Pack({
      .Read = FlagsForCondClassType(Op->Cond),
      .Write = FLAG_NZCV,
      .CanEliminate = true,
    });
  }

  case OP_RMIFNZCV: {
    auto Op = IROp->CW<IR::IROp_RmifNZCV>();

    static_assert(FLAG_N == (1 << 3), "rmif mask lines up with our bits");
    static_assert(FLAG_Z == (1 << 2), "rmif mask lines up with our bits");
    static_assert(FLAG_C == (1 << 1), "rmif mask lines up with our bits");
    static_assert(FLAG_V == (1 << 0), "rmif mask lines up with our bits");

    return FlagInfo::Pack({
      .Write = Op->Mask,
      .CanEliminate = true,
    });
  }

  case OP_INVALIDATEFLAGS: {
    auto Op = IROp->CW<IR::IROp_InvalidateFlags>();
    unsigned Flags = 0;

    // TODO: Make this translation less silly
    if (Op->Flags & (1u << X86State::RFLAG_SF_RAW_LOC)) {
      Flags |= FLAG_N;
    }

    if (Op->Flags & (1u << X86State::RFLAG_ZF_RAW_LOC)) {
      Flags |= FLAG_Z;
    }

    if (Op->Flags & (1u << X86State::RFLAG_CF_RAW_LOC)) {
      Flags |= FLAG_C;
    }

    if (Op->Flags & (1u << X86State::RFLAG_OF_RAW_LOC)) {
      Flags |= FLAG_V;
    }

    if (Op->Flags & (1u << X86State::RFLAG_PF_RAW_LOC)) {
      Flags |= FLAG_P;
    }

    if (Op->Flags & (1u << X86State::RFLAG_AF_RAW_LOC)) {
      Flags |= FLAG_A;
    }

    // The mental model of InvalidateFlags is writing undefined values to all
    // of the selected flags, allowing the write-after-write optimizations to
    // optimize invalidate-after-write for free.
    return FlagInfo::Pack({
      .Write = Flags,
      .CanEliminate = true,
    });
  }

  default: LOGMAN_THROW_A_FMT(false, "invalid special op"); FEX_UNREACHABLE;
  }

  FEX_UNREACHABLE;
}

// Exported for CompareBranchFusion, which must walk backwards past everything
// that is NOT a flag writer to find the compare feeding a branch. An op missing
// from a private copy of that set would let it walk past a real NZCV write and
// fuse the wrong compare -- silent and data-dependent -- so the answer is
// derived from the table above rather than restated.
bool IROpWritesNZCV(IROp_Header* IROp) {
  return (DeadFlagCalculationEliminination::Classify(IROp).Write() & FLAG_NZCV) != 0;
}

// General purpose dead code elimination. Returns whether flag handling should
// be skipped (because it was removed or could not possibly affect flags).
bool DeadFlagCalculationEliminination::EliminateDeadCode(IREmitter* IREmit, Ref CodeNode, IROp_Header* IROp) {
  // Can't remove anything used or with side effects.
  if (CodeNode->GetUses() > 0 || IR::HasSideEffects(IROp->Op)) {
    return false;
  }

  IREmit->Remove(CodeNode);
  return true;
}

CondClass DeadFlagCalculationEliminination::X86ToArmFloatCond(CondClass X86) {
  // Table of x86 condition codes that map to arm64 condition codes, in the
  // sense that fcmp+axflag+branch(x86) is equivalent to fcmp+branch(arm).
  //
  // E would be "equal or unordered", no condition code.
  // G would be "greater than or less than", no condition code.
  //
  // SF/OF conditions are trivial and therefore shouldn't actually be generated
  switch (X86) {
  // UGE = CF=0     = x86 "AE" (above-or-equal).  UGT = CF=0 && ZF=0 = x86 "A".
  // Previous comments had A / AE swapped.  Functional mapping was correct.
  case CondClass::UGE /* AE */: return CondClass::FGE /* GE */;
  case CondClass::UGT /* A  */: return CondClass::FGT /* GT */;
  case CondClass::ULT /* B  */: return CondClass::SLT /* LT */;
  case CondClass::ULE /* BE */: return CondClass::SLE /* LE */;
  case CondClass::SLE /* LE */: return CondClass::SLE /* LE */;
  default: return CondClass::AL;
  }
}

void DeadFlagCalculationEliminination::FoldBranch(IREmitter* IREmit, IRListView& CurrentIR, IROp_CondJump* Op, Ref CodeNode) {
  // A vector-compare CondJump (VCmpElementSize != iInvalid) carries FPR-class
  // values in Cmp1/Cmp2, and the folds below REPLACE those arguments with a
  // compare's GPR operands. Today we are unreachable for it -- the only caller
  // gates on Op->FromNZCV, which that mode never sets -- but that is a
  // coincidence of the caller, not a property of this function. Assert it, so
  // relaxing the caller's guard fails loudly instead of silently branching on
  // whatever GPR happened to be there.
  LOGMAN_THROW_A_FMT(Op->VCmpElementSize == IR::OpSize::iInvalid, "FoldBranch cannot rewrite a vector-compare CondJump's operands");

  // Skip past StoreRegisters at the end -- they don't touch flags.
  //
  // NOTE (ppc64le, measured 2026-08-05): this walk does NOT skip
  // OP_GUESTOPCODE, and Core.cpp emits a GuestOpcode marker before EVERY guest
  // instruction on this port (per-instruction markers are required for
  // instruction-granular RIP reconstruction, 7a8007a1e). The marker belonging
  // to the jcc therefore always sits immediately before the CondJump, so
  // BOTH arms below are unreachable here -- FoldBranch is dead on ppc64le
  // regardless of whether DFCE is enabled. Verified by IR dump: every
  // CondJump in unittests/ASM/FEX_bugs/FoldBranch_Sub8_Sub16.asm and
  // dfce_foldbranch_axflag.asm is preceded by `GuestOpcode`, and both files
  // still show the unfolded AXFLAG / SUBNZCV in the after-opt IR. That also
  // means FoldBranch_Sub8_Sub16.asm has never actually tested FoldBranch.
  auto PrevWrap = CodeNode->Header.Previous;
  while (CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREREGISTER ||
         CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREPF || CurrentIR.GetOp<IR::IROp_Header>(PrevWrap)->Op == OP_STOREAF) {
    PrevWrap = CurrentIR.GetNode(PrevWrap)->Header.Previous;
  }

  auto Prev = CurrentIR.GetOp<IR::IROp_Header>(PrevWrap);
  if (Prev->Op == OP_AXFLAG) {
    // The AXFLAG arm is DISABLED. It is measurably wrong, and it is only
    // "safe" today because the GuestOpcode marker above makes it unreachable
    // -- exactly the kind of accidental safety that stops being safe the
    // moment someone makes the marker skippable. So refuse it explicitly.
    //
    // Evidence (2026-08-05): with the predecessor walk temporarily taught to
    // skip OP_GUESTOPCODE, so this arm fires,
    // unittests/ASM/FEX_bugs/dfce_foldbranch_axflag.asm fails in jit_500_m:
    //   RAX (jae) = 0xE, expected 0x6  -- branch taken on UNORDERED
    //   RDI (jle) = 0xB, expected 0xA  -- branch taken on ordered LESS
    // Two independent defects, both in "remap the condition against the raw
    // Arm FCMP layout and delete the AXFLAG":
    //
    //  1. UGE -> FGE. The backend lowers CondClass::FGE under NZCV as
    //     PPC CC_GE = "CR0.LT clear", and fcmpu leaves LT clear for NaN
    //     (it sets FU/SO instead), so `jae` is taken on unordered. x86
    //     comiss sets CF=1 for unordered, so `jae` must NOT be taken.
    //     Arm's own GE is N==V, which excludes unordered -- CC_GE is not
    //     that. See MapNZCVCC in JIT/PPC64LE/JIT.cpp.
    //
    //     STATUS: half-fixed. MapNZCVCC now folds XER.OV (unordered) into
    //     both FGE and FLU via ProjectXERToCR1 + crnor/cror, so the packed-
    //     NZCV path is correct. MapCC still returns bare CC_GE / CC_LT and
    //     CANNOT be fixed in the table (it is static, and callers rebase its
    //     BI onto arbitrary CR fields) -- that one needs a caller-side
    //     composite. Defect 2 below is untouched.
    //
    //  2. SLE -> SLE (the identity remap) is wrong independent of the
    //     backend. x86 `jle` after comiss is ZF || (SF!=OF); comiss forces
    //     SF=OF=0, and AXFLAG sets Z_x86 = Z|V, so it means "equal or
    //     unordered". Evaluated instead against the RAW fcmp flags, Arm LE
    //     is Z || N!=V = equal || less || unordered -- it additionally
    //     fires on ordered less. This one is a property of the shared
    //     mapping table, not of PPC64LE.
    //
    // The SUBNZCV arm below is fine: with the same experiment, all three
    // ctest configurations of FoldBranch_Sub8_Sub16.asm pass. Only the
    // AXFLAG arm is rejected.
    //
    // Re-enabling requires fixing both defects and then re-running
    // dfce_foldbranch_axflag.asm under jit_500_m, which pins the correct
    // x86 answers for all five remappable conditions x all four comiss
    // outcomes whether or not the fold fires.
    return;
  } else if (Prev->Op == OP_SUBNZCV) {
    // Pattern match a branch fed by a compare. We could also handle bit tests
    // here, but tbz/tbnz has a limited offset range which we don't have a way to
    // deal with yet. Let's hope that's not a big deal.
    if (!(Op->Cond == CondClass::NEQ || Op->Cond == CondClass::EQ)) {
      return;
    }

    auto SecondArg = CurrentIR.GetOp<IR::IROp_Header>(Prev->Args[1]);
    if (SecondArg->Op != OP_INLINECONSTANT || SecondArg->C<IR::IROp_InlineConstant>()->Constant != 0) {
      return;
    }

    // We've matched. Fold the compare into branch.
    IREmit->ReplaceNodeArgument(CodeNode, 0, CurrentIR.GetNode(Prev->Args[0]));
    IREmit->ReplaceNodeArgument(CodeNode, 1, CurrentIR.GetNode(Prev->Args[1]));
    Op->FromNZCV = false;
    Op->CompareSize = Prev->Size;
  } else {
    return;
  }

  // The compare/test/axflag sets flags but does not write registers. Flags are
  // dead after the jump. The jump does not read flags anymore.  There is no
  // intervening instruction. Therefore the compare is dead.
  IREmit->Remove(CurrentIR.GetNode(PrevWrap));
}

/**
 * @brief This pass removes dead code locally.
 */
bool DeadFlagCalculationEliminination::ProcessBlock(IREmitter* IREmit, IRListView& CurrentIR, Ref Block, ControlFlowGraph& CFG) {
  uint32_t FlagsRead = FLAG_ALL;

  // Presence-check kill switch for the ReplacementNoWrite arm below (raw
  // getenv, resolved once per process — the convention for codegen-affecting
  // env toggles, e.g. FEX_NO_THUNK_PARTIAL_FILL). See the use site comment.
  static const bool NoWriteArmDisabled = getenv("FEX_NO_DFCE_NOWRITE") != nullptr;

  // Reverse iteration is not yet working with the iterators
  auto BlockIROp = CurrentIR.GetOp<IR::IROp_CodeBlock>(Block);

  // We grab these nodes this way so we can iterate easily
  auto CodeBegin = CurrentIR.at(BlockIROp->Begin);
  auto CodeLast = CurrentIR.at(BlockIROp->Last);

  // Advance past EndBlock to get at the exit.
  --CodeLast;

  // Initialize the FlagsRead mask according to the exit instruction.
  auto [ExitNode, ExitOp] = CodeLast();
  if (ExitOp->Op == IR::OP_CONDJUMP) {
    auto Op = ExitOp->CW<IR::IROp_CondJump>();
    FlagsRead = CFG.Get(Op->TrueBlock)->Flags | CFG.Get(Op->FalseBlock)->Flags;
  } else if (ExitOp->Op == IR::OP_JUMP) {
    FlagsRead = CFG.Get(ExitOp->Args[0])->Flags;
  }

  // Iterate the block in reverse
  while (true) {
    auto [CodeNode, IROp] = CodeLast();

    // Optimizing flags can cause earlier flag reads to become dead but dead
    // flag reads should not impede optimiation of earlier dead flag writes.
    // We must DCE as we go to ensure we converge in a single iteration.
    if (!EliminateDeadCode(IREmit, CodeNode, IROp)) {
      // Optimiation algorithm: For each flag written...
      //
      //  If the flag has a later read (per FlagsRead), remove the flag from
      //  FlagsRead, since the reader is covered by this write.
      //
      //  Else, there is no later read, so remove the flag write (if we can).
      //  This is the active part of the optimization.
      //
      // Then, add each flag read to FlagsRead.
      //
      // This order is important: instructions that read-modify-write flags
      // (like adcs) first read flags, then write flags. Since we're iterating
      // the block backwards, that means we handle the write first.
      struct FlagInfo Info = Classify(IROp);

      if (!Info.Trivial()) {
        bool Eliminated = false;

        if ((FlagsRead & Info.Write()) == 0) {
          // EliminateDeadCode() above already refuses to drop side-effecting
          // ops, so anything that reaches here with GetUses()==0 is
          // side-effecting by construction -- an op like StoreNZCV / StorePF /
          // StoreAF / ShiftFlags has its *observable* effect in the flag
          // state, not in its SSA result. Removing it here is nonetheless
          // sound: this arm is only reached when every flag the op writes is
          // dead per the converged cross-block liveness ((FlagsRead &
          // Info.Write()) == 0), and for CanEliminate/Replacement ops the
          // flag write IS the side effect. Note the flags-precision caveat:
          // like the in-place Replacement rewrites below, removal makes dead
          // flag state imprecise at a synchronous fault between the removed
          // write and the overwriting one -- a trade FEX already makes.
          //
          // History: from 2026-08-05 to 2026-08-10 this arm additionally
          // required !IR::HasSideEffects(op), which made it unreachable (every
          // op classified CanEliminate/Replacement is side-effecting in
          // IR.json) -- so no flag store was ever removed, and hot
          // shift-flag/parity chains survived whole (measured: the W3 asset
          // decompressor block spent most of its host instructions on dead
          // CR0/XER<->GPR flag packing). The guard dated to the 2026-05-11
          // reproducers (32-bit ld.so _dl_sort_maps_dfs; bash SEGV), which no
          // longer reproduce with it removed (verified 2026-08-05: full ASM
          // suite, both reproducers, 60 bash startups; re-verified when this
          // knob landed). FEX_DISABLEDFCESTOREELIM=1 restores the guarded
          // behaviour in the field without a rebuild.
          if ((Info.CanEliminate() || Info.Replacement()) && CodeNode->GetUses() == 0 && !DisableDFCEStoreElim()) {
            IREmit->Remove(CodeNode);
            Eliminated = true;
          } else if (Info.Replacement()) {
            IROp->Op = Info.Replacement();
          }
        } else if (Info.ReplacementNoWrite() && CodeNode->GetUses() == 0 && Is64BitMode() && !NoWriteArmDisabled) {
          // ReplacementNoWrite: the value is SSA-dead but some written flag is
          // still live, so demote to the flags-only form (SubWithFlags ->
          // SubNZCV, AddWithFlags -> AddNZCV, AndWithFlags -> TestNZ,
          // Adc/SbbWithFlags -> Adc/SbbNZCV). This kills the dead value def
          // that otherwise occupies a register through compare-dense blocks
          // (CMP/TEST feed their result only to StorePF; once a dead StorePF
          // is removed above, the value has zero uses).
          //
          // 64-BIT GUESTS ONLY (as of 2026-08-13). History: disabled on all
          // hosts from 2026-05-11 (8774c7dda) because with it enabled, 32-bit
          // i686 guests corrupt — glibc's dynamic linker walks linked-list
          // maps and `_dl_sort_maps_dfs` trips its internal "rpo_head == rpo"
          // assertion. ARM64 reaches the same code paths but doesn't fail.
          // That ROOT CAUSE REMAINS OPEN: the i686 repro stays excluded
          // (32-bit mode keeps the arm off, byte-for-byte the old behaviour),
          // and the enabled sibling Replacement arm above performs the same
          // in-place pre-RA opcode rewrite, so if the mechanism is a
          // rewrite/RA interaction the sibling may share it. Note the
          // 2026-05-11 commit message also recorded the disable as gaining a
          // handful of 64-bit ASM tests at the time; several backend defects
          // of that era have since been fixed (CondJump TSTZ/TSTNZ cr7
          // routing in that same commit, the CR0/NZCV VectorOps clobber
          // eb1a4c858, the AdcWithFlags i32 OF-aliasing), and one more was
          // found by inspection while enabling this arm: DEF_OP(AdcNZCV) had
          // both carry polarities inverted and had never executed, since this
          // arm is its only producer (fixed alongside this enable; same class
          // as the DEF_OP(Adc) polarity bug).
          //
          // Kill switch (presence check, tree convention for raw codegen env
          // toggles): FEX_NO_DFCE_NOWRITE=1 disables the arm even for 64-bit
          // guests. It changes emitted code, so it is hashed into the code
          // cache config id (CodeCache.cpp).
          //
          // Cross-block gating tests for exactly this shape:
          // unittests/ASM/FEX_bugs/dfce_nowrite_*.asm,
          // dfce_crossblock_*.asm, dfce_flags_across_ret.asm.
          //
          // TODO(ppc64le): root-cause the i686 corruption, then either fix
          // the backend or drop the 64-bit gate.
          IROp->Op = Info.ReplacementNoWrite();
        }

        // If we don't care about the sign or carry, we can optimize testnz.
        // Carry is inverted between testz and testnz so we check that too. Note
        // this flag is outside of the if, since the TestNZ might result from
        // optimizing AndWithFlags, and we need to converge locally in a single
        // iteration.
        if (IROp->Op == OP_TESTNZ && IROp->Size < OpSize::i32Bit && !(FlagsRead & (FLAG_N | FLAG_C))) {
          IROp->Op = OP_TESTZ;
        }

        FlagsRead &= ~Info.Write();

        // If we eliminated the instruction, we eliminate its read too. This
        // check is required to ensure the pass converges locally in a single
        // iteration.
        if (!Eliminated) {
          FlagsRead |= Info.Read();
        }
      }
    }

    // Iterate in reverse
    if (CodeLast == CodeBegin) {
      break;
    }
    --CodeLast;
  }

  // For the purposes of global propagation, the content of our progress doesn't
  // matter -- only the difference in our final FlagsRead contributes to changes
  // in the predecessors.
  uint32_t OldFlagsRead = CFG.Get(BlockIROp->ID)->Flags;
  CFG.Get(BlockIROp->ID)->Flags = FlagsRead;
  return (OldFlagsRead != FlagsRead);
}

void DeadFlagCalculationEliminination::OptimizeParity(IREmitter* IREmit, IRListView& CurrentIR, ControlFlowGraph& CFG) {
  // Mapping for flags inside this pass.
  const uint8_t PARTIAL = 0;
  const uint8_t FULL = 1;

  // Initialize conservatively: all blocks need full parity. This initialization
  // matters for proper handling of backedges.
  for (auto [Block, BlockHeader] : CurrentIR.GetBlocks()) {
    auto ID = BlockHeader->C<IROp_CodeBlock>()->ID;
    CFG.Get(ID)->Flags = FULL;
  }

  for (auto [Block, BlockHeader] : CurrentIR.GetBlocks()) {
    const auto ID = BlockHeader->C<IROp_CodeBlock>()->ID;
    const auto& Predecessors = CFG.Get(ID)->Predecessors;
    bool Full = false;

    if (Predecessors.empty()) {
      // Conservatively assume there was full parity before the start block
      Full = true;
    } else {
      // If any predecessor needs full parity at the end, we need full parity.
      for (auto Pred : Predecessors) {
        Full |= (CFG.Get(Pred)->Flags == FULL);
      }
    }

    for (auto [CodeNode, IROp] : CurrentIR.GetCode(Block)) {
      if (IROp->Op == OP_STOREPF) {
        auto Op = IROp->CW<IR::IROp_StorePF>();
        auto Generator = CurrentIR.GetOp<IR::IROp_Header>(Op->Value);

        // Determine if we only write 0/1 to the parity flag.
        Full = true;
        if (Generator->Op == OP_NZCVSELECT) {
          auto C0 = CurrentIR.GetOp<IR::IROp_Header>(Generator->Args[0]);
          auto C1 = CurrentIR.GetOp<IR::IROp_Header>(Generator->Args[1]);
          if (C0->Op == C1->Op && C0->Op == OP_INLINECONSTANT) {
            auto IC0 = CurrentIR.GetOp<IR::IROp_InlineConstant>(Generator->Args[0]);
            auto IC1 = CurrentIR.GetOp<IR::IROp_InlineConstant>(Generator->Args[1]);

            // We need the full 8 if the constant has upper bits set.
            Full = (IC0->Constant | IC1->Constant) & ~1;
          }
        }
      } else if (IROp->Op == OP_PARITY && !Full) {
        // Eliminate parity calculations if it's only 1-bit.
        auto Parity = IROp->C<IROp_Parity>();
        Ref Value = CurrentIR.GetNode(Parity->Raw);

        if (Parity->Invert) {
          IREmit->SetWriteCursor(CodeNode);
          Value = IREmit->_Xor(OpSize::i32Bit, Value, IREmit->_InlineConstant(1));
        }

        IREmit->ReplaceUsesWithAfter(CodeNode, Value, CurrentIR.at(CodeNode));
        IREmit->Remove(CodeNode);
      }
    }

    // Record our final state for our successors to read.
    CFG.Get(ID)->Flags = Full ? FULL : PARTIAL;
  }
}

void DeadFlagCalculationEliminination::Run(IREmitter* IREmit) {
  FEXCORE_PROFILE_SCOPED("PassManager::DFE");

  auto CurrentIR = IREmit->ViewIR();
  fextl::deque<uint32_t> Worklist;

  // Initialize CFG
  ControlFlowGraph CFG {.IR = CurrentIR};
  CFG.Init(Worklist, CurrentIR.GetHeader()->BlockCount);

  // Gather CFG
  for (auto [BlockNode, BlockHeader] : CurrentIR.GetBlocks()) {
    auto Block = BlockHeader->C<IROp_CodeBlock>();
    auto CodeLast = CurrentIR.at(Block->Last);
    --CodeLast;
    auto [ExitNode, ExitOp] = CodeLast();
    if (ExitOp->Op == IR::OP_CONDJUMP) {
      auto Op = ExitOp->CW<IR::IROp_CondJump>();

      CFG.RecordEdge(Block->ID, Op->TrueBlock);
      CFG.RecordEdge(Block->ID, Op->FalseBlock);
    } else if (ExitOp->Op == IR::OP_JUMP) {
      CFG.RecordEdge(Block->ID, ExitOp->Args[0]);
    }

    CFG.Get(Block->ID)->Node = BlockNode;
  }

  // After processing a block, if we made progress, we must process its
  // predecessors to propagate globally. A block will be reprocessed only if
  // there is a loop backedge.
  for (; !Worklist.empty(); Worklist.pop_back()) {
    auto Block = Worklist.back();
    auto Info = CFG.Get(Block);
    Info->InWorklist = false;

    if (ProcessBlock(IREmit, CurrentIR, Info->Node, CFG)) {
      for (auto Pred : Info->Predecessors) {
        CFG.AddWorklist(Worklist, Pred);
      }
    }
  }

  // Fold compares into branches now that we're otherwise optimized. This needs
  // to run after eliminating carries etc and it needs the global flag metadata.
  // But it only needs to run once, we don't do it in the loop.
  for (auto [Block, _] : CurrentIR.GetBlocks()) {
    // Grab the jump
    auto BlockIROp = CurrentIR.GetOp<IR::IROp_CodeBlock>(Block);
    auto CodeLast = CurrentIR.at(BlockIROp->Last);
    --CodeLast;

    auto [ExitNode, ExitOp] = CodeLast();
    if (ExitOp->Op == IR::OP_CONDJUMP) {
      auto Op = ExitOp->CW<IR::IROp_CondJump>();
      uint32_t FlagsOut = CFG.Get(Op->TrueBlock)->Flags | CFG.Get(Op->FalseBlock)->Flags;

      if ((FlagsOut & FLAG_NZCV) == 0 && Op->FromNZCV) {
        FoldBranch(IREmit, CurrentIR, Op, ExitNode);
      }
    }
  }

  if (CurrentIR.GetHeader()->ReadsParity) {
    OptimizeParity(IREmit, CurrentIR, CFG);
  }
}

fextl::unique_ptr<FEXCore::IR::Pass> CreateDeadFlagCalculationEliminination() {
  return fextl::make_unique<DeadFlagCalculationEliminination>();
}

} // namespace FEXCore::IR
