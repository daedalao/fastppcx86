// SPDX-License-Identifier: MIT
// PPC64LE JIT backend class definition.
// Analogous to FEXCore/Source/Interface/Core/JIT/JITClass.h
#pragma once

#include "Interface/Core/ArchHelpers/PPC64Emitter.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/IR.h"
#include "Interface/IR/IntrusiveIRList.h"
#include "Interface/IR/RegisterAllocationData.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/LongJump.h>

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <variant>

namespace FEXCore::Core  { struct InternalThreadState; }
namespace FEXCore::Context { struct ExitFunctionLinkData; }
namespace FEXCore::IR { class RegisterAllocationPass; }

namespace FEXCore::CPU {

// RDRAND fallback (POWER8 has no `darn`); defined in JIT.cpp.
extern "C" uint64_t PPC64_RDRAND();

class PPC64JITCore final : public CPUBackend, public PPC64EmitterBase {
public:
  explicit PPC64JITCore(FEXCore::Context::ContextImpl* ctx,
                        FEXCore::Core::InternalThreadState* Thread);
  ~PPC64JITCore() override;

  [[nodiscard]]
  CPUBackend::CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst,
                                       const FEXCore::IR::IRListView* IR,
                                       FEXCore::Core::DebugData* DebugData,
                                       bool CheckTF) override;

  void ClearCache() override;

  void ClearRelocations() override { Relocations.clear(); }

  static uint64_t ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP);

  fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) override {
    return std::move(Relocations);
  }

private:
  FEXCore::Context::ContextImpl*     CTX {};
  const FEXCore::IR::IRListView*     IR {};
  uint64_t                           Entry {};
  CPUBackend::CompiledCode           CodeData {};

  // Per-block jump targets
  fextl::vector<PPC64Emitter::Label> JumpTargets;

  PPC64Emitter::Label* JumpTarget(IR::Ref Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    return &JumpTargets[Block->ID];
  }

  PPC64Emitter::Label* JumpTarget(IR::OrderedNodeWrapper Node) {
    auto Block = IR->GetOp<IR::IROp_CodeBlock>(Node);
    return &JumpTargets[Block->ID];
  }

  // Spill slots management.
  //
  // SpillSlots is sampled from IR->SpillSlots() at the top of CompileCode.
  // EmitEntryPoint allocates `SpillFrameSize` bytes below the dispatcher
  // frame via stdu r1, -SpillFrameSize, r1. SpillRegister/FillRegister then
  // address slots at POSITIVE offsets from the new r1: slot 0 at [r1+0],
  // slot 1 at [r1+32], etc. Every block-exit emit site calls ResetStack()
  // to undo the frame extension before transferring control out of the JIT.
  //
  // Mirrors Arm64JITCore::CompileCode + ResetStack (gemini-fex JIT.cpp:804
  // and JIT.cpp:1157). The previous fixed `SpillBase = -768` formula went
  // positive after slot 24 and silently walked off the top of r1; observed
  // as a SIGSEGV in add_sub_carry_2.asm.jit_500 where the RA spilled 200+
  // NZCV temps from 256 unrolled SBBs in a single IR block.
  uint32_t SpillSlots {};
  uint32_t SpillFrameSize {};

  int32_t SpillOffset(uint32_t slot) const {
    return static_cast<int32_t>(slot * MaxSpillSlotSize);
  }

  // -----------------------------------------------------------------------
  // Register helpers
  // -----------------------------------------------------------------------

  [[nodiscard]]
  GPR GetReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();
    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::GPRFixed || RegClass == IR::RegClass::GPR,
                       "Unexpected RegClass: {}", Reg.Class);
    if (RegClass == IR::RegClass::GPRFixed)
      return StaticRegisters[Reg.Reg];
    return GeneralRegisters[Reg.Reg];
  }

  [[nodiscard]] GPR GetReg(IR::Ref Node)              const { return GetReg(IR::PhysicalRegister(Node)); }
  // OrderedNodeWrapper carries either an immediate-encoded PhysicalRegister
  // (post-RA, IsImmediate=true) or an SSA pointer (pre-RA, points to an
  // OrderedNode whose Reg byte holds the PhysicalRegister). Build the right
  // PhysicalRegister depending on which form it's in — calling GetImmediate()
  // on a non-immediate wrapper produces a garbage Reg/Class byte and OOBs
  // the SRA/RA span.
  [[nodiscard]] GPR GetReg(IR::OrderedNodeWrapper W)  const {
    if (W.IsImmediate()) {
      return GetReg(IR::PhysicalRegister(W));
    }
    return GetReg(IR::PhysicalRegister(IR->GetNode(W)));
  }

  [[nodiscard]]
  VR GetVReg(IR::PhysicalRegister Reg) const {
    const auto RegClass = Reg.AsRegClass();
    LOGMAN_THROW_A_FMT(RegClass == IR::RegClass::FPRFixed || RegClass == IR::RegClass::FPR,
                       "Unexpected RegClass: {}", Reg.Class);
    if (RegClass == IR::RegClass::FPRFixed)
      return StaticFPRegisters[Reg.Reg];
    return GeneralFPRegisters[Reg.Reg];
  }

  [[nodiscard]] VR GetVReg(IR::Ref Node)              const { return GetVReg(IR::PhysicalRegister(Node)); }
  [[nodiscard]] VR GetVReg(IR::OrderedNodeWrapper W)  const {
    if (W.IsImmediate()) {
      return GetVReg(IR::PhysicalRegister(W));
    }
    return GetVReg(IR::PhysicalRegister(IR->GetNode(W)));
  }

  [[nodiscard]]
  static IR::RegClass GetRegClass(IR::Ref Node) {
    return IR::PhysicalRegister(Node).AsRegClass();
  }

  [[nodiscard]]
  static bool IsFPR(IR::RegClass C) {
    return C == IR::RegClass::FPR || C == IR::RegClass::FPRFixed;
  }
  [[nodiscard]] static bool IsFPR(IR::Ref N) { return IsFPR(GetRegClass(N)); }
  [[nodiscard]] static bool IsFPR(IR::OrderedNodeWrapper W) {
    return IsFPR(IR::PhysicalRegister(W).AsRegClass());
  }
  [[nodiscard]]
  static bool IsGPR(IR::RegClass C) {
    return C == IR::RegClass::GPR || C == IR::RegClass::GPRFixed;
  }
  [[nodiscard]] static bool IsGPR(IR::Ref N) { return IsGPR(GetRegClass(N)); }
  [[nodiscard]] static bool IsGPR(IR::OrderedNodeWrapper W) {
    return IsGPR(IR::PhysicalRegister(W).AsRegClass());
  }

  [[nodiscard]]
  bool IsInlineConstant(const IR::OrderedNodeWrapper& Node, uint64_t* Value = nullptr) const;

  [[nodiscard]]
  bool IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode, uint64_t* Value) const;

  // Get a register that may be zero-register if the node is constant 0
  [[nodiscard]]
  GPR GetZeroableReg(IR::OrderedNodeWrapper Src) const {
    uint64_t Const;
    if (IsInlineConstant(Src, &Const) && Const == 0) {
      return r0;  // r0 reads as 0 in many PPC instructions (addi RA=r0 means imm only)
    }
    return GetReg(Src);
  }

  // -----------------------------------------------------------------------
  // Size helpers
  // -----------------------------------------------------------------------

  [[nodiscard]]
  static bool Is32Bit(const IR::IROp_Header* Op) {
    return Op->Size < IR::OpSize::i64Bit;
  }

  // Mask a value to N-bit width in-place, needed for sub-32-bit ops
  void MaskForSize(GPR dst, GPR src, IR::OpSize sz) {
    switch (sz) {
    case IR::OpSize::i8Bit:
      rlwinm(dst, src, 0, 24, 31);  // AND with 0xFF
      break;
    case IR::OpSize::i16Bit:
      rlwinm(dst, src, 0, 16, 31);  // AND with 0xFFFF
      break;
    case IR::OpSize::i32Bit:
      rlwinm(dst, src, 0, 0, 31);   // clear upper 32 bits
      break;
    default:
      if (dst != src) mr(dst, src);
      break;
    }
  }

  void SignExtendForSize(GPR dst, GPR src, IR::OpSize sz) {
    switch (sz) {
    case IR::OpSize::i8Bit:  extsb(dst, src); break;
    case IR::OpSize::i16Bit: extsh(dst, src); break;
    case IR::OpSize::i32Bit: extsw(dst, src); break;
    default: if (dst != src) mr(dst, src); break;
    }
  }

  // -----------------------------------------------------------------------
  // Condition mapping (from IR CondClass to PPC64 branch condition)
  // We use CR0 for all comparisons.
  // -----------------------------------------------------------------------
  [[nodiscard]]
  static PPC64Emitter::Cond MapCC(IR::CondClass Cond);

  // Emit compare for a CondJump that evaluates Src1 op Src2.
  // After this, CR0 reflects the comparison result for MapCC(Cond).
  void EmitCompare(IR::CondClass Cond, IR::OpSize Sz,
                   IR::OrderedNodeWrapper Src1, IR::OrderedNodeWrapper Src2);

  // Project XER.SO/OV/CA -> CR1.LT/GT/EQ non-destructively. Used to make
  // C/V flags branch-testable after an x86 *WithFlags op. Clobbers TMP1, TMP2.
  void ProjectXERToCR1();

  // Write a 4-bit NZCV literal (bit3=N, bit2=Z, bit1=C, bit0=V) into our
  // flag domain (CR0.LT/EQ + XER.CA/OV). Other CR0 / XER bits preserved.
  // Used by CondAddNZCV / CondSubNZCV "false" paths.
  void SetNZCVConstant(uint8_t NZCV);

  // After a sub-64-bit AND result has been computed in `Result`, mask/extend
  // it to the IR operand size and set CR0 from the resized value, so that
  // CR0.LT/EQ encode SF/ZF for the operand width (TestNZ/TestZ helper).
  void EmitTestNZSetCR(GPR Result, IR::OpSize Size);

  // Build a 16-byte vperm control vector at r1-16 then `lvx` into Dst.
  // hi packs phys[8..15] (byte 7 = phys[8], byte 0 = phys[15]).
  // lo packs phys[0..7]  (byte 7 = phys[0], byte 0 = phys[7]).
  void LoadPermCtrl(VR Dst, uint64_t hi, uint64_t lo);

  // Map an IR CondClass to a PPC bc cond using NZCV semantics — i.e., the
  // condition is decoded against the packed PSTATE NZCV flags rather than a
  // direct compare. May emit ProjectXERToCR1() and CR-bit ops (crand/crxor/...)
  // to synthesize composite conditions; returns the {BO, BI} for the final bc.
  PPC64Emitter::Cond MapNZCVCC(IR::CondClass Cond);

  // -----------------------------------------------------------------------
  // Stack management
  // -----------------------------------------------------------------------
  void ResetStack();

  // -----------------------------------------------------------------------
  // Relocation support
  // -----------------------------------------------------------------------
  fextl::vector<FEXCore::CPU::Relocation> Relocations;

  // Load a named thunk's function pointer into Reg via LoadConstant, recording
  // a RELOC_NAMED_THUNK_MOVE relocation for code-cache patching.
  void InsertNamedThunkRelocation(GPR Reg, const IR::SHA256Sum& Sum);

  // Load a 64-bit function pointer into CTR and branch to it via bctrl
  void CallCFunction(void* Fn) {
    LoadConstant(TMP1, reinterpret_cast<uint64_t>(Fn));
    mtctr(TMP1);
    bctrl();
  }

  // Load a 64-bit function pointer into CTR and branch to it via bctr (no link)
  void JumpCFunction(void* Fn) {
    LoadConstant(TMP1, reinterpret_cast<uint64_t>(Fn));
    mtctr(TMP1);
    bctr();
  }

  // Emit the JIT block entry sequence (SRA fill, TF check)
  void EmitEntryPoint(PPC64Emitter::Label& HeaderLabel, bool CheckTF);

  // -----------------------------------------------------------------------
  // Memory operation helpers (defined in MemoryOps.cpp)
  // -----------------------------------------------------------------------

  // Compute effective address: Base + Offset (scaled by OffsetScale)
  GPR ComputeAddress(GPR Base, IR::OrderedNodeWrapper Offset,
                     IR::MemOffsetType OffsetType, uint8_t OffsetScale);

  // SVE predicate mem ops — thin wrappers reusing load/store logic
  void StoreMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node);
  void LoadMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node);

  // -----------------------------------------------------------------------
  // Op dispatch helpers
  // -----------------------------------------------------------------------
  IR::RegisterAllocationPass* RAPass {};
  FEXCore::Core::DebugData*   DebugData {};

  // -----------------------------------------------------------------------
  // Op handler declarations (filled in by the separate *.cpp files)
  // -----------------------------------------------------------------------
#define DEF_OP(x) void Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

  DEF_OP(Unhandled);
  DEF_OP(NoOp);

#define IROP_DISPATCH_DEFS
#include <FEXCore/IR/IRDefines_Dispatch.inc>

  // -----------------------------------------------------------------------
  // x87 stack bookkeeping ops (X87Ops.cpp).
  // These IR ops are normally lowered away by the x87StackOptimization pass
  // into LoadContext/StoreContext primitives. The pass is conditional on
  // !DisablePasses(), so when O0 is set (or the optimizer doesn't fully
  // eliminate them) they survive to the JIT. The base FallbackHandler table
  // has no entry for any of these — relying on Op_Unhandled would silently
  // leave destination registers unwritten, so we implement the slow-path
  // semantics directly here, mirroring the IR the pass would have emitted.
  // -----------------------------------------------------------------------
  DEF_OP(InitStack);
  DEF_OP(IncStackTop);
  DEF_OP(DecStackTop);
  DEF_OP(InvalidateStack);
  DEF_OP(PushStack);
  DEF_OP(CopyPushStack);
  DEF_OP(PopStackDestroy);
  DEF_OP(ReadStackValue);
  DEF_OP(StoreStackMem);
  DEF_OP(StoreStackToStack);
  DEF_OP(StackValidTag);
  DEF_OP(SyncStackToSlow);
  DEF_OP(StackForceSlow);

  // Bucket C: stack-form arithmetic ops that survive the optimisation pass.
  // Each is a thin wrapper that loads operands from x87 stack slots, calls
  // the corresponding F80 fallback handler via the existing FABI bridge,
  // and stores the result back to a stack slot.
  DEF_OP(F80AddStack);
  DEF_OP(F80SubStack);
  DEF_OP(F80MulStack);
  DEF_OP(F80DivStack);
  DEF_OP(F80AddValue);
  DEF_OP(F80SubValue);
  DEF_OP(F80SubRValue);
  DEF_OP(F80MulValue);
  DEF_OP(F80DivValue);
  DEF_OP(F80DivRValue);
  DEF_OP(F80CmpStack);
  DEF_OP(F80CmpValue);
  DEF_OP(F80StackTest);
  DEF_OP(F80SQRTStack);
  DEF_OP(F80SINStack);
  DEF_OP(F80COSStack);
  DEF_OP(F80F2XM1Stack);
  DEF_OP(F80SINCOSStack);
  DEF_OP(F80RoundStack);
  DEF_OP(F80FYL2XStack);
  DEF_OP(F80SCALEStack);
  DEF_OP(F80FPREMStack);
  DEF_OP(F80FPREM1Stack);
  DEF_OP(F80PTANStack);
  DEF_OP(F80ATANStack);
  DEF_OP(F80VBSLStack);
  DEF_OP(F80StackXchange);
  DEF_OP(F80StackChangeSign);
  DEF_OP(F80StackAbs);
#undef DEF_OP
};

#define DEF_OP(x) void PPC64JITCore::Op_##x(IR::IROp_Header const* IROp, IR::Ref Node)

[[nodiscard]]
fextl::unique_ptr<CPUBackend> CreatePPC64JITCore(FEXCore::Context::ContextImpl* ctx,
                                                  FEXCore::Core::InternalThreadState* Thread);

} // namespace FEXCore::CPU
