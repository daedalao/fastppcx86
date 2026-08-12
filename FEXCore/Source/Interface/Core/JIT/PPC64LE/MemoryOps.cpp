// SPDX-License-Identifier: MIT
// PPC64LE memory operations for FEX JIT backend.
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/CPUID.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>

#include <bit>

namespace FEXCore::CPU {

// =========================================================================
// Context load/store (accessing CpuStateFrame fields)
// =========================================================================

DEF_OP(LoadContext) {
  auto Op    = IROp->C<IR::IROp_LoadContext>();
  auto Dst   = Node;
  int32_t Offset = static_cast<int32_t>(Op->Offset);

  if (IsFPR(Dst)) {
    auto VDst = GetVReg(Dst);
    // Compute EA = STATE + Offset into TMP4, then dispatch on size. Using
    // raw lvx ignores Op->Size and reads 16B even for x86 vmovd m32 / vmovq
    // m64, corrupting upper-lane state from neighbouring CpuStateFrame
    // bytes. LoadFPRSized zero-extends to 128 bits matching x86 semantics.
    if (Offset >= -32768 && Offset <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset)));
      add(TMP4, STATE, TMP4);
    }
    LoadFPRSized(VDst, TMP4, IR::OpSizeToSize(IROp->Size));
    return;
  }

  auto GDst = GetReg(Dst);
  // Choose load instruction based on size
  switch (IR::OpSizeToSize(IROp->Size)) {
  case 1:
    if (Offset >= -32768 && Offset <= 32767) lbz(GDst, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); lbzx(GDst, STATE, TMP1); }
    break;
  case 2:
    if (Offset >= -32768 && Offset <= 32767) lhz(GDst, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); lhzx(GDst, STATE, TMP1); }
    break;
  case 4:
    if (Offset >= -32768 && Offset <= 32767) lwz(GDst, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); lwzx(GDst, STATE, TMP1); }
    break;
  case 8:
    if (Offset >= -32768 && Offset <= 32764 && (Offset & 3) == 0)
      ld(GDst, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); ldx(GDst, STATE, TMP1); }
    break;
  default:
    LOGMAN_MSG_A_FMT("Unknown context load size: {}", IROp->Size);
    break;
  }
}

DEF_OP(LoadContextPair) {
  auto Op = IROp->C<IR::IROp_LoadContextPair>();
  auto D1 = IR::PhysicalRegister(Op->OutValue1);
  auto D2 = IR::PhysicalRegister(Op->OutValue2);
  int32_t Offset = static_cast<int32_t>(Op->Offset);
  int32_t Stride = static_cast<int32_t>(IR::OpSizeToSize(IROp->Size));

  if (IsFPR(D1.AsRegClass())) {
    // Same fix as LoadContext: dispatch on Stride, not always lvx 16B.
    if (Offset >= -32768 && Offset <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset)));
      add(TMP4, STATE, TMP4);
    }
    LoadFPRSized(GetVReg(D1), TMP4, static_cast<uint32_t>(Stride));
    int32_t Offset2 = Offset + Stride;
    if (Offset2 >= -32768 && Offset2 <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset2));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset2)));
      add(TMP4, STATE, TMP4);
    }
    LoadFPRSized(GetVReg(D2), TMP4, static_cast<uint32_t>(Stride));
  } else {
    auto R1 = GetReg(D1);
    auto R2 = GetReg(D2);
    switch (Stride) {
    case 4:
      if (Offset >= -32768 && Offset + 4 <= 32767) {
        lwz(R1, static_cast<int16_t>(Offset), STATE);
        lwz(R2, static_cast<int16_t>(Offset + 4), STATE);
      } else {
        LoadConstant(TMP1, static_cast<uint32_t>(Offset));
        lwzx(R1, STATE, TMP1);
        addi(TMP1, TMP1, 4);
        lwzx(R2, STATE, TMP1);
      }
      break;
    case 8:
      if (Offset >= -32768 && Offset + 8 <= 32764 && (Offset & 3) == 0) {
        ld(R1, static_cast<int16_t>(Offset), STATE);
        ld(R2, static_cast<int16_t>(Offset + 8), STATE);
      } else {
        LoadConstant(TMP1, static_cast<uint32_t>(Offset));
        ldx(R1, STATE, TMP1);
        addi(TMP1, TMP1, 8);
        ldx(R2, STATE, TMP1);
      }
      break;
    default: break;
    }
  }
}

DEF_OP(StoreContext) {
  auto Op    = IROp->C<IR::IROp_StoreContext>();
  int32_t Offset = static_cast<int32_t>(Op->Offset);

  // Dispatch on Op->Class — see StoreContextPair note. IsFPR(Value) reads the
  // value-node's PhysicalRegister byte which is uninitialised for InlineConstant
  // operands and intermittently misroutes a GPR-class store into the FPR path.
  if (Op->Class == IR::RegClass::FPR || Op->Class == IR::RegClass::FPRFixed) {
    auto VSrc = GetVReg(Op->Value);
    if (Offset >= -32768 && Offset <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset)));
      add(TMP4, STATE, TMP4);
    }
    StoreFPRSized(VSrc, TMP4, IR::OpSizeToSize(IROp->Size));
    return;
  }

  // IR.json marks StoreContext's Value as "Inline: Zero" — the optimizer may
  // fold a Constant 0 into the operand. GetReg on an inline-constant wrapper
  // walks past Invalid into GeneralRegisters[0] and returns whatever stale
  // value lives in that dynamic RA host reg (= r24 in our x64 RA pool),
  // silently corrupting the context slot. Mirror StoreMem/MemSet: route
  // inline-zero stores through r0 (held at zero by the JIT invariant) and
  // materialise any non-zero inline constant into TMP1.
  GPR GSrc;
  uint64_t ValConst;
  if (IsInlineConstant(Op->Value, &ValConst)) {
    if (ValConst == 0) {
      GSrc = r0;
    } else {
      LoadConstant(TMP1, ValConst);
      GSrc = TMP1;
    }
  } else {
    GSrc = GetReg(Op->Value);
  }
  switch (IR::OpSizeToSize(IROp->Size)) {
  case 1:
    if (Offset >= -32768 && Offset <= 32767) stb(GSrc, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); stbx(GSrc, STATE, TMP1); }
    break;
  case 2:
    if (Offset >= -32768 && Offset <= 32767) sth(GSrc, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); sthx(GSrc, STATE, TMP1); }
    break;
  case 4:
    if (Offset >= -32768 && Offset <= 32767) stw(GSrc, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); stwx(GSrc, STATE, TMP1); }
    break;
  case 8:
    if (Offset >= -32768 && Offset <= 32764 && (Offset & 3) == 0)
      std(GSrc, static_cast<int16_t>(Offset), STATE);
    else { LoadConstant(TMP1, static_cast<uint32_t>(Offset)); stdx(GSrc, STATE, TMP1); }
    break;
  default:
    LOGMAN_MSG_A_FMT("Unknown context store size: {}", IROp->Size);
    break;
  }
}

DEF_OP(StoreContextPair) {
  auto Op = IROp->C<IR::IROp_StoreContextPair>();
  int32_t Offset = static_cast<int32_t>(Op->Offset);
  int32_t Stride = static_cast<int32_t>(IR::OpSizeToSize(IROp->Size));

  // Dispatch on the IR-declared Class field, NOT IsFPR(Value1). The
  // dispatcher's StoreContextHelper rewrites a 128-bit FPR-zero context
  // store into `StoreContextPair GPR, InlineZero, InlineZero`, but the
  // InlineConstant operand's PhysicalRegister byte is left uninitialised
  // by the IR-builder pool allocator (RA pass explicitly skips InlineConstants).
  // IsFPR(Value1) reads garbage Class bits and intermittently takes the FPR
  // branch, calling StoreFPRSized on a junk vector reg — overwriting the
  // target slot with whatever vector data lives in that physical reg
  // instead of zeroing it. Manifests as "upper-128 of YMM not cleared"
  // for jit_1 vpgather/vgather (the InlineZero slots happen to inherit
  // FPR-class garbage there); other sites get GPR-class garbage and
  // take the correct path.
  if (Op->Class == IR::RegClass::FPR || Op->Class == IR::RegClass::FPRFixed) {
    if (Offset >= -32768 && Offset <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset)));
      add(TMP4, STATE, TMP4);
    }
    StoreFPRSized(GetVReg(Op->Value1), TMP4, static_cast<uint32_t>(Stride));
    int32_t Offset2 = Offset + Stride;
    if (Offset2 >= -32768 && Offset2 <= 32767) {
      addi(TMP4, STATE, static_cast<int16_t>(Offset2));
    } else {
      LoadConstant(TMP4, static_cast<uint64_t>(static_cast<int64_t>(Offset2)));
      add(TMP4, STATE, TMP4);
    }
    StoreFPRSized(GetVReg(Op->Value2), TMP4, static_cast<uint32_t>(Stride));
  } else {
    // Both Value1 and Value2 are "Inline: Zero" per IR.json. Same trap as
    // StoreContext: GetReg on an inline-zero wrapper returns RA[0]=r24 holding
    // garbage. Funnel inline zeros through r0 and materialise any non-zero
    // inline constant into TMP3/TMP4 (TMP1 is reserved for the offset path
    // below; TMP2 is free).
    auto ResolveSrc = [&](IR::OrderedNodeWrapper Val, GPR Materialise) -> GPR {
      uint64_t C;
      if (IsInlineConstant(Val, &C)) {
        if (C == 0) return r0;
        LoadConstant(Materialise, C);
        return Materialise;
      }
      return GetReg(Val);
    };
    auto R1 = ResolveSrc(Op->Value1, TMP3);
    auto R2 = ResolveSrc(Op->Value2, TMP4);
    switch (Stride) {
    case 4:
      if (Offset >= -32768 && Offset + 4 <= 32767) {
        stw(R1, static_cast<int16_t>(Offset), STATE);
        stw(R2, static_cast<int16_t>(Offset + 4), STATE);
      } else {
        LoadConstant(TMP1, static_cast<uint32_t>(Offset));
        stwx(R1, STATE, TMP1);
        addi(TMP1, TMP1, 4);
        stwx(R2, STATE, TMP1);
      }
      break;
    case 8:
      if (Offset >= -32768 && Offset + 8 <= 32764 && (Offset & 3) == 0) {
        std(R1, static_cast<int16_t>(Offset), STATE);
        std(R2, static_cast<int16_t>(Offset + 8), STATE);
      } else {
        LoadConstant(TMP1, static_cast<uint32_t>(Offset));
        stdx(R1, STATE, TMP1);
        addi(TMP1, TMP1, 8);
        stdx(R2, STATE, TMP1);
      }
      break;
    default: break;
    }
  }
}

// Out = BaseOffset + Idx * Stride, the context-relative displacement shared by
// Load/StoreContextIndexed. Stride is a register-array element size, so in
// practice always a power of two (8 for GPRs, 16 for XMM), and BaseOffset is a
// CpuStateFrame field offset that comfortably fits addi's signed 16-bit
// immediate. That collapses two LoadConstants, a mulld and an add into a shift
// and an addi -- and leaves TMP1/TMP2 untouched. FormContextAddress below is
// the existing precedent for the shift. Anything that does not fit keeps the
// general multiply.
static void FormIndexedContextOffset(PPC64JITCore* j, GPR Out, GPR Idx, uint32_t Stride, uint32_t BaseOffset) {
  const bool Pow2 = Stride != 0 && (Stride & (Stride - 1)) == 0;
  if (Pow2 && BaseOffset <= 32767) {
    if (Stride == 1) {
      if (BaseOffset != 0) {
        j->addi(Out, Idx, static_cast<int16_t>(BaseOffset));
      } else if (Out != Idx) {
        j->mr(Out, Idx);
      }
    } else {
      j->sldi(Out, Idx, static_cast<uint32_t>(__builtin_ctz(Stride)));
      if (BaseOffset != 0) {
        j->addi(Out, Out, static_cast<int16_t>(BaseOffset));
      }
    }
    return;
  }
  j->LoadConstant(TMP1, static_cast<uint32_t>(BaseOffset));
  j->LoadConstant(TMP2, static_cast<uint64_t>(Stride));
  j->mulld(Out, Idx, TMP2);
  j->add(Out, Out, TMP1);
}

DEF_OP(LoadContextIndexed) {
  auto Op = IROp->C<IR::IROp_LoadContextIndexed>();
  auto Idx = GetReg(Op->Index);
  // EA = STATE + BaseOffset + Idx * Stride. Compute into TMP3.
  FormIndexedContextOffset(this, TMP3, Idx, Op->Stride, Op->BaseOffset);
  if (Op->Class == IR::RegClass::FPR) {
    // Vector / XMM context load (e.g. fxsave/fxrstor stride-16 dispatch).
    // EA goes through STATE + TMP3; LoadFPRSized expects a single GPR EA.
    add(TMP4, STATE, TMP3);
    LoadFPRSized(GetVReg(Node), TMP4, IR::OpSizeToSize(IROp->Size));
    return;
  }
  auto Dst = GetReg(Node);
  switch (IR::OpSizeToSize(IROp->Size)) {
  case 1: lbzx(Dst, STATE, TMP3); break;
  case 2: lhzx(Dst, STATE, TMP3); break;
  case 4: lwzx(Dst, STATE, TMP3); break;
  case 8: ldx(Dst, STATE, TMP3);  break;
  default: LOGMAN_MSG_A_FMT("Unhandled LoadContextIndexed GPR size: {}", IROp->Size); break;
  }
}

DEF_OP(StoreContextIndexed) {
  auto Op  = IROp->C<IR::IROp_StoreContextIndexed>();
  auto Idx = GetReg(Op->Index);
  FormIndexedContextOffset(this, TMP3, Idx, Op->Stride, Op->BaseOffset);
  if (Op->Class == IR::RegClass::FPR) {
    add(TMP4, STATE, TMP3);
    StoreFPRSized(GetVReg(Op->Value), TMP4, IR::OpSizeToSize(IROp->Size));
    return;
  }
  auto Src = GetReg(Op->Value);
  switch (IR::OpSizeToSize(IROp->Size)) {
  case 1: stbx(Src, STATE, TMP3); break;
  case 2: sthx(Src, STATE, TMP3); break;
  case 4: stwx(Src, STATE, TMP3); break;
  case 8: stdx(Src, STATE, TMP3); break;
  default: LOGMAN_MSG_A_FMT("Unhandled StoreContextIndexed GPR size: {}", IROp->Size); break;
  }
}

DEF_OP(FormContextAddress) {
  auto Op   = IROp->C<IR::IROp_FormContextAddress>();
  auto Dst  = GetReg(Node);
  auto Idx  = GetReg(Op->Index);
  // Dst = STATE + Idx * Stride  (Stride is a power of 2)
  if (Op->Stride == 1) {
    add(Dst, STATE, Idx);
  } else {
    sldi(TMP1, Idx, __builtin_ctz(Op->Stride));
    add(Dst, STATE, TMP1);
  }
}

// =========================================================================
// Spill/Fill registers (JIT register allocator support)
// =========================================================================

DEF_OP(SpillRegister) {
  auto Op  = IROp->C<IR::IROp_SpillRegister>();
  auto Src = Op->Value;
  int32_t SlotOffset = SpillOffset(Op->Slot);

  if (IsFPR(Src)) {
    auto VSrc = GetVReg(Src);
    LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(SlotOffset)));
    stvx(VSrc, r1, TMP1);
  } else {
    auto GSrc = GetReg(Src);
    switch (IR::OpSizeToSize(IROp->Size)) {
    case 1: stb(GSrc, static_cast<int16_t>(SlotOffset), r1); break;
    case 2: sth(GSrc, static_cast<int16_t>(SlotOffset), r1); break;
    case 4: stw(GSrc, static_cast<int16_t>(SlotOffset), r1); break;
    case 8:
      if ((SlotOffset & 3) == 0 && SlotOffset >= -32768 && SlotOffset <= 32764)
        std(GSrc, static_cast<int16_t>(SlotOffset), r1);
      else {
        LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(SlotOffset)));
        stdx(GSrc, r1, TMP1);
      }
      break;
    default: break;
    }
  }
}

DEF_OP(FillRegister) {
  auto Op     = IROp->C<IR::IROp_FillRegister>();
  auto DstRef = Node;
  int32_t SlotOffset = SpillOffset(Op->Slot);

  if (IsFPR(DstRef)) {
    auto VDst = GetVReg(DstRef);
    LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(SlotOffset)));
    lvx(VDst, r1, TMP1);
  } else {
    auto GDst = GetReg(DstRef);
    switch (IR::OpSizeToSize(IROp->Size)) {
    case 1: lbz(GDst, static_cast<int16_t>(SlotOffset), r1); break;
    case 2: lhz(GDst, static_cast<int16_t>(SlotOffset), r1); break;
    case 4: lwz(GDst, static_cast<int16_t>(SlotOffset), r1); break;
    case 8:
      if ((SlotOffset & 3) == 0 && SlotOffset >= -32768 && SlotOffset <= 32764)
        ld(GDst, static_cast<int16_t>(SlotOffset), r1);
      else {
        LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(SlotOffset)));
        ldx(GDst, r1, TMP1);
      }
      break;
    default: break;
    }
  }
}

// =========================================================================
// Static register save/restore (LoadRegister / StoreRegister)
// =========================================================================

DEF_OP(LoadRegister) {
  auto Op = IROp->C<IR::IROp_LoadRegister>();
  if (Op->Class == IR::RegClass::FPR) {
    auto Dst = GetVReg(Node);
    auto Src = StaticFPRegisters[Op->Reg];
    if (Dst != Src) vmr(Dst, Src);
  } else {
    auto Dst = GetReg(Node);
    auto Src = StaticRegisters[Op->Reg];
    if (Dst != Src) mr(Dst, Src);
  }
}

DEF_OP(StoreRegister) {
  auto Op = IROp->C<IR::IROp_StoreRegister>();
  const auto Reg = IR::PhysicalRegister(Node);
  const auto RegClass = Reg.AsRegClass();
  if (RegClass == IR::RegClass::FPRFixed) {
    auto Dst = GetVReg(Reg);
    auto Src = GetVReg(Op->Value);
    if (Dst != Src) vmr(Dst, Src);
  } else {
    auto Dst = GetReg(Reg);
    auto Src = GetReg(Op->Value);
    if (Dst != Src) mr(Dst, Src);
  }
}

DEF_OP(LoadPF) {
  auto Dst = GetReg(Node);
  if (Dst != REG_PF) mr(Dst, REG_PF);
}

DEF_OP(LoadAF) {
  auto Dst = GetReg(Node);
  if (Dst != REG_AF) mr(Dst, REG_AF);
}

DEF_OP(StorePF) {
  auto Src = GetReg(IROp->C<IR::IROp_StorePF>()->Value);
  if (REG_PF != Src) mr(REG_PF, Src);
}

DEF_OP(StoreAF) {
  auto Src = GetReg(IROp->C<IR::IROp_StoreAF>()->Value);
  if (REG_AF != Src) mr(REG_AF, Src);
}

// =========================================================================
// Memory load/store (guest address)
// =========================================================================

// -------------------------------------------------------------------------
// Effective-address form selection for GPR load/store
// -------------------------------------------------------------------------
//
// EA = Base + Disp (D/DS-form) or EA = Base + Index (X-form); exactly one of
// the two is live. ComputeAddress collapses both into a single register, which
// costs an addi/add per access and then wastes the X-form's RB operand on r0.
// Keeping the shape lets the memory instruction absorb it.
//
// GetReg/IsInlineConstant are PPC64JITCore members, so the DEF_OP bodies do the
// operand extraction and these file-local helpers only emit — the change stays
// inside this translation unit.
struct MemAddrForm {
  GPR Base;
  GPR Index;      // meaningful only when HasIndex
  int32_t Disp;   // meaningful only when !HasIndex
  bool HasIndex;
};

// Offset operand as the caller sees it. Valid=false means "no offset operand".
struct MemOffsetOperand {
  bool Valid;
  bool IsConst;
  uint64_t Const;
  GPR Reg;        // meaningful only when Valid && !IsConst
  IR::MemOffsetType Type;
  uint8_t Scale;
};

// Scratch contract: writes TMP3 only, and only when the offset needs extension,
// scaling, or a wide-constant materialization. Matches ComputeAddress's old
// contract so callers' TMP assumptions are unchanged.
static MemAddrForm MakeAddrForm(PPC64EmitterBase& E, GPR Base, const MemOffsetOperand& Off) {
  MemAddrForm A {Base, Base, 0, false};
  if (!Off.Valid) {
    return A;
  }
  if (Off.IsConst) {
    const int64_t sOff = static_cast<int64_t>(Off.Const) * Off.Scale;
    if (sOff >= -32768 && sOff <= 32767) {
      A.Disp = static_cast<int32_t>(sOff);
      return A;
    }
    // Wider than any D/DS displacement: materialize and hand it to the X-form's
    // RB rather than folding it into Base with a separate add.
    E.LoadConstant(TMP3, static_cast<uint64_t>(sOff));
    A.Index = TMP3;
    A.HasIndex = true;
    return A;
  }
  GPR OffReg = Off.Reg;
  if (Off.Type == IR::MemOffsetType::UXTW) {
    E.rldicl(TMP3, OffReg, 0, 32);
    OffReg = TMP3;
  } else if (Off.Type == IR::MemOffsetType::SXTW) {
    E.extsw(TMP3, OffReg);
    OffReg = TMP3;
  }
  if (Off.Scale > 1) {
    E.sldi(TMP3, OffReg, __builtin_ctz(Off.Scale));
    OffReg = TMP3;
  }
  A.Index = OffReg;
  A.HasIndex = true;
  return A;
}

// Collapse to a single register. FPR/vector paths and any caller that needs an
// address register (rather than an addressing mode) go through this; it emits
// exactly what ComputeAddress used to, including landing in TMP3.
static GPR MaterializeAddr(PPC64EmitterBase& E, const MemAddrForm& A) {
  if (A.HasIndex) {
    E.add(TMP3, A.Base, A.Index);
    return TMP3;
  }
  if (A.Disp == 0) {
    return A.Base;
  }
  E.addi(TMP3, A.Base, static_cast<int16_t>(A.Disp));
  return TMP3;
}

// D-form is usable when there is no register index and the displacement fits.
// ld/std/lwa are DS-form: the low two displacement bits are the extended opcode,
// so the displacement must be a multiple of 4. Everything else is plain D-form
// and takes any signed 16-bit value.
static bool CanUseDForm(const MemAddrForm& A, IR::OpSize Size) {
  if (A.HasIndex) {
    return false;
  }
  if (A.Disp < -32768 || A.Disp > 32767) {
    return false;
  }
  if (Size == IR::OpSize::i64Bit && (A.Disp & 3) != 0) {
    return false;
  }
  return true;
}

// rA=0 in D/DS-form encodes the literal value zero, not r0's contents, so a
// base of r0 would silently become an absolute address. TMPs are r3-r6 and both
// RA pools start at r7, so this cannot happen — assert rather than assume.
static void AssertNonZeroBase(const MemAddrForm& A) {
  LOGMAN_THROW_A_FMT(A.Base != r0, "PPC64 D-form base register must not be r0");
}

// A displacement that no D/DS-form can hold must move into the X-form's RB;
// the X-form has no displacement field, so leaving it in the form would drop it
// silently. That is not hypothetical: `mov rbx, qword [data+2]` folds a
// displacement of 2, which DS-form ld cannot encode.
static MemAddrForm LegalizeForm(PPC64EmitterBase& E, const MemAddrForm& A, IR::OpSize Size) {
  if (A.HasIndex || CanUseDForm(A, Size)) {
    return A;
  }
  MemAddrForm R = A;
  E.LoadConstant(TMP3, static_cast<uint64_t>(static_cast<int64_t>(A.Disp)));
  R.Index = TMP3;
  R.HasIndex = true;
  return R;
}

static void EmitLoadGPR(PPC64EmitterBase& E, IR::OpSize Size, GPR Dst, const MemAddrForm& A_) {
  const MemAddrForm A = LegalizeForm(E, A_, Size);
  if (CanUseDForm(A, Size)) {
    AssertNonZeroBase(A);
    const int16_t D = static_cast<int16_t>(A.Disp);
    switch (Size) {
    case IR::OpSize::i8Bit:  E.lbz(Dst, D, A.Base); break;
    case IR::OpSize::i16Bit: E.lhz(Dst, D, A.Base); break;
    case IR::OpSize::i32Bit: E.lwz(Dst, D, A.Base); break;
    case IR::OpSize::i64Bit: E.ld(Dst, D, A.Base);  break;
    default: break;
    }
    return;
  }
  // X-form base+index. When there is no index the old shape's r0 stand-in is
  // still correct (r0 in RB reads GPR0's contents, and the backend holds r0==0).
  const GPR Index = A.HasIndex ? A.Index : r0;
  switch (Size) {
  case IR::OpSize::i8Bit:  E.lbzx(Dst, A.Base, Index); break;
  case IR::OpSize::i16Bit: E.lhzx(Dst, A.Base, Index); break;
  case IR::OpSize::i32Bit: E.lwzx(Dst, A.Base, Index); break;
  case IR::OpSize::i64Bit: E.ldx(Dst, A.Base, Index);  break;
  default: break;
  }
}

static void EmitStoreGPR(PPC64EmitterBase& E, IR::OpSize Size, GPR Src, const MemAddrForm& A_) {
  const MemAddrForm A = LegalizeForm(E, A_, Size);
  if (CanUseDForm(A, Size)) {
    AssertNonZeroBase(A);
    const int16_t D = static_cast<int16_t>(A.Disp);
    switch (Size) {
    case IR::OpSize::i8Bit:  E.stb(Src, D, A.Base); break;
    case IR::OpSize::i16Bit: E.sth(Src, D, A.Base); break;
    case IR::OpSize::i32Bit: E.stw(Src, D, A.Base); break;
    case IR::OpSize::i64Bit: E.std(Src, D, A.Base); break;
    default: break;
    }
    return;
  }
  const GPR Index = A.HasIndex ? A.Index : r0;
  switch (Size) {
  case IR::OpSize::i8Bit:  E.stbx(Src, A.Base, Index); break;
  case IR::OpSize::i16Bit: E.sthx(Src, A.Base, Index); break;
  case IR::OpSize::i32Bit: E.stwx(Src, A.Base, Index); break;
  case IR::OpSize::i64Bit: E.stdx(Src, A.Base, Index); break;
  default: break;
  }
}

// Helper: compute effective address = Base + Offset (immediate or register)
GPR PPC64JITCore::ComputeAddress(GPR Base, IR::OrderedNodeWrapper Offset,
                                  IR::MemOffsetType OffsetType, uint8_t OffsetScale) {
  // EA = Base + Offset (with optional UXTW/SXTW + scale).
  //
  // Historical note: 32-bit guest mode used to mask the final EA to 32 bits to
  // simulate x86 32-bit pointer wraparound. That was wrong — the same code
  // path is used for *host* pointer dereferences (e.g. LoadContextIndexed +
  // LoadMem to walk a 64-bit pointer to the GDT for segment loads). Masking
  // such addresses to 32 bits destroys the host pointer's high bits and
  // segfaults the host on the first segment-register load that hits
  // segment_arrays[]. Guest 32-bit pointer wrap is the dispatcher's
  // responsibility: i32-typed SSA values are already zero-extended when
  // written, so 64-bit Base+Offset arithmetic produces the correct address.
  uint64_t OffC = 0;
  const bool OffValid = !Offset.IsInvalid();
  const bool OffConst = OffValid && IsInlineConstant(Offset, &OffC);
  const MemOffsetOperand Off {OffValid, OffConst, OffC, (OffValid && !OffConst) ? GetReg(Offset) : r0,
                              OffsetType, OffsetScale};
  return MaterializeAddr(*this, MakeAddrForm(*this, Base, Off));
}

DEF_OP(LoadMem) {
  auto Op   = IROp->C<IR::IROp_LoadMem>();
  auto Dst  = Node;
  // Op->Addr can be an inline constant per the IR's "Mem" inline form;
  // materialize into TMP4 first if so, otherwise use the SSA reg.
  GPR Addr;
  uint64_t Const;
  if (IsInlineConstant(Op->Addr, &Const)) {
    LoadConstant(TMP4, Const);
    Addr = TMP4;
  } else {
    Addr = GetReg(Op->Addr);
  }
  // Keep the addressing mode rather than collapsing it: the memory instruction
  // absorbs either a displacement (D/DS-form) or a register index (X-form).
  // GetReg/IsInlineConstant are core members, so the extraction is done here and
  // MakeAddrForm only emits.
  uint64_t OffC = 0;
  const bool OffValid = !Op->Offset.IsInvalid();
  const bool OffConst = OffValid && IsInlineConstant(Op->Offset, &OffC);
  const MemOffsetOperand Off {OffValid, OffConst, OffC, (OffValid && !OffConst) ? GetReg(Op->Offset) : r0,
                              Op->OffsetType, Op->OffsetScale};
  const MemAddrForm EAF = MakeAddrForm(*this, Addr, Off);

  if (Op->Class == IR::RegClass::FPR) {
    // Honour Op->Size so vmovd/vmovq don't read 16B and clobber upper lanes.
    LoadFPRSized(GetVReg(Dst), MaterializeAddr(*this, EAF), IR::OpSizeToSize(IROp->Size));
    return;
  }
  if (IROp->Size == IR::OpSize::i128Bit) {
    LoadUnalignedV128(GetVReg(Dst), MaterializeAddr(*this, EAF));
    return;
  }
  EmitLoadGPR(*this, IROp->Size, GetReg(Dst), EAF);
}

// Materialize Addr + Offset into `scratch`, or return Addr unchanged when
// Offset==0. Used by [Load|Store]MemPair to recompute each pair-half's address
// from a non-clobbered base, since *UnalignedV128 internally trashes TMP1-TMP3.
static GPR ComputeOffsetAddrInto(PPC64EmitterBase& E, GPR Addr, int64_t Offset, GPR scratch) {
  if (Offset == 0) return Addr;
  if (Offset >= -32768 && Offset <= 32767) {
    E.addi(scratch, Addr, static_cast<int16_t>(Offset));
  } else {
    E.LoadConstant(scratch, static_cast<uint64_t>(Offset));
    E.add(scratch, Addr, scratch);
  }
  return scratch;
}

DEF_OP(LoadMemPair) {
  auto Op   = IROp->C<IR::IROp_LoadMemPair>();
  auto Addr = GetReg(Op->Addr);
  uint32_t Stride = IR::OpSizeToSize(IROp->Size);

  // Op->Offset is u32 in IR.json but conceptually a signed displacement
  // (e.g. `vmovdqu %ymm,-0x20(...)` arrives as 0xffffffe0). Sign-extend.
  const int64_t Offset = static_cast<int32_t>(Op->Offset);

  if (Op->Class == IR::RegClass::GPR) {
    GPR Base = ComputeOffsetAddrInto(*this, Addr, Offset, TMP1);
    auto D1 = GetReg(Op->OutValue1);
    auto D2 = GetReg(Op->OutValue2);
    // D-form: Stride is 1/2/4/8, so the second half's displacement always
    // fits the 16-bit field, and 8 satisfies ld's DS-form 4-byte alignment.
    // The index registers this drops (an li of the stride, plus r0 for the
    // first half) were pure overhead in a sequence Mono runs in every
    // function prologue.
    const int16_t S = static_cast<int16_t>(Stride);
    switch (IROp->Size) {
    case IR::OpSize::i8Bit:  lbz(D1, 0, Base); lbz(D2, S, Base); break;
    case IR::OpSize::i16Bit: lhz(D1, 0, Base); lhz(D2, S, Base); break;
    case IR::OpSize::i32Bit: lwz(D1, 0, Base); lwz(D2, S, Base); break;
    case IR::OpSize::i64Bit: ld (D1, 0, Base); ld (D2, S, Base); break;
    default: break;
    }
  } else {
    // Recompute B2 from Addr after the first call rather than from B1, since
    // LoadFPRSized (like LoadUnalignedV128) clobbers TMP1-TMP3.
    auto D1 = GetVReg(Op->OutValue1);
    auto D2 = GetVReg(Op->OutValue2);
    GPR B1 = ComputeOffsetAddrInto(*this, Addr, Offset, TMP1);
    LoadFPRSized(D1, B1, Stride);
    GPR B2 = ComputeOffsetAddrInto(*this, Addr, Offset + static_cast<int64_t>(Stride), TMP1);
    LoadFPRSized(D2, B2, Stride);
  }
}

DEF_OP(StoreMem) {
  auto Op   = IROp->C<IR::IROp_StoreMem>();
  GPR Addr;
  uint64_t Const;
  if (IsInlineConstant(Op->Addr, &Const)) {
    LoadConstant(TMP4, Const);
    Addr = TMP4;
  } else {
    Addr = GetReg(Op->Addr);
  }
  uint64_t OffC = 0;
  const bool OffValid = !Op->Offset.IsInvalid();
  const bool OffConst = OffValid && IsInlineConstant(Op->Offset, &OffC);
  const MemOffsetOperand Off {OffValid, OffConst, OffC, (OffValid && !OffConst) ? GetReg(Op->Offset) : r0,
                              Op->OffsetType, Op->OffsetScale};
  const MemAddrForm EAF = MakeAddrForm(*this, Addr, Off);

  // Dispatch on the explicit RegisterClass field — IsFPR(Op->Value) reads the
  // *node's* class which can disagree with the store's class (e.g. an FPR-class
  // value stored as a GPR-sized chunk). Use the IR-declared class.
  if (Op->Class == IR::RegClass::FPR) {
    // Honour Op->Size so vmovd m32 / vmovq m64 don't write 16B and stomp on
    // adjacent stack slots (e.g. wiping [rsp+8] in __tls_init_tp).
    const auto Size = IR::OpSizeToSize(IROp->Size);

    // Splat-form values (see Passes/ScalarSplatChain.cpp) hold element 0's bits
    // replicated across the register, so doubleword 0 already equals doubleword
    // 1 and StoreFPRSized's xxpermdi(DM=2) staging permute is a no-op. Drop it
    // and issue the scalar-VSX store directly -- the movss store that ends a
    // guest scalar chain becomes one instruction.
    //
    // The accepted element sizes differ per store width and are checked here
    // rather than inherited from the pass: stxsiwx reads word 1 of doubleword
    // 0, which is element 0's word under an f32 splat and the low word of
    // element 0 under an f64 splat; stxsdx reads all of doubleword 0, which is
    // only element 0 under an f64 splat.
    const bool SplatSrc = (Size == 4 && (IsSplatFormValue(Op->Value, IR::OpSize::i32Bit) || IsSplatFormValue(Op->Value, IR::OpSize::i64Bit))) ||
                          (Size == 8 && IsSplatFormValue(Op->Value, IR::OpSize::i64Bit));
    if (SplatSrc) {
      const auto VSrc = GetVReg(Op->Value);
      const auto Ea = MaterializeAddr(*this, EAF);
      if (Size == 4) {
        stxsiwx(VSrc, Ea, r0);
      } else {
        stxsdx(VSrc, Ea, r0);
      }
      return;
    }

    StoreFPRSized(GetVReg(Op->Value), MaterializeAddr(*this, EAF), Size);
    return;
  }
  if (IROp->Size == IR::OpSize::i128Bit) {
    StoreUnalignedV128(GetVReg(Op->Value), MaterializeAddr(*this, EAF));
    return;
  }
  // Op->Value may be an inline constant (e.g. `mov [mem], 0`). GetReg on an
  // inline-constant node returns garbage; materialise into r0 (zero) or TMP1.
  GPR GSrc;
  uint64_t ValConst;
  if (IsInlineConstant(Op->Value, &ValConst)) {
    if (ValConst == 0) {
      GSrc = r0;
    } else {
      LoadConstant(TMP1, ValConst);
      GSrc = TMP1;
    }
  } else {
    GSrc = GetReg(Op->Value);
  }
  EmitStoreGPR(*this, IROp->Size, GSrc, EAF);
}

DEF_OP(StoreMemPair) {
  auto Op   = IROp->C<IR::IROp_StoreMemPair>();
  auto Addr = GetReg(Op->Addr);
  uint32_t Stride = IR::OpSizeToSize(IROp->Size);

  const int64_t Offset = static_cast<int32_t>(Op->Offset);

  if (Op->Class == IR::RegClass::GPR) {
    GPR Base = ComputeOffsetAddrInto(*this, Addr, Offset, TMP1);
    auto S1 = GetReg(Op->Value1);
    auto S2 = GetReg(Op->Value2);
    // D-form, same reasoning as LoadMemPair.
    const int16_t S = static_cast<int16_t>(Stride);
    switch (IROp->Size) {
    case IR::OpSize::i8Bit:  stb(S1, 0, Base); stb(S2, S, Base); break;
    case IR::OpSize::i16Bit: sth(S1, 0, Base); sth(S2, S, Base); break;
    case IR::OpSize::i32Bit: stw(S1, 0, Base); stw(S2, S, Base); break;
    case IR::OpSize::i64Bit: std(S1, 0, Base); std(S2, S, Base); break;
    default: break;
    }
  } else {
    auto S1 = GetVReg(Op->Value1);
    auto S2 = GetVReg(Op->Value2);
    GPR B1 = ComputeOffsetAddrInto(*this, Addr, Offset, TMP1);
    StoreFPRSized(S1, B1, Stride);
    GPR B2 = ComputeOffsetAddrInto(*this, Addr, Offset + static_cast<int64_t>(Stride), TMP1);
    StoreFPRSized(S2, B2, Stride);
  }
}

// =========================================================================
// TSO (total store order) variants — use barriers on PPC64
// =========================================================================

DEF_OP(LoadMemTSO) {
  auto Op   = IROp->C<IR::IROp_LoadMemTSO>();
  auto Dst  = Node;
  GPR Addr;
  uint64_t Const;
  if (IsInlineConstant(Op->Addr, &Const)) {
    LoadConstant(TMP4, Const);
    Addr = TMP4;
  } else {
    Addr = GetReg(Op->Addr);
  }
  // TSO loads carry the same Offset/OffsetType/OffsetScale fields as plain
  // LoadMem; without folding them in we silently drop the displacement (e.g.
  // the +0x4 in `mov %fs:0x4(%r8), …`), producing a bad effective address.
  uint64_t OffC = 0;
  const bool OffValid = !Op->Offset.IsInvalid();
  const bool OffConst = OffValid && IsInlineConstant(Op->Offset, &OffC);
  const MemOffsetOperand Off {OffValid, OffConst, OffC, (OffValid && !OffConst) ? GetReg(Op->Offset) : r0,
                              Op->OffsetType, Op->OffsetScale};
  const MemAddrForm EAF = MakeAddrForm(*this, Addr, Off);

  // Acquire barrier: `lwsync` AFTER the load.
  //
  // This is kept on ARCHITECTURAL grounds, not measured ones. `lwsync` after a
  // load is the plainest correct load-acquire on POWER, and it is the simpler of
  // two valid constructs. It replaced a self-compare / never-taken-branch /
  // `isync` sequence — also a documented and valid load-acquire, and cheaper,
  // which is why the port originally chose it. `LockOnlyTSO` exists in the config
  // precisely because per-load acquire cost "cumulatively dominates runtime in
  // libc / pthread tight loops", so the cheap construct had a real motivation.
  //
  // HONEST STATUS OF THE EVIDENCE, because an earlier version of this comment
  // overstated it twice and the corrections matter more than the conclusion:
  //
  //   * A campaign of ~240 runs appeared to show this change roughly halving a
  //     memory-corruption rate (~30% to 13.3%) in a Mono `mcs` workload. Those
  //     numbers do not survive. Every run in that campaign died early on an
  //     unrelated failure — a missing rootfs library, diagnosed later — so the
  //     whole matrix measured crash behaviour on an error path rather than on
  //     real work. It does not establish that this construct is better, or that
  //     the previous one was defective.
  //   * A 15-run sample of this change once read 0/15, which was luck rather
  //     than a result: at a 13% rate, P(0 in 15) is about 12%.
  //
  // So: no verified defect is fixed here, and no verified regression is
  // introduced. The change stands because it is the more obviously-correct of
  // two correct options, and the performance cost of choosing it is UNMEASURED
  // — SMT was misconfigured for every attempt at a comparable number.
  //
  // What is owed, for whoever picks this up:
  //   1. Re-measure with a workload that actually runs, now that the rootfs
  //      library gap is closed. That decides whether either construct matters.
  //   2. Get a recipe-compliant benchmark (SMT2, node-pinned) for the cost of
  //      `lwsync` per guest load. If it is significant and neither construct
  //      affects correctness, the cheap one should come back — or `LockOnlyTSO`
  //      becomes the better lever than either.
  //   3. Do not accept a zero-event run as proof of anything: at these rates 15
  //      trials cannot establish a zero, and 30 only rules out a true rate above
  //      about 10%.
  if (Op->Class == IR::RegClass::FPR) {
    LoadFPRSized(GetVReg(Dst), MaterializeAddr(*this, EAF), IR::OpSizeToSize(IROp->Size));
    lwsync();
    return;
  }

  // X-form fallback puts the address in RA and r0 in RB. Power's literal-zero
  // rule covers RA only, so that reads GPR0's *contents* as the index and
  // depends on an r0==0 invariant. Nothing in this backend writes r0 without
  // restoring it, so the invariant holds — but it is an invariant, not an
  // architectural guarantee. Contrast `PPC64.cpp:222-224`, which puts r0 in RA
  // where the rule genuinely applies. The D/DS-form selection has the mirror
  // constraint on the *base*, checked in AssertNonZeroBase.
  EmitLoadGPR(*this, IROp->Size, GetReg(Dst), EAF);
  // Barrier placement unchanged: acquire is still the lwsync after the load.
  lwsync();
}

DEF_OP(StoreMemTSO) {
  auto Op   = IROp->C<IR::IROp_StoreMemTSO>();
  GPR Addr;
  uint64_t Const;
  if (IsInlineConstant(Op->Addr, &Const)) {
    LoadConstant(TMP4, Const);
    Addr = TMP4;
  } else {
    Addr = GetReg(Op->Addr);
  }
  // Fold in Offset/OffsetType/OffsetScale (mirrors StoreMem). Must happen
  // before the lwsync so the displacement add is also release-ordered with
  // respect to the store; ComputeAddress only does a couple of arithmetic
  // ops on TMP3, no memory ops, so it's safe either side of the barrier.
  uint64_t OffC = 0;
  const bool OffValid = !Op->Offset.IsInvalid();
  const bool OffConst = OffValid && IsInlineConstant(Op->Offset, &OffC);
  const MemOffsetOperand Off {OffValid, OffConst, OffC, (OffValid && !OffConst) ? GetReg(Op->Offset) : r0,
                              Op->OffsetType, Op->OffsetScale};
  const MemAddrForm EAF = MakeAddrForm(*this, Addr, Off);

  if (Op->Class == IR::RegClass::FPR) {
    // Materialize before the barrier so the FPR path's instruction order across
    // the lwsync is exactly what it was; the GPR path now folds the
    // displacement into the store itself and needs no address arithmetic at all.
    GPR EA = MaterializeAddr(*this, EAF);
    // x86 TSO stores are release stores. lwsync before the store provides
    // StoreStore + LoadStore release ordering relative to prior memory ops.
    lwsync();
    // Size-aware so TSO `vmovd m32, %xmm` writes 4B not 16B.
    StoreFPRSized(GetVReg(Op->Value), EA, IR::OpSizeToSize(IROp->Size));
    return;
  }

  // Release barrier before the store — placement unchanged.
  lwsync();

  // Same inline-constant-Value handling as StoreMem (e.g. TSO `mov [m], 0`).
  GPR GSrc;
  uint64_t ValConst;
  if (IsInlineConstant(Op->Value, &ValConst)) {
    if (ValConst == 0) {
      GSrc = r0;
    } else {
      LoadConstant(TMP1, ValConst);
      GSrc = TMP1;
    }
  } else {
    GSrc = GetReg(Op->Value);
  }
  EmitStoreGPR(*this, IROp->Size, GSrc, EAF);
}

// =========================================================================
// Stack push/pop
// =========================================================================

DEF_OP(Push) {
  // Push:  GPR:$Addr = Push OpSize:#Size, OpSize:$ValueSize, GPR:$Value, GPR:$Addr
  // TiedSource:1 — destination shares the Addr operand's register, so decrement
  // happens in place. Don't hardcode RSP: the IR may use any GPR (e.g. the
  // generic stack helpers re-use Push for non-RSP addresses).
  auto Op    = IROp->C<IR::IROp_Push>();
  auto Src   = GetReg(Op->Value);
  auto Addr  = GetReg(Op->Addr);
  auto Dst   = GetReg(Node);
  uint32_t SZ = IR::OpSizeToSize(Op->ValueSize);

  // ALWAYS stash Src into TMP1 before any address arithmetic. Eliminates the
  // aliasing variable.
  mr(TMP1, Src);
  GPR Stored = TMP1;

  if (Dst != Addr) mr(Dst, Addr);

  addi(Dst, Dst, -static_cast<int16_t>(SZ));
  // 32-bit guest: wrap the new stack pointer at the 32-bit boundary.  This
  // serves two purposes: (1) the immediate stb/sth/stw/stdx below uses Dst as
  // its base, so a 0xFFFFFFFFFFFFFFFC value must become 0x00000000FFFFFFFC;
  // (2) the new RSP fed back to SRA stays canonical 32-bit, matching how
  // SpillStaticRegs/FillStaticRegs round-trip 32-bit GPRs.
  MaybeClrUpper32(Dst);
  switch (SZ) {
  case 1: stb(Stored, 0, Dst); break;
  case 2: sth(Stored, 0, Dst); break;
  case 4: stw(Stored, 0, Dst); break;
  case 8: stdx(Stored, Dst, r0); break;
  }
}

DEF_OP(PushTwo) {
  // PushTwo OpSize:#Size, OpSize:$ValueSize, GPR:$Value1, GPR:$Value2, GPR:$Addr
  // The op has no destination ("Fused post-RA so doesn't have a destination"),
  // so the inline header `Size` (= IROp->Size) is unset/zero — reading it gives
  // SZ=0, producing a no-op `addi r11,r11,0` and skipping the case-8 stores.
  // The actual element width is the explicit `ValueSize` argument.
  //
  // RA fusion gates on `ValueSize >= OpSize::i32Bit`, so SZ ∈ {4, 8}. The
  // 32-bit case is required for i686 guest mode — without it, every fused
  // push pair silently dropped both stores (RSP decremented but memory
  // unchanged), corrupting any stack frame whose prologue had two adjacent
  // pushes (notably _start's `push $0; push %ecx` argv setup).
  auto Op = IROp->C<IR::IROp_PushTwo>();
  uint32_t SZ = IR::OpSizeToSize(Op->ValueSize);
  auto RSP = StaticRegisters[FEXCore::X86State::REG_RSP];
  addi(RSP, RSP, -static_cast<int16_t>(SZ * 2));
  // 32-bit guest: mask the new RSP, same rationale as Push above.
  MaybeClrUpper32(RSP);
  auto S1 = GetReg(Op->Value1);
  auto S2 = GetReg(Op->Value2);
  switch (SZ) {
  case 4:
    stw(S1, 0, RSP);
    stw(S2, 4, RSP);
    break;
  case 8:
    std(S1, 0, RSP);
    std(S2, 8, RSP);
    break;
  default:
    LOGMAN_MSG_A_FMT("PushTwo: unsupported ValueSize {}", SZ);
    break;
  }
}

DEF_OP(Pop) {
  // Pop: GPR:$Addr, GPR:$Value = Pop OpSize:$Size, GPR:$Addr
  // Two outputs: the new (post-increment) Addr and the popped Value.
  // RA should guarantee Addr != Value (ARM64 backend asserts this).  If they
  // alias (e.g. extreme register pressure), use TMP4 as a temporary to avoid
  // clobbering Addr before the increment.
  auto Op    = IROp->C<IR::IROp_Pop>();
  auto Addr  = GetReg(Op->InoutAddr);
  auto Value = GetReg(Op->OutValue);
  uint32_t SZ = IR::OpSizeToSize(Op->Size);

  GPR LoadDst = (Value == Addr) ? TMP4 : Value;

  // 32-bit guest: mask the load EA. We can't safely mutate Addr in place since
  // it's also the SRA-bound RSP and the post-increment must use the same base.
  // Use TMP3 to hold the masked load EA when in 32-bit mode.
  GPR LoadAddr = Addr;
  if (!CTX->Config.Is64BitMode()) {
    rldicl(TMP3, Addr, 0, 32);
    LoadAddr = TMP3;
  }
  switch (SZ) {
  case 1: lbzx(LoadDst, LoadAddr, r0); break;
  case 2: lhzx(LoadDst, LoadAddr, r0); break;
  case 4: lwzx(LoadDst, LoadAddr, r0); break;
  case 8: ldx (LoadDst, LoadAddr, r0); break;
  }
  addi(Addr, Addr, static_cast<int16_t>(SZ));
  // Re-mask the new RSP so SRA stays 32-bit-canonical.
  MaybeClrUpper32(Addr);
  if (LoadDst != Value) mr(Value, LoadDst);
}

DEF_OP(PopTwo) {
  // PopTwo's IR signature is `OpSize:$Size, GPR:$Addr` — the Addr is an RMW
  // input that gets post-incremented by 2*Size and lives in a RA-assigned
  // GPR (typically but not always the SRA REG_RSP slot).
  //
  // CRITICAL: do NOT hardcode StaticRegisters[REG_RSP] as the load base. The
  // IR pass chains Pop and PopTwo ops via an RMWHandle SSA value seeded from
  // REG_RSP; the RMW handle's allocation may be a DIFFERENT physical register
  // than the SRA-RSP slot. Pop operates on the RMW reg (advancing it) while
  // the SRA-RSP register stays unchanged. If PopTwo then loads from
  // SRA-RSP, the load EA is stale and PopTwo reads the wrong stack slots.
  //
  // Bash $() doesn't hit this because $() unwinds linearly without
  // re-popping a chained RSP. IRET (Primary_CF) DOES: it emits
  // PopTwo + Pop + PopTwo with the IR-RMW SSA Addr chained across all three;
  // the middle Pop advances the RMW reg but the second PopTwo, hardcoded
  // to SRA-RSP, reads from the original RSP+16 (RFLAGS slot) instead of
  // RSP+24 (the actual RSP-slot to pop). The popped value ends up being
  // RFLAGS (0x202) instead of the saved RSP (0xe0000030).
  //
  // Use Op->InoutAddr like DEF_OP(Pop) does. The RA pass should keep this
  // bound to SRA-RSP in trivial cases (RMWHandle becomes a no-op), and even
  // when not, the chain is correct because all three Pops use the same SSA.
  auto Op = IROp->C<IR::IROp_PopTwo>();
  auto Addr = GetReg(Op->InoutAddr);
  auto D1 = GetReg(Op->OutValue1);
  auto D2 = GetReg(Op->OutValue2);
  uint32_t SZ = IR::OpSizeToSize(Op->Size);
  // 32-bit guest: mask the load base so EA wraps at 4 GiB.
  GPR LoadBase = Addr;
  if (!CTX->Config.Is64BitMode()) {
    rldicl(TMP3, Addr, 0, 32);
    LoadBase = TMP3;
  }
  switch (SZ) {
  case 4:
    lwz(TMP1, 0, LoadBase);            // TMP1 = [Addr+0]
    lwz(TMP2, 4, LoadBase);            // TMP2 = [Addr+SZ]
    break;
  case 8:
    ld(TMP1, 0, LoadBase);
    ld(TMP2, 8, LoadBase);
    break;
  default:
    LOGMAN_MSG_A_FMT("PopTwo: unsupported Size {}", SZ);
    break;
  }
  addi(Addr, Addr, static_cast<int16_t>(SZ * 2));
  MaybeClrUpper32(Addr);
  // Writeback Value1 / Value2. If D1 happens to equal Addr (the IR can wire
  // OutValue1 to REG_RSP directly when the last popped slot IS the new RSP
  // — that's exactly the IRET case), the mr overwrites Addr's post-increment
  // with the loaded data, which is the intended semantic (the new RSP IS
  // the popped value, NOT the post-incremented value).
  if (D1 != TMP1) mr(D1, TMP1);
  if (D2 != TMP2) mr(D2, TMP2);
}

// =========================================================================
// RMW (read-modify-write) handle
// =========================================================================

DEF_OP(RMWHandle) {
  // RA marks this trivial (and eliminates it) when the output register is the
  // same as the source.  When register pressure forces a different assignment
  // we still need to move the value.  Match ARM64 backend: unconditional copy.
  auto Dst = GetReg(Node);
  auto Src = GetReg(IROp->Args[0]);
  if (Dst != Src) mr(Dst, Src);
}

// =========================================================================
// MemSet / MemCpy (use C runtime)
// =========================================================================

// REP-prefixed string ops: emit a software loop. The IR contract requires
// us to return the FINAL address(es) after the copy, not just call libc and
// hope the SRA registers happen to land in the right place. The loop is
// linear in element count but the elements are typically small.
DEF_OP(MemSet) {
  auto Op = IROp->C<IR::IROp_MemSet>();
  // x86 REP STOS preserves flags per Intel SDM.  Save CR0 (packed-NZCV)
  // to the red zone before the loop's cmpdi clobbers it; restore after
  // the loop.  TMP3 is overwritten below by the direction-step setup, so
  // we use it briefly here as a transit before the std to memory.
  // mfocrf 0x80 (single-field): only the CR0 nibble is defined pre-3.0C —
  // sufficient, the sole consumer is the mtocrf(0x80) restore below.
  mfocrf(TMP3, 0x80);
  std(TMP3, -8, r1);
  GPR AddrIn = GetReg(Op->Addr);
  // Op->Value is annotated "Inline: Any" in IR.json — IsInlineConstant may
  // return true and GetReg(Op->Value) would index the RA pool with a stale
  // Reg byte, producing a garbage host reg as the store source. ARM64 uses
  // GetZeroableReg here for the zero case; we materialise non-zero inline
  // constants into TMP2 and use r0 (zero register) for the zero case.
  GPR ValIn;
  uint64_t ValConst;
  if (IsInlineConstant(Op->Value, &ValConst)) {
    if (ValConst == 0) {
      ValIn = r0;
    } else {
      LoadConstant(TMP2, ValConst);
      ValIn = TMP2;
    }
  } else {
    ValIn = GetReg(Op->Value);
  }
  GPR LenIn  = GetReg(Op->Length);
  GPR Out    = GetReg(Node);
  uint32_t Sz = IR::OpSizeToSize(Op->Size);

  // Honour Op->Prefix: when valid, the effective base address is Prefix+Addr
  // (mirrors ARM64 backend). Compute into TMP1 up-front so the loop body
  // doesn't need to know about it.
  GPR Base;
  if (Op->Prefix.IsInvalid()) {
    Base = AddrIn;
  } else {
    GPR Prefix = GetReg(Op->Prefix);
    add(TMP1, Prefix, AddrIn);
    Base = TMP1;
  }

  // Direction is a byte: 0xFF backward / 0x01 forward — sign-extend low byte
  // to a 64-bit signed step (-1 / +1) before scaling by Sz.
  uint64_t DirConst;
  if (IsInlineConstant(Op->Direction, &DirConst)) {
    int64_t Signed = static_cast<int64_t>(static_cast<int8_t>(DirConst));
    LoadConstant(TMP3, static_cast<uint64_t>(Signed * static_cast<int64_t>(Sz)));
  } else {
    GPR DirReg = GetReg(Op->Direction);
    extsb(TMP3, DirReg);
    if (Sz != 1) {
      LoadConstant(TMP4, Sz);
      mulld(TMP3, TMP3, TMP4);
    }
  }

  // Fast path: REP STOSB, forward, 64-bit guest. This is libc/Mono memset —
  // measured as the Hard West main thread's hottest block (Mono zeroes every
  // allocation through it; the generic loop below costs ~6 host insns per
  // BYTE). Byte-store to 8-byte alignment, then aligned std chunks (splat via
  // one mulld), then byte tail. Aligned stds cannot cross a page, so a fault
  // mid-set still leaves byte-granular-consistent memory, and guest RCX/RDI
  // are only written back at op end in both paths — fault-visible state is
  // unchanged from the generic loop. 32-bit guests keep the generic loop (the
  // 4 GiB pointer wrap is per-store); backward direction likewise. When the
  // direction is NOT an inline constant (guest DF loaded from state — Hard
  // West's second-hottest stos site), the forward/backward split is decided
  // at runtime on the computed step in TMP3.
  // Follow-up candidate (not done): dcbz 128-byte chunks for the zero case.
  const bool ConstDir = IsInlineConstant(Op->Direction, &DirConst);
  // Eligibility must fold in size/bitness: AlwaysFast may only suppress the
  // generic loop when the fast path was actually emitted for this op —
  // getting this wrong makes constant-forward stosw/d/q emit NO loop at all.
  const bool FastEligible = Sz == 1 && CTX->Config.Is64BitMode() && !(ConstDir && static_cast<int8_t>(DirConst) != 1);
  const bool AlwaysFast = FastEligible && ConstDir && static_cast<int8_t>(DirConst) == 1;
  PPC64Emitter::Label generic_path, out;
  if (FastEligible) {
    if (!AlwaysFast) {
      // TMP3 holds the sign-extended step; +1 selects the fast path.
      cmpdi(TMP3, 1);
      bc(CC_NE, &generic_path);
    }
    if (Base != TMP1) mr(TMP1, Base);
    // Splat the fill byte across 64 bits. Zero case stores r0 directly (the
    // JIT keeps r0 == 0). Tail/align stores use the splat's low byte, which
    // equals the fill byte, so TMP2 is always free as the alignment scratch
    // even when ValIn aliases it.
    GPR Splat = r0;
    if (ValIn != r0) {
      andi_(TMP3, ValIn, 0xFF);
      LoadConstant(TMP4, 0x0101010101010101ULL);
      mulld(TMP3, TMP3, TMP4);
      Splat = TMP3;
    }
    mr(TMP4, LenIn);

    // dcbz block-zero path, zero fill only. dcbz clears one d-cache block per
    // instruction with no store-queue traffic, so a large memset(0) runs at
    // roughly cache-fill bandwidth instead of one store per 8 bytes.
    //
    // Line size comes from HostFeatures.DCacheLineSize, which is
    // AT_DCACHEBSIZE as the kernel reports it (Source/Common/HostFeatures.cpp
    // :731-736, with a 128 fallback) -- never a hardcoded constant, because
    // dcbz's block size *is* that value and getting it wrong zeroes the wrong
    // span. We additionally require a power of two in [32, 256] so the
    // align-up mask and the shift below are well-formed, and bail to the plain
    // std path otherwise.
    //
    // CACHE-INHIBITED STORAGE. dcbz on caching-inhibited or write-through
    // memory takes an alignment interrupt rather than zeroing. Guest heap,
    // stack and anonymous mappings -- everything a memset(0) of >= 2 blocks
    // realistically targets -- are ordinary cacheable memory; POWER glibc's
    // own memset uses dcbz on arbitrary user pointers for exactly this reason.
    // The guard is kept narrow anyway: 64-bit guest, forward direction, byte
    // element, zero fill value, and at least two full blocks remaining.
    // Anything else keeps the std loop.
    //
    // The zero test is a *runtime* compare on the splat, not a compile-time
    // one. Keying it on `Splat == r0` (the inline-constant-zero case) looked
    // natural but is dead code in practice: measured with a JIT-time probe on
    // the ASM tests, every `xor eax,eax; rep stosb` still arrives here with
    // Value as a live register, so the fill byte is only known at run time.
    // One cmpdi+bc per rep-stos op is nothing against a >= 256-byte fill.
    //
    // FAULT GRANULARITY is unchanged from the std path: TMP1 is block-aligned
    // before the loop, a block is a power of two no larger than a page, so a
    // dcbz can neither cross a page nor partially write, and blocks are zeroed
    // in increasing address order -- on a fault the destination still holds a
    // byte-exact prefix, and RCX/RDI are still written back only at op end.
    const uint32_t DBlock = CTX->HostFeatures.DCacheLineSize;
    const bool UseDcbz = DBlock >= 32 && DBlock <= 256 && (DBlock & (DBlock - 1)) == 0;
    const uint32_t DBlockShift = UseDcbz ? static_cast<uint32_t>(std::countr_zero(DBlock)) : 0;

    PPC64Emitter::Label align_loop, chunk_setup, chunk_loop, tail_loop, done;
    PPC64Emitter::Label dcbz_entry, dcbz_align, dcbz_setup, dcbz_loop;
    Bind(&align_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    andi_(TMP2, TMP1, 7);
    bc(CC_EQ, UseDcbz ? &dcbz_entry : &chunk_setup);
    stb(Splat, 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP4, TMP4, -1);
    b(&align_loop);

    if (UseDcbz) {
      Bind(&dcbz_entry);
      // Non-zero fill, or fewer than two blocks left (where the block align-up
      // would dominate): stay on the std chunk loop.
      if (Splat != r0) {
        cmpdi(Splat, 0);
        bc(CC_NE, &chunk_setup);
      }
      cmpldi(TMP4, static_cast<uint16_t>(2 * DBlock));
      bc(CC_ULT, &chunk_setup);

      // Align up to a block boundary with 8-byte stores. TMP1 is already
      // 8-byte aligned here, so this runs at most DBlock/8 - 1 times and
      // consumes at most DBlock-8 bytes -- leaving at least one whole block.
      Bind(&dcbz_align);
      andi_(TMP2, TMP1, static_cast<uint16_t>(DBlock - 1));
      bc(CC_EQ, &dcbz_setup);
      std(Splat, 0, TMP1);
      addi(TMP1, TMP1, 8);
      addi(TMP4, TMP4, -8);
      b(&dcbz_align);

      Bind(&dcbz_setup);
      srdi(TMP2, TMP4, DBlockShift);   // number of whole blocks left
      mtctr(TMP2);
      andi_(TMP4, TMP4, static_cast<uint16_t>(DBlock - 1));
      Bind(&dcbz_loop);
      // r0 in the RA slot of an X-form cache op is the literal-zero form, so
      // the effective address is exactly TMP1 -- and TMP1 is block-aligned, so
      // dcbz's truncation to a block boundary is a no-op.
      dcbz(r(0), TMP1);
      addi(TMP1, TMP1, static_cast<int16_t>(DBlock));
      bdnz(&dcbz_loop);
      // Falls through with TMP4 < DBlock: the std chunk loop and byte tail
      // finish the remainder.
    }

    // CTR-counted chunk loop: 2 instructions + one CTR back-edge per 8 bytes,
    // versus the previous cmpldi/bc/std/addi/addi/b (6 insns + 2 branches). CTR
    // is free mid-block here (the JIT only loads it at block exits for bctr).
    //
    // stdu Splat,8(ptr) writes to ptr+8 and then sets ptr = ptr+8, so ptr is
    // pre-biased by -8 before entering. After N iterations ptr = base+8*(N-1),
    // hence the +8 fixup on exit. Both the aligned-store and the
    // fault-visibility argument above are preserved: TMP1 enters the loop
    // 8-byte aligned so ptr-8 is too, every EA is 8-byte aligned and cannot
    // cross a page, and on a faulting update-form store RA is architecturally
    // left unmodified (and TMP1 is not guest-visible until op end regardless).
    Bind(&chunk_setup);
    srdi(TMP2, TMP4, 3);      // chunk count = len >> 3
    cmpdi(TMP2, 0);
    bc(CC_EQ, &tail_loop);
    mtctr(TMP2);
    andi_(TMP4, TMP4, 7);     // remaining tail length after the chunks
    addi(TMP1, TMP1, -8);
    Bind(&chunk_loop);
    stdu(Splat, 8, TMP1);
    bdnz(&chunk_loop);
    addi(TMP1, TMP1, 8);

    Bind(&tail_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    stb(Splat, 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP4, TMP4, -1);
    b(&tail_loop);
    Bind(&done);
    if (!AlwaysFast) {
      b(&out);
    }
  }
  if (!AlwaysFast) {
    Bind(&generic_path);
    // Loop pointer in TMP1 (TMP1 may already hold Base if prefix was applied).
    if (Base != TMP1) mr(TMP1, Base);
    mr(TMP4, LenIn);

    PPC64Emitter::Label loop, done;
    Bind(&loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    // 32-bit guest: wrap pointer at 4 GiB before each store iteration.
    MaybeClrUpper32(TMP1);
    switch (Sz) {
    case 1: stb(ValIn, 0, TMP1); break;
    case 2: sth(ValIn, 0, TMP1); break;
    case 4: stw(ValIn, 0, TMP1); break;
    case 8: std(ValIn, 0, TMP1); break;
    }
    add(TMP1, TMP1, TMP3);
    addi(TMP4, TMP4, -1);
    b(&loop);
    Bind(&done);
  }
  Bind(&out);

  // Restore CR0 (saved at op entry) — REP STOS preserves flags.
  ld(TMP3, -8, r1);
  mtocrf(0x80, TMP3);

  // Final pointer may sit in upper-half-dirty form for 32-bit guest; mask
  // before writing back to the SSA destination.
  MaybeClrUpper32(TMP1);
  mr(Out, TMP1);
}

DEF_OP(MemCpy) {
  // x86 REP MOVS preserves flags per Intel SDM.  Save CR0 (packed-NZCV)
  // to the red zone before the loop's cmpdi clobbers it; restore after.
  // TMP3 is overwritten below by the direction-step setup — that's fine,
  // we've already stashed the CR0 snapshot to memory.
  // mfocrf 0x80 (single-field): only the CR0 nibble is defined pre-3.0C —
  // sufficient, the sole consumer is the mtocrf(0x80) restore below.
  mfocrf(TMP3, 0x80);
  std(TMP3, -8, r1);
  auto Op = IROp->C<IR::IROp_MemCpy>();
  GPR DestIn = GetReg(Op->Dest);
  GPR SrcIn  = GetReg(Op->Src);
  GPR LenIn  = GetReg(Op->Length);
  GPR OutDst = GetReg(Op->OutDstAddress);
  GPR OutSrc = GetReg(Op->OutSrcAddress);
  uint32_t Sz = IR::OpSizeToSize(Op->Size);

  // Two-stage: get Direction's value into TMP3, then multiply by Sz.
  // OrderedNodeWrapper "IsImmediate" here means "post-RA: holds a
  // PhysicalRegister directly" — NOT "is an inline constant". For an
  // InlineConstant SSA op, the wrapper is a Pointer (IsImmediate=false), and
  // IsInlineConstant returns the constant. For a regular register (post-RA
  // immediate-encoded wrapper), GetReg returns the assigned host register
  // which already holds the materialized value (the IR codegen emits a
  // Constant op writing to the register before this op).
  // Direction is loaded by FEX as a byte from the DF context slot:
  //   forward: 0x01,  backward: 0xFF.
  // Used here as a signed step (-1 or +1), so sign-extend the low byte
  // *before* multiplying by Sz.  Without extsb, 0xFF becomes 255 and we'd
  // step forward by Sz*255 instead of backward by Sz.
  uint64_t DirConst;
  if (IsInlineConstant(Op->Direction, &DirConst)) {
    LoadConstant(TMP3, static_cast<int64_t>(static_cast<int8_t>(DirConst)));
  } else {
    GPR DirReg = GetReg(Op->Direction);
    extsb(TMP3, DirReg);
  }
  if (Sz != 1) {
    LoadConstant(TMP4, Sz);
    mulld(TMP3, TMP3, TMP4);
  }
  GPR Step = TMP3;

  // Fast path: REP MOVSB, forward, 64-bit guest. Guest glibc 2.44 lowers every
  // copy >= 2KB to `rep movsb` because the port advertises ERMS, and the
  // generic loop below costs ~8 host instructions per BYTE. Byte-copy to
  // 8-byte DST alignment, then ld/std chunks, then byte tail.
  //
  // Register allocation on the fast path (same three loop registers as the
  // generic loop, so the OutDst/OutSrc writeback below is correct on every
  // path):
  //   TMP1 = running dst, TMP2 = running src, TMP4 = remaining count,
  //   TMP3 = dead after the direction test, reused as the delta/alignment
  //          scratch, r0 = data scratch (restored to 0 at op end, both paths).
  //
  // OVERLAP GUARD. x86 forward `rep movsb` with dst inside (src, src+len) is a
  // legal self-replicating pattern fill: byte-by-byte forward semantics are
  // architecturally required there. With delta = dst - src (mod 2^64), chunked
  // and byte-forward copies agree exactly when delta == 0 or delta >= 8
  // unsigned. Proof sketch: byte i of a chunk reads memory that the store
  // covering it wrote in chunk floor((i-delta)/8); that chunk index is strictly
  // less than the current one iff delta > (i mod 8) - ((i-delta) mod 8), whose
  // range is [-7,7], so delta >= 8 always satisfies it and 0 < delta < 8 fails
  // it for the byte where the difference equals delta. dst < src makes the
  // unsigned delta enormous (guest addresses are far below 2^63), so it passes.
  // The single unsigned test `delta >= 8` therefore covers both safe cases and
  // sends only 0 <= delta < 8 to the generic loop — delta == 0 (dst == src) is
  // correct either way but is rare enough not to be worth a second test.
  //
  // FAULT GRANULARITY. The chunk stores are 8-byte aligned, so they cannot
  // cross a page and cannot partially fault. The chunk loads may be unaligned
  // and may fault mid-chunk, but a faulting load modifies no memory. So on any
  // fault the destination holds a byte-exact prefix of the copy, exactly like
  // the generic loop, and guest RCX/RSI/RDI are written back only at op end on
  // both paths — the guest-visible state at fault time is unchanged.
  //
  // Gating: 32-bit guests keep the generic loop (the 4 GiB pointer wrap is
  // per-element). Sz != 1 keeps the generic loop. The generic loop is emitted
  // UNCONDITIONALLY whenever the fast path exists, because the runtime overlap
  // guard branches into it even when the direction is a compile-time forward
  // constant — a size/bitness-blind "fast path always taken" predicate is what
  // made constant-forward REP STOSW/D/Q emit no loop at all (acbbb3405).
  const bool ConstDir = IsInlineConstant(Op->Direction, &DirConst);
  const bool FastEligible = Sz == 1 && CTX->Config.Is64BitMode() && !(ConstDir && static_cast<int8_t>(DirConst) != 1);
  const bool ConstForward = FastEligible && ConstDir && static_cast<int8_t>(DirConst) == 1;
  PPC64Emitter::Label generic_path, out;
  if (FastEligible) {
    if (!ConstForward) {
      // Step (TMP3) is the sign-extended direction; +1 selects forward.
      cmpdi(TMP3, 1);
      bc(CC_NE, &generic_path);
    }
    mr(TMP1, DestIn);
    mr(TMP2, SrcIn);
    mr(TMP4, LenIn);

    // delta = dst - src; subf rt,ra,rb computes rb - ra. Computed into r0, NOT
    // TMP3: this branch can still fall through to the generic loop, which needs
    // Step alive in TMP3. r0 is already the op's declared data scratch and is
    // restored to 0 at op end on every path. cmpldi reads RA's contents (the
    // "(RA|0)" literal-zero rule is a load/store + addi rule), so r0 is legal
    // as its operand.
    subf(r(0), TMP2, TMP1);
    cmpldi(r(0), 8);
    bc(CC_ULT, &generic_path);

    // 16B-tier overlap gate: stage `delta >= 16` into CR6 NOW, while delta is
    // still live in r0 — the alignment loop below reuses r0 as its data
    // scratch. Every other compare in this op targets CR0, and the guest's
    // packed-NZCV CR0 snapshot/restore brackets the whole op, so parking a
    // predicate in CR6 across the alignment loop is free. Same proof shape as
    // the delta >= 8 argument above with chunk size 16: byte-forward and
    // 16B-chunked copies agree exactly when delta == 0 or delta >= 16, so
    // deltas in [8, 16) must stay on the 8B tier.
    cmpldi(cr(6), r(0), 16);
    // 32B-tier overlap gate, same staging trick one CR field up: byte-forward
    // and 32B-chunked copies agree exactly when delta == 0 or delta >= 32, so
    // deltas in [16, 32) must stay on the 16B tier.
    cmpldi(cr(7), r(0), 32);

    PPC64Emitter::Label align_loop, chunk_setup, chunk8_setup, chunk16_setup, chunk16_go, chunk16_loop, chunk32_loop, chunk_loop, tail_loop, done;
    Bind(&align_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    andi_(TMP3, TMP1, 7);
    bc(CC_EQ, &chunk_setup);
    lbz(r(0), 0, TMP2);
    stb(r(0), 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP2, TMP2, 1);
    addi(TMP4, TMP4, -1);
    b(&align_loop);

    // CTR-counted chunk loop: ldu/stdu + one CTR back-edge per 8 bytes, versus
    // the previous cmpldi/bc/ld/std/addi/addi/addi/b. Both pointers are
    // pre-biased by -8 because the update forms compute EA = RA+8 and then set
    // RA = EA; after N iterations each sits at base+8*(N-1), hence the +8
    // fixups on exit. TMP3 is dead here (the direction test and the overlap
    // guard are both behind us, and no path from inside these loops reaches
    // the generic loop, which is the only consumer of Step).
    //
    // Source may be unaligned: POWER8 handles unaligned cacheable loads in
    // hardware, and the DS-form constraint is on the immediate (8, 4-aligned),
    // not on the address. The stores stay 8-byte aligned, so the fault
    // granularity argument above is unchanged; a faulting update-form access
    // also leaves RA architecturally unmodified.
    Bind(&chunk_setup);
    // 16-byte VSX tier. Gates, in order:
    //   - CR6.LT set (delta < 16, staged before the alignment loop): a
    //     forward delta in [8, 16) is a legal self-replicating pattern for
    //     16B chunks to break, but the 8B tier below is still exact there.
    //   - remaining length < 32: not worth the 16-alignment step plus loop
    //     setup; the 8B tier handles short copies fine.
    bc(Cond {12, 24}, &chunk8_setup); // CR6.LT (BI = 6*4 + 0)
    cmpdi(TMP4, 32);
    bc(CC_LT, &chunk8_setup);

    // Destination is 8-aligned here (align_loop above); one 8-byte unit
    // reaches 16-alignment when bit 3 is set. The 16B *stores* below are then
    // 16-aligned, so they can never cross a page and never partially fault —
    // the fault-granularity argument above carries over to this tier
    // unchanged (the unaligned loads may still fault; they modify no memory).
    andi_(TMP3, TMP1, 8);
    bc(CC_EQ, &chunk16_setup);
    ld(r(0), 0, TMP2);
    std(r(0), 0, TMP1);
    addi(TMP1, TMP1, 8);
    addi(TMP2, TMP2, 8);
    addi(TMP4, TMP4, -8);

    Bind(&chunk16_setup);
    // Delta (r0) is dead once CR6/CR7 are staged; restore the JIT's r0=0
    // zero-index invariant early so lxvd2x/stxvd2x can use r0 as their RB
    // index. len >= 24 here (>= 32 gated, minus at most one 8B alignment
    // step), so the 16B CTR count is >= 1 and mtctr 0 is impossible.
    li(r(0), 0);
    // 32B tier: 2x-unrolled lxvd2x/stxvd2x. Gates mirror the 16B tier's:
    //   - CR7.LT set (delta < 32): a forward delta in [16, 32) is a legal
    //     self-replicating pattern for 32B chunks to break; the 16B tier is
    //     still exact there.
    //   - remaining length < 64: not worth the extra setup; and it keeps the
    //     32B CTR count >= 2, so mtctr 0 is impossible here too.
    // Both 16B stores stay 16-aligned, so neither can cross a page: on any
    // fault the destination holds a byte-exact 16B-granular prefix and the
    // fault-granularity argument above carries over unchanged. Both loads of
    // a chunk issue before either store, so each 32B chunk reads strictly
    // before it writes, matching the delta >= 32 exactness proof.
    bc(Cond {12, 28}, &chunk16_go); // CR7.LT (BI = 7*4 + 0)
    cmpdi(TMP4, 64);
    bc(CC_LT, &chunk16_go);
    srdi(TMP3, TMP4, 5);      // 32B chunk count = len >> 5
    mtctr(TMP3);
    andi_(TMP4, TMP4, 31);    // remainder: one optional 16B step + 8B tier + tail
    li(TMP3, 16);             // second-lane RB index; TMP3 is dead here (see 8B tier note)
    Bind(&chunk32_loop);
    lxvd2x(VTMP1, TMP2, r(0));
    lxvd2x(VTMP2, TMP2, TMP3);
    stxvd2x(VTMP1, TMP1, r(0));
    stxvd2x(VTMP2, TMP1, TMP3);
    addi(TMP1, TMP1, 32);
    addi(TMP2, TMP2, 32);
    bdnz(&chunk32_loop);
    // The remainder is < 32 with dst still 16-aligned: peel at most one 16B
    // chunk here rather than falling into chunk16_setup, whose mtctr would
    // spin 2^64 times on a zero count.
    andi_(TMP3, TMP4, 16);
    bc(CC_EQ, &chunk8_setup);
    lxvd2x(VTMP1, TMP2, r(0));
    stxvd2x(VTMP1, TMP1, r(0));
    addi(TMP1, TMP1, 16);
    addi(TMP2, TMP2, 16);
    addi(TMP4, TMP4, -16);
    b(&chunk8_setup);

    Bind(&chunk16_go);
    srdi(TMP3, TMP4, 4);      // 16B chunk count = len >> 4
    mtctr(TMP3);
    andi_(TMP4, TMP4, 15);    // remainder for the 8B tier + byte tail
    // lxvd2x/stxvd2x pair on the SAME VSR: both perform the LE doubleword
    // swap, so the swaps cancel and the 16 bytes are copied verbatim — no
    // xxpermdi needed, unlike LoadUnalignedV128 (whose TMP1-TMP3 clobber
    // contract would also collide with the loop registers here). VTMP1/VTMP2
    // are per-op scratch, dead across ops, same as their other DEF_OP uses.
    // No update forms exist for these, so the pointers step by explicit addi;
    // both end exactly at the end of the chunked region.
    Bind(&chunk16_loop);
    lxvd2x(VTMP1, TMP2, r(0));
    stxvd2x(VTMP1, TMP1, r(0));
    addi(TMP1, TMP1, 16);
    addi(TMP2, TMP2, 16);
    bdnz(&chunk16_loop);
    // Fall into the 8B tier for the 8..15-byte remainder: dst is still
    // 16-aligned (hence 8-aligned) and TMP4 < 16, so it runs 0 or 1 chunks
    // plus the byte tail.

    Bind(&chunk8_setup);
    srdi(TMP3, TMP4, 3);      // chunk count = len >> 3
    cmpdi(TMP3, 0);
    bc(CC_EQ, &tail_loop);
    mtctr(TMP3);
    andi_(TMP4, TMP4, 7);     // remaining tail length after the chunks
    addi(TMP1, TMP1, -8);
    addi(TMP2, TMP2, -8);
    Bind(&chunk_loop);
    ldu(r(0), 8, TMP2);
    stdu(r(0), 8, TMP1);
    bdnz(&chunk_loop);
    addi(TMP1, TMP1, 8);
    addi(TMP2, TMP2, 8);

    Bind(&tail_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    lbz(r(0), 0, TMP2);
    stb(r(0), 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP2, TMP2, 1);
    addi(TMP4, TMP4, -1);
    b(&tail_loop);
    Bind(&done);
    b(&out);
  }

  Bind(&generic_path);
  {
    // Loop state: TMP1 = current Dst, TMP2 = current Src, TMP4 = remaining count.
    mr(TMP1, DestIn);
    mr(TMP2, SrcIn);
    mr(TMP4, LenIn);

    PPC64Emitter::Label loop, done;
    Bind(&loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    // 32-bit guest: wrap pointers at 4 GiB before each iteration's load+store.
    MaybeClrUpper32(TMP1);
    MaybeClrUpper32(TMP2);
    switch (Sz) {
    case 1: lbz(r(0), 0, TMP2); stb(r(0), 0, TMP1); break;
    case 2: lhz(r(0), 0, TMP2); sth(r(0), 0, TMP1); break;
    case 4: lwz(r(0), 0, TMP2); stw(r(0), 0, TMP1); break;
    case 8: ld(r(0), 0, TMP2);  std(r(0), 0, TMP1); break;
    }
    add(TMP1, TMP1, Step);
    add(TMP2, TMP2, Step);
    addi(TMP4, TMP4, -1);
    b(&loop);
    Bind(&done);
  }
  Bind(&out);

  MaybeClrUpper32(TMP1);
  MaybeClrUpper32(TMP2);
  mr(OutDst, TMP1);
  mr(OutSrc, TMP2);
  // r0 was clobbered as the value scratch above; restore the JIT's r0=0
  // zero-index invariant before subsequent indexed mem ops.
  li(r(0), 0);
  // Restore CR0 (saved at op entry) — REP MOVS preserves flags.
  ld(TMP3, -8, r1);
  mtocrf(0x80, TMP3);
}

// =========================================================================
// Cache control
// =========================================================================

DEF_OP(CacheLineClear)  {
  GPR Addr = GetReg(IROp->C<IR::IROp_CacheLineClear>()->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  dcbst(r0, Addr);
  sync(0);
}

DEF_OP(CacheLineClean)  {
  GPR Addr = GetReg(IROp->C<IR::IROp_CacheLineClean>()->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  dcbt(r0, Addr);
}

DEF_OP(CacheLineZero)   {
  GPR Addr = GetReg(IROp->C<IR::IROp_CacheLineZero>()->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }

  if (CTX->HostFeatures.DCacheLineSize == CPUIDEmu::CACHELINE_SIZE) {
    // Fast path: dcbz zeroes exactly one host d-cache line, at an effective
    // address truncated to that line. That is the semantics x86 CLZERO wants
    // only when the host line is 64 bytes.
    //
    // NEVER TAKEN ON POWER8/9 -- their line is 128 bytes, and HostFeatures.cpp
    // :722-729 reports the kernel's AT_DCACHEBSIZE (measured 128) with a 128
    // fallback. Written as a guarded branch anyway so the intent is legible
    // and so the instruction does not merely look forgotten.
    dcbz(r0, Addr);
  } else {
    // We must walk the cacheline ourselves.
    //
    // x86 CLZERO zeroes 64 bytes at a 64-byte-truncated effective address. A
    // bare dcbz on POWER zeroes 128 bytes at a 128-byte-truncated address, so
    // it destroys up to 64 bytes of unrelated guest memory before and/or after
    // the intended region -- silent guest heap corruption, not a fault.
    //
    // Mirrors ARM64's non-CLZERO path (JIT/MemoryOps.cpp:2451-2460), including
    // the forced alignment: the guest address is not required to be aligned and
    // CLZERO truncates rather than faulting.
    clrrdi(TMP1, Addr, 6);  // EA & ~63
    for (int16_t Offset = 0; Offset < static_cast<int16_t>(CPUIDEmu::CACHELINE_SIZE); Offset += 8) {
      // r0 in the RS slot reads the register, which the backend's r0 == 0 block
      // invariant holds at zero (see MemoryOps.cpp:705, ALUOps.cpp:3275).
      std(r0, Offset, TMP1);
    }
  }
}

DEF_OP(Fence) {
  auto Op = IROp->C<IR::IROp_Fence>();
  switch (Op->Fence) {
  case IR::FenceType::Load:             lwsync(); isync(); break;
  case IR::FenceType::LoadStore:        hwsync(); break;
  case IR::FenceType::Store:            lwsync(); break;
  default:                              hwsync(); break;
  }
}

DEF_OP(Prefetch) {
  auto Op = IROp->C<IR::IROp_Prefetch>();
  // dcbt hint: 0 = load, 16 = dcbtst (store). CacheLevel/Stream fields are advisory.
  uint32_t Hint = Op->ForStore ? 16 : 0;
  GPR Addr = GetReg(Op->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  dcbt(r0, Addr, Hint);
}

// =========================================================================
// Non-temporal store
// =========================================================================

DEF_OP(VStoreNonTemporal) {
  auto Op   = IROp->C<IR::IROp_VStoreNonTemporal>();
  auto Src  = GetVReg(Op->Value);
  auto Addr = GetReg(Op->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  li(TMP4, Op->Offset);
  stvxl(Src, Addr, TMP4);  // LRU hint = non-temporal
}

DEF_OP(VStoreNonTemporalPair) {
  auto Op   = IROp->C<IR::IROp_VStoreNonTemporalPair>();
  auto Addr = GetReg(Op->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  li(TMP4, 0);
  stvxl(GetVReg(Op->ValueLow), Addr, TMP4);
  li(TMP4, 16);
  stvxl(GetVReg(Op->ValueHigh), Addr, TMP4);
}

DEF_OP(VLoadNonTemporal) {
  auto Op   = IROp->C<IR::IROp_VLoadNonTemporal>();
  auto Dst  = GetVReg(Node);
  auto Addr = GetReg(Op->Addr);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  li(TMP4, Op->Offset);
  lvxl(Dst, Addr, TMP4);
}

// =========================================================================
// Context clear (zero out x86 registers)
// =========================================================================

DEF_OP(ContextClear) {
  // Zero `Length` bytes of context state at `STATE + Offset`. The IR uses this
  // to wipe ranges like avx_high[..] after vzeroupper / VEX-encoded ops on
  // YMM. The previous implementation wiped *every* SRA register (incl. RSP) —
  // catastrophic when the IR only meant to clear avx_high.
  auto Op = IROp->C<IR::IROp_ContextClear>();
  const int32_t Offset = static_cast<int32_t>(Op->Offset);
  const int32_t Length = static_cast<int32_t>(Op->Size);

  vspltisw(VTMP1, 0);                          // VTMP1 = {0}
  int32_t Pos = 0;
  // 16-byte chunks via stvx (Length is typically a multiple of 16 for AVX clears).
  while (Pos + 16 <= Length) {
    LoadConstant(TMP1, static_cast<uint32_t>(Offset + Pos));
    stvx(VTMP1, STATE, TMP1);
    Pos += 16;
  }
  // Tail in 8-byte chunks.
  while (Pos + 8 <= Length) {
    if (Offset + Pos >= -32768 && Offset + Pos <= 32764 && ((Offset + Pos) & 3) == 0) {
      std(r0, static_cast<int16_t>(Offset + Pos), STATE);
    } else {
      LoadConstant(TMP1, static_cast<uint32_t>(Offset + Pos));
      stdx(r0, STATE, TMP1);
    }
    Pos += 8;
  }
  // Trailing bytes (rare).
  while (Pos < Length) {
    if (Offset + Pos >= -32768 && Offset + Pos <= 32767) {
      stb(r0, static_cast<int16_t>(Offset + Pos), STATE);
    } else {
      LoadConstant(TMP1, static_cast<uint32_t>(Offset + Pos));
      stbx(r0, STATE, TMP1);
    }
    Pos += 1;
  }
}

// =========================================================================
// Masked vector loads/stores
// =========================================================================
//
// VLoad/StoreVectorMasked back x86 VPMASKMOV/VMASKMOV (AVX/AVX2). We handle
// only the 128-bit case here; 256-bit lowers to two 128-bit ops via the
// AVX-128 path. Per-element conditional load/store: for each LE element i,
// if the high bit of MaskReg's element i is set, copy element i between
// memory[Addr + Offset + i*ElemSz] and the vector. Loaded elements are
// zero on mask=0; stored elements leave memory untouched on mask=0.
//
// The implementation spills the vector to the stack scratch slot, then
// loops scalar over each element with a per-element mask test branch.
// This is slow but correct, and matches the ARM64 fallback path used when
// SVE is unavailable.

// Helper: branch to Skip when MaskWord's high (sign) bit of the loaded element
// is zero. Result of load already in TMP1; Sz is element size in bytes. Uses
// rlwinm./sradi. to set CR0[EQ] = (sign bit clear).
static void EmitMaskBitTestSkip(PPC64JITCore* j, int sz) {
  switch (sz) {
  case 1: j->andi_(TMP1, TMP1, 0x80);                  break;  // mask bit7 of byte
  case 2: j->rlwinm_(TMP1, TMP1, 0, 16, 16);           break;  // mask bit15 of halfword
  case 4: j->rlwinm_(TMP1, TMP1, 0, 0, 0);             break;  // mask bit31 of word
  // sradi_ would set CR0 correctly but ALSO writes XER.CA (the canonical
  // CFInverted x86 CF storage).  Use rldicl_ instead: rotate-left 1 + mask
  // bit 0 puts the sign bit (originally bit 63 in BE-numbering = MSB) into
  // LSB position, then Rc form sets CR0.EQ = (sign bit was 0).  rldicl
  // does not touch XER, so x86 CF is preserved across VPMASKMOVQ-style ops.
  case 8: j->rldicl_(TMP1, TMP1, 1, 63);                break;
  }
}

DEF_OP(VLoadVectorMasked) {
  const auto Op       = IROp->C<IR::IROp_VLoadVectorMasked>();
  const auto OpSize   = IROp->Size;
  const auto ElemSz   = IR::OpSizeToSize(IROp->ElementSize);
  const auto Dst      = GetVReg(Node);
  const auto MaskReg  = GetVReg(Op->Mask);
  const auto MemReg   = GetReg(Op->Addr);
  LOGMAN_THROW_A_FMT(OpSize == IR::OpSize::i128Bit, "VLoadVectorMasked: only 128-bit supported on PPC64LE");
  const size_t NumElements = IR::NumElements(OpSize, IROp->ElementSize);

  GPR Base = ComputeAddress(MemReg, Op->Offset, Op->OffsetType, Op->OffsetScale);
  // ComputeAddress may return TMP3 when the offset is non-trivial; preserve it.
  if (Base == TMP3) { mr(TMP4, Base); Base = TMP4; }

  // Spill mask to stack[r1-32 .. r1-16]; zero-init result slot at [r1-16 .. r1).
  addi(TMP3, r1, -32);
  li(TMP2, 0);
  stvx(MaskReg, TMP3, TMP2);
  std(r0, -16, r1);
  std(r0,  -8, r1);

  for (size_t i = 0; i < NumElements; ++i) {
    const int16_t MaskOff = static_cast<int16_t>(-32 + i * ElemSz);
    const int16_t DstOff  = static_cast<int16_t>(-16 + i * ElemSz);
    switch (ElemSz) {
    case 1: lbz(TMP1, MaskOff, r1); break;
    case 2: lhz(TMP1, MaskOff, r1); break;
    case 4: lwz(TMP1, MaskOff, r1); break;
    case 8: ld (TMP1, MaskOff, r1); break;
    default: ERROR_AND_DIE_FMT("VLoadVectorMasked: bad ElemSz {}", ElemSz);
    }
    EmitMaskBitTestSkip(this, ElemSz);
    auto Skip = PPC64Emitter::Label{};
    bc(CC_EQ, &Skip);
    // Compute element address index reg.
    GPR Idx = r0;
    if (i != 0) { LoadConstant(TMP2, static_cast<uint64_t>(i * ElemSz)); Idx = TMP2; }
    switch (ElemSz) {
    case 1: lbzx(TMP2, Base, Idx); stb(TMP2, DstOff, r1); break;
    case 2: lhzx(TMP2, Base, Idx); sth(TMP2, DstOff, r1); break;
    case 4: lwzx(TMP2, Base, Idx); stw(TMP2, DstOff, r1); break;
    case 8: ldx (TMP2, Base, Idx); std(TMP2, DstOff, r1); break;
    }
    Bind(&Skip);
  }

  addi(TMP3, r1, -16);
  li(TMP2, 0);
  lvx(Dst, TMP3, TMP2);
}

DEF_OP(VStoreVectorMasked) {
  const auto Op       = IROp->C<IR::IROp_VStoreVectorMasked>();
  const auto OpSize   = IROp->Size;
  const auto ElemSz   = IR::OpSizeToSize(IROp->ElementSize);
  const auto Data     = GetVReg(Op->Data);
  const auto MaskReg  = GetVReg(Op->Mask);
  const auto MemReg   = GetReg(Op->Addr);
  LOGMAN_THROW_A_FMT(OpSize == IR::OpSize::i128Bit, "VStoreVectorMasked: only 128-bit supported on PPC64LE");
  const size_t NumElements = IR::NumElements(OpSize, IROp->ElementSize);

  GPR Base = ComputeAddress(MemReg, Op->Offset, Op->OffsetType, Op->OffsetScale);
  if (Base == TMP3) { mr(TMP4, Base); Base = TMP4; }

  // Spill mask to [r1-32 .. r1-16] and data to [r1-16 .. r1).
  li(TMP2, 0);
  addi(TMP3, r1, -32);
  stvx(MaskReg, TMP3, TMP2);
  addi(TMP3, r1, -16);
  stvx(Data,    TMP3, TMP2);

  for (size_t i = 0; i < NumElements; ++i) {
    const int16_t MaskOff = static_cast<int16_t>(-32 + i * ElemSz);
    const int16_t DataOff = static_cast<int16_t>(-16 + i * ElemSz);
    switch (ElemSz) {
    case 1: lbz(TMP1, MaskOff, r1); break;
    case 2: lhz(TMP1, MaskOff, r1); break;
    case 4: lwz(TMP1, MaskOff, r1); break;
    case 8: ld (TMP1, MaskOff, r1); break;
    default: ERROR_AND_DIE_FMT("VStoreVectorMasked: bad ElemSz {}", ElemSz);
    }
    EmitMaskBitTestSkip(this, ElemSz);
    auto Skip = PPC64Emitter::Label{};
    bc(CC_EQ, &Skip);
    // Use a displacement form rather than an indexed store: the prior code
    // materialised the byte offset into TMP4 and used st[bhwd]x(rs, Base, TMP4),
    // but `Base` is also TMP4 whenever ComputeAddress returned via TMP3 (the
    // mr-to-TMP4 alias guard), so loading the offset into TMP4 silently clobbered
    // Base and we ended up storing to (i*ElemSz)+(i*ElemSz). With a displacement
    // store Base stays in TMP4 untouched. i*ElemSz <= 24 fits int16 easily and
    // is always 4-byte-aligned when ElemSz>=4 (required by std/stw).
    const int16_t ElemOff = static_cast<int16_t>(i * ElemSz);
    switch (ElemSz) {
    case 1: lbz(TMP2, DataOff, r1); stb(TMP2, ElemOff, Base); break;
    case 2: lhz(TMP2, DataOff, r1); sth(TMP2, ElemOff, Base); break;
    case 4: lwz(TMP2, DataOff, r1); stw(TMP2, ElemOff, Base); break;
    case 8: ld (TMP2, DataOff, r1); std(TMP2, ElemOff, Base); break;
    }
    Bind(&Skip);
  }
}

// AVX2 VSIB gather (VPGATHERD*, VGATHERDPS/PD, VGATHERQPS/PD). Per-element
// software loop using stack-roundtrip to extract vector lanes. POWER8 has no
// scalar element-extract for arbitrary-index vectors, so we spill mask, the
// index vector(s), and the incoming-merge vector to the stack, then process
// each element with regular GPR loads/stores.
//
// Stack frame (all offsets relative to r1; ELFv2 ABI guarantees 16-byte
// alignment, so all 16-byte slots below are 16-byte aligned for stvx/lvx):
//   r1-64 .. r1-48   Mask spill          (16 bytes)
//   r1-48 .. r1-32   VectorIndexLow      (16 bytes)
//   r1-32 .. r1-16   VectorIndexHigh     (16 bytes; only used if needed)
//   r1-16 .. r1       Result             (initialised from Incoming)
//
// Invariant 7 (r0=zero in load index forms): we use a real scratch GPR for
// the displacement index into the spill area, never r0.
namespace {
constexpr int16_t kMaskOff   = -64;
constexpr int16_t kIdxLoOff  = -48;
constexpr int16_t kIdxHiOff  = -32;
constexpr int16_t kResultOff = -16;
}

DEF_OP(VLoadVectorGatherMasked) {
  const auto Op       = IROp->C<IR::IROp_VLoadVectorGatherMasked>();
  const auto OpSize   = IROp->Size;
  const auto ElemSz   = IR::OpSizeToSize(IROp->ElementSize);
  const auto IdxSz    = IR::OpSizeToSize(Op->VectorIndexElementSize);
  const auto OffsetScale = Op->OffsetScale;
  const size_t DataElementOffsetStart  = Op->DataElementOffsetStart;
  const size_t IndexElementOffsetStart = Op->IndexElementOffsetStart;
  const bool   AddrSize64 = Op->AddrSize == IR::OpSize::i64Bit;

  LOGMAN_THROW_A_FMT(OpSize == IR::OpSize::i128Bit,
                     "VLoadVectorGatherMasked: PPC64LE only sees 128-bit (AVX_128 split path)");
  LOGMAN_THROW_A_FMT(IdxSz == 4 || IdxSz == 8,
                     "VLoadVectorGatherMasked: bad VectorIndexElementSize {}", IdxSz);

  const auto Dst         = GetVReg(Node);
  const auto IncomingDst = GetVReg(Op->Incoming);
  const auto MaskReg     = GetVReg(Op->Mask);
  const auto VIdxLow     = GetVReg(Op->VectorIndexLow);

  const bool HasBase = !Op->AddrBase.IsInvalid();
  const bool HasHigh = !Op->VectorIndexHigh.IsInvalid();

  // Element counts. NumDataElements is clamped both by the data-vector size
  // and by the available index lanes (IndexElementOffsetStart consumes some).
  const size_t NumAddrElements = (HasHigh ? 32u : 16u) / IdxSz;
  const size_t NumDataElements = std::min<size_t>(IR::OpSizeToSize(OpSize) / ElemSz, NumAddrElements);

  // Spill state to stack.
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kMaskOff)));
  stvx(MaskReg, r1, TMP1);
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kIdxLoOff)));
  stvx(VIdxLow, r1, TMP1);
  if (HasHigh) {
    const auto VIdxHigh = GetVReg(Op->VectorIndexHigh);
    LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kIdxHiOff)));
    stvx(VIdxHigh, r1, TMP1);
  }
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kResultOff)));
  stvx(IncomingDst, r1, TMP1);

  // Snapshot BaseAddr to a stable scratch (the input GPR may not be reachable
  // through r0 in addi semantics, and we may need to mask it for 32-bit guest).
  GPR Base = r0;  // sentinel "no base"
  if (HasBase) {
    Base = GetReg(Op->AddrBase);
    if (!CTX->Config.Is64BitMode() || !AddrSize64) {
      // In 32-bit guest mode, or when AddrSize is i32Bit, mask to 32 bits.
      // Use TMP4 as a stable copy.
      rldicl(TMP4, Base, 0, 32);
      Base = TMP4;
    }
  }

  for (size_t i = DataElementOffsetStart, IndexElement = IndexElementOffsetStart;
       i < NumDataElements; ++i, ++IndexElement) {
    auto Skip = PPC64Emitter::Label{};

    // --- Mask test: load element i of MaskReg from spill, test sign bit. ---
    const int16_t MaskElemOff = static_cast<int16_t>(kMaskOff + i * ElemSz);
    switch (ElemSz) {
    case 1: lbz(TMP1, MaskElemOff, r1); break;
    case 2: lhz(TMP1, MaskElemOff, r1); break;
    case 4: lwz(TMP1, MaskElemOff, r1); break;
    case 8: ld (TMP1, MaskElemOff, r1); break;
    default:
      ERROR_AND_DIE_FMT("VLoadVectorGatherMasked: bad ElemSz {}", ElemSz);
    }
    EmitMaskBitTestSkip(this, ElemSz);
    bc(CC_EQ, &Skip);

    // --- Load index element (sign-extended). Honour IndexElementOffsetStart
    //     and the low/high vector split. ---
    const size_t LowLanes  = 16 / IdxSz;
    const bool   FromHigh  = (IndexElement >= LowLanes);
    const size_t LaneInBlk = FromHigh ? (IndexElement - LowLanes) : IndexElement;
    const int16_t IdxBase  = FromHigh ? kIdxHiOff : kIdxLoOff;
    const int16_t IdxOff   = static_cast<int16_t>(IdxBase + LaneInBlk * IdxSz);
    if (FromHigh) {
      LOGMAN_THROW_A_FMT(HasHigh, "Index element overflow without VectorIndexHigh");
    }
    if (IdxSz == 4) {
      lwa(TMP2, IdxOff, r1);   // sign-extend 32-bit index to 64-bit
    } else {
      ld(TMP2, IdxOff, r1);
    }

    // --- Compute address = Base + index*OffsetScale. ---
    if (OffsetScale != 1) {
      sldi(TMP2, TMP2, __builtin_ctz(OffsetScale));
    }
    GPR EA = TMP2;
    if (HasBase) {
      add(TMP3, Base, TMP2);
      EA = TMP3;
    }
    if (!AddrSize64) {
      // Mask to 32 bits per AddrSize=i32Bit.
      rldicl(TMP3, EA, 0, 32);
      EA = TMP3;
    } else if (!CTX->Config.Is64BitMode()) {
      // 32-bit guest with i64Bit AddrSize from the IR shouldn't really
      // happen, but be defensive — guest pointers are still 32-bit.
      rldicl(TMP3, EA, 0, 32);
      EA = TMP3;
    }

    // --- Load ElemSz bytes from EA, store into result spill slot i. ---
    const int16_t DstElemOff = static_cast<int16_t>(kResultOff + i * ElemSz);
    // We need a scratch GPR for the result slot index; use TMP1.
    switch (ElemSz) {
    case 1: lbzx(TMP1, r0, EA); stb(TMP1, DstElemOff, r1); break;
    case 2: lhzx(TMP1, r0, EA); sth(TMP1, DstElemOff, r1); break;
    case 4: lwzx(TMP1, r0, EA); stw(TMP1, DstElemOff, r1); break;
    case 8: ldx (TMP1, r0, EA); std(TMP1, DstElemOff, r1); break;
    }

    Bind(&Skip);
  }

  // Materialise result vector.
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kResultOff)));
  lvx(Dst, r1, TMP1);
}

DEF_OP(VLoadVectorGatherMaskedQPS) {
  // VPGATHERQPS / VPGATHERQD: 32-bit data elements gathered via 64-bit
  // address indices. Output is a single 128-bit vector; up to 4 32-bit
  // elements (2 if VectorIndexHigh is Invalid). Mask is 32-bit per element.
  const auto Op = IROp->C<IR::IROp_VLoadVectorGatherMaskedQPS>();
  const auto OffsetScale = Op->OffsetScale;
  const bool AddrSize64  = Op->AddrSize == IR::OpSize::i64Bit;

  LOGMAN_THROW_A_FMT(IROp->Size == IR::OpSize::i128Bit,
                     "VLoadVectorGatherMaskedQPS: only 128-bit dst supported");
  LOGMAN_THROW_A_FMT(IROp->ElementSize == IR::OpSize::i32Bit,
                     "VLoadVectorGatherMaskedQPS: ElementSize must be 32-bit");

  const auto Dst         = GetVReg(Node);
  const auto IncomingDst = GetVReg(Op->Incoming);
  const auto MaskReg     = GetVReg(Op->MaskReg);
  const auto VIdxLow     = GetVReg(Op->VectorIndexLow);

  const bool HasBase = !Op->AddrBase.IsInvalid();
  const bool HasHigh = !Op->VectorIndexHigh.IsInvalid();

  // Number of data elements = number of 64-bit indices available, capped at 4.
  const size_t NumDataElements = HasHigh ? 4u : 2u;
  constexpr size_t ElemSz = 4;  // 32-bit data
  constexpr size_t IdxSz  = 8;  // 64-bit index

  // Spill state.
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kMaskOff)));
  stvx(MaskReg, r1, TMP1);
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kIdxLoOff)));
  stvx(VIdxLow, r1, TMP1);
  if (HasHigh) {
    const auto VIdxHigh = GetVReg(Op->VectorIndexHigh);
    LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kIdxHiOff)));
    stvx(VIdxHigh, r1, TMP1);
  }
  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kResultOff)));
  stvx(IncomingDst, r1, TMP1);

  GPR Base = r0;
  if (HasBase) {
    Base = GetReg(Op->AddrBase);
    if (!CTX->Config.Is64BitMode() || !AddrSize64) {
      rldicl(TMP4, Base, 0, 32);
      Base = TMP4;
    }
  }

  for (size_t i = 0; i < NumDataElements; ++i) {
    auto Skip = PPC64Emitter::Label{};

    // Mask is 32-bit per element. Test bit 31.
    const int16_t MaskElemOff = static_cast<int16_t>(kMaskOff + i * ElemSz);
    lwz(TMP1, MaskElemOff, r1);
    EmitMaskBitTestSkip(this, ElemSz);
    bc(CC_EQ, &Skip);

    // 64-bit index: lanes 0,1 from IdxLow, lanes 2,3 from IdxHigh.
    const bool   FromHigh  = (i >= 2);
    const size_t LaneInBlk = FromHigh ? (i - 2) : i;
    const int16_t IdxBase  = FromHigh ? kIdxHiOff : kIdxLoOff;
    const int16_t IdxOff   = static_cast<int16_t>(IdxBase + LaneInBlk * IdxSz);
    ld(TMP2, IdxOff, r1);

    if (OffsetScale != 1) {
      sldi(TMP2, TMP2, __builtin_ctz(OffsetScale));
    }
    GPR EA = TMP2;
    if (HasBase) {
      add(TMP3, Base, TMP2);
      EA = TMP3;
    }
    if (!AddrSize64 || !CTX->Config.Is64BitMode()) {
      rldicl(TMP3, EA, 0, 32);
      EA = TMP3;
    }

    const int16_t DstElemOff = static_cast<int16_t>(kResultOff + i * ElemSz);
    lwzx(TMP1, r0, EA);
    stw(TMP1, DstElemOff, r1);

    Bind(&Skip);
  }

  LoadConstant(TMP1, static_cast<uint64_t>(static_cast<int64_t>(kResultOff)));
  lvx(Dst, r1, TMP1);
}
// VLoadVectorElement / VStoreVectorElement: implemented in VectorOps.cpp.

// VBroadcastFromMem: load `ElementSize` bytes from [Address] and broadcast
// across all lanes of a 128-bit destination vector. x86 `vpbroadcast{b,w,d,q}`
// with memory operand lowers here. We don't support 256-bit; the upstream
// AVX-128 lowering emits two paired 128-bit broadcasts when needed.
//
// Op_Unhandled silently no-ops in release builds when no fallback handler is
// registered, leaving the destination vreg with stale data — that was
// observed to corrupt main_arena.bins[] during glibc-static startup
// (hello_static SIGSEGV in _int_malloc / tcache_init), since glibc uses
// memory-source vpbroadcastq heavily for arena initialization. Implement.
DEF_OP(VBroadcastFromMem) {
  const auto Op = IROp->C<IR::IROp_VBroadcastFromMem>();
  const auto Dst = GetVReg(Node);
  GPR MemReg = GetReg(Op->Address);
  if (!CTX->Config.Is64BitMode()) {
    rldicl(TMP3, MemReg, 0, 32);
    MemReg = TMP3;
  }
  const auto ElementSize = Op->Header.ElementSize;

  // mtvsrd defines BE dword 0 (phys[0..7]); BE dword 1 (phys[8..15]) is
  // undefined per ISA. The splat indices 15/7/3 read from phys[15]/phys[14..15]/
  // phys[12..15] — all in the undefined half. Use xxpermdi DM=0 to duplicate
  // the defined dword into both halves before splatting (same pattern as
  // VShlI i64 — invariant 0a).
  switch (ElementSize) {
  case IR::OpSize::i8Bit:
    lbzx(TMP1, MemReg, r0);
    mtvsrd(VTMP1, TMP1);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vspltb(Dst, VTMP1, 15);
    break;
  case IR::OpSize::i16Bit:
    lhzx(TMP1, MemReg, r0);
    mtvsrd(VTMP1, TMP1);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsplth(Dst, VTMP1, 7);
    break;
  case IR::OpSize::i32Bit:
    lwzx(TMP1, MemReg, r0);
    mtvsrd(VTMP1, TMP1);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vspltw(Dst, VTMP1, 3);
    break;
  case IR::OpSize::i64Bit:
    // lxvdsx is exactly this operation in one instruction: load a doubleword
    // and splat it into both halves. It replaces a GPR load, two stores, an
    // addi and a vector load whose data comes straight from those stores --
    // a store-hit-load on the path glibc takes through memory-source
    // vpbroadcastq during arena init. Byte-identical to the old sequence on
    // POWER8, checked with an asymmetric value at a non-16-byte-aligned
    // address (lxvdsx does not truncate the EA the way lvx does, and does
    // not byte-reverse). Still no vsldoi-after-mtvsrd: that would read the
    // ISA-undefined doubleword.
    lxvdsx(Dst, r(0), MemReg);
    break;
  case IR::OpSize::i128Bit:
    // 128-bit "broadcast" is just a 128-bit load.
    LoadUnalignedV128(Dst, MemReg);
    break;
  default:
    Op_Unhandled(IROp, Node);
    break;
  }
}

// =========================================================================
// X87 SVE optimisation stubs (ARM64-specific, fall back)
// =========================================================================
DEF_OP(StoreMemX87SVEOptPredicate) { StoreMem_Impl(IROp, Node); }
DEF_OP(LoadMemX87SVEOptPredicate)  { LoadMem_Impl(IROp, Node); }

// (These are thin wrappers — reuse the regular load/store logic)
void PPC64JITCore::StoreMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node) {
  // Treat as regular StoreMem
  auto Op   = IROp->C<IR::IROp_StoreMemX87SVEOptPredicate>();
  GPR Addr = GetReg(Op->Addr);
  auto Src  = GetVReg(Op->Value);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  li(TMP4, 0);
  stvx(Src, Addr, TMP4);
}
void PPC64JITCore::LoadMem_Impl(const IR::IROp_Header* IROp, IR::Ref Node) {
  auto Op   = IROp->C<IR::IROp_LoadMemX87SVEOptPredicate>();
  GPR Addr = GetReg(Op->Addr);
  auto Dst  = GetVReg(Node);
  if (!CTX->Config.Is64BitMode()) { rldicl(TMP3, Addr, 0, 32); Addr = TMP3; }
  li(TMP4, 0);
  lvx(Dst, Addr, TMP4);
}

} // namespace FEXCore::CPU
