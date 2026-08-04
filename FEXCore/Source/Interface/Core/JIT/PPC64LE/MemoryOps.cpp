// SPDX-License-Identifier: MIT
// PPC64LE memory operations for FEX JIT backend.
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/CPUID.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>

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

DEF_OP(LoadContextIndexed) {
  auto Op = IROp->C<IR::IROp_LoadContextIndexed>();
  auto Idx = GetReg(Op->Index);
  // EA = STATE + BaseOffset + Idx * Stride. Compute into TMP3.
  LoadConstant(TMP1, static_cast<uint32_t>(Op->BaseOffset));
  LoadConstant(TMP2, static_cast<uint64_t>(Op->Stride));
  mulld(TMP3, Idx, TMP2);
  add(TMP3, TMP3, TMP1);
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
  LoadConstant(TMP1, static_cast<uint32_t>(Op->BaseOffset));
  LoadConstant(TMP2, static_cast<uint64_t>(Op->Stride));
  mulld(TMP3, Idx, TMP2);
  add(TMP3, TMP3, TMP1);
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
  if (Offset.IsInvalid()) {
    return Base;
  }
  uint64_t Const;
  if (IsInlineConstant(Offset, &Const)) {
    if (Const == 0) {
      return Base;
    }
    int64_t sOff = static_cast<int64_t>(Const) * OffsetScale;
    if (sOff >= -32768 && sOff <= 32767) {
      addi(TMP3, Base, static_cast<int16_t>(sOff));
    } else {
      LoadConstant(TMP3, static_cast<uint64_t>(sOff));
      add(TMP3, Base, TMP3);
    }
    return TMP3;
  }
  GPR OffReg = GetReg(Offset);
  if (OffsetType == IR::MemOffsetType::UXTW) {
    rldicl(TMP3, OffReg, 0, 32);
    OffReg = TMP3;
  } else if (OffsetType == IR::MemOffsetType::SXTW) {
    extsw(TMP3, OffReg);
    OffReg = TMP3;
  }
  if (OffsetScale > 1) {
    sldi(TMP3, OffReg, __builtin_ctz(OffsetScale));
    add(TMP3, Base, TMP3);
  } else {
    add(TMP3, Base, OffReg);
  }
  return TMP3;
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
  GPR EA = ComputeAddress(Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);

  if (Op->Class == IR::RegClass::FPR) {
    // Honour Op->Size so vmovd/vmovq don't read 16B and clobber upper lanes.
    LoadFPRSized(GetVReg(Dst), EA, IR::OpSizeToSize(IROp->Size));
    return;
  }
  auto GDst = GetReg(Dst);
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:   lbzx(GDst, EA, r0); break;  // r0 = 0 for EA+0
  case IR::OpSize::i16Bit:  lhzx(GDst, EA, r0); break;
  case IR::OpSize::i32Bit:  lwzx(GDst, EA, r0); break;
  case IR::OpSize::i64Bit:  ldx(GDst, EA, r0);  break;
  case IR::OpSize::i128Bit:
    LoadUnalignedV128(GetVReg(Dst), EA);
    break;
  default: break;
  }
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
    li(TMP4, static_cast<int16_t>(Stride));
    switch (IROp->Size) {
    case IR::OpSize::i8Bit:  lbzx(D1, Base, r0); lbzx(D2, Base, TMP4); break;
    case IR::OpSize::i16Bit: lhzx(D1, Base, r0); lhzx(D2, Base, TMP4); break;
    case IR::OpSize::i32Bit: lwzx(D1, Base, r0); lwzx(D2, Base, TMP4); break;
    case IR::OpSize::i64Bit: ldx (D1, Base, r0); ldx (D2, Base, TMP4); break;
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
  GPR EA = ComputeAddress(Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);

  // Dispatch on the explicit RegisterClass field — IsFPR(Op->Value) reads the
  // *node's* class which can disagree with the store's class (e.g. an FPR-class
  // value stored as a GPR-sized chunk). Use the IR-declared class.
  if (Op->Class == IR::RegClass::FPR) {
    // Honour Op->Size so vmovd m32 / vmovq m64 don't write 16B and stomp on
    // adjacent stack slots (e.g. wiping [rsp+8] in __tls_init_tp).
    StoreFPRSized(GetVReg(Op->Value), EA, IR::OpSizeToSize(IROp->Size));
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
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:   stbx(GSrc, EA, r0); break;
  case IR::OpSize::i16Bit:  sthx(GSrc, EA, r0); break;
  case IR::OpSize::i32Bit:  stwx(GSrc, EA, r0); break;
  case IR::OpSize::i64Bit:  stdx(GSrc, EA, r0); break;
  case IR::OpSize::i128Bit:
    StoreUnalignedV128(GetVReg(Op->Value), EA);
    break;
  default: break;
  }
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
    li(TMP4, static_cast<int16_t>(Stride));
    switch (IROp->Size) {
    case IR::OpSize::i8Bit:  stbx(S1, Base, r0); stbx(S2, Base, TMP4); break;
    case IR::OpSize::i16Bit: sthx(S1, Base, r0); sthx(S2, Base, TMP4); break;
    case IR::OpSize::i32Bit: stwx(S1, Base, r0); stwx(S2, Base, TMP4); break;
    case IR::OpSize::i64Bit: stdx(S1, Base, r0); stdx(S2, Base, TMP4); break;
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
  GPR EA = ComputeAddress(Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);

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
    LoadFPRSized(GetVReg(Dst), EA, IR::OpSizeToSize(IROp->Size));
    lwsync();
    return;
  }

  auto GDst = GetReg(Dst);
  switch (IROp->Size) {
  // NOTE the operand order: address in RA, r0 in RB. Power's literal-zero rule
  // covers RA only, so this reads GPR0's *contents* as the index and depends on
  // an r0==0 invariant. Nothing in this backend writes r0, so the invariant
  // holds — but it is an invariant, not an architectural guarantee. Contrast
  // `PPC64.cpp:222-224`, which puts r0 in RA where the rule genuinely applies.
  case IR::OpSize::i8Bit:  lbzx(GDst, EA, r0); break;
  case IR::OpSize::i16Bit: lhzx(GDst, EA, r0); break;
  case IR::OpSize::i32Bit: lwzx(GDst, EA, r0); break;
  case IR::OpSize::i64Bit: ldx(GDst, EA, r0);  break;
  default: break;
  }
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
  GPR EA = ComputeAddress(Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);

  // x86 TSO stores are release stores. lwsync before the store provides
  // StoreStore + LoadStore release ordering relative to prior memory ops.
  lwsync();

  if (Op->Class == IR::RegClass::FPR) {
    // Size-aware so TSO `vmovd m32, %xmm` writes 4B not 16B.
    StoreFPRSized(GetVReg(Op->Value), EA, IR::OpSizeToSize(IROp->Size));
    return;
  }

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
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:  stbx(GSrc, EA, r0); break;
  case IR::OpSize::i16Bit: sthx(GSrc, EA, r0); break;
  case IR::OpSize::i32Bit: stwx(GSrc, EA, r0); break;
  case IR::OpSize::i64Bit: stdx(GSrc, EA, r0); break;
  default: break;
  }
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
    stwx(S1, RSP, r0);
    li(TMP4, 4);
    stwx(S2, RSP, TMP4);
    break;
  case 8:
    stdx(S1, RSP, r0);
    li(TMP4, 8);
    stdx(S2, RSP, TMP4);
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
  li(TMP4, static_cast<int16_t>(SZ));
  switch (SZ) {
  case 4:
    lwzx(TMP1, LoadBase, r0);          // TMP1 = [Addr+0]
    lwzx(TMP2, LoadBase, TMP4);        // TMP2 = [Addr+SZ]
    break;
  case 8:
    ldx(TMP1, LoadBase, r0);
    ldx(TMP2, LoadBase, TMP4);
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
  // 4 GiB pointer wrap is per-store); backward/unknown direction likewise.
  // Follow-up candidate (not done): dcbz 128-byte chunks for the zero case.
  const bool ConstDir = IsInlineConstant(Op->Direction, &DirConst);
  if (ConstDir && static_cast<int8_t>(DirConst) == 1 && Sz == 1 && CTX->Config.Is64BitMode()) {
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

    PPC64Emitter::Label align_loop, chunk_loop, tail_loop, done;
    Bind(&align_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    andi_(TMP2, TMP1, 7);
    bc(CC_EQ, &chunk_loop);
    stb(Splat, 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP4, TMP4, -1);
    b(&align_loop);

    Bind(&chunk_loop);
    cmpldi(TMP4, 8);
    bc(CC_ULT, &tail_loop);
    std(Splat, 0, TMP1);
    addi(TMP1, TMP1, 8);
    addi(TMP4, TMP4, -8);
    b(&chunk_loop);

    Bind(&tail_loop);
    cmpdi(TMP4, 0);
    bc(CC_EQ, &done);
    stb(Splat, 0, TMP1);
    addi(TMP1, TMP1, 1);
    addi(TMP4, TMP4, -1);
    b(&tail_loop);
    Bind(&done);
  } else {
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
    // Stack-roundtrip 64-bit duplicate. Avoids the undefined-doubleword
    // hazard of `vsldoi VTMP1,VTMP1,VTMP1,8` after `mtvsrd` (which only
    // defines the high doubleword per ISA).
    ldx(TMP1, MemReg, r0);
    std(TMP1, -16, r1);
    std(TMP1,  -8, r1);
    addi(TMP2, r1, -16);
    lvx(Dst, TMP2, r0);
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
