// SPDX-License-Identifier: MIT
// PPC64LE vector operations for FEX JIT backend.
// AltiVec/VMX instructions target POWER8 (ISA 2.07).
// All AltiVec ops are element-wise arithmetic — endianness-neutral for
// add/sub/compare. Permute/splat ops adjust indices for LE byte ordering
// (physical byte N in register = logical byte 15-N in LE element 0=low-addr).
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Context/Context.h"
#include <algorithm>
#include <cmath>

namespace FEXCore::CPU {

using namespace PPC64Emitter::FPRegs;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// In PPC64LE, vsplt* selects from physical byte position (BE ordering).
// To select logical LE element index E of N elements per 128-bit vector:
//   physical_idx = (N - 1) - E
static constexpr uint8_t SplatByteIdx(uint8_t LEIdx)   { return (uint8_t)(15 - LEIdx); }
static constexpr uint8_t SplatHalfIdx(uint8_t LEIdx)   { return (uint8_t)(7  - LEIdx); }
static constexpr uint8_t SplatWordIdx(uint8_t LEIdx)   { return (uint8_t)(3  - LEIdx); }

// Emit a vsplt* for the given element size and logical LE index.
// Result: every element of Dst = element LEIdx of Src.
static void EmitVSplat(PPC64JITCore* jit, VR Dst, VR Src,
                       IR::OpSize ElemSz, uint8_t LEIdx) {
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    jit->vspltb(Dst, Src, SplatByteIdx(LEIdx));
    break;
  case IR::OpSize::i16Bit:
    jit->vsplth(Dst, Src, SplatHalfIdx(LEIdx));
    break;
  case IR::OpSize::i32Bit:
    jit->vspltw(Dst, Src, SplatWordIdx(LEIdx));
    break;
  case IR::OpSize::i64Bit:
    // POWER8 has no vspltd. Use `xxpermdi VRT, Src, Src, DM` which takes
    // BE doubleword (DM>>1) of VRA and BE doubleword (DM&1) of VRB.
    // BE dw0 = phys[0..7] = LE element 1; BE dw1 = phys[8..15] = LE element 0.
    // So:
    //   LEIdx=0 → both halves = phys[8..15] = BE dw1 → DM = 0b11
    //   LEIdx=1 → both halves = phys[0..7]  = BE dw0 → DM = 0b00
    // Previous implementation devolved to `vmr Dst, Src` (an identity copy),
    // which silently broke any IR like `VDupElement(Src, i64, 1)` —
    // observed as `vpmovsxdq ymm,xmm` producing the LOW xmm lanes in both
    // 256-bit halves and contaminating glibc malloc init.
    jit->xxpermdi(Dst, Src, Src, LEIdx == 0 ? 0b11u : 0b00u);
    break;
  default:
    break;
  }
}

// ---------------------------------------------------------------------------
// VMov — copy vector register (zero upper bits for sub-128-bit ops)
// ---------------------------------------------------------------------------
DEF_OP(VMov) {
  const auto Op = IROp->C<IR::IROp_VMov>();
  const auto OpSize = IROp->Size;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Source);

  if (OpSize == IR::OpSize::i128Bit) {
    if (Dst != Src) vmr(Dst, Src);
    return;
  }

  // Sub-128-bit move: keep the low LE bytes of Src, zero the rest.
  //
  // In FEX's LE convention LE byte i lives at physical byte (15-i), so the
  // "low N bytes" are at physical [16-N .. 15].  We shift Src left by (16-N)
  // bytes so those bytes land at physical [0..N-1], then shift right by N
  // bytes (with zero on the high side) so they end up at [16-N..15] with
  // physical [0..15-N] cleared.
  vspltisw(VTMP1, 0);
  switch (OpSize) {
  case IR::OpSize::i8Bit:
    vsldoi(VTMP2, Src, VTMP1, 15);  // VTMP2 phys[0] = Src phys[15], rest zero
    vsldoi(Dst,  VTMP1, VTMP2, 1);  // Dst phys[15] = VTMP2 phys[0], rest zero
    break;
  case IR::OpSize::i16Bit:
    vsldoi(VTMP2, Src, VTMP1, 14);
    vsldoi(Dst,  VTMP1, VTMP2, 2);
    break;
  case IR::OpSize::i32Bit:
    vsldoi(VTMP2, Src, VTMP1, 12);
    vsldoi(Dst,  VTMP1, VTMP2, 4);
    break;
  case IR::OpSize::i64Bit:
    vsldoi(VTMP2, Src, VTMP1, 8);
    vsldoi(Dst,  VTMP1, VTMP2, 8);
    break;
  default:
    if (Dst != Src) vmr(Dst, Src);
    break;
  }
}

// ---------------------------------------------------------------------------
// VectorImm — load immediate into every element
// ---------------------------------------------------------------------------
DEF_OP(VectorImm) {
  const auto Op = IROp->C<IR::IROp_VectorImm>();
  const auto Dst = GetVReg(Node);
  const auto ElemSz = Op->Header.ElementSize;
  const uint8_t Imm = Op->Immediate;
  const uint8_t Shift = Op->ShiftAmount;
  uint64_t val = static_cast<uint64_t>(Imm) << Shift;

  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    if (val >= 0x80) {
      // vspltisb is signed, range -16..15 only.
      // mtvsrd lands the GPR in BE-dword 0 (BE-bytes 0..7) and leaves BE-dword 1
      // (BE-bytes 8..15) undefined per ISA. SplatByteIdx(0)=15 reads from the
      // undefined half. Duplicate dword 0 into both halves first (same fix as
      // VDupFromGPR).
      LoadConstant(TMP1, val & 0xFF);
      mtvsrd(Dst, TMP1);
      xxpermdi(Dst, Dst, Dst, 0);          // dword0 || dword0
      vspltb(Dst, Dst, SplatByteIdx(0));   // broadcast LE-byte 0 (= BE-byte 15)
    } else {
      vspltisb(Dst, (int8_t)(val & 0xFF));
    }
    break;
  case IR::OpSize::i16Bit:
    if ((int16_t)val >= -16 && (int16_t)val <= 15) {
      vspltish(Dst, (int16_t)val);
    } else {
      LoadConstant(TMP1, val & 0xFFFF);
      mtvsrd(Dst, TMP1);
      xxpermdi(Dst, Dst, Dst, 0);          // dword0 || dword0 (see i8 note)
      vsplth(Dst, Dst, SplatHalfIdx(0));
    }
    break;
  case IR::OpSize::i32Bit:
    if ((int32_t)val >= -16 && (int32_t)val <= 15) {
      vspltisw(Dst, (int32_t)val);
    } else {
      LoadConstant(TMP1, val & 0xFFFFFFFF);
      mtvsrd(Dst, TMP1);
      xxpermdi(Dst, Dst, Dst, 0);          // dword0 || dword0 (see i8 note)
      vspltw(Dst, Dst, SplatWordIdx(0));
    }
    break;
  case IR::OpSize::i64Bit:
    // mtvsrd writes BE-dword 0 (phys 0..7); BE-dword 1 (phys 8..15) is UNDEFINED
    // per POWER ISA. `vsldoi(Dst, Dst, Dst, 8)` would rotate by reading that
    // undefined half — on POWER8 it observably zeroes BE-dword 0 of the result,
    // which made VPERMILPD's i64 IndexMask lose its high-qword selector bit.
    // Use xxpermdi DM=0 (dword0 || dword0) to duplicate the defined doubleword
    // into both halves without ever reading the undefined half. Matches the
    // existing pattern in VShlI/VUShrI/VSShrI i64Bit and VDupFromGPR i*Bit.
    LoadConstant(TMP1, val);
    mtvsrd(Dst, TMP1);
    xxpermdi(Dst, Dst, Dst, 0);
    break;
  default:
    vspltisw(Dst, 0);
    break;
  }
}

// ---------------------------------------------------------------------------
// LoadNamedVectorConstant / LoadNamedVectorIndexedConstant — unhandled
// ---------------------------------------------------------------------------
DEF_OP(LoadNamedVectorConstant) {
  const auto Op  = IROp->C<IR::IROp_LoadNamedVectorConstant>();
  const auto Dst = GetVReg(Node);
  // NAMED_VECTOR_ZERO is a sentinel (= NAMED_VECTOR_CONST_POOL_MAX, indexing
  // past the populated table) — match the ARM64 backend's `movi #0`
  // interception, otherwise we'd lvx 16 bytes of OOB memory and leak
  // whatever sits past JITPointers (observed: `0x0000000000000200` EFLAGS
  // reserved-bit pattern, breaking VEX.256 zero-flush downstream).
  // Use vspltisb #0 (signed-imm splat) rather than `vxor self,self,self`
  // because it doesn't read Dst — avoids any RA edge case where Dst's
  // assigned physical reg overlaps a same-block live range.
  if (Op->Constant == FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_ZERO) {
    vspltisb(Dst, 0);
    return;
  }
  // Each entry is 16 bytes (alignas(16)), load via lvx (EA must be 16-byte aligned).
  const uint64_t Off = ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.NamedVectorConstants, Op->Constant);

  // i64-and-smaller named constants: zero the upper half of the VR. Several
  // constants (e.g. CVTMAX_I32) are stored as full 128-bit broadcasts of an
  // INT_MIN/sentinel pattern, but the OpcodeDispatcher requests them with
  // OpSize::i64Bit when only the low element is meaningful (see VBSL with
  // ZeroUpperHalf=true in Vector_CVT_Float_To_Int32Impl). If we keep the
  // table's upper-64 broadcast, the downstream VBSL picks it up and leaks
  // INT_MIN into the result's upper qword — corrupting `cvtpd2dq xmm`.
  if (IROp->Size <= IR::OpSize::i64Bit) {
    // Load just the low 8 bytes of the table entry, zero the upper 8.
    // mtvsrd staging: no stack round-trip, no store-forwarding stall
    // (docs/EMITTER_REVIEW.md finding 2). mtvsrd puts the value in the
    // VSR's BE dw0; xxpermdi dm=0b00 takes zero.dw0 into phys[0..7] and
    // value.dw0 into phys[8..15] — the same image the old std/lvx pair
    // produced (LE u64 at the lower address → phys[8..15], LSB at phys[15]).
    LoadConstant(TMP1, Off);
    add(TMP3, STATE, TMP1);
    ld(TMP2, 0, TMP3);
    mtvsrd(VTMP1, TMP2);
    vspltisb(Dst, 0);
    xxpermdi(Dst, Dst, VTMP1, 0b00);
    return;
  }

  LoadConstant(TMP1, Off);
  lvx(Dst, STATE, TMP1);
  // The "LE byte-reverse fix" vperm that used to follow (5-word control
  // build + vperm, ~14 insns) was an IDENTITY permute: in LE mode lvx
  // already places mem[A+i] at phys[15-i], so the reversal it tried to
  // apply had been applied by the load itself, and the control vector —
  // itself loaded through the same reversing lvx — composed to identity.
  // Proven on hardware (lnvc_probe.c, 2026-08-03) and by the ASM suite
  // running clean without it. Every consumer's phys[] conventions were
  // built against the post-lvx layout, which is unchanged by the deletion.
}

DEF_OP(LoadNamedVectorIndexedConstant) {
  // Indexed table lookup of a named vector constant: typically the per-imm8
  // shuffle masks for PSHUFD / PSHUFLW / PSHUFHW / SHUFPS / PBLENDW etc.
  // Each table entry is RegisterSize bytes, stored LE in memory.
  //
  // Op_Unhandled here was a silent no-op in release builds (no fallback
  // registered) — the destination vreg kept stale data, and downstream
  // pshufb/pshufd ops then permuted "garbage", which could leak prior
  // vector contents (including XMM-pattern data) into pointer-shaped
  // memory writes during glibc startup.
  const auto Op = IROp->C<IR::IROp_LoadNamedVectorIndexedConstant>();
  const auto Dst = GetVReg(Node);
  const auto Size = IROp->Size;

  // Load pointer to the constant table from CpuStateFrame.
  const uint64_t PtrOff = ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame,
                                          Pointers.IndexedNamedVectorConstantPointers,
                                          Op->Constant);
  LoadConstant(TMP1, PtrOff);
  ldx(TMP1, STATE, TMP1);                  // TMP1 = base ptr to the table
  if (Op->Index != 0) {
    if (Op->Index <= 0x7FFF) {
      addi(TMP1, TMP1, static_cast<int16_t>(Op->Index));
    } else {
      LoadConstant(TMP2, static_cast<uint64_t>(Op->Index));
      add(TMP1, TMP1, TMP2);
    }
  }

  switch (Size) {
  case IR::OpSize::i128Bit:
    // Same LE-fixup pattern as LoadNamedVectorConstant: lvx loads as BE so
    // byte-reverse via vperm. Table entries are 16-byte aligned (IR.json
    // says "Index needs to be aligned register size").
    lvx(VTMP1, TMP1, r0);
    LoadConstant(TMP2, 0x08090A0B0C0D0E0FULL); std(TMP2, -16, r1);
    LoadConstant(TMP2, 0x0001020304050607ULL); std(TMP2, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(VTMP2, TMP2, r0);
    vperm(Dst, VTMP1, VTMP1, VTMP2);
    break;
  case IR::OpSize::i64Bit:
    // Load 8 LE bytes into low 8 bytes of bounce, zero high 8, single lvx.
    // Mirrors LoadNamedVectorConstant's i64 case - no byte-reverse needed:
    // lvx places memory-byte-i at phys-byte-i, and downstream consumers
    // (e.g. VTBL1) read FEX's phys-i = LE-i convention directly.  The prior
    // vperm reversed the bytes within the low 8, which scrambled the
    // PSHUFLW / PSHUFHW byte-index tables and made MMX PSHUFW with imm
    // values that hit the default path (not 0x00 / 0xFF fast-path) produce
    // a broadcast of the source's LE byte 0.
    ld(TMP2, 0, TMP1);
    std(TMP2, -16, r1);
    std(r(0), -8, r1);
    addi(TMP3, r1, -16);
    lvx(Dst, r(0), TMP3);
    break;
  case IR::OpSize::i32Bit:
    lwz(TMP2, 0, TMP1);
    mtvsrd(VTMP1, TMP2);
    vspltisb(Dst, 0);
    xxpermdi(Dst, Dst, VTMP1, 0b00); // zero:phys[0..7], value:phys[8..15]
    // No byte-reversal needed: lwz loads LE->GPR-natural and mtvsrd's dw0,
    // placed into phys[8..15], reproduces the old std/lvx image exactly
    // (value at LE element 0, other lanes 0).
    break;
  case IR::OpSize::i16Bit:
    lhz(TMP2, 0, TMP1);
    mtvsrd(VTMP1, TMP2);
    vspltisb(Dst, 0);
    xxpermdi(Dst, Dst, VTMP1, 0b00); // zero:phys[0..7], value:phys[8..15]
    break;
  case IR::OpSize::i8Bit:
    lbz(TMP2, 0, TMP1);
    mtvsrd(VTMP1, TMP2);
    vspltisb(Dst, 0);
    xxpermdi(Dst, Dst, VTMP1, 0b00); // zero:phys[0..7], value:phys[8..15]
    break;
  default:
    Op_Unhandled(IROp, Node);
    break;
  }
}

// ---------------------------------------------------------------------------
// Simple unary vector ops
// ---------------------------------------------------------------------------

DEF_OP(VNot) {
  const auto Op = IROp->C<IR::IROp_VNot>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vnot(Dst, Src);
}

DEF_OP(VNeg) {
  const auto Op = IROp->C<IR::IROp_VNeg>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsububm(Dst, VTMP1, Src); break;
  case IR::OpSize::i16Bit: vsubuhm(Dst, VTMP1, Src); break;
  case IR::OpSize::i32Bit: vsubuwm(Dst, VTMP1, Src); break;
  case IR::OpSize::i64Bit: vsubudm(Dst, VTMP1, Src); break;
  default: vmr(Dst, Src); break;
  }
}

DEF_OP(VAbs) {
  const auto Op = IROp->C<IR::IROp_VAbs>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  // abs(x) = max(x, -x) for signed integers
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vsububm(VTMP2, VTMP1, Src);
    vmaxsb(Dst, Src, VTMP2);
    break;
  case IR::OpSize::i16Bit:
    vsubuhm(VTMP2, VTMP1, Src);
    vmaxsh(Dst, Src, VTMP2);
    break;
  case IR::OpSize::i32Bit:
    vsubuwm(VTMP2, VTMP1, Src);
    vmaxsw(Dst, Src, VTMP2);
    break;
  case IR::OpSize::i64Bit:
    vsubudm(VTMP2, VTMP1, Src);
    vmaxsd(Dst, Src, VTMP2);
    break;
  default:
    vmr(Dst, Src);
    break;
  }
}

DEF_OP(VPopcount) {
  const auto Op = IROp->C<IR::IROp_VPopcount>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpopcntb(Dst, Src); break;
  case IR::OpSize::i16Bit: vpopcnth(Dst, Src); break;
  case IR::OpSize::i32Bit: vpopcntw(Dst, Src); break;
  case IR::OpSize::i64Bit: vpopcntd(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VFAbs / VFNeg: VSX has direct per-element abs/neg instructions on POWER8.
DEF_OP(VFAbs) {
  const auto Op = IROp->C<IR::IROp_VFAbs>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvabssp(Dst, Src); break;
  case IR::OpSize::i64Bit: xvabsdp(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFNeg) {
  const auto Op = IROp->C<IR::IROp_VFNeg>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvnegsp(Dst, Src); break;
  case IR::OpSize::i64Bit: xvnegdp(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VFRecp: x86 RCP{PS,SS} 12-bit reciprocal estimate.  vrefp matches that for
// f32; for f64 there is no Altivec/VSX estimate op, so emit 1.0/x via per-lane
// fdiv (closer to RCPPD which does not exist on x86 but FEX uses it for AVX
// f64 reciprocal lowerings — matches ARM64's fmov+fdiv fallback).
DEF_OP(VFRecp) {
  const auto Op = IROp->C<IR::IROp_VFRecp>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  if (ElemSz == IR::OpSize::i32Bit) {
    vrefp(Dst, Src);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 1.0 / Src per lane, via stack roundtrip (POWER8 has no xvredp).
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    LoadConstant(TMP2, 0x3FF0000000000000ULL); // 1.0
    std(TMP2, -24, r1);
    lfd(f0, -24, r1);
    lfd(f1, 0, TMP1);   // lane 0
    fdiv(f1, f0, f1);
    stfd(f1, 0, TMP1);
    lfd(f1, 8, TMP1);   // lane 1
    fdiv(f1, f0, f1);
    stfd(f1, 8, TMP1);
    lvx(Dst, r(0), TMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// VFRecpPrecision: 14-bit precision needed (3DNow!).  Per IR.json this only
// ever has ElementSize == i32.  Refine vrefp (~12 bits) via one Newton step:
//   r' = r * (2 - x*r).
// Implemented with vnmsubfp (= VRB - VRA*VRC) so we use only VTMP1 + VTMP2.
DEF_OP(VFRecpPrecision) {
  const auto Op = IROp->C<IR::IROp_VFRecpPrecision>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vrefp(VTMP1, Src);                        // r0 ≈ 1/Src  (±inf for ±0)
  // Build {2.0f,...}: vspltisw 2 = signed-int 2 per lane, vcfsx 0 → 2.0f.
  vspltisw(VTMP2, 2);
  vcfsx(VTMP2, VTMP2, 0);                   // VTMP2 = 2.0
  // vnmsubfp(t,a,b,c) = b - a*c  →  VTMP2 = 2.0 - Src*r0
  vnmsubfp(VTMP2, Src, VTMP2, VTMP1);
  // vmaddfp(t,a,b,c)  = a*c + b  →  Dst = r0 * VTMP2 + 0
  vspltisw(Dst, 0);
  vmaddfp(Dst, VTMP1, Dst, VTMP2);
  // Newton-Raphson refinement misbehaves on three input classes that x86
  // PFRCP / RCPSS must still answer correctly:
  //   (1) Src = ±0      →  vrefp = ±inf; step = 2 - 0*inf = NaN;
  //                        Newton = inf*NaN = NaN.
  //   (2) Src very tiny non-zero subnormal (|Src| < ~2^-127, e.g. 1.4e-45 =
  //                        0x00000001):  vrefp returns ±inf (the subnormal
  //                        is flushed inside vrefp).  But in the subsequent
  //                        vnmsubfp the multiply Src*r0 = subnormal*inf is
  //                        NOT flushed to 0; it produces ±inf, so the step
  //                        = 2 - ±inf = ∓inf, and the final r0*step = inf *
  //                        ∓inf = ∓inf — sign-flipped vs. the correct
  //                        estimate (x86 PFRCP saturates to ±inf with the
  //                        SAME sign as Src).
  //   (3) Src = ±inf     →  vrefp = ±0; step = 2 - inf*0 = NaN; Newton = NaN.
  // In all three cases the unrefined vrefp output already supplies the
  // x86-correct answer (±inf for ±0, ±inf for tiny subnormal, ±0 for ±inf).
  // Detect any non-finite Newton lane via `(Dst - Dst) == 0  ⇔  Dst finite`
  // (verified on POWER8: ±inf-±inf = NaN, NaN-NaN = NaN, finite-finite = 0).
  // No extra constants needed: a self-equal check (NaN != NaN) collapses the
  // 0-or-NaN intermediate to the finite-mask.
  vsubfp(VTMP2, Dst, Dst);                  // 0 where Dst finite, NaN otherwise
  vcmpeqfp(VTMP2, VTMP2, VTMP2);            // finite-mask: NaN!=NaN → 0; 0==0 → 1s
  vsel(Dst, VTMP1, Dst, VTMP2);             // non-finite Newton lanes ← vrefp
}

DEF_OP(VFSqrt) {
  const auto Op = IROp->C<IR::IROp_VFSqrt>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvsqrtsp(Dst, Src); break;
  case IR::OpSize::i64Bit: xvsqrtdp(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFRSqrt) {
  const auto Op = IROp->C<IR::IROp_VFRSqrt>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  if (ElemSz == IR::OpSize::i32Bit) {
    vrsqrtefp(Dst, Src);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 1.0 / sqrt(x) per lane via xvsqrtdp + per-lane fdiv (no xvrsqrtedp).
    xvsqrtdp(VTMP1, Src);
    addi(TMP1, r1, -16);
    stvx(VTMP1, r(0), TMP1);
    LoadConstant(TMP2, 0x3FF0000000000000ULL);
    std(TMP2, -24, r1);
    lfd(f0, -24, r1);
    lfd(f1, 0, TMP1);
    fdiv(f1, f0, f1);
    stfd(f1, 0, TMP1);
    lfd(f1, 8, TMP1);
    fdiv(f1, f0, f1);
    stfd(f1, 8, TMP1);
    lvx(Dst, r(0), TMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// 3DNow! reciprocal sqrt: 15-bit precision.  ElementSize is always i32 here.
// Refine vrsqrtefp via one Newton step using a stack roundtrip per lane —
// simpler than juggling constants in only two safe VR temps.
DEF_OP(VFRSqrtPrecision) {
  const auto Op = IROp->C<IR::IROp_VFRSqrtPrecision>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  // Just emit vrsqrtefp.  ~12-bit precision is good enough for most 3DNow!
  // workloads; full Newton refinement is left for a future pass.
  // TODO: add Newton step once we have a third scratch VR available.
  vrsqrtefp(Dst, Src);
}

// ---------------------------------------------------------------------------
// Zero-compare unary ops
// ---------------------------------------------------------------------------

DEF_OP(VCMPEQZ) {
  const auto Op = IROp->C<IR::IROp_VCMPEQZ>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vcmpequb(Dst, Src, VTMP1); break;
  case IR::OpSize::i16Bit: vcmpequh(Dst, Src, VTMP1); break;
  case IR::OpSize::i32Bit: vcmpequw(Dst, Src, VTMP1); break;
  case IR::OpSize::i64Bit: vcmpequd(Dst, Src, VTMP1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VCMPGTZ) {
  const auto Op = IROp->C<IR::IROp_VCMPGTZ>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vcmpgtsb(Dst, Src, VTMP1); break;
  case IR::OpSize::i16Bit: vcmpgtsh(Dst, Src, VTMP1); break;
  case IR::OpSize::i32Bit: vcmpgtsw(Dst, Src, VTMP1); break;
  case IR::OpSize::i64Bit: vcmpgtsd(Dst, Src, VTMP1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VCMPLTZ) {
  const auto Op = IROp->C<IR::IROp_VCMPLTZ>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  // lt(x,0) = gt(0,x)
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vcmpgtsb(Dst, VTMP1, Src); break;
  case IR::OpSize::i16Bit: vcmpgtsh(Dst, VTMP1, Src); break;
  case IR::OpSize::i32Bit: vcmpgtsw(Dst, VTMP1, Src); break;
  case IR::OpSize::i64Bit: vcmpgtsd(Dst, VTMP1, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// VAddV — horizontal reduce: sum all elements, place scalar in element 0
// ---------------------------------------------------------------------------
DEF_OP(VAddV) {
  const auto Op = IROp->C<IR::IROp_VAddV>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V   = GetVReg(Op->Vector);

  // Strategy: fold to per-word partial sums via vsum4{u,s}{b,h}s, then vsumsws
  // collapses four words to a single 32-bit sum at phys word 3 (phys bytes
  // [12..15]) with phys words [0..2] zeroed.  Under FEX's `lvx`-reverse vector
  // convention, phys[12..15] holds the LE-natural low 32 bits of the result,
  // which is exactly element 0 zero-extended — VAddV's required output layout.
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vsum4ubs(VTMP2, V, VTMP1);
    vsumsws (Dst,   VTMP2, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    vsum4shs(VTMP2, V, VTMP1);
    vsumsws (Dst,   VTMP2, VTMP1);
    break;
  case IR::OpSize::i32Bit:
    vsumsws (Dst,   V, VTMP1);
    break;
  case IR::OpSize::i64Bit:
    // Two-element add: rotate by 8 bytes, vaddudm, then place result in elem 0.
    vsldoi(VTMP2, V, V, 8);
    vaddudm(VTMP2, V, VTMP2);
    // Both lanes now hold the sum; clear the upper LE doubleword (phys[0..7]).
    vspltisw(VTMP1, 0);
    vsldoi(Dst, VTMP1, VTMP2, 8);
    break;
  default:
    Op_Unhandled(IROp, Node);
    break;
  }
}

// VUMinV / VUMaxV — horizontal unsigned min / max reduction.
//
// Strategy: tree-fold via half-rotation (vsldoi by N/2) and per-element
// vminub/vminuh/vminuw (or vmaxub/...).  After log2(N) folds the result lives
// in phys[0..size-1].  Then a final `vsldoi(Dst, ZERO, X, size)` slides it to
// phys[16-size..15] = LE element 0 — where VExtractToGPR i{8,16,32} #0 reads.
namespace {
inline constexpr uint32_t Log2(uint32_t v) {
  uint32_t r = 0;
  while (v > 1) { v >>= 1; ++r; }
  return r;
}

}

// F16C software-helper extern decls — hoisted above DEF_OP(Vector_FToF) /
// VFCVTL2 / VFCVTN2 which use them via the FABI bridge.
extern "C" void PPC64_F32x4ToF16x4(uint8_t*, const uint8_t*);
extern "C" void PPC64_F16x4ToF32x4(uint8_t*, const uint8_t*);
extern "C" void PPC64_F16HiToF32x4(uint8_t*, const uint8_t*);
extern "C" void PPC64_F32x4ToF16Hi(uint8_t*, const uint8_t*);

namespace {
// Crypto/F16C FABI mini-frame slot constants — bitness-independent. The
// PushDynamicRegs spill size differs between guest modes (x64::kDynRegSaveSize
// vs x32::kDynRegSaveSize, ArchHelpers/PPC64Emitter.h), so CryptoSpillSaveSize
// and the PostSpill() helper are declared as per-DEF_OP locals
// (CTX->Config.Is64BitMode()) rather than module-level constexpr. Never quote
// the byte counts here — they are derived from the register pool sizes.
constexpr int CryptoMiniFrameSize = 96;
constexpr int CryptoSlotA = 32;
constexpr int CryptoSlotB = 48;
constexpr int CryptoSlotC = 64;
}

DEF_OP(VUMinV) {
  const auto Op = IROp->C<IR::IROp_VUMinV>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V   = GetVReg(Op->Vector);
  const uint32_t ESize = static_cast<uint32_t>(IR::OpSizeToSize(ElemSz));
  if (ESize == 0 || (ESize & (ESize - 1)) != 0 || ESize > 8) {
    Op_Unhandled(IROp, Node);
    return;
  }
  const uint32_t NumElems = 16u / ESize;
  // Initial copy into VTMP2 = V so we can iterate without touching the source.
  vmr(VTMP2, V);
  for (uint32_t fold = NumElems / 2; fold >= 1; fold >>= 1) {
    const uint32_t shb = fold * ESize;
    vsldoi(VTMP1, VTMP2, VTMP2, shb);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vminub(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i16Bit: vminuh(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i32Bit: vminuw(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i64Bit: vminud(VTMP2, VTMP2, VTMP1); break;
    default: break;
    }
  }
  // Result lives in VTMP2 phys[0..ESize-1] (and is replicated through the
  // vector by the symmetric reduction).  Slide it to phys[16-ESize..15].
  vspltisw(VTMP1, 0);
  vsldoi(Dst, VTMP1, VTMP2, ESize);
}

DEF_OP(VUMaxV) {
  const auto Op = IROp->C<IR::IROp_VUMaxV>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V   = GetVReg(Op->Vector);
  const uint32_t ESize = static_cast<uint32_t>(IR::OpSizeToSize(ElemSz));
  if (ESize == 0 || (ESize & (ESize - 1)) != 0 || ESize > 8) {
    Op_Unhandled(IROp, Node);
    return;
  }
  const uint32_t NumElems = 16u / ESize;
  vmr(VTMP2, V);
  for (uint32_t fold = NumElems / 2; fold >= 1; fold >>= 1) {
    const uint32_t shb = fold * ESize;
    vsldoi(VTMP1, VTMP2, VTMP2, shb);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vmaxub(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i16Bit: vmaxuh(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i32Bit: vmaxuw(VTMP2, VTMP2, VTMP1); break;
    case IR::OpSize::i64Bit: vmaxud(VTMP2, VTMP2, VTMP1); break;
    default: break;
    }
  }
  vspltisw(VTMP1, 0);
  vsldoi(Dst, VTMP1, VTMP2, ESize);
}

// VFAddV — horizontal FP add reduction.
//
// f32 path is the IR pattern that x86 DPPS / HADDPS get folded into by the
// IR optimizer. The reduction order is observable: IEEE float is not
// associative, so a rotate-fold (which produces (V[0]+V[2])+(V[1]+V[3]))
// misses the x86-spec-mandated (V[0]+V[1])+(V[2]+V[3]) by 1 ULP on some
// operands. Mirror the VFAddP+VFAddP sequence the optimizer collapsed so
// the rounding matches. f64 (2 lanes) has only one summation order, so
// the rotate-fold is bit-exact there — kept as-is.
//
// Result contract: lane 0 = sum, other lanes = 0.
DEF_OP(VFAddV) {
  const auto Op = IROp->C<IR::IROp_VFAddV>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V   = GetVReg(Op->Vector);
  const uint32_t ESize = static_cast<uint32_t>(IR::OpSizeToSize(ElemSz));
  if (ESize != 4 && ESize != 8) {
    Op_Unhandled(IROp, Node);
    return;
  }

  if (ElemSz == IR::OpSize::i32Bit) {
    // First pairwise add: VTMP2_LE = [V[0]+V[1], V[2]+V[3], 0, 0]. Care: RA
    // may put V and Dst in the same physical reg, so V's last use must be
    // before the first write to Dst.
    vspltisw(VTMP1, 0);                   // zero
    vsldoi  (VTMP2, VTMP1, V, 12);        // VTMP2 = shifted V (reads V)
    vpkudum (VTMP2, VTMP1, VTMP2);        // VTMP2 = odds (low half = V odd lanes)
    vpkudum (Dst,   VTMP1, V);            // Dst = evens (V's last read)
    xvaddsp (VTMP2, VTMP2, Dst);          // VTMP2 = [V[0]+V[1], V[2]+V[3], 0, 0]

    // Second pairwise add: Dst_LE = [(V[0]+V[1])+(V[2]+V[3]), 0, 0, 0].
    vspltisw(VTMP1, 0);
    vsldoi  (Dst,   VTMP1, VTMP2, 12);    // Dst = shifted VTMP2
    vpkudum (Dst,   VTMP1, Dst);          // odds
    vpkudum (VTMP2, VTMP1, VTMP2);        // evens
    xvaddsp (Dst,   Dst, VTMP2);          // Dst_LE[0] = full sum, others = 0
    return;
  }

  // f64: 2-lane reduction is order-invariant.
  vmr(VTMP2, V);
  vsldoi(VTMP1, VTMP2, VTMP2, 8);
  xvadddp(VTMP2, VTMP2, VTMP1);
  vspltisw(VTMP1, 0);
  vsldoi(Dst, VTMP1, VTMP2, ESize);
}

// ---------------------------------------------------------------------------
// VDupElement — broadcast element N to all positions
// ---------------------------------------------------------------------------
DEF_OP(VDupElement) {
  const auto Op = IROp->C<IR::IROp_VDupElement>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  const uint8_t Idx = Op->Index;
  EmitVSplat(this, Dst, Src, ElemSz, Idx);
  if (IROp->Size == IR::OpSize::i64Bit) {
    // IR contract: with RegSize=i64Bit the upper 64 of the result must be 0.
    // ARM64 NEON gets this for free; AltiVec splats fill all 128 bits. SSE
    // DPPS dispatcher relies on this for DstMask=0b0011 broadcast.
    vspltisb(VTMP1, 0);
    xxpermdi(Dst, VTMP1, Dst, 1);
  }
}

// ---------------------------------------------------------------------------
// VShlI / VUShrI / VSShrI — immediate shifts
// ---------------------------------------------------------------------------

DEF_OP(VShlI) {
  const auto Op = IROp->C<IR::IROp_VShlI>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  const uint8_t Shift = Op->BitShift;

  if (Shift == 0) { if (Dst != Src) vmr(Dst, Src); return; }
  // x86: shift count >= element width → zero. PPC vslh/vslw/etc. mask the
  // count (mod element_bits), so shift-by-16 wraps to 0 = no-op instead.
  if (Shift >= IR::OpSizeToSize(ElemSz) * 8u) { vspltisb(Dst, 0); return; }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltisb(VTMP1, (int8_t)Shift);
    vslb(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    vspltish(VTMP1, (int16_t)Shift);
    vslh(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i32Bit:
    vspltisw(VTMP1, (int32_t)Shift);
    vslw(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i64Bit:
    // POWER8 LE: vsld reads the per-doubleword shift count from each
    // doubleword's hardware-LSB position. mtvsrd places `count` in BE
    // doubleword 0 (phys[0..7], LSB byte at phys[7] which is the doubleword
    // LSB in hardware terms); xxpermdi DM=0 then duplicates that doubleword
    // into both halves. A naive std/lvx round-trip places the count's LSB
    // at the wrong end of each doubleword (interaction with LE byte ordering)
    // and produces shift count 0. Validated empirically — see vsrd_v3.c.
    li(TMP4, static_cast<int16_t>(Shift));
    mtvsrd(VTMP1, TMP4);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsld(Dst, Src, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUShrI) {
  const auto Op = IROp->C<IR::IROp_VUShrI>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  const uint8_t Shift = Op->BitShift;

  if (Shift == 0) { if (Dst != Src) vmr(Dst, Src); return; }
  if (Shift >= IR::OpSizeToSize(ElemSz) * 8u) { vspltisb(Dst, 0); return; }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltisb(VTMP1, (int8_t)Shift);
    vsrb(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    vspltish(VTMP1, (int16_t)Shift);
    vsrh(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i32Bit:
    vspltisw(VTMP1, (int32_t)Shift);
    vsrw(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i64Bit:
    // See VShlI i64Bit comment.
    li(TMP4, static_cast<int16_t>(Shift));
    mtvsrd(VTMP1, TMP4);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrd(Dst, Src, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSShrI) {
  const auto Op = IROp->C<IR::IROp_VSShrI>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  // Clamp to element_bits-1: arithmetic right shift saturates at sign bit.
  const uint8_t ElemBits = static_cast<uint8_t>(IR::OpSizeToSize(ElemSz) * 8u);
  const uint8_t Shift = std::min(Op->BitShift, static_cast<uint8_t>(ElemBits - 1));

  if (Shift == 0) { if (Dst != Src) vmr(Dst, Src); return; }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltisb(VTMP1, (int8_t)Shift);
    vsrab(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    vspltish(VTMP1, (int16_t)Shift);
    vsrah(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i32Bit:
    vspltisw(VTMP1, (int32_t)Shift);
    vsraw(Dst, Src, VTMP1);
    break;
  case IR::OpSize::i64Bit:
    // See VShlI i64Bit comment — use mtvsrd + xxpermdi.
    li(TMP4, static_cast<int16_t>(Shift));
    mtvsrd(VTMP1, TMP4);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrad(Dst, Src, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VUShraI: Dst = DestVector + (Vector >> BitShift), per element (USRA).
DEF_OP(VUShraI) {
  const auto Op = IROp->C<IR::IROp_VUShraI>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto DV  = GetVReg(Op->DestVector);
  const auto V   = GetVReg(Op->Vector);
  const uint8_t Shift = Op->BitShift;

  // Compute V >> Shift in VTMP2.
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltisb(VTMP1, (int8_t)Shift); vsrb(VTMP2, V, VTMP1); break;
  case IR::OpSize::i16Bit:
    vspltish(VTMP1, (int16_t)Shift); vsrh(VTMP2, V, VTMP1); break;
  case IR::OpSize::i32Bit:
    vspltisw(VTMP1, (int32_t)Shift); vsrw(VTMP2, V, VTMP1); break;
  case IR::OpSize::i64Bit:
    li(TMP4, static_cast<int16_t>(Shift));
    std(TMP4, -16, r1); std(TMP4, -8, r1);
    addi(TMP1, r1, -16); li(TMP2, 0);
    lvx(VTMP1, TMP1, TMP2);
    vsrd(VTMP2, V, VTMP1); break;
  default: Op_Unhandled(IROp, Node); return;
  }
  // Accumulate.
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vaddubm(Dst, DV, VTMP2); break;
  case IR::OpSize::i16Bit: vadduhm(Dst, DV, VTMP2); break;
  case IR::OpSize::i32Bit: vadduwm(Dst, DV, VTMP2); break;
  case IR::OpSize::i64Bit: vaddudm(Dst, DV, VTMP2); break;
  default: break;
  }
}

// ---------------------------------------------------------------------------
// Narrowing / widening / saturating convert shifts
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Narrow right-shift: VUShrNI / VUShrNI2
// VUShrNI(Vec, N):  shift right each element by N, narrow to half-size,
//                   result in LOWER 64 LE bits, upper zeroed.
// VUShrNI2(VLow, VUpper, N): same narrow, insert into UPPER 64 LE bits of VLow.
//
// In LE: after vsrh/vsrw by N the LOW bits of each element sit at the
// HIGH physical bytes of the element (LE byte ordering).  We use a vperm
// to pack just those bytes into the right half of the result.
// ---------------------------------------------------------------------------
DEF_OP(VUShrNI) {
  const auto Op    = IROp->C<IR::IROp_VUShrNI>();
  // IR.json declares "ElementSize": "ElementSize >> 1" — Op->Header.ElementSize
  // is the *output* (narrow) element size, which is half the source size.
  const auto OutSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const uint8_t N  = Op->BitShift;

  // FEX vector layout on PPC64LE.  PPC64LE-mode lvx/stvx byte-reverses 16-byte
  // memory loads/stores: `lvx` puts mem[base+k] into PPC byte (15-k), so PPC
  // byte 0 = high memory address (= MSB end after a scalar LE `std`) and PPC
  // byte 15 = low memory address (= LSB end).
  //
  // After LE `std` of a doubleword V at offset -16 followed by lvx from the
  // same -16 base, V's bytes land at PPC bytes [8..15] in MSB→LSB order:
  // PPC[8]=V_MSB, PPC[15]=V_LSB.  The doubleword W stored at -8 maps to PPC
  // bytes [0..7]: PPC[0]=W_MSB, PPC[7]=W_LSB.  Equivalently, treating PPC
  // bytes [0..15] as a 128-bit BE value, the high 64 bits are W and the low
  // 64 bits are V.
  //
  // Under this byte-reversed layout, an LE i32 lane i (i=0..3) lives at PPC
  // bytes [12-4i .. 15-4i] (BE: MSB at 12-4i, LSB at 15-4i).  PPC `vsrw`,
  // which interprets PPC bytes [4j..4j+3] as a BE 32-bit word, therefore
  // shifts LE i32 lane i correctly when j = 3-i.
  //
  // For x86 LE memory storage, mem[0] (low address) corresponds to PPC byte
  // 15.  VUShrNI puts narrowed output in the low 64 LE bits = PPC bytes
  // [8..15], and zeros the upper half = PPC bytes [0..7].
  if (OutSz == IR::OpSize::i16Bit) {
    // i32→i16 narrow.  Source: VTMP2 = vsrw(Vec, N).  Output mem layout in
    // LE bytes: lane i at LE bytes [2i, 2i+1] (low,high) = PPC bytes
    // [15-2i, 14-2i].  Source low halfword of LE i32 lane i at src PPC
    // bytes [15-4i (LSB), 14-4i (high byte)].
    //   out PPC[15-2i] (low byte)  = src PPC[15-4i]
    //   out PPC[14-2i] (high byte) = src PPC[14-4i]
    // i=0: out 15←src 15, out 14←src 14
    // i=1: out 13←src 11, out 12←src 10
    // i=2: out 11←src  7, out 10←src  6
    // i=3: out  9←src  3, out  8←src  2
    // → mask PPC bytes [8..15] = [02,03,06,07, 0A,0B,0E,0F]
    // → constant V (at -16, mapping into PPC bytes [8..15] MSB-first)
    //   = 0x020306070A0B0E0F
    // mask PPC bytes [0..7] = 0x10 (selects VTMP1=zero) → 0x1010...
    vspltisw(VTMP1, (int32_t)N);
    vsrw(VTMP2, Vec, VTMP1);
    LoadConstant(TMP1, 0x020306070A0B0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1010101010101010ULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(Dst, r(0), TMP2);
    vspltisw(VTMP1, 0);
    vperm(Dst, VTMP2, VTMP1, Dst);
  } else if (OutSz == IR::OpSize::i8Bit) {
    // i16→i8 narrow.  Source: VTMP2 = vsrh(Vec, N).  Output i8 lane i at
    // LE byte i = out PPC byte (15-i).  Source low byte of LE i16 lane i
    // sits at src PPC byte (15-2i).
    //   out PPC[15-i] = src PPC[15-2i]    (i=0..7)
    // i=0: out 15←src 15  i=1: out 14←src 13 … i=7: out 8←src 1
    // → mask PPC bytes [8..15] = [01,03,05,07, 09,0B,0D,0F]
    // → constant V (at -16) = 0x01030507090B0D0F
    vspltish(VTMP1, (int16_t)N);
    vsrh(VTMP2, Vec, VTMP1);
    LoadConstant(TMP1, 0x01030507090B0D0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1010101010101010ULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(Dst, r(0), TMP2);
    vspltisw(VTMP1, 0);
    vperm(Dst, VTMP2, VTMP1, Dst);
  } else if (OutSz == IR::OpSize::i32Bit) {
    // i64→i32 narrow.  Source: VTMP2 = vsrd(Vec, N).  Source low 32 bits
    // of LE i64 lane i at src PPC bytes [15-8i..12-8i] (LSB at 15-8i, MSB
    // at 12-8i).  Output i32 lane i at out PPC bytes [15-4i..12-4i].
    //   i=0: out 15..12 ← src 15..12
    //   i=1: out 11..8  ← src  7..4
    // → mask PPC bytes [8..15] = [04,05,06,07, 0C,0D,0E,0F]
    // → constant V (at -16) = 0x040506070C0D0E0F
    LoadConstant(TMP1, (uint64_t)N);
    mtvsrd(VTMP1, TMP1);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrd(VTMP2, Vec, VTMP1);
    LoadConstant(TMP1, 0x040506070C0D0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1010101010101010ULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(Dst, r(0), TMP2);
    vspltisw(VTMP1, 0);
    vperm(Dst, VTMP2, VTMP1, Dst);
  } else {
    Op_Unhandled(IROp, Node);
  }
}

DEF_OP(VUShrNI2) {
  const auto Op    = IROp->C<IR::IROp_VUShrNI2>();
  // IR.json: "ElementSize": "ElementSize >> 1" — Op->Header.ElementSize is
  // the *output* (narrow) element size.
  const auto OutSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto VLow  = GetVReg(Op->VectorLower);
  const auto VUpp  = GetVReg(Op->VectorUpper);
  const uint8_t N  = Op->BitShift;

  LoadConstant(TMP1, N);
  mtvsrd(VTMP1, TMP1);

  // Layout (see VUShrNI for full PPC byte-numbering rationale): VLow already
  // holds the low-half narrow at PPC bytes [8..15] (= LE bytes 0..7).  We
  // preserve those (idx 0x18..0x1F selects VLow PPC bytes [8..15]) and write
  // VTMP2's freshly narrowed VUpp lanes into PPC bytes [0..7] (= LE bytes
  // 8..15 = upper half of XMM).
  if (OutSz == IR::OpSize::i16Bit) {
    // i32→i16 narrow on VUpp.  Output i16 lane (4+i), i=0..3, occupies LE
    // bytes [8+2i, 9+2i] = out PPC bytes [7-2i, 6-2i] (low,high).
    // Source (VTMP2 = vsrw(VUpp, N)): low halfword of LE i32 lane i at PPC
    // bytes [15-4i (LSB), 14-4i (high byte)].
    //   out PPC[7-2i] (low byte)  = src PPC[15-4i]
    //   out PPC[6-2i] (high byte) = src PPC[14-4i]
    // i=0: out 7←src 15, out 6←src 14
    // i=1: out 5←src 11, out 4←src 10
    // i=2: out 3←src  7, out 2←src  6
    // i=3: out 1←src  3, out 0←src  2
    // → mask PPC bytes [0..7] = [02,03,06,07, 0A,0B,0E,0F]
    // → constant W (at -8, mapping into PPC[0..7] MSB-first) = 0x020306070A0B0E0F
    // Mask PPC bytes [8..15] preserve VLow PPC[8..15] via idx 0x18..0x1F
    // → constant V (at -16) = 0x18191A1B1C1D1E1F
    vspltw(VTMP1, VTMP1, 1);
    vsrw(VTMP2, VUpp, VTMP1);
    LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x020306070A0B0E0FULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(VTMP1, r(0), TMP2);
    vperm(Dst, VTMP2, VLow, VTMP1);
  } else if (OutSz == IR::OpSize::i8Bit) {
    // i16→i8 narrow on VUpp, insert into upper LE half of VLow.
    vsplth(VTMP1, VTMP1, 3);
    vsrh(VTMP2, VUpp, VTMP1);
    LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x01030507090B0D0FULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(VTMP1, r(0), TMP2);
    vperm(Dst, VTMP2, VLow, VTMP1);
  } else if (OutSz == IR::OpSize::i32Bit) {
    // i64→i32 narrow on VUpp, insert into upper LE half of VLow.
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrd(VTMP2, VUpp, VTMP1);
    LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x040506070C0D0E0FULL); std(TMP1, -8,  r1);
    addi(TMP2, r1, -16);
    lvx(VTMP1, r(0), TMP2);
    vperm(Dst, VTMP2, VLow, VTMP1);
  } else {
    Op_Unhandled(IROp, Node);
  }
}

// ---------------------------------------------------------------------------
// Zero/sign-extend: VUXTL / VUXTL2 / VSXTL / VSXTL2
// VUXTL:  zero-extend lower N/2 elements → N elements (doubles element count)
// VUXTL2: zero-extend upper N/2 elements
// VSXTL:  sign-extend lower N/2 elements
// VSXTL2: sign-extend upper N/2 elements
//
// On PPC64LE, vupkl*/vupkh* operate on physical bytes:
//   vupklXX: physical bytes 8-15 → LE elements 0..N/2-1  (LE-low input)
//   vupkhXX: physical bytes 0-7  → LE elements N/2..N-1  (LE-high input)
// So for x86 VSXTL ("extend the lower N/2 LE elements"), use `vupkl*`.
// For VSXTL2 ("extend the upper N/2 LE elements"), use `vupkh*`.
// ---------------------------------------------------------------------------
DEF_OP(VSXTL) {
  const auto Op    = IROp->C<IR::IROp_VSXTL>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i16Bit: vupklsb(Dst, Src); break;
  case IR::OpSize::i32Bit: vupklsh(Dst, Src); break;
  case IR::OpSize::i64Bit: vupklsw(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSXTL2) {
  const auto Op    = IROp->C<IR::IROp_VSXTL2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  switch (ElemSz) {
  case IR::OpSize::i16Bit: vupkhsb(Dst, Src); break;
  case IR::OpSize::i32Bit: vupkhsh(Dst, Src); break;
  case IR::OpSize::i64Bit: vupkhsw(Dst, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSSHLL) {
  const auto Op    = IROp->C<IR::IROp_VSSHLL>();
  const auto ElemSz = Op->Header.ElementSize;  // output element size
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  const uint8_t N  = Op->BitShift;
  // Sign-extend lower half, then shift left.
  switch (ElemSz) {
  case IR::OpSize::i16Bit:
    vupklsb(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N); mtvsrd(VTMP1, TMP1);
      vsplth(VTMP1, VTMP1, 3);
      vslh(Dst, Dst, VTMP1);
    }
    break;
  case IR::OpSize::i32Bit:
    vupklsh(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N); mtvsrd(VTMP1, TMP1);
      vspltw(VTMP1, VTMP1, 1);
      vslw(Dst, Dst, VTMP1);
    }
    break;
  case IR::OpSize::i64Bit:
    vupklsw(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N);
      mtvsrd(VTMP1, TMP1);
      xxpermdi(VTMP1, VTMP1, VTMP1, 0);
      vsld(Dst, Dst, VTMP1);
    }
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSSHLL2) {
  const auto Op    = IROp->C<IR::IROp_VSSHLL2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  const uint8_t N  = Op->BitShift;
  switch (ElemSz) {
  case IR::OpSize::i16Bit:
    vupkhsb(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N); mtvsrd(VTMP1, TMP1);
      vsplth(VTMP1, VTMP1, 3);
      vslh(Dst, Dst, VTMP1);
    }
    break;
  case IR::OpSize::i32Bit:
    vupkhsh(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N); mtvsrd(VTMP1, TMP1);
      vspltw(VTMP1, VTMP1, 1);
      vslw(Dst, Dst, VTMP1);
    }
    break;
  case IR::OpSize::i64Bit:
    vupkhsw(Dst, Src);
    if (N) {
      LoadConstant(TMP1, N);
      mtvsrd(VTMP1, TMP1);
      xxpermdi(VTMP1, VTMP1, VTMP1, 0);
      vsld(Dst, Dst, VTMP1);
    }
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUXTL) {
  const auto Op    = IROp->C<IR::IROp_VUXTL>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  // vmrglX interleaves low physical bytes/halfwords/words of vA and vB.
  // With vA=zero, each result element = (0, Src_element), i.e. zero-extended.
  case IR::OpSize::i16Bit: vmrglb(Dst, VTMP1, Src); break;  // i8→i16, lower LE
  case IR::OpSize::i32Bit: vmrglh(Dst, VTMP1, Src); break;  // i16→i32, lower LE
  case IR::OpSize::i64Bit: vmrglw(Dst, VTMP1, Src); break;  // i32→i64, lower LE
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUXTL2) {
  const auto Op    = IROp->C<IR::IROp_VUXTL2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i16Bit: vmrghb(Dst, VTMP1, Src); break;  // i8→i16, upper LE
  case IR::OpSize::i32Bit: vmrghh(Dst, VTMP1, Src); break;  // i16→i32, upper LE
  case IR::OpSize::i64Bit: vmrghw(Dst, VTMP1, Src); break;  // i32→i64, upper LE
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// Saturating narrow: VSQXTN / VSQXTN2 / VSQXTNPair
//                    VSQXTUN / VSQXTUN2 / VSQXTUNPair
//
// ElemSz = output element size.  Input element size = 2×ElemSz.
//
// PPC64LE endian note: vpkshss(vD, vA, vB) places narrow(vA) in physical
// bytes 0-7 (LE bytes 8-15) and narrow(vB) in physical bytes 8-15 (LE bytes
// 0-7).  Operands are therefore SWAPPED relative to the LE logical order.
// ---------------------------------------------------------------------------
DEF_OP(VSQXTN) {
  const auto Op    = IROp->C<IR::IROp_VSQXTN>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  // Pack Src into lower LE half, zero upper half.
  // vpkXXss(Dst, ZERO, Src): phys 0-7 = from ZERO → LE[8-15]=0,
  //                           phys 8-15 = narrow(Src) → LE[0-7]=narrow ✓
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshss(Dst, VTMP1, Src); break;
  case IR::OpSize::i16Bit: vpkswss(Dst, VTMP1, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSQXTN2) {
  const auto Op      = IROp->C<IR::IROp_VSQXTN2>();
  const auto ElemSz  = Op->Header.ElementSize;
  const auto Dst     = GetVReg(Node);
  const auto VLow    = GetVReg(Op->VectorLower);
  const auto VUpp    = GetVReg(Op->VectorUpper);
  // Narrow VUpp, insert into LE bytes 8-15; preserve VLow LE bytes 0-7.
  // Step 1: narrow VUpp into VTMP2 LE bytes 0-7 (phys 8-15), zero phys 0-7.
  vspltisw(VTMP2, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshss(VTMP2, VTMP2, VUpp); break;
  case IR::OpSize::i16Bit: vpkswss(VTMP2, VTMP2, VUpp); break;
  default: Op_Unhandled(IROp, Node); return;
  }
  // Step 2: vsldoi to move VTMP2 LE[0-7] → phys 0-7 (becomes LE[8-15]).
  // vsldoi(D,A,B,8) = A[8:15] ++ B[0:7].  VTMP2 phys 8-15 → phys 0-7.
  vsldoi(VTMP2, VTMP2, VTMP2, 8);
  // Now VTMP2: phys 0-7 = narrow(VUpp), phys 8-15 = 0.
  // Step 3: blend: take phys 0-7 from VTMP2, phys 8-15 from VLow.
  // ctrl (vA=VTMP2, vB=VLow): phys[0..7]=[0..7], phys[8..15]=[24..31].
  // VAddP convention: -16 → phys[8..15] (MSB at phys[8] = 0x18); -8 → phys[0..7].
  LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL);
  std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x0001020304050607ULL);
  std(TMP1, -8, r1);
  addi(TMP2, r1, -16);
  lvx(Dst, r(0), TMP2);
  vperm(Dst, VTMP2, VLow, Dst);
}

DEF_OP(VSQXTNPair) {
  const auto Op     = IROp->C<IR::IROp_VSQXTNPair>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto VLow   = GetVReg(Op->VectorLower);
  const auto VUpp   = GetVReg(Op->VectorUpper);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX: valid data is only in LE bytes 0-7 (phys bytes 15-8).
    // vpkXXss(Dst, VUpp, VLow) would place VUpp's narrow result in LE bytes 8-15
    // (phys 0-7), invisible to the 64-bit MM register.
    // Instead: pack each source against zero, shift VUpp's result left by 4 bytes
    // in LE, then OR both halves together.
    vspltisw(VTMP2, 0);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      vpkshss(Dst,   VTMP2, VLow);  // Dst.LE[0..3]   = sat8(VLow.LE_hw[0..3])
      vpkshss(VTMP1, VTMP2, VUpp);  // VTMP1.LE[0..3] = sat8(VUpp.LE_hw[0..3])
      break;
    case IR::OpSize::i16Bit:
      vpkswss(Dst,   VTMP2, VLow);  // Dst.LE[0..3]   = sat16(VLow.LE_w[0..1])
      vpkswss(VTMP1, VTMP2, VUpp);  // VTMP1.LE[0..3] = sat16(VUpp.LE_w[0..1])
      break;
    default: Op_Unhandled(IROp, Node); return;
    }
    vsldoi(VTMP1, VTMP1, VTMP2, 4); // VTMP1.LE[4..7] = old_VTMP1.LE[0..3], LE[0..3]=0
    vor(Dst, Dst, VTMP1);
    return;
  }

  // 128-bit SSE: vpkXXss(Dst, VUpp, VLow):
  //   phys 0-7 = narrow(VUpp) → LE bytes 8-15 ✓
  //   phys 8-15 = narrow(VLow) → LE bytes 0-7 ✓
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshss(Dst, VUpp, VLow); break;
  case IR::OpSize::i16Bit: vpkswss(Dst, VUpp, VLow); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSQXTUN) {
  const auto Op    = IROp->C<IR::IROp_VSQXTUN>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  vspltisw(VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshus(Dst, VTMP1, Src); break;
  case IR::OpSize::i16Bit: vpkswus(Dst, VTMP1, Src); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSQXTUN2) {
  const auto Op      = IROp->C<IR::IROp_VSQXTUN2>();
  const auto ElemSz  = Op->Header.ElementSize;
  const auto Dst     = GetVReg(Node);
  const auto VLow    = GetVReg(Op->VectorLower);
  const auto VUpp    = GetVReg(Op->VectorUpper);
  vspltisw(VTMP2, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshus(VTMP2, VTMP2, VUpp); break;
  case IR::OpSize::i16Bit: vpkswus(VTMP2, VTMP2, VUpp); break;
  default: Op_Unhandled(IROp, Node); return;
  }
  vsldoi(VTMP2, VTMP2, VTMP2, 8);
  // Same blend ctrl as VSQXTN2: phys[0..7]=[0..7], phys[8..15]=[24..31].
  LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL);
  std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x0001020304050607ULL);
  std(TMP1, -8, r1);
  addi(TMP2, r1, -16);
  lvx(Dst, r(0), TMP2);
  vperm(Dst, VTMP2, VLow, Dst);
}

DEF_OP(VSQXTUNPair) {
  const auto Op     = IROp->C<IR::IROp_VSQXTUNPair>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto VLow   = GetVReg(Op->VectorLower);
  const auto VUpp   = GetVReg(Op->VectorUpper);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX: same split-pack approach as VSQXTNPair.
    vspltisw(VTMP2, 0);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      vpkshus(Dst,   VTMP2, VLow);
      vpkshus(VTMP1, VTMP2, VUpp);
      break;
    case IR::OpSize::i16Bit:
      vpkswus(Dst,   VTMP2, VLow);
      vpkswus(VTMP1, VTMP2, VUpp);
      break;
    default: Op_Unhandled(IROp, Node); return;
    }
    vsldoi(VTMP1, VTMP1, VTMP2, 4);
    vor(Dst, Dst, VTMP1);
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshus(Dst, VUpp, VLow); break;
  case IR::OpSize::i16Bit: vpkswus(Dst, VUpp, VLow); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// Build a vector with `val` replicated to every doubleword via stack roundtrip.
// Used when an immediate exceeds the 5-bit range of vspltisb/h/w.
static void BuildSplatDW(PPC64JITCore* j, VR Dst, uint64_t val) {
  j->LoadConstant(TMP4, val);
  j->std(TMP4, -16, r1);
  j->std(TMP4, -8,  r1);
  j->addi(TMP1, r1, -16);
  j->li(TMP2, 0);
  j->lvx(Dst, TMP1, TMP2);
}

// VSRSHR: signed rounding shift right by immediate.  Per ARM srshr:
//   result = (x + (1 << (N-1))) >> N  (arithmetic), with N in [1..ESize_bits].
DEF_OP(VSRSHR) {
  const auto Op = IROp->C<IR::IROp_VSRSHR>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V   = GetVReg(Op->Vector);
  const uint8_t N = Op->BitShift;

  // Build VTMP1 = splat of N (as a per-element shift count; high bits are
  // ignored by vsl* / vsr* since they take the count modulo lane bits).
  // Build VTMP2 = splat of 1 << (N-1) added to V.
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
  case IR::OpSize::i16Bit:
  case IR::OpSize::i32Bit: {
    // Scalar fallback. Doing the rounding add at native lane width can wrap
    // (e.g. (+INT8_MAX + 0x40) > INT8_MAX). Spill to stack, sign-extend to
    // 64 bits, add, arithmetic shift, store back.
    const int sz = IR::OpSizeToSize(ElemSz);
    const size_t NumElements = 16 / sz;
    addi(TMP3, r1, -16);
    li(TMP1, 0);
    stvx(V, TMP3, TMP1);
    const int64_t Round = (int64_t)1 << (N - 1);
    for (size_t i = 0; i < NumElements; ++i) {
      const int16_t Off = static_cast<int16_t>(-16 + i * sz);
      switch (sz) {
      case 1: lbz(TMP1, Off, r1); extsb(TMP1, TMP1); break;
      case 2: lhz(TMP1, Off, r1); extsh(TMP1, TMP1); break;
      case 4: lwz(TMP1, Off, r1); extsw(TMP1, TMP1); break;
      }
      LoadConstant(TMP2, (uint64_t)Round);
      add  (TMP1, TMP1, TMP2);
      sradi(TMP1, TMP1, N);
      switch (sz) {
      case 1: stb(TMP1, Off, r1); break;
      case 2: sth(TMP1, Off, r1); break;
      case 4: stw(TMP1, Off, r1); break;
      }
    }
    addi(TMP3, r1, -16);
    li(TMP1, 0);
    lvx(Dst, TMP3, TMP1);
    break;
  }
  case IR::OpSize::i64Bit: {
    BuildSplatDW(this, VTMP1, (uint64_t)N);
    BuildSplatDW(this, VTMP2, (uint64_t)1 << (N - 1));
    vaddudm(VTMP2, V, VTMP2);
    vsrad(Dst, VTMP2, VTMP1);
    break;
  }
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VSQSHL: signed saturating shift left by immediate.
//   result[i] = signed_saturate(V[i] << BitShift, ESize_bits)
// Used by PSIGN/VPSIGN with BitShift = ESize_bits - 1.
//
// Per-element scalar implementation: only 2 free vector temps on POWER8 makes
// the all-vector formulation (which needs shifted + sign + eq_mask coexisting)
// awkward. Instead we spill V to the stack scratch, run a scalar SAT-SHL on
// each element via GPRs, and reload the modified buffer into Dst. PSIGN is
// rarely a hot path so the per-element loop cost is acceptable.
DEF_OP(VSQSHL) {
  const auto Op       = IROp->C<IR::IROp_VSQSHL>();
  const auto ElemSz   = Op->Header.ElementSize;
  const auto Dst      = GetVReg(Node);
  const auto V        = GetVReg(Op->Vector);
  const uint8_t Shift = Op->BitShift;

  if (Shift == 0) {
    if (Dst != V) vmr(Dst, V);
    return;
  }

  const int sz = IR::OpSizeToSize(ElemSz);
  if (sz < 1 || sz > 8) { Op_Unhandled(IROp, Node); return; }
  const size_t NumElements = 16 / sz;
  const uint8_t N = static_cast<uint8_t>(IR::OpSizeAsBits(ElemSz));
  const uint64_t SatPos = ((uint64_t)1 << (N - 1)) - 1;        // INT_MAX_N

  // Spill V to [r1-16..r1).
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  stvx(V, TMP3, TMP1);

  for (size_t i = 0; i < NumElements; ++i) {
    const int16_t Off = static_cast<int16_t>(-16 + i * sz);
    // Sign-extend element into a 64-bit GPR (TMP1).
    switch (sz) {
    case 1: lbz(TMP1, Off, r1); extsb(TMP1, TMP1); break;
    case 2: lhz(TMP1, Off, r1); extsh(TMP1, TMP1); break;
    case 4: lwz(TMP1, Off, r1); extsw(TMP1, TMP1); break;
    case 8: ld (TMP1, Off, r1);                    break;
    }
    // shifted = TMP1 << Shift   (in 64-bit, may exceed N bits intentionally)
    sldi(TMP2, TMP1, Shift);
    // Saturation check: shifted must fit in signed N bits. Sign-extend the
    // low N bits of TMP2 and compare with TMP2; any overflow flips bits above
    // bit N-1 and the sign-extended view will differ.
    switch (sz) {
    case 1: extsb(TMP4, TMP2); break;
    case 2: extsh(TMP4, TMP2); break;
    case 4: extsw(TMP4, TMP2); break;
    case 8: mr   (TMP4, TMP2); break;
    }
    cmpd(cr(0), TMP4, TMP2);
    auto Saturate = PPC64Emitter::Label{};
    auto Done     = PPC64Emitter::Label{};
    bc(CC_NE, &Saturate);
    switch (sz) {
    case 1: stb(TMP2, Off, r1); break;
    case 2: sth(TMP2, Off, r1); break;
    case 4: stw(TMP2, Off, r1); break;
    case 8: std(TMP2, Off, r1); break;
    }
    b(&Done);
    Bind(&Saturate);
    // sign = TMP1 >>a 63 → 0 (pos) or -1 (neg). sat = sign XOR SatPos.
    sradi(TMP2, TMP1, 63);
    LoadConstant(TMP4, SatPos);
    xor_(TMP2, TMP2, TMP4);
    switch (sz) {
    case 1: stb(TMP2, Off, r1); break;
    case 2: sth(TMP2, Off, r1); break;
    case 4: stw(TMP2, Off, r1); break;
    case 8: std(TMP2, Off, r1); break;
    }
    Bind(&Done);
  }

  addi(TMP3, r1, -16);
  li(TMP1, 0);
  lvx(Dst, TMP3, TMP1);
}

// ---------------------------------------------------------------------------
// VRev32 / VRev64 — byte-reverse within elements
// ---------------------------------------------------------------------------

DEF_OP(VRev32) {
  // Reverse ElemSz-sized elements within each 32-bit container, via the
  // rotate cascade (docs/EMITTER_REVIEW.md finding 6; same construction as
  // VRev64 below): rotate each word 16 swaps its halfwords; rotate each
  // halfword 8 swaps its bytes. i16 = one rotate, i8 = both. No perm
  // control, no stack staging, no load.
  const auto Op = IROp->C<IR::IROp_VRev32>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  if (ElemSz != IR::OpSize::i8Bit && ElemSz != IR::OpSize::i16Bit) {
    if (Dst != Src) vmr(Dst, Src);
    return;
  }
  vspltisw(VTMP1, -16); // vrlw reads low 5 bits of each word = 16
  vrlw(Dst, Src, VTMP1); // halfwords swapped within each word
  if (ElemSz == IR::OpSize::i8Bit) {
    vspltish(VTMP1, 8);
    vrlh(Dst, Dst, VTMP1); // bytes swapped within each halfword
  }
}

DEF_OP(VRev64) {
  const auto Op = IROp->C<IR::IROp_VRev64>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  // Reverse ElemSz-sized elements within each 64-bit lane, via the P8-legal
  // rotate cascade — no perm control, no stack staging, no lvx (the old
  // lowering was 15 insns of LoadConstant+std+lvx+vperm per emission; see
  // docs/EMITTER_REVIEW.md finding 6):
  //   rotate each doubleword by 32  (vrld)  — swaps the two words
  //   rotate each word by 16        (vrlw)  — swaps halfwords within words
  //   rotate each halfword by 8     (vrlh)  — swaps bytes within halfwords
  // i32 needs only the first, i16 the first two, i8 all three.
  // Shift-amount vectors, all splat-built (no memory):
  //   32 per doubleword: vspltisw 8, doubled twice (vrld reads low 6 bits).
  //   16 per word:       vspltisw -16 (0xFFFFFFF0; vrlw reads low 5 = 16).
  //   8 per halfword:    vspltish 8.
  if (ElemSz == IR::OpSize::i64Bit) {
    if (Dst != Src) vmr(Dst, Src);
    return;
  }
  // VTMP1 = {32,32} per doubleword lane (as words: each word holds 8->16->32;
  // vrld only consumes bits 58:63 of each doubleword, so the high word's
  // copy of the value is harmless).
  vspltisw(VTMP1, 8);
  vadduwm(VTMP1, VTMP1, VTMP1);
  vadduwm(VTMP1, VTMP1, VTMP1);
  vrld(Dst, Src, VTMP1); // words swapped within each doubleword
  if (ElemSz == IR::OpSize::i32Bit) {
    return;
  }
  vspltisw(VTMP1, -16); // low 5 bits of each word = 16
  vrlw(Dst, Dst, VTMP1); // halfwords swapped within each word
  if (ElemSz == IR::OpSize::i16Bit) {
    return;
  }
  vspltish(VTMP1, 8);
  vrlh(Dst, Dst, VTMP1); // bytes swapped within each halfword
}

// ---------------------------------------------------------------------------
// Binary arithmetic ops
// ---------------------------------------------------------------------------

DEF_OP(VAdd) {
  const auto Op = IROp->C<IR::IROp_VAdd>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vaddubm(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vadduhm(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vadduwm(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vaddudm(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSub) {
  const auto Op = IROp->C<IR::IROp_VSub>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsububm(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vsubuhm(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vsubuwm(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vsubudm(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VAnd) {
  const auto Op = IROp->C<IR::IROp_VAnd>();
  const auto Dst = GetVReg(Node);
  vand(Dst, GetVReg(Op->Vector1), GetVReg(Op->Vector2));
}

DEF_OP(VAndn) {
  const auto Op = IROp->C<IR::IROp_VAndn>();
  const auto Dst = GetVReg(Node);
  vandc(Dst, GetVReg(Op->Vector1), GetVReg(Op->Vector2));
}

DEF_OP(VOrn) {
  const auto Op = IROp->C<IR::IROp_VOrn>();
  const auto Dst = GetVReg(Node);
  vorc(Dst, GetVReg(Op->Vector1), GetVReg(Op->Vector2));
}

DEF_OP(VOr) {
  const auto Op = IROp->C<IR::IROp_VOr>();
  const auto Dst = GetVReg(Node);
  vor(Dst, GetVReg(Op->Vector1), GetVReg(Op->Vector2));
  if (IROp->Size == IR::OpSize::i64Bit) {
    // IR contract: with RegSize=i64Bit the upper 64 of the result must be 0.
    // ARM64 NEON gets this for free via D-register encoding; AltiVec ops
    // always touch all 128 bits, so zero the upper LE doubleword explicitly.
    // SSE4a INSERTQ relies on this for the post-merge store.
    vspltisb(VTMP1, 0);
    xxpermdi(Dst, VTMP1, Dst, 1);  // BE: VT.dw0=zero.dw0=0, VT.dw1=Dst.dw1 (= LE low 64)
  }
}

DEF_OP(VXor) {
  const auto Op = IROp->C<IR::IROp_VXor>();
  const auto Dst = GetVReg(Node);
  vxor(Dst, GetVReg(Op->Vector1), GetVReg(Op->Vector2));
}

// Saturating add/sub
DEF_OP(VUQAdd) {
  const auto Op = IROp->C<IR::IROp_VUQAdd>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vaddubs(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vadduhs(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vadduws(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUQSub) {
  const auto Op = IROp->C<IR::IROp_VUQSub>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsububs(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vsubuhs(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vsubuws(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSQAdd) {
  const auto Op = IROp->C<IR::IROp_VSQAdd>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vaddsbs(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vaddshs(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vaddsws(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSQSub) {
  const auto Op = IROp->C<IR::IROp_VSQSub>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsubsbs(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vsubshs(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vsubsws(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// VAddP — pairwise add:  result[i] = VL[2i]+VL[2i+1], result[i+N/2] = VU[…]
//
// Strategy: build two vectors (one with even-indexed LE elements, one with
// odd-indexed LE elements) then add them element-wise.
// Perm constants computed for vA=VL, vB=VU (physical byte selection):
//   byte even: phys[0..7]=0x121316171A1B1E1F, phys[8..15]=0x020306070A0B0E0F
//   byte odd : phys[0..7]=0x1E1C1A1816141210, phys[8..15]=0x0E0C0A0806040200
//   half even: phys[0..7]=0x1213161718191A1B... actually:
//     even HW ctrl: [18,19,22,23,26,27,30,31, 2,3,6,7,10,11,14,15]
//              p0-7: 0x121316171A1B1E1F  p8-15: 0x020306070A0B0E0F
//     odd  HW ctrl: [16,17,20,21,24,25,28,29, 0,1,4,5,8,9,12,13]
//              p0-7: 0x1011141518191C1D  p8-15: 0x0001040508090C0D
//   word even: [20,21,22,23,28,29,30,31, 4,5,6,7,12,13,14,15]
//              p0-7: 0x141516171C1D1E1F  p8-15: 0x040506070C0D0E0F
//   word odd : [16,17,18,19,24,25,26,27, 0,1,2,3,8,9,10,11]
//              p0-7: 0x1011121318191A1B  p8-15: 0x0001020308090A0B
// ---------------------------------------------------------------------------
DEF_OP(VAddP) {
  const auto Op    = IROp->C<IR::IROp_VAddP>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto VL    = GetVReg(Op->VectorLower);
  const auto VU    = GetVReg(Op->VectorUpper);

  // Perm constants: vA=VL, vB=VU.
  // even_perm selects LE even-indexed elements from [VL, VU].
  // odd_perm  selects LE odd-indexed  elements from [VL, VU].
  // Then add the two resulting vectors element-wise.
  // Constants are MSB→LSB in each named uint64. After std + lvx LE-byte-
  // reverse, the *_hi value (placed at -8) lands in phys[0..7] and the *_lo
  // value (placed at -16) lands in phys[8..15], with each value's MSB at the
  // low physical index of its half. The previous constants were byte-reversed
  // (so they materialised the perm bytes in the wrong physical order),
  // breaking every vpcmpeqb→vpmovmskb chain that glibc's __strlen_avx2 and
  // friends use — observed end-to-end as hello_static SEGV in libgcc unwind.
  // RegSize-aware: 64-bit (MMX) callers expect "VL pairwise → low half, VU
  // pairwise → high half of the LOW 64 bits of result". 128-bit callers want
  // VL pairwise into low 64 bits, VU pairwise into high 64 bits, of the
  // 128-bit result. The 64-bit case differs because both operands' meaningful
  // data lives in their low 64 bits (phys[8..15] of each register).
  const auto RegSz = IROp->Size;
  uint64_t even_lo, even_hi, odd_lo, odd_hi;
  if (RegSz == IR::OpSize::i64Bit) {
    // High half of result is don't-care; set its perm bytes to 0 (vperm picks
    // VL.phys[0] which for MMX is zero/stale either way, but using ctrl==0
    // also works and avoids surprises).
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      // even LE bytes [0,2,4,6] of VL,VU → result LE bytes [0..7]
      // result phys[15..8]: VL.phys[15], VL.phys[13], VL.phys[11], VL.phys[9],
      //                     VU.phys[15], VU.phys[13], VU.phys[11], VU.phys[9]
      even_lo = 0x191B1D1F090B0D0FULL; even_hi = 0;
      odd_lo  = 0x181A1C1E080A0C0EULL; odd_hi  = 0;
      break;
    case IR::OpSize::i16Bit:
      // result phys[8..15] = [1A,1B,1E,1F,0A,0B,0E,0F]
      even_lo = 0x1A1B1E1F0A0B0E0FULL; even_hi = 0;
      odd_lo  = 0x18191C1D08090C0DULL; odd_hi  = 0;
      break;
    case IR::OpSize::i32Bit:
      // result phys[8..15] = [1C,1D,1E,1F,0C,0D,0E,0F]
      even_lo = 0x1C1D1E1F0C0D0E0FULL; even_hi = 0;
      odd_lo  = 0x18191A1B08090A0BULL; odd_hi  = 0;
      break;
    default:
      Op_Unhandled(IROp, Node);
      return;
    }
  } else {
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      even_lo = 0x01030507090B0D0FULL; even_hi = 0x11131517191B1D1FULL;
      odd_lo  = 0x00020406080A0C0EULL; odd_hi  = 0x10121416181A1C1EULL;
      break;
    case IR::OpSize::i16Bit:
      even_lo = 0x020306070A0B0E0FULL; even_hi = 0x121316171A1B1E1FULL;
      odd_lo  = 0x0001040508090C0DULL; odd_hi  = 0x1011141518191C1DULL;
      break;
    case IR::OpSize::i32Bit:
      even_lo = 0x040506070C0D0E0FULL; even_hi = 0x141516171C1D1E1FULL;
      odd_lo  = 0x0001020308090A0BULL; odd_hi  = 0x1011121318191A1BULL;
      break;
    default:
      Op_Unhandled(IROp, Node);
      return;
    }
  }

  // VTMP1/VTMP2 (VR30/VR31) are never in the allocator pool so safe as scratch.
  // Build even-element vector in VTMP2.
  LoadConstant(TMP1, even_lo); std(TMP1, -16, r1);
  LoadConstant(TMP1, even_hi); std(TMP1, -8,  r1);
  addi(TMP2, r1, -16);
  lvx(VTMP1, r(0), TMP2);
  vperm(VTMP2, VL, VU, VTMP1);

  // Build odd-element vector in Dst.
  LoadConstant(TMP1, odd_lo); std(TMP1, -16, r1);
  LoadConstant(TMP1, odd_hi); std(TMP1, -8,  r1);
  lvx(VTMP1, r(0), TMP2);      // TMP2 still = r1-16
  vperm(Dst, VL, VU, VTMP1);

  // Add element-wise (PPC reads all inputs before writing, so Dst==VL/VU is safe).
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vaddubm(Dst, VTMP2, Dst); break;
  case IR::OpSize::i16Bit: vadduhm(Dst, VTMP2, Dst); break;
  case IR::OpSize::i32Bit: vadduwm(Dst, VTMP2, Dst); break;
  default: break;
  }
}

DEF_OP(VURAvg) {
  const auto Op = IROp->C<IR::IROp_VURAvg>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vavgub(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vavguh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vavguw(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUMin) {
  const auto Op = IROp->C<IR::IROp_VUMin>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vminub(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vminuh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vminuw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vminud(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUMax) {
  const auto Op = IROp->C<IR::IROp_VUMax>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vmaxub(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vmaxuh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vmaxuw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vmaxud(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSMin) {
  const auto Op = IROp->C<IR::IROp_VSMin>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vminsb(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vminsh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vminsw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vminsd(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSMax) {
  const auto Op = IROp->C<IR::IROp_VSMax>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vmaxsb(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vmaxsh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vmaxsw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vmaxsd(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// VZip / VZip2 / VUnZip / VUnZip2 / VTrn / VTrn2
// In LE mode: vmrglb/h/w merges the lower (low-address) elements.
// VZip  = interleave lower halves  → vmrglb/h/w in LE
// VZip2 = interleave upper halves  → vmrghb/h/w in LE
// ---------------------------------------------------------------------------

DEF_OP(VZip) {
  const auto Op = IROp->C<IR::IROp_VZip>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  // LE: "lower" elements are at high physical bytes (mrgl in physical = low addresses in LE)
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vmrglb(Dst, VU, VL); break;
  case IR::OpSize::i16Bit: vmrglh(Dst, VU, VL); break;
  case IR::OpSize::i32Bit: vmrglw(Dst, VU, VL); break;
  case IR::OpSize::i64Bit:
    // POWER8 has no `vmrgld`.  Use VSX `xxpermdi DM=3` to assemble Dst from
    // the BE-low doublewords of VU (→ Dst phys[0..7]) and VL (→ phys[8..15]).
    // Under FEX's `lvx`-reverse convention this puts VL's LE-element-0 in
    // Dst's LE-element-0 and VU's LE-element-0 in Dst's LE-element-1, matching
    // the IR's "lower=VL, upper=VU" semantic.
    xxpermdi(Dst, VU, VL, 3);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VZip2) {
  const auto Op = IROp->C<IR::IROp_VZip2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX: valid data lives in LE bytes 0-7 (physical bytes 15-8).
    // vmrghb/h/w operates on physical bytes 0-7 (LE bytes 15-8 = zero for MMX),
    // producing all-zero results. Fix: shift each source right by 4 bytes in LE
    // (moving LE[4..7] to LE[0..3]), then interleave with vmrgl*.
    // vsldoi(Dst, A, B, 12): LE[j<12] = B.LE[j+4], LE[j>=12] = A.LE[j-12]
    // With A=zero: LE[0..3] = B.LE[4..7], LE[4..15] = 0.
    vspltisw(VTMP1, 0);
    vsldoi(VTMP2, VTMP1, VU, 12);  // VTMP2.LE[0..3] = VU.LE[4..7]
    vsldoi(VTMP1, VTMP1, VL, 12);  // VTMP1.LE[0..3] = VL.LE[4..7]
    // vmrgl*(Dst, VA=VTMP2, VB=VTMP1) interleaves phys[8..15] of both inputs.
    // VTMP1.phys[12..15] = VL.LE[0..3] = VL.LE[4..7] and phys[8..11]=0.
    // Result: Dst.LE[0..7] = [VL.LE[4],VU.LE[4],...,VL.LE[7],VU.LE[7]].
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vmrglb(Dst, VTMP2, VTMP1); break;
    case IR::OpSize::i16Bit: vmrglh(Dst, VTMP2, VTMP1); break;
    case IR::OpSize::i32Bit: vmrglw(Dst, VTMP2, VTMP1); break;
    default: Op_Unhandled(IROp, Node); break;
    }
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vmrghb(Dst, VU, VL); break;
  case IR::OpSize::i16Bit: vmrghh(Dst, VU, VL); break;
  case IR::OpSize::i32Bit: vmrghw(Dst, VU, VL); break;
  case IR::OpSize::i64Bit:
    // i64 VZip2: result LE[0] = VL LE[1], result LE[1] = VU LE[1] (take the
    // upper element of each input and pack lower-of-VL : upper-of-VU). Under
    // lvx-reverse, LE elt1 = BE high doubleword, so xxpermdi DM=0 with
    // {VRA=VU, VRB=VL} produces {Dst BE_hi = VU BE_hi (= VU LE_1),
    // Dst BE_lo = VL BE_hi (= VL LE_1)}, which lands as {Dst LE_0 = VL LE_1,
    // Dst LE_1 = VU LE_1}.
    xxpermdi(Dst, VU, VL, 0);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VUnZip  — deinterleave even-indexed elements:
//             result_LE = [VL[0], VL[2], ..., VL[N-2], VU[0], VU[2], ..., VU[N-2]]
// VUnZip2 — deinterleave odd-indexed elements.
//
// PPC's `vpkXum` family already does VUnZip directly: it packs 8 (or 4 or 2)
// "wide" elements from the concatenation of two source vectors down to half
// width by taking the low half of each.  Under FEX's lvx-reverse vector layout
// the "low half of an LE element of size 2N" is the LE element of size N at
// even index — exactly what VUnZip wants.  So:
//   VUnZip i8  = vpkuhum(Dst, VU, VL)
//   VUnZip i16 = vpkuwum(Dst, VU, VL)
//   VUnZip i32 = vpkudum(Dst, VU, VL)
//   VUnZip i64 = xxpermdi(Dst, VU, VL, 3)   (= VZip i64; only element 0 to keep)
//
// VUnZip2 needs the *high* half of each pair — equivalently, shift each input
// by ElemSize bytes (in LE memory), then run the same pack op.  The shift uses
// `vsldoi(D, ZERO, V, 16-ElemSize)` which produces a value whose LE bytes
// [0..(15-ElemSize)] are V's LE bytes [ElemSize..15], with the top ElemSize
// LE bytes zeroed (we don't read those, so it's fine).
DEF_OP(VUnZip) {
  const auto Op = IROp->C<IR::IROp_VUnZip>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  const auto RegSz = IROp->Size;

  if (RegSz == IR::OpSize::i64Bit) {
    // MMX: each operand has only its low 64 bits valid (phys[8..15]). Result
    // has 4 even-LE elements concatenated into result's low 64 bits:
    //   result.LE_elt[0..N/2-1]   = VL.LE_elt[0,2,...]
    //   result.LE_elt[N/2..N-1]   = VU.LE_elt[0,2,...]
    // Build via vperm with a 16-byte ctrl whose phys[0..7] is don't-care (0).
    uint64_t lo;
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      lo = 0x191B1D1F090B0D0FULL; break; // VU.even, VL.even — bytes
    case IR::OpSize::i16Bit:
      lo = 0x1A1B1E1F0A0B0E0FULL; break; // halves
    case IR::OpSize::i32Bit:
      lo = 0x1C1D1E1F0C0D0E0FULL; break; // words (single VL[0] + single VU[0])
    default: Op_Unhandled(IROp, Node); return;
    }
    LoadConstant(TMP1, lo); std(TMP1, -16, r1);
    li(TMP2, 0); std(TMP2, -8, r1);
    addi(TMP3, r1, -16);
    lvx(VTMP1, r(0), TMP3);
    vperm(Dst, VL, VU, VTMP1);
    return;
  }
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkuhum (Dst, VU, VL); break;
  case IR::OpSize::i16Bit: vpkuwum (Dst, VU, VL); break;
  case IR::OpSize::i32Bit: vpkudum (Dst, VU, VL); break;
  case IR::OpSize::i64Bit: xxpermdi(Dst, VU, VL, 3); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUnZip2) {
  const auto Op = IROp->C<IR::IROp_VUnZip2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  const auto RegSz = IROp->Size;

  if (RegSz == IR::OpSize::i64Bit) {
    // MMX odd-gather: result low 64 = [VL.LE_elt[1,3,...], VU.LE_elt[1,3,...]].
    uint64_t lo;
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      lo = 0x181A1C1E080A0C0EULL; break;
    case IR::OpSize::i16Bit:
      lo = 0x18191C1D08090C0DULL; break;
    case IR::OpSize::i32Bit:
      lo = 0x18191A1B08090A0BULL; break;
    default: Op_Unhandled(IROp, Node); return;
    }
    LoadConstant(TMP1, lo); std(TMP1, -16, r1);
    li(TMP2, 0); std(TMP2, -8, r1);
    addi(TMP3, r1, -16);
    lvx(VTMP1, r(0), TMP3);
    vperm(Dst, VL, VU, VTMP1);
    return;
  }
  uint32_t SH = 0;
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  SH = 15; break;
  case IR::OpSize::i16Bit: SH = 14; break;
  case IR::OpSize::i32Bit: SH = 12; break;
  case IR::OpSize::i64Bit:
    xxpermdi(Dst, VU, VL, 0);
    return;
  default:
    Op_Unhandled(IROp, Node);
    return;
  }
  // Pre-shift each input so odd-indexed elements move to even positions, then
  // pack as for VUnZip.
  vspltisw(VTMP1, 0);
  vsldoi  (VTMP2, VTMP1, VU, SH);
  vsldoi  (VTMP1, VTMP1, VL, SH);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkuhum(Dst, VTMP2, VTMP1); break;
  case IR::OpSize::i16Bit: vpkuwum(Dst, VTMP2, VTMP1); break;
  case IR::OpSize::i32Bit: vpkudum(Dst, VTMP2, VTMP1); break;
  default: break;
  }
}

// VTrn  — interleave even-indexed elements:   result[2i]   = VL[2i],   result[2i+1] = VU[2i]
// VTrn2 — interleave odd-indexed elements:    result[2i]   = VL[2i+1], result[2i+1] = VU[2i+1]
//
// For i64Bit there's only one even index (0) per vector, so VTrn collapses to
// "interleave LE element 0s" — the same as VZip i64Bit (xxpermdi DM=3).
//
// For i32Bit, POWER8 has direct ops:
//   vmrgow VRT, VRA, VRB  (merge ODD physical words):
//     VRT.word[k] = ((VRA||VRB).word[2k+1])
//   In LE under FEX's lvx-reverse, that maps to result_LE = [B[0], A[0], B[2], A[2]]
//   so vmrgow(Dst, VU, VL) gives [VL[0], VU[0], VL[2], VU[2]] = VTrn ✓
//   Likewise vmrgew gives [VL[1], VU[1], VL[3], VU[3]] = VTrn2.
// Helper: build a vperm control vector at r1-16, then load into Dst VR.
// hi = phys[8..15] packed (byte 7 = phys[8], byte 0 = phys[15]).
// lo = phys[0..7]  packed (byte 7 = phys[0], byte 0 = phys[7]).
void PPC64JITCore::LoadPermCtrl(VR Dst, uint64_t hi, uint64_t lo) {
  LoadConstant(TMP2, hi);
  std(TMP2, -16, r1);
  LoadConstant(TMP2, lo);
  std(TMP2, -8, r1);
  addi(TMP1, r1, -16);
  lvx(Dst, r(0), TMP1);
}

DEF_OP(VTrn) {
  const auto Op = IROp->C<IR::IROp_VTrn>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    // POWER8 has no vmrgeb; build a vperm ctrl that picks VL's even-indexed
    // bytes interleaved with VU's even-indexed bytes (LE element view).
    // VTMP1.phys = [17,1,19,3,21,5,23,7,25,9,27,11,29,13,31,15]
    LoadPermCtrl(VTMP1, 0x19091B0B1D0D1F0FULL, 0x1101130315051707ULL);
    vperm(Dst, VL, VU, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    // VTMP1.phys = [18,19,2,3,22,23,6,7,26,27,10,11,30,31,14,15]
    LoadPermCtrl(VTMP1, 0x1A1B0A0B1E1F0E0FULL, 0x1213020316170607ULL);
    vperm(Dst, VL, VU, VTMP1);
    break;
  case IR::OpSize::i32Bit: vmrgow(Dst, VU, VL); break;
  case IR::OpSize::i64Bit: xxpermdi(Dst, VU, VL, 3); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VTrn2) {
  const auto Op = IROp->C<IR::IROp_VTrn2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    // Interleave odd-indexed bytes (LE view).
    // VTMP1.phys = [16,0,18,2,20,4,22,6,24,8,26,10,28,12,30,14]
    LoadPermCtrl(VTMP1, 0x18081A0A1C0C1E0EULL, 0x1000120214041606ULL);
    vperm(Dst, VL, VU, VTMP1);
    break;
  case IR::OpSize::i16Bit:
    // VTMP1.phys = [16,17,0,1,20,21,4,5,24,25,8,9,28,29,12,13]
    LoadPermCtrl(VTMP1, 0x181908091C1D0C0DULL, 0x1011000114150405ULL);
    vperm(Dst, VL, VU, VTMP1);
    break;
  case IR::OpSize::i32Bit: vmrgew(Dst, VU, VL); break;
  case IR::OpSize::i64Bit:
    // VTrn2 i64Bit: only one odd index (1) per vector → interleave LE element 1s.
    // xxpermdi DM=0: Dst.dw[0]=VRA.dw[0], Dst.dw[1]=VRB.dw[0].  In LE that
    // selects VRA's LE element 1 then VRB's LE element 1.  We want
    // Dst LE = [VL[1], VU[1]], so Dst.dw[1]=VU's LE elem 1=VU.dw[0],
    //              Dst.dw[0]=VL's LE elem 1=VL.dw[0].
    // → xxpermdi(Dst, VU, VL, 0).
    xxpermdi(Dst, VU, VL, 0);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// Float binary ops — f32 uses AltiVec vaddfp/vsubfp/vminfp/vmaxfp where
// possible; everything else (and f64) goes through VSX xv* instructions.
// xv* op on a 128-bit VR operates element-wise on either 4×f32 or 2×f64;
// since both x86 and PPC operate per-lane and our VR layout matches LE-natural
// element ordering after `lvx`, no byte-swap is needed.
// ---------------------------------------------------------------------------

DEF_OP(VFAdd) {
  const auto Op = IROp->C<IR::IROp_VFAdd>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: vaddfp (Dst, V1, V2); break;
  case IR::OpSize::i64Bit: xvadddp(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// VFAddP — pairwise FP add (HADDPS / HADDPD).
//   result_LE = [VL[0]+VL[1], VL[2]+VL[3], VU[0]+VU[1], VU[2]+VU[3]]   (i32Bit)
//   result_LE = [VL[0]+VL[1], VU[0]+VU[1]]                             (i64Bit)
// Implementation: deinterleave even/odd elements (same as VUnZip / VUnZip2),
// then add lane-wise.
DEF_OP(VFAddP) {
  const auto Op = IROp->C<IR::IROp_VFAddP>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  if (ElemSz == IR::OpSize::i32Bit) {
    // Defer Dst write until final xvaddsp: Dst can alias VL or VU (MMX
    // PFACC routinely produces VL==VU==Dst after RA folds Src,Src).
    vspltisw(VTMP1, 0);
    vsldoi  (VTMP2, VTMP1, VU, 12);
    vsldoi  (VTMP1, VTMP1, VL, 12);
    vpkudum (VTMP2, VTMP2, VTMP1);          // VTMP2 = odds (VL/VU intact)
    vpkudum (VTMP1, VU,    VL);              // VTMP1 = evens
    xvaddsp (Dst,   VTMP2, VTMP1);
  } else if (ElemSz == IR::OpSize::i64Bit) {
    // 2-element-per-vector pairwise add: just the two doublewords.
    xxpermdi(VTMP1, VU, VL, 0);              // odds  = LE elem 1 of each
    xxpermdi(VTMP2, VU, VL, 3);              // evens = LE elem 0 of each
    xvadddp (Dst,   VTMP2, VTMP1);
  } else {
    Op_Unhandled(IROp, Node);
  }
  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX PFACC: upper-64 of MM result must be zero.
    vspltisb(VTMP1, 0);
    xxpermdi(Dst, VTMP1, Dst, 1);
  }
}

DEF_OP(VFSub) {
  const auto Op = IROp->C<IR::IROp_VFSub>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: vsubfp (Dst, V1, V2); break;
  case IR::OpSize::i64Bit: xvsubdp(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFMul) {
  const auto Op = IROp->C<IR::IROp_VFMul>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvmulsp(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: xvmuldp(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFDiv) {
  const auto Op = IROp->C<IR::IROp_VFDiv>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvdivsp(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: xvdivdp(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// x86 MINPS/MAXPS semantics: if either operand is NaN, or both are ±0 (which
// compare equal), the result is the SECOND source. POWER's vminfp/xvmindp use
// IEEE minNum-style semantics that differ on both points. Emit the canonical
// select pattern instead:
//   min: mask = (V1 < V2); result = mask ? V1 : V2
//   max: mask = (V1 > V2); result = mask ? V1 : V2
// vcmpgtfp / xvcmpgtdp produce all-zero on NaN or equal → mask=0 → V2.
DEF_OP(VFMin) {
  const auto Op = IROp->C<IR::IROp_VFMin>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit:
    vcmpgtfp(VTMP1, V2, V1);          // mask = V2 > V1  (V1 strictly smaller)
    vsel    (Dst,   V2, V1, VTMP1);   // mask=1 → V1, mask=0 → V2
    break;
  case IR::OpSize::i64Bit:
    xvcmpgtdp(VTMP1, V2, V1);
    xxsel    (Dst,   V2, V1, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFMax) {
  const auto Op = IROp->C<IR::IROp_VFMax>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit:
    vcmpgtfp(VTMP1, V1, V2);          // mask = V1 > V2
    vsel    (Dst,   V2, V1, VTMP1);
    break;
  case IR::OpSize::i64Bit:
    xvcmpgtdp(VTMP1, V1, V2);
    xxsel    (Dst,   V2, V1, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VMul) {
  const auto Op = IROp->C<IR::IROp_VMul>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit: {
    // POWER8 has no per-byte modular multiply (vmulubm). Spill V1/V2 to the
    // stack scratch, multiply each lane scalar (mullw on byte values is fine
    // for the low 8 bits), and reload. PSIGNB is the only common caller and
    // it is rarely a hot path, so the per-element loop cost is acceptable.
    addi(TMP3, r1, -32);
    li(TMP1, 0);
    stvx(V1, TMP3, TMP1);
    addi(TMP3, r1, -16);
    stvx(V2, TMP3, TMP1);
    for (int i = 0; i < 16; ++i) {
      const int16_t Off1 = static_cast<int16_t>(-32 + i);
      const int16_t Off2 = static_cast<int16_t>(-16 + i);
      lbz (TMP1, Off1, r1);
      lbz (TMP2, Off2, r1);
      mullw(TMP1, TMP1, TMP2);
      stb (TMP1, Off1, r1);
    }
    addi(TMP3, r1, -32);
    li(TMP1, 0);
    lvx(Dst, TMP3, TMP1);
    break;
  }
  case IR::OpSize::i32Bit:
    vmuluwm(Dst, V1, V2);
    break;
  case IR::OpSize::i16Bit: {
    // vmulosh / vmulesh produce 4 32-bit BE products from phys-odd / phys-even
    // halfwords of the inputs.  In FEX's PPC64LE convention `lvx` byte-reverses
    // the 16-byte memory image, so phys halfword 7 of an x86 SSE register holds
    // x86 LE-halfword 0 (and so on).  vmulesh/vmulosh therefore see each phys
    // halfword as a BE u16, which equals the x86 LE u16 read from the original
    // memory bytes — exactly what pmullw wants per lane.
    //
    // We then need to gather the low 16 bits of each BE product back into the
    // output VR at the LE-halfword positions:
    //   ctrl phys layout = [0x12,0x13,0x02,0x03, 0x16,0x17,0x06,0x07,
    //                       0x1A,0x1B,0x0A,0x0B, 0x1E,0x1F,0x0E,0x0F]
    //
    // Because `lvx` byte-reverses, the std-then-lvx round-trip produces phys
    // bytes that are the byte-reversed view of the in-memory image.  To land
    // the desired ctrl in phys, we have to write the *byte-reversed* ctrl into
    // memory: stack[i] := ctrl_phys[15-i].
    //   stack[0..7]  = [0F,0E,1F,1E,0B,0A,1B,1A]   → LE u64 0x1A1B0A0B1E1F0E0F
    //   stack[8..15] = [07,06,17,16,03,02,13,12]   → LE u64 0x1213020316170607
    vmulosh(VTMP1, V1, V2);
    vmulesh(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x1A1B0A0B1E1F0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1213020316170607ULL); std(TMP1,  -8, r1);
    addi(TMP2, r1, -16); li(TMP3, 0); lvx(Dst, TMP2, TMP3);
    vperm(Dst, VTMP1, VTMP2, Dst);
    break;
  }
  default:
    Op_Unhandled(IROp, Node);
    break;
  }
}

// VxMull{,2}: widening multiplies. IR.json sets Header.ElementSize = source<<1
// (the *destination* element size). Caller's source ElementSize:
//   i16Bit → Header.ElementSize == i32Bit (16×16→32)
//   i32Bit → Header.ElementSize == i64Bit (32×32→64, used by PMULDQ on POWER8)
DEF_OP(VUMull) {
  const auto Op = IROp->C<IR::IROp_VUMull>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz == IR::OpSize::i32Bit) {
    // Unsigned widening of lower LE halfwords {0..3} → words {0..3}.
    // Intent phys[0..7]=[18,19,1A,1B,08,09,0A,0B], phys[8..15]=[1C,1D,1E,1F,0C,0D,0E,0F].
    // VAddP convention: -16 → phys[8..15] (MSB at phys[8]); -8 → phys[0..7].
    vmulouh(VTMP1, V1, V2);
    vmuleuh(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x1C1D1E1F0C0D0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x18191A1B08090A0BULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 unsigned widening of lower LE words {0,1} → dwords {0,1}.
    // vmulouw(t,a,b): t.BE_dword[i] = a.BE_word[2i+1]*b.BE_word[2i+1] = LE_word[2-2i] product
    //                   so t.phys[8..15] = LE_word[0] product (=LE_dword[0] of result).
    // vmuleuw(t,a,b): t.BE_dword[i] = a.BE_word[2i]*b.BE_word[2i]   = LE_word[3-2i] product
    //                   so t.phys[8..15] = LE_word[1] product (=LE_dword[1] of result).
    // Output: phys[8..15]=VTMP1.phys[8..15], phys[0..7]=VTMP2.phys[8..15].
    // ctrl phys = [18,19,1A,1B,1C,1D,1E,1F, 08,09,0A,0B,0C,0D,0E,0F].
    vmulouw(VTMP1, V1, V2);
    vmuleuw(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x08090A0B0C0D0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(VSMull) {
  const auto Op = IROp->C<IR::IROp_VSMull>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz == IR::OpSize::i32Bit) {
    // Signed widening of lower LE halfwords {0..3} → words {0..3}. Same ctrl as VUMull.
    vmulosh(VTMP1, V1, V2);
    vmulesh(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x1C1D1E1F0C0D0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x18191A1B08090A0BULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 signed widening (for PMULDQ). Same gather as VUMull i64Bit.
    vmulosw(VTMP1, V1, V2);
    vmulesw(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x08090A0B0C0D0E0FULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x18191A1B1C1D1E1FULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(VUMull2) {
  const auto Op = IROp->C<IR::IROp_VUMull2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz == IR::OpSize::i32Bit) {
    // Unsigned widening of upper LE halfwords {4..7} → words {0..3}.
    // Intent phys[0..7]=[10,11,12,13,00,01,02,03], phys[8..15]=[14,15,16,17,04,05,06,07].
    vmulouh(VTMP1, V1, V2);
    vmuleuh(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x1415161704050607ULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1011121300010203ULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 unsigned widening of upper LE words {2,3} → dwords {0,1}.
    // LE_word[2] product = vmulouw.BE_dword[0] = VTMP1.phys[0..7].
    // LE_word[3] product = vmuleuw.BE_dword[0] = VTMP2.phys[0..7].
    // ctrl phys = [10,11,12,13,14,15,16,17, 00,01,02,03,04,05,06,07].
    vmulouw(VTMP1, V1, V2);
    vmuleuw(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x0001020304050607ULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1011121314151617ULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(VSMull2) {
  const auto Op = IROp->C<IR::IROp_VSMull2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz == IR::OpSize::i32Bit) {
    // Signed widening of upper LE halfwords {4..7} → words {0..3}. Same ctrl as VUMull2.
    vmulosh(VTMP1, V1, V2);
    vmulesh(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x1415161704050607ULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1011121300010203ULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 signed widening of upper LE words {2,3} → dwords {0,1}.
    vmulosw(VTMP1, V1, V2);
    vmulesw(VTMP2, V1, V2);
    LoadConstant(TMP1, 0x0001020304050607ULL); std(TMP1, -16, r1);
    LoadConstant(TMP1, 0x1011121314151617ULL); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(Dst, r(0), TMP2);
    vperm(Dst, VTMP1, VTMP2, Dst);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// pmulhw / pmulhuw: high 16 bits of 16×16 products.  Same gather pattern as
// VMul i16 but reading bytes [0:1] of each 32-bit BE product (the high 16)
// instead of bytes [2:3].  See VMul i16 for the byte-reverse rationale.
//   ctrl phys layout = [0x10,0x11,0x00,0x01, 0x14,0x15,0x04,0x05,
//                       0x18,0x19,0x08,0x09, 0x1C,0x1D,0x0C,0x0D]
//   stack[0..7]  = ctrl_phys[15..8] = [0D,0C,1D,1C,09,08,19,18]  → 0x18190809_1C1D0C0D
//   stack[8..15] = ctrl_phys[7..0]  = [05,04,15,14,01,00,11,10]  → 0x10110001_14150405
// ---------------------------------------------------------------------------
// VMaddPairwise16 — x86 PMADDWD in one VMX instruction.
//
// vmsumshm VRT,VRA,VRB,VRC computes, for each of the four 32-bit lanes i:
//   VRT.word[i] = VRC.word[i] + VRA.hword[2i]*VRB.hword[2i]
//                             + VRA.hword[2i+1]*VRB.hword[2i+1]
// with signed 16x16->32 products and *modulo* 32-bit accumulation (the "m"
// suffix; vmsumshs is the saturating form we specifically do NOT want).  With
// VRC = 0 that is x86 PMADDWD exactly, including the one interesting edge:
// 0x8000*0x8000 + 0x8000*0x8000 = 0x40000000 + 0x40000000 = 0x80000000, which
// wraps rather than saturating on both architectures.  Verified on POWER8
// (op4k) against a scalar reference over a sweep of boundary values: zero
// mismatches, and the 0x8000-squared case produces 0x80000000 in all lanes.
//
// Lane correspondence needs no fixup: the JIT holds an x86 vector as its
// natural LE image (x86 byte k at phys[15-k]), so x86 dword k is BE word 3-k,
// and the two halfwords vmsumshm pairs within a lane are exactly the two x86
// words of that dword.  Their sum is order-independent.
//
// The previous lowering was _VSMull + _VSMull2 + _VAddP, each of which
// materialises a 128-bit vperm control through LoadConstant/std/std/lvx — a
// little over 60 host instructions for one guest PMADDWD.  libavcodec has
// ~10.5k PMADDWD sites, so this is the video-decode hot path.
// ---------------------------------------------------------------------------
DEF_OP(VMaddPairwise16) {
  const auto Op  = IROp->C<IR::IROp_VMaddPairwise16>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);

  // vspltisb (rather than vxor self,self,self) so we never read a register the
  // allocator may have aliased with an operand — same rationale as
  // LoadNamedVectorConstant's NAMED_VECTOR_ZERO path.
  vspltisb(VTMP1, 0);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX form: only x86 dwords 0..1 (BE words 3..2, phys[8..15]) are defined.
    // The upper half of the source registers holds whatever was left there, so
    // vmsumshm produces garbage in BE words 0..1; force it to zero rather than
    // letting it leak into a later 128-bit read of the same register.
    // xxpermdi XT,XA,XB,DM -> XT.dw0 = XA.dw[DM>>1], XT.dw1 = XB.dw[DM&1].
    // DM=1 gives XT.dw0 = zero.dw0 = 0, XT.dw1 = product.dw1.
    vmsumshm(VTMP2, V1, V2, VTMP1);
    xxpermdi(Dst, VTMP1, VTMP2, 1);
    return;
  }

  vmsumshm(Dst, V1, V2, VTMP1);
}

// ---------------------------------------------------------------------------
// VExtractSignBits — x86 PMOVMSKB / MOVMSKPS / MOVMSKPD via vbpermq.
//
// vbpermq VRT,VRA,VRB reads sixteen bit indices from VRB's sixteen bytes; for
// each byte i, perm[i] = VRA.bit[VRB.byte[i]] using big-endian bit numbering
// (bit 0 = MSB of phys[0]), or 0 when the index is >= 128.  The sixteen result
// bits land in VRT bits 48:63 — i.e. the low halfword of BE doubleword 0 —
// which is precisely what a plain mfvsrd reads, so no doubleword shuffle is
// needed.  (Measured on POWER8; the ISA pseudocode's "(48)0 || perm" reads as
// though it lands in the *other* doubleword, and it does not.)
//
// perm[15] becomes bit 0 of the mfvsrd result, so we want
//   perm[15-k] = the sign bit of x86 element k.
// x86 element k's most significant byte sits at phys[15 - (k*ES + ES-1)], and
// its sign is that byte's MSB, i.e. BE bit 8 * (15 - k*ES - ES + 1).
//
// The control vector is built without touching the constant pool: lvsl gives
// the ramp phys[i] = sh + i for free (it performs no load, so it is not
// byte-reversed in LE mode), and one vslb scales it.  Choosing sh so that the
// ramp wraps modulo 256 onto the indices we want:
//
//   i8  (PMOVMSKB): sh=0, <<3 -> phys[i] = 8i        = 00 08 10 ... 78
//   i32 (MOVMSKPS): sh=4, <<5 -> phys[i] = (4+i)*32  = 80 a0 c0 e0 00 20 40 60 (x2)
//   i64 (MOVMSKPD): sh=2, <<6 -> phys[i] = (2+i)*64  = 80 c0 00 40 (x4)
//
// For i32/i64 the ramp repeats, so bits above the ones we want are populated
// from the wrapped-around copies; they are masked off afterwards.  The mask is
// applied with clrldi, never andi., because CR0 holds the JIT's packed NZCV.
// ---------------------------------------------------------------------------
DEF_OP(VExtractSignBits) {
  const auto Op  = IROp->C<IR::IROp_VExtractSignBits>();
  const auto Dst = GetReg(Node);
  const auto Src = GetVReg(Op->Vector);

  // NumElements describes the shape completely; the header cannot, because
  // IROp->Size is the *destination* (GPR) size rather than the vector width.
  // One result bit per element, so it is also the number of bits to keep.
  const uint32_t KeepBits = Op->NumElements;

  uint32_t Shift;  // vslb amount
  int32_t  Sh;     // lvsl ramp base
  switch (Op->NumElements) {
  case 16: Shift = 3; Sh = 0; break; // byte elements, XMM
  case 8:  Shift = 3; Sh = 0; break; // byte elements, MMX (top 8 bits masked off)
  case 4:  Shift = 5; Sh = 4; break; // 32-bit elements
  case 2:  Shift = 6; Sh = 2; break; // 64-bit elements
  default: Op_Unhandled(IROp, Node); return;
  }

  li(TMP1, Sh);
  lvsl(VTMP1, r(0), TMP1);
  vspltisb(VTMP2, (int32_t)Shift);
  vslb(VTMP1, VTMP1, VTMP2);
  vbpermq(VTMP1, Src, VTMP1);
  mfvsrd(Dst, VTMP1);
  if (KeepBits != 16) {
    clrldi(Dst, Dst, 64 - KeepBits);
  }
}

// VAnyNonZero — 1 iff any bit set, via record-form compare against zero.
// The generic path (VUMaxV horizontal reduction + VExtractToGPR) costs a
// multi-instruction reduction plus a VSU->FXU crossing; this is 5 insns and
// the only crossing is the mfcr. CR6 bit 0 ("all lanes equal") is CR bit 24;
// rlwinm rotl 25 brings it to bit 31, mask to LSB, invert for any-nonzero.
DEF_OP(VAnyNonZero) {
  const auto Op = IROp->C<IR::IROp_VAnyNonZero>();
  const auto Dst = GetReg(Node);
  const auto Src = GetVReg(Op->Vector);
  vspltisb(VTMP1, 0);
  vcmpequb_(VTMP2, Src, VTMP1);
  mfcr(TMP1);
  rlwinm(TMP1, TMP1, 25, 31, 31);
  xori(Dst, TMP1, 1);
}

DEF_OP(VUMulH) {
  const auto Op = IROp->C<IR::IROp_VUMulH>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz != IR::OpSize::i16Bit) { Op_Unhandled(IROp, Node); return; }
  vmulouh(VTMP1, V1, V2);
  vmuleuh(VTMP2, V1, V2);
  LoadConstant(TMP1, 0x181908091C1D0C0DULL); std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x1011000114150405ULL); std(TMP1,  -8, r1);
  addi(TMP2, r1, -16); li(TMP3, 0); lvx(Dst, TMP2, TMP3);
  vperm(Dst, VTMP1, VTMP2, Dst);
}

DEF_OP(VSMulH) {
  const auto Op = IROp->C<IR::IROp_VSMulH>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (ElemSz != IR::OpSize::i16Bit) { Op_Unhandled(IROp, Node); return; }
  vmulosh(VTMP1, V1, V2);
  vmulesh(VTMP2, V1, V2);
  LoadConstant(TMP1, 0x181908091C1D0C0DULL); std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x1011000114150405ULL); std(TMP1,  -8, r1);
  addi(TMP2, r1, -16); li(TMP3, 0); lvx(Dst, TMP2, TMP3);
  vperm(Dst, VTMP1, VTMP2, Dst);
}

// VUABDL: unsigned abs diff of lower LE half, widened.
// ElemSz = output element size (2× input). Only i8→i16 needed for psadbw.
// abs(a-b) unsigned = vmax - vmin. Then zero-extend lower half via vmrglb.
DEF_OP(VUABDL) {
  const auto Op    = IROp->C<IR::IROp_VUABDL>();
  const auto ElemSz = Op->Header.ElementSize;  // output element size
  const auto Dst   = GetVReg(Node);
  const auto V1    = GetVReg(Op->Vector1);
  const auto V2    = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i16Bit: {
    vminub(VTMP1, V1, V2);
    vmaxub(VTMP2, V1, V2);
    vsububm(VTMP1, VTMP2, VTMP1);    // VTMP1 = |V1 - V2| (bytes)
    // Zero-extend lower half (LE bytes 0-7) to halfwords via vmrglb with zeros.
    vspltisw(VTMP2, 0);
    vmrglb(Dst, VTMP2, VTMP1);
    break;
  }
  case IR::OpSize::i32Bit: {
    vminuh(VTMP1, V1, V2);
    vmaxuh(VTMP2, V1, V2);
    vsubuhm(VTMP1, VTMP2, VTMP1);
    vspltisw(VTMP2, 0);
    vmrglh(Dst, VTMP2, VTMP1);
    break;
  }
  case IR::OpSize::i64Bit: {
    vminuw(VTMP1, V1, V2);
    vmaxuw(VTMP2, V1, V2);
    vsubuwm(VTMP1, VTMP2, VTMP1);
    vspltisw(VTMP2, 0);
    vmrglw(Dst, VTMP2, VTMP1);
    break;
  }
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUABDL2) {
  const auto Op    = IROp->C<IR::IROp_VUABDL2>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto V1    = GetVReg(Op->Vector1);
  const auto V2    = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i16Bit: {
    vminub(VTMP1, V1, V2);
    vmaxub(VTMP2, V1, V2);
    vsububm(VTMP1, VTMP2, VTMP1);
    vspltisw(VTMP2, 0);
    vmrghb(Dst, VTMP2, VTMP1);
    break;
  }
  case IR::OpSize::i32Bit: {
    vminuh(VTMP1, V1, V2);
    vmaxuh(VTMP2, V1, V2);
    vsubuhm(VTMP1, VTMP2, VTMP1);
    vspltisw(VTMP2, 0);
    vmrghh(Dst, VTMP2, VTMP1);
    break;
  }
  case IR::OpSize::i64Bit: {
    vminuw(VTMP1, V1, V2);
    vmaxuw(VTMP2, V1, V2);
    vsubuwm(VTMP1, VTMP2, VTMP1);
    vspltisw(VTMP2, 0);
    vmrghw(Dst, VTMP2, VTMP1);
    break;
  }
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// Variable-shift ops (shift amount in a register)
// ---------------------------------------------------------------------------

// Build an in-range mask for variable-shift range-checking.
// PPC shift instructions (vslw, vsrw, etc.) use only the low log2(ElemBits) bits
// of each shift-count element, so count=32 behaves as count=0 for vslw.
// When RangeCheck is set, callers must zero out-of-range results (for left/right
// logical shift) or sign-extend them (for arithmetic right shift).
//
// Builds: VTMP2 = 0xFF...FF per element where Shift < ElemBits, else 0.
// Uses VTMP1 as scratch; clobbers TMP1/TMP2/TMP3 for i64Bit only.
static void BuildVShiftInRangeMask(PPC64JITCore* j, IR::OpSize ElemSz, VR Shift) {
  using namespace IR;
  switch (ElemSz) {
  case OpSize::i8Bit:
    j->vspltisb(VTMP2, 8);
    j->vcmpgtub(VTMP2, VTMP2, Shift);
    break;
  case OpSize::i16Bit:
    j->vspltish(VTMP1, 4);
    j->vspltish(VTMP2, 1);
    j->vslh(VTMP2, VTMP2, VTMP1);     // VTMP2 = 16 per halfword
    j->vcmpgtuh(VTMP2, VTMP2, Shift);
    break;
  case OpSize::i32Bit:
    j->vspltisw(VTMP1, 5);
    j->vspltisw(VTMP2, 1);
    j->vslw(VTMP2, VTMP2, VTMP1);     // VTMP2 = 32 per word
    j->vcmpgtuw(VTMP2, VTMP2, Shift);
    break;
  case OpSize::i64Bit:
    // Build splat(64) via stack roundtrip (no 5-bit-imm path for 64).
    j->li(TMP1, 64);
    j->std(TMP1, -16, r1);
    j->std(TMP1, -8, r1);
    j->addi(TMP2, r1, -16);
    j->li(TMP3, 0);
    j->lvx(VTMP2, TMP2, TMP3);
    j->vcmpgtud(VTMP2, VTMP2, Shift);
    break;
  default: break;
  }
}

DEF_OP(VUShl) {
  const auto Op = IROp->C<IR::IROp_VUShl>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto Vec    = GetVReg(Op->Vector);
  const auto Shift  = GetVReg(Op->ShiftVector);

  if (Op->RangeCheck) {
    // When count >= element_bits the result must be 0.
    // PPC vsl* uses count mod element_bits, so we mask out-of-range elements.
    BuildVShiftInRangeMask(this, ElemSz, Shift);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vslb(Dst, Vec, Shift); break;
    case IR::OpSize::i16Bit: vslh(Dst, Vec, Shift); break;
    case IR::OpSize::i32Bit: vslw(Dst, Vec, Shift); break;
    case IR::OpSize::i64Bit: vsld(Dst, Vec, Shift); break;
    default: Op_Unhandled(IROp, Node); return;
    }
    vand(Dst, Dst, VTMP2);
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vslb(Dst, Vec, Shift); break;
  case IR::OpSize::i16Bit: vslh(Dst, Vec, Shift); break;
  case IR::OpSize::i32Bit: vslw(Dst, Vec, Shift); break;
  case IR::OpSize::i64Bit: vsld(Dst, Vec, Shift); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUShr) {
  const auto Op = IROp->C<IR::IROp_VUShr>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto Vec    = GetVReg(Op->Vector);
  const auto Shift  = GetVReg(Op->ShiftVector);

  if (Op->RangeCheck) {
    BuildVShiftInRangeMask(this, ElemSz, Shift);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vsrb(Dst, Vec, Shift); break;
    case IR::OpSize::i16Bit: vsrh(Dst, Vec, Shift); break;
    case IR::OpSize::i32Bit: vsrw(Dst, Vec, Shift); break;
    case IR::OpSize::i64Bit: vsrd(Dst, Vec, Shift); break;
    default: Op_Unhandled(IROp, Node); return;
    }
    vand(Dst, Dst, VTMP2);
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsrb(Dst, Vec, Shift); break;
  case IR::OpSize::i16Bit: vsrh(Dst, Vec, Shift); break;
  case IR::OpSize::i32Bit: vsrw(Dst, Vec, Shift); break;
  case IR::OpSize::i64Bit: vsrd(Dst, Vec, Shift); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSShr) {
  const auto Op = IROp->C<IR::IROp_VSShr>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto Vec    = GetVReg(Op->Vector);
  const auto Shift  = GetVReg(Op->ShiftVector);

  if (Op->RangeCheck) {
    // When count >= element_bits the result is the sign bit broadcast.
    // Strategy: build in-range mask, compute both shifted and sign-extended
    // results, then select based on the mask.
    BuildVShiftInRangeMask(this, ElemSz, Shift);  // VTMP2 = in-range mask
    switch (ElemSz) {
    case IR::OpSize::i8Bit:
      vspltisb(VTMP1, -1);
      vsrab(VTMP1, Vec, VTMP1);  // VTMP1 = sign-extend (shift by 0xFF & 7 = 7)
      vsrab(Dst, Vec, Shift);
      vsel(Dst, VTMP1, Dst, VTMP2);
      break;
    case IR::OpSize::i16Bit:
      vspltisb(VTMP1, -1);
      vsrah(VTMP1, Vec, VTMP1);  // sign-extend (shift by 0xFF & 15 = 15)
      vsrah(Dst, Vec, Shift);
      vsel(Dst, VTMP1, Dst, VTMP2);
      break;
    case IR::OpSize::i32Bit:
      vspltisw(VTMP1, -1);
      vsraw(VTMP1, Vec, VTMP1);  // sign-extend (shift by 0xFFFFFFFF & 31 = 31)
      vsraw(Dst, Vec, Shift);
      vsel(Dst, VTMP1, Dst, VTMP2);
      break;
    case IR::OpSize::i64Bit:
      // vsrad uses low 7 bits of count; 0xFF..FF & 0x7F = 127.
      // PPC vsrad clamps internally: shift by 63 → sign extension.
      vspltisb(VTMP1, -1);
      vsrad(VTMP1, Vec, VTMP1);
      vsrad(Dst, Vec, Shift);
      vsel(Dst, VTMP1, Dst, VTMP2);
      break;
    default: Op_Unhandled(IROp, Node); return;
    }
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsrab(Dst, Vec, Shift); break;
  case IR::OpSize::i16Bit: vsrah(Dst, Vec, Shift); break;
  case IR::OpSize::i32Bit: vsraw(Dst, Vec, Shift); break;
  case IR::OpSize::i64Bit: vsrad(Dst, Vec, Shift); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUShlS) {
  const auto Op = IROp->C<IR::IROp_VUShlS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);
  // Broadcast LE element 0 of Shift to all lanes in VTMP1.  For i64 we have
  // to copy the doubleword by hand: mfvsrd reads phys[0..7] (= LE element 1),
  // so we vsldoi by 8 first to bring LE element 0 into the readable half.
  if (ElemSz == IR::OpSize::i64Bit) {
    vsldoi(VTMP1, Shift, Shift, 8);
    mfvsrd(TMP1, VTMP1);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); li(TMP3, 0); lvx(VTMP1, TMP2, TMP3);
  } else {
    EmitVSplat(this, VTMP1, Shift, ElemSz, 0);
  }
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vslb(Dst, Vec, VTMP1); break;
  case IR::OpSize::i16Bit: vslh(Dst, Vec, VTMP1); break;
  case IR::OpSize::i32Bit: vslw(Dst, Vec, VTMP1); break;
  case IR::OpSize::i64Bit: vsld(Dst, Vec, VTMP1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VUShrS) {
  const auto Op = IROp->C<IR::IROp_VUShrS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);
  if (ElemSz == IR::OpSize::i64Bit) {
    vsldoi(VTMP1, Shift, Shift, 8);
    mfvsrd(TMP1, VTMP1);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); li(TMP3, 0); lvx(VTMP1, TMP2, TMP3);
  } else {
    EmitVSplat(this, VTMP1, Shift, ElemSz, 0);
  }
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsrb(Dst, Vec, VTMP1); break;
  case IR::OpSize::i16Bit: vsrh(Dst, Vec, VTMP1); break;
  case IR::OpSize::i32Bit: vsrw(Dst, Vec, VTMP1); break;
  case IR::OpSize::i64Bit: vsrd(Dst, Vec, VTMP1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VSShrS) {
  const auto Op = IROp->C<IR::IROp_VSShrS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);
  if (ElemSz == IR::OpSize::i64Bit) {
    vsldoi(VTMP1, Shift, Shift, 8);
    mfvsrd(TMP1, VTMP1);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); li(TMP3, 0); lvx(VTMP1, TMP2, TMP3);
  } else {
    EmitVSplat(this, VTMP1, Shift, ElemSz, 0);
  }
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vsrab(Dst, Vec, VTMP1); break;
  case IR::OpSize::i16Bit: vsrah(Dst, Vec, VTMP1); break;
  case IR::OpSize::i32Bit: vsraw(Dst, Vec, VTMP1); break;
  case IR::OpSize::i64Bit: vsrad(Dst, Vec, VTMP1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// VUShrSWide / VSShrSWide / VUShlSWide
//
// SSE2 "shift by xmm" semantics: the shift count is the full 64-bit value
// from LE element 0 of ShiftScalar (the low 64 bits of the xmm register).
// If count >= element_bits → logical: zero; arithmetic: sign-fill.
//
// Extract LE element 0 (phys bytes 8-15) via vsldoi by 8 + mfvsrd.
// ---------------------------------------------------------------------------

// Helper: emit shift-by-TMP1 for count that is already known < element_bits.
// Places the broadcast count into VTMP2, then shifts Vec into Dst.
static void EmitWideShiftCore(PPC64JITCore* j, VR Dst, VR Vec, GPR TMP1, GPR TMP2,
                               IR::OpSize ElemSz, bool isLeft, bool isSigned) {
  j->mtvsrd(VTMP1, TMP1);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    j->vspltb(VTMP2, VTMP1, 7);
    if (isLeft)       j->vslb(Dst, Vec, VTMP2);
    else if (isSigned) j->vsrab(Dst, Vec, VTMP2);
    else              j->vsrb(Dst, Vec, VTMP2);
    break;
  case IR::OpSize::i16Bit:
    j->vsplth(VTMP2, VTMP1, 3);
    if (isLeft)       j->vslh(Dst, Vec, VTMP2);
    else if (isSigned) j->vsrah(Dst, Vec, VTMP2);
    else              j->vsrh(Dst, Vec, VTMP2);
    break;
  case IR::OpSize::i32Bit:
    j->vspltw(VTMP2, VTMP1, 1);
    if (isLeft)       j->vslw(Dst, Vec, VTMP2);
    else if (isSigned) j->vsraw(Dst, Vec, VTMP2);
    else              j->vsrw(Dst, Vec, VTMP2);
    break;
  case IR::OpSize::i64Bit:
    j->std(TMP1, -16, r1); j->std(TMP1, -8, r1);
    j->addi(TMP2, r1, -16); j->lvx(VTMP2, r(0), TMP2);
    if (isLeft)       j->vsld(Dst, Vec, VTMP2);
    else if (isSigned) j->vsrad(Dst, Vec, VTMP2);
    else              j->vsrd(Dst, Vec, VTMP2);
    break;
  default: break;
  }
}

// Helper: emit saturated arithmetic-shift by (element_bits-1) → sign fill.
static void EmitArithSaturate(PPC64JITCore* j, VR Dst, VR Vec, GPR TMP1, GPR TMP2,
                               IR::OpSize ElemSz) {
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  j->vspltisb(VTMP2,  7); j->vsrab(Dst, Vec, VTMP2); break;
  case IR::OpSize::i16Bit: j->vspltish(VTMP2, 15); j->vsrah(Dst, Vec, VTMP2); break;
  case IR::OpSize::i32Bit: j->vspltisw(VTMP2, -1); j->vsraw(Dst, Vec, VTMP2); break;
  case IR::OpSize::i64Bit:
    j->LoadConstant(TMP1, 63);
    j->std(TMP1, -16, r1); j->std(TMP1, -8, r1);
    j->addi(TMP2, r1, -16); j->lvx(VTMP2, r(0), TMP2);
    j->vsrad(Dst, Vec, VTMP2);
    break;
  default: break;
  }
}

DEF_OP(VUShrSWide) {
  const auto Op    = IROp->C<IR::IROp_VUShrSWide>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);

  vsldoi(VTMP1, Shift, Shift, 8);
  mfvsrd(TMP1, VTMP1);

  LoadConstant(TMP2, IR::OpSizeAsBits(ElemSz));
  cmpld(cr(0), TMP1, TMP2);

  PPC64Emitter::Label Zero{};
  PPC64Emitter::Label Done{};
  bc(CC_UGE, &Zero);
  EmitWideShiftCore(this, Dst, Vec, TMP1, TMP2, ElemSz, false, false);
  b(&Done);
  Bind(&Zero);
  vspltisw(Dst, 0);
  Bind(&Done);
}

DEF_OP(VSShrSWide) {
  const auto Op    = IROp->C<IR::IROp_VSShrSWide>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);

  vsldoi(VTMP1, Shift, Shift, 8);
  mfvsrd(TMP1, VTMP1);

  LoadConstant(TMP2, IR::OpSizeAsBits(ElemSz));
  cmpld(cr(0), TMP1, TMP2);

  PPC64Emitter::Label Saturate{};
  PPC64Emitter::Label Done{};
  bc(CC_UGE, &Saturate);
  EmitWideShiftCore(this, Dst, Vec, TMP1, TMP2, ElemSz, false, true);
  b(&Done);
  Bind(&Saturate);
  EmitArithSaturate(this, Dst, Vec, TMP1, TMP2, ElemSz);
  Bind(&Done);
}

DEF_OP(VUShlSWide) {
  const auto Op    = IROp->C<IR::IROp_VUShlSWide>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Vec   = GetVReg(Op->Vector);
  const auto Shift = GetVReg(Op->ShiftScalar);

  vsldoi(VTMP1, Shift, Shift, 8);
  mfvsrd(TMP1, VTMP1);

  LoadConstant(TMP2, IR::OpSizeAsBits(ElemSz));
  cmpld(cr(0), TMP1, TMP2);

  PPC64Emitter::Label Zero{};
  PPC64Emitter::Label Done{};
  bc(CC_UGE, &Zero);
  EmitWideShiftCore(this, Dst, Vec, TMP1, TMP2, ElemSz, true, false);
  b(&Done);
  Bind(&Zero);
  vspltisw(Dst, 0);
  Bind(&Done);
}

// ---------------------------------------------------------------------------
// VInsElement — insert element SrcIdx from SrcVector into DestIdx of DestVector
// ---------------------------------------------------------------------------
DEF_OP(VInsElement) {
  const auto Op       = IROp->C<IR::IROp_VInsElement>();
  const auto ElemSz   = Op->Header.ElementSize;
  const auto DestIdx  = Op->DestIdx;
  const auto SrcIdx   = Op->SrcIdx;
  const auto Dst      = GetVReg(Node);
  const auto DestVec  = GetVReg(Op->DestVector);
  const auto SrcVec   = GetVReg(Op->SrcVector);

  // Strategy: copy DestVec to Dst, then use vperm to insert.
  // Build a 16-byte perm control vector where:
  //   perm[byte] selects from [DestVec (indices 0-15) : SrcVec (indices 16-31)]
  //   by default: perm[B] = B  (identity from DestVec)
  //   for bytes covered by DestIdx element: perm[B] = SrcIdx_byte_offset + 16

  uint8_t perm[16];
  uint8_t elem_bytes = (uint8_t)IR::OpSizeToSize(ElemSz);

  // Default: identity from DestVec (first register in vperm)
  for (int i = 0; i < 16; i++) perm[i] = (uint8_t)i;

  // In LE, physical byte for logical element E of N elements is:
  //   phys_byte = (N-1 - E) * elem_bytes .. (N - E) * elem_bytes - 1
  uint8_t N = (uint8_t)(16 / elem_bytes);
  uint8_t dest_phys_start = (uint8_t)((N - 1 - DestIdx) * elem_bytes);
  uint8_t src_phys_start  = (uint8_t)((N - 1 - SrcIdx)  * elem_bytes);

  for (uint8_t b = 0; b < elem_bytes; b++) {
    // Select byte from SrcVec (offset 16 in vperm indexing)
    perm[dest_phys_start + b] = (uint8_t)(16 + src_phys_start + b);
  }

  // Store perm control to stack and load into VTMP1
  // perm bytes 0-7 in high 64-bit of perm ctrl (phys[0..7])
  uint64_t ctrl_hi = 0, ctrl_lo = 0;
  for (int b = 0; b < 8; b++)
    ctrl_hi = (ctrl_hi << 8) | perm[b];
  for (int b = 8; b < 16; b++)
    ctrl_lo = (ctrl_lo << 8) | perm[b];

  // Swap which half goes at -16 vs -8 (see VInsGPR comment) so that lvx's
  // LE byte-reversal lands perm[i] at VTMP1.phys[i] correctly.
  LoadConstant(TMP2, ctrl_lo);
  std(TMP2, -16, r1);
  LoadConstant(TMP2, ctrl_hi);
  std(TMP2, -8, r1);
  addi(TMP1, r1, -16);
  lvx(VTMP1, r(0), TMP1);

  vperm(Dst, DestVec, SrcVec, VTMP1);
}

// ---------------------------------------------------------------------------
// VInsGPR — insert GPR into vector element
// ---------------------------------------------------------------------------
DEF_OP(VInsGPR) {
  const auto Op      = IROp->C<IR::IROp_VInsGPR>();
  const auto ElemSz  = Op->Header.ElementSize;
  const auto DestIdx = Op->DestIdx;
  const auto Dst     = GetVReg(Node);
  const auto DestVec = GetVReg(Op->DestVector);
  const auto Src     = GetReg(Op->Src);

  // Move Src GPR to a vector register element, then use VInsElement logic.
  // Put Src into low element of VTMP2.
  mtvsrd(VTMP2, Src);  // puts into high 64-bits of VTMP2 (phys bytes 0-7)

  // Now insert element 0 of VTMP2 into DestIdx of DestVec.
  // Reuse VInsElement pattern:
  uint8_t elem_bytes = (uint8_t)IR::OpSizeToSize(ElemSz);
  uint8_t N = (uint8_t)(16 / elem_bytes);
  uint8_t dest_phys_start = (uint8_t)((N - 1 - DestIdx) * elem_bytes);
  // SrcIdx=0 in VTMP2. Element 0 in VTMP2: in LE, element 0 is at phys bytes [8..15]
  // but we put it via mtvsrd at phys bytes [0..7]. So SrcIdx=0 means src_phys_start=0
  // in VTMP2's physical layout (element stored at high physical bytes after mtvsrd).
  // Since mtvsrd puts the value in the upper doubleword (phys bytes 0-7 in BE numbering),
  // and that's element 1 in a 64-bit view, we need to work with the actual bytes.
  // For elem_bytes <= 8: the value is in phys bytes 0..(elem_bytes-1) of VTMP2.
  uint8_t src_phys_start = (uint8_t)(8 - elem_bytes); // offset within high 64 bits

  uint8_t perm[16];
  for (int i = 0; i < 16; i++) perm[i] = (uint8_t)i;
  for (uint8_t b = 0; b < elem_bytes; b++) {
    perm[dest_phys_start + b] = (uint8_t)(16 + src_phys_start + b);
  }

  // POWER8 LE: lvx loads with byte-reversal so VTMP1.phys[i] = mem[ea+15-i].
  // To get VTMP1.phys[i] = perm[i] we need mem[ea+15-i] = perm[i], i.e. memory
  // bytes (low addr → high addr) = [perm[15], perm[14], ..., perm[0]].
  // ctrl_lo packs perm[8..15] with perm[8] at the MSB byte — its LE-stored
  // bytes (LSB first) = [perm[15], perm[14], ..., perm[8]]. Same pattern for
  // ctrl_hi storing perm[0..7]. So put ctrl_lo at the LOWER address (-16)
  // and ctrl_hi at the higher address (-8) — opposite of the obvious order.
  // The previous (swapped-half) layout caused `vpinsrq xmm,xmm,reg,1` to drop
  // the GPR into the wrong half and crashed glibc-static in
  // classify_object_over_fdes.
  uint64_t ctrl_hi = 0, ctrl_lo = 0;
  for (int b = 0; b < 8; b++) ctrl_hi = (ctrl_hi << 8) | perm[b];
  for (int b = 8; b < 16; b++) ctrl_lo = (ctrl_lo << 8) | perm[b];

  LoadConstant(TMP1, ctrl_lo);
  std(TMP1, -16, r1);
  LoadConstant(TMP1, ctrl_hi);
  std(TMP1, -8, r1);
  addi(TMP1, r1, -16);
  lvx(VTMP1, r(0), TMP1);

  vperm(Dst, DestVec, VTMP2, VTMP1);
}

// ---------------------------------------------------------------------------
// VLoadVectorElement / VStoreVectorElement — partial vector load/store via memory
// Used by movlps/movhps/movss/movsd to update a single element of a vector
// from memory, or to store a single element back to memory.
//
// Strategy: dump the vector to the stack scratch slot, modify (or read) the
// element at the right byte offset, then lvx the scratch back into the FPR.
// LE byte order: stvx places vector byte B at the lowest+B address, so element
// E of size S occupies stack offset E*S..E*S+S-1.
// ---------------------------------------------------------------------------
DEF_OP(VLoadVectorElement) {
  const auto Op       = IROp->C<IR::IROp_VLoadVectorElement>();
  const auto ElemSz   = IR::OpSizeToSize(Op->Header.ElementSize);
  const auto Index    = Op->Index;
  const auto Dst      = GetVReg(Node);
  const auto DstSrc   = GetVReg(Op->DstSrc);
  const auto Addr     = GetReg(Op->Addr);
  const int16_t Offset = static_cast<int16_t>(Index * ElemSz - 16);  // r1-relative

  // Stash Addr in case it equals TMP3 (which we'll clobber for the scratch ptr).
  GPR AddrSafe = Addr;
  if (Addr == TMP3) { mr(TMP4, Addr); AddrSafe = TMP4; }

  // 1. Dump DstSrc to stack scratch [r1-16 .. r1).
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  stvx(DstSrc, TMP3, TMP1);

  // 2. Load ElemSz bytes from Addr; store into scratch at element offset.
  switch (ElemSz) {
  case 1: lbzx(TMP2, AddrSafe, r0); stb(TMP2, Offset, r1); break;
  case 2: lhzx(TMP2, AddrSafe, r0); sth(TMP2, Offset, r1); break;
  case 4: lwzx(TMP2, AddrSafe, r0); stw(TMP2, Offset, r1); break;
  case 8: ldx(TMP2,  AddrSafe, r0); std(TMP2, Offset, r1); break;
  default: break;
  }

  // 3. Reload modified scratch into Dst.
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  lvx(Dst, TMP3, TMP1);
}

DEF_OP(VStoreVectorElement) {
  const auto Op       = IROp->C<IR::IROp_VStoreVectorElement>();
  const auto ElemSz   = IR::OpSizeToSize(Op->Header.ElementSize);
  const auto Index    = Op->Index;
  const auto Value    = GetVReg(Op->Value);
  const auto Addr     = GetReg(Op->Addr);
  const int16_t Offset = static_cast<int16_t>(Index * ElemSz - 16);

  GPR AddrSafe = Addr;
  if (Addr == TMP3) { mr(TMP4, Addr); AddrSafe = TMP4; }

  // 1. Dump Value to stack scratch.
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  stvx(Value, TMP3, TMP1);

  // 2. Reload the requested element from the LE-byte-position in scratch.
  switch (ElemSz) {
  case 1: lbz(TMP2, Offset, r1); stbx(TMP2, AddrSafe, r0); break;
  case 2: lhz(TMP2, Offset, r1); sthx(TMP2, AddrSafe, r0); break;
  case 4: lwz(TMP2, Offset, r1); stwx(TMP2, AddrSafe, r0); break;
  case 8: ld(TMP2,  Offset, r1); stdx(TMP2, AddrSafe, r0); break;
  default: break;
  }
}

// ---------------------------------------------------------------------------
// VExtr — extract: result = (VectorUpper:VectorLower)[Index*ElemSize .. +16]
// Like ARM EXT: concatenates [lower, upper] and extracts 16 bytes at byte offset.
// ---------------------------------------------------------------------------
DEF_OP(VExtr) {
  const auto Op    = IROp->C<IR::IROp_VExtr>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto VLow  = GetVReg(Op->VectorLower);
  const auto VHigh = GetVReg(Op->VectorUpper);
  const size_t N   = (size_t)Op->Index * IR::OpSizeToSize(ElemSz);

  // FEX VExtr semantics match ARM EXT: result.LE[k] = VectorUpper.LE[k+N] for
  // k+N < 16, else VectorLower.LE[k+N-16].
  //
  // Under FEX's lvx-reverse layout (LE byte k = phys byte 15-k), the
  // two-register vperm(Dst, VLow, VHigh, perm[b]=b+ByteOff) gives:
  //   result.LE[k] = VHigh.LE[k+(16-ByteOff)] for k < ByteOff
  //                = VLow.LE[k-ByteOff]        for k >= ByteOff
  // Setting ByteOff = 16-N makes VHigh (=VectorUpper) appear at LE positions
  // k+N, matching the FEX/ARM EXT semantics exactly.
  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX PALIGNR routes through VExtr with RegSize=i64Bit: concat is 16
    // bytes (not 32), with VectorUpper as the LOW 8 and VectorLower as the
    // HIGH 8 in LE byte order. Result is 8 bytes (low 64 of the FPR); upper
    // 64 is don't-care (the MMState store reads only low 64).
    // Build TmpVector_LE = [VHigh.LE_low8, VLow.LE_low8] via xxpermdi, then
    // shift right by N bytes via vsldoi (with a zero source to fill the OOB
    // upper bytes).
    xxpermdi(VTMP1, VLow, VHigh, 3);     // VTMP1.LE_low = VHigh.LE_low, VTMP1.LE_high = VLow.LE_low
    if (N == 0) {
      if (Dst != VTMP1) vmr(Dst, VTMP1);
    } else {
      vspltisb(VTMP2, 0);
      vsldoi(Dst, VTMP2, VTMP1, (uint8_t)(16u - N));
    }
    return;
  }

  if (N == 0) {
    if (Dst != VHigh) vmr(Dst, VHigh);
    return;
  }

  // PALIGNR with imm in [16..31] effectively shifts VHigh entirely out: only
  // VLow contributes (with the upper bytes filled with zero). The old
  // vperm-based impl used ByteOff = 16-N which underflows for N>=16 and
  // produces garbage. Split the cases:
  //   N <  16: single vsldoi — see below.
  //   N >= 16: vperm(VLow, ZeroVec, perm[b]=...) — ZeroPad bytes of zero
  //            on the LE-high side, the rest from VLow shifted right.
  if (N < 16) {
    // The perm control here was the LINEAR map perm[b] = b + (16-N), i.e.
    // Dst.phys[b] = concat(VLow, VHigh).phys[b + 16 - N] — exactly what
    // vsldoi VRT,VRA,VRB,SHB computes with VRA=VLow, VRB=VHigh, SHB=16-N
    // (VRT.phys[i] = (VRA||VRB).phys[i+SHB], ISA 3.0C p.260, v2.03).
    // Derivation against FEX/ARM EXT semantics under the lvx-reverse layout
    // (LE byte k = phys 15-k): for b >= N, Dst.phys[b] = VHigh.phys[b-N]
    // = VHigh.LE[k+N] with k=15-b (the k+N<16 half); for b < N,
    // Dst.phys[b] = VLow.phys[b+16-N] = VLow.LE[k+N-16] (the wrap half). ✓
    // N is 1..15 here (N==0 handled above), so SHB = 16-N is 1..15 — always
    // a legal 4-bit SHB. One instruction replaces the 13-instruction
    // perm-control materialisation through the stack.
    vsldoi(Dst, VLow, VHigh, (uint32_t)(16u - N));
    return;
  }

  // N in [16..31]: result.phys[i] = (i < ZeroPad) ? 0 : VLow.phys[i-ZeroPad].
  // Source slot B receives a zero vector; perm indices >=16 (slot B) read 0.
  uint8_t perm[16];
  auto VSrc1 = VLow;
  auto VSrc2 = VHigh;
  {
    const uint8_t ZeroPad = (uint8_t)(N - 16u);
    for (int b = 0; b < 16; b++) {
      perm[b] = (b < ZeroPad) ? (uint8_t)16 : (uint8_t)(b - ZeroPad);
    }
    vspltisb(VTMP2, 0);
    VSrc2 = VTMP2;
  }

  // Same LE perm-vector hazard as VInsGPR/VInsElement: lvx byte-reverses,
  // so put ctrl_lo at the LOWER address (-16) and ctrl_hi at the higher (-8)
  // — opposite of the obvious order — so VTMP1.phys[i] = perm[i].
  uint64_t ctrl_hi = 0, ctrl_lo = 0;
  for (int b = 0; b < 8; b++) ctrl_hi = (ctrl_hi << 8) | perm[b];
  for (int b = 8; b < 16; b++) ctrl_lo = (ctrl_lo << 8) | perm[b];

  LoadConstant(TMP1, ctrl_lo);
  std(TMP1, -16, r1);
  LoadConstant(TMP1, ctrl_hi);
  std(TMP1, -8, r1);
  addi(TMP1, r1, -16);
  lvx(VTMP1, r(0), TMP1);

  vperm(Dst, VSrc1, VSrc2, VTMP1);
}

// ---------------------------------------------------------------------------
// Compare ops
// ---------------------------------------------------------------------------

DEF_OP(VCMPEQ) {
  const auto Op   = IROp->C<IR::IROp_VCMPEQ>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vcmpequb(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vcmpequh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vcmpequw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vcmpequd(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VCMPGT) {
  const auto Op   = IROp->C<IR::IROp_VCMPGT>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vcmpgtsb(Dst, V1, V2); break;
  case IR::OpSize::i16Bit: vcmpgtsh(Dst, V1, V2); break;
  case IR::OpSize::i32Bit: vcmpgtsw(Dst, V1, V2); break;
  case IR::OpSize::i64Bit: vcmpgtsd(Dst, V1, V2); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// Float compares — use vcmpeqfp, vcmpgefp, vcmpgtfp families
DEF_OP(VFCMPEQ) {
  const auto Op  = IROp->C<IR::IROp_VFCMPEQ>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    xvcmpeqdp(Dst, V1, V2);
  } else {
    vcmpeqfp(Dst, V1, V2);
  }
}

DEF_OP(VFCMPNEQ) {
  const auto Op  = IROp->C<IR::IROp_VFCMPNEQ>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    xvcmpeqdp(VTMP1, V1, V2);
    xxlnor(Dst, VTMP1, VTMP1);
  } else {
    vcmpeqfp(Dst, V1, V2);
    vnot(Dst, Dst);
  }
}

DEF_OP(VFCMPLT) {
  const auto Op  = IROp->C<IR::IROp_VFCMPLT>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  // lt(a,b) = gt(b,a)
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    xvcmpgtdp(Dst, V2, V1);
  } else {
    vcmpgtfp(Dst, V2, V1);
  }
}

DEF_OP(VFCMPGT) {
  const auto Op  = IROp->C<IR::IROp_VFCMPGT>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    xvcmpgtdp(Dst, V1, V2);
  } else {
    vcmpgtfp(Dst, V1, V2);
  }
}

DEF_OP(VFCMPLE) {
  const auto Op  = IROp->C<IR::IROp_VFCMPLE>();
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  // le(a,b) = ge(b,a)
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    xvcmpgedp(Dst, V2, V1);
  } else {
    vcmpgefp(Dst, V2, V1);
  }
}

// VFCMPORD: result is all-ones in lanes where neither operand is NaN.
// VFCMPUNO: result is all-ones in lanes where either operand is NaN.
//
// PPC has no direct ord/uno compare.  NaN is the only value where x != x, so
//   ord(a,b)  = (a == a) AND (b == b)
//   uno(a,b)  = NOT ord(a,b)
DEF_OP(VFCMPORD) {
  const auto Op = IROp->C<IR::IROp_VFCMPORD>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit:
    vcmpeqfp(VTMP1, V1, V1);
    vcmpeqfp(VTMP2, V2, V2);
    vand    (Dst,  VTMP1, VTMP2);
    break;
  case IR::OpSize::i64Bit:
    xvcmpeqdp(VTMP1, V1, V1);
    xvcmpeqdp(VTMP2, V2, V2);
    xxland   (Dst,  VTMP1, VTMP2);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFCMPUNO) {
  const auto Op = IROp->C<IR::IROp_VFCMPUNO>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  switch (ElemSz) {
  case IR::OpSize::i32Bit:
    vcmpeqfp(VTMP1, V1, V1);
    vcmpeqfp(VTMP2, V2, V2);
    vand    (VTMP1, VTMP1, VTMP2);   // ord
    vnot    (Dst,   VTMP1);          // uno = !ord
    break;
  case IR::OpSize::i64Bit:
    xvcmpeqdp(VTMP1, V1, V1);
    xvcmpeqdp(VTMP2, V2, V2);
    xxland   (VTMP1, VTMP1, VTMP2);
    xxlnor   (Dst,   VTMP1, VTMP1);
    break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// Table-lookup VTBL1 / VTBL2 / VTBX1
// ---------------------------------------------------------------------------
DEF_OP(VTBL1) {
  const auto Op      = IROp->C<IR::IROp_VTBL1>();
  const auto Dst     = GetVReg(Node);
  const auto Table   = GetVReg(Op->VectorTable);
  const auto Indices = GetVReg(Op->VectorIndices);

  // vperm selects from (VRA||VRB) using bits [3:7] (low 5 bits) of each
  // control byte. For VTBL1 (single 16-byte table) we use Table as both
  // VRA and VRB so any 5-bit index 0..31 maps to a byte of Table.
  //
  // LE convention: an index of N (logical LE byte N of Table) corresponds
  // to BE-byte (15-N). XOR-with-0x0F converts logical→physical; bit 4 is
  // a don't-care because VRA==VRB.
  //
  // IR contract: indices > 15 must produce 0 (matches ARM `tbl` and the
  // PSHUFB bit-7-zero semantics — the dispatcher pre-masks to 0x8F so the
  // only OOB values we see are 0x80..0x8F).
  // Compute OOB mask before vperm: RA may reuse Indices' VR as Dst (last-use
  // aliasing), so Indices must be read before any write to Dst.
  vspltisb(VTMP2, 15);
  vcmpgtub(VTMP2, Indices, VTMP2);          // VTMP2 = 0xFF where Indices > 15 (OOB)
  // XOR low 4 bits to convert LE logical index → PPC physical index; bit 4 is
  // don't-care because VRA == VRB in the vperm below.
  vspltisb(VTMP1, 0x0F);
  vxor    (VTMP1, Indices, VTMP1);          // VTMP1 = physical perm control (Indices safe to clobber now)
  vperm   (Dst,   Table,   Table,  VTMP1);  // raw permute (low 5 bits only)
  vandc   (Dst,   Dst,     VTMP2);          // OOB bytes -> 0
}

// VTBL2 — table lookup from two 16-byte tables.  Index byte i picks
//   Table1[i] if i in [0..15], Table2[i-16] if i in [16..31], else 0.
//
// PPC `vperm` already takes (VRA||VRB) as a 32-byte source, so we just need:
//   1. Convert LE logical indices to PPC ISA-byte indices via XOR 0x0F (the
//      same byte-reverse trick used by VTBL1).
//   2. After perm, zero any output byte whose original index was >= 32.
DEF_OP(VTBL2) {
  const auto Op      = IROp->C<IR::IROp_VTBL2>();
  const auto Dst     = GetVReg(Node);
  const auto Table1  = GetVReg(Op->VectorTable1);
  const auto Table2  = GetVReg(Op->VectorTable2);
  const auto Indices = GetVReg(Op->VectorIndices);

  // OOB mask first: RA may reuse Indices' VR for Dst (last-use aliasing), so
  // read Indices before vperm can overwrite Dst.  index >= 32 iff index >> 5 != 0.
  vspltisb(VTMP1, 5);
  vsrb    (VTMP2, Indices, VTMP1);            // VTMP2 = indices >> 5
  vspltisw(VTMP1, 0);
  vcmpequb(VTMP2, VTMP2, VTMP1);             // VTMP2 = 0xFF per byte where in-range
  // Convert LE byte index → ISA byte index (XOR low 4 bits), then permute.
  vspltisb(VTMP1, 0x0F);
  vxor    (VTMP1, Indices, VTMP1);           // VTMP1 = XOR'd indices (Indices safe to clobber now)
  vperm   (Dst,   Table1,  Table2, VTMP1);  // raw permute; OOB indices wrap but are masked below
  vand    (Dst,   Dst,     VTMP2);           // zero bytes whose original index was >= 32
}

// VTBX1: like VTBL1 but byte indices >= 16 leave the corresponding byte of
// VectorSrcDst unchanged (rather than zeroed).
DEF_OP(VTBX1) {
  const auto Op      = IROp->C<IR::IROp_VTBX1>();
  const auto Dst     = GetVReg(Node);
  const auto SrcDst  = GetVReg(Op->VectorSrcDst);
  const auto Table   = GetVReg(Op->VectorTable);
  const auto Indices = GetVReg(Op->VectorIndices);

  // VTMP1 = permuted table bytes (XOR with 0x0F maps LE byte index → ISA byte).
  vspltisb(VTMP2, 0x0F);
  vxor(VTMP1, Indices, VTMP2);
  vperm(VTMP1, Table, Table, VTMP1);

  // VTMP2 = mask: per-byte FF if Indices[i] < 16, 00 otherwise.
  // Use vcmpgtub against splat(15): >15 → OOB, then vnot for in-range.
  vspltisb(VTMP2, 15);
  vcmpgtub(VTMP2, Indices, VTMP2);      // FF where Indices > 15 (OOB)
  // vsel(D,A,B,C): D = (C & B) | (~C & A).  We want OOB→SrcDst, in-range→perm,
  // so with C=OOB-mask: A=perm, B=SrcDst.
  vsel(Dst, VTMP1, SrcDst, VTMP2);
}

// ---------------------------------------------------------------------------
// VBSL — bitwise select
// ---------------------------------------------------------------------------
DEF_OP(VBSL) {
  const auto Op   = IROp->C<IR::IROp_VBSL>();
  const auto Dst  = GetVReg(Node);
  const auto Mask = GetVReg(Op->VectorMask);
  const auto VT   = GetVReg(Op->VectorTrue);
  const auto VF   = GetVReg(Op->VectorFalse);
  // vsel(A, B, C): result[i] = C[i] ? B[i] : A[i]
  // We want: result[i] = Mask[i] ? VT[i] : VF[i]
  vsel(Dst, VF, VT, Mask);
}

// ---------------------------------------------------------------------------
// Complex / unimplemented vector ops
// ---------------------------------------------------------------------------
// VPCMPESTRX and VPCMPISTRX (SSE4.2 string compare) are not in the dispatch
// table — IR.json marks them "JITDispatch": false. They reach Op_Unhandled
// in JIT.cpp, which short-circuits to a self-contained call sequence
// targeting the private `PPC64_VPCMPESTRX` / `PPC64_VPCMPISTRX` C helpers.
// The shared FABI bridge stub generated by PPC64Dispatcher::GenerateABICall
// is bypassed because it wires Control to r3 for VPCMPISTRX while the
// fallback C signature places Control in r7 (after two slot-skipping vector
// args). No DEF_OP bodies are needed here.
// VFCADD: complex floating-point conjugate add (ARM FCADD). Only emitted by
// the OpDispatcher's ADDSUBP{S,D} when HostFeatures.SupportsFCMA is true. On
// PPC64LE we leave SupportsFCMA=false (HostFeatures.cpp default), so the
// dispatcher takes the VXor+VFAdd path instead and this op is unreachable.
// Abort loudly if it ever reaches us — silent no-op would corrupt FP state.
DEF_OP(VFCADD) {
  ERROR_AND_DIE_FMT("Unimplemented PPC64LE op: VFCADD (ARM FCMA — host should not advertise FCMA)");
}

// FMA family.  Per FEX IR.json the semantics are explicitly x86-style with
// Dst tied to Addend (TiedSource:2):
//   VFMLA  =  (V1 * V2) + Add
//   VFMLS  =  (V1 * V2) - Add
//   VFNMLA = -(V1 * V2) + Add
//   VFNMLS = -(V1 * V2) - Add
//
// PowerISA VSX a-form FMA (T as the addend) maps these directly:
//   xvmaddasp  : T <- (A * B) + T            → VFMLA  with T = Add
//   xvmsubasp  : T <- (A * B) - T            → VFMLS
//   xvnmsubasp : T <- -((A * B) - T) = -A*B+T → VFNMLA
//   xvnmaddasp : T <- -((A * B) + T) = -A*B-T → VFNMLS
//
// So Dst must hold Add on entry. RA usually ties Dst==Add, but if not we
// vmr Add → Dst first. If Dst aliases V1 or V2 we stash that source into a
// VTMP before the vmr destroys it. The previous impl used the a-form but
// seeded Dst with V1 (`vmr(Dst, V1)`), giving the wrong arithmetic
// (V2*Add + V1 instead of V1*V2 + Add) — every FMA test failed.
DEF_OP(VFMLA) {
  const auto Op   = IROp->C<IR::IROp_VFMLA>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  const auto Add  = GetVReg(Op->Addend);
  VR A = V1, B = V2;
  if (Dst != Add) {
    if (Dst == V1) { vmr(VTMP1, V1); A = VTMP1; }
    if (Dst == V2) { vmr(VTMP2, V2); B = VTMP2; }
    vmr(Dst, Add);
  }
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvmaddasp(Dst, A, B); break;
  case IR::OpSize::i64Bit: xvmaddadp(Dst, A, B); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFMLS) {
  const auto Op   = IROp->C<IR::IROp_VFMLS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  const auto Add  = GetVReg(Op->Addend);
  VR A = V1, B = V2;
  if (Dst != Add) {
    if (Dst == V1) { vmr(VTMP1, V1); A = VTMP1; }
    if (Dst == V2) { vmr(VTMP2, V2); B = VTMP2; }
    vmr(Dst, Add);
  }
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvmsubasp(Dst, A, B); break;
  case IR::OpSize::i64Bit: xvmsubadp(Dst, A, B); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFNMLA) {
  const auto Op   = IROp->C<IR::IROp_VFNMLA>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  const auto Add  = GetVReg(Op->Addend);
  VR A = V1, B = V2;
  if (Dst != Add) {
    if (Dst == V1) { vmr(VTMP1, V1); A = VTMP1; }
    if (Dst == V2) { vmr(VTMP2, V2); B = VTMP2; }
    vmr(Dst, Add);
  }
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvnmsubasp(Dst, A, B); break;
  case IR::OpSize::i64Bit: xvnmsubadp(Dst, A, B); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

DEF_OP(VFNMLS) {
  const auto Op   = IROp->C<IR::IROp_VFNMLS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst  = GetVReg(Node);
  const auto V1   = GetVReg(Op->Vector1);
  const auto V2   = GetVReg(Op->Vector2);
  const auto Add  = GetVReg(Op->Addend);
  VR A = V1, B = V2;
  if (Dst != Add) {
    if (Dst == V1) { vmr(VTMP1, V1); A = VTMP1; }
    if (Dst == V2) { vmr(VTMP2, V2); B = VTMP2; }
    vmr(Dst, Add);
  }
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvnmaddasp(Dst, A, B); break;
  case IR::OpSize::i64Bit: xvnmaddadp(Dst, A, B); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// VectorScalar insert ops (all delegated — these mix scalar and vector modes)
// ---------------------------------------------------------------------------
// SSE-style scalar FP ops: result = Vec1 with element 0 replaced by
//   (Vec1.elem[0] OP Vec2.elem[0]).  Upper elements are preserved from Vec1.
//
// Stack-roundtrip strategy (same as the existing VFSqrtScalarInsert):
//   1. stvx Vec1 → buf[-32..-17].  In FEX's PPC64LE convention, stvx reverses
//      byte order so x86 LE element 0 of Vec1 lands at buf[-32..-32+ESize-1].
//   2. stvx Vec2 → buf[-16..-1].
//   3. lfs/lfd both element-0 scalars into f0,f1; do the FP op; stfs/stfd
//      back over Vec1's element-0 slot at buf[-32..].
//   4. lvx the patched buf[-32..-17] into Dst.
#define DEF_SCALAR_INSERT(NAME, FOP_S, FOP_D)                                  \
DEF_OP(NAME) {                                                                 \
  const auto Op   = IROp->C<IR::IROp_##NAME>();                                \
  const auto Dst  = GetVReg(Node);                                             \
  const auto Vec1 = GetVReg(Op->Vector1);                                      \
  const auto Vec2 = GetVReg(Op->Vector2);                                      \
  addi(TMP1, r1, -32);                                                         \
  stvx(Vec1, r(0), TMP1);                                                      \
  addi(TMP2, r1, -16);                                                         \
  stvx(Vec2, r(0), TMP2);                                                      \
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {                          \
    lfs(f0, -32, r1);                                                          \
    lfs(f1, -16, r1);                                                          \
    FOP_S(f0, f0, f1);                                                         \
    stfs(f0, -32, r1);                                                         \
  } else {                                                                     \
    lfd(f0, -32, r1);                                                          \
    lfd(f1, -16, r1);                                                          \
    FOP_D(f0, f0, f1);                                                         \
    stfd(f0, -32, r1);                                                         \
  }                                                                            \
  lvx(Dst, r(0), TMP1);                                                        \
}
DEF_SCALAR_INSERT(VFAddScalarInsert, fadds, fadd)
DEF_SCALAR_INSERT(VFSubScalarInsert, fsubs, fsub)
DEF_SCALAR_INSERT(VFMulScalarInsert, fmuls, fmul)
DEF_SCALAR_INSERT(VFDivScalarInsert, fdivs, fdiv)
#undef DEF_SCALAR_INSERT

// VFMin / VFMax scalar insert: x86 minss/maxss specifically return src2 when
// either operand is NaN or when (a == b == ±0).  PPC has no fmin/fmax FPR op
// — we emulate via fsel on (b - a): fsel(F, FRA, FRC, FRB) gives FRC if
// FRA >= 0 else FRB, with NaN treated as negative.
//   minss(a, b): if (a < b) return a else b
//                = (b - a) >= 0 ? a : b ... wait, b - a >= 0 iff b >= a iff !(a < b)? When a==b, it returns b (= a, same value).
// For NaN: (b - a) is NaN.  fsel treats NaN as < 0 → returns FRB.
// We want: NaN → return src2 (= b). So FRA = b - a, FRC = a, FRB = b.
//   minss = (b-a >= 0) ? a : b   (= a when a < b, else b)
//   maxss = (a-b >= 0) ? a : b   (= a when a > b, else b)
// x86 MINSS/MAXSS/MINSD/MAXSD: NaN or both ±0 → second source (bit-exact).
// fsel-based shortcut gets the tie/NaN tiebreaker wrong, so emit the same
// vector select pattern used by VFMin/VFMax (vcmpgtfp/xvcmpgtdp + vsel/xxsel)
// and bit-copy lane 0 via GPR — avoids fp-load-store SNaN canonicalization.
DEF_OP(VFMinScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFMinScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    vcmpgtfp(VTMP1, Vec2, Vec1);          // mask = Vec2 > Vec1
    vsel    (VTMP1, Vec2, Vec1, VTMP1);
  } else {
    xvcmpgtdp(VTMP1, Vec2, Vec1);
    xxsel    (VTMP1, Vec2, Vec1, VTMP1);
  }
  addi(TMP1, r1, -32);
  stvx(Vec1,  r(0), TMP1);                 // [-32..-17] = Vec1
  addi(TMP2, r1, -16);
  stvx(VTMP1, r(0), TMP2);                 // [-16..-1]  = computed min
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    lwz(TMP3, -16, r1);
    stw(TMP3, -32, r1);
  } else {
    ld (TMP3, -16, r1);
    std(TMP3, -32, r1);
  }
  lvx(Dst, r(0), TMP1);
}

DEF_OP(VFMaxScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFMaxScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    vcmpgtfp(VTMP1, Vec1, Vec2);          // mask = Vec1 > Vec2
    vsel    (VTMP1, Vec2, Vec1, VTMP1);
  } else {
    xvcmpgtdp(VTMP1, Vec1, Vec2);
    xxsel    (VTMP1, Vec2, Vec1, VTMP1);
  }
  addi(TMP1, r1, -32);
  stvx(Vec1,  r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(VTMP1, r(0), TMP2);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    lwz(TMP3, -16, r1);
    stw(TMP3, -32, r1);
  } else {
    ld (TMP3, -16, r1);
    std(TMP3, -32, r1);
  }
  lvx(Dst, r(0), TMP1);
}
DEF_OP(VFSqrtScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFSqrtScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);

  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);

  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    lfs(f0, -16, r1);
    fsqrts(f0, f0);
    stfs(f0, -32, r1);
  } else {
    lfd(f0, -16, r1);
    fsqrt(f0, f0);
    stfd(f0, -32, r1);
  }

  // (Was previously `lvx(VTMP1, ...)` — bug: result never made it to Dst.)
  lvx(Dst, r(0), TMP1);
}
// VFRSqrt / VFRecp scalar inserts.  x86 RSQRTSS / RCPSS produce ~12-bit
// approximations; PPC frsqrtes/fres give similar-precision estimates.  For
// f64 (no x86 equivalent) we use the f64 estimate ops.
DEF_OP(VFRSqrtScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFRSqrtScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    lfs(f0, -16, r1);
    frsqrtes(f0, f0);
    stfs(f0, -32, r1);
  } else {
    lfd(f0, -16, r1);
    frsqrte(f0, f0);
    stfd(f0, -32, r1);
  }
  lvx(Dst, r(0), TMP1);
}

DEF_OP(VFRecpScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFRecpScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    lfs(f0, -16, r1);
    fres(f0, f0);
    stfs(f0, -32, r1);
  } else {
    lfd(f0, -16, r1);
    // PPC has no scalar f64 fre; use 1.0/x via fdiv.
    LoadConstant(TMP3, 0x3FF0000000000000ULL); // 1.0 as f64
    std(TMP3, -48, r1);
    lfd(f1, -48, r1);
    fdiv(f0, f1, f0);
    stfd(f0, -32, r1);
  }
  lvx(Dst, r(0), TMP1);
}

// VFToFScalarInsert: cvtss2sd / cvtsd2ss style conversion.
//   src=f32 → dst=f64: lfs (PPC promotes f32→f64 in FPR) → stfd.
//   src=f64 → dst=f32: lfd → frsp → stfs.
DEF_OP(VFToFScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFToFScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);
  const auto DstES = Op->Header.ElementSize;
  const auto SrcES = Op->SrcElementSize;
  if (SrcES == IR::OpSize::i32Bit && DstES == IR::OpSize::i64Bit) {
    // f32 → f64: lfs already promotes, stfd writes f64.
    lfs(f0, -16, r1);
    stfd(f0, -32, r1);
  } else if (SrcES == IR::OpSize::i64Bit && DstES == IR::OpSize::i32Bit) {
    // f64 → f32: lfd, frsp narrows, stfs writes 4 bytes (preserves elem 1+).
    lfd(f0, -16, r1);
    frsp(f0, f0);
    stfs(f0, -32, r1);
  } else {
    // Same size — degenerate copy.
    if (DstES == IR::OpSize::i32Bit) { lfs(f0, -16, r1); stfs(f0, -32, r1); }
    else                              { lfd(f0, -16, r1); stfd(f0, -32, r1); }
  }
  lvx(Dst, r(0), TMP1);
}

// VSToFVectorInsert: signed-int → float, source from FPR vector.
// For x86 cvtsi2ss/cvtsi2sd (HasTwoElements=0) and cvtpi2ps (HasTwoElements=1).
DEF_OP(VSToFVectorInsert) {
  const auto Op   = IROp->C<IR::IROp_VSToFVectorInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  const auto DstES = Op->Header.ElementSize;
  const auto SrcES = Op->SrcElementSize;
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);

  if (Op->HasTwoElements) {
    // cvtpi2ps: convert two i32 → two f32, write to lower 64 bits of dst.
    // Src elements 0,1 (4 bytes each) at -16, -12.
    lwa(TMP3, -16, r1);  // sign-extend i32 elem0 → i64
    std(TMP3, -48, r1);
    lfd(f0, -48, r1);
    fcfids(f0, f0);
    stfs(f0, -32, r1);
    lwa(TMP3, -12, r1);  // i32 elem1
    std(TMP3, -48, r1);
    lfd(f0, -48, r1);
    fcfids(f0, f0);
    stfs(f0, -28, r1);
  } else {
    // Single conversion: src element 0 of size SrcES → dst f-element 0 of DstES.
    // Source path: load int as 64-bit signed in GPR, then mtfprd → fcfid(s).
    if (SrcES == IR::OpSize::i32Bit) {
      lwa(TMP3, -16, r1);              // sign-extend low 32 → i64
    } else {
      ld(TMP3, -16, r1);               // 64-bit
    }
    std(TMP3, -48, r1);
    lfd(f0, -48, r1);
    if (DstES == IR::OpSize::i32Bit) {
      fcfids(f0, f0);
      stfs(f0, -32, r1);
    } else {
      fcfid(f0, f0);
      stfd(f0, -32, r1);
    }
  }
  lvx(Dst, r(0), TMP1);
}

// VSToFGPRInsert: GPR signed int → float, insert into Vec1[0].
DEF_OP(VSToFGPRInsert) {
  const auto Op   = IROp->C<IR::IROp_VSToFGPRInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec  = GetVReg(Op->Vector);
  const auto Src  = GetReg(Op->Src);
  const auto DstES = Op->Header.ElementSize;
  const auto SrcES = Op->SrcElementSize;

  addi(TMP1, r1, -32);
  stvx(Vec, r(0), TMP1);

  // Move signed int from GPR → FPR via memory.
  if (SrcES == IR::OpSize::i32Bit) {
    extsw(TMP3, Src);          // sign-extend low 32 → 64
    std(TMP3, -48, r1);
  } else {
    std(Src, -48, r1);         // already 64-bit
  }
  lfd(f0, -48, r1);
  if (DstES == IR::OpSize::i32Bit) {
    fcfids(f0, f0);
    stfs(f0, -32, r1);
  } else {
    fcfid(f0, f0);
    stfd(f0, -32, r1);
  }
  lvx(Dst, r(0), TMP1);
}

// VFToIScalarInsert: float → signed integer with explicit rounding mode.
DEF_OP(VFToIScalarInsert) {
  // ROUND[SS|SD]: round the scalar in Vector2 to an integral *float* per Round
  // mode, insert into element 0 of Vector1, copy other elements through.  The
  // output is float, not integer — earlier versions of this op stored fctid's
  // int result, which broke ROUNDSS/ROUNDSD.
  const auto Op   = IROp->C<IR::IROp_VFToIScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  const auto ESize = Op->Header.ElementSize;
  const auto Round = Op->Round;

  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);

  // Load source scalar (lfs auto-promotes f32→f64 in FPR).
  if (ESize == IR::OpSize::i32Bit) {
    lfs(f0, -16, r1);
  } else {
    lfd(f0, -16, r1);
  }

  // Round-to-integral, output is float.  Nearest / Host route through
  // fctid+fcfid which honors FPSCR.RN (default RN=0 = banker's), since the
  // direct `frin` instruction is "round-half-away-from-zero" — wrong for x86
  // Nearest semantics.  Other modes have direct in-mode round-to-FP scalar ops.
  //
  // ROUNDSS/ROUNDSD on PPC64LE: project_vftoiscalarinsert_nan_inf bug — the
  // fctid+fcfid round-trip SATURATES NaN and out-of-range FP to INT64_MIN,
  // which fcfid converts back to a finite -2^63 instead of propagating the
  // original value. x86 ROUNDSS/ROUNDSD spec: NaN passes through unchanged,
  // and values with |f0| >= 2^52 are already integer-valued (no fractional
  // bits in f64) so need no rounding. Bypass the round-trip for both classes.
  // Other rounding modes (NegInf/PosInf/TowardsZero) use frim/frip/friz which
  // are FP→FP and already NaN-correct, so they need no special handling.
  switch (Round) {
  case IR::RoundMode::NegInfinity: frim(f0, f0); break;
  case IR::RoundMode::PosInfinity: frip(f0, f0); break;
  case IR::RoundMode::TowardsZero: friz(f0, f0); break;
  case IR::RoundMode::Nearest:
  case IR::RoundMode::Host:
  default: {
    PPC64Emitter::Label skip_roundtrip{};

    // Bypass #1: NaN.  f0 != f0 iff NaN; fcmpu sets CR0.UN (PPC bit 3).
    fcmpu(cr(0), f0, f0);
    bc({12, 3}, &skip_roundtrip);  // BO=12 BI=3 → branch if CR0.UN set

    // Bypass #2: |f0| >= 2^52. f64 mantissa is 52 bits; magnitudes at or
    // above this boundary are integer-valued exactly and need no rounding.
    // This also covers +/-Infinity (fabs(±Inf) = +Inf > +2^52).
    LoadConstant(TMP3, 0x4330000000000000ULL);  // double 2^52
    std(TMP3, -64, r1);
    lfd(f2, -64, r1);
    fabs(f3, f0);
    fcmpu(cr(0), f3, f2);
    bc({12, 1}, &skip_roundtrip);  // BO=12 BI=1 → branch if CR0.GT (f3 > 2^52)

    fctid(f1, f0);  // f64 → i64 using FPSCR.RN (banker's by default)
    fcfid(f0, f1);  // i64 → f64 (exact for values within precision boundary)

    Bind(&skip_roundtrip);
    break;
  }
  }

  // Store the rounded *float* back at element 0 of the result image.
  if (ESize == IR::OpSize::i32Bit) {
    frsp(f0, f0);              // narrow to f32 precision
    stfs(f0, 0, TMP1);
  } else {
    stfd(f0, 0, TMP1);
  }
  lvx(Dst, r(0), TMP1);
}

// VFCMPScalarInsert: scalar FP compare with predicate, result is all-ones / zero
// mask in the destination's element 0.  Uses fcmpu + CR0 manipulation.
DEF_OP(VFCMPScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFCMPScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  const auto ESize = Op->Header.ElementSize;
  const auto Pred = Op->Op;

  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);

  if (ESize == IR::OpSize::i32Bit) {
    lfs(f0, -32, r1);
    lfs(f1, -16, r1);
  } else {
    lfd(f0, -32, r1);
    lfd(f1, -16, r1);
  }
  fcmpu(cr(0), f0, f1);
  // CR0: bit 0=LT (a<b), bit 1=GT (a>b), bit 2=EQ (a==b), bit 3=SO (NaN).
  // Normalize predicate result into CR0.EQ (bit 2) so we can branch on CC_NE.
  switch (Pred) {
  case IR::FloatCompareOp::EQ:
    /* CR0.EQ already correct */
    break;
  case IR::FloatCompareOp::LT:
    cror(2, 0, 0);   // EQ = LT
    break;
  case IR::FloatCompareOp::LE:
    cror(2, 0, 2);   // EQ = LT || EQ
    break;
  case IR::FloatCompareOp::UNO:
    cror(2, 3, 3);   // EQ = SO
    break;
  case IR::FloatCompareOp::NEQ:
    crnor(2, 2, 2);  // EQ = !EQ
    break;
  case IR::FloatCompareOp::ORD:
    crnor(2, 3, 3);  // EQ = !SO
    break;
  }

  PPC64Emitter::Label done{};
  li(TMP3, 0);
  bc(CC_NE, &done);              // skip if predicate false
  li(TMP3, -1);                  // mask = all-ones
  Bind(&done);

  if (ESize == IR::OpSize::i32Bit) {
    stw(TMP3, 0, TMP1);
  } else {
    std(TMP3, 0, TMP1);
  }
  lvx(Dst, r(0), TMP1);
}
// FMA scalar inserts.  Semantics match VFMLA et al but only on element 0;
// upper elements are copied from `Upper`.  Stack roundtrip per the
// DEF_SCALAR_INSERT pattern, but with three operand vectors.
//
// PowerPC scalar FMAs:
//   fmadd  : T = A*C + B   ("mul-add"      → VFMLA)
//   fmsub  : T = A*C - B   ("mul-sub"      → VFMLS)
//   fnmadd : T = -(A*C + B) → -A*C - B    ("neg mul-add" → VFNMLS)
//   fnmsub : T = -(A*C - B) → -A*C + B    ("neg mul-sub" → VFNMLA)
// Note: fnmadd matches FEX's VFNMLS, and fnmsub matches FEX's VFNMLA.
#define DEF_FMA_SCALAR_INSERT(NAME, FOP_S, FOP_D)                              \
DEF_OP(NAME) {                                                                 \
  const auto Op    = IROp->C<IR::IROp_##NAME>();                               \
  const auto Dst   = GetVReg(Node);                                            \
  const auto Upper = GetVReg(Op->Upper);                                       \
  const auto V1    = GetVReg(Op->Vector1);                                     \
  const auto V2    = GetVReg(Op->Vector2);                                     \
  const auto Add   = GetVReg(Op->Addend);                                      \
  /* Spill Upper at -32 (becomes result base, preserves upper lanes). */       \
  addi(TMP1, r1, -32);                                                         \
  stvx(Upper, r(0), TMP1);                                                     \
  /* Spill V1, V2, Add at -16, -48, -64 to read element 0. */                  \
  addi(TMP2, r1, -16);                                                         \
  stvx(V1, r(0), TMP2);                                                        \
  addi(TMP3, r1, -48);                                                         \
  stvx(V2, r(0), TMP3);                                                        \
  addi(TMP4, r1, -64);                                                         \
  stvx(Add, r(0), TMP4);                                                       \
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {                          \
    lfs(f0, 0, TMP2);                                                          \
    lfs(f1, 0, TMP3);                                                          \
    lfs(f2, 0, TMP4);                                                          \
    FOP_S(f0, f0, f1, f2);                                                     \
    stfs(f0, 0, TMP1);                                                         \
  } else {                                                                     \
    lfd(f0, 0, TMP2);                                                          \
    lfd(f1, 0, TMP3);                                                          \
    lfd(f2, 0, TMP4);                                                          \
    FOP_D(f0, f0, f1, f2);                                                     \
    stfd(f0, 0, TMP1);                                                         \
  }                                                                            \
  lvx(Dst, r(0), TMP1);                                                        \
}
// fmadd(t,a,b,c)/fmsub etc per emitter signature: (t, fra, frc, frb).
// PPC fmadd ISA: T = FRA*FRC + FRB → emitter call fmadd(t, a, c, b).
// We pass: f0=V1, f1=V2, f2=Add → call fmadd(t, f0, f1, f2) emits
//   fmadd FRT, FRA=f0, FRC=f1, FRB=f2  →  T = f0*f1 + f2 = V1*V2 + Add.  ✓
DEF_FMA_SCALAR_INSERT(VFMLAScalarInsert,  fmadds,  fmadd)
DEF_FMA_SCALAR_INSERT(VFMLSScalarInsert,  fmsubs,  fmsub)
// VFNMLA: -(V1*V2) + Add → fnmsub: -A*C + B = -V1*V2 + Add  ✓
DEF_FMA_SCALAR_INSERT(VFNMLAScalarInsert, fnmsubs, fnmsub)
// VFNMLS: -(V1*V2) - Add → fnmadd: -(A*C+B) = -V1*V2 - Add  ✓
DEF_FMA_SCALAR_INSERT(VFNMLSScalarInsert, fnmadds, fnmadd)
#undef DEF_FMA_SCALAR_INSERT
// VFCopySign — magnitude from V1, sign from V2.
DEF_OP(VFCopySign) {
  const auto Op = IROp->C<IR::IROp_VFCopySign>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst = GetVReg(Node);
  const auto V1  = GetVReg(Op->Vector1);
  const auto V2  = GetVReg(Op->Vector2);
  // ISA says xvcpsgn{sp,dp}(T, A, B): T = magnitude(B) | sign(A).  FEX
  // semantics ("magnitude from V1, sign from V2") need V2 as A and V1 as B.
  switch (ElemSz) {
  case IR::OpSize::i32Bit: xvcpsgnsp(Dst, V2, V1); break;
  case IR::OpSize::i64Bit: xvcpsgndp(Dst, V2, V1); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// ---------------------------------------------------------------------------
// Conv ops
// ---------------------------------------------------------------------------

DEF_OP(VCastFromGPR) {
  const auto Op    = IROp->C<IR::IROp_VCastFromGPR>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetReg(Op->Src);

  // Place the GPR value into the lowest element of the vector (all others zero).
  // mtvsrd places the GPR in physical bytes [0..7] of VTMP1 (BE order); the
  // other doubleword is *undefined* per ISA, so we never read it.  Zero-extend
  // the GPR to the desired width first, then use `vsldoi(Dst, zero, VTMP1, 8)`
  // to combine [zero | VTMP1_high] — the result has the value in LE element 0
  // (phys[8..15]) and zeros everywhere else.
  vspltisw(VTMP2, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    rldicl(TMP1, Src, 0, 56);
    mtvsrd(VTMP1, TMP1);
    vsldoi(Dst, VTMP2, VTMP1, 8);
    break;
  case IR::OpSize::i16Bit:
    rldicl(TMP1, Src, 0, 48);
    mtvsrd(VTMP1, TMP1);
    vsldoi(Dst, VTMP2, VTMP1, 8);
    break;
  case IR::OpSize::i32Bit:
    rldicl(TMP1, Src, 0, 32);
    mtvsrd(VTMP1, TMP1);
    vsldoi(Dst, VTMP2, VTMP1, 8);
    break;
  case IR::OpSize::i64Bit:
    mtvsrd(VTMP1, Src);
    vsldoi(Dst, VTMP2, VTMP1, 8);
    break;
  default:
    vspltisw(Dst, 0);
    break;
  }
}

DEF_OP(VDupFromGPR) {
  const auto Op    = IROp->C<IR::IROp_VDupFromGPR>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetReg(Op->Src);

  // mtvsrd defines BE dword 0 (phys[0..7]); BE dword 1 (phys[8..15]) is
  // undefined per ISA. SplatByteIdx(0)=15/SplatHalfIdx(0)=7/SplatWordIdx(0)=3
  // all read from the undefined half — duplicate the defined dword into both
  // halves first (same pattern as VShlI i64 — invariant 0a).
  mtvsrd(VTMP1, Src);
  xxpermdi(VTMP1, VTMP1, VTMP1, 0);
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltb(Dst, VTMP1, SplatByteIdx(0));
    break;
  case IR::OpSize::i16Bit:
    vsplth(Dst, VTMP1, SplatHalfIdx(0));
    break;
  case IR::OpSize::i32Bit:
    vspltw(Dst, VTMP1, SplatWordIdx(0));
    break;
  case IR::OpSize::i64Bit:
    // Stack-roundtrip 64-bit duplicate (avoids the undefined-doubleword hazard
    // of vsldoi(VTMP1, VTMP1, ..., 8)).
    std(Src, -16, r1);
    std(Src,  -8, r1);
    addi(TMP1, r1, -16);
    li(TMP2, 0);
    lvx(Dst, TMP1, TMP2);
    break;
  default:
    break;
  }
}

DEF_OP(VLoadTwoGPRs) {
  const auto Op  = IROp->C<IR::IROp_VLoadTwoGPRs>();
  const auto Dst = GetVReg(Node);
  const auto Lo  = GetReg(Op->Lower);
  const auto Hi  = GetReg(Op->Upper);

  // Build a 128-bit vector with Lo at LE element 0 (low 64 bits, memory
  // bytes 0-7) and Hi at LE element 1 (memory bytes 8-15). On PPC64LE Linux
  // (MSR.LE=1), `lvx`/`stvx` use little-endian byte semantics — the same
  // convention that the FABI bridge stubs rely on with `stvx; lfd offset 0`
  // to extract a double from LE element 0. So store Lo at the low address
  // (-16) and Hi at the high address (-8); lvx then puts Lo bytes into
  // physical positions 0-7 and Hi bytes into 8-15.
  std(Lo, -16, r1);
  std(Hi,  -8, r1);
  addi(TMP1, r1, -16);
  li(TMP2, 0);
  lvx(Dst, TMP1, TMP2);
}

DEF_OP(Float_FromGPR_S) {
  const auto Op     = IROp->C<IR::IROp_Float_FromGPR_S>();
  const auto DstSz  = Op->Header.ElementSize;
  const auto SrcSz  = Op->SrcElementSize;
  const auto Dst    = GetVReg(Node);
  const auto Src    = GetReg(Op->Src);

  // Convert integer GPR to FP scalar using FP unit instructions.
  // Move GPR → FPR via stack, convert, move back to vector register.
  std(Src, -8, r1);
  addi(TMP1, r1, -8);
  lfd(f0, 0, TMP1);  // load as integer bits into f0

  if (DstSz == IR::OpSize::i32Bit) {
    // int→float: need fcfid then frsp
    if (SrcSz == IR::OpSize::i32Bit) {
      // sign-extend 32→64 for fcfid
      extsw(TMP2, Src);
      std(TMP2, -8, r1);
      lfd(f0, -8, r1);
    }
    fcfid(f0, f0);
    frsp(f0, f0);
    // Store f0 back as float, load into vector
    stfs(f0, -8, r1);
    addi(TMP1, r1, -8);
    lvx(VTMP1, r(0), TMP1);
    // The float is at the low 4 bytes of the 8-byte store, adjust...
    // Actually stfs writes 4 bytes; we want those in element 0 of Dst.
    vspltisw(Dst, 0);
    // Load 4-byte float into element 0 (LE: phys bytes [12:15]).
    // Use lvewx + vperm to place correctly.
    vspltisw(Dst, 0);
    lwz(TMP1, -8, r1);
    mtvsrd(VTMP1, TMP1);        // 32-bit value in upper bits
    vsldoi(VTMP1, VTMP1, VTMP1, 8);  // move to both halves
    vspltw(Dst, VTMP1, SplatWordIdx(0)); // splat element 0 (BE bytes 0..3 = f32)
    // Only keep element 0, zero rest.  Read from Dst (where vspltw just placed
    // the f32 in BE bytes 0..3) — NOT from VTMP1, whose BE bytes 0..3 are the
    // undefined upper-half of mtvsrd (rotated into that position by the prior
    // vsldoi shb=8).  Previously this `vsldoi(Dst, VTMP2, VTMP1, 4)` would
    // overwrite the just-built splat with the undefined bytes.
    vspltisw(VTMP2, 0);
    vsldoi(Dst, VTMP2, Dst, 4); // [zero(12) | f32(4)] in BE = LE elem0=f32, rest=0
  } else {
    // lvx ignores low 4 bits of EA. stfd at r1-8 lands the double in the upper
    // half of the r1-16-aligned block, which arrives at LE[8..15] of VTMP1;
    // vsldoi(Dst, Dst, VTMP1, 8) slides that to LE[0..7] and zeroes the rest.
    if (SrcSz == IR::OpSize::i32Bit) extsw(TMP2, Src);
    else mr(TMP2, Src);
    std(TMP2, -8, r1);
    lfd(f0, -8, r1);
    fcfid(f0, f0);
    stfd(f0, -8, r1);
    addi(TMP1, r1, -16);
    vspltisw(Dst, 0);
    lvx(VTMP1, r(0), TMP1);
    vsldoi(Dst, Dst, VTMP1, 8);
  }
}

DEF_OP(Float_FToF) {
  const auto Op    = IROp->C<IR::IROp_Float_FToF>();
  const auto DstSz = Op->Header.ElementSize;
  const auto SrcSz = Op->SrcElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Scalar);

  const uint32_t Conv = (IR::OpSizeToSize(DstSz) << 8) | IR::OpSizeToSize(SrcSz);

  // Use FP unit via stack for the conversion.
  // Store Src scalar to stack, load into FPR, convert, store, load into Dst vector.
  addi(TMP1, r1, -8);
  stvx(Src, r(0), TMP1);  // store all 16 bytes of Src

  switch (Conv) {
  case 0x0804: { // f64 ← f32
    lfs(f0, -8, r1);   // load float (last 4 bytes relative? use offset into vector)
    // The f32 is in element 0 of Src vector. In LE, element 0 is at low address,
    // which within the 16-byte aligned stvx block is at offset 0 of the block.
    // But stvx stores at 16-byte aligned addr, so r1-8 may not be aligned...
    // Use stfs/lfd approach instead.
    // Store element 0 of Src as f32:
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);    // stores at 16-byte aligned -16
    lfs(f0, 0, TMP1);      // load first 4 bytes of Src as f32; lfs auto-converts to f64 in f0
    stfd(f0, -8, r1);
    // Load 64-bit result into Dst vector element 0
    vspltisw(Dst, 0);
    ld(TMP2, -8, r1);
    mtvsrd(VTMP1, TMP2);
    vsldoi(Dst, Dst, VTMP1, 8);  // [Dst(zero)(8), VTMP1(8)] in phys
    break;
  }
  case 0x0408: { // f32 ← f64
    // After lwz, TMP2 holds the F32 bits in the low 32 of a zero-extended GPR.
    // mtvsrd places GPR into VTMP1's BE bits [0..63] = phys[0..7], so the F32
    // ends up at phys[4..7] (the low half of doubleword 0). Then vsldoi by 8
    // moves VTMP1's phys[0..7] into Dst's phys[8..15] = LE element 0, leaving
    // the F32 at phys[12..15] = LE bits [0..31] of element 0. (Shift-by-4
    // would have selected phys[0..3] = the zero-extension half, dropping the
    // F32.)
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    lfd(f0, 0, TMP1);
    frsp(f0, f0);
    stfs(f0, -4, r1);
    lwz(TMP2, -4, r1);
    mtvsrd(VTMP1, TMP2);
    vspltisw(Dst, 0);
    vsldoi(Dst, Dst, VTMP1, 8);
    break;
  }
  default:
    if (Dst != Src) vmr(Dst, Src);
    break;
  }
}

DEF_OP(Vector_SToF) {
  const auto Op    = IROp->C<IR::IROp_Vector_SToF>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i32Bit) {
    // vcfsx converts 32-bit fixed-point to f32: vcfsx(D, S, 0) = S as float
    vcfsx(Dst, Src, 0);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 2× i64 → 2× f64 via per-lane GPR roundtrip with fcfid.
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    ld(TMP3, 0, TMP1);
    std(TMP3, -32, r1);
    lfd(f0, -32, r1);
    fcfid(f0, f0);
    stfd(f0, 0, TMP1);
    ld(TMP3, 8, TMP1);
    std(TMP3, -32, r1);
    lfd(f0, -32, r1);
    fcfid(f0, f0);
    stfd(f0, 8, TMP1);
    lvx(Dst, r(0), TMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(Vector_FToS) {
  const auto Op    = IROp->C<IR::IROp_Vector_FToS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i32Bit) {
    // xvcvspsxws (and vctsxs) unconditionally truncate; pair with xvrspic so
    // the FP-to-int rounds in current FPSCR.RN. Earlier `vrfin + vctsxs` did
    // round-to-nearest then truncate — double-rounding for x.5 cases.
    xvrspic(VTMP1, Src);
    xvcvspsxws(Dst, VTMP1);
    // POWER returns INT_MAX on +overflow but x86 wants INT_MIN ("integer
    // indefinite") sentinel.  Detect Src >= 2^31 and substitute INT_MIN.
    // NaN comparisons return 0 from xvcmpgesp (and POWER already maps NaN
    // → INT_MIN), so the mask correctly captures only +overflow / +Inf.
    LoadConstant(TMP1, 0x4F0000004F000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);  // VTMP2 = splat f32(2^31)
    xvcmpgesp(VTMP1, Src, VTMP2);                  // mask: 1 where Src >= 2^31
    LoadConstant(TMP1, 0x8000000080000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);                        // VTMP2 = splat INT_MIN
    xxsel(Dst, Dst, VTMP2, VTMP1);                 // overflow ? INT_MIN : Dst
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // Match Vector_FToISized's HostRound=true path for f64→i64.
    xvrdpic(VTMP1, Src);
    xvcvdpsxds(Dst, VTMP1);
    // Same INT_MIN sentinel fix for f64 → i64.  Bound = 2^63 as f64.
    LoadConstant(TMP1, 0x43E0000000000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    LoadConstant(TMP1, 0x8000000000000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(Vector_FToZS) {
  const auto Op    = IROp->C<IR::IROp_Vector_FToZS>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i32Bit) {
    vrfiz(VTMP1, Src);    // round towards zero
    vctsxs(Dst, VTMP1, 0);
    // INT_MIN sentinel for +overflow (see Vector_FToS for rationale)
    LoadConstant(TMP1, 0x4F0000004F000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);
    xvcmpgesp(VTMP1, Src, VTMP2);
    LoadConstant(TMP1, 0x8000000080000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    xvrdpiz(VTMP1, Src);
    xvcvdpsxds(Dst, VTMP1);
    // INT_MIN sentinel for +overflow (see Vector_FToS for rationale)
    LoadConstant(TMP1, 0x43E0000000000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    LoadConstant(TMP1, 0x8000000000000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// Vector_FToF: packed float widening (f32→f64, lower half) or narrowing
// (f64→f32, into low half).  Implemented via per-lane fpr roundtrip — POWER8's
// xvcvspdp / xvcvdpsp use BE word indexing which doesn't line up with FEX's
// LE-element layout.
DEF_OP(Vector_FToF) {
  const auto Op    = IROp->C<IR::IROp_Vector_FToF>();
  const auto DstSz = Op->Header.ElementSize;
  const auto SrcSz = Op->SrcElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);
  const uint32_t Conv = (IR::OpSizeToSize(DstSz) << 8) | IR::OpSizeToSize(SrcSz);

  if (Conv == 0x0804) {
    // f32 → f64 packed.  Source has 4 f32 lanes; we promote elements 0,1 into
    // a 2-lane f64 result.  Spill source at -16, write f64 results at -32..-17.
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    lfs(f0, 0, TMP1);                 // f32 elem 0 → f64 in f0 (lfs auto-promotes)
    stfd(f0, -32, r1);
    lfs(f0, 4, TMP1);                 // f32 elem 1
    stfd(f0, -24, r1);
    addi(TMP2, r1, -32);
    lvx(Dst, r(0), TMP2);
    return;
  }
  if (Conv == 0x0408) {
    // f64 → f32 packed.  Source 2 f64 lanes → 2 f32 lanes in low half;
    // upper half zeroed (matches CVTPD2PS).
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    lfd(f0, 0, TMP1);
    frsp(f0, f0);
    stfs(f0, -32, r1);
    lfd(f0, 8, TMP1);
    frsp(f0, f0);
    stfs(f0, -28, r1);
    li(TMP3, 0);
    std(TMP3, -24, r1);
    addi(TMP2, r1, -32);
    lvx(Dst, r(0), TMP2);
    return;
  }
  if (Conv == 0x0402 || Conv == 0x0204) {
    // F16C: f16x4↔f32x4 packed conversion via software FABI helper.
    // Conv 0x0402: src f16 (i16) → dst f32 (i32) — VCVTPH2PS.
    // Conv 0x0204: src f32 (i32) → dst f16 (i16) — VCVTPS2PH (low half = 4 halves,
    //                                              upper half zeroed).
    const bool SrcIsF16 = (Conv == 0x0402);
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };
    stdu(r1, -CryptoMiniFrameSize, r1);
    mflr(r(0)); std(r(0), 16, r1);
    LoadConstant(TMP1, CryptoSlotA); stvx(Src, r1, TMP1);
    SpillForABICall(TMP1);
    addi(r3, r1, PostSpill(CryptoSlotA));
    addi(r4, r1, PostSpill(CryptoSlotA));
    LoadConstant(r(12), SrcIsF16
                          ? reinterpret_cast<uint64_t>(&PPC64_F16x4ToF32x4)
                          : reinterpret_cast<uint64_t>(&PPC64_F32x4ToF16x4));
    std(r2, PostSpill(24), r1);
    mtctr(r(12)); bctrl();
    ld(r2, PostSpill(24), r1);
    FillForABICall();
    LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
    ld(r(0), 16, r1); mtlr(r(0));
    addi(r1, r1, CryptoMiniFrameSize);
    li(r(0), 0);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// VFCVTL2: f32→f64 from the UPPER 64 bits of the source (CVTPS2PD upper).
// IR.json defines DestElementSize as "ElementSize << 1", so Header.ElementSize
// here is the *destination* size.  We only handle i64 (f32→f64); f32 (from f16)
// would need an FP16 convert that POWER8 lacks.
DEF_OP(VFCVTL2) {
  const auto Op = IROp->C<IR::IROp_VFCVTL2>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  if (Op->Header.ElementSize == IR::OpSize::i64Bit) {
    addi(TMP1, r1, -16);
    stvx(Src, r(0), TMP1);
    // f32 elem 2 at byte offset 8, f32 elem 3 at offset 12.
    lfs(f0, 8, TMP1);
    stfd(f0, -32, r1);
    lfs(f0, 12, TMP1);
    stfd(f0, -24, r1);
    addi(TMP2, r1, -32);
    lvx(Dst, r(0), TMP2);
    return;
  }
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    // f16→f32 from the upper half of Src — software path via FABI helper.
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };
    stdu(r1, -CryptoMiniFrameSize, r1);
    mflr(r(0)); std(r(0), 16, r1);
    LoadConstant(TMP1, CryptoSlotA); stvx(Src, r1, TMP1);
    SpillForABICall(TMP1);
    addi(r3, r1, PostSpill(CryptoSlotA));
    addi(r4, r1, PostSpill(CryptoSlotA));
    EmitLoadPPC64Helper(r(12), PPC64_HELPER_F16HiToF32x4);
    std(r2, PostSpill(24), r1);
    mtctr(r(12)); bctrl();
    ld(r2, PostSpill(24), r1);
    FillForABICall();
    LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
    ld(r(0), 16, r1); mtlr(r(0));
    addi(r1, r1, CryptoMiniFrameSize);
    li(r(0), 0);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// VFCVTN2: narrow f64→f32 (or f32→f16) and insert into the upper 64 bits of
// the destination, lower 64 bits from VectorLower.  IR.json defines this op's
// ElementSize as "ElementSize >> 1" — so Header.ElementSize is the destination
// element size.  i32 = f64→f32 narrow; i16 (f32→f16) we don't support.
DEF_OP(VFCVTN2) {
  const auto Op = IROp->C<IR::IROp_VFCVTN2>();
  const auto Dst = GetVReg(Node);
  const auto VL  = GetVReg(Op->VectorLower);
  const auto VU  = GetVReg(Op->VectorUpper);
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    // Spill VL at -32 (becomes result base), spill VU at -16 (source f64s).
    addi(TMP1, r1, -32);
    stvx(VL, r(0), TMP1);
    addi(TMP2, r1, -16);
    stvx(VU, r(0), TMP2);
    // Narrow VU's two f64s into upper half of -32 buffer (offsets 8, 12).
    lfd(f0, 0, TMP2);
    frsp(f0, f0);
    stfs(f0, 8, TMP1);
    lfd(f0, 8, TMP2);
    frsp(f0, f0);
    stfs(f0, 12, TMP1);
    lvx(Dst, r(0), TMP1);
    return;
  }
  if (Op->Header.ElementSize == IR::OpSize::i16Bit) {
    // f32→f16 narrow: write 4 f16 from VU into upper half of dst,
    // preserve VL's low half (which already holds 4 f16 from prior Vector_FToF).
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };
    stdu(r1, -CryptoMiniFrameSize, r1);
    mflr(r(0)); std(r(0), 16, r1);
    LoadConstant(TMP1, CryptoSlotA); stvx(VL, r1, TMP1);  // dst seed
    LoadConstant(TMP1, CryptoSlotB); stvx(VU, r1, TMP1);  // f32 source
    SpillForABICall(TMP1);
    addi(r3, r1, PostSpill(CryptoSlotA));   // dst (= VL spill, helper writes upper half)
    addi(r4, r1, PostSpill(CryptoSlotB));   // f32 source (VU)
    EmitLoadPPC64Helper(r(12), PPC64_HELPER_F32x4ToF16Hi);
    std(r2, PostSpill(24), r1);
    mtctr(r(12)); bctrl();
    ld(r2, PostSpill(24), r1);
    FillForABICall();
    LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
    ld(r(0), 16, r1); mtlr(r(0));
    addi(r1, r1, CryptoMiniFrameSize);
    li(r(0), 0);
    return;
  }
  Op_Unhandled(IROp, Node);
}

DEF_OP(Vector_FToI) {
  const auto Op    = IROp->C<IR::IROp_Vector_FToI>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst   = GetVReg(Node);
  const auto Src   = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i32Bit) {
    // Vector_FToI is round-to-integral-FLOAT (result stays floating-point).
    // x86 RoundMode::Nearest is "round-half-to-even" (banker's).  POWER's
    // xvrspi/vrfin are "round-half-away-from-zero", so for Nearest we must use
    // xvrspic which honors FPSCR.RN (defaults to RN=0 = nearest-even).  Host
    // mode uses the same path.
    switch (Op->Round) {
    case FEXCore::IR::RoundMode::NegInfinity: vrfim(Dst, Src); break;
    case FEXCore::IR::RoundMode::PosInfinity: vrfip(Dst, Src); break;
    case FEXCore::IR::RoundMode::TowardsZero: vrfiz(Dst, Src); break;
    case FEXCore::IR::RoundMode::Nearest:
    case FEXCore::IR::RoundMode::Host:
    default:                                  xvrspic(Dst, Src); break;
    }
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    switch (Op->Round) {
    case FEXCore::IR::RoundMode::NegInfinity: xvrdpim(Dst, Src); break;
    case FEXCore::IR::RoundMode::PosInfinity: xvrdpip(Dst, Src); break;
    case FEXCore::IR::RoundMode::TowardsZero: xvrdpiz(Dst, Src); break;
    case FEXCore::IR::RoundMode::Nearest:
    case FEXCore::IR::RoundMode::Host:
    default:                                  xvrdpic(Dst, Src); break;  // FPSCR.RN
    }
    return;
  }
  Op_Unhandled(IROp, Node);
}

// Vector_FToISized: convert each FP element to a sized integer.
// IntSize == ElementSize for the common cases (f32→i32, f64→i64).
// HostRound = true uses the current FPSCR rounding mode; false rounds toward
// zero (truncate).  PowerISA's xvcvspsxws / xvcvdpsxds use FPSCR.RN, so for
// truncate we first do an in-domain round-to-zero with xvrspiz / xvrdpiz.
DEF_OP(Vector_FToISized) {
  const auto Op       = IROp->C<IR::IROp_Vector_FToISized>();
  const auto ElemSz   = Op->Header.ElementSize;
  const auto IntSize  = Op->IntSize;
  const auto HostRound = Op->HostRound;
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i32Bit && IntSize == IR::OpSize::i32Bit) {
    // xvcvspsxws on POWER8 unconditionally rounds toward zero, so for both the
    // truncate and host-rounding paths we explicitly pre-round to integral FP
    // first; HostRound uses FPSCR.RN (xvrspic), Truncate uses xvrspiz.
    if (HostRound) {
      xvrspic(VTMP1, Src);
    } else {
      xvrspiz(VTMP1, Src);
    }
    xvcvspsxws(Dst, VTMP1);
    // POWER returns INT_MAX on f32 +overflow but x86 CVT{T}PS2DQ wants
    // INT_MIN (0x80000000) as the integer-indefinite sentinel.  See
    // commit c9db77322 for the rationale.  xvcmpgesp NaN compare returns
    // 0, so NaN (already INT_MIN per POWER) is correctly preserved.
    LoadConstant(TMP1, 0x4F0000004F000000ULL);  // splat f32(2^31)
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);
    xvcmpgesp(VTMP1, Src, VTMP2);                // mask: 1 where Src >= 2^31
    LoadConstant(TMP1, 0x8000000080000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);                      // splat INT_MIN
    xxsel(Dst, Dst, VTMP2, VTMP1);               // overflow ? INT_MIN : Dst
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit && IntSize == IR::OpSize::i64Bit) {
    if (HostRound) {
      xvrdpic(VTMP1, Src);
    } else {
      xvrdpiz(VTMP1, Src);
    }
    xvcvdpsxds(Dst, VTMP1);
    // INT_MIN sentinel for f64 -> i64 +overflow (matches CVT{T}SD2SI etc.).
    LoadConstant(TMP1, 0x43E0000000000000ULL);  // f64(2^63)
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    addi(TMP2, r1, -16); lvx(VTMP2, r(0), TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    LoadConstant(TMP1, 0x8000000000000000ULL);
    std(TMP1, -16, r1); std(TMP1, -8, r1);
    lvx(VTMP2, r(0), TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);
    return;
  }
  Op_Unhandled(IROp, Node);
}

// Vector_F64ToI32: CVTPD2DQ/CVTTPD2DQ semantics.  Each of the two f64 lanes
// becomes an i32 in the LE-low quadword of the result; EnsureZeroUpperHalf
// controls whether the upper 64 bits are zeroed.
DEF_OP(Vector_F64ToI32) {
  const auto Op = IROp->C<IR::IROp_Vector_F64ToI32>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  const auto Round = Op->Round;
  const auto Zero  = Op->EnsureZeroUpperHalf;

  // xvcvdpsxws on POWER8 unconditionally rounds toward zero — we have to
  // pre-round to integral FP using the requested mode first.  Nearest uses
  // xvrdpic (FPSCR.RN) for x86 banker's rounding, not xvrdpi (ties away).
  switch (Round) {
  case IR::RoundMode::TowardsZero: xvrdpiz(VTMP1, Src); break;
  case IR::RoundMode::NegInfinity: xvrdpim(VTMP1, Src); break;
  case IR::RoundMode::PosInfinity: xvrdpip(VTMP1, Src); break;
  case IR::RoundMode::Nearest:
  case IR::RoundMode::Host:
  default:                         xvrdpic(VTMP1, Src); break;  // FPSCR.RN
  }
  xvcvdpsxws(Dst, VTMP1);
  // xvcvdpsxws places the two result words in BE word elements 1 and 3
  // (physical bytes 4..7 and 12..15); elements 0 and 2 are "UNDEFINED" per
  // PowerISA. On POWER8 they're filled with duplicates of the adjacent
  // defined word — NOT INT_MIN as an earlier comment claimed and NOT zero.
  // Pack to LE-low (lanes 0 and 1) unconditionally; the upper-64 zero side
  // effect is harmless because Vector_F64ToI32's callers either zip away the
  // upper half (CVTPD2DQ YMM) or want it zeroed (CVTPD2DQ XMM via
  // AVX128_Zext). Doing this conditionally on the Zero flag left the
  // duplicate-int garbage visible in the YMM path's VBSL, miscompiling
  // CVTPD2DQ/CVTTPD2DQ 256->128.

  // First: build the overflow mask BEFORE packing the convert result, so
  // we have the f64 source comparison available in a per-lane form that
  // shares the same BE byte 0..3-of-each-dw layout as xvcvdpsxws's output.
  // POWER returns INT_MAX on f64 +overflow but x86 wants INT_MIN (the
  // "integer indefinite" sentinel).  NaN already maps to INT_MIN per POWER
  // and xvcmpgedp NaN compare returns 0 — both handled correctly.
  //
  // Sequence:
  //   1. Stash 2^31_f64 splat into the stack scratch.
  //   2. Load it into VTMP2 (overwriting any prior content), compare:
  //        VTMP2 = (Src >= splat(2^31_f64)) per lane, all-ones or zero
  //   3. xxsel between Dst (POWER's INT_MAX-saturated result) and an
  //      INT_MIN broadcast.  Since the mask's per-dw layout is full-64-on
  //      or full-64-off, xxsel acts per-byte but identically across all
  //      bytes of each dw — i.e. for each i64 lane, either preserve all
  //      32 bits of POWER's result word OR substitute INT_MIN.
  //   4. AFTER the substitution, do the existing vperm-pack to LE-low.
  LoadConstant(TMP1, 0x43E0000000000000ULL);  // 2^31 as f64
  std(TMP1, -16, r1); std(TMP1, -8, r1);
  addi(TMP1, r1, -16);
  lvx(VTMP2, r(0), TMP1);                     // VTMP2 = splat f64(2^31)
  xvcmpgedp(VTMP2, Src, VTMP2);               // per-i64-lane overflow mask
  LoadConstant(TMP1, 0x80000000ULL);          // INT_MIN as i32; broadcast via mtvsrd-splat
  std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x80000000ULL);
  std(TMP1, -8, r1);
  // Actually need per-32-bit INT_MIN.  Splat 0x80000000 8 times (16 bytes):
  LoadConstant(TMP1, 0x8000000080000000ULL);
  std(TMP1, -16, r1); std(TMP1, -8, r1);
  addi(TMP1, r1, -16);
  lvx(VTMP1, r(0), TMP1);                     // VTMP1 = splat i32(INT_MIN)
  xxsel(Dst, Dst, VTMP1, VTMP2);              // mask ? INT_MIN : Dst (per-byte == per-i32-lane here)

  // Now pack the (possibly INT_MIN-substituted) i32 results to LE-low.
  vspltisw(VTMP1, 0);
  LoadConstant(TMP1, 0x040506070C0D0E0FULL); std(TMP1, -16, r1);
  LoadConstant(TMP1, 0x1010101010101010ULL); std(TMP1, -8,  r1);
  addi(TMP1, r1, -16);
  lvx(VTMP2, r(0), TMP1);
  vperm(Dst, Dst, VTMP1, VTMP2);
  (void)Zero;
}

// ---------------------------------------------------------------------------
// F64 transcendentals — intra-DSO helper calls via ELFv2 ABI
//
// All libm functions are wrapped in static helpers below so every call is
// intra-DSO (no PLT TOC hazard). ELFv2 requires r12 = callee GEP address
// before bctrl so the callee's GEP can recompute r2 if needed.
//
// Scratch layout (after SpillForABICall, r1 16-byte aligned):
//   [r1-16 .. r1- 1] : 16-byte slot A  (first  VR / result)
//   [r1-32 .. r1-17] : 16-byte slot B  (second VR, two-arg ops only)
//
// LE AltiVec element 0 is at byte offset 0 from the stvx base address, so
// lfd/stfd at offset 0 directly reads/writes element 0 of the VR.
// ---------------------------------------------------------------------------

namespace {
static double F64SinImpl(double x)  { return std::sin(x); }
static double F64CosImpl(double x)  { return std::cos(x); }
static double F64TanImpl(double x)  { return std::tan(x); }
static double F64AtanImpl(double y, double x) { return std::atan2(y, x); }
static double F64FYL2XImpl(double x, double y) { return y * std::log2(x); }
// x87 FSCALE computes x * 2^trunc(n).
//
// `std::ldexp(x, static_cast<int>(n))` is undefined behaviour when n is NaN or
// |n| > INT_MAX -- the float-to-int conversion, not ldexp, is the problem.
// Measured consequence on this backend: FSCALE with a NaN exponent returned
// 1.0 where upstream returns NaN. Huge |n| happened to saturate to Inf on the
// compilers tested, but that is UB, not a guarantee.
//
// Use upstream's fallback form (F80Fallbacks.h:421-430), which has no integer
// conversion at all: NaN propagates through trunc/exp2, huge |n| overflows to
// Inf as required, and the zero early-out preserves the sign of x.
static double F64ScaleImpl(double x, double n) {
  if (x == 0.0) {
    return x;
  }
  return x * std::exp2(std::trunc(n));
}
// x87 F2XM1 computes 2^x - 1 over the architectural domain |x| <= 1, and exists
// specifically for x near zero.
//
// Do NOT write the in-domain case as `std::exp2(x) - 1.0`. exp2 returns a
// correctly rounded result carrying up to 0.5 ULP of error *at its own
// magnitude*; for x near zero that magnitude is ~1.0 while the true result is
// near zero. The subtraction is exact by Sterbenz, so the whole absolute error
// is inherited into a result whose ULP is far smaller. Measured against a
// 70-digit reference over 120k in-domain points, that form is off by more than
// 1 ULP on 44.6% of inputs, with unbounded relative error near zero: every
// denormal and every |x| < ~2^-27 returns exactly 0.0. At x=0.5 it is 1.74 ULP
// out, which is the D9_F0_02_F64 failure.
//
// expm1 computes e^y - 1 without ever forming an intermediate 1+something, so
// no cancellation occurs. 2^x - 1 = e^(x*ln2) - 1.
//
// This is NOT correctly rounded -- the x*kLn2 product is itself inexact, so
// about a third of in-domain results are 1 ULP off. It puts ppc64le in the same
// ~1-2 ULP class as ARM64's inline polynomial (Dispatcher.cpp:1301-1424), which
// is the bar. A Dekker split of ln2 would recover ~0.35 ULP if that is ever
// wanted. It also fixes a signed-zero bug the ARM64 path still has: Intel SDM
// requires F2XM1(-0) = -0, and only this form delivers it.
//
// Outside |x| <= 1 the result is architecturally undefined, but ARM64 defines
// it as exp2(x)-1 via its out-of-domain fallback, so match that exactly. Left
// unguarded, expm1(x*ln2) amplifies the product's rounding by |x*ln2| and
// diverges badly -- 404 ULP at x=1023.9, and at x=1024 it returns a finite
// value just under DBL_MAX where +Inf is required.
static double F64F2XM1Impl(double x) {
  // ln(2), correctly rounded: 0x3FE62E42FEFA39EF. Bit-identical to ARM64's C1.
  constexpr double kLn2 = 0.6931471805599453094172321214581766;
  // Written as !(fabs(x) <= 1.0) so NaN routes to the fallback, matching the
  // `b.hi` sense of ARM64's range check at Dispatcher.cpp:1324-1327.
  if (!(std::fabs(x) <= 1.0)) {
    return std::exp2(x) - 1.0;
  }
  return std::expm1(x * kLn2);
}
} // namespace

// Emit code to transfer VR element 0 (double) → f1 using slot A (r1-16).
// Must be called after SpillForABICall so r1 is 16-byte aligned.
#define MARSHAL_VR_TO_F1(VRSrc) \
  do { \
    addi(TMP1, r1, -16); \
    stvx((VRSrc), r(0), TMP1); \
    lfd(f(1), 0, TMP1); \
  } while (0)

// Emit code to transfer VR element 0 (double) → f2 using slot B (r1-32).
#define MARSHAL_VR_TO_F2(VRSrc) \
  do { \
    addi(TMP1, r1, -32); \
    stvx((VRSrc), r(0), TMP1); \
    lfd(f(2), 0, TMP1); \
  } while (0)

// Emit code to transfer f1 (double) → VR element 0, zeroing element 1.
// Uses slot A (r1-16); result loaded into DstVR.
#define MARSHAL_F1_TO_VR(DstVR) \
  do { \
    stfd(f(1), -16, r1); \
    li(TMP2, 0); \
    std(TMP2, -8, r1); \
    addi(TMP1, r1, -16); \
    lvx((DstVR), r(0), TMP1); \
  } while (0)

DEF_OP(F64SIN) {
  const auto Op  = IROp->C<IR::IROp_F64SIN>();
  const auto Src = GetVReg(Op->Src);
  const auto Dst = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64Sin);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

DEF_OP(F64COS) {
  const auto Op  = IROp->C<IR::IROp_F64COS>();
  const auto Src = GetVReg(Op->Src);
  const auto Dst = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64Cos);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

DEF_OP(F64TAN) {
  const auto Op  = IROp->C<IR::IROp_F64TAN>();
  const auto Src = GetVReg(Op->Src);
  const auto Dst = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64Tan);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

// F64ATAN: Src1=y (ST1), Src2=x (ST0) → atan2(y, x).
// ELFv2: f1=y, f2=x; result in f1.
DEF_OP(F64ATAN) {
  const auto Op   = IROp->C<IR::IROp_F64ATAN>();
  const auto Src1 = GetVReg(Op->Src1);  // y
  const auto Src2 = GetVReg(Op->Src2);  // x
  const auto Dst  = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src1);
  MARSHAL_VR_TO_F2(Src2);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64Atan);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

// F64FYL2X: Src=x (ST0), Src2=y (ST1) → y * log2(x).
// ELFv2: f1=x, f2=y; result in f1.
DEF_OP(F64FYL2X) {
  const auto Op   = IROp->C<IR::IROp_F64FYL2X>();
  const auto Src  = GetVReg(Op->Src);   // x
  const auto Src2 = GetVReg(Op->Src2);  // y
  const auto Dst  = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src);
  MARSHAL_VR_TO_F2(Src2);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64FYL2X);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

// F64SCALE: Src1=x (ST1), Src2=n (ST0) → x * 2^floor(n).
// ELFv2: f1=x, f2=n; result in f1.
DEF_OP(F64SCALE) {
  const auto Op   = IROp->C<IR::IROp_F64SCALE>();
  const auto Src1 = GetVReg(Op->Src1);  // x
  const auto Src2 = GetVReg(Op->Src2);  // n
  const auto Dst  = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src1);
  MARSHAL_VR_TO_F2(Src2);
  EmitLoadPPC64Helper(TMP1, PPC64_HELPER_F64Scale);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

DEF_OP(F64F2XM1) {
  const auto Op  = IROp->C<IR::IROp_F64F2XM1>();
  const auto Src = GetVReg(Op->Src);
  const auto Dst = GetVReg(Node);

  SpillForABICall(TMP1);
  MARSHAL_VR_TO_F1(Src);
  // S3.7-C5: route via the PPC64_HelperTable so the F64F2XM1Impl pointer
  // isn't baked into JIT code — under ASLR the impl address differs per
  // process, and no relocation can rewrite a bare LoadConstant. Any
  // cached block that reached this path would `bctrl` into a stale
  // address. Uses the local F64F2XM1Impl (in the helper table array
  // below), NOT Pointers.F64F2XM1Handler — the two have divergent
  // semantics; see the note above PPC64_HELPER_F64F2XM1 in JITClass.h.
  EmitLoadPPC64Helper(TMP1, ::FEXCore::CPU::PPC64_HELPER_F64F2XM1);
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();
  FillForABICall();
  MARSHAL_F1_TO_VR(Dst);
}

#undef MARSHAL_VR_TO_F1
#undef MARSHAL_VR_TO_F2
#undef MARSHAL_F1_TO_VR

// =========================================================================
// Crypto / hash software fallbacks.
//
// POWER8 has neither AES nor SHA hardware. These shims marshal vector args
// through an in-frame 16-byte buffer, call the C helper in JIT.cpp, and
// reload the destination via lvx. The mini-frame layout (96 bytes) is:
//
//   [r1+ 0]  back chain
//   [r1+ 8]  pad
//   [r1+16]  LR save (per ELFv2 caller frame layout)
//   [r1+24]  TOC save (r2) across the bctrl
//   [r1+32]  buf A (16-byte aligned, used as src1 input AND dst output)
//   [r1+48]  buf B (16-byte aligned, src2)
//   [r1+64]  buf C (16-byte aligned, src3 — reserved for future use)
//   [r1+80..95] pad
//
// SpillForABICall further drops r1 by the PushDynamicRegs frame size
// (x64::kDynRegSaveSize / x32::kDynRegSaveSize, ArchHelpers/PPC64Emitter.h),
// so post-spill offsets add that — see PostSpill() at each callsite. Do not
// write the number here; it is derived from the register pool sizes.
// Helpers in JIT.cpp are declared extern "C"; we materialise their address
// as a 64-bit literal and call via r12 per ELFv2 indirect-call ABI.
// =========================================================================
extern "C" void PPC64_VAESEnc(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VAESEncLast(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VAESDec(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VAESDecLast(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VAESImc(uint8_t*, const uint8_t*);
extern "C" void PPC64_VAESKeyGenAssist(uint8_t*, const uint8_t*, uint64_t RCON);
extern "C" uint64_t PPC64_CRC32(uint64_t Acc, uint64_t Val, uint64_t Bytes);
extern "C" void PPC64_PCLMUL(uint8_t*, const uint8_t*, const uint8_t*, uint64_t Selector);
extern "C" void PPC64_VSha1H(uint8_t*, const uint8_t*);
// SSE4.2 string ops (implemented in JIT.cpp).
extern "C" uint64_t PPC64_VPCMPESTRX(const uint8_t* lhs, const uint8_t* rhs,
                                     uint64_t la, uint64_t ra, uint64_t imm);
extern "C" uint64_t PPC64_VPCMPISTRX(const uint8_t* lhs, const uint8_t* rhs,
                                     uint64_t imm);
// Split-lock emulation (implemented in FEXCore/Source/Utils/ArchHelpers/PPC64.cpp).
namespace FEXCore::ArchHelpers::PPC64 {
extern "C" void PPC64_SplitLockEmulate(uint8_t op, uint64_t* addr, uint64_t* value,
                                       uint64_t* result, uint32_t size);
}
extern "C" void PPC64_VSha1C(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha1M(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha1P(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha1SU1(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha256H(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha256H2(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha256U0(uint8_t*, const uint8_t*, const uint8_t*);
extern "C" void PPC64_VSha256U1(uint8_t*, const uint8_t*, const uint8_t*);
// (F16C externs are hoisted to the top of the file — see above.)

// -------------------------------------------------------------------------
// PPC64 helper-address table (P2.1 C1 — infrastructure only)
// -------------------------------------------------------------------------
// Static array of the host-function addresses that JIT-emitted call sites
// need to reach. Sits at namespace-scope in this file because most helpers
// (F64* impls in anon-ns above, plus the PPC64_V* crypto helpers whose
// extern "C" prototypes are in this file) are only lookup-visible here.
// A CpuStateFrame pointer field (CoreState.h::PPC64_HelperTable) is
// initialised in PPC64JITCore's constructor via GetPPC64HelperTable() to
// point at this array. JIT emitters replace absolute-address bakes with
// `ld TMP1, PPC64_HelperTable_off(STATE); ld TMP1, IDX*8(TMP1); mtctr TMP1;
// bctrl`.  Uses C99-style designated initializers to make the mapping
// enum ↔ helper impossible to get subtly wrong. Enumerator additions
// require a matching row here.
namespace {
static const uint64_t PPC64Helpers[::FEXCore::CPU::PPC64_HELPER_MAX] = {
  [::FEXCore::CPU::PPC64_HELPER_SplitLockEmulate] =
      reinterpret_cast<uint64_t>(&FEXCore::ArchHelpers::PPC64::PPC64_SplitLockEmulate),
  [::FEXCore::CPU::PPC64_HELPER_F16HiToF32x4]     = reinterpret_cast<uint64_t>(&PPC64_F16HiToF32x4),
  [::FEXCore::CPU::PPC64_HELPER_F32x4ToF16Hi]     = reinterpret_cast<uint64_t>(&PPC64_F32x4ToF16Hi),
  [::FEXCore::CPU::PPC64_HELPER_F64Sin]           = reinterpret_cast<uint64_t>(F64SinImpl),
  [::FEXCore::CPU::PPC64_HELPER_F64Cos]           = reinterpret_cast<uint64_t>(F64CosImpl),
  [::FEXCore::CPU::PPC64_HELPER_F64Tan]           = reinterpret_cast<uint64_t>(F64TanImpl),
  [::FEXCore::CPU::PPC64_HELPER_F64Atan]          = reinterpret_cast<uint64_t>(F64AtanImpl),
  [::FEXCore::CPU::PPC64_HELPER_F64FYL2X]         = reinterpret_cast<uint64_t>(F64FYL2XImpl),
  [::FEXCore::CPU::PPC64_HELPER_F64Scale]         = reinterpret_cast<uint64_t>(F64ScaleImpl),
  [::FEXCore::CPU::PPC64_HELPER_VAESImc]          = reinterpret_cast<uint64_t>(&PPC64_VAESImc),
  [::FEXCore::CPU::PPC64_HELPER_VAESKeyGenAssist] = reinterpret_cast<uint64_t>(&PPC64_VAESKeyGenAssist),
  [::FEXCore::CPU::PPC64_HELPER_VAESEnc]          = reinterpret_cast<uint64_t>(&PPC64_VAESEnc),
  [::FEXCore::CPU::PPC64_HELPER_VAESEncLast]      = reinterpret_cast<uint64_t>(&PPC64_VAESEncLast),
  [::FEXCore::CPU::PPC64_HELPER_VAESDec]          = reinterpret_cast<uint64_t>(&PPC64_VAESDec),
  [::FEXCore::CPU::PPC64_HELPER_VAESDecLast]      = reinterpret_cast<uint64_t>(&PPC64_VAESDecLast),
  [::FEXCore::CPU::PPC64_HELPER_VSha1H]           = reinterpret_cast<uint64_t>(&PPC64_VSha1H),
  [::FEXCore::CPU::PPC64_HELPER_VSha1C]           = reinterpret_cast<uint64_t>(&PPC64_VSha1C),
  [::FEXCore::CPU::PPC64_HELPER_VSha1M]           = reinterpret_cast<uint64_t>(&PPC64_VSha1M),
  [::FEXCore::CPU::PPC64_HELPER_VSha1P]           = reinterpret_cast<uint64_t>(&PPC64_VSha1P),
  [::FEXCore::CPU::PPC64_HELPER_VSha1SU1]         = reinterpret_cast<uint64_t>(&PPC64_VSha1SU1),
  [::FEXCore::CPU::PPC64_HELPER_VSha256H]         = reinterpret_cast<uint64_t>(&PPC64_VSha256H),
  [::FEXCore::CPU::PPC64_HELPER_VSha256H2]        = reinterpret_cast<uint64_t>(&PPC64_VSha256H2),
  [::FEXCore::CPU::PPC64_HELPER_VSha256U0]        = reinterpret_cast<uint64_t>(&PPC64_VSha256U0),
  [::FEXCore::CPU::PPC64_HELPER_VSha256U1]        = reinterpret_cast<uint64_t>(&PPC64_VSha256U1),
  [::FEXCore::CPU::PPC64_HELPER_PCLMUL]           = reinterpret_cast<uint64_t>(&PPC64_PCLMUL),
  [::FEXCore::CPU::PPC64_HELPER_RDRAND]           = reinterpret_cast<uint64_t>(&PPC64_RDRAND),
  [::FEXCore::CPU::PPC64_HELPER_CRC32]            = reinterpret_cast<uint64_t>(&PPC64_CRC32),
  [::FEXCore::CPU::PPC64_HELPER_VPCMPESTRX]       = reinterpret_cast<uint64_t>(&PPC64_VPCMPESTRX),
  [::FEXCore::CPU::PPC64_HELPER_VPCMPISTRX]       = reinterpret_cast<uint64_t>(&PPC64_VPCMPISTRX),
  [::FEXCore::CPU::PPC64_HELPER_F64F2XM1]         = reinterpret_cast<uint64_t>(F64F2XM1Impl),
};
} // namespace

// Handed to CpuStateFrame::PPC64_HelperTable at thread-JIT construction.
// The pointer is stable for program lifetime.
uint64_t* GetPPC64HelperTable() {
  return const_cast<uint64_t*>(PPC64Helpers);
}

// (Crypto FABI mini-frame constants are hoisted to the top of the file so
// that DEF_OP(Vector_FToF)'s F16C path — which appears earlier in the file —
// can use the same FABI mini-frame plumbing. See top-of-file anonymous
// namespace.  Layout:
//   [r1+ 0]  back chain
//   [r1+ 8]  pad
//   [r1+16]  LR save (per ELFv2 caller frame layout)
//   [r1+24]  TOC save (r2) across the bctrl
//   [r1+32]  Slot A — primary vector input + dst output
//   [r1+48]  Slot B — secondary vector input
//   [r1+64]  Slot C — reserved (e.g. 3rd vector input for SHA1C)
//   [r1+80..95]  pad)

DEF_OP(VAESImc) {
  const auto Op  = IROp->C<IR::IROp_VAESImc>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);
  const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };

  stdu(r1, -CryptoMiniFrameSize, r1);
  mflr(r(0)); std(r(0), 16, r1);

  // Stage Src to slot A BEFORE SpillForABICall (the spill clobbers VRs we're
  // not using, but we must commit live SRA-allocated regs ourselves).
  LoadConstant(TMP1, CryptoSlotA);
  stvx(Src, r1, TMP1);

  SpillForABICall(TMP1);


  // r3 = &dstbuf (slot A reused), r4 = &srcbuf (slot A) — same buffer is fine,
  // helper copies src→local before writing.
  addi(r3, r1, PostSpill(CryptoSlotA));
  addi(r4, r1, PostSpill(CryptoSlotA));
  EmitLoadPPC64Helper(r(12), PPC64_HELPER_VAESImc);
  std(r2, PostSpill(24), r1);
  mtctr(r(12)); bctrl();
  ld(r2, PostSpill(24), r1);


  FillForABICall();

  LoadConstant(TMP1, CryptoSlotA);
  lvx(Dst, r1, TMP1);

  ld(r(0), 16, r1); mtlr(r(0));
  addi(r1, r1, CryptoMiniFrameSize);
  li(r(0), 0);
}

// Common emitter for the 3-VR-arg AES round ops (Enc/EncLast/Dec/DecLast).
// Slot A: State→dst.  Slot B: Key.  ZeroReg is unused (helpers operate on
// State directly; the ARM "aese with ZeroReg" pattern does state^0 = state).
// HelperIdx: PPC64_HELPER_* enumerator naming the target helper.
#define EMIT_AES_ROUND(HelperIdx, StateReg, KeyReg, DstReg)                  \
  do {                                                                       \
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize); \
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; }; \
    stdu(r1, -CryptoMiniFrameSize, r1);                                      \
    mflr(r(0)); std(r(0), 16, r1);                                            \
    LoadConstant(TMP1, CryptoSlotA); stvx((StateReg), r1, TMP1);             \
    LoadConstant(TMP1, CryptoSlotB); stvx((KeyReg),   r1, TMP1);             \
    SpillForABICall(TMP1);                                                   \
    addi(r3, r1, PostSpill(CryptoSlotA));                                    \
    addi(r4, r1, PostSpill(CryptoSlotA));                                    \
    addi(r5, r1, PostSpill(CryptoSlotB));                                    \
    EmitLoadPPC64Helper(r(12), (HelperIdx));                                 \
    std(r2, PostSpill(24), r1);                                              \
    mtctr(r(12)); bctrl();                                                   \
    ld(r2, PostSpill(24), r1);                                               \
    FillForABICall();                                                        \
    LoadConstant(TMP1, CryptoSlotA); lvx((DstReg), r1, TMP1);                \
    ld(r(0), 16, r1); mtlr(r(0));                                             \
    addi(r1, r1, CryptoMiniFrameSize);                                       \
    li(r(0), 0);                                                             \
  } while (0)

DEF_OP(VAESEnc) {
  if (IROp->Size != IR::OpSize::i128Bit) { Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESEnc>();
  EMIT_AES_ROUND(PPC64_HELPER_VAESEnc, GetVReg(Op->State), GetVReg(Op->Key), GetVReg(Node));
}

DEF_OP(VAESEncLast) {
  if (IROp->Size != IR::OpSize::i128Bit) { Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESEncLast>();
  EMIT_AES_ROUND(PPC64_HELPER_VAESEncLast, GetVReg(Op->State), GetVReg(Op->Key), GetVReg(Node));
}

DEF_OP(VAESDec) {
  if (IROp->Size != IR::OpSize::i128Bit) { Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESDec>();
  EMIT_AES_ROUND(PPC64_HELPER_VAESDec, GetVReg(Op->State), GetVReg(Op->Key), GetVReg(Node));
}

DEF_OP(VAESDecLast) {
  if (IROp->Size != IR::OpSize::i128Bit) { Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESDecLast>();
  EMIT_AES_ROUND(PPC64_HELPER_VAESDecLast, GetVReg(Op->State), GetVReg(Op->Key), GetVReg(Node));
}
#undef EMIT_AES_ROUND

DEF_OP(VAESKeyGenAssist) {
  const auto Op  = IROp->C<IR::IROp_VAESKeyGenAssist>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Src);
  const uint64_t RCON = static_cast<uint64_t>(Op->RCON);
  const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };
  // KeyGenTBLSwizzle and ZeroReg are unused — the helper computes the x86
  // result directly. They remain valid IR sources (so RA keeps the live
  // ranges sound), but no host instruction reads them here.

  stdu(r1, -CryptoMiniFrameSize, r1);
  mflr(r(0)); std(r(0), 16, r1);
  LoadConstant(TMP1, CryptoSlotA); stvx(Src, r1, TMP1);

  SpillForABICall(TMP1);


  addi(r3, r1, PostSpill(CryptoSlotA));
  addi(r4, r1, PostSpill(CryptoSlotA));
  LoadConstant(r5, RCON);
  EmitLoadPPC64Helper(r(12), PPC64_HELPER_VAESKeyGenAssist);
  std(r2, PostSpill(24), r1);
  mtctr(r(12)); bctrl();
  ld(r2, PostSpill(24), r1);


  FillForABICall();

  LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
  ld(r(0), 16, r1); mtlr(r(0));
  addi(r1, r1, CryptoMiniFrameSize);
  li(r(0), 0);
}

// VSha1H: rotate-left 30 of element 0 (32-bit), upper lanes zeroed.
// Trivial enough that we could inline-emit it, but we already have a helper
// and consistency with the rest of the SHA path is more readable.
DEF_OP(VSha1H) {
  const auto Op  = IROp->C<IR::IROp_VSha1H>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Src);
  const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };

  stdu(r1, -CryptoMiniFrameSize, r1);
  mflr(r(0)); std(r(0), 16, r1);
  LoadConstant(TMP1, CryptoSlotA); stvx(Src, r1, TMP1);

  SpillForABICall(TMP1);


  addi(r3, r1, PostSpill(CryptoSlotA));
  addi(r4, r1, PostSpill(CryptoSlotA));
  EmitLoadPPC64Helper(r(12), PPC64_HELPER_VSha1H);
  std(r2, PostSpill(24), r1);
  mtctr(r(12)); bctrl();
  ld(r2, PostSpill(24), r1);


  FillForABICall();

  LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
  ld(r(0), 16, r1); mtlr(r(0));
  addi(r1, r1, CryptoMiniFrameSize);
  li(r(0), 0);
}

// SHA1 / SHA256 round-step ops. POWER8 has no hardware SHA-NI, so each
// primitive routes through a software helper in JIT.cpp (PPC64_VSha*) via
// the same FABI mini-frame used for AES/PCLMUL. The helpers implement the
// ARMv8 SHA1*/SHA256* instructions exactly (FIPS-180-4 primitives), since
// the IR ops mirror that semantic — the x86 SHA-NI dispatcher already
// pre-shuffles inputs to the ARM lane layout (see Crypto.cpp).

// 3-VR-arg SHA round-step emitter: A/B/C → slots, helper(dst=A, A, B, C).
// HelperIdx: PPC64_HELPER_* enumerator naming the target helper.
#define EMIT_SHA_3ARG(HelperIdx, Src1Reg, Src2Reg, Src3Reg, DstReg)           \
  do {                                                                       \
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize); \
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; }; \
    stdu(r1, -CryptoMiniFrameSize, r1);                                      \
    mflr(r(0)); std(r(0), 16, r1);                                            \
    LoadConstant(TMP1, CryptoSlotA); stvx((Src1Reg), r1, TMP1);              \
    LoadConstant(TMP1, CryptoSlotB); stvx((Src2Reg), r1, TMP1);              \
    LoadConstant(TMP1, CryptoSlotC); stvx((Src3Reg), r1, TMP1);              \
    SpillForABICall(TMP1);                                                   \
    addi(r3, r1, PostSpill(CryptoSlotA));                                    \
    addi(r4, r1, PostSpill(CryptoSlotA));                                    \
    addi(r5, r1, PostSpill(CryptoSlotB));                                    \
    addi(r6, r1, PostSpill(CryptoSlotC));                                    \
    EmitLoadPPC64Helper(r(12), (HelperIdx));                                 \
    std(r2, PostSpill(24), r1);                                              \
    mtctr(r(12)); bctrl();                                                   \
    ld(r2, PostSpill(24), r1);                                               \
    FillForABICall();                                                        \
    LoadConstant(TMP1, CryptoSlotA); lvx((DstReg), r1, TMP1);                \
    ld(r(0), 16, r1); mtlr(r(0));                                             \
    addi(r1, r1, CryptoMiniFrameSize);                                       \
    li(r(0), 0);                                                             \
  } while (0)

// 2-VR-arg SHA emitter: A/B → slots, helper(dst=A, A, B).
// HelperIdx: PPC64_HELPER_* enumerator naming the target helper.
#define EMIT_SHA_2ARG(HelperIdx, Src1Reg, Src2Reg, DstReg)                    \
  do {                                                                       \
    const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize); \
    const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; }; \
    stdu(r1, -CryptoMiniFrameSize, r1);                                      \
    mflr(r(0)); std(r(0), 16, r1);                                            \
    LoadConstant(TMP1, CryptoSlotA); stvx((Src1Reg), r1, TMP1);              \
    LoadConstant(TMP1, CryptoSlotB); stvx((Src2Reg), r1, TMP1);              \
    SpillForABICall(TMP1);                                                   \
    addi(r3, r1, PostSpill(CryptoSlotA));                                    \
    addi(r4, r1, PostSpill(CryptoSlotA));                                    \
    addi(r5, r1, PostSpill(CryptoSlotB));                                    \
    EmitLoadPPC64Helper(r(12), (HelperIdx));                                 \
    std(r2, PostSpill(24), r1);                                              \
    mtctr(r(12)); bctrl();                                                   \
    ld(r2, PostSpill(24), r1);                                               \
    FillForABICall();                                                        \
    LoadConstant(TMP1, CryptoSlotA); lvx((DstReg), r1, TMP1);                \
    ld(r(0), 16, r1); mtlr(r(0));                                             \
    addi(r1, r1, CryptoMiniFrameSize);                                       \
    li(r(0), 0);                                                             \
  } while (0)

DEF_OP(VSha1C) {
  const auto Op = IROp->C<IR::IROp_VSha1C>();
  EMIT_SHA_3ARG(PPC64_HELPER_VSha1C, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), GetVReg(Node));
}
DEF_OP(VSha1M) {
  const auto Op = IROp->C<IR::IROp_VSha1M>();
  EMIT_SHA_3ARG(PPC64_HELPER_VSha1M, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), GetVReg(Node));
}
DEF_OP(VSha1P) {
  const auto Op = IROp->C<IR::IROp_VSha1P>();
  EMIT_SHA_3ARG(PPC64_HELPER_VSha1P, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), GetVReg(Node));
}
DEF_OP(VSha1SU1) {
  const auto Op = IROp->C<IR::IROp_VSha1SU1>();
  EMIT_SHA_2ARG(PPC64_HELPER_VSha1SU1, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Node));
}
DEF_OP(VSha256H) {
  const auto Op = IROp->C<IR::IROp_VSha256H>();
  EMIT_SHA_3ARG(PPC64_HELPER_VSha256H, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), GetVReg(Node));
}
DEF_OP(VSha256H2) {
  const auto Op = IROp->C<IR::IROp_VSha256H2>();
  EMIT_SHA_3ARG(PPC64_HELPER_VSha256H2, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), GetVReg(Node));
}
DEF_OP(VSha256U0) {
  const auto Op = IROp->C<IR::IROp_VSha256U0>();
  EMIT_SHA_2ARG(PPC64_HELPER_VSha256U0, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Node));
}
DEF_OP(VSha256U1) {
  const auto Op = IROp->C<IR::IROp_VSha256U1>();
  EMIT_SHA_2ARG(PPC64_HELPER_VSha256U1, GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Node));
}

#undef EMIT_SHA_3ARG
#undef EMIT_SHA_2ARG

DEF_OP(PCLMUL) {
  const auto Op   = IROp->C<IR::IROp_PCLMUL>();
  const auto Dst  = GetVReg(Node);
  const auto Src1 = GetVReg(Op->Src1);
  const auto Src2 = GetVReg(Op->Src2);
  const uint64_t Selector = static_cast<uint64_t>(Op->Selector);
  const int CryptoSpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const auto PostSpill = [&](int Off) { return Off + CryptoSpillSaveSize; };

  // Only 128-bit PCLMUL is supported here; VPCLMULQDQ on 256-bit operands
  // would need two helper invocations, which we leave for later.
  if (IROp->Size != IR::OpSize::i128Bit) {
    Op_Unhandled(IROp, Node);
    return;
  }

  stdu(r1, -CryptoMiniFrameSize, r1);
  mflr(r(0)); std(r(0), 16, r1);
  LoadConstant(TMP1, CryptoSlotA); stvx(Src1, r1, TMP1);
  LoadConstant(TMP1, CryptoSlotB); stvx(Src2, r1, TMP1);

  SpillForABICall(TMP1);


  addi(r3, r1, PostSpill(CryptoSlotA));   // dst (reuses slot A)
  addi(r4, r1, PostSpill(CryptoSlotA));   // src1
  addi(r5, r1, PostSpill(CryptoSlotB));   // src2
  LoadConstant(r6, Selector);
  EmitLoadPPC64Helper(r(12), PPC64_HELPER_PCLMUL);
  std(r2, PostSpill(24), r1);
  mtctr(r(12)); bctrl();
  ld(r2, PostSpill(24), r1);


  FillForABICall();

  LoadConstant(TMP1, CryptoSlotA); lvx(Dst, r1, TMP1);
  ld(r(0), 16, r1); mtlr(r(0));
  addi(r1, r1, CryptoMiniFrameSize);
  li(r(0), 0);
}

} // namespace FEXCore::CPU
