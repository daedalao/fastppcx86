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
    // Table entries are 16-byte aligned (IR.json: "Index needs to be
    // aligned register size"). The byte-reverse vperm that used to follow
    // was an identity permute, same proof as LoadNamedVectorConstant:
    // LE-mode lvx already reverses, and the control loaded through the
    // same reversing lvx composed to identity (lnvc_probe.c, 2026-08-03).
    lvx(Dst, TMP1, r0);
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
    mtvsrd(VTMP1, TMP2);
    vspltisb(Dst, 0);
    xxpermdi(Dst, Dst, VTMP1, 0b00); // zero:phys[0..7], value:phys[8..15]
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
    // 1.0 / Src per lane. The old comment claimed POWER8 lacks xvredp - it
    // does exist (ISA 2.06) but is an ESTIMATE; the precise-divide semantic
    // wanted here is xvdivdp, same operation the old per-lane fdiv
    // stack-roundtrip computed, minus the spill and two store-hit-loads.
    EmitLoadPPC64VConst(VTMP1, PPC64_VCONST_F64_ONE, TMP1, TMP2);
    xvdivdp(Dst, VTMP1, Src);
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
    // 1.0 / sqrt(x) per lane: precise sqrt then precise vector divide,
    // replacing the per-lane fdiv stack roundtrip.
    xvsqrtdp(VTMP2, Src);
    EmitLoadPPC64VConst(VTMP1, PPC64_VCONST_F64_ONE, TMP1, TMP2);
    xvdivdp(Dst, VTMP1, VTMP2);
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
    // Same shift-count splat as VUShrI i64Bit: see BuildSplatDW.
    li(TMP4, static_cast<int16_t>(Shift));
    mtvsrd(VTMP1, TMP4);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
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
    // → mask PPC bytes [8..15] = [02,03,06,07, 0A,0B,0E,0F], PPC bytes [0..7]
    //   all zero.  That is exactly vpkuwum(Dst, ZERO, VTMP2): vpkuwum keeps
    //   the low halfword of each BE word, VRA's four into phys[0..7] and
    //   VRB's four into phys[8..15].  Hardware-verified ("VUShrNI i32->i16").
    vspltisw(VTMP1, (int32_t)N);
    vsrw(VTMP2, Vec, VTMP1);
    vspltisw(VTMP1, 0);
    vpkuwum(Dst, VTMP1, VTMP2);
  } else if (OutSz == IR::OpSize::i8Bit) {
    // i16→i8 narrow.  Source: VTMP2 = vsrh(Vec, N).  Output i8 lane i at
    // LE byte i = out PPC byte (15-i).  Source low byte of LE i16 lane i
    // sits at src PPC byte (15-2i).
    //   out PPC[15-i] = src PPC[15-2i]    (i=0..7)
    // i=0: out 15←src 15  i=1: out 14←src 13 … i=7: out 8←src 1
    // → mask PPC bytes [8..15] = [01,03,05,07, 09,0B,0D,0F], [0..7] zero =
    //   vpkuhum(Dst, ZERO, VTMP2).  Hardware-verified ("VUShrNI i16->i8").
    vspltish(VTMP1, (int16_t)N);
    vsrh(VTMP2, Vec, VTMP1);
    vspltisw(VTMP1, 0);
    vpkuhum(Dst, VTMP1, VTMP2);
  } else if (OutSz == IR::OpSize::i32Bit) {
    // i64→i32 narrow.  Source: VTMP2 = vsrd(Vec, N).  Source low 32 bits
    // of LE i64 lane i at src PPC bytes [15-8i..12-8i] (LSB at 15-8i, MSB
    // at 12-8i).  Output i32 lane i at out PPC bytes [15-4i..12-4i].
    //   i=0: out 15..12 ← src 15..12
    //   i=1: out 11..8  ← src  7..4
    // → mask PPC bytes [8..15] = [04,05,06,07, 0C,0D,0E,0F], [0..7] zero =
    //   vpkudum(Dst, ZERO, VTMP2).  Hardware-verified ("VUShrNI i64->i32").
    LoadConstant(TMP1, (uint64_t)N);
    mtvsrd(VTMP1, TMP1);
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrd(VTMP2, Vec, VTMP1);
    vspltisw(VTMP1, 0);
    vpkudum(Dst, VTMP1, VTMP2);
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
    // → mask PPC bytes [0..7] = [02,03,06,07, 0A,0B,0E,0F], PPC bytes [8..15]
    //   preserve VLow PPC[8..15].
    // Split into the same narrow-pack VUShrNI uses (vpkuwum against zero puts
    // the gathered halfwords at VTMP2.phys[8..15] = dw1) followed by a
    // dw-blend: Dst.dw0 = narrowed.dw1, Dst.dw1 = VLow.dw1 = xxpermdi(...,3).
    // Hardware-verified ("VUShrNI2 i32->i16").
    vspltw(VTMP1, VTMP1, 1);
    vsrw(VTMP2, VUpp, VTMP1);
    vspltisw(VTMP1, 0);
    vpkuwum(VTMP2, VTMP1, VTMP2);
    xxpermdi(Dst, VTMP2, VLow, 3);
  } else if (OutSz == IR::OpSize::i8Bit) {
    // i16→i8 narrow on VUpp, insert into upper LE half of VLow.
    // Hardware-verified ("VUShrNI2 i16->i8").
    vsplth(VTMP1, VTMP1, 3);
    vsrh(VTMP2, VUpp, VTMP1);
    vspltisw(VTMP1, 0);
    vpkuhum(VTMP2, VTMP1, VTMP2);
    xxpermdi(Dst, VTMP2, VLow, 3);
  } else if (OutSz == IR::OpSize::i32Bit) {
    // i64→i32 narrow on VUpp, insert into upper LE half of VLow.
    // Hardware-verified ("VUShrNI2 i64->i32").
    xxpermdi(VTMP1, VTMP1, VTMP1, 0);
    vsrd(VTMP2, VUpp, VTMP1);
    vspltisw(VTMP1, 0);
    vpkudum(VTMP2, VTMP1, VTMP2);
    xxpermdi(Dst, VTMP2, VLow, 3);
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
  // Step 2: blend directly out of the pack result — Dst.dw0 must be the
  // narrowed VUpp (which vpkXXss already left at VTMP2.phys[8..15] = dw1)
  // and Dst.dw1 must be VLow.dw1.  That is xxpermdi(Dst, VTMP2, VLow, 3),
  // which subsumes the old `vsldoi ...,8` staging step (now deleted) and the
  // whole perm-control materialisation.  Hardware-verified against the old
  // sequence on POWER8 ("VSQXTN2 i8" / "VSQXTN2 i16").
  xxpermdi(Dst, VTMP2, VLow, 3);
}

DEF_OP(VSQXTNPair) {
  const auto Op     = IROp->C<IR::IROp_VSQXTNPair>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto VLow   = GetVReg(Op->VectorLower);
  const auto VUpp   = GetVReg(Op->VectorUpper);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX: valid data is only in LE bytes 0-7 (phys dw1); the upper
    // doubleword of an MMX-carrying vector is not guaranteed zero.  Packing a
    // source register whole therefore folds saturated junk from its upper
    // half into LE bytes 4-7 of the result (Portal 2 mixer: volume words 2-3
    // became [0x7FFF, 0], every odd frame mixed at garbage gain).
    // Merge the two payload doublewords first, then pack once against zero:
    //   VTMP1.phys_dw0 = VUpp payload, VTMP1.phys_dw1 = VLow payload
    //   => VTMP1.LE_w[0..3] = [VLow.d0, VLow.d1, VUpp.d0, VUpp.d1]
    xxpermdi(VTMP1, VUpp, VLow, 3);
    vspltisw(VTMP2, 0);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vpkshss(Dst, VTMP2, VTMP1); break;
    case IR::OpSize::i16Bit: vpkswss(Dst, VTMP2, VTMP1); break;
    default: Op_Unhandled(IROp, Node); return;
    }
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
  // Same dw-blend as VSQXTN2 (the `vsldoi ...,8` staging step is subsumed).
  // Hardware-verified ("VSQXTUN2 i8" / "VSQXTUN2 i16").
  xxpermdi(Dst, VTMP2, VLow, 3);
}

DEF_OP(VSQXTUNPair) {
  const auto Op     = IROp->C<IR::IROp_VSQXTUNPair>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Dst    = GetVReg(Node);
  const auto VLow   = GetVReg(Op->VectorLower);
  const auto VUpp   = GetVReg(Op->VectorUpper);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // MMX: same payload-merge as VSQXTNPair — never pack the raw sources,
    // their upper doublewords may hold junk.
    xxpermdi(VTMP1, VUpp, VLow, 3);
    vspltisw(VTMP2, 0);
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  vpkshus(Dst, VTMP2, VTMP1); break;
    case IR::OpSize::i16Bit: vpkswus(Dst, VTMP2, VTMP1); break;
    default: Op_Unhandled(IROp, Node); return;
    }
    return;
  }

  switch (ElemSz) {
  case IR::OpSize::i8Bit:  vpkshus(Dst, VUpp, VLow); break;
  case IR::OpSize::i16Bit: vpkswus(Dst, VUpp, VLow); break;
  default: Op_Unhandled(IROp, Node); break;
  }
}

// Build a vector with `val` replicated to every doubleword.
// Used when an immediate exceeds the 5-bit range of vspltisb/h/w.
//
// mtvsrd defines the doubleword that xxpermdi index 0 reads (BE dword 0, the
// half mfvsrd/mtvsrd see, which is FEX's LE element 1); dm=0 then duplicates
// that half into both. Byte-for-byte identical to the std/std/lvx roundtrip
// this replaces -- verified on POWER8 by storing both forms back through stvx
// and comparing the 16 bytes -- but without the guaranteed store-hit-load
// stall of feeding a vector load from two GPR stores issued two cycles
// earlier.
static void BuildSplatDW(PPC64JITCore* j, VR Dst, uint64_t val) {
  j->LoadConstant(TMP4, val);
  j->mtvsrd(Dst, TMP4);
  j->xxpermdi(Dst, Dst, Dst, 0);
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
      // NOT sradi: PPC arithmetic shifts write XER.CA, the canonical guest CF
      // (see DEF_OP(Ashr)'s block comment), and PSIGN/rounding-shift guests
      // preserve EFLAGS. srdi (rldicl, no XER) is exact here: the value is
      // 64-bit sign-extended and only the low sz*8 bits are stored, so the
      // logical/arithmetic difference lives entirely in discarded bits
      // (sz*8 + N <= 64 always: sz*8 <= 32, N < sz*8).
      srdi(TMP1, TMP1, N);
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
    cmpd(cr(1), TMP4, TMP2);  // cr(1) so CR0 (packed NZCV) is preserved
    auto Saturate = PPC64Emitter::Label{};
    auto Done     = PPC64Emitter::Label{};
    bc({4, 6}, &Saturate);    // bne on CR1.EQ
    switch (sz) {
    case 1: stb(TMP2, Off, r1); break;
    case 2: sth(TMP2, Off, r1); break;
    case 4: stw(TMP2, Off, r1); break;
    case 8: std(TMP2, Off, r1); break;
    }
    b(&Done);
    Bind(&Saturate);
    // sign = 0 (pos) or -1 (neg); sat = sign XOR SatPos. NOT sradi — it
    // writes XER.CA (guest CF; see DEF_OP(Ashr)). rldicl isolates the sign
    // bit and neg splats it; neither touches XER.
    rldicl(TMP2, TMP1, 1, 63);
    neg(TMP2, TMP2);
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
  // Perm controls now live in the vconst pool (12 variants: even/odd x
  // 3 element sizes x 128-bit/MMX layouts, byte values unchanged from the
  // inline builds this replaces — see the pool initializer). Each control
  // load is 3 instructions with no store-queue traffic, versus a
  // LoadConstant+std+std+lvx store-hit-load per constant per emission.
  PPC64VConstIndex EvenIdx, OddIdx;
  if (RegSz == IR::OpSize::i64Bit) {
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  EvenIdx = PPC64_VCONST_ADDP_EVEN_B64; OddIdx = PPC64_VCONST_ADDP_ODD_B64; break;
    case IR::OpSize::i16Bit: EvenIdx = PPC64_VCONST_ADDP_EVEN_H64; OddIdx = PPC64_VCONST_ADDP_ODD_H64; break;
    case IR::OpSize::i32Bit: EvenIdx = PPC64_VCONST_ADDP_EVEN_W64; OddIdx = PPC64_VCONST_ADDP_ODD_W64; break;
    default: Op_Unhandled(IROp, Node); return;
    }
  } else {
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  EvenIdx = PPC64_VCONST_ADDP_EVEN_B; OddIdx = PPC64_VCONST_ADDP_ODD_B; break;
    case IR::OpSize::i16Bit: EvenIdx = PPC64_VCONST_ADDP_EVEN_H; OddIdx = PPC64_VCONST_ADDP_ODD_H; break;
    case IR::OpSize::i32Bit: EvenIdx = PPC64_VCONST_ADDP_EVEN_W; OddIdx = PPC64_VCONST_ADDP_ODD_W; break;
    default: Op_Unhandled(IROp, Node); return;
    }
  }

  // VTMP1/VTMP2 (VR30/VR31) are never in the allocator pool so safe as scratch.
  EmitLoadPPC64VConst(VTMP1, EvenIdx, TMP1, TMP2);
  vperm(VTMP2, VL, VU, VTMP1);
  EmitLoadPPC64VConst(VTMP1, OddIdx, TMP1, TMP2);
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
    // The even-gather controls are byte-identical to VAddP's MMX even
    // selectors — reuse those pool entries instead of an inline build.
    PPC64VConstIndex Idx;
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  Idx = PPC64_VCONST_ADDP_EVEN_B64; break;
    case IR::OpSize::i16Bit: Idx = PPC64_VCONST_ADDP_EVEN_H64; break;
    case IR::OpSize::i32Bit: Idx = PPC64_VCONST_ADDP_EVEN_W64; break;
    default: Op_Unhandled(IROp, Node); return;
    }
    EmitLoadPPC64VConst(VTMP1, Idx, TMP1, TMP2);
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
    // Byte-identical to VAddP's MMX odd selectors — reuse the pool entries.
    PPC64VConstIndex Idx;
    switch (ElemSz) {
    case IR::OpSize::i8Bit:  Idx = PPC64_VCONST_ADDP_ODD_B64; break;
    case IR::OpSize::i16Bit: Idx = PPC64_VCONST_ADDP_ODD_H64; break;
    case IR::OpSize::i32Bit: Idx = PPC64_VCONST_ADDP_ODD_W64; break;
    default: Op_Unhandled(IROp, Node); return;
    }
    EmitLoadPPC64VConst(VTMP1, Idx, TMP1, TMP2);
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
  // mtvsrd staging: no stack round-trip, no store-forwarding stall
  // (docs/EMITTER_REVIEW.md finding 2). Image identical to the old
  // std(-16)/std(-8)/lvx: the -16 value (hi) lands in phys[8..15] and the
  // -8 value (lo) in phys[0..7]; mtvsrd's dw0 carries each 64-bit value
  // MSB-first, exactly as the LE store + reversing lvx did.
  LoadConstant(TMP2, lo);
  mtvsrd(Dst, TMP2);      // lo -> dw0 -> phys[0..7] after merge
  LoadConstant(TMP2, hi);
  mtvsrd(VTMP2, TMP2);    // hi -> dw0
  xxpermdi(Dst, Dst, VTMP2, 0b00); // dw0=lo(phys[0..7]), dw1=hi(phys[8..15])
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
// Float binary ops — f32 min/max still use AltiVec vminfp/vmaxfp; arithmetic
// (add/sub/mul/div) and everything f64 goes through VSX xv* instructions.
//
// Add and sub deliberately use xvaddsp/xvsubsp rather than AltiVec
// vaddfp/vsubfp. The AltiVec forms are Java/IEEE-mode VMX float ops: they
// always round to nearest and ignore FPSCR.RN entirely, whereas VFMul and
// VFDiv have always lowered to xvmulsp/xvdivsp, which honour it. Mixing the
// two meant a single guest expression could round its multiplies under the
// guest's selected MXCSR rounding mode and its adds under round-to-nearest.
// Making all four VSX removes that inconsistency.
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
  case IR::OpSize::i32Bit: xvaddsp(Dst, V1, V2); break;
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
  case IR::OpSize::i32Bit: xvsubsp(Dst, V1, V2); break;
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
    // pmullw: per-lane low 16 bits of the product.
    //
    // vmladduhm VRT,VRA,VRB,VRC computes (VRA[i] * VRB[i] + VRC[i]) mod 2^16
    // for each halfword independently, so a zero addend makes it exactly
    // pmullw. Because it is strictly elementwise, no permute and no
    // endianness fixup is needed: whichever physical halfword holds guest
    // lane i in V1 holds lane i in V2 as well, and the product lands in that
    // same position. Modular low-16 arithmetic is sign-agnostic, so the one
    // instruction serves both pmullw and its signed reading.
    //
    // Replaces vmulosh/vmulesh + two LoadConstants + std/std + addi/li/lvx +
    // vperm — roughly fifteen instructions that materialised a permute
    // control on the stack and then reloaded it, eating a store-hit-load on
    // every PMULLW. Same store-to-load-forwarding pathology the
    // StoreFPRSized and ScalarInsert paths already removed.
    vxor(VTMP1, VTMP1, VTMP1);
    vmladduhm(Dst, V1, V2, VTMP1);
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
    // Wanted phys[0..7]=[18,19,1A,1B,08,09,0A,0B], phys[8..15]=[1C,1D,1E,1F,0C,0D,0E,0F],
    // i.e. Dst BE words = [VTMP2.w2, VTMP1.w2, VTMP2.w3, VTMP1.w3] — exactly
    // vmrglw(Dst, VTMP2, VTMP1) (the ISA definition is in BE word numbering and
    // is endian-independent at the instruction level).  Hardware-verified on
    // POWER8 against the old vperm sequence (see report: "VUMull i32").
    vmulouh(VTMP1, V1, V2);
    vmuleuh(VTMP2, V1, V2);
    vmrglw(Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 unsigned widening of lower LE words {0,1} → dwords {0,1}.
    // vmulouw(t,a,b): t.BE_dword[i] = a.BE_word[2i+1]*b.BE_word[2i+1] = LE_word[2-2i] product
    //                   so t.phys[8..15] = LE_word[0] product (=LE_dword[0] of result).
    // vmuleuw(t,a,b): t.BE_dword[i] = a.BE_word[2i]*b.BE_word[2i]   = LE_word[3-2i] product
    //                   so t.phys[8..15] = LE_word[1] product (=LE_dword[1] of result).
    // Output: phys[8..15]=VTMP1.phys[8..15], phys[0..7]=VTMP2.phys[8..15],
    // i.e. Dst.dw0 = VTMP2.dw1 and Dst.dw1 = VTMP1.dw1.  xxpermdi(D,A,B,dm)
    // gives dw0 = A.dw[dm>>1], dw1 = B.dw[dm&1], so dm=3 with A=VTMP2,
    // B=VTMP1.  Hardware-verified ("VUMull i64").
    vmulouw(VTMP1, V1, V2);
    vmuleuw(VTMP2, V1, V2);
    xxpermdi(Dst, VTMP2, VTMP1, 3);
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
    // Signed widening of lower LE halfwords {0..3} → words {0..3}. Same gather
    // as VUMull i32Bit — see there.  Hardware-verified ("VSMull i32").
    vmulosh(VTMP1, V1, V2);
    vmulesh(VTMP2, V1, V2);
    vmrglw(Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 signed widening (for PMULDQ). Same gather as VUMull i64Bit.
    // Hardware-verified ("VSMull i64").
    vmulosw(VTMP1, V1, V2);
    vmulesw(VTMP2, V1, V2);
    xxpermdi(Dst, VTMP2, VTMP1, 3);
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
    // Wanted phys[0..7]=[10,11,12,13,00,01,02,03], phys[8..15]=[14,15,16,17,04,05,06,07],
    // i.e. Dst BE words = [VTMP2.w0, VTMP1.w0, VTMP2.w1, VTMP1.w1] =
    // vmrghw(Dst, VTMP2, VTMP1).  Hardware-verified ("VUMull2 i32").
    vmulouh(VTMP1, V1, V2);
    vmuleuh(VTMP2, V1, V2);
    vmrghw(Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 unsigned widening of upper LE words {2,3} → dwords {0,1}.
    // LE_word[2] product = vmulouw.BE_dword[0] = VTMP1.phys[0..7].
    // LE_word[3] product = vmuleuw.BE_dword[0] = VTMP2.phys[0..7].
    // ctrl phys = [10,11,12,13,14,15,16,17, 00,01,02,03,04,05,06,07], i.e.
    // Dst.dw0 (phys[8..15]) = VTMP1.dw0 and Dst.dw1 (phys[0..7]) = VTMP2.dw0
    // → xxpermdi(Dst, VTMP2, VTMP1, 0).  NOTE the operand order: the naive
    // reading (VTMP1, VTMP2) produces the two halves SWAPPED — caught by the
    // POWER8 differential test ("VUMull2 i64"), which failed on (T1,T2,0).
    vmulouw(VTMP1, V1, V2);
    vmuleuw(VTMP2, V1, V2);
    xxpermdi(Dst, VTMP2, VTMP1, 0);
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
    // Signed widening of upper LE halfwords {4..7} → words {0..3}. Same gather
    // as VUMull2 i32Bit.  Hardware-verified ("VSMull2 i32").
    vmulosh(VTMP1, V1, V2);
    vmulesh(VTMP2, V1, V2);
    vmrghw(Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // 32×32→64 signed widening of upper LE words {2,3} → dwords {0,1}.
    // Same blend as VUMull2 i64Bit.  Hardware-verified ("VSMull2 i64").
    vmulosw(VTMP1, V1, V2);
    vmulesw(VTMP2, V1, V2);
    xxpermdi(Dst, VTMP2, VTMP1, 0);
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
  // mfocrf reads only CR6 (FXM 0x02); mfcr serializes all eight CR fields on
  // POWER8. Bits outside the addressed field are undefined but the rlwinm
  // masks to the single CR6 bit we consume - same argument as the CRC-area
  // flag extraction in ALUOps.cpp.
  mfocrf(TMP1, 0x02);
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
  EmitLoadPPC64VConst(Dst, PPC64_VCONST_MULH_HI_I16, TMP1, TMP2);
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
  EmitLoadPPC64VConst(Dst, PPC64_VCONST_MULH_HI_I16, TMP1, TMP2);
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
// Uses VTMP1 as scratch; clobbers TMP1 for i64Bit only.
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
    // Build splat(64) (no 5-bit-imm path for 64). See BuildSplatDW.
    j->li(TMP1, 64);
    j->mtvsrd(VTMP2, TMP1);
    j->xxpermdi(VTMP2, VTMP2, VTMP2, 0);
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
  // Broadcast LE element 0 of Shift to all lanes in VTMP1.
  if (ElemSz == IR::OpSize::i64Bit) {
    // Broadcast LE element 0 of Shift to both doublewords in one instruction.
    // xxpermdi(XT, XA, XB, DM) takes XT's index-0 half from XA's index-(DM>>1)
    // half and XT's index-1 half from XB's index-(DM&1) half; index 1 is LE
    // element 0, so dm=3 with XA==XB==Shift puts LE element 0 in both halves.
    // That is precisely what the six-instruction sequence it replaces did:
    // vsldoi 8 swapped the halves so LE element 0 landed in the mfvsrd-visible
    // doubleword, mfvsrd pulled it into a GPR, and the two stds plus lvx put
    // it back into both halves -- with a store-hit-load stall in the middle.
    // Verified byte-identical on POWER8 against the old sequence.
    xxpermdi(VTMP1, Shift, Shift, 3);
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
    // Broadcast LE element 0 of Shift to both doublewords in one instruction.
    // xxpermdi(XT, XA, XB, DM) takes XT's index-0 half from XA's index-(DM>>1)
    // half and XT's index-1 half from XB's index-(DM&1) half; index 1 is LE
    // element 0, so dm=3 with XA==XB==Shift puts LE element 0 in both halves.
    // That is precisely what the six-instruction sequence it replaces did:
    // vsldoi 8 swapped the halves so LE element 0 landed in the mfvsrd-visible
    // doubleword, mfvsrd pulled it into a GPR, and the two stds plus lvx put
    // it back into both halves -- with a store-hit-load stall in the middle.
    // Verified byte-identical on POWER8 against the old sequence.
    xxpermdi(VTMP1, Shift, Shift, 3);
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
    // Broadcast LE element 0 of Shift to both doublewords in one instruction.
    // xxpermdi(XT, XA, XB, DM) takes XT's index-0 half from XA's index-(DM>>1)
    // half and XT's index-1 half from XB's index-(DM&1) half; index 1 is LE
    // element 0, so dm=3 with XA==XB==Shift puts LE element 0 in both halves.
    // That is precisely what the six-instruction sequence it replaces did:
    // vsldoi 8 swapped the halves so LE element 0 landed in the mfvsrd-visible
    // doubleword, mfvsrd pulled it into a GPR, and the two stds plus lvx put
    // it back into both halves -- with a store-hit-load stall in the middle.
    // Verified byte-identical on POWER8 against the old sequence.
    xxpermdi(VTMP1, Shift, Shift, 3);
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
    // VTMP1 already holds TMP1 in the mtvsrd-defined doubleword (above), so
    // duplicating it into both halves is the whole splat -- one instruction
    // in place of two stores, an addi and a vector load. See BuildSplatDW.
    j->xxpermdi(VTMP2, VTMP1, VTMP1, 0);
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
    j->li(TMP1, 63);
    j->mtvsrd(VTMP2, TMP1);
    j->xxpermdi(VTMP2, VTMP2, VTMP2, 0);
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
  cmpld(cr(1), TMP1, TMP2);  // cr(1) so CR0 (packed NZCV) is preserved

  PPC64Emitter::Label Zero{};
  PPC64Emitter::Label Done{};
  bc({4, 0 + 4}, &Zero);  // bge (CC_UGE) on cr(1)
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
  cmpld(cr(1), TMP1, TMP2);  // cr(1) so CR0 (packed NZCV) is preserved

  PPC64Emitter::Label Saturate{};
  PPC64Emitter::Label Done{};
  bc({4, 0 + 4}, &Saturate);  // bge (CC_UGE) on cr(1)
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
  cmpld(cr(1), TMP1, TMP2);  // cr(1) so CR0 (packed NZCV) is preserved

  PPC64Emitter::Label Zero{};
  PPC64Emitter::Label Done{};
  bc({4, 0 + 4}, &Zero);  // bge (CC_UGE) on cr(1)
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

  // i64 elements are a pure doubleword blend — one xxpermdi, no perm control.
  // Under the lvx-reverse layout LE dword 0 is phys[8..15] (= VSR dw1) and LE
  // dword 1 is phys[0..7] (= VSR dw0), so LE index j maps to VSR dw (1-j).
  // xxpermdi(D,A,B,dm): D.dw0 = A.dw[dm>>1], D.dw1 = B.dw[dm&1].
  //   DestIdx==0: keep DestVec's LE dword 1 (= dw0) and take SrcVec's LE dword
  //               SrcIdx (= dw 1-SrcIdx) into LE dword 0 (= dw1)
  //               → xxpermdi(Dst, DestVec, SrcVec, 1-SrcIdx)
  //   DestIdx==1: → xxpermdi(Dst, SrcVec, DestVec, 2*(1-SrcIdx)+1)
  // Single instruction, so Dst may alias either source.  Hardware-verified for
  // all four (DestIdx,SrcIdx) combinations ("VInsElement i64 D=.. S=..").
  if (ElemSz == IR::OpSize::i64Bit) {
    if (DestIdx == 0) {
      xxpermdi(Dst, DestVec, SrcVec, (uint32_t)(1u - SrcIdx));
    } else {
      xxpermdi(Dst, SrcVec, DestVec, (uint32_t)(2u * (1u - SrcIdx) + 1u));
    }
    return;
  }

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

  // LoadPermCtrl's first parameter is the old -16 slot (-> phys[8..15]);
  // this site's swap convention (see VInsGPR comment) maps ctrl_lo there.
  LoadPermCtrl(VTMP1, ctrl_lo, ctrl_hi);

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

  // i64: mtvsrd already leaves Src in VTMP2.dw0, so the insert is one
  // doubleword blend (see VInsElement i64 for the LE dword ↔ VSR dw mapping).
  //   DestIdx==0 → Dst.dw1 = VTMP2.dw0, Dst.dw0 = DestVec.dw0
  //              → xxpermdi(Dst, DestVec, VTMP2, 0)
  //   DestIdx==1 → Dst.dw0 = VTMP2.dw0, Dst.dw1 = DestVec.dw1
  //              → xxpermdi(Dst, VTMP2, DestVec, 1)
  // Hardware-verified for both DestIdx ("VInsGPR i64 DestIdx=0/1"); the same
  // test also confirms mtvsrd lands the GPR in dw0 (phys[0..7]).
  if (ElemSz == IR::OpSize::i64Bit) {
    if (DestIdx == 0) {
      xxpermdi(Dst, DestVec, VTMP2, 0);
    } else {
      xxpermdi(Dst, VTMP2, DestVec, 1);
    }
    return;
  }

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

  // N in [16..31]: result.phys[i] = (i < ZeroPad) ? 0 : VLow.phys[i-ZeroPad],
  // with ZeroPad = N-16 in [0..15].
  //
  // vsldoi(VRT, VRA, VRB, SHB) computes VRT.phys[i] = (VRA||VRB).phys[i+SHB].
  // With VRA = ZERO and VRB = VLow the concatenation is 16 zero bytes followed
  // by VLow, so VRT.phys[i] = 0 for i+SHB < 16 and VLow.phys[i+SHB-16]
  // otherwise.  Choosing SHB = 16-ZeroPad makes those two conditions become
  // exactly `i < ZeroPad` and `VLow.phys[i-ZeroPad]`.  ✓
  //
  // ZeroPad == 0 (N == 16) would need SHB == 16, which is not encodable — but
  // that case is just a copy of VLow.  Otherwise SHB is 1..15, always legal.
  // Hardware-verified for every N in [16..31] against the old vperm sequence
  // ("VExtr N=16".."VExtr N=31").
  const uint8_t ZeroPad = (uint8_t)(N - 16u);
  if (ZeroPad == 0) {
    if (Dst != VLow) vmr(Dst, VLow);
    return;
  }
  vspltisb(VTMP2, 0);
  vsldoi(Dst, VTMP2, VLow, (uint32_t)(16u - ZeroPad));
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
  // uno = !(a==a && b==b) is literally NAND, so xxlnand folds the trailing
  // complement into the AND: 3 instructions instead of 4. (xxl* addresses
  // VTMP1/VTMP2 = v30/v31 = vs62/vs63 exactly as xxland already does here.)
  switch (ElemSz) {
  case IR::OpSize::i32Bit:
    vcmpeqfp(VTMP1, V1, V1);
    vcmpeqfp(VTMP2, V2, V2);
    xxlnand (Dst,   VTMP1, VTMP2);   // uno = !(ord)
    break;
  case IR::OpSize::i64Bit:
    xvcmpeqdp(VTMP1, V1, V1);
    xvcmpeqdp(VTMP2, V2, V2);
    xxlnand  (Dst,   VTMP1, VTMP2);
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
// Vector-domain strategy (replaces the stack round trip through lfs/fadds):
//   1. Splat each operand's LE element 0 across all lanes — f32 elem0 is BE
//      word 3, f64 elem0 is dw1 (LE lvx element reversal; the dm=3 splat is
//      the same hardware-verified idiom as VUShlS).
//   2. One xv* vector op. All lanes hold identical values, so the FPSCR
//      sticky bits raised are exactly those the one real computation raises,
//      and rounding follows FPSCR.RN like the scalar op did.
//   3. Merge the result lane back over Vec1's element 0: xxpermdi for f64
//      (dw-granular); for f32 a two-xxsldwi rotate pair — word-granular
//      permutes can compose the {Vec1.w0..w2, result.w3} layout directly:
//        xxsldwi(T, R, Keep, 3)  = {R.w3, Keep.w0, Keep.w1, Keep.w2}
//        xxsldwi(D, T, T, 1)     = {Keep.w0, Keep.w1, Keep.w2, R.w3}
//      which replaced the earlier pooled-mask xxsel (a 2-3 instruction
//      EmitLoadPPC64VConst plus the load-use stall on its lvx, per op —
//      measured as 120 lvx mask loads inside ONE Wwise mixer block).
//      Only R's word 3 is read, so R may hold junk in other lanes.
//
// Why vector-domain and not xs* scalar: measured on op4k (2026-08-05,
// notes/denormal_bench.c), xs*/f* SCALAR float ops take a ~22.8x denormal
// assist penalty on POWER8 while xv* VECTOR ops run denormal-flat. Guest
// audio DSP (IIR/reverb tails) decays into denormals by design and x86 games
// mask it with MXCSR.FTZ, which we do not emulate — routing scalar SSE math
// through xv* removes the cliff without any MXCSR machinery. It also deletes
// the two GPR-store->vector-load forwarding stalls of the old lowering.
//   old: 9 instructions + 2 store-hit-load stalls + denormal cliff
//   new: f64 = 4 instructions, f32 = 5, no stalls, no memory traffic
//
// SPLAT CHAINS (see Interface/IR/Passes/ScalarSplatChain.cpp).
//
// Step 2 above is the whole trick: with both operands splatted, the xv* result
// is ALREADY splatted in every element. So for a scalar op sitting inside a
// guest chain (movss; subss; mulss; movss) the step-3 merge only exists to
// rebuild upper elements that the next link immediately throws away again.
//
// The IR pass proves per node that nothing observes the upper elements and sets
// SplatResult. Two independent savings follow, both keyed off that one bit:
//   * Op->SplatResult      -> skip the merge, write the xv* straight to Dst.
//   * operand is splat-form -> skip that operand's splat, feed it in directly.
// A chain-internal op with both a marked producer and a marked self is then a
// single xv* instruction, down from five.
//
// The backend keeps no value state and does not need any: the splat-form test
// reads the SplatResult bit off the operand's DEFINING op, which is the same
// bit that op's own lowering consulted when it decided not to merge. The pass
// guarantees a marked value never leaves its block, never reaches a
// StoreRegister/StoreContext, never reaches a 16-byte store, and never reaches
// a consumer that reads anything above element 0.
//
// Denormals are unaffected: every lane still computes the same value with the
// same xv* op, exactly as the splat-both-operands lowering already did. Do not
// be tempted to "simplify" a splat chain into xs*/f* scalar ops -- that is the
// 22.8x POWER8 denormal assist this lowering exists to avoid.
#define DEF_SCALAR_INSERT(NAME, XVOP_S, XVOP_D)                                \
DEF_OP(NAME) {                                                                 \
  const auto Op   = IROp->C<IR::IROp_##NAME>();                                \
  const auto ElemSz = Op->Header.ElementSize;                                  \
  const auto Dst  = GetVReg(Node);                                             \
  const auto Vec1 = GetVReg(Op->Vector1);                                      \
  const auto Vec2 = GetVReg(Op->Vector2);                                      \
  const bool Splat1 = IsSplatFormValue(Op->Vector1, ElemSz);                   \
  const bool Splat2 = IsSplatFormValue(Op->Vector2, ElemSz);                   \
  VR A = Vec1, B = Vec2;                                                       \
  if (ElemSz == IR::OpSize::i32Bit) {                                          \
    if (!Splat1) { xxspltw(VTMP1, Vec1, 3); A = VTMP1; }                       \
    if (!Splat2) { xxspltw(VTMP2, Vec2, 3); B = VTMP2; }                       \
    if (Op->SplatResult) {                                                     \
      XVOP_S(Dst, A, B);                                                       \
    } else {                                                                   \
      /* Vec1 is read again below, so the xv* must land in a scratch. */       \
      XVOP_S(VTMP1, A, B);                                                     \
      xxsldwi(VTMP2, VTMP1, Vec1, 3);                                          \
      xxsldwi(Dst, VTMP2, VTMP2, 1);                                           \
    }                                                                          \
  } else {                                                                     \
    if (!Splat1) { xxpermdi(VTMP1, Vec1, Vec1, 3); A = VTMP1; }                \
    if (!Splat2) { xxpermdi(VTMP2, Vec2, Vec2, 3); B = VTMP2; }                \
    if (Op->SplatResult) {                                                     \
      XVOP_D(Dst, A, B);                                                       \
    } else {                                                                   \
      XVOP_D(VTMP1, A, B);                                                     \
      xxpermdi(Dst, Vec1, VTMP1, 1); /* {Vec1.dw0, result.dw1} */              \
    }                                                                          \
  }                                                                            \
}
DEF_SCALAR_INSERT(VFAddScalarInsert, xvaddsp, xvadddp)
DEF_SCALAR_INSERT(VFSubScalarInsert, xvsubsp, xvsubdp)
DEF_SCALAR_INSERT(VFMulScalarInsert, xvmulsp, xvmuldp)
DEF_SCALAR_INSERT(VFDivScalarInsert, xvdivsp, xvdivdp)
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
  // Lane 0 is merged by permute/select, not through the stack. The old path
  // spent nine instructions (addi/stvx/addi/stvx/lwz/stw/lvx) and took two
  // store-hit-loads to move one element; xxpermdi/xxsel do it in one or two.
  // These are bitwise ops, so they also sidestep the SNaN canonicalisation
  // that motivated the integer lwz/stw copy in the first place - a bit-exact
  // merge, which is what MINSS/MINSD require.
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    vcmpgtfp(VTMP1, Vec2, Vec1);          // mask = Vec2 > Vec1
    vsel    (VTMP1, Vec2, Vec1, VTMP1);
    xxsldwi (VTMP2, VTMP1, Vec1, 3);      // {result.w3, Vec1.w0..w2}
    xxsldwi (Dst, VTMP2, VTMP2, 1);       // rotate: result into BE word 3 (elem0)
  } else {
    xvcmpgtdp(VTMP1, Vec2, Vec1);
    xxsel    (VTMP1, Vec2, Vec1, VTMP1);
    xxpermdi (Dst, Vec1, VTMP1, 1);       // {Vec1.dw0, result.dw1}
  }
}

DEF_OP(VFMaxScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFMaxScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  // Same lane-0 merge as VFMinScalarInsert: permute/select instead of a
  // nine-instruction stack round trip with two store-hit-loads.
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    vcmpgtfp(VTMP1, Vec1, Vec2);          // mask = Vec1 > Vec2
    vsel    (VTMP1, Vec2, Vec1, VTMP1);
    xxsldwi (VTMP2, VTMP1, Vec1, 3);      // {result.w3, Vec1.w0..w2}
    xxsldwi (Dst, VTMP2, VTMP2, 1);       // rotate: result into BE word 3 (elem0)
  } else {
    xvcmpgtdp(VTMP1, Vec1, Vec2);
    xxsel    (VTMP1, Vec2, Vec1, VTMP1);
    xxpermdi (Dst, Vec1, VTMP1, 1);
  }
}
DEF_OP(VFSqrtScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFSqrtScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);

  // Vector domain, same shape as DEF_SCALAR_INSERT: splat the source element,
  // one xv* sqrt, merge lane 0 back over Vec1.
  //
  // The old lowering was two stvx, then lfs/fsqrts/stfs in the SCALAR FPU
  // domain, then lvx: eight instructions, two store-hit-loads, a VSU<->FPU
  // domain crossing on the critical path, and - the expensive part - a scalar
  // float op, which on POWER8 takes the ~22.8x denormal assist penalty that
  // the xv* ops do not (measured op4k 2026-08-05, notes/denormal_bench.c).
  //
  // All lanes compute the same value, so the FPSCR sticky bits raised are
  // exactly those of the one real computation, and rounding follows FPSCR.RN
  // as the scalar op did.
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    xxspltw (VTMP1, Vec2, 3);             // guest f32 elem0 = BE word 3
    xvsqrtsp(VTMP1, VTMP1);
    xxsldwi (VTMP2, VTMP1, Vec1, 3);      // {result.w3, Vec1.w0..w2}
    xxsldwi (Dst, VTMP2, VTMP2, 1);       // rotate: result into BE word 3 (elem0)
  } else {
    xxpermdi(VTMP1, Vec2, Vec2, 3);       // guest f64 elem0 = BE dw1
    xvsqrtdp(VTMP1, VTMP1);
    xxpermdi(Dst, Vec1, VTMP1, 1);        // {Vec1.dw0, result.dw1}
  }
}
// VFRSqrt / VFRecp scalar inserts.  x86 RSQRTSS / RCPSS produce ~12-bit
// approximations; PPC frsqrtes/fres give similar-precision estimates.  For
// f64 (no x86 equivalent) we use the f64 estimate ops.
DEF_OP(VFRSqrtScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFRSqrtScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  // f32 is the only size x86 can reach here (RSQRTSS); vrsqrtefp is the
  // vector-domain analogue of frsqrtes with the same estimate precision
  // class, so the stack round trip and the scalar-FPU crossing both go.
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    xxspltw  (VTMP1, Vec2, 3);            // guest f32 elem0 = BE word 3
    vrsqrtefp(VTMP1, VTMP1);
    xxsldwi  (VTMP2, VTMP1, Vec1, 3);     // {result.w3, Vec1.w0..w2}
    xxsldwi  (Dst, VTMP2, VTMP2, 1);      // rotate: result into BE word 3 (elem0)
    return;
  }

  // f64 has no x86 equivalent and no VSX double rsqrt-estimate encoder in
  // this tree, so it keeps the scalar path.
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);
  lfd(f0, -16, r1);
  frsqrte(f0, f0);
  stfd(f0, -32, r1);
  lvx(Dst, r(0), TMP1);
}

DEF_OP(VFRecpScalarInsert) {
  const auto Op   = IROp->C<IR::IROp_VFRecpScalarInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec1 = GetVReg(Op->Vector1);
  const auto Vec2 = GetVReg(Op->Vector2);
  // f32 is the only size x86 can reach here (RCPSS); vrefp is the
  // vector-domain analogue of fres with the same estimate precision class.
  if (Op->Header.ElementSize == IR::OpSize::i32Bit) {
    xxspltw(VTMP1, Vec2, 3);              // guest f32 elem0 = BE word 3
    vrefp  (VTMP1, VTMP1);
    xxsldwi(VTMP2, VTMP1, Vec1, 3);       // {result.w3, Vec1.w0..w2}
    xxsldwi(Dst, VTMP2, VTMP2, 1);        // rotate: result into BE word 3 (elem0)
    return;
  }

  // f64 has no x86 equivalent. It also is NOT an estimate here: PPC has no
  // scalar f64 fre, so this computes an exact 1.0/x via fdiv. Keeping the
  // scalar path preserves that precision - swapping in a double estimate
  // would quietly downgrade it.
  addi(TMP1, r1, -32);
  stvx(Vec1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(Vec2, r(0), TMP2);
  lfd(f0, -16, r1);
  LoadConstant(TMP3, 0x3FF0000000000000ULL); // 1.0 as f64
  std(TMP3, -48, r1);
  lfd(f1, -48, r1);
  fdiv(f0, f1, f0);
  stfd(f0, -32, r1);
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
  const auto DstES = Op->Header.ElementSize;
  const auto SrcES = Op->SrcElementSize;

  // Vector domain throughout: no red-zone traffic and no scalar-FPU crossing.
  // Lane bookkeeping is the whole difficulty, because the VSX converts do not
  // read or write the lane the guest keeps its scalar element in:
  //   xvcvspdp reads single-precision from BE words 0 and 2
  //   xvcvdpsp writes single-precision to  BE words 0 and 2
  // while guest f32 element 0 is BE word 3 and guest f64 element 0 is BE dw1.
  // A splat before (and after, for the narrowing case) reconciles the two.
  if (SrcES == IR::OpSize::i32Bit && DstES == IR::OpSize::i64Bit) {
    // f32 -> f64 (cvtss2sd). Splatting the guest element across all four words
    // puts it in both lanes xvcvspdp reads, so both doublewords come out equal
    // and dw1 is the value the merge wants.
    xxspltw (VTMP1, Vec2, 3);
    xvcvspdp(VTMP1, VTMP1);
    xxpermdi(Dst, Vec1, VTMP1, 1);
  } else if (SrcES == IR::OpSize::i64Bit && DstES == IR::OpSize::i32Bit) {
    // f64 -> f32 (cvtsd2ss). Splat dw1 into both doublewords, convert, then
    // splat BE word 0 back across the register so the result also sits in
    // word 3 where the merge reads it.
    xxpermdi(VTMP1, Vec2, Vec2, 3);
    xvcvdpsp(VTMP1, VTMP1);
    xxspltw (VTMP1, VTMP1, 0);
    xxsldwi (VTMP2, VTMP1, Vec1, 3);      // {result.w3, Vec1.w0..w2}
    xxsldwi (Dst, VTMP2, VTMP2, 1);       // rotate: result into BE word 3 (elem0)
  } else {
    // Same size: a lane copy, no conversion at all.
    if (DstES == IR::OpSize::i32Bit) {
      xxsldwi(VTMP2, Vec2, Vec1, 3);      // {Vec2.w3, Vec1.w0..w2}
      xxsldwi(Dst, VTMP2, VTMP2, 1);      // rotate: Vec2.elem0 into BE word 3
    } else {
      xxpermdi(Dst, Vec1, Vec2, 1);
    }
  }
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
  if (Op->HasTwoElements) {
    // cvtpi2ps: two i32 -> two f32 in the low 64 bits. xvcvsxwsp is lane-wise
    // word->word, so both guest elements (BE words 2 and 3) convert in place
    // with no permute at all, and one xxpermdi takes the whole low doubleword.
    xvcvsxwsp(VTMP1, Vec2);
    xxpermdi(Dst, Vec1, VTMP1, 1);      // {Vec1.dw0, both results}
    return;
  }

  if (SrcES == IR::OpSize::i32Bit) {
    if (DstES == IR::OpSize::i32Bit) {
      // i32 -> f32, lane-wise; the guest element stays in BE word 3.
      xvcvsxwsp(VTMP1, Vec2);
      xxsldwi(VTMP2, VTMP1, Vec1, 3);     // {result.w3, Vec1.w0..w2}
      xxsldwi(Dst, VTMP2, VTMP2, 1);      // rotate: result into BE word 3 (elem0)
    } else {
      // i32 -> f64. xvcvsxwdp reads BE words 0 and 2, so splat the guest
      // element across the register first; both doublewords then match.
      xxspltw(VTMP1, Vec2, 3);
      xvcvsxwdp(VTMP1, VTMP1);
      xxpermdi(Dst, Vec1, VTMP1, 1);
    }
    return;
  }

  // i64 source: splat dw1 so both lanes convert the guest element.
  xxpermdi(VTMP1, Vec2, Vec2, 3);
  if (DstES == IR::OpSize::i32Bit) {
    // Single rounding, as in VSToFGPRInsert; results land in BE words 0 and 2.
    xvcvsxdsp(VTMP1, VTMP1);
    xxspltw(VTMP1, VTMP1, 0);
    xxsldwi(VTMP2, VTMP1, Vec1, 3);       // {result.w3, Vec1.w0..w2}
    xxsldwi(Dst, VTMP2, VTMP2, 1);        // rotate: result into BE word 3 (elem0)
  } else {
    xvcvsxddp(VTMP1, VTMP1);
    xxpermdi(Dst, Vec1, VTMP1, 1);
  }
}

// VSToFGPRInsert: GPR signed int → float, insert into Vec1[0].
DEF_OP(VSToFGPRInsert) {
  const auto Op   = IROp->C<IR::IROp_VSToFGPRInsert>();
  const auto Dst  = GetVReg(Node);
  const auto Vec  = GetVReg(Op->Vector);
  const auto Src  = GetReg(Op->Src);
  const auto DstES = Op->Header.ElementSize;
  const auto SrcES = Op->SrcElementSize;

  // GPR -> VSX directly with mtvsrd (ISA 2.07) instead of bouncing the value
  // through the red zone and the scalar FPU.
  if (SrcES == IR::OpSize::i32Bit) {
    extsw(TMP3, Src);                   // sign-extend low 32 -> 64
    mtvsrd(VTMP1, TMP3);
  } else {
    mtvsrd(VTMP1, Src);
  }
  // mtvsrd writes doubleword 0 and leaves doubleword 1 undefined; splat so
  // both lanes convert the same value and no garbage lane can raise FP flags.
  xxpermdi(VTMP1, VTMP1, VTMP1, 0);

  if (DstES == IR::OpSize::i32Bit) {
    // xvcvsxdsp is i64 -> f32 with a SINGLE rounding. Converting via f64 and
    // narrowing would round twice, which cvtsi2ss with a 64-bit source would
    // expose. Results land in BE words 0 and 2, so splat word 0 across the
    // register to reach word 3 where the guest element lives.
    xvcvsxdsp(VTMP1, VTMP1);
    xxspltw(VTMP1, VTMP1, 0);
    xxsldwi(VTMP2, VTMP1, Vec, 3);        // {result.w3, Vec.w0..w2}
    xxsldwi(Dst, VTMP2, VTMP2, 1);        // rotate: result into BE word 3 (elem0)
  } else {
    xvcvsxddp(VTMP1, VTMP1);
    xxpermdi(Dst, Vec, VTMP1, 1);       // {Vec.dw0, result.dw1}
  }
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

  // Fully in-register via the VSX scalar round-to-integral family. xsrdpi*
  // are FP->FP: NaN propagates quietly and |x| >= 2^52 is an identity by
  // construction, so the fctid/fcfid saturation bug this op used to guard
  // against (NaN/huge -> -2^63) cannot occur — no compare-and-branch
  // bypasses, no runtime 2^52 constant, no stack bounce. xsrdpic honors
  // FPSCR.RN for the Nearest/Host modes (banker's at the x86 default);
  // signal-safety of FPSCR.RN is guaranteed since the PPC64ContextBackup
  // FPSCR fix. The f32 path converts through f64 with the NON-SIGNALLING
  // converts (xscvspdpn/xscvdpspn), which are bit-preserving for NaN —
  // matching x86 ROUNDSS's pass-through-unchanged even for SNaN patterns,
  // which the old lfs/stfs bounce could not promise. The f64->f32 narrow is
  // exact: the rounded value is integral and within f32's range because the
  // input was an f32.
  //
  // Lane math (LE lvx element reversal): elem0 = BE word 3 / dw1. xsrdpi*
  // and the converts operate on dw0 / word 0, so splat elem0 across the
  // register first (dm=3 / UIM=3 splat, the hardware-verified idiom).
  auto EmitRound = [&](VR t, VR b) {
    switch (Round) {
    case IR::RoundMode::NegInfinity: xsrdpim(t, b); break;
    case IR::RoundMode::PosInfinity: xsrdpip(t, b); break;
    case IR::RoundMode::TowardsZero: xsrdpiz(t, b); break;
    case IR::RoundMode::Nearest:
    case IR::RoundMode::Host:
    default:                         xsrdpic(t, b); break;
    }
  };

  if (ESize == IR::OpSize::i32Bit) {
    xxspltw(VTMP1, Vec2, 3);       // elem0 f32 in every word incl. word 0
    xscvspdpn(VTMP1, VTMP1);       // f32 (word 0) -> f64 (dw0), NaN-bit-exact
    EmitRound(VTMP1, VTMP1);
    xscvdpspn(VTMP1, VTMP1);       // f64 (dw0) -> f32 (word 0), exact here
    xxspltw(VTMP1, VTMP1, 0);      // result to every word incl. elem0's
    xxsldwi(VTMP2, VTMP1, Vec1, 3); // {result.w3, Vec1.w0..w2}
    xxsldwi(Dst, VTMP2, VTMP2, 1);  // rotate: result into BE word 3 (elem0)
  } else {
    xxpermdi(VTMP1, Vec2, Vec2, 3);  // elem0 f64 -> dw0 (and dw1)
    EmitRound(VTMP1, VTMP1);
    xxpermdi(Dst, Vec1, VTMP1, 0);   // {Vec1.dw0, result.dw0}
  }
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

  // Branchless, in the vector domain. The old lowering spilled both operands
  // to the red zone, reloaded them into the scalar FPU, compared with fcmpu,
  // normalised the predicate through CR1 bit twiddling, then took a
  // conditional BRANCH to pick 0 vs -1, stored that into lane 0 of the
  // spilled Vec1 and reloaded the whole vector: ~14 instructions, two
  // store-hit-loads, a scalar-FPU domain crossing and an unpredictable branch
  // on what is usually a data-dependent comparison.
  //
  // The vector float compares already produce exactly the all-ones/all-zeros
  // per-lane mask x86 CMPSS/CMPSD wants, and they are elementwise, so lane 0
  // of the result is computed from lane 0 of the inputs with no splat needed.
  //
  // As a bonus this no longer writes ANY condition register: the cr(1) dance
  // existed to avoid clobbering CR0's packed NZCV (the Hard West
  // cmp -> cmpltss -> jne wedge). That hazard is now structurally absent
  // rather than merely relocated.
  //
  // Unordered predicates: a NaN operand fails every ordered compare, so
  // ORD = (V1 == V1) && (V2 == V2), and UNO/NEQ are its complement / the
  // complement of EQ.
  const bool Is32 = ESize == IR::OpSize::i32Bit;
  switch (Pred) {
  case IR::FloatCompareOp::EQ:
    if (Is32) { vcmpeqfp(VTMP1, Vec1, Vec2); } else { xvcmpeqdp(VTMP1, Vec1, Vec2); }
    break;
  case IR::FloatCompareOp::LT:
    if (Is32) { vcmpgtfp(VTMP1, Vec2, Vec1); } else { xvcmpgtdp(VTMP1, Vec2, Vec1); }
    break;
  case IR::FloatCompareOp::LE:
    if (Is32) { vcmpgefp(VTMP1, Vec2, Vec1); } else { xvcmpgedp(VTMP1, Vec2, Vec1); }
    break;
  case IR::FloatCompareOp::NEQ:
    if (Is32) {
      vcmpeqfp(VTMP1, Vec1, Vec2);
      vnor    (VTMP1, VTMP1, VTMP1);
    } else {
      xvcmpeqdp(VTMP1, Vec1, Vec2);
      xxlnor   (VTMP1, VTMP1, VTMP1);
    }
    break;
  case IR::FloatCompareOp::ORD:
    if (Is32) {
      vcmpeqfp(VTMP1, Vec1, Vec1);
      vcmpeqfp(VTMP2, Vec2, Vec2);
      vand    (VTMP1, VTMP1, VTMP2);
    } else {
      xvcmpeqdp(VTMP1, Vec1, Vec1);
      xvcmpeqdp(VTMP2, Vec2, Vec2);
      xxland   (VTMP1, VTMP1, VTMP2);
    }
    break;
  case IR::FloatCompareOp::UNO:
    // !(a==a && b==b) — one xxlnand instead of AND + complement (see the
    // matching fold in DEF_OP(VFCMPUNO)).
    if (Is32) {
      vcmpeqfp(VTMP1, Vec1, Vec1);
      vcmpeqfp(VTMP2, Vec2, Vec2);
      xxlnand (VTMP1, VTMP1, VTMP2);
    } else {
      xvcmpeqdp(VTMP1, Vec1, Vec1);
      xvcmpeqdp(VTMP2, Vec2, Vec2);
      xxlnand  (VTMP1, VTMP1, VTMP2);
    }
    break;
  }

  // Merge the mask into element 0, upper elements from Vec1 - same lane-0
  // merge as the arithmetic ScalarInsert path.
  if (Is32) {
    xxsldwi(VTMP2, VTMP1, Vec1, 3);       // {mask.w3, Vec1.w0..w2}
    xxsldwi(Dst, VTMP2, VTMP2, 1);        // rotate: mask into BE word 3 (elem0)
  } else {
    xxpermdi(Dst, Vec1, VTMP1, 1);
  }
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
// Vector-domain lowering. The old one spilled FOUR vectors to the red zone
// (Upper, V1, V2, Add), reloaded three of them into the scalar FPU, ran the
// scalar FMA and stored the result back over the spilled Upper before
// reloading the whole thing: thirteen instructions, four store-hit-loads, a
// VSU<->FPU crossing, and - as with the rest of this family - a SCALAR float
// op, which on POWER8 carries the ~22.8x denormal assist penalty that xv*
// does not.
//
// Splat all three inputs so every lane computes the same value: the FPSCR
// sticky bits raised are then exactly those of the one real computation, and
// a single rounding is preserved because the FMA stays fused.
//
// Register pressure is the whole difficulty: three splatted operands must be
// live at once and this backend has only VTMP1/VTMP2 (v30/v31). Dst supplies
// the third, which is safe as long as Dst is not Upper - Upper has to survive
// until the merge. Sequencing also matters: Add and V1 are splatted before Dst
// is written, so Dst aliasing V1, V2 or Add is fine (each is already consumed,
// and xxspltw reading and writing the same register is well defined).
//
// XT is the accumulator here, matching the non-scalar VFMLA path a few lines
// up (Dst <- Add, then xvmaddasp(Dst, V1, V2) == V1*V2 + Add).
#define DEF_FMA_SCALAR_INSERT(NAME, XVOP_S, XVOP_D, FOP_S, FOP_D)              \
DEF_OP(NAME) {                                                                 \
  const auto Op    = IROp->C<IR::IROp_##NAME>();                               \
  const auto Dst   = GetVReg(Node);                                            \
  const auto Upper = GetVReg(Op->Upper);                                       \
  const auto V1    = GetVReg(Op->Vector1);                                     \
  const auto V2    = GetVReg(Op->Vector2);                                     \
  const auto Add   = GetVReg(Op->Addend);                                      \
  const bool Is32  = Op->Header.ElementSize == IR::OpSize::i32Bit;             \
                                                                               \
  /* VTMP3_VSX supplies the third splat slot, so this is unconditional now -   \
   * no Dst == Upper fallback and no red-zone traffic in any case. */          \
  if (Is32) {                                                                  \
    xxspltw(toVSX(VTMP1), toVSX(Add), 3);                                      \
    xxspltw(toVSX(VTMP2), toVSX(V1), 3);                                       \
    xxspltw(VTMP3_VSX, toVSX(V2), 3);                                          \
    XVOP_S(toVSX(VTMP1), toVSX(VTMP2), VTMP3_VSX);                             \
    xxsldwi(VTMP2, VTMP1, Upper, 3); /* {result.w3, Upper.w0..w2} */           \
    xxsldwi(Dst, VTMP2, VTMP2, 1);   /* rotate: result into BE word 3 */       \
  } else {                                                                     \
    /* Splat-form sources (lxvdsx loads, see SplatFormLoadNodes) already hold \
     * the value in both doublewords: the accumulator still needs its copy    \
     * into VTMP1 (the xv*a form is destructive) but drops the permute for a  \
     * cheaper xxlor; multiplicands pass through with no copy at all. */      \
    if (IdInVec(SplatFormLoadNodes, Op->Addend.ID().Value)) {                  \
      xxlor(toVSX(VTMP1), toVSX(Add), toVSX(Add));                             \
    } else {                                                                   \
      xxpermdi(toVSX(VTMP1), toVSX(Add), toVSX(Add), 3);                       \
    }                                                                          \
    PPC64Emitter::VSXR SrcA = toVSX(VTMP2);                                    \
    if (IdInVec(SplatFormLoadNodes, Op->Vector1.ID().Value)) {                 \
      SrcA = toVSX(V1);                                                        \
    } else {                                                                   \
      xxpermdi(toVSX(VTMP2), toVSX(V1), toVSX(V1), 3);                         \
    }                                                                          \
    PPC64Emitter::VSXR SrcB = VTMP3_VSX;                                       \
    if (IdInVec(SplatFormLoadNodes, Op->Vector2.ID().Value)) {                 \
      SrcB = toVSX(V2);                                                        \
    } else {                                                                   \
      xxpermdi(VTMP3_VSX, toVSX(V2), toVSX(V2), 3);                            \
    }                                                                          \
    XVOP_D(toVSX(VTMP1), SrcA, SrcB);                                          \
    xxpermdi(toVSX(Dst), toVSX(Upper), toVSX(VTMP1), 1);                       \
  }                                                                            \
}
// fmadd(t,a,b,c)/fmsub etc per emitter signature: (t, fra, frc, frb).
// PPC fmadd ISA: T = FRA*FRC + FRB → emitter call fmadd(t, a, c, b).
// We pass: f0=V1, f1=V2, f2=Add → call fmadd(t, f0, f1, f2) emits
//   fmadd FRT, FRA=f0, FRC=f1, FRB=f2  →  T = f0*f1 + f2 = V1*V2 + Add.  ✓
// Vector op pairing mirrors the non-scalar DEF_OP(VFMLA/VFMLS/VFNMLA/VFNMLS)
// handlers exactly, so the FEX-vs-PPC naming inversion is inherited from a
// path that is already proven rather than re-derived here.
DEF_FMA_SCALAR_INSERT(VFMLAScalarInsert,  xvmaddasp,  xvmaddadp,  fmadds,  fmadd)
DEF_FMA_SCALAR_INSERT(VFMLSScalarInsert,  xvmsubasp,  xvmsubadp,  fmsubs,  fmsub)
// VFNMLA: -(V1*V2) + Add → fnmsub: -A*C + B = -V1*V2 + Add  ✓
DEF_FMA_SCALAR_INSERT(VFNMLAScalarInsert, xvnmsubasp, xvnmsubadp, fnmsubs, fnmsub)
// VFNMLS: -(V1*V2) - Add → fnmadd: -(A*C+B) = -V1*V2 - Add  ✓
DEF_FMA_SCALAR_INSERT(VFNMLSScalarInsert, xvnmaddasp, xvnmaddadp, fnmadds, fnmadd)
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
    // VTMP1 above is already Src duplicated into both doublewords, which is
    // exactly the i64 result -- the old stack roundtrip recomputed it. Still
    // no vsldoi(VTMP1, VTMP1, ..., 8): that would read the ISA-undefined half.
    vmr(Dst, VTMP1);
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
  // bytes 0-7) and Hi at LE element 1 (memory bytes 8-15).
  //
  // mtvsrd defines the doubleword that xxpermdi reads as index 0 -- the same
  // half mfvsrd sees, which in FEX's LE layout is element 1. xxpermdi(XT, XA,
  // XB, DM) takes XT's index-0 half from XA's index-(DM>>1) half and XT's
  // index-1 half from XB's index-(DM&1) half, so with Hi and Lo each parked
  // in their register's index-0 half, dm=0 lands Hi at LE element 1 and Lo at
  // LE element 0. Byte-identical to the std/std/lvx roundtrip it replaces
  // (checked on POWER8 by stvx'ing both forms with distinguishable halves),
  // three instructions instead of five and no store-hit-load.
  mtvsrd(VTMP1, Hi);
  mtvsrd(VTMP2, Lo);
  xxpermdi(Dst, VTMP1, VTMP2, 0);
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
    // Store f0 back as a 4-byte float, then bring it in through a GPR: the
    // value reaches the vector via mtvsrd below, so neither an lvx of the
    // spill slot nor a pre-zeroed Dst is needed. vspltw overwrites all 128
    // bits of Dst and VTMP1 is not read before mtvsrd defines it, so both of
    // those (a dead lvx and a doubly-emitted vspltisw(Dst,0)) are dropped.
    stfs(f0, -8, r1);
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
    //
    // This select is LOAD-BEARING, not dead — do NOT remove it. Hardware-
    // measured on POWER8 (op4k, notes/vperm-verify): xvrspic+xvcvspsxws on
    // {+2^40, NaN, -2^40, 1.5} = {7fffffff, 80000000, 80000000, 2}. The
    // +overflow lane is INT_MAX (7fffffff), so without the substitution x86
    // CVTPS2DQ of an out-of-range positive would return 0x7fffffff instead of
    // 0x80000000. The xvcvspsxws/xvcvdpsxds "+overflow → INT_MAX" behaviour is
    // the reason every FToS/FToISized site keeps this block.
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F32_2P31, TMP1, TMP2);
    xvcmpgesp(VTMP1, Src, VTMP2);                // mask: 1 where Src >= 2^31
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I32_MIN, TMP1, TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);                 // overflow ? INT_MIN : Dst
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    // Match Vector_FToISized's HostRound=true path for f64→i64.
    xvrdpic(VTMP1, Src);
    xvcvdpsxds(Dst, VTMP1);
    // Same INT_MIN sentinel fix for f64 → i64.  Bound = 2^63 as f64.
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F64_2P63, TMP1, TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I64_MIN, TMP1, TMP2);
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
    // INT_MIN sentinel for +overflow. This fix-up is LOAD-BEARING, not dead:
    // hardware-measured on POWER8, vctsxs of {+2^40, NaN, -2^40, 1.5} gives
    // {7fffffff, 00000000, 80000000, 1} — +overflow saturates to INT_MAX, so
    // without the select the +overflow lane would be 0x7fffffff not x86's
    // 0x80000000. KNOWN BUG (not fixed here): vctsxs maps NaN -> 0x00000000
    // (VMX), and xvcmpgesp returns 0 for NaN, so the select leaves 0 where
    // x86 CVTTPS2DQ(NaN) wants 0x80000000. Unlike the VSX converts, VMX vctsxs
    // does NOT map NaN to INT_MIN. Needs a separate NaN mask to fully match.
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F32_2P31, TMP1, TMP2);
    xvcmpgesp(VTMP1, Src, VTMP2);                // mask: 1 where Src >= 2^31
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I32_MIN, TMP1, TMP2);
    xxsel(Dst, Dst, VTMP2, VTMP1);
    return;
  }
  if (ElemSz == IR::OpSize::i64Bit) {
    xvrdpiz(VTMP1, Src);
    xvcvdpsxds(Dst, VTMP1);
    // INT_MIN sentinel for +overflow (see Vector_FToS for rationale)
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F64_2P63, TMP1, TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I64_MIN, TMP1, TMP2);
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
    // f32 -> f64 packed (CVTPS2PD low): promote guest elements 0,1. Guest f32
    // element k sits at BE word (3-k); xvcvspdp converts BE words 0 and 2
    // into dw0 and dw1. vmrglw(Src,Src) = [w2,w2,w3,w3] puts f32 e1 at w0 and
    // e0 at w2, so the convert lands e1 in dw0 (guest f64 e1) and e0 in dw1
    // (guest f64 e0) - exactly the target layout. Two instructions replace a
    // spill + two lfs/stfd round trips (two store-hit-loads).
    vmrglw(VTMP1, Src, Src);
    xvcvspdp(Dst, VTMP1);
    return;
  }
  if (Conv == 0x0408) {
    // f64 -> f32 packed (CVTPD2PS): narrow both f64s into the low half,
    // upper half zeroed. xvcvdpsp leaves the results at BE words 0 and 2;
    // the vmrghw-with-shifted-self trick packs [w0:w2] into one doubleword,
    // and the final xxpermdi pairs it with VZERO's dw0 (the ABI-preserved
    // half). Rounding: xvcvdpsp honours FPSCR.RN exactly as frsp did.
    xvcvdpsp(VTMP1, Src);
    xxsldwi(VTMP2, VTMP1, VTMP1, 2);
    vmrghw(VTMP1, VTMP1, VTMP2);         // dw0 = cvt(e1) : cvt(e0)
    xxpermdi(AsVSX(Dst), VZERO_VSX, AsVSX(VTMP1), 0b00);
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
    // Table-resolved (S3.7-C5): a bare LoadConstant of the host address here
    // is the serialized-block stale-pointer hazard — a cached block replayed
    // in a new process would bctrl into the old ASLR layout.
    EmitLoadPPC64Helper(r(12), SrcIsF16 ? PPC64_HELPER_F16x4ToF32x4 : PPC64_HELPER_F32x4ToF16x4);
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
    // Promote guest f32 elements 2,3 (CVTPS2PD upper). Elements 2,3 sit at BE
    // words 1,0; vmrghw(Src,Src) = [w0,w0,w1,w1] positions e3 at w0 and e2 at
    // w2, exactly where xvcvspdp reads. Mirror of the Conv 0x0804 path.
    vmrghw(VTMP1, Src, Src);
    xvcvspdp(Dst, VTMP1);
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
    // Narrow VU's two f64s into guest f32 elements 2,3; elements 0,1 come
    // from VL. Same [w0:w2] packing trick as the Conv 0x0408 path, but the
    // packed doubleword lands in dw0 (guest upper half) and the closing
    // xxpermdi takes dw1 from VL. All sources are consumed before Dst is
    // written, so Dst may alias VL or VU.
    xvcvdpsp(VTMP1, VU);
    xxsldwi(VTMP2, VTMP1, VTMP1, 2);
    vmrghw(VTMP1, VTMP1, VTMP2);         // dw0 = cvt(e1) : cvt(e0)
    xxpermdi(AsVSX(Dst), AsVSX(VTMP1), AsVSX(VL), 0b01);
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
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F32_2P31, TMP1, TMP2);
    xvcmpgesp(VTMP1, Src, VTMP2);                // mask: 1 where Src >= 2^31
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I32_MIN, TMP1, TMP2);
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
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F64_2P63, TMP1, TMP2);
    xvcmpgedp(VTMP1, Src, VTMP2);
    EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_I64_MIN, TMP1, TMP2);
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
  // BOUND FIX (2026-08-05): this compared against 2^63 while claiming to be
  // 2^31 — f64 values in [2^31, 2^63) kept POWER's INT_MAX saturation
  // instead of x86's 0x80000000 indefinite. The i32 overflow boundary is
  // 2^31, and the compare uses the ROUNDED value (VTMP1), not Src: an input
  // like 2^31 - 0.4 rounds up to exactly 2^31 and must also go indefinite.
  // Negative overflow needs no mask: POWER already saturates to INT_MIN,
  // which IS the sentinel. NaN: xvcmpgedp returns 0 (unordered), and POWER's
  // NaN convert is already INT_MIN — correct either way.
  EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_F64_2P31, TMP1, TMP2);
  xvcmpgedp(VTMP2, VTMP1, VTMP2);             // per-i64-lane overflow mask (rounded src)
  EmitLoadPPC64VConst(VTMP1, FEXCore::CPU::PPC64_VCONST_I32_MIN, TMP1, TMP2);
  xxsel(Dst, Dst, VTMP1, VTMP2);              // mask ? INT_MIN : Dst (per-byte == per-i32-lane here)

  // Now pack the (possibly INT_MIN-substituted) i32 results to LE-low.
  EmitLoadPPC64VConst(VTMP2, FEXCore::CPU::PPC64_VCONST_PACK_DW_LO_I32, TMP1, TMP2);
  vspltisw(VTMP1, 0);
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
static const ::FEXCore::CPU::PPC64RuntimeTables PPC64Tables = {
  .Helpers = {
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
  [::FEXCore::CPU::PPC64_HELPER_F16x4ToF32x4]     = reinterpret_cast<uint64_t>(&PPC64_F16x4ToF32x4),
  [::FEXCore::CPU::PPC64_HELPER_F32x4ToF16x4]     = reinterpret_cast<uint64_t>(&PPC64_F32x4ToF16x4),
  },
  // 128-bit constant pool. Each entry is written the way the inline
  // LoadConstant/std/std/lvx sequences it replaces wrote it: the first
  // doubleword is what went to the low address (r1-16) and the second is what
  // went to r1-8. An lvx of the pair therefore reproduces the same register
  // image, so no endianness argument is needed to justify a conversion --
  // it is the identical 16 bytes.
  .Constants = {
    [2 * ::FEXCore::CPU::PPC64_VCONST_F32_2P31 + 0] = 0x4F0000004F000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F32_2P31 + 1] = 0x4F0000004F000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_I32_MIN  + 0] = 0x8000000080000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_I32_MIN  + 1] = 0x8000000080000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_2P63 + 0] = 0x43E0000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_2P63 + 1] = 0x43E0000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_2P31 + 0] = 0x41E0000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_2P31 + 1] = 0x41E0000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_I64_MIN  + 0] = 0x8000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_I64_MIN  + 1] = 0x8000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_PACK_DW_LO_I32 + 0] = 0x040506070C0D0E0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_PACK_DW_LO_I32 + 1] = 0x1010101010101010ULL,
    // All-ones over guest bytes 0-3 (LE f32 element 0), zero elsewhere. In
    // the register image after lvx this covers exactly the elem0 lane, so
    // `xxsel(Dst, Vec1, Result, MASK)` implements SSE scalar-insert merges.
    [2 * ::FEXCore::CPU::PPC64_VCONST_LANE0_MASK_F32 + 0] = 0x00000000FFFFFFFFULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_LANE0_MASK_F32 + 1] = 0x0000000000000000ULL,
    // CRC-32C Barrett constants: value in dw0 (entry [+1]), dw1 zero.
    [2 * ::FEXCore::CPU::PPC64_VCONST_CRC32C_MU + 0]     = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_CRC32C_MU + 1]     = 0xA434F61C6F5389F8ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_CRC32C_P + 0]      = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_CRC32C_P + 1]      = 0x0000000105EC76F1ULL,
    // VAddP vperm controls (values verbatim from the old inline builds).
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_B + 0]   = 0x01030507090B0D0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_B + 1]   = 0x11131517191B1D1FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_B + 0]    = 0x00020406080A0C0EULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_B + 1]    = 0x10121416181A1C1EULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_H + 0]   = 0x020306070A0B0E0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_H + 1]   = 0x121316171A1B1E1FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_H + 0]    = 0x0001040508090C0DULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_H + 1]    = 0x1011141518191C1DULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_W + 0]   = 0x040506070C0D0E0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_W + 1]   = 0x141516171C1D1E1FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_W + 0]    = 0x0001020308090A0BULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_W + 1]    = 0x1011121318191A1BULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_B64 + 0] = 0x191B1D1F090B0D0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_B64 + 1] = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_B64 + 0]  = 0x181A1C1E080A0C0EULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_B64 + 1]  = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_H64 + 0] = 0x1A1B1E1F0A0B0E0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_H64 + 1] = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_H64 + 0]  = 0x18191C1D08090C0DULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_H64 + 1]  = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_W64 + 0] = 0x1C1D1E1F0C0D0E0FULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_EVEN_W64 + 1] = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_W64 + 0]  = 0x18191A1B08090A0BULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_ADDP_ODD_W64 + 1]  = 0x0000000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_MULH_HI_I16 + 0]   = 0x181908091C1D0C0DULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_MULH_HI_I16 + 1]   = 0x1011000114150405ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_ONE + 0]       = 0x3FF0000000000000ULL,
    [2 * ::FEXCore::CPU::PPC64_VCONST_F64_ONE + 1]       = 0x3FF0000000000000ULL,
  },
};
} // namespace

// Handed to CpuStateFrame::PPC64_HelperTable at thread-JIT construction.
// The pointer is stable for program lifetime. It addresses the whole
// table/pool allocation: Helpers is at offset 0 (so every existing helper
// call site is unaffected) and the 128-bit constant pool sits at
// PPC64VConstPoolOffset from the same base.
uint64_t* GetPPC64HelperTable() {
  return const_cast<uint64_t*>(PPC64Tables.Helpers);
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

// ===========================================================================
// AES-NI, lowered to the POWER8 (ISA 2.07) hardware cipher instructions.
//
// These used to bridge to scalar C helpers (PPC64_VAESEnc et al.) through the
// FABI mini-frame. That cost a stack frame, two stvx, a FULL dynamic-VR
// SpillForABICall/FillForABICall pair and an indirect call PER GUEST
// INSTRUCTION, on top of a byte-at-a-time software round - measured at ~49% of
// all Steam CPU during a download (PPC64_VAESDec + AES_InvMixColumns). The
// sequences below are 6-7 instructions, touch no memory, and are not calls, so
// they also stop acting as register-allocator barriers.
//
// TWO THINGS MAKE THIS WORK (see also the crypto block in CodeEmitter's
// Emitter.h and the vs14-vs31 hazard note in PPC64Emitter.h):
//
//  1. BYTE ORDER. The hardware reads the AES state big-endian (state byte 0 at
//     BE byte element 0); a guest XMM lives here with guest byte 0 at BE
//     element 15. AES state is a byte ARRAY, so unlike a 128-bit integer the
//     two images do not coincide and the difference cannot be absorbed
//     algebraically - reversal maps state index i -> 15-i, i.e.
//     (row,col) -> (3-row,3-col), which flips ShiftRows' direction and changes
//     MixColumns' circulant. Hence a vperm on the way in and on the way out.
//
//  2. THE EQUIVALENT-INVERSE-CIPHER MISMATCH. vncipher applies InvMixColumns
//     after its VRB xor, x86 AESDEC applies it before. InvMixColumns is
//     GF(2)-linear so InvMixColumns(0) == 0: feeding VRB=0 and xoring the round
//     key separately is exact. This is what makes the software InvMixColumns
//     unnecessary rather than merely faster.
//
// Register discipline, uniform across all five: VTMP1 is a rotating scratch
// holding either the reverse mask or zero (both copied in with one xxlor from
// the RA-free pinned low-bank slots), VTMP2 carries the state. Dst is written
// only by the final instruction, after every source has been read, so Dst may
// safely alias State and/or Key - the Dst==Src aliasing case that has bitten
// this backend before is correct by construction here.
// ===========================================================================

// STATELESS byte-reverse bracketing. This deliberately trusts NO vector
// register contents from before the current guest instruction.
//
// An earlier revision pinned the reverse mask in vs15 (beside VZERO_VSX in the
// "RA-free, callee-saved" low VSX bank) and copied it in with one xxlor. That
// design was built on a false premise, found the hard way when Steam's 32-bit
// manifest decryption produced garbage for exactly the >=64-byte inputs (the
// AESNI-routed ones) while every isolated KAT passed:
//
//   ELFv2 preserves only the FPR HALF (dw0) of vs14-vs31 across calls - the
//   vector half is volatile. Worse, POWER ISA scalar FP loads leave dw1 of
//   the target VSR UNDEFINED, so any host callee that stfd/lfd-restores
//   f14/f15 in its epilogue (glibc has eight such sites) hands back a
//   half-poisoned register. Any lowering that reads the full 128 bits of a
//   "pinned" vs14-vs31 value after an arbitrary host call is wrong by
//   construction. The same hazard applies to VZERO_VSX consumers that read
//   its vector half, and to the AVX-high bank (vs16-31) across host calls.
//
// Materializing the mask is 4 instructions, no memory access:
//   li r0,0 (also preserves the backend's r0==0 index invariant),
//   vspltisb {15,...,15}, lvsl@EA=0 {0,...,15}, subtract -> {15,...,0}.
// The mask is then parked in VTMP3_VSX (vs12) across the cipher instruction -
// legal because it is never live across a host call within a single lowering -
// and pulled back for the outbound reversal.

// ---------------------------------------------------------------------------
// ISA 3.0 (POWER9) ARM.
//
// xxbrq reverses all 16 bytes of a VSR in ONE instruction, which is exactly
// the G-image <-> AES-state-image bridge the mask+vperm above is emulating.
// With it the whole mask apparatus disappears: no {15..0} materialization, no
// vs12 park, no AESMaskCached bookkeeping, and no lvsl scratch clobber. The
// key-folding structure is unchanged - revKey is just xxbrq instead of vperm,
// and still feeds vcipher/vcipherlast/vncipherlast directly.
//
// Every AES handler below is written as two obviously parallel arms selected
// on CTX->HostFeatures.SupportsISA30 (the JIT-layer spelling of the gate;
// PPC64Emitter.cpp says EmitterCTX->HostFeatures.SupportsISA30 for the same
// field - LoadUnalignedV128 is the canonical example). Emitting xxbrq on
// POWER8 is a SIGILL, so the gate is load-bearing, and with it OFF the
// POWER8 arm is byte-for-byte what it was before this change.
//
// AESMaskCached is untouched by the ISA 3.0 arm: EmitAESLoadMask is the only
// writer of that flag and only the POWER8 arm calls it, so on an ISA 3.0 host
// the flag is false for the life of the process and the vs12 park is never
// created OR consumed. Nothing in the ISA 3.0 arm reads VTMP3_VSX.
//
// Instruction counts per guest op (POWER8 hot / POWER8 cold / ISA 3.0):
//   VAESEnc, VAESEncLast, VAESDecLast   5 / 8 / 4
//   VAESDec                             6 / 9 / 5
//   VAESImc                             7 / 10 / 5
// The ISA 3.0 arm also drops the r0 write and the VTMP2 cold-path clobber.
// ---------------------------------------------------------------------------

// VTMP1 <- {15,...,0} byte-reverse mask. Cold: 4-instruction register-only
// materialization, then parked in VTMP3_VSX (vs12) and AESMaskCached set so
// consecutive AES-family ops in the block pay a single xxlor instead.
// Clobbers VTMP2 on the cold path (lvsl scratch) - callers load state after.
// POWER8 (ISA 2.07) arm only - never called when SupportsISA30 is set.
void PPC64JITCore::EmitAESLoadMask() {
  if (AESMaskCached) {
    xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
    return;
  }
  li(r(0), 0);
  vspltisb(VTMP1, 15);
  lvsl(VTMP2, r(0), r(0));
  vsububm(VTMP1, VTMP1, VTMP2);
  xxlor(VTMP3_VSX, AsVSX(VTMP1), AsVSX(VTMP1));
  AESMaskCached = true;
}

// AESIMC: out = InvMixColumns(src).
// vcipherlast(S,0) = ShiftRows(SubBytes(S)); vncipher's leading
// InvShiftRows/InvSubBytes then cancel those exactly, leaving InvMixColumns.
DEF_OP(VAESImc) {
  // Same width guard as the four round ops. VAESIMC is 128-bit-only in
  // practice, but this handler is on the AES-family allowlist in
  // CompileCode's mask-cache invalidation switch, so a bail through
  // Op_Unhandled (a host call) must kill the vs12 park explicitly.
  if (IROp->Size != IR::OpSize::i128Bit) { InvalidateAESCache(); Op_Unhandled(IROp, Node); return; }
  const auto Op  = IROp->C<IR::IROp_VAESImc>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Vector);

  if (CTX->HostFeatures.SupportsISA30) {
    xxbrq(VTMP2, Src);
    vxor(VTMP1, VTMP1, VTMP1); // stateless zero - never read VZERO's vector half
    vcipherlast(VTMP2, VTMP2, VTMP1);
    vncipher(VTMP2, VTMP2, VTMP1);
    xxbrq(Dst, VTMP2);
    return;
  }

  EmitAESLoadMask();
  vperm(VTMP2, Src, Src, VTMP1);
  vxor(VTMP1, VTMP1, VTMP1);   // stateless zero - never read VZERO's vector half
  vcipherlast(VTMP2, VTMP2, VTMP1);
  vncipher(VTMP2, VTMP2, VTMP1);
  xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
  vperm(Dst, VTMP2, VTMP2, VTMP1);
}

// The four round ops, with two fusions over the naive bracketed form:
//
//  * MASK REUSE: EmitAESLoadMask parks the byte-reverse mask in vs12; runs of
//    adjacent AES ops (every real-world AES code shape - key schedules, CBC
//    interleaves, round chains) rebuild it with one xxlor instead of four
//    instructions. CompileCode invalidates the park on any other op.
//
//  * KEY FOLDING: vcipher/vcipherlast/vncipherlast apply their B operand xor
//    at the same point x86 applies the round key, so feeding them the
//    byte-REVERSED key computes the whole x86 op in one instruction - the
//    separate zero operand and trailing vxor disappear. AESDEC alone cannot
//    fold: vncipher xors B BEFORE InvMixColumns (equivalent inverse cipher),
//    x86 after, so it keeps the zero-operand + explicit key xor form. The
//    InvMixColumns(0) == 0 linearity argument makes that exact - see the
//    block comment above DEF_OP(VAESImc).
//
// Aliasing: every source is fully consumed before Dst is written (the final
// vperm/vxor reads its sources in the same instruction), so Dst may alias
// State, Key, or both. The SSE forms alias Dst==State on every instruction.

DEF_OP(VAESEnc) {
  if (IROp->Size != IR::OpSize::i128Bit) { InvalidateAESCache(); Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESEnc>();
  const auto Dst = GetVReg(Node);
  const auto State = GetVReg(Op->State);
  const auto Key = GetVReg(Op->Key);

  if (CTX->HostFeatures.SupportsISA30) {
    xxbrq(VTMP2, State);          // revState
    xxbrq(VTMP1, Key);            // revKey
    vcipher(VTMP2, VTMP2, VTMP1); // rev(MixColumns(ShiftRows(SubBytes(s))) ^ k)
    xxbrq(Dst, VTMP2);
    return;
  }

  EmitAESLoadMask();
  vperm(VTMP2, State, State, VTMP1);   // revState
  vperm(VTMP1, Key, Key, VTMP1);       // revKey (self-overwrite of mask is fine)
  vcipher(VTMP2, VTMP2, VTMP1);        // rev(MixColumns(ShiftRows(SubBytes(s))) ^ k)
  xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
  vperm(Dst, VTMP2, VTMP2, VTMP1);
}

DEF_OP(VAESEncLast) {
  if (IROp->Size != IR::OpSize::i128Bit) { InvalidateAESCache(); Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESEncLast>();
  const auto Dst = GetVReg(Node);
  const auto State = GetVReg(Op->State);
  const auto Key = GetVReg(Op->Key);

  if (CTX->HostFeatures.SupportsISA30) {
    xxbrq(VTMP2, State);
    xxbrq(VTMP1, Key);
    vcipherlast(VTMP2, VTMP2, VTMP1); // rev(ShiftRows(SubBytes(s)) ^ k)
    xxbrq(Dst, VTMP2);
    return;
  }

  EmitAESLoadMask();
  vperm(VTMP2, State, State, VTMP1);
  vperm(VTMP1, Key, Key, VTMP1);
  vcipherlast(VTMP2, VTMP2, VTMP1);    // rev(ShiftRows(SubBytes(s)) ^ k)
  xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
  vperm(Dst, VTMP2, VTMP2, VTMP1);
}

// AESDEC(A,K) = InvMixColumns(InvSubBytes(InvShiftRows(A))) ^ K.
// vncipher(A,0) = InvMixColumns(InvSubBytes(InvShiftRows(A)) ^ 0), and
// InvMixColumns is GF(2)-linear so InvMixColumns(0) == 0 - the two agree
// exactly once the key xor is pulled out. This identity is the whole reason
// the old scalar AES_InvMixColumns helper is gone.
DEF_OP(VAESDec) {
  if (IROp->Size != IR::OpSize::i128Bit) { InvalidateAESCache(); Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESDec>();
  const auto Dst = GetVReg(Node);
  const auto State = GetVReg(Op->State);
  const auto Key = GetVReg(Op->Key);

  if (CTX->HostFeatures.SupportsISA30) {
    xxbrq(VTMP2, State);
    vxor(VTMP1, VTMP1, VTMP1); // stateless zero - never read VZERO's vector half
    vncipher(VTMP2, VTMP2, VTMP1);
    xxbrq(VTMP2, VTMP2);
    vxor(Dst, VTMP2, Key);     // Key read in the same insn that writes Dst
    return;
  }

  EmitAESLoadMask();
  vperm(VTMP2, State, State, VTMP1);
  vxor(VTMP1, VTMP1, VTMP1);   // stateless zero - never read VZERO's vector half
  vncipher(VTMP2, VTMP2, VTMP1);
  xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
  vperm(VTMP2, VTMP2, VTMP2, VTMP1);
  vxor(Dst, VTMP2, Key);
}

DEF_OP(VAESDecLast) {
  if (IROp->Size != IR::OpSize::i128Bit) { InvalidateAESCache(); Op_Unhandled(IROp, Node); return; }
  const auto Op = IROp->C<IR::IROp_VAESDecLast>();
  const auto Dst = GetVReg(Node);
  const auto State = GetVReg(Op->State);
  const auto Key = GetVReg(Op->Key);

  if (CTX->HostFeatures.SupportsISA30) {
    xxbrq(VTMP2, State);
    xxbrq(VTMP1, Key);
    vncipherlast(VTMP2, VTMP2, VTMP1); // rev(InvSubBytes(InvShiftRows(s)) ^ k) - xor is after, folds
    xxbrq(Dst, VTMP2);
    return;
  }

  EmitAESLoadMask();
  vperm(VTMP2, State, State, VTMP1);
  vperm(VTMP1, Key, Key, VTMP1);
  vncipherlast(VTMP2, VTMP2, VTMP1);   // rev(InvSubBytes(InvShiftRows(s)) ^ k) - xor is after, folds
  xxlor(AsVSX(VTMP1), VTMP3_VSX, VTMP3_VSX);
  vperm(Dst, VTMP2, VTMP2, VTMP1);
}

// AESKEYGENASSIST: x86 takes Src=[X3,X2,X1,X0] (32-bit lanes) and produces
//   out[0..31]   = SubWord(X1)                                 (LE bytes 0..3)
//   out[32..63]  = RotWord(SubWord(X1)) XOR RCON               (LE bytes 4..7)
//   out[64..95]  = SubWord(X3)                                 (LE bytes 8..11)
//   out[96..127] = RotWord(SubWord(X3)) XOR RCON               (LE bytes 12..15)
// SubWord is the AES SBox per byte; RotWord takes a 4-byte LE word
// [a,b,c,d] -> [b,c,d,a].
//
// vsbox is the forward SBox per byte, so - being bytewise - it needs no byte
// reversal, unlike the round ops above. One vperm then reshuffles the SBoxed
// bytes straight into the x86 layout (its mask already folds in this
// backend's LE-byte = phys-byte(15-i) mapping), and a vxor injects RCON.
//
// Unlike the AES rounds this still needs a real 16-byte constant, so it takes
// the one memory bounce here - through STATE+JITScratch, NOT an r1-relative
// red-zone slot. The red zone is nominally 288B under ELFv2, but an
// r1-relative scratch has been observed to fault on tight clone-allocated
// stacks whose mapping ended early (see the block comment on
// StoreFPRSized in PPC64Emitter.cpp). KeyGenAssist runs once per key
// schedule, so the store-to-load-forward stall is irrelevant here.
DEF_OP(VAESKeyGenAssist) {
  if (IROp->Size != IR::OpSize::i128Bit) { Op_Unhandled(IROp, Node); return; }
  const auto Op  = IROp->C<IR::IROp_VAESKeyGenAssist>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Src);
  const uint64_t RCON = static_cast<uint64_t>(Op->RCON) & 0xFFu;
  // KeyGenTBLSwizzle and ZeroReg remain valid IR sources so RA keeps the live
  // ranges sound, but no host instruction reads them on this path.

  constexpr int32_t kScratchOff = offsetof(::FEXCore::Core::CpuStateFrame, JITScratch);
  static_assert(kScratchOff >= -32768 && kScratchOff <= 32767,
                "JITScratch offset must fit in int16 for addi-based addressing");

  // VTMP1 = SubBytes(Src), bytewise so order-agnostic.
  vsbox(VTMP1, Src);

  // Gather mask, in PPC physical-byte order:
  //   phys[0..15] = [3,0,1,2, 0,1,2,3, 11,8,9,10, 8,9,10,11]
  // Stored little-endian: mem byte M lands at phys byte (15-M), so
  //   mem[0..7]  = phys[15..8] = [11,10,9,8,10,9,8,11] = 0x0B08090A08090A0B
  //   mem[8..15] = phys[7..0]  = [3,2,1,0,2,1,0,3]     = 0x0300010200010203
  addi(TMP3, STATE, static_cast<int16_t>(kScratchOff));
  LoadConstant(TMP1, 0x0B08090A08090A0BULL); std(TMP1, 0, TMP3);
  LoadConstant(TMP1, 0x0300010200010203ULL); std(TMP1, 8, TMP3);
  li(TMP1, 0);
  lvx(VTMP2, TMP3, TMP1);
  vperm(VTMP1, VTMP1, VTMP1, VTMP2);

  if (RCON != 0) {
    // RCON lands at LE bytes 4 and 12, i.e. phys bytes 11 and 3. In each
    // doubleword that is mem byte 4, so both halves are the same value.
    const uint64_t RconWord = RCON << 32;
    LoadConstant(TMP1, RconWord);
    std(TMP1, 0, TMP3);
    std(TMP1, 8, TMP3);
    li(TMP1, 0);
    lvx(VTMP2, TMP3, TMP1);
    vxor(Dst, VTMP1, VTMP2);
  } else if (Dst != VTMP1) {
    vmr(Dst, VTMP1);
  }
}

// VSha1H: rotate-left 30 of element 0 (32-bit), upper lanes zeroed.
// Trivial enough that we could inline-emit it, but we already have a helper
// and consistency with the rest of the SHA path is more readable.
// VSha1H: rotate-left-30 of guest element 0, upper lanes zeroed. Pure lane
// arithmetic — vrlw rotates every 32-bit lane (the upper lanes' rotated
// garbage is masked off), then the pooled lane0 mask isolates element 0.
// Replaces a full FABI mini-frame + spill/fill + bctrl with 6 inline
// instructions and no memory traffic beyond the pool lvx.
DEF_OP(VSha1H) {
  const auto Op  = IROp->C<IR::IROp_VSha1H>();
  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->Src);

  vspltisw(VTMP2, 15);
  vadduwm(VTMP2, VTMP2, VTMP2);        // splat 30 (vspltisw imm caps at 15)
  vrlw(VTMP1, Src, VTMP2);
  EmitLoadPPC64VConst(VTMP2, PPC64_VCONST_LANE0_MASK_F32, TMP1, TMP2);
  vand(Dst, VTMP1, VTMP2);
}

// SHA1 / SHA256 round-step ops. POWER8 has no SHA-NI-equivalent round
// instructions, but everything below is now emitted inline (vshasigmaw for
// the SHA-256 Sigmas, plain VMX rotate/select/add for the rest). The
// EMIT_SHA_3ARG/2ARG FABI macros that used to bridge these to the PPC64_VSha*
// software helpers are gone; the helpers remain in JIT.cpp as reference
// implementations reachable only through their (now-unused) table slots.
// The IR ops mirror the ARMv8 SHA1*/SHA256* semantics (FIPS-180-4), since
// the x86 SHA-NI dispatcher pre-shuffles inputs to the ARM lane layout
// (see Crypto.cpp).

// ===========================================================================
// SHA-1 four-round step (VSha1C/M/P), fully inline. Ground truth is the
// retired helper's Sha1Hash (JIT.cpp): VA=[A,B,C,D] guest lanes 0-3, E scalar
// in Src2 lane 0, WK=[W+K 0..3]. Per round:
//   T = ROL(A,5) + f(B,C,D) + E + WK[i]
//   E=D; D=C; C=ROL(B,30); B=A; A=T
// f per flavor, on the lane rotations A1=[B,C,D,A], A2=[C,D,A,B], A3=[D,A,B,C]
// (lane 0 = B / C / D respectively):
//   Choose  (B&C)|(~B&D)      = vsel(A3, A2, A1)
//   Majority (two-of-three)   = (C^D) ? B : C = vsel(A2, A1, vxor(A2,A3))
//   Parity                    = A1 ^ A2 ^ A3
// The state update is the neat part: [T,A,B,C] via vsel(A3, T, LANE0_MASK),
// then ONE vrlw against the per-lane rotate vector {0,0,30,0} applies the
// ROL(B,30) to lane 2 alone. The next round's E is old D = A3 lane 0, free.
// Same two-dyn-VR borrow protocol as EmitSha256Rounds4.
void PPC64JITCore::EmitSha1Rounds4(PPC64Emitter::VR Dst, PPC64Emitter::VR ABCD, PPC64Emitter::VR E,
                                   PPC64Emitter::VR WK, Sha1Fn Fn) {
  using namespace PPC64Emitter;
  constexpr auto S_VA  = VSXR{2};
  constexpr auto S_E   = VSXR{3};
  constexpr auto S_WK  = VSXR{4};
  constexpr auto S_M0  = VSXR{5};
  constexpr auto S_SHV = VSXR{6};
  constexpr auto S_A3  = VSXR{7};
  constexpr auto S_B1  = VSXR{8};
  constexpr auto S_B2  = VSXR{9};

  VR Borrow[2] = {VR{0}, VR{0}};
  for (uint32_t idx = 16, found = 0; idx <= 29 && found < 2; ++idx) {
    if (idx == Dst.idx || idx == ABCD.idx || idx == E.idx || idx == WK.idx) continue;
    Borrow[found++] = VR{idx};
  }
  const VR B1 = Borrow[0], B2 = Borrow[1];

  xxlor(S_B1, AsVSX(B1), AsVSX(B1));
  xxlor(S_B2, AsVSX(B2), AsVSX(B2));
  EmitLoadPPC64VConst(VTMP1, PPC64_VCONST_LANE0_MASK_F32, TMP1, TMP2);
  xxlor(S_M0, AsVSX(VTMP1), AsVSX(VTMP1));
  // Per-lane rotate vector {0,0,30,0}: splat 30, mask to lane 2 (the lane0
  // mask rotated by two guest lanes).
  vspltisw(VTMP2, 15);
  vadduwm(VTMP2, VTMP2, VTMP2);
  vsldoi(VTMP1, VTMP1, VTMP1, 8);      // lane0 mask -> lane2 mask
  vand(VTMP1, VTMP2, VTMP1);
  xxlor(S_SHV, AsVSX(VTMP1), AsVSX(VTMP1));
  xxlor(S_VA, AsVSX(ABCD), AsVSX(ABCD));
  xxlor(S_E, AsVSX(E), AsVSX(E));
  xxlor(S_WK, AsVSX(WK), AsVSX(WK));

  for (int i = 0; i < 4; ++i) {
    xxlor(AsVSX(VTMP2), S_VA, S_VA);     // VA = [A,B,C,D]
    vsldoi(B1, VTMP2, VTMP2, 12);        // A1 = [B,C,D,A]
    vsldoi(B2, VTMP2, VTMP2, 8);         // A2 = [C,D,A,B]
    vsldoi(VTMP1, VTMP2, VTMP2, 4);      // A3 = [D,A,B,C]
    xxlor(S_A3, AsVSX(VTMP1), AsVSX(VTMP1));
    switch (Fn) {
    case Sha1Fn::Choose:
      vsel(B1, VTMP1, B2, B1);           // B ? C : D
      break;
    case Sha1Fn::Majority:
      vxor(VTMP2, B2, VTMP1);            // C^D  (VA dead past here)
      vsel(B1, B2, B1, VTMP2);           // (C^D) ? B : C
      break;
    case Sha1Fn::Parity:
      vxor(B1, B1, B2);
      vxor(B1, B1, VTMP1);
      break;
    }
    // T = f + ROL(A,5) + E + WK[i], accumulated in B1 (lane 0).
    xxlor(AsVSX(VTMP2), S_VA, S_VA);
    vspltisw(B2, 5);
    vrlw(VTMP2, VTMP2, B2);              // ROL(A,5) in lane 0
    vadduwm(B1, B1, VTMP2);
    xxlor(AsVSX(VTMP2), S_E, S_E);
    vadduwm(B1, B1, VTMP2);
    xxlor(AsVSX(VTMP2), S_WK, S_WK);
    if (i) vsldoi(VTMP2, VTMP2, VTMP2, 4 * (4 - i));  // WK[i] -> lane 0
    vadduwm(B1, B1, VTMP2);              // T

    // E' = old D (A3 lane 0); VA' = vrlw(vsel(A3, T, mask0), {0,0,30,0}).
    xxlor(S_E, S_A3, S_A3);
    xxlor(AsVSX(VTMP1), S_A3, S_A3);     // [D,A,B,C]
    xxlor(AsVSX(VTMP2), S_M0, S_M0);
    vsel(VTMP1, VTMP1, B1, VTMP2);       // [T,A,B,C]
    xxlor(AsVSX(VTMP2), S_SHV, S_SHV);
    vrlw(VTMP1, VTMP1, VTMP2);           // [T,A,ROL(B,30),C]
    xxlor(S_VA, AsVSX(VTMP1), AsVSX(VTMP1));
  }

  xxlor(AsVSX(VTMP1), S_VA, S_VA);
  xxlor(AsVSX(B1), S_B1, S_B1);
  xxlor(AsVSX(B2), S_B2, S_B2);
  vmr(Dst, VTMP1);
}

DEF_OP(VSha1C) {
  const auto Op = IROp->C<IR::IROp_VSha1C>();
  EmitSha1Rounds4(GetVReg(Node), GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), Sha1Fn::Choose);
}
DEF_OP(VSha1M) {
  const auto Op = IROp->C<IR::IROp_VSha1M>();
  EmitSha1Rounds4(GetVReg(Node), GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), Sha1Fn::Majority);
}
DEF_OP(VSha1P) {
  const auto Op = IROp->C<IR::IROp_VSha1P>();
  EmitSha1Rounds4(GetVReg(Node), GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), Sha1Fn::Parity);
}

// SHA1SU1(Vd, Vn): T[k] = Vd[k] ^ Vn[k+1] (Vn term zero for k=3), then
// r[k] = ROL(T[k],1) with the lane-3 recurrence r[3] = ROL(T[3]^r[0], 1).
// Rotate distributes over XOR, so the recurrence folds to one correction:
// r = ROL(T,1);  r[3] ^= ROL(T[0], 2). Dst is usable as scratch once both
// sources are consumed.
DEF_OP(VSha1SU1) {
  const auto Op = IROp->C<IR::IROp_VSha1SU1>();
  const auto Dst = GetVReg(Node);
  const auto Vd  = GetVReg(Op->Src1);
  const auto Vn  = GetVReg(Op->Src2);

  vxor(VTMP1, VTMP1, VTMP1);
  vsldoi(VTMP1, VTMP1, Vn, 12);        // [Vn1,Vn2,Vn3,0] (guest lanes)
  vxor(VTMP1, Vd, VTMP1);              // T
  vspltisw(VTMP2, 1);
  vrlw(VTMP2, VTMP1, VTMP2);           // ROL(T,1) — both sources now dead
  vspltisw(Dst, 2);
  vrlw(VTMP1, VTMP1, Dst);             // ROL(T,2)
  vxor(Dst, Dst, Dst);
  vsldoi(VTMP1, VTMP1, Dst, 12);       // [0,0,0,ROL(T0,2)] at guest lane 3
  vxor(Dst, VTMP2, VTMP1);
}
// ===========================================================================
// SHA256RNDS2 (VSha256H / VSha256H2), fully inline via POWER8 vshasigmaw ST=1.
//
// Ground truth is the retired FABI helper's Sha256Round4 (JIT.cpp): four
// FIPS-180 rounds over VA=[A,B,C,D], VE=[E,F,G,H] (guest lane 0 = A / E),
// WK=[W+K 0..3]. Per round:
//   T1 = H + BigSigma1(E) + Ch(E,F,G) + WK[i]
//   T2 = BigSigma0(A) + Maj(A,B,C)
//   VE' = [D+T1, E, F, G]     VA' = [T1+T2, A, B, C]
// Everything vectorizes with lane 0 carrying the live value (other lanes
// compute garbage that the final vsel discards):
//   BigSigma:  vshasigmaw ST=1 (SIX=0xF -> Sigma1, SIX=0 -> Sigma0), lane-wise.
//   Ch(E,F,G): vsel(V2, V1, VE) with V1/V2 the lane rotations of VE.
//   Maj(A,B,C) = (B^C) ? A : B = vsel(A1, VA, vxor(A1,A2)).
//   State insert: vsel(rotated_state, new_value, LANE0_MASK).
// LANE ORDER NOTE: guest lane k sits at BE word (3-k), so a guest
// "lane k <- lane k+1" rotation is vsldoi by 12, k+2 by 8, k+3 by 4 —
// mirrored from the BE-intuitive values. Derived and checked by hand; the
// GuestCrypto sha_test full-message vectors are the enforcement.
//
// REGISTER BUDGET: the backend owns only VTMP1/VTMP2 in VMX, and every VMX op
// here (vsel/vsldoi/vshasigmaw/vadduwm) physically cannot address the VSX low
// bank. So the emitter BORROWS two dynamic VRs (never Dst or a source): their
// values are parked in the RA-free low VSX bank via xxlor and restored at the
// end. This is call-free, memory-free (registers only), and async signals
// restore the full file via sigreturn, so the borrow window is sound — the
// same trust model as VTMP3_VSX's "not live across a host call" rule.
// Round state parks in vs2-vs8; all op-local, per the vs14-vs31 hazard note
// (nothing here survives, or needs to survive, a host call).
void PPC64JITCore::EmitSha256Rounds4(PPC64Emitter::VR Dst, PPC64Emitter::VR ABCD, PPC64Emitter::VR EFGH,
                                     PPC64Emitter::VR WK, bool ReturnABCD) {
  using namespace PPC64Emitter;
  constexpr auto S_VA   = VSXR{2};
  constexpr auto S_VE   = VSXR{3};
  constexpr auto S_WK   = VSXR{4};
  constexpr auto S_MASK = VSXR{5};
  constexpr auto S_HV   = VSXR{6};
  constexpr auto S_B1   = VSXR{7};
  constexpr auto S_B2   = VSXR{8};

  // Borrow two dynamic-pool VRs distinct from Dst and every source. v16-v29
  // are RA-owned in both guest modes; saving/restoring makes any choice safe.
  VR Borrow[2] = {VR{0}, VR{0}};
  for (uint32_t idx = 16, found = 0; idx <= 29 && found < 2; ++idx) {
    if (idx == Dst.idx || idx == ABCD.idx || idx == EFGH.idx || idx == WK.idx) continue;
    Borrow[found++] = VR{idx};
  }
  const VR B1 = Borrow[0], B2 = Borrow[1];

  xxlor(S_B1, AsVSX(B1), AsVSX(B1));
  xxlor(S_B2, AsVSX(B2), AsVSX(B2));
  EmitLoadPPC64VConst(VTMP1, PPC64_VCONST_LANE0_MASK_F32, TMP1, TMP2);
  xxlor(S_MASK, AsVSX(VTMP1), AsVSX(VTMP1));
  xxlor(S_VA, AsVSX(ABCD), AsVSX(ABCD));
  xxlor(S_VE, AsVSX(EFGH), AsVSX(EFGH));
  xxlor(S_WK, AsVSX(WK), AsVSX(WK));

  for (int i = 0; i < 4; ++i) {
    // T1 = H + BigSigma1(E) + Ch(E,F,G) + WK[i], accumulated in B2 (lane 0).
    xxlor(AsVSX(VTMP2), S_VE, S_VE);      // VE = [E,F,G,H]
    vsldoi(B1, VTMP2, VTMP2, 12);         // V1 = [F,G,H,E]
    vsldoi(B2, VTMP2, VTMP2, 8);          // V2 = [G,H,E,F]
    vsel(B2, B2, B1, VTMP2);              // Ch: E ? F : G
    vshasigmaw(B1, VTMP2, 1, 0xF);        // BigSigma1 per lane
    vadduwm(B2, B2, B1);
    vsldoi(VTMP1, VTMP2, VTMP2, 4);       // Hv = [H,E,F,G]
    xxlor(S_HV, AsVSX(VTMP1), AsVSX(VTMP1));
    vadduwm(B2, B2, VTMP1);               // + H
    xxlor(AsVSX(VTMP1), S_WK, S_WK);
    if (i) vsldoi(VTMP1, VTMP1, VTMP1, 4 * (4 - i));  // WK[i] -> lane 0
    vadduwm(B2, B2, VTMP1);               // T1

    // T2 = BigSigma0(A) + Maj(A,B,C); then the two new lane-0 words.
    xxlor(AsVSX(VTMP2), S_VA, S_VA);      // VA = [A,B,C,D]
    vsldoi(B1, VTMP2, VTMP2, 12);         // A1 = [B,C,D,A]
    vsldoi(VTMP1, VTMP2, VTMP2, 8);       // A2 = [C,D,A,B]
    vxor(VTMP1, B1, VTMP1);               // t = B^C (lane 0)
    vsel(B1, B1, VTMP2, VTMP1);           // Maj: t ? A : B
    vshasigmaw(VTMP1, VTMP2, 1, 0);       // BigSigma0 per lane
    vadduwm(B1, B1, VTMP1);               // T2
    vadduwm(B1, B1, B2);                  // newA = T1 + T2
    vsldoi(VTMP1, VTMP2, VTMP2, 4);       // Dv = [D,A,B,C]
    vadduwm(B2, B2, VTMP1);               // newE = T1 + D

    // Rotate the new words in through lane 0.
    xxlor(AsVSX(VTMP2), S_MASK, S_MASK);
    vsel(B1, VTMP1, B1, VTMP2);           // VA' = [newA, A, B, C]
    xxlor(S_VA, AsVSX(B1), AsVSX(B1));
    xxlor(AsVSX(VTMP1), S_HV, S_HV);
    vsel(B2, VTMP1, B2, VTMP2);           // VE' = [newE, E, F, G]
    xxlor(S_VE, AsVSX(B2), AsVSX(B2));
  }

  if (ReturnABCD) {
    xxlor(AsVSX(VTMP1), S_VA, S_VA);
  } else {
    xxlor(AsVSX(VTMP1), S_VE, S_VE);
  }
  xxlor(AsVSX(B1), S_B1, S_B1);           // restore borrows
  xxlor(AsVSX(B2), S_B2, S_B2);
  vmr(Dst, VTMP1);
}

// SHA256H(Vd=ABCD tied, Vn=EFGH, Vm=W+K) -> post-step ABCD.
DEF_OP(VSha256H) {
  const auto Op = IROp->C<IR::IROp_VSha256H>();
  EmitSha256Rounds4(GetVReg(Node), GetVReg(Op->Src1), GetVReg(Op->Src2), GetVReg(Op->Src3), true);
}
// SHA256H2(Vd=EFGH tied, Vn=ABCD, Vm=W+K) -> post-step EFGH. Note the ARM
// operand order: Src1 is the EFGH-tied register, Src2 is ABCD.
DEF_OP(VSha256H2) {
  const auto Op = IROp->C<IR::IROp_VSha256H2>();
  EmitSha256Rounds4(GetVReg(Node), GetVReg(Op->Src2), GetVReg(Op->Src1), GetVReg(Op->Src3), false);
}
// VSha256U0(Vd, Vn): SHA-256 message schedule sigma0 helper (x86 SHA256MSG1).
//   IR_result[i] = sigma0(T[i]),  T = [Vd[1], Vd[2], Vd[3], Vn[0]], then + Vd
// POWER8 vshasigmaw with ST=0, SIX=0 is lane-wise sigma0, and was verified on
// hardware to line up lane-for-lane with the IR input. No byte reversal: these
// are 32-bit lane ops and the element convention already matches.
DEF_OP(VSha256U0) {
  const auto Op  = IROp->C<IR::IROp_VSha256U0>();
  const auto Dst = GetVReg(Node);
  const auto Vd  = GetVReg(Op->Src1);
  const auto Vn  = GetVReg(Op->Src2);

  // IR lane i lives at phys[12-4i..15-4i], so
  //   T_phys[0..3]  = Vn_phys[12..15] (IR Vn[0])
  //   T_phys[4..15] = Vd_phys[0..11]  (IR Vd[3..1])
  // vsldoi(T, Vn, Vd, 12) = (Vn::Vd) << 12 bytes = Vn[12..15] :: Vd[0..11].
  vsldoi(VTMP1, Vn, Vd, 12);
  vshasigmaw(VTMP2, VTMP1, 0, 0);
  vadduwm(Dst, VTMP2, Vd);
}

// VSha256U1(Vn, Vm): SHA-256 message schedule sigma1 helper (x86 SHA256MSG2).
//   IR_result[0] = Vn[1] + sigma1(Vm[2])
//   IR_result[1] = Vn[2] + sigma1(Vm[3])
//   IR_result[2] = Vn[3] + sigma1(IR_result[0])   <- recurrence
//   IR_result[3] = Vm[0] + sigma1(IR_result[1])   <- recurrence
// The recurrence forces two passes: lanes 0,1 first, then lanes 2,3 from
// those. With only VTMP1/VTMP2 available the partial has to be parked, so it
// goes to STATE+JITScratch rather than an r1-relative red-zone slot (see the
// note on VAESKeyGenAssist above).
DEF_OP(VSha256U1) {
  const auto Op  = IROp->C<IR::IROp_VSha256U1>();
  const auto Dst = GetVReg(Node);
  const auto Vn  = GetVReg(Op->Src1);
  const auto Vm  = GetVReg(Op->Src2);

  constexpr int32_t kScratchOff = offsetof(::FEXCore::Core::CpuStateFrame, JITScratch);
  static_assert(kScratchOff >= -32768 && kScratchOff <= 32767,
                "JITScratch offset must fit in int16 for addi-based addressing");

  // Pass 1: partial lanes 0,1. sigma1 across Vm, then slide so
  // sigma1(Vm[2,3]) land in IR lanes 0,1; slide Vn so Vn[1,2] land there too.
  vshasigmaw(VTMP1, Vm, 0, 0xF);
  vsldoi(VTMP2, VTMP1, VTMP1, 8);
  vsldoi(VTMP1, Vn, Vn, 12);
  vadduwm(VTMP1, VTMP2, VTMP1);

  // Park the partial so VTMP1 can be reused as the sigma1 input.
  addi(TMP3, STATE, static_cast<int16_t>(kScratchOff));
  li(TMP1, 0);
  stvx(VTMP1, TMP3, TMP1);

  // Pass 2: final lanes 2,3 = [Vn[3], Vm[0]] + sigma1(partial[0,1]).
  vshasigmaw(VTMP1, VTMP1, 0, 0xF);
  vsldoi(VTMP1, VTMP1, VTMP1, 8);
  vsldoi(VTMP2, Vm, Vn, 12);
  vadduwm(VTMP1, VTMP1, VTMP2);

  // Reload the partial and merge: Dst hi half (phys[0..7] = IR lanes 2,3)
  // from VTMP1, lo half (phys[8..15] = IR lanes 0,1) from the partial.
  addi(TMP3, STATE, static_cast<int16_t>(kScratchOff));
  li(TMP1, 0);
  lvx(VTMP2, TMP3, TMP1);
  xxpermdi(Dst, VTMP1, VTMP2, 0b01);
}


DEF_OP(PCLMUL) {
  const auto Op   = IROp->C<IR::IROp_PCLMUL>();
  const auto Dst  = GetVReg(Node);
  const auto Src1 = GetVReg(Op->Src1);
  const auto Src2 = GetVReg(Op->Src2);
  const uint64_t Selector = static_cast<uint64_t>(Op->Selector);

  // Only 128-bit PCLMUL is supported here; VPCLMULQDQ on 256-bit operands
  // would need two lowerings, which we leave for later (VAES/VPCLMULQDQ are
  // advertised off - see HostFeatures.cpp).
  if (IROp->Size != IR::OpSize::i128Bit) {
    Op_Unhandled(IROp, Node);
    return;
  }

  // PCLMULQDQ on POWER8, via vpmsumd. Replaces a helper whose body was a
  // 64-iteration shift/xor bit loop plus the full FABI call sequence; this is
  // three instructions and no memory traffic.
  //
  // vpmsumd is a multiply-SUM: it forms both doubleword carry-less products
  // and xors them together,
  //   vpmsumd(A,B) = clmul(A.dw0, B.dw0) ^ clmul(A.dw1, B.dw1)
  // so a single product is isolated by zeroing the unused doubleword of BOTH
  // operands - clmul(x,0) is 0, and the unwanted term drops out.
  //
  // Doubleword numbering: a guest XMM sits here with guest byte i at BE byte
  // element 15-i, which puts guest qword k in BE doubleword (1-k).
  //
  // NO byte reversal is needed, unlike the AES ops above. That asymmetry is
  // real: an AES state is a byte ARRAY (x86 pins state byte i to XMM byte i,
  // POWER pins it to BE element i, so the images disagree), whereas a PCLMUL
  // operand and result are 128-bit INTEGERS - and "guest byte i at BE element
  // 15-i" is precisely what storing an integer big-endian in the register
  // means. The vpmsumd result therefore already lands in guest layout.
  const uint32_t Src1Dw = 1u - static_cast<uint32_t>(Selector & 1);
  const uint32_t Src2Dw = 1u - static_cast<uint32_t>((Selector >> 4) & 1);

  // XXPERMDI T,A,B,DM: T.dw0 = A.dw[DM>>1], T.dw1 = B.dw[DM&1].
  // Pick the selected doubleword into dw0 and take dw1 from the pinned zero.
  // Reading VZERO_VSX here is safe where the AES ops' old zero-copy was not:
  // DM&1 == 0 selects VZERO's dw0, which aliases f14 - the half ELFv2
  // actually preserves across host calls. Its dw1 (volatile, trashed by any
  // callee's lfd f14 restore) is never read. Keep it that way.
  xxpermdi(AsVSX(VTMP1), AsVSX(Src1), VZERO_VSX, Src1Dw << 1);
  xxpermdi(AsVSX(VTMP2), AsVSX(Src2), VZERO_VSX, Src2Dw << 1);
  // Both sources are dead by here, so Dst may alias either.
  vpmsumd(Dst, VTMP1, VTMP2);
}

} // namespace FEXCore::CPU
