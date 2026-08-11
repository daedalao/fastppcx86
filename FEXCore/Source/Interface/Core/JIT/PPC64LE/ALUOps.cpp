// SPDX-License-Identifier: MIT
// PPC64LE ALU operations for FEX JIT backend.
#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"

namespace FEXCore::CPU {

using namespace PPC64Emitter::FPRegs;

// -------------------------------------------------------------------------
// IntegerNZCVCond: rewrite FU/FNU to VS/VC for integer-NZCV consumers.
//
// The dispatcher reuses CondClass::FU/FNU as the OF-set/OF-clear codes when
// it lowers x86 JO/JNO/CMOVO/CMOVNO/INTO/etc., because on AArch64 both FP
// "unordered" and integer "overflow" alias onto the same V flag. On PPC the
// two live in different bits — XER.OV (integer overflow) vs CR0.SO (FP
// unordered set by fcmpu) — so feeding FU straight into MapNZCVCC tests the
// wrong bit (CR0.SO) when the producer was an integer NZCV writer such as
// StoreNZCV or AddNZCV.
//
// Every IR op in this translation unit that reaches MapNZCVCC is a consumer
// of packed NZCV state (StoreNZCV routes V → XER.OV), so FU here always
// means "OF set" and must be remapped to VS. The FCmp follow-up case never
// uses NZCVSelect/CondJumpNZCV/etc.; FCmp consumers go through MapCC's FU
// path which still tests CR0.SO correctly.
static inline IR::CondClass IntegerNZCVCond(IR::CondClass C) {
  if (C == IR::CondClass::FU)  return IR::CondClass::VS;
  if (C == IR::CondClass::FNU) return IR::CondClass::VC;
  return C;
}

// -------------------------------------------------------------------------
// SplitAddisAddi: express a 33-bit-or-narrower signed addend as the (Hi, Lo)
// pair consumed by `addis rD, rA, Hi ; addi rD, rD, Lo`, which adds
// (Hi << 16) + Lo to rA. Both immediates are sign-extended by the hardware,
// so Lo being negative eats 0x10000 out of the high part — hence the
// `V - Lo` before the shift, which is the standard +1 correction to Hi when
// the low half has its top bit set. `V - Lo` is exact and always a multiple
// of 65536, and it is done in int64 so the near-INT32_MAX cases cannot wrap.
//
// Returns false when Hi does not fit a signed 16-bit field, i.e. whenever V
// is outside roughly +/-2^31; callers fall back to LoadConstant + add.
//
// NOTE for callers: addi/addis interpret an RA field of 0 as the literal
// value 0, not as GPR[r0]. Guest registers never map to r0 (it is the JIT's
// zero-index invariant), but callers still guard on the register index so a
// future allocator change cannot silently miscompile.
static inline bool SplitAddisAddi(int64_t V, int16_t& Hi, int16_t& Lo) {
  const int64_t L = static_cast<int16_t>(static_cast<uint16_t>(static_cast<uint64_t>(V)));
  const int64_t H = (V - L) >> 16;
  if (H < -32768 || H > 32767) return false;
  Hi = static_cast<int16_t>(H);
  Lo = static_cast<int16_t>(L);
  return true;
}

// =========================================================================
// Constants and inline values
// =========================================================================

DEF_OP(Constant) {
  auto Op  = IROp->C<IR::IROp_Constant>();
  auto Dst = GetReg(Node);
  // SMC Idea 4 (FEX_SMCSEMANTICPATCH): a constant the frontend tagged as the
  // immediate of a guest mov gets a fixed-width, repatchable window instead of
  // the ordinary value-dependent 1..5 instruction sequence. Untagged constants
  // (everything, with the flag off) take the unchanged path.
  // See Interface/Core/SMCSemanticPatch.h.
  if (!TryInsertPatchableImmMove(Dst, Op->Constant, Op->PatchSite)) {
    LoadConstant(Dst, Op->Constant);
  }
}

DEF_OP(EntrypointOffset) {
  auto Op       = IROp->C<IR::IROp_EntrypointOffset>();
  uint64_t Mask = (IROp->Size == IR::OpSize::i32Bit) ? 0xFFFF'FFFFull : ~0ULL;
  // S3.7-C2: `Entry + Op->Offset` is a guest RIP baked into 20 bytes of
  // host constant-load; mirrors ARM64 JIT/ALUOps.cpp:67. The mask is
  // applied at emit time so the recorded value equals the emitted value.
  InsertEntrypointRIPMove(GetReg(Node), (Entry + Op->Offset) & Mask);
}

DEF_OP(InlineConstant)         { /* nop — handled by IsInlineConstant */ }
DEF_OP(InlineEntrypointOffset) { /* nop */ }

DEF_OP(CycleCounter) {
  auto Op = IROp->C<IR::IROp_CycleCounter>();
  if (Op->SelfSynchronizingLoads) {
    // The guest (RDTSCP) requires all prior instructions and loads to have
    // completed before the counter read. Power ISA Book II prescribes `isync`
    // for this: the timebase read may otherwise complete out of order.
    // Deliberately NOT preceded by `hwsync` — Book II only calls for that when
    // storage accesses must be ordered too, which this IR flag does not ask
    // for, and this handler also serves plain RDTSC where it would be pure cost.
    isync();
  }
  // mftb reads the 64-bit time base register (SPR 268)
  mftb(GetReg(Node));
}

// =========================================================================
// Basic integer ALU
// =========================================================================

DEF_OP(Add) {
  auto Op  = IROp->C<IR::IROp_Add>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if (Const == 0) {
      if (Dst != S1) mr(Dst, S1);
    } else if (static_cast<int64_t>(Const) >= -32768 &&
               static_cast<int64_t>(Const) <= 32767) {
      addi(Dst, S1, static_cast<int16_t>(Const));
    } else {
      // 17..32-bit addends: addis + addi is two instructions and needs no
      // scratch register, versus LoadConstant (lis+ori, two instructions for
      // this range) plus a separate add. At i32Bit the result is masked to 32
      // bits below, so a constant whose bit 31 is set can be fed through as
      // its sign-extended int32 form — the low 32 bits of the sum are the
      // same either way.
      int64_t V = static_cast<int64_t>(Const);
      if (IROp->Size == IR::OpSize::i32Bit) {
        V = static_cast<int32_t>(static_cast<uint32_t>(Const));
      }
      int16_t Hi, Lo;
      if (S1.idx != 0 && SplitAddisAddi(V, Hi, Lo)) {
        addis(Dst, S1, Hi);
        addi(Dst, Dst, Lo);
      } else {
        LoadConstant(TMP4, Const);
        add(Dst, S1, TMP4);
      }
    }
  } else {
    add(Dst, S1, GetReg(Op->Src2));
  }
  if (IROp->Size == IR::OpSize::i32Bit) {
    // Mask to 32 bits (zero-extend)
    rldicl(Dst, Dst, 0, 32);
  }
}

DEF_OP(Sub) {
  auto Op  = IROp->C<IR::IROp_Sub>();
  auto Dst = GetReg(Node);
  uint64_t C1, C2;
  bool S1Inline = IsInlineConstant(Op->Src1, &C1);
  bool S2Inline = IsInlineConstant(Op->Src2, &C2);

  if (S2Inline) {
    // Dst = Src1 - C2  →  addi/subf with negated constant
    auto S1 = GetReg(Op->Src1);
    // Negate in unsigned so C2 = 0x8000...0 cannot trip signed-overflow UB.
    int64_t NegC = static_cast<int64_t>(~C2 + 1);
    if (NegC >= -32768 && NegC <= 32767) {
      addi(Dst, S1, static_cast<int16_t>(NegC));
    } else {
      // Same addis+addi form as DEF_OP(Add): subtracting C2 is adding -C2,
      // and at i32Bit only the low 32 bits survive the mask below, so the
      // int32-truncated negation is equivalent there.
      int64_t V = NegC;
      if (IROp->Size == IR::OpSize::i32Bit) {
        V = static_cast<int32_t>(static_cast<uint32_t>(NegC));
      }
      int16_t Hi, Lo;
      if (S1.idx != 0 && SplitAddisAddi(V, Hi, Lo)) {
        addis(Dst, S1, Hi);
        addi(Dst, Dst, Lo);
      } else {
        LoadConstant(TMP4, C2);
        subf(Dst, TMP4, S1);
      }
    }
  } else if (S1Inline) {
    // Dst = C1 - Src2. _Sub is a value-only op — it MUST NOT touch XER.CA
    // (canonical x86 CF storage when CFInverted=true). PPC's subfic sets CA;
    // route through subf via a TMP register instead, even for small immediates.
    auto S2 = GetReg(Op->Src2);
    LoadConstant(TMP4, C1);
    subf(Dst, S2, TMP4);
  } else {
    auto S1 = GetReg(Op->Src1);
    subf(Dst, GetReg(Op->Src2), S1);  // subf RT,RA,RB → RT = RB - RA
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Neg) {
  // Predicated negation: Dest = Cond ? -Src : Src.  Cond is decoded against
  // the architecturally packed NZCV state (set by SubNZCV / NZCV-producing
  // ALU ops earlier in the block). For the unconditional default
  // CondClass::AL we simply negate.
  auto Op  = IROp->C<IR::IROp_Neg>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  if (Op->Cond == IR::CondClass::AL) {
    neg(Dst, Src);
  } else {
    // Conditional: Dst = Cond ? -Src : Src, branch-free via isel. isel reads
    // both source operands before writing RT, so Dst aliasing Src is fine and
    // the old mr/bc/mr dance (plus its Label and forward branch) is
    // unnecessary. The condition is decoded from the architecturally packed
    // NZCV in CR0 that a preceding *NZCV op set, and CC.BI is an absolute CR
    // bit index in CR0's 0..3 range, which is what isel's BC field wants.
    //
    // A branch here would be the worst case for it: a data-dependent condition
    // feeding pure dataflow, i.e. unpredictable. That is the same reasoning
    // recorded at DEF_OP(NZCVSelect), where making the analogous select
    // branchy was measured as a 5.7 ns/op regression.
    //
    // isel's RA = 0 encoding means literal zero rather than GPR[r0], so a
    // source in the RA slot must not be r0 — TMP4 is r6 and Src is a mapped
    // guest register, neither of which is r0.
    neg(TMP4, Src);
    auto CC = MapNZCVCC(IntegerNZCVCond(Op->Cond));
    iselcc(Dst, CC, TMP4, Src);
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Not) {
  auto Op  = IROp->C<IR::IROp_Not>();
  auto Dst = GetReg(Node);
  not_(Dst, GetReg(Op->Src));
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Mul) {
  auto Op  = IROp->C<IR::IROp_Mul>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const) &&
      static_cast<int64_t>(Const) >= -32768 &&
      static_cast<int64_t>(Const) <= 32767) {
    mulli(Dst, S1, static_cast<int16_t>(Const));
  } else {
    GPR S2 = IsInlineConstant(Op->Src2, &Const)
               ? (LoadConstant(TMP4, Const), TMP4)
               : GetReg(Op->Src2);
    if (IROp->Size <= IR::OpSize::i32Bit)
      mullw(Dst, S1, S2);
    else
      mulld(Dst, S1, S2);
  }
  // mullw/mulli sign-extend the 32-bit product into bits 0..31.
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(UMul) {
  auto Op  = IROp->C<IR::IROp_UMul>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  if (IROp->Size <= IR::OpSize::i32Bit)
    mullw(Dst, S1, S2);
  else
    mulld(Dst, S1, S2);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(UMull) {
  auto Op  = IROp->C<IR::IROp_UMull>();
  // Zero-extend both sources to 32-bit then multiply to 64-bit
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  // Mask to 32 bits
  rldicl(TMP1, S1, 0, 32);
  rldicl(TMP2, S2, 0, 32);
  mulld(Dst, TMP1, TMP2);
}

DEF_OP(SMull) {
  auto Op  = IROp->C<IR::IROp_SMull>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  // Sign-extend sources from 32 to 64 bit
  extsw(TMP1, S1);
  extsw(TMP2, S2);
  mulld(Dst, TMP1, TMP2);
}

DEF_OP(MulH) {
  // PPC `mulhd` returns upper 64 of a 64x64→128 product. For 32-bit MulH we
  // need upper 32 of a 32x32→64 product (mulhw), and for 16/8-bit the upper
  // half of a same-width signed product. Use mulhw for 32-bit, otherwise
  // sign-extend the operands and shift down for 16/8 (mulhw doesn't exist for
  // narrower widths).
  auto Op  = IROp->C<IR::IROp_MulH>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:
    // Signed 8x8→16 product fits in 16 bits. mulld of sign-extended-64 inputs
    // yields a 64-bit sign-extended version of the 16-bit signed product.
    // Logical right by 8 then mask low 8 == arithmetic right by 8 + mask
    // (because bits 16..63 are already sign-fill). Avoids sradi (which would
    // clobber XER.CA = canonical x86 CF under CFInverted=true).
    extsb(TMP1, S1);
    extsb(TMP2, S2);
    mulld(Dst, TMP1, TMP2);
    // (Dst >> 8) & 0xFF in one rotate-and-mask: rldicl RA,RS,sh,mb computes
    // ROTL64(RS, sh) & MASK(mb, 63), so sh = 56 (= 64 - 8) brings bits 15:8
    // down to 7:0 and mb = 56 keeps exactly those low 8 bits. The two-step
    // srdi-then-clear this replaces produced the identical value.
    rldicl(Dst, Dst, 56, 56);
    break;
  case IR::OpSize::i16Bit:
    // Same trick: 16x16→32 signed product, sign-extended to 64 by mulld.
    // Logical right by 16 == arithmetic right by 16 in the low 32 bits.
    extsh(TMP1, S1);
    extsh(TMP2, S2);
    mulld(Dst, TMP1, TMP2);
    rldicl(Dst, Dst, 48, 48);   // (Dst >> 16) & 0xFFFF, one rotate-and-mask
    break;
  case IR::OpSize::i32Bit:
    mulhw(Dst, S1, S2);
    rldicl(Dst, Dst, 0, 32);
    break;
  default:
    mulhd(Dst, S1, S2);
    break;
  }
}

DEF_OP(UMulH) {
  // Same width-dispatch as MulH, but with mulhwu / unsigned masking. For
  // 8/16-bit there's no native PPC mulhwu narrower than 32-bit, so do the
  // multiply at 64-bit width on zero-extended operands and shift down.
  auto Op  = IROp->C<IR::IROp_UMulH>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:
    rldicl(TMP1, S1, 0, 56);
    rldicl(TMP2, S2, 0, 56);
    mulld(Dst, TMP1, TMP2);
    rldicl(Dst, Dst, 56, 56);   // (Dst >> 8) & 0xFF, one rotate-and-mask
    break;
  case IR::OpSize::i16Bit:
    rldicl(TMP1, S1, 0, 48);
    rldicl(TMP2, S2, 0, 48);
    mulld(Dst, TMP1, TMP2);
    rldicl(Dst, Dst, 48, 48);   // (Dst >> 16) & 0xFFFF, one rotate-and-mask
    break;
  case IR::OpSize::i32Bit:
    mulhwu(Dst, S1, S2);
    rldicl(Dst, Dst, 0, 32);
    break;
  default:
    mulhdu(Dst, S1, S2);
    break;
  }
}

DEF_OP(Div) {
  // x86 div/idiv: dividend = (Upper:Lower) at 2x op size, divisor at op size.
  // For 32-bit: 64-bit signed dividend / 32-bit signed divisor → 32-bit quotient/remainder.
  //   (PPC has no native 64/32 → 32 idiv; combine into a sign-extended 64-bit
  //    dividend, divide via divd, mask result.) For 64-bit dividend, FEX emits
  //    a runtime helper — handle the common case here, fall through for 64-bit
  //    long-div which needs 128-bit dividend support.
  auto Op      = IROp->C<IR::IROp_Div>();
  auto Lower   = GetReg(Op->Lower);
  auto Divisor = GetReg(Op->Divisor);
  auto Quotient  = GetReg(Op->OutQuotient);
  auto Remainder = GetReg(Op->OutRemainder);
  bool LongDiv = !Op->Upper.IsInvalid();

  if (IROp->Size <= IR::OpSize::i32Bit) {
    // x86 16-bit IDIV: dividend = signed 32-bit (DX << 16) | AX, then signed
    // divide by sign-extended divisor16.
    // x86 32-bit IDIV: dividend = signed 64-bit (EDX << 32) | EAX, signed
    // divide by sign-extended divisor32.
    // Lower/Upper come in as full 64-bit values; mask per operand size before
    // composing, sign-extend the divisor and the i16-case composition to i64.
    const bool Is16 = (IROp->Size == IR::OpSize::i16Bit);
    const uint32_t MaskBits = Is16 ? 48 : 32;
    const uint32_t Shift    = Is16 ? 16 : 32;
    if (LongDiv) {
      auto Upper = GetReg(Op->Upper);
      rldicl(TMP4, Lower, 0, MaskBits);            // TMP4 = Lower & op-size mask
      rldicl(TMP3, Upper, 0, MaskBits);            // TMP3 = Upper & op-size mask
      sldi  (TMP1, TMP3,  Shift);                   // TMP1 = Upper << op-width
      or_   (TMP1, TMP1,  TMP4);
      if (Is16) {
        // i16 composition lives in the low 32; sign-extend to i64.
        extsw(TMP1, TMP1);
      }
    } else if (Is16) {
      extsh(TMP1, Lower);                           // sign-extend i16 to i64
    } else {
      extsw(TMP1, Lower);                           // sign-extend i32 to i64
    }
    if (Is16) extsh(TMP4, Divisor);
    else      extsw(TMP4, Divisor);
    divd(Quotient, TMP1, TMP4);
    mulld(TMP3, Quotient, TMP4);
    subf(Remainder, TMP3, TMP1);
    rldicl(Quotient,  Quotient,  0, 32);
    rldicl(Remainder, Remainder, 0, 32);
  } else if (LongDiv) {
    // Real signed 128/64 divide: (Upper:Lower) / Divisor.
    //   1) Save sign masks (dividend = sign(Upper); quotient = sign XOR).
    //   2) Take |dividend| as a 128-bit pair, |divisor| as 64-bit.
    //   3) Run the unsigned divdeu+divdu+correction sequence (same as
    //      DEF_OP(UDiv)'s 64-bit long path).
    //   4) Negate quotient if signs differed; negate remainder if dividend
    //      was negative (x86 rem takes the dividend's sign).
    //
    // Red-zone slots -40/-48 hold the saved sign masks across the divide;
    // -8/-16/-24 are reserved by other ops, so stay below -32.
    auto Upper = GetReg(Op->Upper);

    sradi(TMP1, Upper, 63);                   // dividend sign mask (-1 or 0)
    sradi(TMP2, Divisor, 63);                 // divisor  sign mask
    xor_(TMP3, TMP1, TMP2);                   // quotient sign mask
    std(TMP1, -40, r1);
    std(TMP3, -48, r1);

    // abs(Divisor) → TMP3
    xor_(TMP3, Divisor, TMP2);
    subf(TMP3, TMP2, TMP3);

    // abs(Upper:Lower) → (TMP2=abs_Upper, TMP4=abs_Lower) via two-word negate.
    Label NotNegDividend, AfterAbs;
    cmpdi(Upper, 0);
    bc(CC_GE, &NotNegDividend);
    subfic(TMP4, Lower, 0);                   // TMP4 = -Lower, CA = (Lower==0)
    subfze(TMP2, Upper);                      // TMP2 = -Upper - 1 + CA
    b(&AfterAbs);
    Bind(&NotNegDividend);
    mr(TMP4, Lower);
    mr(TMP2, Upper);
    Bind(&AfterAbs);

    // Unsigned 128/64 via POWER8 divdeu + divdu + at-most-one correction.
    divdeu(TMP1, TMP2, TMP3);                 // q1 = (abs_Upper * 2^64) / abs_Div
    divdu(TMP2, TMP4, TMP3);                  // q2 = abs_Lower / abs_Div
    add(TMP1, TMP1, TMP2);                    // tentative quotient
    mulld(TMP2, TMP1, TMP3);                  // (tentative * abs_Div) low 64
    subf(TMP2, TMP2, TMP4);                   // rem_lo = abs_Lower - mul_lo

    Label NoCorrection;
    cmpld(TMP2, TMP3);
    bc(CC_ULT, &NoCorrection);
    addi(TMP1, TMP1, 1);
    subf(TMP2, TMP3, TMP2);
    Bind(&NoCorrection);

    // Re-apply signs. xor+subf is the standard "conditional negate by mask"
    // idiom: value^mask - mask = value if mask==0, -value if mask==-1.
    ld(TMP3, -48, r1);                         // quotient sign mask
    ld(TMP4, -40, r1);                         // dividend sign mask
    xor_(TMP1, TMP1, TMP3);
    subf(Quotient, TMP3, TMP1);
    xor_(TMP2, TMP2, TMP4);
    subf(Remainder, TMP4, TMP2);
  } else {
    divd(Quotient, Lower, Divisor);
    mulld(TMP4, Quotient, Divisor);
    subf(Remainder, TMP4, Lower);
  }
}

DEF_OP(UDiv) {
  auto Op      = IROp->C<IR::IROp_UDiv>();
  auto Lower   = GetReg(Op->Lower);
  auto Divisor = GetReg(Op->Divisor);
  auto Quotient  = GetReg(Op->OutQuotient);
  auto Remainder = GetReg(Op->OutRemainder);
  bool LongDiv = !Op->Upper.IsInvalid();

  if (IROp->Size <= IR::OpSize::i32Bit) {
    // x86 16-bit DIV: dividend = (DX << 16) | AX (32-bit composition).
    // x86 32-bit DIV: dividend = (EDX << 32) | EAX (64-bit composition).
    // RAX/RDX may carry stale upper bits from prior 64-bit writes (dispatcher
    // LoadGPRRegister returns full 64; per-op masking is the JIT's job).
    // Earlier code unconditionally masked to 32 / shifted by 32 — wrong for
    // i16: a `div word` after `mov rax, <64-bit>; mov ax, <16>; cwd` would
    // pull RAX[16..31] into the dividend instead of zeroing them.
    const uint32_t MaskBits = (IROp->Size == IR::OpSize::i16Bit) ? 48 : 32;
    const uint32_t Shift    = (IROp->Size == IR::OpSize::i16Bit) ? 16 : 32;
    if (LongDiv) {
      auto Upper = GetReg(Op->Upper);
      rldicl(TMP4, Lower, 0, MaskBits);            // TMP4 = Lower & operand-size mask
      rldicl(TMP3, Upper, 0, MaskBits);            // TMP3 = Upper & operand-size mask
      sldi  (TMP1, TMP3,  Shift);                  // TMP1 = Upper << operand-width
      or_   (TMP1, TMP1,  TMP4);
    } else {
      rldicl(TMP1, Lower, 0, MaskBits);
    }
    rldicl(TMP4, Divisor, 0, MaskBits);
    divdu(Quotient, TMP1, TMP4);
    mulld(TMP3, Quotient, TMP4);
    subf(Remainder, TMP3, TMP1);
    rldicl(Quotient,  Quotient,  0, 32);
    rldicl(Remainder, Remainder, 0, 32);
  } else if (LongDiv) {
    // 64-bit unsigned long-div: (Upper:Lower) / Divisor, with Upper < Divisor
    // (the latter is x86's invariant — otherwise quotient overflows and the
    // hardware raises #DE; the dispatcher filters that case).
    //
    // PPC has no native 128/64 divide, but POWER8 has divdeu (extended
    // unsigned divide) which computes (rA << 64) / rB. Combined with
    // divdu(Lower, Divisor) the sum q1+q2 lands within {Q, Q-1} of the true
    // quotient. One correction step (compare remainder against Divisor)
    // recovers the exact answer.
    auto Upper = GetReg(Op->Upper);
    divdeu(TMP1, Upper, Divisor);            // q1 = floor(Upper * 2^64 / Divisor)
    divdu(TMP2, Lower, Divisor);              // q2 = floor(Lower / Divisor)
    add(TMP1, TMP1, TMP2);                    // tentative = q1 + q2

    // The remainder MUST be computed as a full 128-bit subtract. Computing it
    // in 64 bits is wrong for large divisors and was a live bug: guest
    // `__uint128_t % v` returned a quotient exactly one too low.
    //
    // Why. When tentative == Q-1 the pre-correction remainder is R + Divisor,
    // and since R < Divisor that is bounded only by 2*Divisor. For any
    // Divisor > 2^63 that exceeds 2^64 and wraps, so a 64-bit
    // `Lower - (tentative*Divisor mod 2^64)` produces a small value, the
    // `rem >= Divisor` test reads false, the correction is skipped, and both
    // outputs are wrong. Concretely Divisor = 2^63+1 with a true remainder of
    // 2^63-1 gives R+Divisor = 2^64, which wraps to 0.
    //
    // This is reachable from ordinary guest code. libgcc's __udivmodti4
    // NORMALISES the divisor so its high bit is set before dividing, which
    // puts the effective 64-bit divisor above 2^63 by construction — so every
    // 128-bit divide or modulo through the general path hit it. Found via
    // stress-ng --vecmath, isolated to `a %= v23` on __uint128_t.
    //
    // Not a problem on the signed path above: a signed 64-bit divisor has
    // magnitude <= 2^63, so R + |Divisor| < 2^64 and cannot wrap.
    //
    // Fix: compute the 128-bit product and subtract with borrow. Because x86
    // guarantees Upper < Divisor for a non-#DE divide, the true remainder is
    // < 2*Divisor < 2^65, so rem_hi is exactly 0 or 1 — a non-zero high word
    // means the remainder already exceeds 2^64 > Divisor and correction is
    // required without inspecting rem_lo at all.
    mulld (TMP4, TMP1, Divisor);              // prod_lo = (tentative*Divisor) low
    mulhdu(TMP3, TMP1, Divisor);              // prod_hi = (tentative*Divisor) high
    subfc (TMP4, TMP4, Lower);                // rem_lo = Lower - prod_lo, sets CA
    subfe (TMP3, TMP3, Upper);                // rem_hi = Upper - prod_hi - borrow

    Label DoCorrection, NoCorrection;
    cmpldi(TMP3, 0);
    bc(CC_NE, &DoCorrection);                 // rem_hi != 0 -> rem >= 2^64 > Divisor
    cmpld(TMP4, Divisor);
    bc(CC_ULT, &NoCorrection);
    Bind(&DoCorrection);
    addi(TMP1, TMP1, 1);
    subf(TMP4, Divisor, TMP4);
    Bind(&NoCorrection);

    or_(Quotient,  TMP1, TMP1);               // mr Quotient,  TMP1
    or_(Remainder, TMP4, TMP4);               // mr Remainder, TMP4
  } else {
    divdu(Quotient, Lower, Divisor);
    mulld(TMP4, Quotient, Divisor);
    subf(Remainder, TMP4, Lower);
  }
}

// =========================================================================
// Logical
// =========================================================================

DEF_OP(Or) {
  auto Op  = IROp->C<IR::IROp_Or>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if (Const == 0) {
      if (Dst != S1) mr(Dst, S1);
    } else if ((Const & 0xFFFF) == Const) {
      ori(Dst, S1, static_cast<uint16_t>(Const));
    } else if ((Const & 0xFFFF0000ull) == Const) {
      oris(Dst, S1, static_cast<uint16_t>(Const >> 16));
    } else {
      LoadConstant(TMP4, Const);
      or_(Dst, S1, TMP4);
    }
  } else {
    or_(Dst, S1, GetReg(Op->Src2));
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(And) {
  // Plain `_And` is flag-neutral — avoid PPC `andi.`/`andis.` (always Rc=1)
  // because they wipe CR0 and that breaks downstream LoadNZCV consumers.
  auto Op  = IROp->C<IR::IROp_And>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    LoadConstant(TMP4, Const);
    and_(Dst, S1, TMP4);
  } else {
    and_(Dst, S1, GetReg(Op->Src2));
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Xor) {
  auto Op  = IROp->C<IR::IROp_Xor>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if ((Const & 0xFFFF) == Const) {
      xori(Dst, S1, static_cast<uint16_t>(Const));
    } else if ((Const & 0xFFFF0000ull) == Const) {
      xoris(Dst, S1, static_cast<uint16_t>(Const >> 16));
    } else {
      LoadConstant(TMP4, Const);
      xor_(Dst, S1, TMP4);
    }
  } else {
    xor_(Dst, S1, GetReg(Op->Src2));
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Andn) {
  // Andn = Src1 & ~Src2
  auto Op  = IROp->C<IR::IROp_Andn>();
  auto Dst = GetReg(Node);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    LoadConstant(TMP4, ~Const);
    and_(Dst, GetReg(Op->Src1), TMP4);
  } else {
    andc(Dst, GetReg(Op->Src1), GetReg(Op->Src2));
  }
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Orlshl) {
  auto Op  = IROp->C<IR::IROp_Orlshl>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  sldi(TMP4, S2, Op->BitShift);
  or_(Dst, S1, TMP4);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Orlshr) {
  auto Op  = IROp->C<IR::IROp_Orlshr>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  srdi(TMP4, S2, Op->BitShift);
  or_(Dst, S1, TMP4);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(Ornror) {
  // Dst = Src1 | NOT(ROR(Src2, BitShift)) per IR.json semantics. PPC `orc`
  // already gives `S1 | NOT(TMP4)` directly, so no second NOT.
  auto Op  = IROp->C<IR::IROp_Ornror>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  uint32_t sh = (64 - Op->BitShift) & 63;
  rldicl(TMP4, S2, sh, 0);   // TMP4 = ROR(S2, BitShift)
  orc(Dst, S1, TMP4);         // Dst = S1 | NOT(TMP4)
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

// XorShift / XornShift / AndShift: Honor the IR ShiftType field. Earlier
// versions of these handlers always emitted sldi (LSL), which produced wrong
// results when the dispatcher emitted LSR/ASR/ROR variants — most visibly the
// 1-bit RCR OF computation `XorShift Res, Res, LSR, 1` (= bit(N-1) ^ bit(N-2)).
//
// Operand size matters: an i32Bit XorShift with LSR 1 must shift the 32-bit
// view (rlwinm with rot=31, mask=1..31) so we don't pull bit 32 of an
// upper-garbage register into the bottom. The final 32-bit zero-extend on the
// parent op handles the upper 32 bits of the destination.
DEF_OP(XorShift) {
  auto Op  = IROp->C<IR::IROp_XorShift>();
  auto Dst = GetReg(Node);
  auto S2  = GetReg(Op->Src2);
  uint8_t Amt = Op->ShiftAmount;
  bool Is32 = (IROp->Size == IR::OpSize::i32Bit);
  switch (Op->Shift) {
    case IR::ShiftType::LSL:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, Amt & 31, 0, 31 - (Amt & 31));
      else           sldi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::LSR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, Amt & 31, 31);
      else           srdi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::ASR:
      // Avoid srawi/sradi — they clobber XER.CA, our canonical x86 CF.
      // Build ASR via sign-extend + logical right (32-bit), or sign-replicate
      // mask + sld/srdi (64-bit).
      if (Amt == 0) {
        mr(TMP4, S2);
      } else if (Is32) {
        uint32_t sh = Amt & 31;
        extsw(TMP4, S2);
        rldicl(TMP4, TMP4, 64 - sh, sh);
      } else {
        uint32_t sh = Amt & 63;
        // sign-fill mask = -(S2[63]) ; body = S2 >> sh ; combine.
        rldicl(TMP1, S2, 1, 63);
        neg(TMP1, TMP1);
        srdi(TMP4, S2, sh);
        if (sh < 64) {
          sldi(TMP1, TMP1, 64 - sh);
          or_(TMP4, TMP4, TMP1);
        } else {
          mr(TMP4, TMP1);
        }
      }
      break;
    case IR::ShiftType::ROR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, 0, 31);
      else           rldicl(TMP4, S2, (64 - Amt) & 63, 0);
      break;
  }
  xor_(Dst, GetReg(Op->Src1), TMP4);
  if (Is32) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(XornShift) {
  auto Op  = IROp->C<IR::IROp_XornShift>();
  auto Dst = GetReg(Node);
  auto S2  = GetReg(Op->Src2);
  uint8_t Amt = Op->ShiftAmount;
  bool Is32 = (IROp->Size == IR::OpSize::i32Bit);
  switch (Op->Shift) {
    case IR::ShiftType::LSL:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, Amt & 31, 0, 31 - (Amt & 31));
      else           sldi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::LSR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, Amt & 31, 31);
      else           srdi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::ASR:
      // Avoid srawi/sradi — they clobber XER.CA, our canonical x86 CF.
      // Build ASR via sign-extend + logical right (32-bit), or sign-replicate
      // mask + sld/srdi (64-bit).
      if (Amt == 0) {
        mr(TMP4, S2);
      } else if (Is32) {
        uint32_t sh = Amt & 31;
        extsw(TMP4, S2);
        rldicl(TMP4, TMP4, 64 - sh, sh);
      } else {
        uint32_t sh = Amt & 63;
        // sign-fill mask = -(S2[63]) ; body = S2 >> sh ; combine.
        rldicl(TMP1, S2, 1, 63);
        neg(TMP1, TMP1);
        srdi(TMP4, S2, sh);
        if (sh < 64) {
          sldi(TMP1, TMP1, 64 - sh);
          or_(TMP4, TMP4, TMP1);
        } else {
          mr(TMP4, TMP1);
        }
      }
      break;
    case IR::ShiftType::ROR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, 0, 31);
      else           rldicl(TMP4, S2, (64 - Amt) & 63, 0);
      break;
  }
  not_(TMP4, TMP4);
  xor_(Dst, GetReg(Op->Src1), TMP4);
  if (Is32) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(AndShift) {
  auto Op = IROp->C<IR::IROp_AndShift>();
  auto Dst = GetReg(Node);
  auto S2  = GetReg(Op->Src2);
  uint8_t Amt = Op->ShiftAmount;
  bool Is32 = (IROp->Size == IR::OpSize::i32Bit);
  switch (Op->Shift) {
    case IR::ShiftType::LSL:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, Amt & 31, 0, 31 - (Amt & 31));
      else           sldi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::LSR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, Amt & 31, 31);
      else           srdi(TMP4, S2, Amt);
      break;
    case IR::ShiftType::ASR:
      // Avoid srawi/sradi — they clobber XER.CA, our canonical x86 CF.
      // Build ASR via sign-extend + logical right (32-bit), or sign-replicate
      // mask + sld/srdi (64-bit).
      if (Amt == 0) {
        mr(TMP4, S2);
      } else if (Is32) {
        uint32_t sh = Amt & 31;
        extsw(TMP4, S2);
        rldicl(TMP4, TMP4, 64 - sh, sh);
      } else {
        uint32_t sh = Amt & 63;
        // sign-fill mask = -(S2[63]) ; body = S2 >> sh ; combine.
        rldicl(TMP1, S2, 1, 63);
        neg(TMP1, TMP1);
        srdi(TMP4, S2, sh);
        if (sh < 64) {
          sldi(TMP1, TMP1, 64 - sh);
          or_(TMP4, TMP4, TMP1);
        } else {
          mr(TMP4, TMP1);
        }
      }
      break;
    case IR::ShiftType::ROR:
      if (Amt == 0) { mr(TMP4, S2); }
      else if (Is32) rlwinm(TMP4, S2, (32 - (Amt & 31)) & 31, 0, 31);
      else           rldicl(TMP4, S2, (64 - Amt) & 63, 0);
      break;
  }
  and_(Dst, GetReg(Op->Src1), TMP4);
  if (Is32) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(AndWithFlags) {
  auto Op  = IROp->C<IR::IROp_AndWithFlags>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if ((Const & 0xFFFF) == Const) {
      andi_(Dst, S1, static_cast<uint16_t>(Const));  // andi. sets CR0
    } else {
      LoadConstant(TMP4, Const);
      and__(Dst, S1, TMP4);  // and. sets CR0
    }
  } else {
    and__(Dst, S1, GetReg(Op->Src2));
  }
  // IR contract for `*WithFlags` logical: clear NZCV.C and NZCV.V (x86 TEST/
  // AND/OR/XOR all clear CF and OF). PPC and./andi. only set CR0; XER.CA/OV
  // retain prior values. Without this clear, x86 TEST/AND followed by LAHF/
  // PUSHF / Jcc-on-CF reads stale CA — manifests as a phantom CF=1 in
  // Primary_84/85, Primary_A9, BLSI_flags, BLSR_flags, etc.
  //
  // A single OE=1 add of 0+0 replaces the mfspr/LoadConstant/andc/mtspr XER
  // round trip — see the full equivalence proof above the identical
  // `addco(TMP1, r0, r0)` in DEF_OP(TestNZ). In brief:
  //   * the old mask 0x60000000 = LSB bits 30|29 = OV|CA, andc'd off, so the
  //     old sequence cleared exactly CA and OV and preserved the sticky SO.
  //   * addco writes CA = carry-out and OV = signed overflow of the add;
  //     0 + 0 produces neither, so CA = OV = 0.  SO is sticky (hardware only
  //     ORs OV into it, never clears it), so SO survives — matching andc.
  //   * Rc = 0 (`addco`, not `addco_`), so CR0 — which holds the guest N/Z
  //     just set by the and./andi. above and refined by EmitTestNZSetCR
  //     below — is NOT touched.
  // r0 is the JIT's zero-index invariant register (see PPC64Dispatcher.cpp),
  // so this really is 0 + 0.  TMP1 is dead here: nothing in this handler
  // reads it before this point, and EmitTestNZSetCR overwrites it next.
  addco(TMP1, r0, r0);
  // CR0 from and./andi. covers full 64 bits; refine to operand size so SF/ZF
  // reflect only the low N bits (high garbage from S1 must not leak into Z/N).
  if (IROp->Size != IR::OpSize::i64Bit) EmitTestNZSetCR(Dst, IROp->Size);
  // IR contract for sub-64-bit results: upper bits must be zero (StoreResult_WithOpSize
  // relies on this when GPRSize == i64 && OpSize < i64).  is a full-width AND
  // and only produces a zero-extended result when at least one source is zero-extended
  // in its upper bits — when AllowUpperGarbage=true is passed (which is common for
  // ALU operands), the upper 32 bits of Dst can hold leftover garbage. Mask down
  // explicitly. Without this,  (a 32-bit no-op) silently keeps RBXs
  // original upper 32 bits, breaking x86s implicit-zext-on-32bit-op rule.
  if (IROp->Size == IR::OpSize::i32Bit) {
    rldicl(Dst, Dst, 0, 32);
  } else if (IROp->Size == IR::OpSize::i16Bit) {
    rldicl(Dst, Dst, 0, 48);
  } else if (IROp->Size == IR::OpSize::i8Bit) {
    rldicl(Dst, Dst, 0, 56);
  }
}

// =========================================================================
// Shifts
// =========================================================================

DEF_OP(Lshl) {
  // x86 SHL masks the shift count to 5 bits (8/16/32-bit ops) or 6 bits (64-bit).
  // PPC slw/sld zero the result when the count's "high" bit is set, so feeding
  // an unmasked x86 count (e.g. cl=0x62) returns 0 instead of x86's count & 0x1F.
  auto Op  = IROp->C<IR::IROp_Lshl>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    uint32_t sh = static_cast<uint32_t>(Const & (IROp->Size <= IR::OpSize::i32Bit ? 31 : 63));
    if (IROp->Size <= IR::OpSize::i32Bit) {
      rlwinm(Dst, S1, sh, 0, 31 - sh);
    } else {
      sldi(Dst, S1, sh);
    }
  } else {
    if (IROp->Size <= IR::OpSize::i32Bit) {
      rldicl(TMP4, GetReg(Op->Src2), 0, 59);
      slw(Dst, S1, TMP4);
    } else {
      rldicl(TMP4, GetReg(Op->Src2), 0, 58);
      sld(Dst, S1, TMP4);
    }
  }
}

DEF_OP(Lshr) {
  auto Op  = IROp->C<IR::IROp_Lshr>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    uint32_t sh = static_cast<uint32_t>(Const & (IROp->Size <= IR::OpSize::i32Bit ? 31 : 63));
    if (IROp->Size <= IR::OpSize::i32Bit) {
      if (sh == 0) {
        // sh==0 would make 32-sh==32, and rlwinm only encodes SH in 5 bits.
        // Passing 32 to EmitM as the SH operand spills bit 5 (value 0x20) into
        // the RA field at bit 16 of the encoded instruction — silently corrupting
        // the destination register (e.g. r8 -> r9). Just zero-extend the low 32
        // via rldicl instead; semantically identical for shift-by-zero.
        rldicl(Dst, S1, 0, 32);
      } else {
        rlwinm(Dst, S1, 32 - sh, sh, 31);
      }
    } else {
      srdi(Dst, S1, sh);
    }
  } else {
    if (IROp->Size <= IR::OpSize::i32Bit) {
      rldicl(TMP4, GetReg(Op->Src2), 0, 59);
      srw(Dst, S1, TMP4);
    } else {
      rldicl(TMP4, GetReg(Op->Src2), 0, 58);
      srd(Dst, S1, TMP4);
    }
  }
}

DEF_OP(Ashr) {
  // CRITICAL: PPC `sraw`/`sradi`/`srad` SET XER.CA based on whether any 1-bits
  // were shifted out of a negative value (and CLEAR CA otherwise — even for a
  // shift count of 0). XER.CA is FEX's canonical x86 CF storage when
  // CFInverted=true (the dispatcher's tracking state), so any Ashr emitted by
  // the IR clobbers a flag we are required to preserve. This caused the
  // ShiftZeroFlagsUpdate `sar eax, cl` (cl masked to 0) test to wrongly
  // produce CF=1: the prior popfq left XER.CA=1 (=> x86 CF=0); _Ashr for the
  // SAR's noop-shift cleared CA → ShiftFlags' noShift restore captured the
  // already-corrupt CA → the resulting PUSHF saw CF=1.
  //
  // Replace srawi/sradi/srad with sequences using only rldic*/rlwinm/srd/srw/
  // neg/or_/sldi — none of which touch XER. For sub-64-bit operands we
  // sign-extend (extsw/extsh/extsb) into a scratch and rely on the high bits
  // being properly sign-filled before logical shift right.
  auto Op  = IROp->C<IR::IROp_Ashr>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    uint32_t sh = static_cast<uint32_t>(Const & (IROp->Size <= IR::OpSize::i32Bit ? 31 : 63));
    if (IROp->Size <= IR::OpSize::i32Bit) {
      // Sign-extend low 32 to 64; logical-right via rldicl gives ASR semantics
      // because the high 32 bits are already sign-filled.
      extsw(TMP4, S1);
      if (sh == 0) {
        // No shift; zero-extend writeback.
        rldicl(Dst, TMP4, 0, 32);
      } else {
        rldicl(Dst, TMP4, 64 - sh, sh);    // logical right shift by sh (no Rc)
        rldicl(Dst, Dst, 0, 32);            // zero-extend writeback
      }
    } else {
      if (sh == 0) {
        if (Dst != S1) mr(Dst, S1);
      } else {
        // 64-bit ASR by sh: srdi(body) | sign_fill_mask<<(64-sh).
        // Replicate sign bit into a 64-bit mask without using sradi.
        rldicl(TMP3, S1, 1, 63);             // TMP3 = S1[63] (LSB-only)
        neg(TMP3, TMP3);                     // 0 → 0; 1 → all-1s (no Rc)
        rldicl(TMP4, S1, 64 - sh, sh);       // body: logical right shift
        if (sh == 64) {
          mr(Dst, TMP3);                     // unreachable (sh<64), but safe
        } else {
          sldi(TMP3, TMP3, 64 - sh);         // sign-fill at top
          or_(Dst, TMP4, TMP3);
        }
      }
    }
  } else {
    if (IROp->Size <= IR::OpSize::i32Bit) {
      // Variable count masked to 5 bits; sign-extend then logical-srd.
      rldicl(TMP3, GetReg(Op->Src2), 0, 59);
      extsw(TMP4, S1);
      srd(Dst, TMP4, TMP3);
      rldicl(Dst, Dst, 0, 32);
    } else {
      // 64-bit variable: replicate sign bit, build srd | (sign_mask << (64-cnt)).
      // For count=0 we want Dst=S1; for count=64 PPC `srd` returns 0, so the OR
      // with the sign-fill is what makes the result correct (sign_mask shifted
      // by 0 = sign_mask). Build masked count and (64-count).
      auto Src2 = GetReg(Op->Src2);
      rldicl(TMP3, Src2, 0, 58);             // count = Src2 & 0x3F
      // sign_mask = -(S1 >> 63)
      rldicl(TMP1, S1, 1, 63);
      neg(TMP1, TMP1);
      // body = S1 >> count (logical)
      srd(TMP4, S1, TMP3);
      // shift amount for sign mask = (64 - count) & 0x3F. For count=0 the
      // shift would be 64 → PPC sld returns 0, so sign_mask contribution is 0
      // and Dst = body = S1 (correct). For count=64 (which can't happen since
      // mask is 6 bits and sld treats >=64 as 0) likewise.
      li(TMP2, 64);
      subf(TMP2, TMP3, TMP2);                // TMP2 = 64 - count
      sld(TMP1, TMP1, TMP2);                 // sign_mask << (64-count)
      or_(Dst, TMP4, TMP1);
    }
  }
}

DEF_OP(Ror) {
  auto Op  = IROp->C<IR::IROp_Ror>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    uint32_t rot = static_cast<uint32_t>(Const & 63);
    if (IROp->Size <= IR::OpSize::i32Bit) {
      // CRITICAL: rlwinm's SH field is 5 bits (0..31). When rot==0, the naive
      // `32 - (rot & 31)` evaluates to 32, whose high bit overflows into the
      // RA field of the encoded instruction — silently flipping the dest GPR
      // index by +1. With Dst==r26 (RA[2]) this would write r27 (STATE) and
      // SIGSEGV on the next memory access through STATE. Mask the shift to 5
      // bits so rot==0 yields the correct identity rotation.
      rlwinm(Dst, S1, (32 - (rot & 31)) & 31, 0, 31);
    } else {
      // rotate right = rotate left by (64 - rot). Same overflow story for the
      // 6-bit SH field of rldicl when rot==0 → mask to 6 bits.
      rldicl(Dst, S1, (64 - rot) & 63, 0);
    }
  } else {
    // Rotate-right by n is rotate-left by (width - n), and both rlwnm and
    // rldcl read only the low bits of RB — 5 bits (bits 59:63) for the 32-bit
    // form, 6 bits (58:63) for the 64-bit form — so the count is masked by the
    // hardware. That makes a plain `neg` sufficient: the low k bits of -count
    // are (-count) mod 2^k = (2^k - (count mod 2^k)) mod 2^k, which is exactly
    // the left-rotate amount wanted, including the count ≡ 0 case (neg gives
    // 0 mod 2^k, the identity rotation). No explicit masking of the count and
    // no `width - count` materialisation are needed.
    //
    // neg has OE = 0 and Rc = 0, so it touches neither XER.CA (the canonical
    // x86 CF store under CFInverted=true, which _Ror must not disturb) nor
    // CR0 — the same CA-safety the li/subf pair was chosen for.
    neg(TMP4, GetReg(Op->Src2));
    if (IROp->Size <= IR::OpSize::i32Bit) {
      rlwnm(Dst, S1, TMP4, 0, 31);
    } else {
      rldcl(Dst, S1, TMP4, 0);
    }
  }
}

// =========================================================================
// Bit operations
// =========================================================================

DEF_OP(Popcount) {
  // PPC `popcntw` is a per-word popcount (two parallel 32-bit counts in a
  // 64-bit dest), not a single 32-bit popcount. Using it for a 32-bit POPCNT
  // leaves a stray count in bits 63:32 — e.g. popcntw(0xFFFFFFFFFFFFFFFF)
  // returns 0x0000002000000020 instead of 0x20. Always use popcntd; mask the
  // source for sub-64-bit so the upper bits are zero.
  auto Op  = IROp->C<IR::IROp_Popcount>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:  rldicl(TMP1, Src, 0, 56); Src = TMP1; break;
  case IR::OpSize::i16Bit: rldicl(TMP1, Src, 0, 48); Src = TMP1; break;
  case IR::OpSize::i32Bit: rldicl(TMP1, Src, 0, 32); Src = TMP1; break;
  default: break;
  }
  popcntd(Dst, Src);
}

DEF_OP(FindLSB) {
  // Find least significant bit position (= count trailing zeros).
  // Compute via `cntlz(Src & -Src)`: the AND isolates the lowest set bit,
  // and that bit's position from the LSB equals (width-1 - cntlz).
  // CA-safe: avoid subfic (sets XER.CA).
  auto Op  = IROp->C<IR::IROp_FindLSB>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  neg(TMP1, Src);
  and_(TMP1, Src, TMP1);
  if (IROp->Size <= IR::OpSize::i32Bit) {
    cntlzw(TMP1, TMP1);
    li(TMP2, 31);
    subf(Dst, TMP1, TMP2);
  } else {
    cntlzd(TMP1, TMP1);
    li(TMP2, 63);
    subf(Dst, TMP1, TMP2);
  }
}

DEF_OP(FindMSB) {
  // Find most significant bit position (= width-1 - count leading zeros).
  // CA-safe: avoid subfic (sets XER.CA).
  auto Op  = IROp->C<IR::IROp_FindMSB>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  if (IROp->Size <= IR::OpSize::i32Bit) {
    cntlzw(TMP1, Src);
    li(TMP2, 31);
    subf(Dst, TMP1, TMP2);
  } else {
    cntlzd(TMP1, Src);
    li(TMP2, 63);
    subf(Dst, TMP1, TMP2);
  }
}

DEF_OP(FindTrailingZeroes) {
  // IR contract (matches x86 TZCNT): on zero input return operand width.
  // Formula: popcntd(~MaskedSrc & (MaskedSrc - 1)) yields
  //   nonzero MaskedSrc → tz_count (in [0, Width-1])
  //   zero MaskedSrc    → 64 (since ~0 & -1 = -1, popcntd = 64)
  // For sub-64 operands, mask the inner result to Width bits so the zero
  // case returns Width rather than 64. Also masks Src to operand width so
  // upper garbage doesn't pollute the count for 8/16/32-bit forms.
  auto Op  = IROp->C<IR::IROp_FindTrailingZeroes>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  unsigned Width = 64;
  GPR MaskedSrc = Src;
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:  rldicl(TMP1, Src, 0, 56); MaskedSrc = TMP1; Width = 8;  break;
  case IR::OpSize::i16Bit: rldicl(TMP1, Src, 0, 48); MaskedSrc = TMP1; Width = 16; break;
  case IR::OpSize::i32Bit: rldicl(TMP1, Src, 0, 32); MaskedSrc = TMP1; Width = 32; break;
  default: break;
  }
  addi(TMP2, MaskedSrc, -1);
  not_(TMP3, MaskedSrc);
  and_(TMP2, TMP3, TMP2);
  if (Width < 64) {
    rldicl(TMP2, TMP2, 0, 64 - Width);
  }
  popcntd(Dst, TMP2);
}

DEF_OP(CountLeadingZeroes) {
  // IR contract (matches x86 LZCNT): on zero input return operand width.
  // For sub-64 operands we must count only within the operand bits — using
  // cntlzw on a 16-bit value (with upper 16 implicitly zero) returns 16+lz
  // instead of lz. Mask to operand width then `cntlzd - (64 - Width)`.
  auto Op  = IROp->C<IR::IROp_CountLeadingZeroes>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  switch (IROp->Size) {
  case IR::OpSize::i8Bit:
    rldicl(TMP1, Src, 0, 56);
    cntlzd(TMP1, TMP1);
    addi(Dst, TMP1, -56);
    break;
  case IR::OpSize::i16Bit:
    rldicl(TMP1, Src, 0, 48);
    cntlzd(TMP1, TMP1);
    addi(Dst, TMP1, -48);
    break;
  case IR::OpSize::i32Bit:
    rldicl(TMP1, Src, 0, 32);
    cntlzd(TMP1, TMP1);
    addi(Dst, TMP1, -32);
    break;
  case IR::OpSize::i64Bit:
    cntlzd(Dst, Src);
    break;
  default: break;
  }
}

DEF_OP(Rev) {
  // Byte-reverse (bswap)
  auto Op  = IROp->C<IR::IROp_Rev>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  // RA may tie Dst to Src. The byte-swap sequences below all do at least one
  // write to Dst before the final read of Src, so stash Src in a temp when
  // they alias. Otherwise the first rlwinm overwrites Src, and the second
  // rlwinm reads garbage — manifested as MOVBE 16-bit storing the LOW byte
  // twice (bytes [+0]=0x58, [+1]=0x58 instead of [+0]=0x57, [+1]=0x58 for
  // r15w=0x5758).
  if (Dst == Src) { mr(TMP4, Src); Src = TMP4; }
  // PPC64LE doesn't have a simple bswap GPR instruction.
  // Approach: use brh/brw/brd if available (POWER10), otherwise use rotates.
  // For POWER8: combine rotate+mask to do byte swap.
  switch (IROp->Size) {
  case IR::OpSize::i16Bit: {
    // Swap the two bytes of the low halfword, zero-extending the result.
    // PPC (MSB=0) bit numbering: the low halfword's high byte H is at PPC
    // 16..23, its low byte L at PPC 24..31. ROTL32 by SH moves PPC q to
    // (q - SH) mod 32.
    //   L (24..31) -> 16..23 needs SH = 8;  mask MB=16, ME=23.
    //   H (16..23) -> 24..31 needs SH = 24; mask MB=24, ME=31.
    // rlwinm zeroes everything outside its mask (including bits 0..31 of the
    // 64-bit register), and rlwimi then merges the second byte in, so the
    // separate or_ and the trailing zero-extension mask both disappear.
    rlwinm(Dst, Src, 8,  16, 23);   // L into the high byte slot
    rlwimi(Dst, Src, 24, 24, 31);   // H into the low byte slot
    break;
  }
  case IR::OpSize::i32Bit: {
    // Canonical 3-instruction PPC bswap32. For Src = AABBCCDD (PPC bytes
    // 0..7 = AA, 8..15 = BB, 16..23 = CC, 24..31 = DD) we want DDCCBBAA.
    //   rlwinm Dst, Src, 8, 0, 31   -> Dst = ROTL32(Src, 8)  = BBCCDDAA
    //        which already has CC in byte 1 and AA in byte 3 — correct.
    //   ROTL32(Src, 24) = DDAABBCC has DD in byte 0 and BB in byte 2, so two
    //   rlwimi with SH = 24 insert exactly those two byte lanes:
    //   mask 0..7 for DD and mask 16..23 for BB.
    // The first rlwinm zeroes bits 0..31 of the 64-bit register, and rlwimi
    // preserves them, so the result is zero-extended as before.
    rlwinm(Dst, Src, 8,  0,  31);
    rlwimi(Dst, Src, 24, 0,  7);
    rlwimi(Dst, Src, 24, 16, 23);
    break;
  }
  default: {  // 64-bit
    // stdbrx stores in big-endian byte order; a subsequent regular ld reads
    // it back in little-endian order, producing bswap(Src). Use the red-zone
    // (r1-8) rather than modifying r1 so async signals can't corrupt the frame.
    addi(TMP1, r1, -8);
    stdbrx(Src, TMP1, r0);
    ld(Dst, -8, r1);
    break;
  }
  }
}

DEF_OP(Rbit) {
  // Reverse bits (not bits in bytes, but all 64 bits)
  // No direct instruction on POWER8. Use bpermd + constant.
  auto Op  = IROp->C<IR::IROp_Rbit>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  // bpermd RA, RS, RB: permutes bits of RS using RS as index bytes
  // To reverse 64 bits: use bpermd with pattern 0x3F3E3D3C3B3A3938...
  // For 64-bit reverse: index bytes are 63,62,61,...,56 in each byte lane
  // bpermd selects bits from RS using indices in RB
  // RB bytes [0..7]: each byte selects one bit from RS (bit 63-index means position)
  // For bit-reverse: byte i of RB = 63 - (7 * i + offset within group)
  // Actually bpermd is complex. Let's use a fallback for now.
  // Simple bit-reverse via multiply-and-magic:
  // This is a well-known 64-bit bit-reversal:
  // Using a sequence of SWAR operations.
  if (IROp->Size == IR::OpSize::i64Bit) {
    // 64-bit reverse using bpermd
    // bpermd RA,RS,RB: RA[bit i] = RS[bit RB[byte_i]] for i in 0..7
    // Actually bpermd produces an 8-bit result in the low byte of RA.
    // We need to call it 8 times. Instead, use library call via Op_Unhandled.
    // For now: use the standard SWAR approach with shifts
    mr(TMP1, Src);
    // Swap adjacent bits
    LoadConstant(TMP2, 0x5555555555555555ULL);
    srdi(TMP3, TMP1, 1);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 1);
    or_(TMP1, TMP3, TMP4);
    // Swap adjacent pairs
    LoadConstant(TMP2, 0x3333333333333333ULL);
    srdi(TMP3, TMP1, 2);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 2);
    or_(TMP1, TMP3, TMP4);
    // Swap nibbles
    LoadConstant(TMP2, 0x0F0F0F0F0F0F0F0FULL);
    srdi(TMP3, TMP1, 4);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 4);
    or_(TMP1, TMP3, TMP4);
    // Byte-reverse the result
    addi(r1, r1, -16);
    stdbrx(TMP1, r0, r1);
    ld(Dst, 0, r1);
    addi(r1, r1, 16);
  } else {
    // 32-bit reverse
    mr(TMP1, Src);
    LoadConstant(TMP2, 0x55555555ULL);
    srdi(TMP3, TMP1, 1);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 1);
    or_(TMP1, TMP3, TMP4);
    LoadConstant(TMP2, 0x33333333ULL);
    srdi(TMP3, TMP1, 2);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 2);
    or_(TMP1, TMP3, TMP4);
    LoadConstant(TMP2, 0x0F0F0F0FULL);
    srdi(TMP3, TMP1, 4);
    and_(TMP3, TMP3, TMP2);
    and_(TMP4, TMP1, TMP2);
    sldi(TMP4, TMP4, 4);
    or_(TMP1, TMP3, TMP4);
    // byte-reverse word.  On LE host, stw stores native LE and lwbrx
    // byte-reverses on load — those two operations cancel out, leaving
    // an identity load (no actual byte swap).  Match the 64-bit path
    // which correctly uses stdbrx + ld for the bswap.
    addi(r1, r1, -16);
    stwbrx(TMP1, r0, r1); // byte-reverse on store
    lwz(Dst, 0, r1);      // load native LE -> bswap(TMP1)
    addi(r1, r1, 16);
  }
}

// =========================================================================
// Bit-field operations
// =========================================================================

DEF_OP(Bfe) {
  // Bit field extract (unsigned): extract n bits starting at lsb
  auto Op  = IROp->C<IR::IROp_Bfe>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  uint32_t width  = Op->Width;
  uint32_t lsb    = Op->lsb;
  if (IROp->Size <= IR::OpSize::i32Bit) {
    // rlwinm RA, RS, SH, MB, ME where:
    // We want bits [lsb, lsb+width-1] of Src in low bits of Dst.
    // Rotate right by lsb bits to bring LSB to bit 31, then mask.
    uint32_t rot = (32 - lsb) & 31;
    rlwinm(Dst, Src, rot, 32 - width, 31);
  } else {
    // rldicl: rotate left by (64-lsb) to bring lsb to bit 63, clear bits > width
    uint32_t rot = (64 - lsb) & 63;
    rldicl(Dst, Src, rot, 64 - width);
  }
}

DEF_OP(Sbfe) {
  // Bit field extract (signed). Like Ashr above we cannot use srawi/sradi —
  // they clobber XER.CA, the canonical x86 CF when CFInverted=true. Use
  // extsb/extsh/extsw + rldicl-only sequences. Sbfe is heavily emitted by the
  // ASHROp dispatcher pre-shift sign-extend (sub-32-bit SAR), so a CA leak
  // here corrupts the next Adc/Sbb/PUSHF.
  auto Op  = IROp->C<IR::IROp_Sbfe>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src);
  uint32_t width = Op->Width;
  uint32_t lsb   = Op->lsb;

  // Common cases first: lsb=0 with width matching extsb/extsh/extsw.
  if (lsb == 0) {
    if (width == 8) {
      extsb(Dst, Src);
      if (IROp->Size <= IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
      return;
    }
    if (width == 16) {
      extsh(Dst, Src);
      if (IROp->Size <= IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
      return;
    }
    if (width == 32) {
      extsw(Dst, Src);
      if (IROp->Size <= IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
      return;
    }
  }

  // General case: extract unsigned then construct sign-fill via neg(sign_bit).
  if (IROp->Size <= IR::OpSize::i32Bit) {
    uint32_t rot = (32 - lsb) & 31;
    rlwinm(TMP1, Src, rot, 32 - width, 31);    // TMP1 has unsigned field at bits [0..width-1]
    // Sign bit of the field = TMP1[width-1]. Replicate via neg.
    rldicl(TMP2, TMP1, 64 - (width - 1), 63);  // TMP2 = sign-bit (LSB)
    neg(TMP2, TMP2);                            // 0 → 0; 1 → all-1s
    sldi(TMP2, TMP2, width);                    // sign-fill at positions [width..63]
    or_(Dst, TMP1, TMP2);
    rldicl(Dst, Dst, 0, 32);                    // mask to low 32 (zero-extend writeback)
  } else {
    uint32_t rot = (64 - lsb) & 63;
    rldicl(TMP1, Src, rot, 64 - width);         // TMP1 has unsigned field at bits [0..width-1]
    rldicl(TMP2, TMP1, 64 - (width - 1), 63);   // TMP2 = sign bit (LSB only)
    neg(TMP2, TMP2);                             // 0 → 0; 1 → all-1s
    if (width < 64) {
      sldi(TMP2, TMP2, width);                   // sign-fill positions [width..63]
      or_(Dst, TMP1, TMP2);
    } else {
      mr(Dst, TMP1);                             // width=64: nothing to fill
    }
  }
}

DEF_OP(Bfi) {
  // Bit field insert: insert width bits of Src into Dst at lsb
  auto Op   = IROp->C<IR::IROp_Bfi>();
  auto Dst  = GetReg(Node);
  auto S1   = GetReg(Op->Dest);
  auto Src  = GetReg(Op->Src);
  uint32_t width = Op->Width;
  uint32_t lsb   = Op->lsb;
  // Same last-use aliasing hazard Bfxil below already guards against, and it was
  // never applied here. If RA picked Dst == Src (normal when Src dies at this
  // op) while Dst != S1, the mr(Dst, S1) overwrites Src before the insert reads
  // it, and the field inserted is whatever Dest happened to hold.
  //
  // `xchg %ah, %al` is the case that exposed it: the AL store is
  // Bfi(Dest=RAX, Src=RAX>>8, lsb=0, width=8) with the shifted value at last
  // use, so the mr clobbered it and the insert put RAX's own low byte back --
  // giving (AL << 8) | AL. That instruction is what GCC emits for a runtime
  // 16-bit byteswap, so every htons/ntohs/__builtin_bswap16 in every guest was
  // silently returning the wrong value, with no fault to notice.
  if (Dst == Src && Dst != S1) {
    mr(TMP3, Src);
    Src = TMP3;
  }
  if (Dst != S1) mr(Dst, S1);  // copy Dest into result first
  if (IROp->Size <= IR::OpSize::i32Bit) {
    // rlwimi inserts field
    rlwimi(Dst, Src, lsb, 32 - lsb - width, 31 - lsb);
  } else {
    // rldimi
    rldimi(Dst, Src, lsb, 64 - lsb - width);
  }
}

DEF_OP(Bfxil) {
  // Bit field extract and insert lower: per IR.json, copy Src[lsb+Width-1:lsb]
  // into Dest[Width-1:0], preserving Dest[Size-1:Width].
  //
  // Earlier impl was `rldimi/rlwimi(Dst, Src, (Size-lsb)%Size, Size-Width)`,
  // which has a subtle wrap-around bug: PPC rldimi's MASK(MB, 63-SH) wraps
  // when MB > 63-SH, producing TWO insert windows. For Bfxil(width=16,lsb=16)
  // that gives SH=48, MB=48, ME=15 → mask covers bits [63:48] AND [15:0],
  // so we'd insert Src[15:0] into Dst[63:48] in addition to the intended
  // Src[31:16] → Dst[15:0]. This silently zeroed the upper 16 bits of any
  // 64-bit Bfxil (e.g. MOVBE 16-bit zeroed bits 48..63 of the dest GPR).
  //
  // Avoid the wrap: extract the source field first (rldicl/rlwinm with
  // wrap-free mask) then insert at lsb=0 with SH=0 (no wrap possible).
  auto Op   = IROp->C<IR::IROp_Bfxil>();
  auto Dst  = GetReg(Node);
  auto S1   = GetReg(Op->Dest);
  auto Src  = GetReg(Op->Src);
  uint32_t width = Op->Width;
  uint32_t lsb   = Op->lsb;
  // If RA chose Dst == Src (last-use alias) but Dst != S1, the mr(Dst, S1)
  // below would overwrite Src before the rlwimi/rlwinm can read it. Stash
  // Src into TMP3 first. Caught by `arpl ax, bx` in 32-bit guest mode where
  // the ARPLOp dispatcher emits Bfxil(2, 0, Dest, SrcRPL) with SrcRPL having
  // last use here: RA aliased Dst and SrcRPL into the same physical reg,
  // so the mr clobbered SrcRPL and ARPL's modify path became a no-op.
  if (Dst == Src && Dst != S1) {
    mr(TMP3, Src);
    Src = TMP3;
  }
  if (Dst != S1) mr(Dst, S1);
  if (IROp->Size <= IR::OpSize::i32Bit) {
    if (lsb == 0) {
      rlwimi(Dst, Src, 0, 32 - width, 31);
    } else {
      uint32_t rot = (32u - lsb) & 31u;
      rlwinm(TMP1, Src, rot, 32 - width, 31);   // TMP1 = (Src >> lsb) & mask(width)
      rlwimi(Dst, TMP1, 0, 32 - width, 31);     // insert into Dst[width-1:0]
    }
  } else {
    if (lsb == 0) {
      rldimi(Dst, Src, 0, 64 - width);
    } else {
      uint32_t rot = (64u - lsb) & 63u;
      rldicl(TMP1, Src, rot, 64 - width);       // TMP1 = (Src >> lsb) & mask(width)
      rldimi(Dst, TMP1, 0, 64 - width);
    }
  }
}

DEF_OP(Extr) {
  // Extract: ARM EXTR semantics — Dst = (Upper:Lower) >> LSB, low N bits.
  // For 32-bit, that's (Upper << (32-sh)) | (Lower >> sh): contribution from
  // Upper is its low `sh` bits placed in the top of the result; contribution
  // from Lower is its high `32-sh` bits placed in the bottom.
  //
  // PPC rlwinm with rot=32-sh:
  //   rotate-left(Upper, 32-sh) puts Upper bits[0..sh-1] (LSB nums) into
  //     bits[32-sh..31]; in PPC big-endian numbering those are PPC bits
  //     0..sh-1. Mask 0..sh-1 keeps just that contribution.
  //   rotate-left(Lower, 32-sh) puts Lower bits[sh..31] into bits[0..31-sh];
  //     PPC bits sh..31. Mask sh..31 keeps just that contribution.
  auto Op  = IROp->C<IR::IROp_Extr>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Upper);
  auto S2  = GetReg(Op->Lower);
  uint32_t sh = Op->LSB;
  if (IROp->Size <= IR::OpSize::i32Bit) {
    if (sh == 0) {
      if (Dst != S2) mr(Dst, S2);
      rldicl(Dst, Dst, 0, 32);
      return;
    }
    rlwinm(TMP1, S1, 32 - sh, 0, sh - 1);   // Upper contribution at top
    rlwinm(TMP2, S2, 32 - sh, sh, 31);      // Lower contribution at bottom
    or_(Dst, TMP1, TMP2);
    rldicl(Dst, Dst, 0, 32);                // zero-extend
  } else {
    if (sh == 0) {
      // sldi(_, _, 64) encodes rldicr SH=64 which wraps SH-low-6-bits=0
      // and produces mr instead of zero.  Mirror the 32-bit sh==0 path.
      if (Dst != S2) mr(Dst, S2);
      return;
    }
    srdi(TMP1, S2, sh);
    sldi(TMP2, S1, 64 - sh);
    or_(Dst, TMP1, TMP2);
  }
}

DEF_OP(PDep) {
  // Parallel bits deposit. POWER8 has no equivalent; iterate set bits of mask.
  // Algorithm (per arm64 reference): T0 = isolate-low-set-bit(mask); for each
  // such bit, OR (input&1 ? T0 : 0) into Dst, shift input right by 1, clear T0
  // from mask, repeat until mask==0.
  auto Op       = IROp->C<IR::IROp_PDep>();
  auto Dest     = GetReg(Node);
  auto OrigIn   = GetReg(Op->Input);
  auto OrigMask = GetReg(Op->Mask);

  GPR Input = TMP1, Mask = TMP2, T0 = TMP3, T1 = TMP4;
  PPC64Emitter::Label NextBit, Done;

  mr(Input, OrigIn);
  mr(Mask, OrigMask);
  li(Dest, 0);
  // x86 BMI2 PDEP preserves flags per Intel SDM ("Flags Affected: None").
  // CR0 here is the canonical packed-NZCV scratch — save it to a red-zone
  // slot before the loop and restore at the end so flags survive the op.
  // mfocrf 0x80: CR0 nibble valid in T0 bits 31:28 (LSB), all other bits
  // UNDEFINED pre-ISA-3.0C — safe because the only consumer is the
  // mtocrf(0x80) restore below, which reads exactly that nibble.
  mfocrf(T0, 0x80);            // T0 = CR0 snapshot (using T0 briefly)
  std(T0, -16, r1);            // stash to red zone
  cmpdi(Mask, 0);              // read snapshot (Dest may alias OrigMask)
  bc(CC_EQ, &Done);

  Bind(&NextBit);
  neg(T0, Mask);
  and_(T0, T0, Mask);          // T0 = isolated low set bit
  rldicl(T1, Input, 0, 63);    // T1 = Input & 1
  neg(T1, T1);                 // T1 = 0 or all-ones
  and_(T1, T1, T0);            // T1 = T0 if input bit set else 0
  or_(Dest, Dest, T1);
  srdi(Input, Input, 1);
  andc(Mask, Mask, T0);        // clear processed bit from mask
  cmpdi(Mask, 0);
  bc(CC_NE, &NextBit);

  Bind(&Done);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dest, Dest, 0, 32);
  // Restore CR0 (only — mtocrf field 0 mask = 0x80) so any packed-NZCV
  // held there pre-PDep survives.
  ld(T0, -16, r1);
  mtocrf(0x80, T0);
}

DEF_OP(PExt) {
  // Parallel bits extract. Iterate set bits of mask LSB-first; for each, append
  // that input bit to Dest at position OutPos (held on the stack to free a TMP).
  auto Op       = IROp->C<IR::IROp_PExt>();
  auto Dest     = GetReg(Node);
  auto OrigIn   = GetReg(Op->Input);
  auto OrigMask = GetReg(Op->Mask);

  GPR InputSnap = TMP1, Mask = TMP2, LowBit = TMP3, Scratch = TMP4;
  PPC64Emitter::Label NextBit, Done, NoSet;

  // Snapshot inputs before clobbering Dest (Dest may alias either source).
  mr(InputSnap, OrigIn);
  mr(Mask, OrigMask);
  li(Dest, 0);
  // x86 BMI2 PEXT preserves flags per Intel SDM.  Save CR0 (the canonical
  // packed-NZCV scratch) to a red-zone slot and restore at op end.
  // mfocrf 0x80: only the CR0 nibble is defined pre-3.0C; the sole consumer
  // is the mtocrf(0x80) restore, which reads only that nibble.
  mfocrf(Scratch, 0x80);
  std(Scratch, -16, r1);
  cmpdi(Mask, 0);
  bc(CC_EQ, &Done);

  // Stack slot for OutPos counter.
  addi(r1, r1, -16);
  li(Scratch, 0);
  std(Scratch, 0, r1);

  Bind(&NextBit);
  neg(LowBit, Mask);
  and_(LowBit, LowBit, Mask);          // LowBit = isolated low set bit
  and_(Scratch, LowBit, InputSnap);    // input bit at that position
  cmpdi(Scratch, 0);
  bc(CC_EQ, &NoSet);
  ld(Scratch, 0, r1);                  // OutPos
  li(LowBit, 1);                       // (recompute LowBit later)
  sld(LowBit, LowBit, Scratch);
  or_(Dest, Dest, LowBit);
  neg(LowBit, Mask);                   // recompute isolated low bit for clear
  and_(LowBit, LowBit, Mask);
  Bind(&NoSet);
  andc(Mask, Mask, LowBit);            // strip processed bit
  ld(Scratch, 0, r1);
  addi(Scratch, Scratch, 1);
  std(Scratch, 0, r1);
  cmpdi(Mask, 0);
  bc(CC_NE, &NextBit);
  addi(r1, r1, 16);

  Bind(&Done);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dest, Dest, 0, 32);
  // Restore CR0 so the packed-NZCV scratch held there pre-PExt survives.
  ld(Scratch, -16, r1);
  mtocrf(0x80, Scratch);
}

// =========================================================================
// With-flags variants (set NZCV equivalent in CR0)
// =========================================================================

DEF_OP(AddWithFlags) {
  auto Op  = IROp->C<IR::IROp_AddWithFlags>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  uint64_t Const;
  bool S2Inline = IsInlineConstant(Op->Src2, &Const);

  // For sub-64-bit ops, x86 CF is the carry-out of bit N-1 and OF is the signed
  // overflow at the same boundary. PPC's addco. produces those for bit 63.
  // Trick: shift both operands left by (64-N) so the operand-size carry/overflow
  // boundary lines up at bit 63, do the 64-bit addco., then shift the result
  // back. XER.CA/OV then match x86 semantics for N bits.
  //
  // The shifted addco_ is now the ONLY arithmetic on this path. Previously the
  // value was computed twice — a plain 64-bit add/addic_/addco_ into Dst plus
  // this shifted redo purely for the flags — and a trailing cmpwi/extsX+cmpdi
  // recomputed N/Z that the shifted addco_ had already produced. Both are
  // dropped:
  //   * VALUE: the shifted sum is (a + b) << Sh; its low Sh bits are zero, so
  //     `srdi Dst, TMP1, Sh` yields exactly the low-N-bit sum, zero-extended
  //     into the upper bits. That is precisely the writeback x86-64 requires
  //     for sub-64-bit destinations (and what StoreResult_WithOpSize assumes),
  //     so the zero-extension comes for free instead of via a separate rldicl.
  //   * FLAGS: this is the equivalence already written out at DEF_OP(AddNZCV)
  //     below. CR0 from addco_ on the shifted value has LT = bit 63 of
  //     (sum << Sh) = bit N-1 of sum = x86 SF, and EQ = (sum << Sh) == 0
  //     <=> low N bits of sum == 0 = x86 ZF. The srdi that follows is an
  //     rldicl with Rc=0, so it does not disturb CR0.
  if (IROp->Size <= IR::OpSize::i32Bit) {
    uint32_t Sh = 64 - IR::OpSizeToSize(IROp->Size) * 8;
    sldi(TMP1, S1, Sh);
    if (S2Inline) {
      LoadConstant(TMP2, Const << Sh);
    } else {
      sldi(TMP2, GetReg(Op->Src2), Sh);
    }
    addco_(TMP1, TMP1, TMP2);   // CA/OV reflect bit-(N-1) carry / signed overflow; CR0 = N/Z
    srdi(Dst, TMP1, Sh);        // zero-extended operand-size value, CR0 untouched
    return;
  }

  // 64-bit only from here (everything narrower returned above). There is no
  // shifted redo at this width, so the flag-producing instruction must write
  // CA *and* OV itself: addic_ never writes OV, which is why it used to leak a
  // stale x86 OF (FEX_bugs/add_sub_inline_imm_of.asm) and why it is not used.
  // Materialising the constant and using addco_ costs the same two
  // instructions an addic_-plus-OV-redo would, without adding a second add.
  if (S2Inline) {
    LoadConstant(TMP4, Const);
    addco_(Dst, S1, TMP4);  // addco. sets CA + SO/OV + CR0
  } else {
    addco_(Dst, S1, GetReg(Op->Src2));
  }
}

DEF_OP(SubWithFlags) {
  auto Op  = IROp->C<IR::IROp_SubWithFlags>();
  auto Dst = GetReg(Node);
  uint64_t C1, C2;
  bool S1Inline = IsInlineConstant(Op->Src1, &C1);
  bool S2Inline = IsInlineConstant(Op->Src2, &C2);

  // Sub-64-bit: shift-up trick to move the borrow boundary to bit 63 so XER.CA/OV
  // reflect operand-size CF/OF. As in AddWithFlags above, the shifted subfco_
  // is now the ONLY arithmetic:
  //   * VALUE: the shifted difference is (a - b) << Sh with its low Sh bits
  //     zero, so `srdi Dst, TMP1, Sh` gives the low-N-bit difference
  //     zero-extended — the writeback x86-64 wants for a sub-64-bit dest.
  //     This replaces both the separate 64-bit `subf Dst, S2, S1` (whose upper
  //     bits were whatever the sources happened to carry) and, at 32-bit, the
  //     `rldicl Dst, Dst, 0, 32` that had to clean up after it.
  //   * FLAGS: CR0 from subfco_ on the shifted operands has LT = bit 63 of
  //     (diff << Sh) = bit N-1 of diff = x86 SF, and EQ = (diff << Sh) == 0
  //     <=> low N bits of diff == 0 = x86 ZF. So the trailing extsX+cmpdi
  //     (8/16-bit) and cmpwi (32-bit) recomputed what CR0 already held. Same
  //     equivalence spelled out at DEF_OP(AddNZCV). srdi is rldicl with Rc=0
  //     and leaves CR0 alone.
  if (IROp->Size <= IR::OpSize::i32Bit) {
    uint32_t Sh = 64 - IR::OpSizeToSize(IROp->Size) * 8;
    GPR S1Reg, S2Reg;
    if (S1Inline) { LoadConstant(TMP3, C1); S1Reg = TMP3; } else S1Reg = GetReg(Op->Src1);
    if (S2Inline) { LoadConstant(TMP4, C2); S2Reg = TMP4; } else S2Reg = GetReg(Op->Src2);
    sldi(TMP1, S1Reg, Sh);
    sldi(TMP2, S2Reg, Sh);
    subfco_(TMP1, TMP2, TMP1);   // CA/OV at the correct boundary; CR0 = N/Z
    srdi(Dst, TMP1, Sh);         // zero-extended operand-size value, CR0 untouched
    return;
  }

  // 64-bit only from here. The flag-producing instruction must write CA *and*
  // OV itself, so neither addic_ (no OV; and addic_ with imm 0 yields CA=0
  // where the CFInverted=true subtract convention needs CA=1 for x-0) nor
  // subfic (no OV, no CR0) is usable — both were 32-bit-only fast paths and
  // the 32-bit path no longer reaches here. subfco_ is the canonical sub-form
  // carry: for C != 0 its CA (carry of S1 + ~C + 1) is identical to addic_'s
  // carry of S1 + (-C), and it additionally writes OV and CR0.
  if (S2Inline) {
    LoadConstant(TMP4, C2);
    subfco_(Dst, TMP4, GetReg(Op->Src1));  // sets CA + SO/OV + CR0
  } else if (S1Inline) {
    LoadConstant(TMP4, C1);
    subfco_(Dst, GetReg(Op->Src2), TMP4);  // sets CA + SO/OV + CR0
  } else {
    subfco_(Dst, GetReg(Op->Src2), GetReg(Op->Src1));
  }
}

// IMPORTANT: never use r0 as the destination of *NZCV / Test ops. r0 is the
// JIT's "zero index" invariant for ldx/stdx; writing to r0 as a discard reg
// silently broke addressing for every subsequent indexed memory op until the
// dispatcher re-set r0=0. Use TMP3 (r5) as the scratch instead.
DEF_OP(AddNZCV) {
  auto Op = IROp->C<IR::IROp_AddNZCV>();
  auto S1 = GetReg(Op->Src1);
  uint64_t Const;
  bool S2Inline = IsInlineConstant(Op->Src2, &Const);

  // For 8/16/32-bit ops the carry/overflow boundary is bit N-1; do the addco.
  // on operands shifted left by (64-N) so XER.CA/OV reflect that boundary.
  if (IROp->Size <= IR::OpSize::i32Bit) {
    uint32_t Sh = 64 - IR::OpSizeToSize(IROp->Size) * 8;
    sldi(TMP1, S1, Sh);
    if (S2Inline) {
      LoadConstant(TMP2, Const << Sh);
    } else {
      sldi(TMP2, GetReg(Op->Src2), Sh);
    }
    addco_(TMP3, TMP1, TMP2);    // CA/OV correct; CR0.LT/EQ from shifted result
    // SF/ZF need a check on the *unshifted* truncated result. CR0 from addco_
    // above is already on the shifted value, whose sign bit aligns with the
    // operand-size sign bit (because we shifted left), and whose zero == zero
    // of the truncated result — so it's correct as-is. No extra cmp needed.
    return;
  }

  if (S2Inline) {
    // Only the 64-bit size reaches this point (<= i32Bit returned above), and
    // at 64-bit there is no shifted redo to repair XER.OV — so the former
    // addic_ int16 fast path left OF stale (same defect as AddWithFlags,
    // FEX_bugs/add_sub_inline_imm_of.asm). Materialise the constant and use
    // addco_, which writes CA + SO/OV + CR0. Costs one extra instruction
    // (li/LoadConstant) over addic_; an addic_-plus-OV-redo alternative would
    // cost the same two instructions while executing the add twice.
    LoadConstant(TMP4, Const);
    addco_(TMP3, S1, TMP4);                            // CA + SO/OV + CR0
  } else {
    addco_(TMP3, S1, GetReg(Op->Src2));
  }
}

DEF_OP(SubNZCV) {
  auto Op = IROp->C<IR::IROp_SubNZCV>();
  uint64_t C1, C2;
  bool S1Inline = IsInlineConstant(Op->Src1, &C1);
  bool S2Inline = IsInlineConstant(Op->Src2, &C2);

  // 8/16/32-bit: shift operands left by (64-N) so PPC's bit-63 borrow / signed
  // overflow line up with the operand-size flags x86 needs.
  if (IROp->Size <= IR::OpSize::i32Bit) {
    uint32_t Sh = 64 - IR::OpSizeToSize(IROp->Size) * 8;
    GPR S1Reg, S2Reg;
    if (S1Inline) { LoadConstant(TMP1, C1 << Sh); S1Reg = TMP1; }
    else          { sldi(TMP1, GetReg(Op->Src1), Sh); S1Reg = TMP1; }
    if (S2Inline) { LoadConstant(TMP2, C2 << Sh); S2Reg = TMP2; }
    else          { sldi(TMP2, GetReg(Op->Src2), Sh); S2Reg = TMP2; }
    subfco_(TMP3, S2Reg, S1Reg);   // CA/OV at operand-size boundary; CR0 on shifted result
    return;
  }

  if (S2Inline) {
    auto S1 = GetReg(Op->Src1);
    // Historical note — two independent reasons the addic. int16 shortcut is
    // gone from this (64-bit-only) path:
    //  1. C2 == 0: PPC `addic.` sets CA from S1 + (-C2). For C2==0 that's
    //     S1 + 0 → CA=0 (no carry from a +0). But sub-by-0 has no borrow, so
    //     the SUB-form CA must be 1. The bug masks CFInverted=true downstream:
    //     !CA reads as x86 CF=1 instead of CF=0, and PUSHF / LAHF / Jcc on
    //     carry all see a phantom CF=1 across the ENTIRE block.
    //  2. addic. never writes OV, and only sizes > i32Bit reach here — there
    //     is no shifted redo to repair it, so x86 OF went stale
    //     (FEX_bugs/add_sub_inline_imm_of.asm).
    // subfco_ preserves the CF semantics the C2 != 0 shortcut was chosen for:
    // its CA (carry of S1 + ~C2 + 1) equals addic_'s carry of S1 + (-C2)
    // whenever C2 != 0, and is the correct no-borrow=1 for C2 == 0 too.
    LoadConstant(TMP4, C2);
    subfco_(TMP3, TMP4, S1);                           // CA + SO/OV + CR0
  } else if (S1Inline) {
    auto S2 = GetReg(Op->Src2);
    // subfic sets CA but neither CR0 nor OV; with no 64-bit redo available,
    // materialise C1 and use subfco_ (same stale-OV defect class as above).
    LoadConstant(TMP4, C1);
    subfco_(TMP3, S2, TMP4);                           // CA + SO/OV + CR0
  } else {
    auto S1 = GetReg(Op->Src1);
    subfco_(TMP3, GetReg(Op->Src2), S1);
  }
}

// Set CR0.LT/EQ from a sub-word AND result, honouring IR operand size.
//   The AND result is zero-padded above the operand width, so PPC's `and.`
//   (which tests the full 64-bit value) would miss Z when garbage lives in
//   the high bits of the source — see TestNZ in `path-walk` byte loops where
//   R0 retains old high bits across a Bfi #8.  We sign-extend the AND result
//   from the operand size up to 64-bit, then `cmpdi 0` so that:
//     CR0.EQ = (low <Size> bits == 0)              (Z)
//     CR0.LT = (sign-bit of <Size>-wide value)     (N)
// Sign-extension is correct here because the IR's TestNZ specifies SF/ZF on
// the operand width — without it CR0.LT would always be 0 for sub-64-bit Size.
void PPC64JITCore::EmitTestNZSetCR(GPR Result, IR::OpSize Size) {
  // Sign-extend into TMP1 (don't clobber Result — callers may pass an SSA
  // Dst whose natural value must remain zero-extended for downstream uses).
  // The record forms collapse the old `extsX ; cmpdi 0` pair into one
  // instruction: extsX. writes CR0 from a signed comparison of the 64-bit
  // sign-extended result against zero — bit-for-bit what the cmpdi produced
  // (LT = sign bit of the <Size>-wide value = N, EQ = low <Size> bits zero
  // = Z, SO copied from XER.SO exactly as cmpdi copies it).
  switch (Size) {
    case IR::OpSize::i8Bit:
      extsb_(TMP1, Result);
      return;
    case IR::OpSize::i16Bit:
      extsh_(TMP1, Result);
      return;
    case IR::OpSize::i32Bit:
      extsw_(TMP1, Result);
      return;
    case IR::OpSize::i64Bit:
    default:
      cmpdi(Result, 0);
      return;
  }
}

DEF_OP(TestNZ) {
  auto Op = IROp->C<IR::IROp_TestNZ>();
  auto S1 = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if ((Const & 0xFFFF) == Const) {
      andi_(TMP3, S1, static_cast<uint16_t>(Const));   // sets CR0 from full 64-bit
    } else {
      LoadConstant(TMP4, Const);
      and__(TMP3, S1, TMP4);
    }
  } else {
    and__(TMP3, S1, GetReg(Op->Src2));
  }
  // IR contract: clear C and V (logical ops clear NZCV.C/V). PPC and./andi.
  // only set CR0; XER.CA/OV retain their prior values. Clear them here so
  // SetNZ_ZeroCV's "host carry will be implicitly zeroed" comment in
  // OpcodeDispatcher.h holds for 8/16-bit TEST/AND/OR/XOR via TestNZ.
  // (The 32/64-bit SetNZ_ZeroCV path uses _SubNZCV which writes correct CA;
  // only the sub-32 path goes through _TestNZ.)
  //
  // A single OE=1 add of 0+0 replaces the mfspr/mask/mtspr XER round trip
  // (an SPR move pair is one of the most expensive sequences on POWER8, and
  // this is one of the hottest guest shapes: `test reg,reg` + jcc).
  // Equivalence argument, in LSB bit numbers of the 64-bit XER value
  // (ISA big-endian bit 32 = SO, 33 = OV, 34 = CA  =>  LSB 31/30/29):
  //   * old mask 0x60000000 = LSB bits 30|29 = OV|CA, cleared via andc,
  //     so the old sequence cleared exactly CA and OV and preserved SO.
  //   * addco writes CA = carry out of the add and OV = signed overflow of
  //     the add; 0 + 0 produces neither, so CA = OV = 0.  SO is sticky —
  //     hardware only ORs OV into it, never clears it — so SO survives,
  //     matching the old andc.
  //   * Rc = 0 (Emitter.h `addco`, not `addco_`), so CR0 — which holds the
  //     packed guest NZCV set by the and./andi. above and refined by
  //     EmitTestNZSetCR below — is NOT touched.
  // r0 is the JIT's zero-index invariant register (see PPC64Dispatcher.cpp),
  // so this really is 0 + 0.  TMP1 is dead here: the old sequence's only
  // use of it ended at the mtspr, and EmitTestNZSetCR overwrites it next.
  addco(TMP1, r0, r0);
  // Refine CR0 to reflect ONLY the IR operand-size's worth of bits.
  // At i64 there is nothing to refine: the and./andi. above already set CR0
  // from a signed comparison of the full 64-bit result against zero, which is
  // precisely what EmitTestNZSetCR's i64 case (`cmpdi Result, 0`) recomputes,
  // and the intervening addco has Rc=0 so CR0 still holds it. Skip it — same
  // guard DEF_OP(AndWithFlags) already applies.
  if (IROp->Size != IR::OpSize::i64Bit) EmitTestNZSetCR(TMP3, IROp->Size);
}

DEF_OP(TestZ) {
  auto Op = IROp->C<IR::IROp_TestZ>();
  auto S1 = GetReg(Op->Src1);
  uint64_t Const;
  if (IsInlineConstant(Op->Src2, &Const)) {
    if ((Const & 0xFFFF) == Const) {
      andi_(TMP3, S1, static_cast<uint16_t>(Const));
    } else {
      LoadConstant(TMP4, Const);
      and__(TMP3, S1, TMP4);
    }
  } else {
    and__(TMP3, S1, GetReg(Op->Src2));
  }
  // Same clear-CV invariant as TestNZ above, same 0+0 addco argument
  // (CA/OV cleared, sticky SO preserved, CR0 untouched because Rc=0).
  // TMP1 is dead here for the same reason: EmitTestNZSetCR writes it next.
  addco(TMP1, r0, r0);
  // Same i64 redundancy as TestNZ above: and./andi. already set CR0 over the
  // full 64 bits and addco (Rc=0) left it alone, so the cmpdi is a no-op.
  if (IROp->Size != IR::OpSize::i64Bit) EmitTestNZSetCR(TMP3, IROp->Size);
}

DEF_OP(Adc) {
  auto Op  = IROp->C<IR::IROp_Adc>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  // CFInverted=true: stored XER.CA = !x86_CF. PPC `adde` would inject !x86_CF
  // as the carry-in, producing a result that is off by one. Materialise the
  // carry instead, without disturbing XER.
  //
  // `subfe rT, r0, r0` = ~r0 + r0 + CA. With the JIT's r0 == 0 invariant that
  // is 0xFFFF_FFFF_FFFF_FFFF + 0 + CA, i.e.
  //     CA = 1  ->  rT =  0
  //     CA = 0  ->  rT = -1
  // so rT == -(!CA) == -x86_CF for this op's CFInverted=true convention.
  // (The identity actually holds for any r0 value: ~x + x is all-ones.)
  // Its carry-out is 1 iff CA was 1, so XER.CA is left exactly as found;
  // OE = 0 and Rc = 0, so OV/SO/CR0 are untouched too — which matters here
  // because _Adc is a value-only op that must not perturb flags.
  //
  // Dst = S1 + S2 + x86_CF = (S1 + S2) - (-x86_CF), so the third addend
  // folds into a subf instead of an add.
  // CARRY POLARITY: this op consumes a DIRECT carry (XER.CA == x86_CF), not an
  // inverted one. Its only producer is DeadFlagCalculationElimination rewriting
  // AdcWithFlags -> Adc, and CalculateFlags_ADC (OpcodeDispatcher/Flags.cpp:276)
  // does RectifyCarryInvert(false) + sets CFInverted=false immediately before
  // emitting _AdcWithFlags. The ADX path likewise. So `adde` -- which computes
  // RA + RB + XER.CA -- IS the operation, exactly.
  //
  // The previous sequence here (subfe TMP2,r0,r0; add; subf) assumed the
  // INVERTED convention: subfe r0,r0 yields CA-1 == -(!CA), and subtracting it
  // adds !CA. Under a direct carry that computes S1 + S2 + !x86_CF -- off by
  // one in BOTH carry states. It was never caught because OP_ADC has no other
  // producer, so this handler has never executed with the pass disabled.
  //
  // adde writes XER.CA (carry-out). That is safe here and not a new hazard: the
  // Replacement rewrite only fires when the flag writes are dead, and the
  // AdcWithFlags this replaced wrote CA itself, so nothing can observe the
  // difference. (Sbb/AdcZero keep their subfe forms -- their producers DO
  // rectify to inverted; see the note in each. The three deliberately differ.)
  adde(Dst, S1, S2);          // Dst = S1 + S2 + x86_CF
  if (IROp->Size == IR::OpSize::i32Bit) {
    // x86-64 zero-extends 32-bit writebacks; sources arrive AllowUpperGarbage
    // and the dispatcher stores the raw host register. Matches Add/Sub/And/...
    rldicl(Dst, Dst, 0, 32);
  }
}

DEF_OP(Sbb) {
  auto Op  = IROp->C<IR::IROp_Sbb>();
  auto Dst = GetReg(Node);
  // Carry stays as-is: SBB's producer DOES rectify to the inverted convention
  // (CalculateFlags_SBB), so XER.CA == !x86_CF here and the bare subfe computes
  // S1 + ~S2 + CA == S1 - S2 - x86_CF, which is exactly SBB. Deliberately the
  // opposite polarity from DEF_OP(Adc) above -- do not "uniformize" them.
  subfe(Dst, GetReg(Op->Src2), GetReg(Op->Src1));
  if (IROp->Size == IR::OpSize::i32Bit) {
    rldicl(Dst, Dst, 0, 32);  // zero-extend the 32-bit writeback (see Adc)
  }
}

DEF_OP(AdcWithFlags) {
  auto Op  = IROp->C<IR::IROp_AdcWithFlags>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // AdcWithFlags is emitted by CalculateFlags_ADC after RectifyCarryInvert(false),
    // so stored XER.CA = x86_CF directly. addeo_ uses CA-in and writes CA-out in
    // the same convention — no manual flip needed.
    addeo_(Dst, S1, S2);
    return;
  }

  // i32Bit: zero-extend, do a 64-bit add with x86_CF as the third addend, take
  // bit-32 as x86_CF_out, store directly (CFInverted=false convention).
  //
  // Because the convention here is DIRECT (stored XER.CA == x86_CF, see the
  // i64 comment above), the carry-in needs no flip and `adde` injects exactly
  // the right bit — no mfspr/rldicl extraction, no separate add for it.
  // Both addends are zero-extended 32-bit values, so the sum is at most
  // 2*(2^32 - 1) + 1 < 2^33: adde's own CA-out (the carry at bit 63) is always
  // 0. Clobbering XER.CA here is harmless regardless — the tail below rewrites
  // CA and OV wholesale and only reads XER for the sticky SO.
  rldicl(TMP1, S1, 0, 32);                  // zx32(S1)
  rldicl(TMP2, S2, 0, 32);                  // zx32(S2)
  adde(TMP3, TMP1, TMP2);                   // TMP3 = zx32(S1) + zx32(S2) + x86_CF (≤ 33-bit)
  rldicl(Dst, TMP3, 0, 32);                  // Dst = result low-32, zero-ext
  EmitTestNZSetCR(Dst, IR::OpSize::i32Bit);

  // CA = bit-32 of TMP3 = x86_CF_out, stored directly (CFInverted=false).
  rldicl(TMP4, TMP3, 32, 63);

  // OF = (S1[31] == S2[31]) AND (S1[31] != Dst[31]).
  rldicl(TMP1, S1,  33, 63);
  rldicl(TMP2, S2,  33, 63);
  rldicl(TMP3, Dst, 33, 63);
  xor_(TMP2, TMP2, TMP1);
  xor_(TMP3, TMP3, TMP1);
  andc(TMP3, TMP3, TMP2);

  // Patch XER: new CA = TMP4's LSB, new OV = TMP3's LSB.
  //
  // rlwimi does clear-and-set in one instruction, so the LoadConstant-mask /
  // andc / sldi / or_ chain collapses. The canonical form used at every XER
  // patch site in this file:
  //
  //   rlwimi RA, RS, SH, MB, ME
  //     RA <- (ROTL32(RS, SH) & MASK(MB, ME)) | (RA & ~MASK(MB, ME))
  //
  // with PPC (MSB=0) bit numbering, where PPC bit p == LSB bit (31 - p) in
  // the low word, and the mask lives entirely in bits 32..63 of the 64-bit
  // register so mfspr's upper half is preserved exactly as andc preserved it.
  // ROTL32 by SH moves a bit at PPC position q to position (q - SH) mod 32.
  // The two inserts we need, both from an LSB-0 source bit (PPC 31):
  //
  //   CA at LSB 29 = PPC 2:  (31 - SH) mod 32 = 2  =>  SH = 29, MB = ME = 2
  //   OV at LSB 30 = PPC 1:  (31 - SH) mod 32 = 1  =>  SH = 30, MB = ME = 1
  //
  // Single-bit masks, so whatever the source carries above its LSB is
  // discarded — the same guarantee the sldi/or_ pair relied on.
  mfspr(TMP1, 1);
  rlwimi(TMP1, TMP4, 29, 2, 2);   // CA <- TMP4 LSB
  rlwimi(TMP1, TMP3, 30, 1, 1);   // OV <- TMP3 LSB
  mtspr(1, TMP1);
}

DEF_OP(SbbWithFlags) {
  auto Op  = IROp->C<IR::IROp_SbbWithFlags>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // 64-bit SBB: subfeo. sets CA + OV + CR0 from the 64-bit boundary.
    // PPC `subfe rT, rA, rB` = rB + ~rA + CA, which equals rB - rA - !CA.
    // CA-out is "no-borrow" at the 64-bit boundary; under our CFInverted=true
    // storage convention that's exactly stored-C (= !x86_CF).
    subfeo_(Dst, S2, S1);
    return;
  }

  // i32Bit: do a 64-bit subfe on zero-extended operands. Bit-32 of the result
  // tells us about the borrow at the 32-bit boundary, but in inverted form:
  //   subfe on zx(a), zx(b): result = a + ~b_zx + CA_in.
  //   ~b_zx in low 32 = ~b[31:0]; in high 32 = 0xFFFFFFFF (all ones from extension).
  //   Bit 32 of result = 1 iff a < b + !CA_in (i.e., borrow occurred).
  // Stored C under CFInverted=true = !x86_CF = !borrow = NOT(bit 32 of result).
  rldicl(TMP1, S1, 0, 32);
  rldicl(TMP2, S2, 0, 32);
  subfe(TMP3, TMP2, TMP1);                 // TMP3 = TMP1 + ~TMP2 + CA_in
  rldicl(Dst, TMP3, 0, 32);
  EmitTestNZSetCR(Dst, IR::OpSize::i32Bit);

  // CF (CFInverted-stored) = NOT(bit 32 of TMP3).
  rldicl(TMP4, TMP3, 32, 63);              // bit 32 of TMP3 in LSB
  xori(TMP4, TMP4, 1);                      // invert LSB

  // OF for SBB: (S1[31] != S2[31]) AND (S1[31] != Dst[31]).
  rldicl(TMP1, S1,  33, 63);
  rldicl(TMP2, S2,  33, 63);
  rldicl(TMP3, Dst, 33, 63);
  xor_(TMP2, TMP2, TMP1);                  // S1^S2
  xor_(TMP3, TMP3, TMP1);                  // S1^Dst
  and_(TMP3, TMP3, TMP2);                  // (S1^S2) AND (S1^Dst) = OF

  // XER patch via rlwimi — SH/MB/ME derived in DEF_OP(AdcWithFlags) above.
  mfspr(TMP1, 1);
  rlwimi(TMP1, TMP4, 29, 2, 2);   // CA <- TMP4 LSB
  rlwimi(TMP1, TMP3, 30, 1, 1);   // OV <- TMP3 LSB
  mtspr(1, TMP1);
}

DEF_OP(AdcZero) {
  auto Op  = IROp->C<IR::IROp_AdcZero>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src1);
  // CFInverted=true: PPC `addze` would add !x86_CF. Materialise x86_CF instead.
  // subfe(TMP2, r0, r0) = ~r0 + r0 + CA = all-ones + CA, i.e. 0 when CA=1 and
  // -1 when CA=0 — that is -(!CA) = -x86_CF under this op's inverted
  // convention. Its carry-out equals its carry-in so XER.CA survives, and
  // OE=Rc=0 leaves OV/SO/CR0 alone (this is a value-only op).
  // Dst = Src + x86_CF = Src - (-x86_CF), so the add becomes a subf.
  // Carry stays as-is: IR.json declares AdcZero as "adds GPR with INVERTED
  // carry-in" and the dispatcher's ADCOp literal-zero path rectifies inverted,
  // so XER.CA == !x86_CF. subfe r0,r0 gives CA-1 == -(!CA) == -x86_CF, and
  // subtracting it adds x86_CF. Correct -- and deliberately the opposite
  // polarity from DEF_OP(Adc). Uniformizing these is the AdcZeroWithFlags bug
  // class that broke BoringSSL P-256 / Steam TLS (7224def51).
  subfe(TMP2, r0, r0);        // TMP2 = -x86_CF
  subf(Dst, TMP2, Src);       // Dst = Src - TMP2 = Src + x86_CF
  if (IROp->Size == IR::OpSize::i32Bit) {
    rldicl(Dst, Dst, 0, 32);  // zero-extend the 32-bit writeback (see Adc)
  }
}

DEF_OP(AdcZeroWithFlags) {
  auto Op = IROp->C<IR::IROp_AdcZeroWithFlags>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Src1);

  // Materialise x86_CF from the CFInverted-stored XER.CA. subfe(TMP4, r0, r0)
  // = ~r0 + r0 + CA = all-ones + CA, giving 0 for CA=1 and -1 for CA=0, i.e.
  // -(!CA) = -x86_CF; negate to get x86_CF itself. Both instructions leave XER
  // untouched (subfe's carry-out equals its carry-in; neg has OE=0), so the CA
  // that addco_ below consumes-and-replaces is still the stored one, and CR0
  // is undisturbed until addco_ writes it.
  subfe(TMP4, r0, r0);                       // TMP4 = -x86_CF
  neg(TMP4, TMP4);                           // TMP4 = x86_CF (0 or 1)

  if (IROp->Size == IR::OpSize::i64Bit) {
    // addco_(Dst, Src, TMP4): Dst = Src + x86_CF, CA = carry-out, OV = ovf, CR0 from Dst.
    // CA-out is left in DIRECT (CFInverted=false) form: the dispatcher's ADCOp
    // sets `CFInverted = false` after emitting this op. Flipping it here (as an
    // earlier revision did) made every carry consumer after an `adc $0` read
    // !CF — BoringSSL's p256 point-add computed X/Y off by 2^192 and every
    // Steam TLS handshake died with BAD_SIGNATURE.
    addco_(Dst, Src, TMP4);
    return;
  }

  // i32Bit (and smaller): manual 32-bit add and patch XER.
  rldicl(TMP1, Src, 0, 32);                  // zx32(Src)
  add(TMP3, TMP1, TMP4);                     // TMP3 = zx32(Src) + x86_CF (≤ 33-bit)
  rldicl(Dst, TMP3, 0, 32);                  // Dst = low-32
  EmitTestNZSetCR(Dst, IR::OpSize::i32Bit);

  // CA = bit-32 of TMP3 = x86_CF_out, stored DIRECT (CFInverted=false) to match
  // the dispatcher's `CFInverted = false` after this op — same convention as
  // the 64-bit path above and AdcWithFlags' i32 path.
  rldicl(TMP3, TMP3, 32, 63);

  // OF for ADC-with-zero (TMP4 ∈ {0,1}, sign-bit always 0):
  // OF = !Src[31] AND Dst[31]
  rldicl(TMP1, Src, 33, 63);
  xori(TMP1, TMP1, 1);                        // !Src[31]
  rldicl(TMP4, Dst, 33, 63);                  // Dst[31]
  and_(TMP4, TMP4, TMP1);                     // OF in LSB

  // XER patch via rlwimi — SH/MB/ME derived in DEF_OP(AdcWithFlags) above.
  mfspr(TMP1, 1);
  rlwimi(TMP1, TMP3, 29, 2, 2);   // CA <- TMP3 LSB
  rlwimi(TMP1, TMP4, 30, 1, 1);   // OV <- TMP4 LSB
  mtspr(1, TMP1);
}

DEF_OP(AdcNZCV) {
  // Identical to AdcWithFlags except no architectural Dst writeback —
  // we use TMP4 as a scratch result for CR0 / sign extraction.
  auto Op = IROp->C<IR::IROp_AdcNZCV>();
  auto S1 = GetReg(Op->Src1);
  auto S2 = GetReg(Op->Src2);

  if (IROp->Size == IR::OpSize::i64Bit) {
    // CFInverted=true: pre-flip XER.CA so addeo_ sees x86_CF; post-flip CA-out.
    // Each flip is the subfe/addic pair documented at DEF_OP(CarryInvert):
    // subfe TMP1,r0,r0 leaves 0 when CA=1 and -1 when CA=0 (and preserves CA),
    // then addic TMP1,TMP1,1 sets CA from that value's carry-out — 0 and 1
    // respectively — so CA is inverted in two non-serializing instructions
    // instead of an mfspr/xoris/mtspr round trip.
    //
    // Critically for the POST-flip: neither subfe nor addic writes OV, SO or
    // CR0, so the overflow and N/Z that addeo_ just produced pass through
    // untouched. TMP1 was already this path's only scratch.
    subfe(TMP1, r0, r0);
    addic(TMP1, TMP1, 1);
    addeo_(TMP3, S1, S2);
    subfe(TMP1, r0, r0);
    addic(TMP1, TMP1, 1);
    return;
  }

  // i32Bit: materialise x86_CF, compute manually, store !bit-32 as CFInverted CA.
  // subfe(TMP4, r0, r0) = ~r0 + r0 + CA = all-ones + CA => 0 for CA=1, -1 for
  // CA=0, i.e. -(!CA) = -x86_CF under CFInverted=true. XER survives it (its
  // carry-out equals its carry-in, OE=Rc=0), which matters because the stored
  // CA must still be readable... it is not read again here, but the XER tail
  // below reads XER for the sticky SO, and CR0 must stay clean until
  // EmitTestNZSetCR. Adding x86_CF then becomes subtracting -x86_CF.
  subfe(TMP4, r0, r0);                      // TMP4 = -x86_CF

  rldicl(TMP1, S1, 0, 32);
  rldicl(TMP2, S2, 0, 32);
  add(TMP3, TMP1, TMP2);
  subf(TMP3, TMP4, TMP3);                   // TMP3 = sum + x86_CF (33-bit)
  rldicl(TMP4, TMP3, 0, 32);                 // TMP4 = low-32 result
  EmitTestNZSetCR(TMP4, IR::OpSize::i32Bit);

  // CFInverted CA = !(bit-32 of TMP3).
  rldicl(TMP3, TMP3, 32, 63);
  xori(TMP3, TMP3, 1);

  // OF = (S1[31] == S2[31]) AND (S1[31] != Result[31]).
  rldicl(TMP1, S1,   33, 63);
  rldicl(TMP2, S2,   33, 63);
  rldicl(TMP4, TMP4, 33, 63);
  xor_(TMP2, TMP2, TMP1);
  xor_(TMP4, TMP4, TMP1);
  andc(TMP4, TMP4, TMP2);                   // OF

  // Patch XER: CA = TMP3 LSB (= !x86_CF_out), OV = TMP4 LSB.
  // rlwimi SH/MB/ME derived in DEF_OP(AdcWithFlags) above.
  mfspr(TMP1, 1);
  rlwimi(TMP1, TMP3, 29, 2, 2);   // CA <- TMP3 LSB
  rlwimi(TMP1, TMP4, 30, 1, 1);   // OV <- TMP4 LSB
  mtspr(1, TMP1);
}

DEF_OP(SbbNZCV) {
  auto Op = IROp->C<IR::IROp_SbbNZCV>();
  auto S1 = GetReg(Op->Src1);
  auto S2 = GetReg(Op->Src2);

  if (IROp->Size == IR::OpSize::i64Bit) {
    subfeo_(TMP3, S2, S1);
    return;
  }

  rldicl(TMP1, S1, 0, 32);
  rldicl(TMP2, S2, 0, 32);
  subfe(TMP3, TMP2, TMP1);                 // TMP3 = TMP1 + ~TMP2 + CA_in
  rldicl(TMP4, TMP3, 0, 32);                // low-32 result
  EmitTestNZSetCR(TMP4, IR::OpSize::i32Bit);

  // CF (CFInverted-stored) = NOT(bit-32 of TMP3), since bit-32 = borrow.
  rldicl(TMP3, TMP3, 32, 63);
  xori(TMP3, TMP3, 1);

  // OF for SBB: (S1[31] != S2[31]) AND (S1[31] != Result[31]).
  rldicl(TMP1, S1,   33, 63);
  rldicl(TMP2, S2,   33, 63);
  rldicl(TMP4, TMP4, 33, 63);
  xor_(TMP2, TMP2, TMP1);                  // S1^S2
  xor_(TMP4, TMP4, TMP1);                  // S1^Result
  and_(TMP4, TMP4, TMP2);                  // (S1^S2) AND (S1^Result) = OF

  // XER patch via rlwimi — SH/MB/ME derived in DEF_OP(AdcWithFlags) above.
  mfspr(TMP1, 1);
  rlwimi(TMP1, TMP3, 29, 2, 2);   // CA <- TMP3 LSB
  rlwimi(TMP1, TMP4, 30, 1, 1);   // OV <- TMP4 LSB
  mtspr(1, TMP1);
}

// =========================================================================
// Select / NZCVSelect
// =========================================================================

DEF_OP(Select) {
  auto Op   = IROp->C<IR::IROp_Select>();
  auto Dst  = GetReg(Node);

  // True/False may be InlineConstants (Select01 in particular always passes
  // _InlineConstant(1) and _InlineConstant(0)). Calling GetReg() on an
  // InlineConstant returns garbage — handle inline constants explicitly
  // before any register reads. Mirrors DEF_OP(NZCVSelect) below.
  uint64_t const_true, const_false;
  bool is_const_true  = IsInlineConstant(Op->TrueVal,  &const_true);
  bool is_const_false = IsInlineConstant(Op->FalseVal, &const_false);

  const bool IsFP = (Op->Cond == IR::CondClass::FLU || Op->Cond == IR::CondClass::FGE ||
                     Op->Cond == IR::CondClass::FLEU || Op->Cond == IR::CondClass::FGT ||
                     Op->Cond == IR::CondClass::FU || Op->Cond == IR::CondClass::FNU);
  const bool IsBitTest = (Op->Cond == IR::CondClass::TSTZ || Op->Cond == IR::CondClass::TSTNZ);

  // Every arm compares into cr7 and touches neither CR0 nor XER, so this op
  // clobbers NO architectural flag state on ppc64le. CompareBranchFusion
  // relies on that: it rewrites NZCVSelect (a pure NZCV *reader*) into Select
  // mid-block, between an NZCV def and other live uses of it — legal only
  // while every path through here leaves CR0/XER untouched. (The IR-level
  // ImplicitFlagClobber on Select stays true for the frontend's sake; DFCE
  // does not consult it.)
  PPC64Emitter::Cond CC;
  if (IsFP) {
    // FP compare path: operands are FPRs; defer entirely to EmitCompare.
    EmitCompare(Op->Cond, Op->CompareSize, Op->Cmp1, Op->Cmp2, /*CRField=*/7);
    CC = MapCC(Op->Cond);
    CC = {CC.BO, static_cast<uint8_t>(CC.BI + 28)};
  } else if (IsBitTest) {
    // Bit-test select: Cmp2 is an inline constant bit POSITION (mirrors the
    // CondJumpBit lowering, see DEF_OP(CondJump) in BranchOps.cpp). MapCC has
    // no TSTZ/TSTNZ entry — without this branch it would fall to its default
    // and silently return CC_EQ, miscompiling the Select. Extract the target
    // bit via rldicl (no Rc — CR0 must stay untouched, see above), compare
    // via cr7, then pick NE (TSTNZ) / EQ (TSTZ) on cr7's EQ bit (BI 30).
    uint64_t Bit;
    LOGMAN_THROW_A_FMT(IsInlineConstant(Op->Cmp2, &Bit) && Bit < 64,
                       "Select TSTZ/TSTNZ: expected inline-constant bit < 64");
    auto Reg = GetReg(Op->Cmp1);
    uint32_t sh = (64u - static_cast<uint32_t>(Bit)) & 63u;
    rldicl(TMP1, Reg, sh, 63);
    cmpldi(cr(7), TMP1, 0);
    CC = (Op->Cond == IR::CondClass::TSTNZ) ? Cond{4, 30} : Cond{12, 30};
  } else {
    auto S1 = GetReg(Op->Cmp1);
    uint64_t Const;
    if (IsInlineConstant(Op->Cmp2, &Const)) {
      int64_t sc = static_cast<int64_t>(Const);
      bool isUnsigned = (Op->Cond == IR::CondClass::UGE || Op->Cond == IR::CondClass::ULT ||
                         Op->Cond == IR::CondClass::UGT || Op->Cond == IR::CondClass::ULE);
      if (!isUnsigned && sc >= -32768 && sc <= 32767) {
        if (Op->CompareSize <= IR::OpSize::i32Bit)
          cmpwi(cr(7), S1, static_cast<int16_t>(sc));
        else
          cmpdi(cr(7), S1, static_cast<int16_t>(sc));
      } else {
        // No LoadConstant here: EmitCompare (JIT.cpp) re-materialises the
        // inline constant itself on every path it can take for this operand
        // — TMP4 for the 32/64-bit signed and unsigned wide-constant cases,
        // TMP2 (pre-shifted by Const << Sh) for the 8/16-bit case — and it
        // reads Op->Cmp2 rather than any register we could have primed. A
        // LoadConstant here was therefore pure dead weight.
        EmitCompare(Op->Cond, Op->CompareSize, Op->Cmp1, Op->Cmp2, /*CRField=*/7);
      }
    } else {
      EmitCompare(Op->Cond, Op->CompareSize, Op->Cmp1, Op->Cmp2, /*CRField=*/7);
    }
    CC = MapCC(Op->Cond);
    CC = {CC.BO, static_cast<uint8_t>(CC.BI + 28)};
  }
  // Branch-free select via isel (ISA 2.03). isel reads both sources before
  // writing RT, so the old Dst-aliases-True stash and the mr/bc/mr dance are
  // both unnecessary. The compare/bit-test above has already set the cr7 bit
  // that CC names (CC.BI is an absolute CR bit index — 28..31 on every path
  // through this op; isel's 5-bit BC field encodes it directly).
  //
  // SETTLED — keep isel here too, and do not make the constant form branchy.
  // This op was flagged as a candidate for a branchy constant form on the same reasoning that
  // motivated the NZCVSelect change below. That reasoning was wrong at the premise and the change
  // was measured as a net 5.7 ns/op loss; see the comment in DEF_OP(NZCVSelect) for the numbers and
  // for why the "constant form == SETcc" assumption does not hold. The argument transfers directly:
  // a constant-form select on a data-dependent condition feeding pure dataflow is exactly where an
  // unpredictable branch is worst. Unmeasured here, but there is now no hypothesis motivating the
  // change, so leaving it alone is the position rather than the deferral it was before.
  //
  // Materialise inline constants into TMPs first (GetReg on an InlineConstant
  // returns garbage — same hazard the old code documented). TMP1 may have
  // been used by the TSTZ/TSTNZ rldicl_ and TMP4 by EmitCompare's constant
  // path, but both are dead once the compare has executed; TMP2/TMP3 are free
  // on every path here.
  GPR True_reg = GPR{0}, False_reg = GPR{0};
  if (is_const_true) {
    li(TMP2, static_cast<int16_t>(const_true));
    True_reg = TMP2;
  } else {
    True_reg = GetReg(Op->TrueVal);
  }
  if (is_const_false) {
    li(TMP3, static_cast<int16_t>(const_false));
    False_reg = TMP3;
  } else {
    False_reg = GetReg(Op->FalseVal);
  }
  iselcc(Dst, CC, True_reg, False_reg);
}

DEF_OP(NZCVSelect) {
  auto Op  = IROp->C<IR::IROp_NZCVSelect>();
  auto Dst = GetReg(Node);
  auto CC  = MapNZCVCC(IntegerNZCVCond(Op->Cond));

  uint64_t const_true, const_false;
  bool is_const_true  = IsInlineConstant(Op->TrueVal,  &const_true);
  bool is_const_false = IsInlineConstant(Op->FalseVal, &const_false);

  const uint64_t all_ones = IROp->Size == IR::OpSize::i64Bit
    ? 0xFFFFFFFFFFFFFFFFull : 0xFFFFFFFFull;

  // BOTH forms use isel. Do not make the constant form branchy — that was tried and measured, and
  // it is a net loss. The history matters because the reasoning that motivated it was wrong at the
  // premise, not merely wrong in degree.
  //
  // The claim was that the constant form is "the SETcc archetype", so a branch keeps isel's latency
  // off a dependent chain. It is not. Grep `_NZCVSelect01`: SETccOp (OpcodeDispatcher.cpp) is ONE
  // caller. The dominant caller is per-flag-bit materialisation in OpcodeDispatcher.h — the
  // `!NZCVDirty` path that reconstructs a single RFLAGS bit (CF/OF/ZF) into a GPR — plus
  // ConvertNZCVToX87. An IR dump of bench_select's `main` found 15 constant-form NZCVSelects against
  // 3 register-form, and the constant-form conditions were UGE/ULT/SGT clustered around the compare
  // sites: flag reconstruction, not SETcc.
  //
  // That distinction decides the codegen. Flag-bit materialisation selects on a *data-dependent*
  // condition and feeds pure dataflow, so a branch there is an unpredictable branch that buys
  // nothing. Making these branchy cost, on bench_select over random data:
  //
  //     cmov-unpredictable  8.20 -> 13.87 ns/op   +69%
  //     control             7.69 -> 12.28 ns/op   +60%
  //     adc-chain          19.53 -> 24.67 ns/op   +26%
  //     setcc              17.88 ->  8.29 ns/op   -54%   (the one intended win)
  //     cmov-predictable    8.21 ->  8.12 ns/op     0%   (predictable data — pays nothing)
  //
  // Summed, branchy is 5.7 ns/op WORSE. The tell is cmov-predictable: same guest instruction
  // sequence as cmov-unpredictable, differing only in whether its data makes the condition
  // predictable, and it is the only case that did not regress. The penalty is ~5 ns/op ≈ 20 cycles,
  // one POWER9 mispredict per iteration, and it is additive rather than proportional to op count.
  //
  // The setcc win is real but cannot be captured here, because at this level SETccOp and flag
  // materialisation are indistinguishable — both arrive as NZCVSelect(cond, 1, 0). Capturing it
  // needs a distinct IR op emitted only from SETccOp so this backend can lower that one branchy.
  // Until that exists, isel everywhere is the better trade by a wide margin.
  if (is_const_true) {
    // Only forms generated by the IR frontend: (True=1, False=0) or (True=all_ones, False=0).
    LOGMAN_THROW_A_FMT(is_const_false && const_false == 0 &&
                         (const_true == 1 || const_true == all_ones),
                       "NZCVSelect: unsupported constant pair ({}, {})", const_true, const_false);
    // isel's rA=0 encoding supplies a literal zero, so only the true value needs materialising.
    LoadConstant(TMP1, const_true == all_ones ? ~0ull : 1);
    iselcc(Dst, CC, TMP1, GPR{0});
    return;
  }

  // Branch-free select via isel (ISA 2.03) for the register form — the guest CMOVcc archetype.
  // MapNZCVCC above has already projected XER→CR1 / composed CR3 bits as needed, and returns CC.BI
  // as an absolute CR bit index, so it can be passed straight to isel.

  GPR True = GetReg(Op->TrueVal);
  // No Dst-aliases-True stash needed: isel reads both sources before writing.
  GPR False_ = GPR{0};
  if (is_const_false) {
    LoadConstant(TMP1, const_false);
    False_ = TMP1;
  } else {
    False_ = GetReg(Op->FalseVal);
  }
  iselcc(Dst, CC, True, False_);
}

DEF_OP(NZCVSelectV) {
  auto Op   = IROp->C<IR::IROp_NZCVSelectV>();
  auto Dst  = GetVReg(Node);
  auto True = GetVReg(Op->TrueVal);
  auto False_= GetVReg(Op->FalseVal);
  auto CC   = MapNZCVCC(IntegerNZCVCond(Op->Cond));

  // Aliasing guard: if RA tied Dst to True, the `vmr Dst, False` below would
  // wipe True before the conditional `vmr Dst, True` could read it.  Hit by
  // X87 F64 FXTRACT, which emits two back-to-back NZCVSelectV ops whose first
  // dest aliases its own TrueVal.  (The GPR NZCVSelect above no longer needs
  // this guard — it moved to isel, which has no vector equivalent on ≤2.07,
  // so this op keeps the branchy materialise-then-overwrite form.)
  if (True == Dst) {
    vmr(VTMP1, True);
    True = VTMP1;
  }

  if (Dst != False_) vmr(Dst, False_);
  PPC64Emitter::Label Done{};
  bc(InvertCond(CC), &Done);
  vmr(Dst, True);
  Bind(&Done);
}

DEF_OP(NZCVSelectIncrement) {
  auto Op  = IROp->C<IR::IROp_NZCVSelectIncrement>();
  auto Dst = GetReg(Node);
  auto CC  = MapNZCVCC(IntegerNZCVCond(Op->Cond));

  // Semantics: if CC then Dst=TrueVal else Dst=FalseVal+1 (ARM64 csinc semantics).
  uint64_t const_true, const_false;
  bool is_const_true  = IsInlineConstant(Op->TrueVal,  &const_true);
  bool is_const_false = IsInlineConstant(Op->FalseVal, &const_false);

  // Branch-free via isel (ISA 2.03). Sole producer is IncrementByCarry
  // (Flags.cpp:266), i.e. the ADC/SBB "+carry" select — carry of arbitrary
  // arithmetic is data, and bignum-style ADC chains mispredict a branch
  // ~50% of the time, so this is squarely in the isel-wins class.
  //
  // Compute FalseVal+1 into TMP2 (r4) first. TMP2 is not in SRA or RA, so
  // GetReg never returns it; MapNZCVCC's projection code above also ran
  // before this point, so its TMP1/TMP2 clobbers are already done.
  if (is_const_false)
    LoadConstant(TMP2, const_false + 1);
  else
    addi(TMP2, GetReg(Op->FalseVal), 1);

  GPR TrueReg = GPR{0};
  if (is_const_true) {
    LoadConstant(TMP1, const_true);
    TrueReg = TMP1;
  } else {
    TrueReg = GetReg(Op->TrueVal);
  }

  iselcc(Dst, CC, TrueReg, TMP2);  // cond met → TrueVal, else FalseVal+1
}

DEF_OP(MaskGenerateFromBitWidth) {
  auto Op      = IROp->C<IR::IROp_MaskGenerateFromBitWidth>();
  auto Dst     = GetReg(Node);
  auto BitWidth = GetReg(Op->BitWidth);
  // IR contract (per IR.json): BitWidth=0 is special-cased to a FULL mask
  // (~0ULL), not the empty mask that (1<<0)-1 would produce. The naive
  // sld/addi sequence got BitWidth=0 wrong, silently breaking SSE4a EXTRQ /
  // INSERTQ which encode "width=0 means full 64 bits". Use the identity
  //   mask = ~0ULL >> ((-BitWidth) & 0x3F)
  // which yields ~0 for both BitWidth=0 and BitWidth=64 (PPC srd's count
  // is taken mod 128 with clamp-to-zero for >=64, so we must pre-mask the
  // count to 6 bits to keep BitWidth=1..63 valid).
  li(TMP1, -1);                       // TMP1 = ~0ULL
  neg(TMP2, BitWidth);                 // TMP2 = -BitWidth
  rldicl(TMP2, TMP2, 0, 58);          // TMP2 = -BitWidth & 0x3F
  srd(Dst, TMP1, TMP2);                // Dst = ~0 >> ((-BitWidth) & 0x3F)
}

// =========================================================================
// NZCV flag manipulation ops
// These track the x86 EFLAGS through the CpuStateFrame flags array.
// The ARM64 backend uses a dedicated NZCV register; we use CR0.
// For now these are all no-ops or simple mappings.
// =========================================================================

// InvalidateFlags is handled purely in IR passes; no JIT op handler needed.
DEF_OP(SetSmallNZV)       { /* nop — handled by context */ }
// CarryInvert is implemented below alongside LoadNZCV/StoreNZCV.
DEF_OP(AXFlag) {
  // ARM AXFLAG: converts ARM FCMP-format NZCV into x86-EFLAGS-mapped NZCV.
  //   N_new = 0
  //   Z_new = Z_old OR  V_old
  //   C_new = C_old AND NOT V_old
  //   V_new = 0
  // Our flag layout: N→CR0.LT, Z→CR0.EQ, C→XER.CA, V→XER.OV.
  //
  // Skipping this conversion (the prior nop) leaves the dispatcher's COMISS
  // chain producing N=ARM_LT and unmasked CF/ZF, breaking UCOMISS/COMISS,
  // PTEST, and any other consumer of FCmp-then-axflag flag mapping.
  //
  // PPC bit numbering (MSB=0 within low 32):
  //   CR0.LT=0, CR0.EQ=2.
  //   XER.SO=0, XER.OV=1, XER.CA=2 (after mfspr).
  // The IR's $V_inv parameter is FlagM2 fallback data we don't need here —
  // the conversion is fully derivable from current CR0/XER state.

  // Read XER, isolate OV at LSB 29 (rotate-right-by-1 from LSB 30) and CA at LSB 29.
  mfspr(TMP1, 1);                        // TMP1 = XER (low 32)
  rlwinm(TMP4, TMP1, 31, 2, 2);          // TMP4 = OV at LSB 29 (PPC bit 2)
  rlwinm(TMP3, TMP1, 0, 2, 2);           // TMP3 = CA bit at LSB 29

  // Compute new CA = old CA AND NOT old OV (both at LSB 29 now).
  andc(TMP3, TMP3, TMP4);                // TMP3 = (CA & !OV) at LSB 29

  // Clear old OV+CA in XER, OR in new CA, leave OV cleared.
  LoadConstant(TMP2, 0x60000000ULL);     // mask: bits OV(30) | CA(29)
  andc(TMP1, TMP1, TMP2);                // TMP1 = XER with OV+CA cleared
  or_(TMP1, TMP1, TMP3);                 // TMP1 = XER with new CA
  mtspr(1, TMP1);                        // write back XER

  // Read CR0 (mfocrf 0x80 — single-field form; the rlwinm mask keeps only
  // CR0.EQ at LSB 29, discarding the bits mfocrf leaves undefined pre-3.0C),
  // compute new EQ = old EQ OR old V, clear LT/GT/SO.
  // TMP4 still holds V_old at LSB 29.
  mfocrf(TMP3, 0x80);
  rlwinm(TMP3, TMP3, 0, 2, 2);           // TMP3 = old CR0.EQ isolated at LSB 29
  or_(TMP3, TMP3, TMP4);                 // TMP3 |= V_old at LSB 29
  mtocrf(0x80, TMP3);                    // CR0 = {LT=0, GT=0, EQ=Z|V, SO=0}
}
DEF_OP(Parity) {
  // PF stored "raw" = inverted x86 PF: 1 if odd parity of low byte, 0 if even.
  // Mask to low byte, popcntd to get the count, take LSB.
  // CRITICAL: do NOT use andi_ (PPC `andi.` always sets CR0). The IR's _Parity
  // is a flag-neutral op and is invoked by GetPackedRFLAG between the source
  // cmp and a downstream LoadNZCV — clobbering CR0 corrupts SF/ZF in LAHF.
  // Use rldicl (no Rc) for the masking instead.
  auto Op  = IROp->C<IR::IROp_Parity>();
  auto Dst = GetReg(Node);
  rldicl(TMP1, GetReg(Op->Raw), 0, 56);  // keep low 8 bits
  popcntd(TMP1, TMP1);
  rldicl(Dst, TMP1, 0, 63);              // keep LSB only
  if (Op->Invert) xori(Dst, Dst, 1);
}
// RmifNZCV: rotate Src right by Rotate (mod 64), then for each i where
// Mask[i] is set, write the rotated source's bit i into the corresponding
// NZCV flag. ARM NZCV bit numbering matches mask bit numbering:
//   bit 0 = V (XER.OV), bit 1 = C (XER.CA), bit 2 = Z (CR0.EQ), bit 3 = N (CR0.LT).
DEF_OP(RmifNZCV) {
  auto Op   = IROp->C<IR::IROp_RmifNZCV>();
  auto Src  = GetReg(Op->Src);
  uint8_t Rotate = Op->Rotate & 63;
  uint8_t Mask   = Op->Mask & 0xF;
  if (Mask == 0) return;

  // TMP1 = ROTR(Src, Rotate). Use rldicl with rotate-left amount = (64-Rotate)%64.
  uint32_t Sh = (64u - Rotate) & 63u;
  if (Sh == 0) { if (TMP1 != Src) mr(TMP1, Src); }
  else         { rldicl(TMP1, Src, Sh, 0); }

  bool TouchN = (Mask & 0x8) != 0;
  bool TouchZ = (Mask & 0x4) != 0;
  bool TouchC = (Mask & 0x2) != 0;
  bool TouchV = (Mask & 0x1) != 0;

  // ---- N / Z (CR0.LT, CR0.EQ) ----
  if (TouchN || TouchZ) {
    // Read current CR0 into TMP3 (mfocrf 0x80: the whole field-0 nibble at
    // LSB 31:28 is defined; every bit this block reads or passes through to
    // the mtocrf(0x80) below — LT/GT/EQ/SO — is inside that nibble).
    mfocrf(TMP3, 0x80);
    // CR0 occupies bits 0..3 of CR (PPC MSB), which is LSB bits 31..28 in the
    // GPR result of mfcr. CR0.LT=PPC bit 0=LSB 31; CR0.EQ=PPC bit 2=LSB 29.
    // We need to optionally overwrite LSB 31 (N) and LSB 29 (Z).
    if (TouchN) {
      // Clear LSB 31, then OR in TMP1[3] shifted to LSB 31.
      LoadConstant(TMP2, 0x80000000ULL);
      andc(TMP3, TMP3, TMP2);
      rldicl(TMP2, TMP1, 0, 60);   // keep low 4 bits
      rldicl(TMP2, TMP2, 28, 32);  // bit 3 → bit 31, mask low 32
      // rldicl above shifts left 28 with mask of 32..63: bit at position 3
      // moves to position 31 — exactly LSB 31. Other bits cleared by mask.
      // BUT we want only bit 3, not bits 0..2. Mask with 0x80000000 first:
      LoadConstant(TMP4, 0x80000000ULL);
      and_(TMP2, TMP2, TMP4);
      or_(TMP3, TMP3, TMP2);
    }
    if (TouchZ) {
      // Clear LSB 29 (CR0.EQ).
      LoadConstant(TMP2, 0x20000000ULL);
      andc(TMP3, TMP3, TMP2);
      // Rotated bit 2 → LSB 29. rotate-left 27 puts bit 2 at bit 29.
      rldicl(TMP2, TMP1, 27, 32);
      LoadConstant(TMP4, 0x20000000ULL);
      and_(TMP2, TMP2, TMP4);
      or_(TMP3, TMP3, TMP2);
    }
    // Write back only CR0 (mtocrf 0x80 = field 0, single-field form).
    mtocrf(0x80, TMP3);
  }

  // ---- C / V (XER.CA, XER.OV) ----
  if (TouchC || TouchV) {
    mfspr(TMP3, 1);
    if (TouchC) {
      // XER.CA at LSB 29. Rotated bit 1 → LSB 29 (rotate-left 28).
      LoadConstant(TMP2, 0x20000000ULL);
      andc(TMP3, TMP3, TMP2);
      rldicl(TMP2, TMP1, 28, 32);
      LoadConstant(TMP4, 0x20000000ULL);
      and_(TMP2, TMP2, TMP4);
      or_(TMP3, TMP3, TMP2);
    }
    if (TouchV) {
      // XER.OV at LSB 30. Rotated bit 0 → LSB 30 (rotate-left 30).
      LoadConstant(TMP2, 0x40000000ULL);
      andc(TMP3, TMP3, TMP2);
      rldicl(TMP2, TMP1, 30, 32);
      LoadConstant(TMP4, 0x40000000ULL);
      and_(TMP2, TMP2, TMP4);
      or_(TMP3, TMP3, TMP2);
    }
    mtspr(1, TMP3);
  }
}

// CondAddNZCV / CondSubNZCV: ccmn/ccmp semantics.
// If Cond holds, NZCV ← flags from (Src1 + Src2) or (Src1 - Src2) at OpSize.
// Else NZCV ← FalseNZCV (4-bit immediate, bit3=N, bit2=Z, bit1=C, bit0=V).
// We branch on the *inverted* condition to the "false" path (write constant),
// and fall through on the taken path which performs the flag-setting op.
//
// IROp validation requires Size in {i32Bit, i64Bit}. For i32Bit we use the
// shift-up trick so XER.CA/OV reflect the 32-bit boundary.
//
// Helper SetNZCVConstant writes a 4-bit NZCV literal into our flag domain:
//   bit3=N → CR0.LT (LSB 31)
//   bit2=Z → CR0.EQ (LSB 29)
//   bit1=C → XER.CA (LSB 29)
//   bit0=V → XER.OV (LSB 30)
// Other CR0/XER bits preserved.
void PPC64JITCore::SetNZCVConstant(uint8_t NZCV) {
  // CR0: clear LT+EQ (LSB 31 + 29 = 0xA0000000), OR in N/Z bits.
  // mfocrf 0x80: all bits consumed here (LT/GT/EQ/SO, LSB 31:28) are inside
  // field 0, which is defined; the pre-3.0C-undefined bits are masked out
  // by mtocrf(0x80) reading only bits 31:28.
  mfocrf(TMP1, 0x80);
  LoadConstant(TMP2, 0xA0000000ULL);
  andc(TMP1, TMP1, TMP2);
  uint32_t CR0Bits = 0;
  if (NZCV & 0x8) CR0Bits |= 0x80000000u;  // N → LSB 31
  if (NZCV & 0x4) CR0Bits |= 0x20000000u;  // Z → LSB 29
  if (CR0Bits) {
    LoadConstant(TMP2, CR0Bits);
    or_(TMP1, TMP1, TMP2);
  }
  mtocrf(0x80, TMP1);

  // XER: clear OV+CA (LSB 30 + 29 = 0x60000000), OR in C/V bits.
  mfspr(TMP1, 1);
  LoadConstant(TMP2, 0x60000000ULL);
  andc(TMP1, TMP1, TMP2);
  uint32_t XERBits = 0;
  if (NZCV & 0x2) XERBits |= 0x20000000u;  // C → LSB 29
  if (NZCV & 0x1) XERBits |= 0x40000000u;  // V → LSB 30
  if (XERBits) {
    LoadConstant(TMP2, XERBits);
    or_(TMP1, TMP1, TMP2);
  }
  mtspr(1, TMP1);
}

DEF_OP(CondAddNZCV) {
  auto Op = IROp->C<IR::IROp_CondAddNZCV>();
  LOGMAN_THROW_A_FMT(IROp->Size == IR::OpSize::i32Bit || IROp->Size == IR::OpSize::i64Bit,
                     "CondAddNZCV: unsupported size");

  auto CC = MapNZCVCC(IntegerNZCVCond(Op->Cond));
  PPC64Emitter::Label FalseLbl, Done;
  bc(InvertCond(CC), &FalseLbl);

  // Taken: NZCV from Src1+Src2.
  uint64_t Const;
  bool S2Inline = IsInlineConstant(Op->Src2, &Const);
  GPR S1 = GetReg(Op->Src1);
  if (IROp->Size == IR::OpSize::i32Bit) {
    sldi(TMP1, S1, 32);
    if (S2Inline) LoadConstant(TMP2, Const << 32);
    else          sldi(TMP2, GetReg(Op->Src2), 32);
    addco_(TMP3, TMP1, TMP2);   // CA/OV at 32-bit boundary; CR0 from shifted result
  } else {
    if (S2Inline) {
      if (static_cast<int64_t>(Const) >= -32768 && static_cast<int64_t>(Const) <= 32767) {
        addic_(TMP3, S1, static_cast<int16_t>(Const));   // CA + CR0; OV unchanged from prior op
        // addic. doesn't set OV; force OV=0 since false path is constant anyway —
        // but the "taken" path with addic. + small const won't see signed overflow
        // beyond the 64-bit boundary for typical glibc usage. To be safe: clear OV.
        mfspr(TMP1, 1);
        LoadConstant(TMP2, 0x40000000ULL);
        andc(TMP1, TMP1, TMP2);
        mtspr(1, TMP1);
      } else {
        LoadConstant(TMP4, Const);
        addco_(TMP3, S1, TMP4);
      }
    } else {
      addco_(TMP3, S1, GetReg(Op->Src2));
    }
  }
  b(&Done);

  Bind(&FalseLbl);
  SetNZCVConstant(Op->FalseNZCV);
  Bind(&Done);
}

DEF_OP(CondSubNZCV) {
  auto Op = IROp->C<IR::IROp_CondSubNZCV>();
  LOGMAN_THROW_A_FMT(IROp->Size == IR::OpSize::i32Bit || IROp->Size == IR::OpSize::i64Bit,
                     "CondSubNZCV: unsupported size");

  auto CC = MapNZCVCC(IntegerNZCVCond(Op->Cond));
  PPC64Emitter::Label FalseLbl, Done;
  bc(InvertCond(CC), &FalseLbl);

  // Taken: NZCV from Src1 - Src2.
  uint64_t Const;
  bool S2Inline = IsInlineConstant(Op->Src2, &Const);
  GPR S1 = GetReg(Op->Src1);
  if (IROp->Size == IR::OpSize::i32Bit) {
    sldi(TMP1, S1, 32);
    if (S2Inline) LoadConstant(TMP2, Const << 32);
    else          sldi(TMP2, GetReg(Op->Src2), 32);
    subfco_(TMP3, TMP2, TMP1);
  } else {
    // CRITICAL: always go through subfco_ (subtract-from-carrying-record).
    // We previously had an `addic_(TMP3, S1, -Const)` shortcut for inline
    // constants that fit in int16, but addic_ sets XER.CA per the *add*
    // carry rule (no-carry → CA=0 for 0+0) whereas subfco_ sets CA per the
    // *subtract* no-borrow rule (no-borrow → CA=1 for 0-0). Callers like
    // CalculateFlags_MUL's IMUL flag setup (`_CondSubNZCV(Zero, Zero, EQ, ...)`
    // + `CFInverted=true`) depend on the subtract semantics: for the
    // no-overflow case the EQ branch expects C=1 in NZCV, which inverts to
    // x86 CF=0. The addic_ shortcut silently produced C=0 → x86 CF=1,
    // breaking IMUL/MUL flag tests.
    if (S2Inline) {
      LoadConstant(TMP4, Const);
      subfco_(TMP3, TMP4, S1);
    } else {
      subfco_(TMP3, GetReg(Op->Src2), S1);
    }
  }
  b(&Done);

  Bind(&FalseLbl);
  SetNZCVConstant(Op->FalseNZCV);
  Bind(&Done);
}
DEF_OP(ShiftFlags) {
  // After a variable-count shift: set NZCV from the result and produce the new
  // raw PF. If the masked count is zero, flags stay unchanged — return the
  // PFInput unchanged and skip the CR0/XER updates.
  //
  // ORDERING NOTE: cmpdi/cmpwi from Result must be the *last* CR0-touching
  // op in the path; PPC `andi.` always sets CR0, so any masking with andi_
  // afterward would wipe SF/ZF for downstream LoadNZCV.
  auto Op       = IROp->C<IR::IROp_ShiftFlags>();
  auto Result   = GetReg(Op->Result);
  auto Src1     = GetReg(Op->Src1);
  auto Src2     = GetReg(Op->Src2);
  auto PFIn     = GetReg(Op->PFInput);
  auto Dst      = GetReg(Node);
  uint32_t Sz   = IR::OpSizeToSize(Op->Size);
  uint32_t Mask = (Sz == 8) ? 0x3F : 0x1F;

  PPC64Emitter::Label noShift, done;

  // Save CR + XER to a stack scratch slot before andi_ — `andi.` ALWAYS
  // sets CR0 with a result-of-0 check, so taking the noShift branch
  // would corrupt the preserved-flag invariant (CR0.EQ=1 leaking into
  // ZF on the next PUSHF / LAHF, also CF leak from XER if the previous
  // op left CA in a meaningful state). Restore on the noShift path.
  // Active-shift path drops the save (it overwrites CR0+XER anyway).
  addi(r1, r1, -16);
  // Single-field CR0 save (was a full mfcr + mtcrf 0xff round-trip): the only
  // CR writer between this save and the noShift restore is the andi_ below,
  // which touches CR0 alone — so saving/restoring just field 0 is exact.
  // mfocrf's non-field-0 bits are undefined pre-3.0C; the mtocrf(0x80)
  // restore reads only bits 31:28, which are defined.
  mfocrf(TMP4, 0x80); std(TMP4, 0, r1);
  mfspr(TMP4, 1); std(TMP4, 8, r1);

  andi_(TMP1, Src2, Mask);
  bc(CC_EQ, &noShift);
  addi(r1, r1, 16);             // pop scratch on the active-shift path

  // CF: bit shifted out. LSL → bit (SizeBits - count) of Src1; LSR/ASR →
  // bit (count - 1). Compute via shift right + LSB extract — using rldicl
  // (no Rc) for the LSB mask so we don't wipe CR0.
  if (Op->Shift == IR::ShiftType::LSL) {
    li(TMP2, static_cast<int16_t>(Sz * 8));
    subf(TMP2, TMP1, TMP2);
  } else {
    addi(TMP2, TMP1, -1);
  }
  if (Op->Size == IR::OpSize::i64Bit) srd(TMP3, Src1, TMP2);
  else                                srw(TMP3, Src1, TMP2);
  rldicl(TMP3, TMP3, 0, 63);   // keep LSB only (no CR0 set)
  if (Op->InvertCF) xori(TMP3, TMP3, 1);

  // OF (defined for count=1; we always compute). Universal formula:
  //   OF = MSB(Src1) ^ MSB(Result)
  //   LSL count=1:  shifts left → MSB(Result) = bit(N-2); XOR = sign-change. ✓
  //   LSR count=1:  shifts right zero-fill → MSB(Result) = 0; XOR = MSB(Src1) (SHR). ✓
  //                 SHRD count=1: MSB(Result) = LSB(Src2); XOR = sign-change. ✓
  //   ASR count=1:  sign-preserves → MSB(Result) = MSB(Src1); XOR = 0. ✓
  uint32_t SzBits = Sz * 8;
  GPR OFReg = TMP2;
  if (Op->Shift == IR::ShiftType::ASR) {
    li(OFReg, 0);
  } else {
    srdi(TMP4, Src1, SzBits - 1);
    rldicl(TMP4, TMP4, 0, 63);
    srdi(OFReg, Result, SzBits - 1);
    rldicl(OFReg, OFReg, 0, 63);
    xor_(OFReg, OFReg, TMP4);
  }

  // XER patch via rlwimi (clear-and-set in one instruction) — SH/MB/ME
  // derived in DEF_OP(AdcWithFlags) above: CA sits at LSB 29 = PPC bit 2, so
  // an LSB-0 source needs SH=29 with MB=ME=2; OV at LSB 30 = PPC bit 1 needs
  // SH=30 with MB=ME=1. Single-bit masks discard everything above the
  // source's LSB, exactly as the old sldi/or_ pair did.
  mfspr(TMP4, 1);
  rlwimi(TMP4, TMP3,  29, 2, 2);   // CA <- TMP3 LSB
  rlwimi(TMP4, OFReg, 30, 1, 1);   // OV <- OFReg LSB
  mtspr(1, TMP4);

  // New raw PF = parity of low byte of Result. rldicl-only masking.
  rldicl(TMP2, Result, 0, 56);  // low 8 bits
  popcntd(TMP2, TMP2);
  rldicl(Dst, TMP2, 0, 63);     // LSB

  // SF/ZF from the result — must be the *last* CR0 update. For i8/i16 the
  // sign bit is at bit 7/15 of the operand-size value, not bit 31, so
  // sign-extend into a scratch (don't clobber Result, it's an SSA value).
  if (Op->Size == IR::OpSize::i64Bit)        cmpdi(Result, 0);
  else if (Op->Size == IR::OpSize::i32Bit)   cmpwi(Result, 0);
  else if (Op->Size == IR::OpSize::i16Bit) { extsh(TMP1, Result); cmpdi(TMP1, 0); }
  else                                     { extsb(TMP1, Result); cmpdi(TMP1, 0); }

  b(&done);
  Bind(&noShift);
  // Restore CR0 + XER to the values they held before the andi_ above
  // (only CR0 was clobbered; see the save-site comment).
  ld   (TMP4, 0, r1); mtocrf(0x80, TMP4);
  ld   (TMP4, 8, r1); mtspr(1, TMP4);
  addi (r1,   r1, 16);
  if (Dst != PFIn) mr(Dst, PFIn);
  Bind(&done);
}

DEF_OP(RotateFlags) {
  // After a variable rotate: ROL sets CF = LSB of result; ROR sets CF = MSB of
  // result. ZF/SF/PF/AF unchanged. OF is only architecturally defined for
  // count=1 (= MSB ^ LSB for ROL, = bit(N-1) ^ bit(N-2) for ROR); we set it
  // unconditionally since x86 leaves it undefined for count != 1.
  //
  // CRITICAL contract: the dispatcher emits RectifyCarryInvert(true) before
  // _RotateFlags, so CFInverted is true and we must store !CF (not CF) in the
  // C-bit. Otherwise downstream JC / CMOVC / SETC reads the inverse.
  //
  // Use rldicl/srdi (no Rc) for bit extraction so we don't clobber CR0 —
  // downstream LAHF / NZCVSelect on N/Z still needs the prior cmp's result.
  auto Op       = IROp->C<IR::IROp_RotateFlags>();
  auto Result   = GetReg(Op->Result);
  auto Shift    = GetReg(Op->Shift);
  uint32_t Sz   = IR::OpSizeToSize(Op->Size);
  uint32_t SzBits = Sz * 8;
  // Flags unchanged if the architectural masked count == 0. The dispatcher
  // hands us Src already masked to 0x3F (64-bit) or 0x1F (smaller); andi_
  // re-tests the same range against the byte-loaded register.
  // x86 rotate count masking: 5 bits for 8/16/32-bit operands, 6 bits
  // for 64-bit.  Sz is the byte-size of the x86 operand (1, 2, 4, 8).
  // Mirror ShiftFlags at line 2537.
  uint32_t Mask = (Sz == 8) ? 0x3F : 0x1F;

  PPC64Emitter::Label noRotate, done;
  // x86 ROL/ROR preserve ZF/SF/PF/AF.  Save CR0 (the canonical packed-NZCV
  // scratch) to the red zone before andi_ which would otherwise clobber it
  // for both the rotate-body and rotate-by-0-fallthrough paths.  Restore
  // at the noRotate label so the prior compare's NZCV survives the op.
  // mfocrf 0x80: only field 0 is defined pre-3.0C — sufficient, since the
  // sole consumer is the mtocrf(0x80) restore at noRotate.
  mfocrf(TMP4, 0x80);
  std(TMP4, -16, r1);
  andi_(TMP1, Shift, Mask);
  bc(CC_EQ, &noRotate);

  // CF extraction (real CF first; we'll invert before storing).
  if (Op->Left) {
    rldicl(TMP3, Result, 0, 63);  // ROL: CF = LSB
  } else {
    srdi(TMP3, Result, SzBits - 1);
    rldicl(TMP3, TMP3, 0, 63);    // ROR: CF = MSB
  }

  // OF: MSB(result) XOR CF for ROL = MSB ^ LSB; for ROR = bit(N-1) ^ bit(N-2).
  srdi(TMP2, Result, SzBits - 1);
  rldicl(TMP2, TMP2, 0, 63);      // MSB
  if (Op->Left) {
    xor_(TMP2, TMP2, TMP3);       // MSB ^ LSB(result) = MSB ^ CF
  } else {
    srdi(TMP1, Result, SzBits - 2);
    rldicl(TMP1, TMP1, 0, 63);
    xor_(TMP2, TMP2, TMP1);
  }

  // Invert CF for the CFInverted=true contract.
  xori(TMP3, TMP3, 1);

  // Splat C → XER.CA (LSB 29 = PPC bit 2) and V → XER.OV (LSB 30 = PPC bit 1)
  // without disturbing CR0. rlwimi clears and sets in one instruction; the
  // SH/MB/ME derivation is written out in DEF_OP(AdcWithFlags) above.
  mfspr(TMP4, 1);
  rlwimi(TMP4, TMP3, 29, 2, 2);   // CA <- TMP3 LSB
  rlwimi(TMP4, TMP2, 30, 1, 1);   // OV <- TMP2 LSB
  mtspr(1, TMP4);

  Bind(&noRotate);
  // Restore CR0 (packed-NZCV) saved before the andi_ above.
  ld(TMP4, -16, r1);
  mtocrf(0x80, TMP4);
  Bind(&done);
}
DEF_OP(CmpPairZ) {
  // Set Z = (Src1Lo==Src2Lo) && (Src1Hi==Src2Hi); preserve N (CR0.LT) and V/C.
  // Compute the equality test in CR1 to avoid disturbing CR0, then crmove
  // CR1.EQ → CR0.EQ. PPC CR bit numbering: CR0.EQ = bit 2, CR1.EQ = bit 6.
  //
  // CRITICAL: IROp->Size is the element size (i32 for CMPXCHG8B, i64 for
  // CMPXCHG16B). The source GPRs are physical 64-bit registers that may carry
  // stale upper bits from a wider compute (e.g. an x86 `mov rax, 0x4141...8000`
  // before `cmpxchg8b` leaves the upper 32 bits of RAX live, but x86 semantics
  // compare only EAX/EDX). A bare xor on the full 64-bit values would falsely
  // declare inequality. Mask to the element size before the equality test.
  auto Op = IROp->C<IR::IROp_CmpPairZ>();
  auto LoA = GetReg(Op->Src1Lo);
  auto LoB = GetReg(Op->Src2Lo);
  auto HiA = GetReg(Op->Src1Hi);
  auto HiB = GetReg(Op->Src2Hi);

  if (IROp->Size == IR::OpSize::i32Bit) {
    rldicl(TMP1, LoA, 0, 32);  rldicl(TMP3, LoB, 0, 32);  xor_(TMP1, TMP1, TMP3);
    rldicl(TMP2, HiA, 0, 32);  rldicl(TMP3, HiB, 0, 32);  xor_(TMP2, TMP2, TMP3);
  } else {
    xor_(TMP1, LoA, LoB);
    xor_(TMP2, HiA, HiB);
  }
  or_(TMP1, TMP1, TMP2);
  cmpdi(cr(1), TMP1, 0);    // sets CR1.EQ; CR0 untouched
  crmove(2, 6);             // CR0.EQ (bit 2) := CR1.EQ (bit 6)
}
DEF_OP(AddShift) {
  auto Op = IROp->C<IR::IROp_AddShift>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  // ShiftAmount==0 means OffsetByDir(size=1): DF byte is 0x01 (+1) or 0xFF (-1).
  // sldi by 0 copies without sign-extending, giving 255 instead of -1 for backward DF.
  if (Op->ShiftAmount == 0) {
    extsb(TMP4, S2);
  } else {
    sldi(TMP4, S2, Op->ShiftAmount);
  }
  add(Dst, S1, TMP4);
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

DEF_OP(SubShift) {
  auto Op = IROp->C<IR::IROp_SubShift>();
  auto Dst = GetReg(Node);
  auto S1  = GetReg(Op->Src1);
  auto S2  = GetReg(Op->Src2);
  sldi(TMP4, S2, Op->ShiftAmount);
  subf(Dst, TMP4, S1);  // S1 - TMP4
  if (IROp->Size == IR::OpSize::i32Bit) rldicl(Dst, Dst, 0, 32);
}

// =========================================================================
// Copy
// =========================================================================
DEF_OP(Copy) {
  auto Op = IROp->C<IR::IROp_Copy>();
  auto Dst = GetReg(Node);
  auto Src = GetReg(Op->Source);
  if (Dst != Src) mr(Dst, Src);
}

// =========================================================================
// ProcessorID / CPUID / XGetBV
// =========================================================================
DEF_OP(ProcessorID) {
  // Return a synthesized processor ID
  li(GetReg(Node), 0);
}

// =========================================================================
// CPUID: call CPUIDEmu::RunFunction(this=CPUIDObj, Function, Leaf).
// Returns FEXCore::CPUID::FunctionResults { uint32 eax, ebx, ecx, edx }.
// PPC64 ELFv2: a 16-byte aggregate is returned in r3 (low qword) and r4 (high
// qword). Memory layout (LE) places eax at r3[0..31], ebx at r3[32..63],
// ecx at r4[0..31], edx at r4[32..63].
//
// Calling convention: this is a C++ member function. The `this` pointer
// (CPUIDObj) is the first arg → r3, then r4=Function, r5=Leaf. The function
// pointer comes from STATE->Pointers.CPUIDFunction (loaded as a regular
// function pointer via MemberFunctionToPointerCast).
// =========================================================================
DEF_OP(CPUID) {
  auto Op = IROp->C<IR::IROp_CPUID>();
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);

  // Mini-frame layout (96 bytes, accessed at +0..+88 BEFORE SpillForABICall,
  // and at +kABISpill+0..+kABISpill+88 AFTER SpillForABICall — kABISpill is
  // kDynRegSaveSize from ArchHelpers/PPC64Emitter.h and differs per guest
  // bitness, so it is never written as a literal here):
  //   [r1+ 0]  back chain
  //   [r1+ 8]  CPUIDObj  (this)
  //   [r1+16]  LR save
  //   [r1+24]  CPUIDFunction (callee fn ptr)
  //   [r1+32]  Function arg
  //   [r1+40]  Leaf arg
  //   [r1+48]  TOC save (r2)
  //   [r1+56]  result low  (eax|ebx<<32)
  //   [r1+64]  result high (ecx|edx<<32)
  //   [r1+72..88] padding to keep frame 16-byte aligned
  //
  // We must materialise everything into the frame BEFORE SpillForABICall
  // because that helper clobbers TMP1 and TMP4 internally (NZCV packing in
  // SpillStaticRegs) and PushDynamicRegs uses TMP1 as scratch. Only STATE
  // (r27, an SRA reg whose physical value survives the SRA copy-to-ctx
  // because nothing has overwritten r27 yet) and r2/r0 are safe.
  const auto FuncReg = GetReg(Op->Function);
  const auto LeafReg = GetReg(Op->Leaf);

  stdu(r1, -96, r1);
  mflr(r(0));
  std(r(0), 16, r1);

  // CPUIDObj / CPUIDFunction from STATE.
  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj)),      STATE);
  std(TMP1,  8, r1);
  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDFunction)), STATE);
  std(TMP1, 24, r1);

  // Function/Leaf args — read from SRA-allocated guest regs whose physical
  // host registers still hold the live values (SpillStaticRegs has not yet
  // run). These reads must happen BEFORE SpillForABICall.
  std(FuncReg, 32, r1);
  std(LeafReg, 40, r1);

  SpillForABICall(TMP1);

  // Marshal args into ABI registers (post-spill mini-frame is at +kABISpill).
  ld(r3,     8 + kABISpill, r1);  // r3  = this (CPUIDObj)
  ld(r4,    32 + kABISpill, r1);  // r4  = Function
  ld(r5,    40 + kABISpill, r1);  // r5  = Leaf
  ld(r(12), 24 + kABISpill, r1);  // r12 = callee (ELFv2 indirect-call req)

  std(r2, 48 + kABISpill, r1);    // save TOC across C call
  mtctr(r(12));
  bctrl();
  ld(r2, 48 + kABISpill, r1);     // restore TOC
  // Function returns 16-byte aggregate in r3:r4.

  // Save result to mini-frame slots (post-spill: +kABISpill+56, +kABISpill+64).
  std(r3, 56 + kABISpill, r1);
  std(r4, 64 + kABISpill, r1);

  FillForABICall();
  // r1 is now back at mini-frame top.

  // Restore LR and reload result.
  ld(r(0), 16, r1);
  mtlr(r(0));
  ld(TMP1, 56, r1);   // TMP1 = eax|(ebx<<32)
  ld(TMP2, 64, r1);   // TMP2 = ecx|(edx<<32)
  addi(r1, r1, 96);

  // r0 was clobbered; restore JIT zero-index invariant.
  li(r(0), 0);

  // Split into 4 × i32 destinations.
  //   eax = TMP1 & 0xFFFFFFFF      (low 32 of r3 result)
  //   ebx = TMP1 >> 32             (high 32 of r3 result)
  //   ecx = TMP2 & 0xFFFFFFFF
  //   edx = TMP2 >> 32
  rldicl(GetReg(Op->OutEAX), TMP1, 0,  32);  // clear upper 32 bits
  rldicl(GetReg(Op->OutEBX), TMP1, 32, 32);  // shift right 32, clear upper 32
  rldicl(GetReg(Op->OutECX), TMP2, 0,  32);
  rldicl(GetReg(Op->OutEDX), TMP2, 32, 32);
}

// =========================================================================
// XGetBV: call CPUIDEmu::RunXCRFunction(this=CPUIDObj, Function).
// Returns FEXCore::CPUID::XCRResults { uint32 eax, edx } — 8 bytes, returned
// in r3 alone (low 32 = eax, high 32 = edx).
// =========================================================================
DEF_OP(XGetBV) {
  auto Op = IROp->C<IR::IROp_XGetBV>();
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);

  // Mini-frame layout (64 bytes, slots same scheme as CPUID minus Leaf):
  //   [r1+ 0]  back chain
  //   [r1+ 8]  CPUIDObj
  //   [r1+16]  LR save
  //   [r1+24]  XCRFunction
  //   [r1+32]  Function arg
  //   [r1+40]  TOC save
  //   [r1+48]  result (eax | edx<<32)
  //   [r1+56]  padding
  const auto FuncReg = GetReg(Op->Function);

  stdu(r1, -64, r1);
  mflr(r(0));
  std(r(0), 16, r1);

  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.CPUIDObj)),    STATE);
  std(TMP1, 8, r1);
  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.XCRFunction)), STATE);
  std(TMP1, 24, r1);
  std(FuncReg, 32, r1);

  SpillForABICall(TMP1);

  ld(r3,     8 + kABISpill, r1);  // r3  = CPUIDObj
  ld(r4,    32 + kABISpill, r1);  // r4  = Function
  ld(r(12), 24 + kABISpill, r1);  // r12 = XCRFunction

  std(r2, 40 + kABISpill, r1);
  mtctr(r(12));
  bctrl();
  ld(r2, 40 + kABISpill, r1);
  // Result: r3 = eax | (edx << 32)

  std(r3, 48 + kABISpill, r1);

  FillForABICall();

  ld(r(0), 16, r1);
  mtlr(r(0));
  ld(TMP1, 48, r1);
  addi(r1, r1, 64);
  li(r(0), 0);

  rldicl(GetReg(Op->OutEAX), TMP1, 0,  32);
  rldicl(GetReg(Op->OutEDX), TMP1, 32, 32);
}

// =========================================================================
// RDRAND: POWER8 has no `darn`. Call out to PPC64_RDRAND() (defined in
// JIT.cpp) which returns a 64-bit value in r3.
// The IR op produces a single GPR; CF=valid is fabricated upstream.
// =========================================================================
DEF_OP(RDRAND) {
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  // Mini-frame layout (32 bytes):
  //   [r1+ 0] back chain
  //   [r1+ 8] TOC save
  //   [r1+16] LR save
  //   [r1+24] result
  stdu(r1, -32, r1);
  mflr(r(0));
  std(r(0), 16, r1);

  SpillForABICall(TMP1);

  // Load helper address into r12 (ELFv2 indirect-call req) and call.
  EmitLoadPPC64Helper(r(12), PPC64_HELPER_RDRAND);
  std(r2, 8 + kABISpill, r1);
  mtctr(r(12));
  bctrl();
  ld(r2, 8 + kABISpill, r1);

  std(r3, 24 + kABISpill, r1);  // save 64-bit result

  FillForABICall();

  ld(r(0), 16, r1);
  mtlr(r(0));
  ld(TMP1, 24, r1);
  addi(r1, r1, 32);
  li(r(0), 0);

  mr(GetReg(Node), TMP1);
}

// =========================================================================
// Telemetry (stub)
// =========================================================================
DEF_OP(TelemetrySetValue) { /* nop */ }

// =========================================================================
// Rounding mode
// =========================================================================
DEF_OP(GetRoundingMode) {
  // Read FPSCR RN field (bits [62:63])
  auto Dst = GetReg(Node);
  mffs(f(0));   // f0 = FPSCR
  mffprd(Dst, f(0));
  // andi. would clobber CR0; Rc-free rldicl preserves NZCV state for the
  // flag-sensitive paths that may sit between this and a downstream Jcc.
  rldicl(Dst, Dst, 0, 62);  // extract RN bits
}

DEF_OP(SetRoundingMode) {
  auto Op  = IROp->C<IR::IROp_SetRoundingMode>();
  auto Src = GetReg(Op->RoundMode);
  // Src is NOT limited to 0-3. The feeding IR is _Bfe(i32Bit, 3, 13, MXCSR)
  // (Vector.cpp RestoreMXCSRState) and _Bfe(i32Bit, 3, 10, NewFCW) (X87F64.cpp)
  // — width 3, so Src spans 0-7. Bit 2 is MXCSR.FZ / FCW bit 12, not part of the
  // rounding-control field. Mask it off before using it as a map index.
  //
  // x86: 0=near, 1=down, 2=up, 3=trunc; PPC FPSCR RN: 0=near, 1=trunc, 2=up, 3=down
  // The map {0,1,2,3} -> {0,3,2,1} is the packed-nibble constant 0x1230, where
  // nibble i = (0x1230 >> (i*4)) & 0xF. Computing it in-register avoids both the
  // table and its load.
  //
  // andi. would clobber CR0; Rc-free rldicl preserves NZCV state for the
  // flag-sensitive paths that may sit between this and a downstream Jcc.
  rldicl(TMP2, Src, 0, 62);   // TMP2 = Src & 3 (drop FZ and anything above it)
  sldi(TMP2, TMP2, 2);        // TMP2 = index * 4 (nibble shift amount)
  li(TMP1, 0x1230);           // packed x86 -> PPC RN map
  srd(TMP1, TMP1, TMP2);      // 64-bit shift; shift amount is 0-12
  rldicl(TMP1, TMP1, 0, 60);  // isolate the low nibble = new RN
  mffs(f(0));
  mffprd(TMP3, f(0));
  rldicr(TMP3, TMP3, 0, 61);  // clear C bits 0-1 (= FPSCR RN field)
  or_(TMP3, TMP3, TMP1);
  mtfprd(f(0), TMP3);
  mtfsf(0xFF, f(0));
}

DEF_OP(PushRoundingMode) {
  auto Op  = IROp->C<IR::IROp_PushRoundingMode>();
  auto Dst = GetReg(Node);

  // Save full FPSCR to Dst — PopRoundingMode will restore from this.
  mffs(f(0));
  mffprd(Dst, f(0));

  // Map x86 rounding mode to PPC FPSCR RN (compile-time constant).
  // x86: 0=near, 1=down, 2=up, 3=trunc; PPC: 0=near, 1=trunc, 2=up, 3=down
  static constexpr uint8_t MapTable[4] = { 0, 3, 2, 1 };
  const uint32_t NewRN = MapTable[Op->RoundMode & 3];

  rldicr(TMP1, Dst, 0, 61);   // clear C bits 0-1 (FPSCR RN field)
  ori(TMP1, TMP1, NewRN);     // insert new RN
  mtfprd(f(0), TMP1);
  mtfsf(0xFF, f(0));
}

DEF_OP(PopRoundingMode) {
  auto Op    = IROp->C<IR::IROp_PopRoundingMode>();
  auto Saved = GetReg(Op->FPCR);

  // Restore the full FPSCR saved by PushRoundingMode.
  mtfprd(f(0), Saved);
  mtfsf(0xFF, f(0));
}

// =========================================================================
// Print (debug)
// =========================================================================
DEF_OP(Print) {
  auto Op  = IROp->C<IR::IROp_Print>();
  auto Src = GetReg(Op->Value);
  SpillForABICall(TMP1);
  // ELFv2 §2.2.1.2 requires r12 == callee entry address for indirect calls
  // (the callee's TOC prologue computes its GOT from r12). Load the fn
  // pointer into r12 first, THEN set r3 = Src -- do not load into TMP1
  // (== r3) or r3 would carry the fn pointer address into PrintValue
  // instead of the value the JIT wanted to print.
  static const int32_t PrintValueOff = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, Pointers.PrintValue));
  ld(r(12), PrintValueOff, STATE);
  mr(r3, Src);
  mtctr(r(12));
  bctrl();
  FillForABICall();
}

DEF_OP(PrintMsg) {
  auto Op  = IROp->C<IR::IROp_PrintMsg>();
  SpillForABICall(TMP1);
  // Same ELFv2 r12 discipline as Print above; load fn pointer into r12
  // first, then LoadConstant into r3.
  static const int32_t PrintMsgOff = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, Pointers.PrintMsgValue));
  ld(r(12), PrintMsgOff, STATE);
  LoadConstant(r3, reinterpret_cast<uint64_t>(Op->Value));
  mtctr(r(12));
  bctrl();
  FillForABICall();
}

// Misc
// x86 PAUSE -> counter-gated sched_yield (NO SMT priority change).
//
// POWER ISA has Program Priority Register hints via `or rN,rN,rN` for N in
// {1=low, 6=medium-low, 2=medium}. Naively emitting `or r1,r1,r1` (LOW)
// on every PAUSE is wrong without complementary code to restore MEDIUM
// after the spinlock is acquired — once the thread drops to LOW it stays
// there for the entire critical section, starving the lock-holder and
// causing user-visible hangs across SDL2/Vulkan games (regression
// introduced + reverted 2026-05-17).
//
// Per-block restoration via static-analysis of cmpxchg+jne patterns is
// future work. For now: skip the priority hint entirely. The counter-
// gated sched_yield is what actually gives the OS a chance to schedule
// the lock-holder on a different CPU when threads outnumber physical
// SMT contexts — and it has no priority-state to leak.
//
// Bug-class entries: project_stardew_main_thread_spin, project_ftl_futex_storm,
// project_steam_nul_jit_race (all involve guest threads spinning while their
// lock-holder is parked in the kernel).
DEF_OP(Yield) {
  constexpr uint32_t PAUSE_YIELD_LIMIT = 1000;
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const int16_t pc_off = static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, PauseCount));

  Label skip_full_yield{};
  Label end{};

  // Hot path: lwz/addi/cmplwi/bc — 4 instructions until we either reach the
  // threshold or take the skip branch.
  //
  // Route the threshold compare through cr(7), NOT cr(0): x86 PAUSE must
  // preserve flags, and CR0 is this backend's live packed-NZCV. Comparing into
  // cr(0) destroyed ZF on every single PAUSE — `cmp`/`pause`/`setz` returned
  // ZF=0 after a known-equal compare, 5000 times out of 5000. Any guest spin
  // loop that evaluates its exit condition after the PAUSE (which is the
  // ordinary shape: `pause; cmp; jne`) could therefore branch the wrong way.
  // cr(7) is the established scratch field here — see BranchOps.cpp CondJump
  // and the MonoBackpatcherWrite compares.
  lwz(TMP1, pc_off, STATE);
  addi(TMP1, TMP1, 1);
  cmplwi(cr(7), TMP1, PAUSE_YIELD_LIMIT);
  // BI = cr7 * 4 + LT(0) = 28; BO = 12 (branch when the bit is set).
  constexpr PPC64Emitter::Cond CC_ULT_CR7 {12, 28};
  bc(CC_ULT_CR7, &skip_full_yield);

  // Threshold reached. Reset counter to 0, then call PPC64_PauseSchedYield.
  li(TMP1, 0);
  stw(TMP1, pc_off, STATE);

  // Mini-frame: 64 bytes laid out like MonoBackpatcherWrite.
  //   [r1+ 0]  back chain
  //   [r1+ 8]  Func ptr (PPC64_PauseSchedYield)
  //   [r1+16]  LR save
  //   [r1+24]  TOC save
  //   [r1+32..56] padding (unused)
  stdu(r1, -64, r1);
  mflr(r(0));
  std(r(0), 16, r1);

  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.PPC64_PauseSchedYield)), STATE);
  std(TMP1, 8, r1);

  SpillForABICall(TMP1);

  ld(r(12), 8 + kABISpill, r1);
  std(r2, 24 + kABISpill, r1);
  mtctr(r(12));
  bctrl();
  ld(r2, 24 + kABISpill, r1);

  FillForABICall();

  ld(r(0), 16, r1);
  mtlr(r(0));
  addi(r1, r1, 64);
  // CRITICAL: restore the r0 == 0 zero-index invariant (c1ac6dac6). JIT blocks
  // address guest memory as `ldx/stdx rX, rBase, r0`, so r0 must be 0 on every
  // path back into guest code. The mflr/mtlr round-trip above parks the link
  // register in r0 and leaves it there, so without this the next guest memory
  // access computes rBase + <a code address> and SEGVs. Every other helper that
  // routes LR through r0 already does this (EmitSplitLockHelperCall,
  // EmitSplitLockCASCall, the dispatcher, MonoBackpatcherWrite, X87 FABI);
  // Yield was the sole omission. Reproducer: a guest that merely executes
  // PAUSE_YIELD_LIMIT PAUSE instructions dies with SIGSEGV on the first guest
  // push after the threshold fires -- `stdx r3, r11, r0`, r11 being guest RSP.
  li(r(0), 0);
  b(&end);

  // skip_full_yield: just store the incremented counter.
  Bind(&skip_full_yield);
  stw(TMP1, pc_off, STATE);

  Bind(&end);
  // Deliberately no PPR/SMT-priority hint here. See block comment above.
}
DEF_OP(WFET)                 { /* nop */ }
// =========================================================================
// MonoBackpatcherWrite: Mono/.NET single-instruction patcher.
// C sig: void MonoBackpatcherWrite(CpuStateFrame* Frame, uint8_t Size,
//                                  uint64_t Address, uint64_t Value)
// =========================================================================
DEF_OP(MonoBackpatcherWrite) {
  auto Op = IROp->C<IR::IROp_MonoBackpatcherWrite>();
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);

  // Mini-frame layout (64 bytes):
  //   [r1+ 0]  back chain
  //   [r1+ 8]  Func ptr (MonoBackpatcherWrite)
  //   [r1+16]  LR save
  //   [r1+24]  Addr arg
  //   [r1+32]  Value arg
  //   [r1+40]  TOC save
  //   [r1+48..56] padding
  const auto AddrReg  = GetReg(Op->Addr);
  const auto ValueReg = GetReg(Op->Value);

  stdu(r1, -64, r1);
  mflr(r(0));
  std(r(0), 16, r1);

  ld(TMP1, static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, Pointers.MonoBackpatcherWrite)), STATE);
  std(TMP1,  8, r1);
  std(AddrReg,  24, r1);
  std(ValueReg, 32, r1);

  SpillForABICall(TMP1);

  // Marshal args (post-spill +kABISpill).
  mr(r3, STATE);                          // arg0: Frame*
  li(r4, IR::OpSizeToSize(Op->Size));     // arg1: Size (uint8_t, zero-extended)
  ld(r5,    24 + kABISpill, r1);                // arg2: Addr
  ld(r6,    32 + kABISpill, r1);                // arg3: Value
  ld(r(12),  8 + kABISpill, r1);                // r12 = callee

  std(r2, 40 + kABISpill, r1);
  mtctr(r(12));
  bctrl();
  ld(r2, 40 + kABISpill, r1);

  FillForABICall();

  ld(r(0), 16, r1);
  mtlr(r(0));
  addi(r1, r1, 64);
  li(r(0), 0);
}
DEF_OP(ValidateCode) {
  // CRITICAL: all compares route through cr(7), not the default cr(0).
  //
  // Under CONFIG_SMC_FULL the IR pass emits this op at the start of every
  // x86-instruction block, BEFORE the actual instruction body. FillStaticRegs
  // (run at block entry by the dispatcher) populates CR0+XER from the
  // previously-spilled NZCV — the x86 flag state left by the prior block.
  // If ValidateCode clobbered CR0 here, any subsequent x86 conditional in
  // the same JIT-compile (cmp/jg, cmp/je, ...) consuming NZCV via
  // CondJumpNZCV / MapNZCVCC would read stale bits set by the validate
  // compare instead of the guest cmp's result.
  //
  // Concretely surfaces in SelfModifyingCode/Delinking under SMC_FULL: the
  // test's `cmp rcx,0; jg patched_op` always falls through and `cmp rbx,0;
  // je end` always takes, because CR0 carries the byte-compare's eq/lt
  // outcome rather than the guest cmp's result. SameBlock and DifferentBlock
  // pass only because they don't use conditional jumps.
  //
  // BI mapping for cr7: CR7.LT=28, CR7.GT=29, CR7.EQ=30, CR7.SO=31.
  auto Op = IROp->C<IR::IROp_ValidateCode>();
  const auto OldCode = Op->CodeOriginal.data();
  const auto Base    = GetReg(Op->Header.Args[0]);
  int        len     = Op->CodeLength;
  int        Offset  = 0;
  const auto Dst     = GetReg(Node);

  PPC64Emitter::Label Fail{};
  PPC64Emitter::Label End{};

  // cr7 not-equal: BO=4 (branch if false), BI=30 (CR7.EQ).
  constexpr PPC64Emitter::Cond CR7_NE = {4, 30};

  // 8-byte chunks — ld zero-extends implicitly (64-bit load on LE host)
  while (len >= 8) {
    ld(TMP1, Offset, Base);
    LoadConstant(TMP2, *reinterpret_cast<const uint64_t*>(OldCode + Offset));
    cmpld(cr(7), TMP1, TMP2);
    bc(CR7_NE, &Fail);
    Offset += 8; len -= 8;
  }

  // 4-byte chunk — lwz zero-extends to 64 bits
  if (len >= 4) {
    lwz(TMP1, Offset, Base);
    LoadConstant(TMP2, static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(OldCode + Offset)));
    cmpld(cr(7), TMP1, TMP2);
    bc(CR7_NE, &Fail);
    Offset += 4; len -= 4;
  }

  // 2-byte chunk — lhz zero-extends to 64 bits
  if (len >= 2) {
    lhz(TMP1, Offset, Base);
    LoadConstant(TMP2, static_cast<uint64_t>(*reinterpret_cast<const uint16_t*>(OldCode + Offset)));
    cmpld(cr(7), TMP1, TMP2);
    bc(CR7_NE, &Fail);
    Offset += 2; len -= 2;
  }

  // 1-byte chunk — lbz zero-extends to 64 bits
  if (len >= 1) {
    lbz(TMP1, Offset, Base);
    LoadConstant(TMP2, static_cast<uint64_t>(OldCode[Offset]));
    cmpld(cr(7), TMP1, TMP2);
    bc(CR7_NE, &Fail);
  }

  LoadConstant(Dst, UINT64_C(0));
  b(&End);
  Bind(&Fail);
  LoadConstant(Dst, UINT64_C(1));
  Bind(&End);
}
DEF_OP(GuestOpcode) {
  // Record (guest RIP offset, host PC offset from BlockBegin) so the
  // block-tail vl64pair table lets Core.cpp:RestoreRIPFromHostPC map a
  // fault-time host PC back to the exact guest instruction. Mirrors
  // Arm64JITCore's DEF_OP(GuestOpcode) at FEXCore/Source/Interface/Core/JIT/MiscOps.cpp:45.
  auto Op = IROp->C<IR::IROp_GuestOpcode>();
  DebugData->GuestOpcodes.push_back({Op->GuestEntryOffset,
                                     GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
}

// ThreadRemoveCodeEntry — invoked from the SMC validation tail emitted in
// front of each instruction when CONFIG_SMC_FULL is in effect. When ValidateCode
// detects a guest-code mismatch the IR routes us through a side block that
// calls this op and then ExitFunction()s back to the dispatcher. The op must:
//   1. Spill SRA + dynamic regs (the C call clobbers volatile host regs).
//   2. Call ContextImpl::ThreadRemoveCodeEntryFromJit(Frame*, GuestRIP) so the
//      backing block / lookup-cache entry for `Entry` is purged. Without this,
//      the dispatcher's L1 cache returns the stale block on the very next loop,
//      ValidateCode fails again, and the JIT spins forever — exactly the
//      SelfModifyingCode/DifferentBlock hang we observed.
//   3. Restore SRA + dynamic regs so that the trailing ExitFunction sees a
//      consistent register file (the subsequent ExitFunction will spill again,
//      which is idempotent).
//
// ELFv2 indirect-call ABI: the callee address must be in r12, and r2 (TOC
// pointer) may be clobbered by the callee's global-entry prologue. r2 is saved
// in the dispatcher frame's reserved TOC slot at [r1+24] *before* PushDynamicRegs
// shifts r1, then reloaded after PopDynamicRegs restores r1.
DEF_OP(ThreadRemoveCodeEntry) {
  // Save host TOC (r2) in the dispatcher frame's reserved slot before any
  // r1 manipulation. SpillForABICall (=SpillStaticRegs+PushDynamicRegs) shifts
  // r1 down by SaveSize but FillForABICall restores r1 exactly, so [r1+24]
  // is recoverable after the call.
  std(r2, 24, r1);

  SpillForABICall(TMP1);

  // Arguments (r3, r4). STATE (r27) is non-volatile in the ELFv2 ABI and is
  // not part of x64::SRA/RA, so it survives SpillForABICall untouched.
  mr(r3, STATE);
  // S3.7-C2: Entry is the block's guest RIP baked into a constant load.
  // DELIBERATE DIVERGENCE FROM ARM64 — ARM64 has a `TODO: Relocations don't
  // seem to be wired up to this...?` at JIT/BranchOps.cpp:414-415 and just
  // pads the site instead of recording. Adding the relocation is correct;
  // without it a cached CheckTF prologue would call CompileSingleStep with a
  // stale RIP from the caching session.
  InsertGuestRIPMove(TMP2, Entry);

  // ELFv2 indirect call: r12 must equal the callee entry-point at the moment
  // of the branch (used by the callee's global-entry prologue to recompute r2).
  int32_t fn_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, Pointers.ThreadRemoveCodeEntryFromJIT));
  ld(r(12), fn_off, STATE);
  mtctr(r(12));
  bctrl();

  FillForABICall();

  // Restore host TOC for any subsequent host-ABI activity in this JIT block.
  ld(r2, 24, r1);
}

// =========================================================================
// LoadNZCV / StoreNZCV — flag register save/restore
// =========================================================================
DEF_OP(LoadNZCV) {
  auto Dst = GetReg(Node);
  // mfocrf 0x80 (single-field form — uncracked where mfcr is a 3-iop crack,
  // POWER9 UM §4.1.5.6): the rlwinm extracts below read only CR0.LT (PPC
  // bit 0) and CR0.EQ (PPC bit 2), both inside the defined field-0 nibble;
  // the rlwinm masks discard every pre-3.0C-undefined bit.
  mfocrf(TMP1, 0x80);
  mfspr(TMP2, 1);

  // rlwinm rotate-left sh, mask mb..me (PPC MSB=0). After rotate, PPC bit p
  // lands at PPC bit (p - sh) mod 32. We need:
  //   N: PPC 0 → 0  (sh=0,  mask 0..0)
  //   Z: PPC 2 → 1  (sh=1,  mask 1..1)
  //   C: PPC 2 → 2  (sh=0,  mask 2..2)
  //   V: PPC 1 → 3  (sh=30, mask 3..3)
  // The first rlwinm seeds Dst (its mask covers only bits 32..63, so the
  // upper half of the 64-bit Dst is zeroed and every unselected low bit with
  // it); the three rlwimi then insert directly rather than extracting into a
  // scratch and OR-ing. SH/MB/ME are unchanged from the extracts above —
  // rlwimi uses the identical rotate-and-mask, it just merges into RA instead
  // of replacing it. 7 instructions become 4.
  rlwinm(Dst, TMP1, 0,  0, 0);   // N
  rlwimi(Dst, TMP1, 1,  1, 1);   // Z
  rlwimi(Dst, TMP2, 0,  2, 2);   // C
  rlwimi(Dst, TMP2, 30, 3, 3);   // V
}

DEF_OP(StoreNZCV) {
  auto Op  = IROp->C<IR::IROp_StoreNZCV>();
  auto Src = GetReg(Op->Value);
  // Inverse of LoadNZCV. Src has NZCV packed ARM-style at LSB bits 31..28
  // (N=31, Z=30, C=29, V=28). Spread back to CR0 + XER.
  //
  // mtcrf 0x80 reads CR0 from RS PPC bits 32..35 = GPR LSB 31..28; specifically
  // CR0.LT at LSB 31, CR0.GT at LSB 30, CR0.EQ at LSB 29, CR0.SO at LSB 28.
  // mfspr 1 / mtspr 1 has XER.SO at LSB 31, OV at LSB 30, CA at LSB 29.
  //
  // Required moves (rlwinm sh = rotate-left amount in 32-bit):
  //   N: Src LSB 31 → CR0.LT  LSB 31 (no shift). sh=0,  mb=0,  me=0  (PPC bit 0).
  //   Z: Src LSB 30 → CR0.EQ  LSB 29 (shift right 1 = rotate left 31). sh=31, mb=2, me=2.
  //   C: Src LSB 29 → XER.CA  LSB 29 (no shift). sh=0,  mb=2,  me=2.
  //   V: Src LSB 28 → XER.OV  LSB 30 (shift left 2 = rotate left 2). sh=2,  mb=1,  me=1.

  // CR0 assembly: rlwinm lays down N (and zeroes everything else, including
  // the CR0.GT and CR0.SO slots, exactly as the old rlwinm/or_ pair did),
  // then rlwimi inserts Z on top instead of building it in a scratch and
  // OR-ing. Same SH/MB/ME as the extracts they replace.
  rlwinm(TMP1, Src, 0,  0, 0);   // N → CR0.LT
  rlwimi(TMP1, Src, 31, 2, 2);   // Z → CR0.EQ
  mtocrf(0x80, TMP1);

  // XER: rlwimi clears and sets each target bit in one instruction, so the
  // LoadConstant-mask / andc / rlwinm / or_ chain collapses to two inserts
  // with the SH/MB/ME values the old rlwinm extracts already used.
  mfspr(TMP1, 1);
  rlwimi(TMP1, Src, 0, 2, 2);    // C: Src LSB 29 → XER.CA LSB 29 (no rotate)
  rlwimi(TMP1, Src, 2, 1, 1);    // V: Src LSB 28 (PPC 3) → XER.OV LSB 30 (PPC 1)
  mtspr(1, TMP1);
}

DEF_OP(CarryInvert) {
  // Flip x86 CF, which we route through XER.CA. PPC subtract sets CA = !borrow,
  // so this op is what the IR uses to convert PPC's CA convention to x86's CF.
  //
  // Done without touching the XER SPR at all. mtspr XER is execution-
  // serializing on POWER8, so the old mfspr/xoris/mtspr toggle stalled the
  // pipeline on an op that appears after essentially every emulated SUB/CMP
  // whose carry is consumed.
  //
  // The two-instruction flip:
  //   subfe TMP1, r0, r0   ->  ~r0 + r0 + CA = all-ones + CA
  //                            CA = 1  =>  TMP1 =  0
  //                            CA = 0  =>  TMP1 = -1
  //   addic TMP1, TMP1, 1  ->  writes CA = carry-out of TMP1 + 1
  //                            TMP1 =  0  =>  0 + 1, no carry  =>  CA = 0
  //                            TMP1 = -1  => -1 + 1, carries   =>  CA = 1
  // so CA ends up inverted. subfe's carry-out equals its carry-in, so the
  // value addic sees is the original CA. Neither instruction writes OV or SO
  // (addic is the non-record, non-OE form) and neither writes CR0, so the
  // packed guest N/Z living in CR0 survives. Only TMP1 is clobbered, and it
  // is a scratch with no live value at any CarryInvert site.
  subfe(TMP1, r0, r0);
  addic(TMP1, TMP1, 1);
}

DEF_OP(LoadDF) {
  // Load direction flag from CpuStateFrame. DF is stored as a SIGNED sentinel
  // (-1 = backward / DF=1, +1 = forward / DF=0) by FLAGControlOp's StoreDF.
  // The IR consumers expect a sign-extended 64-bit value:
  //   * GetRFLAG(RFLAG_DF_RAW_LOC) → `Lshr(LoadDF(), 63)` extracts the sign bit.
  //   * OffsetByDir → `AddShift(X, LoadDF(), LSL, log2(Size))` walks the pointer
  //     by ±Size, requiring DF=-1 to actually be the 64-bit -1.
  // `lbz` zero-extends, which makes the sign-bit Lshr return 0 and the pointer
  // walk forward regardless of STD — a silent bug across block boundaries
  // (e.g. `STD; <block-end>; REP LODSD` under FEX_MAXINST=1). Use lbz+extsb
  // to load and sign-extend.
  auto Dst = GetReg(Node);
  int32_t df_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_DF_RAW_LOC]));
  lbz(Dst, static_cast<int16_t>(df_off), STATE);
  extsb(Dst, Dst);
}

// =========================================================================
// Helper macro for getting first source of an op when we know it is Src
// (used in a few ops above that reference Op_Src1)
// =========================================================================
// (We access sources via IROp->C<IR::IROp_Xxx>()->Src1 in each op; the generic
//  Op_Src1 helper below is not needed — each op accesses its own struct.)

DEF_OP(VExtractToGPR) {
  const auto Op    = IROp->C<IR::IROp_VExtractToGPR>();
  const auto ElemSz = Op->Header.ElementSize;
  const auto Index  = Op->Index;
  const auto Dst   = GetReg(Node);
  const auto Vec   = GetVReg(Op->Vector);

  if (ElemSz == IR::OpSize::i64Bit) {
    // mfvsrd reads physical bytes [0..7] (BE-high doubleword) as a 64-bit value.
    // In LE element ordering, element 0 lives at phys[8..15] (BE-low doubleword)
    // and element 1 lives at phys[0..7] (BE-high doubleword).
    //   Index 0 (LE elem 0, phys[8..15]) -> rotate by 8 so phys[8..15] becomes phys[0..7]
    //   Index 1 (LE elem 1, phys[0..7])  -> read directly
    if (Index == 0) {
      vsldoi(VTMP1, Vec, Vec, 8);
      mfvsrd(Dst, VTMP1);
    } else {
      mfvsrd(Dst, Vec);
    }
    return;
  }

  // Splat LE element Index to all lanes, mfvsrd physical bytes 8-15, shift down.
  // Physical index = (N-1) - LEIndex for N elements.
  switch (ElemSz) {
  case IR::OpSize::i8Bit:
    vspltb(VTMP1, Vec, (uint32_t)(15u - Index));
    mfvsrd(Dst, VTMP1);
    srdi(Dst, Dst, 56);
    break;
  case IR::OpSize::i16Bit:
    vsplth(VTMP1, Vec, (uint32_t)(7u - Index));
    mfvsrd(Dst, VTMP1);
    srdi(Dst, Dst, 48);
    break;
  case IR::OpSize::i32Bit: {
    // mfvsrd reads physical bytes [0..7] as a 64-bit BE value: high 32 bits = phys[0..3],
    // low 32 bits = phys[4..7].  Rotate the source so the requested LE element lands at
    // physical bytes [4..7] (i.e. the low 32 bits of mfvsrd's result), then zero-extend.
    //   Index 0 (phys[12..15]) -> SHB=8   (phys[4..7] := phys[12..15])
    //   Index 1 (phys[ 8..11]) -> SHB=4
    //   Index 2 (phys[ 4.. 7]) -> SHB=0
    //   Index 3 (phys[ 0.. 3]) -> SHB=12
    const uint32_t SHB = (8u - 4u * Index) & 0xFu;
    if (SHB != 0) {
      vsldoi(VTMP1, Vec, Vec, SHB);
      mfvsrd(Dst, VTMP1);
    } else {
      mfvsrd(Dst, Vec);
    }
    clrldi(Dst, Dst, 32);
    break;
  }
  default:
    Op_Unhandled(IROp, Node);
    break;
  }
}
// Helper: substitute Dst with x86 "integer indefinite" sentinel (INT_MIN of
// the destination width) on +overflow / NaN, after POWER fctiw[z]/fctid[z]
// has already converted Src into Dst.
//
// POWER's scalar fctiw[z]/fctid[z] saturate +overflow to INT_MAX and -overflow
// to INT_MIN, and produce INT_MIN for NaN.  x86 CVT[T]SS2SI / CVT[T]SD2SI
// instead want INT_MIN (0x80000000_i32 / 0x8000000000000000_i64) for ALL of
// {+overflow, -overflow already matches, NaN already matches}.  So we only
// need to fix up the +overflow case; -overflow and NaN are already correct.
//
// Strategy: scalar fcmpu against the smallest FP value strictly greater than
// INT_MAX in the source precision (equivalently 2^N where N is dst width-1).
// If Src >= bound  OR  Src is NaN  → load INT_MIN into Dst.
//
// fcmpu sets CR.LT / CR.GT / CR.EQ / CR.SO; "no fixup needed" is exactly
// CR.LT set (Src < bound, finite, ordered).  We use cr(1) so we don't
// clobber CR0 (packed NZCV).  bc with BO=12 BI=4 branches on CR1.LT set.
//
// Bound constants (smallest FP > INT_MAX, equal to 2^(W-1) in source precision):
//   f32 -> i32:  2^31  as f32 = 0x4F000000
//   f32 -> i64:  2^63  as f32 = 0x5F000000
//   f64 -> i32:  2^31  as f64 = 0x41E0000000000000
//   f64 -> i64:  2^63  as f64 = 0x43E0000000000000
// Note 2^31 is exactly representable in both f32 and f64 (and 2^63 in f64),
// so "Src == bound" is also overflow on x86 (x86 INT_MAX = 2^(W-1)-1).
// The condition is thus Src >= bound (or NaN), i.e. !CR.LT.

// "Branch if CR1.LT set" — BO=12 (branch if BI set), BI=4 (CR1 bit 0 = LT).
// We use cr(1) for the overflow fcmpu so CR0 (packed NZCV) is preserved.

// Float_ToGPR_ZS: scalar float → signed integer GPR, truncate-toward-zero.
// FPR scalar is element 0 of a vector register; extract via stack roundtrip.
DEF_OP(Float_ToGPR_ZS) {
  auto Op = IROp->C<IR::IROp_Float_ToGPR_ZS>();
  auto Dst = GetReg(Node);
  auto Vec = GetVReg(Op->Scalar);
  const auto SrcES = Op->SrcElementSize;
  const auto DstES = IROp->Size;

  addi(TMP1, r1, -32);
  stvx(Vec, r(0), TMP1);
  if (SrcES == IR::OpSize::i32Bit) {
    lfs(f0, -32, r1);
  } else {
    lfd(f0, -32, r1);
  }

  // Materialise bound = 2^(DstWidth-1) in source precision, compare via
  // fcmpu(cr(1), ...).  See helper-block comment above for derivation.
  uint64_t Bound;
  if (SrcES == IR::OpSize::i32Bit) {
    Bound = (DstES == IR::OpSize::i32Bit) ? 0x4F000000ULL          // 2^31 f32
                                          : 0x5F000000ULL;         // 2^63 f32
    LoadConstant(TMP1, Bound);
    std(TMP1, -16, r1);
    lfs(f1, -16, r1);
  } else {
    Bound = (DstES == IR::OpSize::i32Bit) ? 0x41E0000000000000ULL  // 2^31 f64
                                          : 0x43E0000000000000ULL; // 2^63 f64
    LoadConstant(TMP1, Bound);
    std(TMP1, -16, r1);
    lfd(f1, -16, r1);
  }
  fcmpu(cr(1), f0, f1);

  if (DstES == IR::OpSize::i32Bit) {
    fctiwz(f0, f0);
    mffprd(Dst, f0);
    clrldi(Dst, Dst, 32);  // zero-extend to GPR (high half is undefined per ISA)
  } else {
    fctidz(f0, f0);
    mffprd(Dst, f0);
  }

  // If CR1.LT set (Src < bound, ordered), POWER's result is x86-correct.
  // Otherwise (Src >= bound or NaN) overwrite Dst with INT_MIN sentinel.
  PPC64Emitter::Label NoOvf;
  bc(PPC64Emitter::Cond{12, 4}, &NoOvf);  // branch if CR1.LT set
  if (DstES == IR::OpSize::i32Bit) {
    LoadConstant(Dst, 0x80000000ULL);  // INT_MIN_i32 zero-extended to 64
  } else {
    LoadConstant(Dst, 0x8000000000000000ULL);  // INT_MIN_i64
  }
  Bind(&NoOvf);
}

// Float_ToGPR_S: scalar float → signed integer GPR using host rounding mode.
// We use fctiw/fctid (which obey FPSCR.RN, default Nearest).
DEF_OP(Float_ToGPR_S) {
  auto Op = IROp->C<IR::IROp_Float_ToGPR_S>();
  auto Dst = GetReg(Node);
  auto Vec = GetVReg(Op->Scalar);
  const auto SrcES = Op->SrcElementSize;
  const auto DstES = IROp->Size;

  addi(TMP1, r1, -32);
  stvx(Vec, r(0), TMP1);
  if (SrcES == IR::OpSize::i32Bit) {
    lfs(f0, -32, r1);
  } else {
    lfd(f0, -32, r1);
  }

  // Same INT_MIN-on-overflow fixup as Float_ToGPR_ZS above.
  uint64_t Bound;
  if (SrcES == IR::OpSize::i32Bit) {
    Bound = (DstES == IR::OpSize::i32Bit) ? 0x4F000000ULL
                                          : 0x5F000000ULL;
    LoadConstant(TMP1, Bound);
    std(TMP1, -16, r1);
    lfs(f1, -16, r1);
  } else {
    Bound = (DstES == IR::OpSize::i32Bit) ? 0x41E0000000000000ULL
                                          : 0x43E0000000000000ULL;
    LoadConstant(TMP1, Bound);
    std(TMP1, -16, r1);
    lfd(f1, -16, r1);
  }
  fcmpu(cr(1), f0, f1);

  if (DstES == IR::OpSize::i32Bit) {
    fctiw(f0, f0);
    mffprd(Dst, f0);
    clrldi(Dst, Dst, 32);
  } else {
    fctid(f0, f0);
    mffprd(Dst, f0);
  }

  PPC64Emitter::Label NoOvf;
  bc(PPC64Emitter::Cond{12, 4}, &NoOvf);  // branch if CR1.LT set
  if (DstES == IR::OpSize::i32Bit) {
    LoadConstant(Dst, 0x80000000ULL);
  } else {
    LoadConstant(Dst, 0x8000000000000000ULL);
  }
  Bind(&NoOvf);
}

// FCmp: scalar FP unordered compare, produces ARM-FCMP-style NZCV.
//   ARM N = LT       → CR0.LT       (set by fcmpu)
//   ARM Z = EQ       → CR0.EQ       (set by fcmpu)
//   ARM C = !LT      → XER.CA       (1 unless LT, including NaN)
//   ARM V = unordered → XER.OV      (= CR0.SO from fcmpu)
//
// fcmpu only writes CR0; we also lift CR0.SO and !CR0.LT into XER.OV/CA so
// that AXFlag's NZCV translation and any downstream MapNZCVCC consumer
// (which routes V/C through ProjectXERToCR1) see consistent state.
DEF_OP(FCmp) {
  auto Op = IROp->C<IR::IROp_FCmp>();
  auto S1 = GetVReg(Op->Scalar1);
  auto S2 = GetVReg(Op->Scalar2);
  const auto ESize = Op->ElementSize;

  addi(TMP1, r1, -32);
  stvx(S1, r(0), TMP1);
  addi(TMP2, r1, -16);
  stvx(S2, r(0), TMP2);
  if (ESize == IR::OpSize::i32Bit) {
    lfs(f0, -32, r1);
    lfs(f1, -16, r1);
  } else {
    lfd(f0, -32, r1);
    lfd(f1, -16, r1);
  }
  fcmpu(cr(0), f0, f1);

  // Lift CR0.SO and !CR0.LT into XER.OV/CA.
  // PPC bits (in 32-bit-low view): CR0.LT=0, CR0.SO=3; XER.OV=1, XER.CA=2.
  // mfocrf 0x80: both bits read (CR0.LT, CR0.SO) are inside the defined
  // field-0 nibble; the rlwinm masks discard the undefined remainder.
  mfocrf(TMP1, 0x80);
  rlwinm(TMP3, TMP1, 1, 31, 31);   // LT (PPC 0) → LSB 0
  xori(TMP3, TMP3, 1);             // !LT at LSB 0
  // Insert both bits with rlwimi (clear-and-set in one instruction; SH/MB/ME
  // derivation in DEF_OP(AdcWithFlags) above).
  //   V: source CR0.SO is at PPC bit 3 of TMP1, target XER.OV is PPC bit 1.
  //      ROTL32 by SH sends PPC q to (q - SH) mod 32, so 3 - SH ≡ 1 → SH = 2,
  //      MB = ME = 1.
  //   C: source !LT is at LSB 0 = PPC 31, target XER.CA is PPC bit 2, so
  //      31 - SH ≡ 2 → SH = 29, MB = ME = 2.
  // Both masks are a single bit, so the undefined bits mfocrf may have left
  // in TMP1 outside CR0's nibble are discarded just as the old rlwinm masks
  // discarded them.
  mfspr(TMP4, 1);                  // read XER
  rlwimi(TMP4, TMP1, 2, 1, 1);     // OV <- CR0.SO
  rlwimi(TMP4, TMP3, 29, 2, 2);    // CA <- !CR0.LT
  mtspr(1, TMP4);                  // write XER
}

// =========================================================================
// CRC32: SSE4.2 crc32 instruction. POWER8 has no crc32c hardware (POWER10
// adds vpmsumd-based variants); we route through a software CRC-32C
// (Castagnoli, polynomial 0x1EDC6F41) helper in JIT.cpp.
//
// IR sig: GPR = CRC32 GPR Src1 (accumulator), GPR Src2 (value), OpSize SrcSize.
// C sig:  uint64_t PPC64_CRC32(uint64_t Acc, uint64_t Val, uint64_t Bytes).
// =========================================================================
extern "C" uint64_t PPC64_CRC32(uint64_t Acc, uint64_t Val, uint64_t Bytes);

DEF_OP(CRC32) {
  auto Op = IROp->C<IR::IROp_CRC32>();
  const int kABISpill = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
  const auto SrcSize = Op->SrcSize;
  const auto Src1 = GetReg(Op->Src1);
  const auto Src2 = GetReg(Op->Src2);
  const auto Dst  = GetReg(Node);

  // Mini-frame (48 bytes):
  //   [r1+ 0]  back chain
  //   [r1+ 8]  TOC save
  //   [r1+16]  LR save
  //   [r1+24]  Acc arg
  //   [r1+32]  Val arg
  //   [r1+40]  result
  stdu(r1, -48, r1);
  mflr(r(0)); std(r(0), 16, r1);

  // Stage args from SRA-resident regs BEFORE SpillForABICall clobbers them.
  std(Src1, 24, r1);
  std(Src2, 32, r1);

  SpillForABICall(TMP1);

  ld(r3, 24 + kABISpill, r1);                                 // Acc
  ld(r4, 32 + kABISpill, r1);                                 // Val
  // r5 = byte count from SrcSize.
  switch (SrcSize) {
  case IR::OpSize::i8Bit:  li(r5, 1); break;
  case IR::OpSize::i16Bit: li(r5, 2); break;
  case IR::OpSize::i32Bit: li(r5, 4); break;
  case IR::OpSize::i64Bit: li(r5, 8); break;
  default:                 li(r5, 4); break;            // matches i32 fallthrough
  }

  EmitLoadPPC64Helper(r(12), PPC64_HELPER_CRC32);
  std(r2, 8 + kABISpill, r1);
  mtctr(r(12)); bctrl();
  ld(r2, 8 + kABISpill, r1);

  std(r3, 40 + kABISpill, r1);

  FillForABICall();

  ld(r(0), 16, r1); mtlr(r(0));
  ld(TMP1, 40, r1);
  addi(r1, r1, 48);
  li(r(0), 0);

  // CRC32 result is 32-bit; the IR's DestSize is i32, so zero-extend.
  rldicl(Dst, TMP1, 0, 32);
}

} // namespace FEXCore::CPU
