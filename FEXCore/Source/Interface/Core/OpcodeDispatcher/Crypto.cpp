// SPDX-License-Identifier: MIT
/*
$info$
tags: frontend|x86-to-ir, opcodes|dispatcher-implementations
desc: Handles x86/64 Crypto instructions to IR
$end_info$
*/

#include "Interface/Core/X86Tables/X86Tables.h"

#include <FEXCore/Utils/LogManager.h>
#include "Interface/Core/OpcodeDispatcher.h"

#include <cstdint>

namespace FEXCore::IR {
class OrderedNode;

#define OpcodeArgs [[maybe_unused]] FEXCore::X86Tables::DecodedOp Op

void OpDispatchBuilder::SHA1NEXTEOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  // ARMv8 SHA1 extension provides a `SHA1H` instruction which does a fixed rotate by 30.
  // This only operates on element 0 rather than element 3. We don't have the luxury of rewriting the x86 SHA algorithm to take advantage of this.
  // Move the element to zero, rotate, and then move back (Using duplicates).
  // Saves one instruction versus that path that doesn't support SHA extension.
  auto Duplicated = _VDupElement(OpSize::i128Bit, OpSize::i32Bit, Dest, 3);
  auto Sha1HRotated = _VSha1H(Duplicated);
  auto RotatedNode = _VDupElement(OpSize::i128Bit, OpSize::i32Bit, Sha1HRotated, 0);
  auto Tmp = _VAdd(OpSize::i128Bit, OpSize::i32Bit, Src, RotatedNode);
  auto Result = _VInsElement(OpSize::i128Bit, OpSize::i32Bit, 3, 3, Src, Tmp);

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA1MSG1Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  Ref NewVec = _VExtr(OpSize::i128Bit, OpSize::i64Bit, Dest, Src, 1);

  // [W0, W1, W2, W3] ^ [W2, W3, W4, W5]
  Ref Result = _VXor(OpSize::i128Bit, OpSize::i8Bit, Dest, NewVec);

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA1MSG2Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  // ARM SHA1 mostly matches x86 semantics, except the input and outputs are both flipped from elements 0,1,2,3 to 3,2,1,0.
  auto Src1 = SHADataShuffle(Dest);
  auto Src2 = SHADataShuffle(Src);

  // The result is swizzled differently than expected
  auto Result = SHADataShuffle(_VSha1SU1(Src1, Src2));

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA1RNDS4Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  const uint64_t Imm8 = Op->Src[1].Literal() & 0b11;
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  Ref Result {};
  Ref ConstantVector {};
  switch (Imm8) {
  case 0:
    ConstantVector = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_SHA1RNDS_K0);
    break;
  case 1:
    ConstantVector = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_SHA1RNDS_K1);
    break;
  case 2:
    ConstantVector = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_SHA1RNDS_K2);
    break;
  case 3:
    ConstantVector = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_SHA1RNDS_K3);
    break;
  }

  const auto ZeroRegister = LoadZeroVector(OpSize::i32Bit);

  Ref Src1 = SHADataShuffle(Dest);
  Ref Src2 = SHADataShuffle(Src);
  Src2 = _VAdd(OpSize::i128Bit, OpSize::i32Bit, Src2, ConstantVector);

  switch (Imm8) {
  case 0: Result = SHADataShuffle(_VSha1C(Src1, ZeroRegister, Src2)); break;
  case 2: Result = SHADataShuffle(_VSha1M(Src1, ZeroRegister, Src2)); break;
  case 1:
  case 3: Result = SHADataShuffle(_VSha1P(Src1, ZeroRegister, Src2)); break;
  }

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA256MSG1Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  auto Result = _VSha256U0(Dest, Src);

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA256MSG2Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);

  auto Src1 = _VExtr(OpSize::i128Bit, OpSize::i32Bit, Dest, Dest, 3);
  auto DupDst = _VDupElement(OpSize::i128Bit, OpSize::i32Bit, Dest, 3);
  auto Src2 = _VZip2(OpSize::i128Bit, OpSize::i64Bit, DupDst, Src);

  auto Result = _VSha256U1(Src1, Src2);

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::SHA256RNDS2Op(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsSHA) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  // SHA256RNDS2 implicitly reads round constants W+K from XMM0.
  auto XMM0 = LoadXMMRegister(0);

  // x86 SHA256RNDS2 advances SHA-256 state by exactly TWO rounds.  The
  // previous implementation mapped this to _VSha256H + _VSha256H2, which on
  // both ARM64 (native sha256h) and PPC64LE (Sha256Round4 software helper)
  // advance state by FOUR rounds total -- twice the correct rate.  Result:
  // SHA-256("") via sha256rnds2 produced 45d60b0c...87d9be instead of
  // NIST's e3b0c442...b852b855, breaking every TLS handshake that probes
  // CPUID and selects the SHA-NI fast path (notably the Steam launcher's
  // bundled OpenSSL 1.1).  tmp/sha_ni_test.c on POWER8 is the repro.
  //
  // Correct mapping per Intel SDM Vol.2:
  //   src1 holds {A, B, E, F} in 32-bit lanes [3, 2, 1, 0]
  //   dst  holds {C, D, G, H} in 32-bit lanes [3, 2, 1, 0]
  //   xmm0[31:0]  = WK_0 (round 0 message+key sum)
  //   xmm0[63:32] = WK_1 (round 1 message+key sum)
  // After 2 rounds, dst is overwritten with {A_2, B_2, E_2, F_2} in
  // lanes [3, 2, 1, 0].  This is host-portable: the round math is plain
  // 32-bit ALU IR, so ARM64 picks up the fix too without a dedicated
  // sha256rnds2 emitter.
  const auto i32 = OpSize::i32Bit;
  Ref A = _VExtractToGPR(OpSize::i128Bit, i32, Src,  3);
  Ref B = _VExtractToGPR(OpSize::i128Bit, i32, Src,  2);
  Ref E = _VExtractToGPR(OpSize::i128Bit, i32, Src,  1);
  Ref F = _VExtractToGPR(OpSize::i128Bit, i32, Src,  0);
  Ref C = _VExtractToGPR(OpSize::i128Bit, i32, Dest, 3);
  Ref D = _VExtractToGPR(OpSize::i128Bit, i32, Dest, 2);
  Ref G = _VExtractToGPR(OpSize::i128Bit, i32, Dest, 1);
  Ref H = _VExtractToGPR(OpSize::i128Bit, i32, Dest, 0);
  Ref WK0 = _VExtractToGPR(OpSize::i128Bit, i32, XMM0, 0);
  Ref WK1 = _VExtractToGPR(OpSize::i128Bit, i32, XMM0, 1);

  // SHA-256 mixing functions.
  auto Sigma0 = [&](Ref X) {
    return _Xor(i32,
                _Xor(i32, _Ror(i32, X, _Constant( 2)),
                          _Ror(i32, X, _Constant(13))),
                _Ror(i32, X, _Constant(22)));
  };
  auto Sigma1 = [&](Ref X) {
    return _Xor(i32,
                _Xor(i32, _Ror(i32, X, _Constant( 6)),
                          _Ror(i32, X, _Constant(11))),
                _Ror(i32, X, _Constant(25)));
  };
  auto Ch = [&](Ref X, Ref Y, Ref Z) {
    return _Xor(i32, _And(i32, X, Y),
                     _And(i32, _Not(i32, X), Z));
  };
  auto Maj = [&](Ref X, Ref Y, Ref Z) {
    return _Xor(i32,
                _Xor(i32, _And(i32, X, Y),
                          _And(i32, X, Z)),
                _And(i32, Y, Z));
  };
  auto Round = [&](Ref& A_, Ref& B_, Ref& C_, Ref& D_,
                   Ref& E_, Ref& F_, Ref& G_, Ref& H_, Ref WK) {
    // T1 = H + Sigma1(E) + Ch(E,F,G) + WK
    auto T1 = _Add(i32, _Add(i32, H_, Sigma1(E_)),
                        _Add(i32, Ch(E_, F_, G_), WK));
    // T2 = Sigma0(A) + Maj(A,B,C)
    auto T2 = _Add(i32, Sigma0(A_), Maj(A_, B_, C_));
    Ref Enew = _Add(i32, D_, T1);
    Ref Anew = _Add(i32, T1, T2);
    H_ = G_; G_ = F_; F_ = E_; E_ = Enew;
    D_ = C_; C_ = B_; B_ = A_; A_ = Anew;
  };

  Round(A, B, C, D, E, F, G, H, WK0);
  Round(A, B, C, D, E, F, G, H, WK1);

  // Pack {A_2, B_2, E_2, F_2} into output lanes [3, 2, 1, 0].
  Ref Result = LoadZeroVector(OpSize::i128Bit);
  Result = _VInsGPR(OpSize::i128Bit, i32, 3, Result, A);
  Result = _VInsGPR(OpSize::i128Bit, i32, 2, Result, B);
  Result = _VInsGPR(OpSize::i128Bit, i32, 1, Result, E);
  Result = _VInsGPR(OpSize::i128Bit, i32, 0, Result, F);

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::AESImcOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Result = _VAESImc(Src);
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::AESEncOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Result = _VAESEnc(OpSize::i128Bit, Dest, Src, LoadZeroVector(OpSize::i128Bit));
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::VAESEncOp(OpcodeArgs) {
  const auto DstSize = OpSizeFromDst(Op);
  const auto Is128Bit = DstSize == OpSize::i128Bit;

  // TODO: Handle 256-bit VAESENC.
  LOGMAN_THROW_A_FMT(Is128Bit, "256-bit VAESENC unimplemented");

  Ref State = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Key = LoadSourceFPR(Op, Op->Src[1], Op->Flags);
  Ref Result = _VAESEnc(DstSize, State, Key, LoadZeroVector(DstSize));

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::AESEncLastOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Result = _VAESEncLast(OpSize::i128Bit, Dest, Src, LoadZeroVector(OpSize::i128Bit));
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::VAESEncLastOp(OpcodeArgs) {
  const auto DstSize = OpSizeFromDst(Op);
  const auto Is128Bit = DstSize == OpSize::i128Bit;

  // TODO: Handle 256-bit VAESENCLAST.
  LOGMAN_THROW_A_FMT(Is128Bit, "256-bit VAESENCLAST unimplemented");

  Ref State = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Key = LoadSourceFPR(Op, Op->Src[1], Op->Flags);
  Ref Result = _VAESEncLast(DstSize, State, Key, LoadZeroVector(DstSize));

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::AESDecOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Result = _VAESDec(OpSize::i128Bit, Dest, Src, LoadZeroVector(OpSize::i128Bit));
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::VAESDecOp(OpcodeArgs) {
  const auto DstSize = OpSizeFromDst(Op);
  const auto Is128Bit = DstSize == OpSize::i128Bit;

  // TODO: Handle 256-bit VAESDEC.
  LOGMAN_THROW_A_FMT(Is128Bit, "256-bit VAESDEC unimplemented");

  Ref State = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Key = LoadSourceFPR(Op, Op->Src[1], Op->Flags);
  Ref Result = _VAESDec(DstSize, State, Key, LoadZeroVector(DstSize));

  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::AESDecLastOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Result = _VAESDecLast(OpSize::i128Bit, Dest, Src, LoadZeroVector(OpSize::i128Bit));
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::VAESDecLastOp(OpcodeArgs) {
  const auto DstSize = OpSizeFromDst(Op);
  const auto Is128Bit = DstSize == OpSize::i128Bit;

  // TODO: Handle 256-bit VAESDECLAST.
  LOGMAN_THROW_A_FMT(Is128Bit, "256-bit VAESDECLAST unimplemented");

  Ref State = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Key = LoadSourceFPR(Op, Op->Src[1], Op->Flags);
  Ref Result = _VAESDecLast(DstSize, State, Key, LoadZeroVector(DstSize));

  StoreResultFPR(Op, Result);
}

Ref OpDispatchBuilder::AESKeyGenAssistImpl(OpcodeArgs) {
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  const uint64_t RCON = Op->Src[1].Literal();

  auto KeyGenSwizzle = LoadAndCacheNamedVectorConstant(OpSize::i128Bit, NAMED_VECTOR_AESKEYGENASSIST_SWIZZLE);
  return _VAESKeyGenAssist(Src, KeyGenSwizzle, LoadZeroVector(OpSize::i128Bit), RCON);
}

void OpDispatchBuilder::AESKeyGenAssist(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsAES) {
    UnimplementedOp(Op);
    return;
  }

  Ref Result = AESKeyGenAssistImpl(Op);
  StoreResultFPR(Op, Result);
}

void OpDispatchBuilder::PCLMULQDQOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsPMULL_128Bit) {
    UnimplementedOp(Op);
    return;
  }
  Ref Dest = LoadSourceFPR(Op, Op->Dest, Op->Flags);
  Ref Src = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  const auto Selector = static_cast<uint8_t>(Op->Src[1].Literal());

  auto Res = _PCLMUL(OpSize::i128Bit, Dest, Src, Selector & 0b1'0001);
  StoreResultFPR(Op, Res);
}

void OpDispatchBuilder::VPCLMULQDQOp(OpcodeArgs) {
  if (!CTX->HostFeatures.SupportsPMULL_128Bit) {
    UnimplementedOp(Op);
    return;
  }
  const auto DstSize = OpSizeFromDst(Op);

  Ref Src1 = LoadSourceFPR(Op, Op->Src[0], Op->Flags);
  Ref Src2 = LoadSourceFPR(Op, Op->Src[1], Op->Flags);
  const auto Selector = static_cast<uint8_t>(Op->Src[2].Literal());

  Ref Res = _PCLMUL(DstSize, Src1, Src2, Selector & 0b1'0001);
  StoreResultFPR(Op, Res);
}

} // namespace FEXCore::IR
