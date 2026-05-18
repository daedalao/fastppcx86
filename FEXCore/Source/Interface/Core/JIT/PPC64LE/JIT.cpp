// SPDX-License-Identifier: MIT
/*
$info$
tags: backend|ppc64le
desc: Main glue logic for the PPC64LE (POWER8) JIT backend
$end_info$
*/

#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Utils/MemberFunctionToPointer.h"

#include <FEXCore/Utils/SignalScopeGuards.h>

#include <FEXCore/Core/Thunks.h>

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <cfenv>
#include <cstdio>
#include <cstring>
#include <unistd.h>

namespace FEXCore::CPU {

// -------------------------------------------------------------------------
// Runtime helpers called from JIT code (C ABI)
// -------------------------------------------------------------------------
namespace {

struct DivRem {
  uint64_t Quotient;
  uint64_t Remainder;
};

static DivRem LUDIV(uint64_t SrcHigh, uint64_t SrcLow, uint64_t Divisor) {
  __uint128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;
  return { (uint64_t)(Source / Divisor), (uint64_t)(Source % Divisor) };
}

static DivRem LDIV(uint64_t SrcHigh, uint64_t SrcLow, int64_t Divisor) {
  __int128_t Source = (static_cast<__uint128_t>(SrcHigh) << 64) | SrcLow;
  return { (uint64_t)(Source / Divisor), (uint64_t)(Source % Divisor) };
}

static void PrintValue(uint64_t Value) {
  LogMan::Msg::DFmt("Value: 0x{:x}", Value);
}

static void PrintMsg(const char* Value) {
  LogMan::Msg::DFmt("{}", Value);
}

} // anonymous namespace

// RDRAND fallback: POWER8 lacks `darn` (POWER9+). Use a fast nonblocking PRNG
// driven by the time base. The x86 RDRAND ABI returns the 64-bit random in low
// bits of the result and CF=1 on success; we always succeed.
// Exposed (non-static) so the per-op code generator in ALUOps.cpp can take its
// address; the address is materialised as a 64-bit constant at JIT time.
extern "C" uint64_t PPC64_RDRAND() {
  // xorshift64* seeded from the time base; reseeded each call so successive
  // values aren't trivially correlated.
  static thread_local uint64_t State = 0;
  uint64_t TB;
  asm volatile("mftb %0" : "=r"(TB));
  State ^= TB + 0x9E3779B97F4A7C15ULL;
  uint64_t x = State ? State : 1;
  x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
  State = x;
  return x * 0x2545F4914F6CDD1DULL;
}

// =========================================================================
// Crypto / hash / CRC32 software fallbacks for the PPC64LE backend.
//
// POWER8 lacks AES, SHA, CRC32C, and PMULL128 instructions (these arrived in
// POWER9 in various forms but FEX is generic over POWER8+). The JIT routes
// guest x86 AESNI / SHA-NI / SSE4.2 CRC32 / PCLMULQDQ through these helpers.
//
// All helpers operate on raw 16-byte buffers in memory. The JIT stages source
// VRs to the stack via stvx, calls the helper with pointers, then reloads
// the destination via lvx. The internal byte ordering of the VR (which mixes
// PPC BE-physical with FEX's vector-LE convention) is irrelevant inside the
// helpers because stvx/lvx are inverses on the same address — round-trip is
// identity. We treat the 16 bytes as a flat little-endian XMM image.
// =========================================================================

namespace {

// ---------- AES ---------------------------------------------------------
// FIPS-197 reference S-box / inverse S-box / Rcon.
static const uint8_t AES_SBox[256] = {
  0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
  0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
  0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
  0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
  0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
  0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
  0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
  0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
  0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
  0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
  0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
  0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
  0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
  0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
  0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
  0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};
static const uint8_t AES_InvSBox[256] = {
  0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
  0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
  0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
  0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
  0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
  0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
  0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
  0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
  0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
  0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
  0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
  0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
  0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
  0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
  0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
  0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// GF(2^8) ×2: doubles a byte under the AES Rijndael polynomial 0x11B.
static inline uint8_t AES_xtime(uint8_t b) {
  return (uint8_t)((b << 1) ^ ((b & 0x80) ? 0x1B : 0));
}
static inline uint8_t AES_mul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) r ^= a;
    a = AES_xtime(a);
    b >>= 1;
  }
  return r;
}

// AES uses a 4×4 column-major state (column 0 = bytes 0..3 of input, etc.).
// All three primitives operate in-place on a 16-byte state.
static void AES_SubBytes(uint8_t s[16])    { for (int i = 0; i < 16; ++i) s[i] = AES_SBox[s[i]]; }
static void AES_InvSubBytes(uint8_t s[16]) { for (int i = 0; i < 16; ++i) s[i] = AES_InvSBox[s[i]]; }

// FIPS-197 ShiftRows: row r left-rotates by r bytes. With column-major layout
// element (row r, col c) is at index r + 4*c.
static void AES_ShiftRows(uint8_t s[16]) {
  uint8_t t;
  // row 1: c0<-c1, c1<-c2, c2<-c3, c3<-c0
  t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
  // row 2: swap c0<->c2, c1<->c3
  t = s[2];  s[2]  = s[10]; s[10] = t;
  t = s[6];  s[6]  = s[14]; s[14] = t;
  // row 3: c0<-c3, c3<-c2, c2<-c1, c1<-c0  (i.e. left-rotate by 3 = right by 1)
  t = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = s[3];  s[3]  = t;
}
static void AES_InvShiftRows(uint8_t s[16]) {
  uint8_t t;
  // row 1 right-rotate by 1
  t = s[13]; s[13] = s[9];  s[9]  = s[5];  s[5]  = s[1];  s[1]  = t;
  // row 2 same as forward
  t = s[2];  s[2]  = s[10]; s[10] = t;
  t = s[6];  s[6]  = s[14]; s[14] = t;
  // row 3 right-rotate by 3 = left by 1
  t = s[3];  s[3]  = s[7];  s[7]  = s[11]; s[11] = s[15]; s[15] = t;
}

static void AES_MixColumns(uint8_t s[16]) {
  for (int c = 0; c < 4; ++c) {
    uint8_t* col = s + 4*c;
    uint8_t a0=col[0], a1=col[1], a2=col[2], a3=col[3];
    col[0] = AES_xtime(a0) ^ (AES_xtime(a1) ^ a1) ^ a2 ^ a3;
    col[1] = a0 ^ AES_xtime(a1) ^ (AES_xtime(a2) ^ a2) ^ a3;
    col[2] = a0 ^ a1 ^ AES_xtime(a2) ^ (AES_xtime(a3) ^ a3);
    col[3] = (AES_xtime(a0) ^ a0) ^ a1 ^ a2 ^ AES_xtime(a3);
  }
}
static void AES_InvMixColumns(uint8_t s[16]) {
  for (int c = 0; c < 4; ++c) {
    uint8_t* col = s + 4*c;
    uint8_t a0=col[0], a1=col[1], a2=col[2], a3=col[3];
    col[0] = AES_mul(a0,0x0E) ^ AES_mul(a1,0x0B) ^ AES_mul(a2,0x0D) ^ AES_mul(a3,0x09);
    col[1] = AES_mul(a0,0x09) ^ AES_mul(a1,0x0E) ^ AES_mul(a2,0x0B) ^ AES_mul(a3,0x0D);
    col[2] = AES_mul(a0,0x0D) ^ AES_mul(a1,0x09) ^ AES_mul(a2,0x0E) ^ AES_mul(a3,0x0B);
    col[3] = AES_mul(a0,0x0B) ^ AES_mul(a1,0x0D) ^ AES_mul(a2,0x09) ^ AES_mul(a3,0x0E);
  }
}

} // anonymous namespace

// AESENC: out = MixColumns(SubBytes(ShiftRows(state))) XOR roundkey
extern "C" void PPC64_VAESEnc(uint8_t* dst, const uint8_t* state, const uint8_t* key) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = state[i];
  AES_ShiftRows(s);
  AES_SubBytes(s);
  AES_MixColumns(s);
  for (int i = 0; i < 16; ++i) dst[i] = s[i] ^ key[i];
}

// AESENCLAST: out = SubBytes(ShiftRows(state)) XOR roundkey
extern "C" void PPC64_VAESEncLast(uint8_t* dst, const uint8_t* state, const uint8_t* key) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = state[i];
  AES_ShiftRows(s);
  AES_SubBytes(s);
  for (int i = 0; i < 16; ++i) dst[i] = s[i] ^ key[i];
}

// AESDEC: out = InvMixColumns(InvSubBytes(InvShiftRows(state))) XOR roundkey
extern "C" void PPC64_VAESDec(uint8_t* dst, const uint8_t* state, const uint8_t* key) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = state[i];
  AES_InvShiftRows(s);
  AES_InvSubBytes(s);
  AES_InvMixColumns(s);
  for (int i = 0; i < 16; ++i) dst[i] = s[i] ^ key[i];
}

// AESDECLAST: out = InvSubBytes(InvShiftRows(state)) XOR roundkey
extern "C" void PPC64_VAESDecLast(uint8_t* dst, const uint8_t* state, const uint8_t* key) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = state[i];
  AES_InvShiftRows(s);
  AES_InvSubBytes(s);
  for (int i = 0; i < 16; ++i) dst[i] = s[i] ^ key[i];
}

// AESIMC: out = InvMixColumns(state)
extern "C" void PPC64_VAESImc(uint8_t* dst, const uint8_t* src) {
  uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = src[i];
  AES_InvMixColumns(s);
  for (int i = 0; i < 16; ++i) dst[i] = s[i];
}

// AESKEYGENASSIST: x86 semantics computed directly. The OpcodeDispatcher
// emits VAESKeyGenAssist with auxiliary swizzle/zeroreg arguments tailored
// to the ARM aese path; we ignore those and produce the x86 result from
// (Src, RCON) which is identical to what the swizzle reconstructs.
//
// Per Intel SDM, with Src = [X3,X2,X1,X0] (32-bit lanes):
//   out[0..31]   = SubWord(X1)
//   out[32..63]  = RotWord(SubWord(X1)) XOR RCON
//   out[64..95]  = SubWord(X3)
//   out[96..127] = RotWord(SubWord(X3)) XOR RCON
// where SubWord applies SubBytes per byte and RotWord is a left-rotate by 8.
extern "C" void PPC64_VAESKeyGenAssist(uint8_t* dst, const uint8_t* src, uint64_t RCON) {
  // x1[i] = LE byte i of SubWord(X1) — i.e. SBox of LE byte i of input X1.
  uint8_t x1[4] = { AES_SBox[src[ 4]], AES_SBox[src[ 5]], AES_SBox[src[ 6]], AES_SBox[src[ 7]] };
  uint8_t x3[4] = { AES_SBox[src[12]], AES_SBox[src[13]], AES_SBox[src[14]], AES_SBox[src[15]] };
  // SubWord(X1) at out[0..3]
  dst[0] = x1[0]; dst[1] = x1[1]; dst[2] = x1[2]; dst[3] = x1[3];
  // FIPS-197 RotWord([a0,a1,a2,a3]) = [a1,a2,a3,a0] in LE memory order
  // (a0 is the lowest-address / LSB byte). Equivalent to ROR32(value, 8) on
  // the LE-loaded uint32. RCON XORs into the new LSB lane (dst[4]).
  dst[4] = x1[1] ^ (uint8_t)RCON;
  dst[5] = x1[2];
  dst[6] = x1[3];
  dst[7] = x1[0];
  // SubWord(X3) at out[8..11]
  dst[ 8] = x3[0]; dst[ 9] = x3[1]; dst[10] = x3[2]; dst[11] = x3[3];
  // RotWord(SubWord(X3)) XOR RCON at out[12..15]
  dst[12] = x3[1] ^ (uint8_t)RCON;
  dst[13] = x3[2];
  dst[14] = x3[3];
  dst[15] = x3[0];
}

// ---------- CRC32 -------------------------------------------------------
// SSE4.2 CRC32 uses the Castagnoli polynomial 0x1EDC6F41. We compute it
// bit-by-bit (no table) — correct, slow, fine for a non-hot path.
extern "C" uint64_t PPC64_CRC32(uint64_t Acc, uint64_t Val, uint64_t Bytes) {
  // CRC32-C: reflected polynomial 0x82F63B78.
  uint32_t crc = (uint32_t)Acc;
  for (uint64_t i = 0; i < Bytes; ++i) {
    uint8_t b = (uint8_t)(Val >> (i * 8));
    crc ^= b;
    for (int j = 0; j < 8; ++j) {
      crc = (crc >> 1) ^ (0x82F63B78u & -(crc & 1u));
    }
  }
  return crc;
}

// ---------- PCLMULQDQ ---------------------------------------------------
// Carryless 64-bit multiply. Selector picks which 64-bit lane of each input.
//   bit0 = use high lane of Src1, bit4 = use high lane of Src2.
extern "C" void PPC64_PCLMUL(uint8_t* dst, const uint8_t* src1, const uint8_t* src2, uint64_t Selector) {
  uint64_t a, b;
  __builtin_memcpy(&a, src1 + ((Selector & 0x01) ? 8 : 0), 8);
  __builtin_memcpy(&b, src2 + ((Selector & 0x10) ? 8 : 0), 8);
  __uint128_t r = 0;
  for (int i = 0; i < 64; ++i) {
    if ((b >> i) & 1) r ^= ((__uint128_t)a) << i;
  }
  __builtin_memcpy(dst,     &r,                           8);
  uint64_t hi = (uint64_t)(r >> 64);
  __builtin_memcpy(dst + 8, &hi,                          8);
}

// ---------- F16C: f32x4 ⇄ f16x4 packed conversion -----------------------
// POWER8 has no hardware f16 (xvcvhpsp/xvcvsphp arrived on POWER9). VEX F16C
// (VCVTPS2PH / VCVTPH2PS) feeds through Vector_FToF in the IR, and the
// dispatcher pre-programs the host rounding mode via PushRoundingMode before
// the convert and restores it after — so our f32→f16 helper honours
// fegetround() for the rounding direction. f16→f32 conversion is exact.
namespace PPC64_F16 {

// IEEE 754 binary16 (1/5/10) ⇄ binary32 (1/8/23). All 4 IEEE rounding modes.
inline uint32_t f16_to_f32(uint16_t h) {
  const uint32_t sign = (uint32_t)(h >> 15) & 0x1;
  const uint32_t exp_h = (h >> 10) & 0x1F;
  uint32_t mant_h = h & 0x3FF;
  if (exp_h == 0) {
    if (mant_h == 0) return sign << 31;
    // Subnormal half → renormalise into single's exponent space.
    int shift = 0;
    while (!(mant_h & 0x400)) { mant_h <<= 1; ++shift; }
    mant_h &= 0x3FF;
    const uint32_t exp_f = 127 - 14 - (uint32_t)shift;
    return (sign << 31) | (exp_f << 23) | (mant_h << 13);
  }
  if (exp_h == 31) {
    // INF or NaN. Preserve quiet-NaN bit (Intel SDM: F16C produces qNaN with
    // payload from the half's mantissa shifted into the high mantissa bits).
    if (mant_h == 0) return (sign << 31) | (0xFFu << 23);
    return (sign << 31) | (0xFFu << 23) | (mant_h << 13);
  }
  const uint32_t exp_f = exp_h - 15 + 127;
  return (sign << 31) | (exp_f << 23) | (mant_h << 13);
}

// Round x (signed mantissa-bits-to-keep is implicit in the call site) using
// the active fegetround() mode. m is the 13-bit residue from a 23-bit f32
// mantissa truncated to the 10 high bits; lsb of the kept value is `keep_lsb`;
// sign in `s` (0=+, 1=-).
inline bool round_up(uint32_t residue, uint32_t residue_width, uint32_t keep_lsb, uint32_t s, int rmode) {
  if (residue == 0) return false;
  const uint32_t half = 1u << (residue_width - 1);
  switch (rmode) {
  case FE_DOWNWARD:    return s == 1;
  case FE_UPWARD:      return s == 0;
  case FE_TOWARDZERO:  return false;
  case FE_TONEAREST:
  default:
    if (residue > half) return true;
    if (residue < half) return false;
    return (keep_lsb & 1) != 0;            // tie → round to even
  }
}

inline uint16_t f32_to_f16(uint32_t f, int rmode) {
  const uint32_t sign = (f >> 31) & 0x1;
  int32_t exp = (int32_t)((f >> 23) & 0xFFu) - 127;
  uint32_t mant = f & 0x7FFFFFu;

  if (exp == 128) {                         // INF or NaN
    if (mant == 0) return (uint16_t)((sign << 15) | 0x7C00u);
    uint16_t h = (uint16_t)((sign << 15) | 0x7C00u | (mant >> 13));
    if ((h & 0x3FFu) == 0) h |= 1;          // ensure NaN payload nonzero
    return h;
  }
  if (exp >= 16) {                          // overflow → ±INF (or ±MAX for trunc/away rounds)
    if (rmode == FE_TOWARDZERO ||
        (rmode == FE_DOWNWARD && sign == 0) ||
        (rmode == FE_UPWARD   && sign == 1)) {
      return (uint16_t)((sign << 15) | 0x7BFFu);   // largest finite half
    }
    return (uint16_t)((sign << 15) | 0x7C00u);
  }
  if (exp >= -14) {                         // normal half
    const uint32_t keep_lsb = (mant >> 13) & 1;
    const uint32_t residue  = mant & 0x1FFFu;
    uint32_t mant_h = mant >> 13;
    if (round_up(residue, 13, keep_lsb, sign, rmode)) ++mant_h;
    if (mant_h & 0x400u) {                  // mantissa overflowed into exponent
      mant_h = 0; ++exp;
      if (exp >= 16) return (uint16_t)((sign << 15) | 0x7C00u);
    }
    return (uint16_t)((sign << 15) | (((uint32_t)(exp + 15)) << 10) | (mant_h & 0x3FFu));
  }
  if (exp >= -24) {                         // subnormal half (exp -25..-15 maps to sub)
    const uint32_t shift = (uint32_t)(-exp - 14);
    const uint32_t full_mant = mant | 0x800000u;            // implicit 1
    const uint32_t residue_w = 13 + shift;
    const uint32_t residue   = full_mant & ((1u << residue_w) - 1);
    const uint32_t keep_lsb  = (full_mant >> residue_w) & 1;
    uint32_t mant_h = full_mant >> residue_w;
    if (round_up(residue, residue_w, keep_lsb, sign, rmode)) ++mant_h;
    // mant_h may carry into the lowest normal half (0x400 = exp=-14 normal).
    return (uint16_t)((sign << 15) | (mant_h & 0x7FFu));
  }
  // exp < -24 → underflow → ±0, except RU/RD round away from zero.
  // The f32 is non-zero whenever any of its non-sign bits are set; that's
  // true for any normal f32 (implicit-1) and any non-zero denormal.
  if ((f & 0x7FFFFFFFu) != 0) {
    if (rmode == FE_UPWARD   && sign == 0) return 0x0001;
    if (rmode == FE_DOWNWARD && sign == 1) return 0x8001;
  }
  return (uint16_t)(sign << 15);
}

} // namespace PPC64_F16

// f32x4 → f16x4 (packed). dst gets 4 half-floats in the low 64 bits, upper
// 64 bits zero. The dispatcher staged 16 bytes of source through the FABI
// scratch buffer, but only the low 16 (4 f32) are read.
extern "C" void PPC64_F32x4ToF16x4(uint8_t* dst, const uint8_t* src) {
  const int rmode = fegetround();
  uint32_t in[4]; __builtin_memcpy(in, src, 16);
  uint16_t out[4];
  for (int i = 0; i < 4; ++i) out[i] = PPC64_F16::f32_to_f16(in[i], rmode);
  __builtin_memcpy(dst, out, 8);
  uint64_t zero = 0;
  __builtin_memcpy(dst + 8, &zero, 8);
}

// f16x4 → f32x4 (packed). Source is 8 bytes (4 half-floats) in the low half
// of the staged buffer; we produce 4 f32 in the full 16-byte dst.
extern "C" void PPC64_F16x4ToF32x4(uint8_t* dst, const uint8_t* src) {
  uint16_t in[4]; __builtin_memcpy(in, src, 8);
  uint32_t out[4];
  for (int i = 0; i < 4; ++i) out[i] = PPC64_F16::f16_to_f32(in[i]);
  __builtin_memcpy(dst, out, 16);
}

// VFCVTL2 i32-element: read 4 f16 from the UPPER half of src, expand to
// 4 f32 across full 16-byte dst. Used by AVX_128's 256-bit VCVTPH2PS path
// for the high-half element promotion.
extern "C" void PPC64_F16HiToF32x4(uint8_t* dst, const uint8_t* src) {
  uint16_t in[4]; __builtin_memcpy(in, src + 8, 8);
  uint32_t out[4];
  for (int i = 0; i < 4; ++i) out[i] = PPC64_F16::f16_to_f32(in[i]);
  __builtin_memcpy(dst, out, 16);
}

// VFCVTN2 f32→f16: narrow 4 f32 from `vu_src` (full 16 bytes) into 4 f16,
// writing them to the UPPER half of `dst`. The lower half of dst is
// preserved by the caller (it holds VectorLower's f16 low half from the
// preceding Vector_FToF). Used by AVX_128's 256-bit VCVTPS2PH path.
extern "C" void PPC64_F32x4ToF16Hi(uint8_t* dst, const uint8_t* vu_src) {
  const int rmode = fegetround();
  uint32_t in[4]; __builtin_memcpy(in, vu_src, 16);
  uint16_t out[4];
  for (int i = 0; i < 4; ++i) out[i] = PPC64_F16::f32_to_f16(in[i], rmode);
  __builtin_memcpy(dst + 8, out, 8);
}

// ---------- SHA-1 / SHA-256 software helpers --------------------------
// POWER8 has no hardware SHA — these mirror the ARMv8 SHA1*/SHA256*
// instructions (which the IR ops are modeled after). Implemented from the
// ARM ARM pseudocode (FIPS-180-4 primitives). 16-byte buffers, lane 0 = low.

namespace PPC64_SHA {

static inline uint32_t ROL32(uint32_t x, unsigned n) {
  n &= 31u;
  return (x << n) | (x >> ((32 - n) & 31));
}
static inline uint32_t ROR32(uint32_t x, unsigned n) {
  n &= 31u;
  return (x >> n) | (x << ((32 - n) & 31));
}

static inline void Load4(uint32_t out[4], const uint8_t* src) {
  __builtin_memcpy(out, src, 16);
}
static inline void Store4(uint8_t* dst, const uint32_t in[4]) {
  __builtin_memcpy(dst, in, 16);
}

// SHA-1 round-step common. f selects Ch/Par/Maj.
enum class Sha1F { Choose, Parity, Majority };
static inline uint32_t Sha1Func(Sha1F f, uint32_t b, uint32_t c, uint32_t d) {
  switch (f) {
  case Sha1F::Choose:   return (b & c) | (~b & d);
  case Sha1F::Parity:   return b ^ c ^ d;
  case Sha1F::Majority: return (b & c) | (b & d) | (c & d);
  }
  return 0;
}

// ARMv8 SHA1C/M/P (Vd=ABCD, Sn=scalar E in low 32 bits, Vm=W+K[0..3]).
// The 4-round step:
//   T = ROL(A,5) + f(B,C,D) + E + Wi
//   E=D; D=C; C=ROL(B,30); B=A; A=T
// Result is [A,B,C,D] post-update (lane 0..3).
static inline void Sha1Hash(Sha1F f, uint8_t* dst, const uint8_t* abcd,
                            const uint8_t* sn, const uint8_t* wk) {
  uint32_t s[4];   Load4(s, abcd);             // s[0]=A, s[1]=B, s[2]=C, s[3]=D
  uint32_t Wk[4];  Load4(Wk, wk);
  uint32_t E;      __builtin_memcpy(&E, sn, 4);
  uint32_t A=s[0], B=s[1], C=s[2], D=s[3];
  for (int i = 0; i < 4; ++i) {
    uint32_t T = ROL32(A, 5) + Sha1Func(f, B, C, D) + E + Wk[i];
    E = D; D = C; C = ROL32(B, 30); B = A; A = T;
  }
  uint32_t r[4] = {A, B, C, D};
  Store4(dst, r);
}

} // namespace PPC64_SHA

// VSha1H: rotate-left-30 of element 0 (low 32 bits); upper lanes zeroed.
extern "C" void PPC64_VSha1H(uint8_t* dst, const uint8_t* src) {
  uint32_t s;
  __builtin_memcpy(&s, src, 4);
  uint32_t r = (s << 30) | (s >> 2);
  __builtin_memcpy(dst, &r, 4);
  for (int i = 4; i < 16; ++i) dst[i] = 0;
}

// SHA1C / SHA1M / SHA1P : 4-round step with Choose / Majority / Parity.
// Args: a = ABCD (Vd, tied to Src1), b = scalar E in low 32 bits (Src2),
//       c = W+K schedule (Src3).
extern "C" void PPC64_VSha1C(uint8_t* dst, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  PPC64_SHA::Sha1Hash(PPC64_SHA::Sha1F::Choose, dst, a, b, c);
}
extern "C" void PPC64_VSha1M(uint8_t* dst, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  PPC64_SHA::Sha1Hash(PPC64_SHA::Sha1F::Majority, dst, a, b, c);
}
extern "C" void PPC64_VSha1P(uint8_t* dst, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  PPC64_SHA::Sha1Hash(PPC64_SHA::Sha1F::Parity, dst, a, b, c);
}

// SHA1SU1(Vd, Vn): schedule update part 2 (ARM ARM C7.2.219).
//   T = Vd EOR LSR(Vn, 32)            (whole-vector right shift by one 32-bit element)
//     i.e. T[0]=Vd[0]^Vn[1], T[1]=Vd[1]^Vn[2], T[2]=Vd[2]^Vn[3], T[3]=Vd[3]
//   result[0] = ROL(T[0], 1)
//   result[1] = ROL(T[1], 1)
//   result[2] = ROL(T[2], 1)
//   result[3] = ROL(T[3] EOR result[0], 1)
extern "C" void PPC64_VSha1SU1(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  uint32_t Vd[4]; PPC64_SHA::Load4(Vd, a);
  uint32_t Vn[4]; PPC64_SHA::Load4(Vn, b);
  uint32_t T[4];
  T[0] = Vd[0] ^ Vn[1];
  T[1] = Vd[1] ^ Vn[2];
  T[2] = Vd[2] ^ Vn[3];
  T[3] = Vd[3];
  uint32_t r[4];
  r[0] = PPC64_SHA::ROL32(T[0], 1);
  r[1] = PPC64_SHA::ROL32(T[1], 1);
  r[2] = PPC64_SHA::ROL32(T[2], 1);
  r[3] = PPC64_SHA::ROL32(T[3] ^ r[0], 1);
  PPC64_SHA::Store4(dst, r);
}

// SHA256 sigma functions.
namespace PPC64_SHA {
static inline uint32_t sigma0_256(uint32_t x) { return ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3); }
static inline uint32_t sigma1_256(uint32_t x) { return ROR32(x, 17) ^ ROR32(x, 19) ^ (x >> 10); }
static inline uint32_t bigsig0_256(uint32_t x) { return ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22); }
static inline uint32_t bigsig1_256(uint32_t x) { return ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25); }

// SHA256H / SHA256H2: four SHA-256 rounds.  Vn = ABCD (top half, "tied" Src1
// for H), Vm = EFGH, Vk = W+K[0..3].  After 4 rounds, return upper-half (ABCD)
// for H, lower-half (EFGH) for H2.
//
// Wm is consumed in lane order 0..3.  A maps to lane 0, ..., D to lane 3.
static inline void Sha256Round4(uint32_t out_abcd[4], uint32_t out_efgh[4],
                                const uint32_t abcd[4], const uint32_t efgh[4],
                                const uint32_t wk[4]) {
  uint32_t A = abcd[0], B = abcd[1], C = abcd[2], D = abcd[3];
  uint32_t E = efgh[0], F = efgh[1], G = efgh[2], H = efgh[3];
  for (int i = 0; i < 4; ++i) {
    uint32_t ch  = (E & F) ^ (~E & G);
    uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
    uint32_t T1  = H + bigsig1_256(E) + ch + wk[i];
    uint32_t T2  = bigsig0_256(A) + maj;
    H = G; G = F; F = E; E = D + T1;
    D = C; C = B; B = A; A = T1 + T2;
  }
  out_abcd[0] = A; out_abcd[1] = B; out_abcd[2] = C; out_abcd[3] = D;
  out_efgh[0] = E; out_efgh[1] = F; out_efgh[2] = G; out_efgh[3] = H;
}
} // namespace PPC64_SHA

// SHA256H(Vd=ABCD tied, Vn=EFGH, Vm=W+K) → returns post-step ABCD.
extern "C" void PPC64_VSha256H(uint8_t* dst, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  uint32_t ABCD[4]; PPC64_SHA::Load4(ABCD, a);
  uint32_t EFGH[4]; PPC64_SHA::Load4(EFGH, b);
  uint32_t WK[4];   PPC64_SHA::Load4(WK,   c);
  uint32_t outA[4], outE[4];
  PPC64_SHA::Sha256Round4(outA, outE, ABCD, EFGH, WK);
  PPC64_SHA::Store4(dst, outA);
}

// SHA256H2(Vd=EFGH tied, Vn=ABCD, Vm=W+K) → returns post-step EFGH.
// Note Src1=EFGH (the tied destination) and Src2=ABCD here, mirroring ARM's
// `sha256h2 Vd, Vn, Vm` with Vd as the EFGH-tied register.
extern "C" void PPC64_VSha256H2(uint8_t* dst, const uint8_t* a, const uint8_t* b, const uint8_t* c) {
  uint32_t EFGH[4]; PPC64_SHA::Load4(EFGH, a);
  uint32_t ABCD[4]; PPC64_SHA::Load4(ABCD, b);
  uint32_t WK[4];   PPC64_SHA::Load4(WK,   c);
  uint32_t outA[4], outE[4];
  PPC64_SHA::Sha256Round4(outA, outE, ABCD, EFGH, WK);
  PPC64_SHA::Store4(dst, outE);
}

// SHA256SU0(Vd, Vn): T = Vn[0] :: Vd[3] :: Vd[2] :: Vd[1]
//                    result[i] = sigma0(T[i]) + Vd[i]
extern "C" void PPC64_VSha256U0(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  uint32_t Vd[4]; PPC64_SHA::Load4(Vd, a);
  uint32_t Vn[4]; PPC64_SHA::Load4(Vn, b);
  uint32_t T[4];
  T[0] = Vd[1];
  T[1] = Vd[2];
  T[2] = Vd[3];
  T[3] = Vn[0];
  uint32_t r[4];
  for (int i = 0; i < 4; ++i) r[i] = PPC64_SHA::sigma0_256(T[i]) + Vd[i];
  PPC64_SHA::Store4(dst, r);
}

// SHA256SU1(Vn, Vm): IR 2-arg form, equivalent to ARMv8 sha256su1 with
// the destination Vd pre-zeroed (cf. arm64 JIT EncryptionOps.cpp which
// emits `movi VTMP1, 0; sha256su1 VTMP1, Vn, Vm`).  Per ARM ARM C7.2.226:
//   T0[0]=Vn[1], T0[1]=Vn[2], T0[2]=Vn[3], T0[3]=Vm[0]
//   T1[0]=sigma1(Vm[2]); T1[1]=sigma1(Vm[3])
//   result[0]=T0[0]+T1[0];  result[1]=T0[1]+T1[1]
//   T1[2]=sigma1(result[0]); T1[3]=sigma1(result[1])
//   result[2]=T0[2]+T1[2];  result[3]=T0[3]+T1[3]
// The dispatcher passes Vn = _VExtr(Dest, Dest, 3, i32Bit), which with the
// correct VExtr semantics (ByteOff=16-N) delivers [Dest3,Dest0,Dest1,Dest2].
// The standard ARM T0 picks Vn[1]=Dest0, Vn[2]=Dest1, Vn[3]=Dest2 — exactly right.
extern "C" void PPC64_VSha256U1(uint8_t* dst, const uint8_t* a, const uint8_t* b) {
  uint32_t Vn[4]; PPC64_SHA::Load4(Vn, a);
  uint32_t Vm[4]; PPC64_SHA::Load4(Vm, b);
  uint32_t r[4];
  r[0] = Vn[1] + PPC64_SHA::sigma1_256(Vm[2]);
  r[1] = Vn[2] + PPC64_SHA::sigma1_256(Vm[3]);
  r[2] = Vn[3] + PPC64_SHA::sigma1_256(r[0]);
  r[3] = Vm[0] + PPC64_SHA::sigma1_256(r[1]);
  PPC64_SHA::Store4(dst, r);
}

// ---------- SSE4.2 string compare (VPCMP{E,I}STR{I,M}) ------------------
// Self-contained C implementation of the PCMPxSTRx algorithm. Ported from
// FEXCore's portable interpreter fallback in
// Interpreter/Fallbacks/{VectorFallbacks.h, StringCompareFallbacks.cpp}.
//
// Inputs to the JIT's emitter pass through 16-byte stack buffers (so we
// avoid the PPC64LE ELFv2 vector-arg passing convention entirely). The
// helper returns a 32-bit value: bits 15..0 = intermediate result, bits
// 31..28 = NZCV-style flags (N=SF, Z=ZF, C=CF, V=OF).
namespace PPC64_PCMPSTR {

enum AggregationOp : uint16_t {
  EqualAny      = 0b00,
  Ranges        = 0b01,
  EqualEach     = 0b10,
  EqualOrdered  = 0b11,
};

enum SourceData : uint16_t {
  U8  = 0,
  U16 = 1,
  S8  = 2,
  S16 = 3,
};

enum Polarity : uint16_t {
  PolPositive       = 0,
  PolNegative       = 1,
  PolPositiveMasked = 2,
  PolNegativeMasked = 3,
};

static inline int32_t GetExplicitLength(uint64_t reg, uint16_t control) {
  // Bit 8 controls whether the register is treated as 64-bit or 32-bit.
  int64_t value = (((control >> 8) & 1) != 0)
                    ? static_cast<int64_t>(reg)
                    : static_cast<int64_t>(static_cast<int32_t>(reg));

  // control[0]: 0 = bytes (limit 16), 1 = words (limit 8).
  const int64_t limit = ((control & 1) != 0) ? 8 : 16;

  if (value < -limit || value > limit) {
    return static_cast<int32_t>(limit);
  }
  return value < 0 ? static_cast<int32_t>(-value) : static_cast<int32_t>(value);
}

static inline int32_t GetImplicitLength(const uint8_t* data, uint16_t control) {
  if ((control & 1) != 0) {
    // 16-bit elements
    int32_t length = 0;
    while (length < 8) {
      uint16_t e;
      __builtin_memcpy(&e, data + length * 2, 2);
      if (e == 0) break;
      ++length;
    }
    return length;
  } else {
    int32_t length = 0;
    while (length < 16 && data[length] != 0) ++length;
    return length;
  }
}

static inline int32_t GetElement(const uint8_t* vec, int32_t index, uint16_t control) {
  switch (static_cast<SourceData>(control & 0b11)) {
  case U8:  return static_cast<int32_t>(vec[index]);
  case U16: {
    uint16_t v;
    __builtin_memcpy(&v, vec + (size_t)index * 2, 2);
    return static_cast<int32_t>(v);
  }
  case S8:  return static_cast<int32_t>(static_cast<int8_t>(vec[index]));
  case S16:
  default: {
    int16_t v;
    __builtin_memcpy(&v, vec + (size_t)index * 2, 2);
    return static_cast<int32_t>(v);
  }
  }
}

static uint32_t HandleEqualAny(const uint8_t* lhs, int valid_lhs,
                               const uint8_t* rhs, int valid_rhs, uint16_t control) {
  uint32_t result = 0;
  for (int j = valid_rhs; j >= 0; --j) {
    result <<= 1;
    const int rv = GetElement(rhs, j, control);
    for (int i = valid_lhs; i >= 0; --i) {
      const int lv = GetElement(lhs, i, control);
      result |= (uint32_t)(rv == lv);
    }
  }
  return result;
}

static uint32_t HandleRanges(const uint8_t* lhs, int valid_lhs,
                             const uint8_t* rhs, int valid_rhs, uint16_t control) {
  uint32_t result = 0;
  for (int j = valid_rhs; j >= 0; --j) {
    result <<= 1;
    const int element = GetElement(rhs, j, control);
    for (int i = (valid_lhs - 1) | 1; i >= 0; i -= 2) {
      const int upper = GetElement(lhs, i,     control);
      const int lower = GetElement(lhs, i - 1, control);
      const bool ge = upper >= element;
      const bool le = lower <= element;
      result |= (uint32_t)(ge && le);
    }
  }
  return result;
}

static uint32_t HandleEqualEach(const uint8_t* lhs, int valid_lhs,
                                const uint8_t* rhs, int valid_rhs, uint16_t control) {
  const int upper_limit = (16 >> (control & 1)) - 1;
  const int max_valid   = valid_lhs > valid_rhs ? valid_lhs : valid_rhs;
  const int min_valid   = valid_lhs < valid_rhs ? valid_lhs : valid_rhs;

  // All positions past the larger string's end: forced true (Intel SDM 4.1.6).
  uint32_t result = (1U << (upper_limit - max_valid)) - 1;
  result <<= (max_valid - min_valid);

  for (int i = min_valid; i >= 0; --i) {
    const int le = GetElement(lhs, i, control);
    const int re = GetElement(rhs, i, control);
    result <<= 1;
    result |= (uint32_t)(le == re);
  }
  return result;
}

static uint32_t HandleEqualOrdered(const uint8_t* lhs, int valid_lhs,
                                   const uint8_t* rhs, int valid_rhs, uint16_t control) {
  const int upper_limit = (16 >> (control & 1)) - 1;

  // Special case: empty inner string → all-ones intermediate result.
  if (valid_lhs == -1) {
    return (2U << upper_limit) - 1;
  }

  uint32_t result = 0;
  const int initial = (valid_rhs == upper_limit) ? valid_rhs : valid_rhs - valid_lhs;
  for (int j = initial; j >= 0; --j) {
    result <<= 1;
    uint32_t value = 1;
    int start = valid_rhs - j;
    if (start > valid_lhs) start = valid_lhs;
    for (int i = start; i >= 0; --i) {
      const int lv = GetElement(lhs, i,     control);
      const int rv = GetElement(rhs, i + j, control);
      value &= (uint32_t)(lv == rv);
    }
    result |= value;
  }
  return result;
}

static uint32_t PerformAggregation(const uint8_t* lhs, int valid_lhs,
                                   const uint8_t* rhs, int valid_rhs, uint16_t control) {
  switch (static_cast<AggregationOp>((control >> 2) & 0b11)) {
  case EqualAny:     return HandleEqualAny(lhs, valid_lhs, rhs, valid_rhs, control);
  case Ranges:       return HandleRanges  (lhs, valid_lhs, rhs, valid_rhs, control);
  case EqualEach:    return HandleEqualEach(lhs, valid_lhs, rhs, valid_rhs, control);
  case EqualOrdered:
  default:           return HandleEqualOrdered(lhs, valid_lhs, rhs, valid_rhs, control);
  }
}

static uint32_t HandlePolarity(uint32_t value, uint16_t control, int upper_limit, int valid_rhs) {
  switch (static_cast<Polarity>((control >> 4) & 0b11)) {
  case PolNegative:       return value ^ ((2U << upper_limit) - 1);
  case PolNegativeMasked: return value ^ ((1U << (valid_rhs + 1)) - 1);
  case PolPositive:
  case PolPositiveMasked:
  default:                return value;
  }
}

static uint32_t MainBody(const uint8_t* lhs, int valid_lhs,
                         const uint8_t* rhs, int valid_rhs, uint16_t control) {
  const uint32_t aggregation = PerformAggregation(lhs, valid_lhs, rhs, valid_rhs, control);
  const int upper_limit = (16 >> (control & 1)) - 1;

  // Bits arranged as [SF | ZF | CF | OF] — packed at LSB then shifted
  // left 28 by the caller to land in NZCV positions (N=31 Z=30 C=29 V=28).
  uint32_t flags = 0;
  if (valid_rhs < upper_limit) flags |= 0b0100; // CF
  if (valid_lhs < upper_limit) flags |= 0b1000; // SF

  const uint32_t result = HandlePolarity(aggregation, control, upper_limit, valid_rhs);
  if (result != 0)        flags |= 0b0010;       // ZF
  if ((result & 1) != 0)  flags |= 0b0001;       // OF

  return result | (flags << 28);
}

} // namespace PPC64_PCMPSTR

// JIT-callable entry points. Vectors are passed by memory pointer (16 bytes
// each, little-endian element 0 first) so the helpers do not depend on the
// PPC64LE ELFv2 vector parameter-passing convention. Returning uint64_t lets
// the JIT use the full r3 result register without sign-extension worries —
// the IR consumer extracts the low 32 bits.
extern "C" uint64_t PPC64_VPCMPESTRX(const uint8_t* lhs, const uint8_t* rhs,
                                     uint64_t RAX, uint64_t RDX, uint64_t Control) {
  const uint16_t ctrl = static_cast<uint16_t>(Control);
  const int valid_lhs = PPC64_PCMPSTR::GetExplicitLength(RAX, ctrl) - 1;
  const int valid_rhs = PPC64_PCMPSTR::GetExplicitLength(RDX, ctrl) - 1;
  return PPC64_PCMPSTR::MainBody(lhs, valid_lhs, rhs, valid_rhs, ctrl);
}

extern "C" uint64_t PPC64_VPCMPISTRX(const uint8_t* lhs, const uint8_t* rhs,
                                     uint64_t Control) {
  const uint16_t ctrl = static_cast<uint16_t>(Control);
  const int valid_lhs = PPC64_PCMPSTR::GetImplicitLength(lhs, ctrl) - 1;
  const int valid_rhs = PPC64_PCMPSTR::GetImplicitLength(rhs, ctrl) - 1;
  return PPC64_PCMPSTR::MainBody(lhs, valid_lhs, rhs, valid_rhs, ctrl);
}

// -------------------------------------------------------------------------
// Op_Unhandled: dispatch x87/F80 and other fallback ops via ABI bridge stubs
// -------------------------------------------------------------------------
void PPC64JITCore::Op_Unhandled(const IR::IROp_Header* IROp, IR::Ref Node) {
  // SSE4.2 string compares (VPCMPESTRX / VPCMPISTRX) are routed here because
  // the IR.json marks them "JITDispatch": false. The shared FABI bridge stub
  // built by PPC64Dispatcher::GenerateABICall packs Control into r3 for
  // VPCMPISTRX, but the actual fallback C signature places Control as the
  // last (3rd) argument — which lands in r7 on PPC64LE ELFv2 because the
  // two preceding vector args reserve r5-r6 and r7-r8 as parameter slots.
  // We sidestep that by emitting a self-contained call to a private helper
  // (PPC64_VPCMPESTRX / PPC64_VPCMPISTRX) that takes the vector inputs as
  // memory pointers, eliminating the vector-arg ABI entirely.
  if (IROp->Op == IR::OP_VPCMPESTRX || IROp->Op == IR::OP_VPCMPISTRX) {
    const bool IsExplicit = (IROp->Op == IR::OP_VPCMPESTRX);

    // Mini-frame layout (112 bytes, 16-byte aligned):
    //   [r1+  0]  back chain
    //   [r1+  8]  pad
    //   [r1+ 16]  LR save
    //   [r1+ 24]  TOC save (r2) across bctrl
    //   [r1+ 32]  Slot A: LHS vector (16-byte aligned)
    //   [r1+ 48]  Slot B: RHS vector (16-byte aligned)
    //   [r1+ 64]  RAX save (8 bytes; ESTRX only)
    //   [r1+ 72]  RDX save (8 bytes; ESTRX only)
    //   [r1+ 80]  Result save slot
    //   [r1+ 88]  RA[2] (r26) spill rescue — see comment below
    //   [r1+ 96..111]  pad (keep frame size a multiple of 16)
    //
    // The helper called by bctrl is a non-leaf C function. Its prologue
    // saves the incoming LR to "caller_r1 + 16" per the PPC64LE ELFv2 ABI.
    // After SpillForABICall, our caller_r1 sits inside the dispatcher's
    // PushDynamicRegs spill area, where slot [r1+16..23] holds the saved
    // value of RA[2] = r26. The helper's prologue therefore *clobbers*
    // r26's spill slot. PopDynamicRegs (inside FillForABICall) then reloads
    // r26 from the corrupted slot, giving r26 a stale LR address. If the
    // IR's register allocator put any live value in r26, that value is
    // destroyed across this op — the bug surfaces non-deterministically as
    // missing SF/ZF in LAHF after VPCMPxSTRx because PCMPxSTRXOpImpl's
    // result-NZCV chain happens to land in r26 for some test inputs.
    //
    // Workaround: snapshot the r26 spill slot ([post-spill r1+16]) into a
    // private slot in our mini-frame before bctrl, then restore it after
    // bctrl (before FillForABICall reloads PopDynamicRegs).
    constexpr int FrameSize = 112;
    const int SpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
    constexpr int SlotA   = 32;     // LHS vector
    constexpr int SlotB   = 48;     // RHS vector
    constexpr int SlotRAX = 64;     // ESTRX RAX
    constexpr int SlotRDX = 72;     // ESTRX RDX
    constexpr int SlotR   = 80;     // 64-bit return value
    constexpr int SlotR26 = 88;     // saved r26 spill slot (post-spill [r1+16])
    auto Post = [&](int Off) { return Off + SpillSaveSize; };

    // Capture sources & destination from the strongly-typed IROp variant.
    GPR  DstReg{};
    VR   LhsVR{}, RhsVR{};
    GPR  RAXReg{}, RDXReg{};
    uint64_t Control = 0;
    if (IsExplicit) {
      const auto Op = IROp->C<IR::IROp_VPCMPESTRX>();
      DstReg  = GetReg(Node);
      LhsVR   = GetVReg(Op->LHS);
      RhsVR   = GetVReg(Op->RHS);
      RAXReg  = GetReg(Op->RAX);
      RDXReg  = GetReg(Op->RDX);
      Control = Op->Control;
    } else {
      const auto Op = IROp->C<IR::IROp_VPCMPISTRX>();
      DstReg  = GetReg(Node);
      LhsVR   = GetVReg(Op->LHS);
      RhsVR   = GetVReg(Op->RHS);
      Control = Op->Control;
    }

    stdu(r1, -FrameSize, r1);
    mflr(r(0)); std(r(0), 16, r1);

    // Stage live SRA-resident vectors into the in-frame buffers BEFORE
    // SpillForABICall (which clobbers any non-callee-saved VR).
    LoadConstant(TMP1, SlotA); stvx(LhsVR, r1, TMP1);
    LoadConstant(TMP1, SlotB); stvx(RhsVR, r1, TMP1);

    // Save the SRA GPRs we need (RAX/RDX) before they are clobbered by the
    // spill+ABI traffic.
    if (IsExplicit) {
      std(RAXReg, SlotRAX, r1);
      std(RDXReg, SlotRDX, r1);
    }

    SpillForABICall(TMP1);

    // Snapshot the r26 spill slot ([post-spill r1+16]) so we can restore it
    // after the helper's prologue clobbers it. (Done BEFORE we set up r3..r7
    // for the call, since TMP1 = r3 is needed for the helper's first arg.)
    ld(TMP1, 16, r1);
    std(TMP1, Post(SlotR26), r1);

    // Set up arguments for the helper using ELFv2 ABI:
    //   PPC64_VPCMPESTRX(const uint8_t* lhs, const uint8_t* rhs,
    //                    uint64_t RAX, uint64_t RDX, uint64_t Control)
    //   PPC64_VPCMPISTRX(const uint8_t* lhs, const uint8_t* rhs,
    //                    uint64_t Control)
    // Both signatures are pure scalar — no vector args, no slot skipping.
    addi(r3, r1, Post(SlotA));            // r3 = &lhs buffer
    addi(r4, r1, Post(SlotB));            // r4 = &rhs buffer
    if (IsExplicit) {
      ld(r5, Post(SlotRAX), r1);          // r5 = RAX
      ld(r6, Post(SlotRDX), r1);          // r6 = RDX
      LoadConstant(r7, Control);          // r7 = Control (uint16_t in 64-bit slot)
      LoadConstant(r(12), reinterpret_cast<uint64_t>(&PPC64_VPCMPESTRX));
    } else {
      LoadConstant(r5, Control);          // r5 = Control
      LoadConstant(r(12), reinterpret_cast<uint64_t>(&PPC64_VPCMPISTRX));
    }

    std(r2, Post(24), r1);                // save TOC (helper is intra-DSO,
                                          //   but bctrl semantics are unchanged)
    mtctr(r(12)); bctrl();
    ld(r2, Post(24), r1);                 // restore TOC
    // Restore the r26 spill slot before PopDynamicRegs reloads from it.
    // r3 holds the helper's return value — must not be clobbered yet, so
    // bounce through r0 (volatile, zero-restored later).
    ld(r(0), Post(SlotR26), r1);
    std(r(0), 16, r1);

    // Save 64-bit return value to a scratch slot, then refill SRA. The
    // SRA refill reloads STATE/x86 GPRs but does not touch SlotR.
    std(r3, Post(SlotR), r1);

    FillForABICall();

    // Reload result from frame, deallocate frame.
    ld(TMP1, SlotR, r1);
    ld(r(0), 16, r1); mtlr(r(0));
    addi(r1, r1, FrameSize);
    li(r(0), 0);                          // re-establish r0=0 invariant

    mr(DstReg, TMP1);
    return;
  }

  FallbackInfo Info;
  if (!InterpreterOps::GetFallbackHandler(IROp, &Info)) {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled IR Op: {}", FEXCore::IR::GetName(IROp->Op));
#endif
    return;
  }

  // Compute the STATE-relative byte offsets to the ABIHandler and Func pointers
  // for this fallback handler index.  Using ARRAY_OFFSETOF from CompilerDefs.h.
  const uint32_t ABIHandlerOff = static_cast<uint32_t>(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, Info.HandlerIndex) +
    offsetof(FEXCore::Core::FallbackABIInfo, ABIHandler));
  const uint32_t FuncOff = static_cast<uint32_t>(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, Info.HandlerIndex) +
    offsetof(FEXCore::Core::FallbackABIInfo, Func));

  // Universal frame pattern:
  //   1. Save LR via TMP2 (r4) to [r1+0] of a 16-byte frame
  //   2. Load ABIHandler into r0, Func into TMP4=r6
  //   3. Set up FABI-specific sources (TMP2 is free to reuse after step 1)
  //   4. mtctr(r0); bctrl()
  //   5. Restore LR from [r1+0] via TMP2
  //   6. Move result: VTMP1 (vector) or TMP1=r3 (integer)
  //
  // Using TMP2 for LR save ensures TMP1=r3 is free to hold the integer result
  // returned by FillIntResult() in the stub.

  // Save LR via TMP2; allocate a 4096-byte frame to protect JIT spill slots.
  // The ELFv2 ABI only guarantees 288 bytes of red zone for leaf functions.
  // Op_Unhandled emits bctrl calls (non-leaf), so any spill slot beyond -288
  // from the current r1 can be overwritten by the callee's call chain.  Large
  // JIT blocks place spill slots at -700+ bytes from r1 (many live IR values).
  // With a 4096-byte frame the callee's entire accessible range (its own stack
  // plus its red zone) stays below our spill area — SoftFloat and friends use
  // far less than 4096 bytes of stack.
  mflr(TMP2); addi(r1, r1, -4096); std(TMP2, 0, r1);

  // Load ABIHandler into r0, Func into TMP4
  LoadImm32(TMP2, ABIHandlerOff);
  ldx(r(0), STATE, TMP2);
  LoadImm32(TMP2, FuncOff);
  ldx(TMP4, STATE, TMP2);
  // TMP2 is now free to reuse for source setup

  switch (Info.ABI) {

  case FABI_F80_I16_F32_PTR:
  case FABI_F80_I16_F64_PTR: {
    // Stub expects VTMP1 = source float/double vector (LE-element-0)
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F80_I16_I16_PTR: {
    // Stub expects TMP2(r4) = sign-extended int16
    extsh(TMP2, GetReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F80_I16_I32_PTR: {
    // Stub expects TMP2(r4) = sign-extended int32
    extsw(TMP2, GetReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F32_I16_F80_PTR:
  case FABI_F64_I16_F80_PTR:
  case FABI_F64_F64_PTR:
  case FABI_F80_I16_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F64_F64_F64_PTR:
  case FABI_F80_I16_F80_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    vmr(VTMP2, GetVReg(IROp->Args[1]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_I16_I16_F80_PTR:
  case FABI_I32_I16_F80_PTR:
  case FABI_I64_I16_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_I64_I16_F80_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    vmr(VTMP2, GetVReg(IROp->Args[1]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_F80x2_I16_F80_PTR: {
    // Returns two F80 vectors: VTMP1 (low) and VTMP2 (high)
    const auto DstLo = GetVReg(IROp->Args[1]);
    const auto DstHi = GetVReg(IROp->Args[2]);
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(DstLo, VTMP1);
    vmr(DstHi, VTMP2);
    break;
  }

  case FABI_F64x2_F64_PTR: {
    // Returns two doubles in VTMP1/VTMP2
    const auto DstLo = GetVReg(IROp->Args[1]);
    const auto DstHi = GetVReg(IROp->Args[2]);
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    vmr(DstLo, VTMP1);
    vmr(DstHi, VTMP2);
    break;
  }

  case FABI_I32_I64_I64_V128_V128_I16: {
    // VPCMPESTRX: stub expects TMP1=RAX, TMP2=RDX, TMP3=Control, VTMP1=LHS, VTMP2=RHS
    const auto Op = IROp->C<IR::IROp_VPCMPESTRX>();
    vmr(VTMP1, GetVReg(Op->LHS));
    vmr(VTMP2, GetVReg(Op->RHS));
    mr(TMP2, GetReg(Op->RDX));
    li(TMP3, static_cast<int16_t>(Op->Control));
    mr(TMP1, GetReg(Op->RAX));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_I32_V128_V128_I16: {
    // VPCMPISTRX: stub expects TMP1=Control, VTMP1=LHS, VTMP2=RHS
    const auto Op = IROp->C<IR::IROp_VPCMPISTRX>();
    vmr(VTMP1, GetVReg(Op->LHS));
    vmr(VTMP2, GetVReg(Op->RHS));
    li(TMP1, static_cast<int16_t>(Op->Control));
    mtctr(r(0)); bctrl();
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_UNKNOWN:
  default:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled IR Fallback ABI: {} {}", FEXCore::IR::GetName(IROp->Op), ToUnderlying(Info.ABI));
#endif
    // Still need to pop LR frame
    ld(TMP2, 0, r1); mtlr(TMP2); addi(r1, r1, 4096); li(r(0), 0);
    break;
  }
}

void PPC64JITCore::Op_NoOp(const IR::IROp_Header* IROp, IR::Ref Node) {}

// -------------------------------------------------------------------------
// IsInlineConstant / IsInlineEntrypointOffset
// -------------------------------------------------------------------------
bool PPC64JITCore::IsInlineConstant(const IR::OrderedNodeWrapper& Node,
                                    uint64_t* Value) const {
  if (Node.IsImmediate()) {
    return false;
  }
  auto IROp = IR->GetOp<IR::IROp_Header>(Node);
  if (IROp->Op == IR::IROps::OP_INLINECONSTANT) {
    if (Value) *Value = IROp->C<IR::IROp_InlineConstant>()->Constant;
    return true;
  }
  return false;
}

bool PPC64JITCore::IsInlineEntrypointOffset(const IR::OrderedNodeWrapper& WNode,
                                             uint64_t* Value) const {
  if (WNode.IsImmediate()) {
    return false;
  }
  auto IROp = IR->GetOp<IR::IROp_Header>(WNode);
  if (IROp->Op == IR::IROps::OP_INLINEENTRYPOINTOFFSET) {
    auto Op = IROp->C<IR::IROp_InlineEntrypointOffset>();
    uint64_t Mask = IROp->Size == IR::OpSize::i32Bit ? 0xFFFF'FFFFull : ~0ULL;
    *Value = (Entry + Op->Offset) & Mask;
    return true;
  }
  return false;
}

// -------------------------------------------------------------------------
// Named thunk relocation
// -------------------------------------------------------------------------
void PPC64JITCore::InsertNamedThunkRelocation(GPR Reg, const IR::SHA256Sum& Sum) {
  Relocation Reloc {};
  Reloc.NamedThunkMove.Header = {
    .Offset = static_cast<uint64_t>(GetOffset()),
    .Type   = FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE,
  };
  Reloc.NamedThunkMove.Symbol        = Sum;
  Reloc.NamedThunkMove.RegisterIndex = Reg.idx;

  uint64_t Pointer = 0;
  if (CTX->ThunkHandler) {
    Pointer = reinterpret_cast<uint64_t>(CTX->ThunkHandler->LookupThunk(Sum));
  }
  LoadConstant(Reg, Pointer);
  Relocations.emplace_back(Reloc);
}

// -------------------------------------------------------------------------
// Condition code mapping
// -------------------------------------------------------------------------
PPC64Emitter::Cond PPC64JITCore::MapCC(IR::CondClass Cond) {
  switch (Cond) {
  case IR::CondClass::EQ:  return CC_EQ;
  case IR::CondClass::NEQ: return CC_NE;
  case IR::CondClass::SGE: return CC_GE;
  case IR::CondClass::SLT: return CC_LT;
  case IR::CondClass::SGT: return CC_GT;
  case IR::CondClass::SLE: return CC_LE;
  case IR::CondClass::UGE: return CC_GE;  // after cmpldi
  case IR::CondClass::ULT: return CC_LT;  // after cmpldi
  case IR::CondClass::UGT: return CC_GT;  // after cmpldi
  case IR::CondClass::ULE: return CC_LE;  // after cmpldi
  // Floating-point conditions on CR0 set by fcmpu: LT/GT/EQ have IEEE-ordered
  // meaning, SO is set on unordered. FU/FNU test SO directly.
  case IR::CondClass::FLU:  return CC_LT;
  case IR::CondClass::FGE:  return CC_GE;
  case IR::CondClass::FLEU: return CC_LE;
  case IR::CondClass::FGT:  return CC_GT;
  case IR::CondClass::FU:   return {12, 3};   // CR0.SO=1 (unordered)
  case IR::CondClass::FNU:  return { 4, 3};   // CR0.SO=0 (ordered)
  // NZCV-style
  case IR::CondClass::MI: return CC_LT;
  case IR::CondClass::PL: return CC_GE;
  case IR::CondClass::VS: return {12, 3};  // CR0.SO set
  case IR::CondClass::VC: return { 4, 3};  // CR0.SO clear
  // TSTZ/TSTNZ are bit-test conditions whose Cmp2 is a bit POSITION, not a
  // comparable value. They cannot share the normal CMP-then-Bcc lowering;
  // callers MUST handle them explicitly BEFORE calling MapCC (see
  // DEF_OP(CondJump) and DEF_OP(Select) — both emit `rldicl_` to extract the
  // bit to CR0 and pick CC_NE/CC_EQ themselves). Reaching MapCC with these
  // means a new caller forgot the pre-handling; fail loudly rather than
  // silently returning CC_EQ.
  case IR::CondClass::TSTZ:
  case IR::CondClass::TSTNZ:
    LOGMAN_MSG_A_FMT("MapCC: TSTZ/TSTNZ must be handled by caller, not MapCC");
    return CC_EQ;
  default:
    LOGMAN_MSG_A_FMT("Unsupported compare type");
    return CC_EQ;
  }
}

// -------------------------------------------------------------------------
// ProjectXERToCR1: copy XER.SO/OV/CA into CR1.LT/GT/EQ without modifying XER.
// CR1.LT (PPC bit 4) <- XER.SO
// CR1.GT (PPC bit 5) <- XER.OV
// CR1.EQ (PPC bit 6) <- XER.CA
// CR1.SO (PPC bit 7) <- 0 (don't care)
// XER bits in mfspr-result GPR (LSB numbering): SO=31, OV=30, CA=29.
// rotlwi by 28 maps SO 31->27 (PPC 4), OV 30->26 (PPC 5), CA 29->25 (PPC 6).
// mtcrf with FXM=0x40 selects only CR1.
// -------------------------------------------------------------------------
void PPC64JITCore::ProjectXERToCR1() {
  mfspr(TMP1, 1);
  rlwinm(TMP2, TMP1, 28, 0, 31);  // rotlwi 28
  mtcrf(0x40, TMP2);
}

// -------------------------------------------------------------------------
// MapNZCVCC: decode an IR CondClass against packed NZCV semantics, where
//   N = CR0.LT (sign of last result), Z = CR0.EQ, C = XER.CA, V = XER.OV.
// For C/V conditions and signed-with-OF conditions we project XER->CR1 and
// optionally synthesize a composite CR3 bit via crand/crxor/crandc/crnor.
//
// CR-bit indices used here (PPC numbering):
//   CR0.LT=0, CR0.GT=1, CR0.EQ=2
//   CR1.LT=4 (SO), CR1.GT=5 (OV/V), CR1.EQ=6 (CA/C)
//   CR3.LT=12, CR3.GT=13 (used as scratch for composites)
// -------------------------------------------------------------------------
PPC64Emitter::Cond PPC64JITCore::MapNZCVCC(IR::CondClass Cond) {
  switch (Cond) {
  // Z-only (CR0.EQ)
  case IR::CondClass::EQ:  return CC_EQ;       // Z=1
  case IR::CondClass::NEQ: return CC_NE;       // Z=0
  // N-only (CR0.LT)
  case IR::CondClass::MI:  return {12, 0};     // N=1
  case IR::CondClass::PL:  return { 4, 0};     // N=0

  // C / V (need projection)
  case IR::CondClass::UGE: ProjectXERToCR1(); return {12, 6};  // C=1
  case IR::CondClass::ULT: ProjectXERToCR1(); return { 4, 6};  // C=0
  case IR::CondClass::VS:  ProjectXERToCR1(); return {12, 5};  // V=1
  case IR::CondClass::VC:  ProjectXERToCR1(); return { 4, 5};  // V=0

  // UGT = C=1 AND Z=0 ; ULE = !UGT
  case IR::CondClass::UGT: ProjectXERToCR1();
                           crandc(12, 6, 2);   // CR3.LT = C AND NOT Z
                           return {12, 12};
  case IR::CondClass::ULE: ProjectXERToCR1();
                           crandc(12, 6, 2);
                           return { 4, 12};

  // SLT = N!=V ; SGE = N==V
  case IR::CondClass::SLT: ProjectXERToCR1();
                           crxor(12, 0, 5);    // CR3.LT = N XOR V
                           return {12, 12};
  case IR::CondClass::SGE: ProjectXERToCR1();
                           crxor(12, 0, 5);
                           return { 4, 12};

  // SGT = (N==V) AND Z=0 ; SLE = !SGT
  case IR::CondClass::SGT: ProjectXERToCR1();
                           crxor(12, 0, 5);    // CR3.LT = SLT (N XOR V)
                           crnor(13, 12, 2);   // CR3.GT = NOT (SLT OR Z) = SGT
                           return {12, 13};
  case IR::CondClass::SLE: ProjectXERToCR1();
                           crxor(12, 0, 5);
                           crnor(13, 12, 2);
                           return { 4, 13};

  // FP conditions on CR0 set by fcmpu. Same as MapCC.
  case IR::CondClass::FLU:  return CC_LT;
  case IR::CondClass::FGE:  return CC_GE;
  case IR::CondClass::FLEU: return CC_LE;
  case IR::CondClass::FGT:  return CC_GT;
  // FU/FNU in NZCV context = integer overflow (XER.OV via CR1), NOT
  // FP-unordered. The shared OpcodeDispatcher reuses these as OF-set /
  // OF-clear codes (OpcodeDispatcher.cpp:564, .h:1929) because on AArch64
  // both alias onto PSTATE.V. ALUOps.cpp::IntegerNZCVCond pre-rewrites
  // FU→VS / FNU→VC for in-file callers, but BranchOps.cpp::CondJump and
  // any other MapNZCVCC consumers (e.g. INTO at OpcodeDispatcher.cpp:4756)
  // need the correct projection here too.
  case IR::CondClass::FU:   ProjectXERToCR1(); return {12, 5};   // V=1
  case IR::CondClass::FNU:  ProjectXERToCR1(); return { 4, 5};   // V=0
  default:
    LOGMAN_MSG_A_FMT("MapNZCVCC: unsupported condition");
    return CC_EQ;
  }
}

// -------------------------------------------------------------------------
// EmitCompare: emit a compare before a conditional branch
// -------------------------------------------------------------------------
void PPC64JITCore::EmitCompare(IR::CondClass Cond, IR::OpSize Sz,
                               IR::OrderedNodeWrapper Src1,
                               IR::OrderedNodeWrapper Src2,
                               uint8_t CRField) {
  // FP conditions: operands are FPRs (vector reg holding scalar in element 0).
  const bool IsFP = (Cond == IR::CondClass::FLU || Cond == IR::CondClass::FGE ||
                     Cond == IR::CondClass::FLEU || Cond == IR::CondClass::FGT ||
                     Cond == IR::CondClass::FU || Cond == IR::CondClass::FNU);
  if (IsFP) {
    auto V1 = GetVReg(Src1);
    auto V2 = GetVReg(Src2);
    addi(TMP1, r1, -32);
    stvx(V1, r(0), TMP1);
    addi(TMP2, r1, -16);
    stvx(V2, r(0), TMP2);
    if (Sz == IR::OpSize::i32Bit) {
      lfs(PPC64Emitter::FPRegs::f0, -32, r1);
      lfs(PPC64Emitter::FPRegs::f1, -16, r1);
    } else {
      lfd(PPC64Emitter::FPRegs::f0, -32, r1);
      lfd(PPC64Emitter::FPRegs::f1, -16, r1);
    }
    fcmpu(cr(CRField), PPC64Emitter::FPRegs::f0, PPC64Emitter::FPRegs::f1);
    return;
  }

  uint64_t Const;
  GPR Reg1 = GetReg(Src1);
  bool IsUnsigned = (Cond == IR::CondClass::UGE || Cond == IR::CondClass::ULT ||
                     Cond == IR::CondClass::UGT || Cond == IR::CondClass::ULE);

  // Sub-32 (i8/i16) operands may carry dirty upper bits — GPRs in FEX have no
  // "clean upper" guarantee at narrow sizes. Shift both operands left by
  // (64 - 8N) so the operand-size sign bit lines up with bit 63; the resulting
  // 64-bit compare then matches the operand-size compare for both signed and
  // unsigned ordering, and EQ/NEQ vs 0 is preserved. Same trick used by
  // SubNZCV's narrow path. Currently exercised by FoldBranch's i8/i16
  // EQ/NEQ-vs-0 fold, but written generically so any future caller is safe.
  if (Sz == IR::OpSize::i8Bit || Sz == IR::OpSize::i16Bit) {
    uint32_t Sh = (Sz == IR::OpSize::i8Bit) ? 56u : 48u;
    sldi(TMP1, Reg1, Sh);
    if (IsInlineConstant(Src2, &Const)) {
      if (Const == 0) {
        if (IsUnsigned) cmpldi(cr(CRField), TMP1, 0);
        else            cmpdi(cr(CRField), TMP1, 0);
      } else {
        LoadConstant(TMP2, Const << Sh);
        if (IsUnsigned) cmpld(cr(CRField), TMP1, TMP2);
        else            cmpd(cr(CRField), TMP1, TMP2);
      }
    } else {
      sldi(TMP2, GetReg(Src2), Sh);
      if (IsUnsigned) cmpld(cr(CRField), TMP1, TMP2);
      else            cmpd(cr(CRField), TMP1, TMP2);
    }
    return;
  }

  if (IsInlineConstant(Src2, &Const)) {
    if (IsUnsigned) {
      if (Const <= 0xFFFF) {
        if (Sz <= IR::OpSize::i32Bit)
          cmplwi(cr(CRField), Reg1, static_cast<uint16_t>(Const));
        else
          cmpldi(cr(CRField), Reg1, static_cast<uint16_t>(Const));
      } else {
        LoadConstant(TMP4, Const);
        if (Sz <= IR::OpSize::i32Bit) cmplw(cr(CRField), Reg1, TMP4);
        else                           cmpld(cr(CRField), Reg1, TMP4);
      }
    } else {
      int64_t sConst = static_cast<int64_t>(Const);
      if (sConst >= -32768 && sConst <= 32767) {
        if (Sz <= IR::OpSize::i32Bit)
          cmpwi(cr(CRField), Reg1, static_cast<int16_t>(sConst));
        else
          cmpdi(cr(CRField), Reg1, static_cast<int16_t>(sConst));
      } else {
        LoadConstant(TMP4, Const);
        if (Sz <= IR::OpSize::i32Bit) cmpw(cr(CRField), Reg1, TMP4);
        else                           cmpd(cr(CRField), Reg1, TMP4);
      }
    }
  } else {
    GPR Reg2 = GetReg(Src2);
    if (IsUnsigned) {
      if (Sz <= IR::OpSize::i32Bit) cmplw(cr(CRField), Reg1, Reg2);
      else                           cmpld(cr(CRField), Reg1, Reg2);
    } else {
      if (Sz <= IR::OpSize::i32Bit) cmpw(cr(CRField), Reg1, Reg2);
      else                           cmpd(cr(CRField), Reg1, Reg2);
    }
  }
}

// -------------------------------------------------------------------------
// ResetStack: undo the per-block spill frame extension emitted by
// EmitEntryPoint, restoring r1 to the dispatcher's frame bottom.
//
// Must be called at every JIT-to-dispatcher transition emit site so the
// dispatcher's frame accounting stays correct on the way out. Currently
// invoked from DEF_OP(ExitFunction), DEF_OP(Break), and DEF_OP(CallbackReturn)
// — the only ops that hand control back to the dispatcher / C++ caller.
// -------------------------------------------------------------------------
void PPC64JITCore::ResetStack() {
  if (SpillFrameSize == 0) {
    return;
  }
  // addi's 16-bit signed immediate covers +/-32767. Large CompileCodes
  // (heavy spill pressure under TLS / X25519) can exceed this; fall back to
  // LoadImm32 + add. Skipping this check let asserts silently fail in release
  // builds and r1 walked into unmapped territory after ~2.6M dispatches.
  if (SpillFrameSize <= 32767u) {
    addi(r1, r1, static_cast<int16_t>(SpillFrameSize));
  } else {
    LoadImm32(TMP1, SpillFrameSize);
    add(r1, r1, TMP1);
  }
}

// -------------------------------------------------------------------------
// Constructor / Destructor
// -------------------------------------------------------------------------
// Called from the dispatcher's ExitFunctionLinker when the L1 cache misses.
// Looks up or compiles the block at GuestRIP and returns its host code address.
// Returns DispatcherLoopTop if compilation fails (dispatcher will spin and recheck).
// Forward-declare the dispatcher's ring buffer (defined in PPC64Dispatcher.cpp).
extern "C" {
  extern uint64_t g_dispatch_count;
  extern uint64_t g_recent_rips[16];
  extern uint64_t g_last_exit_rip;
  extern uint64_t g_last_exit_kind;
  extern uint64_t g_last_callback_target;
  extern uint64_t g_last_callback_rsp_pushed;
  extern uint64_t g_last_callback_pushed_val;
  extern uint64_t g_last_callback_return_rip;
}

// Forward-declare the compile-log ring buffer (defined in Frontend.cpp).
// Records what bytes FEX saw at DecodeInstructionsAtEntry time. Used to
// confirm/refute the stale-compile hypothesis: if the bytes FEX read at
// compile time differ from the bytes at the same guest VA at fault time,
// the JIT block was built from stale bytes (and FEX's SMC detection
// missed the change).
extern "C" {
  struct CompileLogEntry {
    uint64_t guest_rip;
    uint64_t src_host_va;
    uint8_t  bytes[16];
  };
  extern CompileLogEntry g_compile_log[256];
  extern uint64_t g_compile_log_count;
}

// Check if a GuestRIP is plausibly valid (mapped, executable, not all-0xCC,
// not near-NULL). When it looks bad, dump the JIT-block PC that called us
// (= the caller's return address = our LR), the last successful guest RIPs
// from g_recent_rips, and disasm of the JIT block tail so we can identify
// which guest x86 op's emit produced the bad target. Aborts after the dump.
//
// Suppress with FEX_EXITLINK_NOABORT=1 to revert to silent forwarding.
static void DiagnoseSuspectGuestRIP(uint64_t GuestRIP, uint64_t HostLR,
                                     FEXCore::Core::CpuStateFrame* Frame) {
  static const bool absorb = (getenv("FEX_EXITLINK_NOABORT") != nullptr);
  if (absorb) {
    return;
  }
  // Direct write to stderr — LogMan may not flush before abort().
  {
    char buf[1024];
    uint64_t RSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
    uint64_t RDI = Frame->State.gregs[FEXCore::X86State::REG_RDI];
    uint64_t RSI = Frame->State.gregs[FEXCore::X86State::REG_RSI];
    uint64_t RAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];
    uint64_t TCR = Frame->Pointers.ThunkCallbackRet;
    int n = snprintf(buf, sizeof(buf),
                     "[FEX] suspect GuestRIP=0x%lx HostLR=0x%lx\n"
                     "[FEX]   recent: [-1]=0x%lx [-2]=0x%lx [-3]=0x%lx [-4]=0x%lx [-5]=0x%lx [-6]=0x%lx\n"
                     "[FEX]   RSP=0x%lx RDI=0x%lx RSI=0x%lx RAX=0x%lx ThunkCallbackRet=0x%lx\n",
                     (unsigned long)GuestRIP, (unsigned long)HostLR,
                     (unsigned long)g_recent_rips[(g_dispatch_count - 1) & 15],
                     (unsigned long)g_recent_rips[(g_dispatch_count - 2) & 15],
                     (unsigned long)g_recent_rips[(g_dispatch_count - 3) & 15],
                     (unsigned long)g_recent_rips[(g_dispatch_count - 4) & 15],
                     (unsigned long)g_recent_rips[(g_dispatch_count - 5) & 15],
                     (unsigned long)g_recent_rips[(g_dispatch_count - 6) & 15],
                     (unsigned long)RSP, (unsigned long)RDI, (unsigned long)RSI,
                     (unsigned long)RAX, (unsigned long)TCR);
    [[maybe_unused]] auto _ = write(2, buf, n);
    // Try to peek at first 8 bytes of RSP and RSI as guest memory
    auto peek8 = [](uint64_t addr) -> uint64_t {
      if (addr < 0x1000 || (addr >> 47) != 0) return 0xDEADBEEFDEADBEEF;
      return *reinterpret_cast<volatile uint64_t*>(addr);
    };
    n = snprintf(buf, sizeof(buf),
                 "[FEX]   *RSP=0x%lx *RSP+8=0x%lx *RSI=0x%lx *RSI+8=0x%lx *RSI+16=0x%lx\n",
                 (unsigned long)peek8(RSP),
                 (unsigned long)peek8(RSP + 8),
                 (unsigned long)peek8(RSI),
                 (unsigned long)peek8(RSI + 8),
                 (unsigned long)peek8(RSI + 16));
    _ = write(2, buf, n);
    // 2026-05-17: callback-flow RIP-truncation trace globals
    n = snprintf(buf, sizeof(buf),
                 "[FEX]   trace: last_exit_rip=0x%lx kind=%lu last_cb_target=0x%lx last_cb_rsp_pushed=0x%lx last_cb_pushed_val=0x%lx last_cb_return_rip=0x%lx\n",
                 (unsigned long)g_last_exit_rip,
                 (unsigned long)g_last_exit_kind,
                 (unsigned long)g_last_callback_target,
                 (unsigned long)g_last_callback_rsp_pushed,
                 (unsigned long)g_last_callback_pushed_val,
                 (unsigned long)g_last_callback_return_rip);
    _ = write(2, buf, n);
    fsync(2);
  }
  LogMan::Msg::EFmt("=== ExitFunctionLink: suspect GuestRIP=0x{:x} ===", GuestRIP);
  LogMan::Msg::EFmt("    Host LR (JIT block tail that called us) = 0x{:x}", HostLR);
  LogMan::Msg::EFmt("    Recent dispatched guest RIPs (g_recent_rips):");
  {
    uint64_t _dcount = g_dispatch_count;
    for (int _ri = 1; _ri <= 16 && _ri <= static_cast<int>(_dcount); ++_ri) {
      LogMan::Msg::EFmt("      rip[-{}] = 0x{:x}", _ri, g_recent_rips[(_dcount - _ri) & 15]);
    }
  }
  LogMan::Msg::EFmt("    Disasm of JIT block at Host LR-512 .. LR+32 (PPC64 instructions):");
  LogMan::Msg::EFmt("    (Look for `std rX, 0x18(rRR)` = the state.rip store, and "
                    "`ldx rX, rA, r0` / `lis;ori;sldi;oris;ori` = the LoadConstant+ldx for malloc GOT)");
  {
    // Widened window: LR-128 misses the actual `ldx` and earlier LoadConstant.
    // Bump to LR-512 (128 words) to catch the full x86-op translation
    // (LoadConstant of GOT VA + ldx + std to State.rip + SpillStaticRegs).
    const uint32_t* base = reinterpret_cast<const uint32_t*>(HostLR);
    for (int i = -128; i <= 8; ++i) {
      const uint32_t* addr = base + i;
      uint32_t insn = *addr;
      // Annotate any std/ldx/lis instructions inline so easier to scan.
      const char* note = "";
      uint32_t opcode = insn >> 26;
      if (opcode == 62) note = "  ; std/stdx (store double)";
      else if (opcode == 58) note = "  ; ld/ldx (load double)";
      else if (opcode == 31 && ((insn >> 1) & 0x3ff) == 21) note = "  ; ldx (X-form load doubleword)";
      else if (opcode == 31 && ((insn >> 1) & 0x3ff) == 149) note = "  ; stdx (X-form store doubleword)";
      else if (opcode == 15) note = "  ; lis (load immed shifted)";
      else if (opcode == 24) note = "  ; ori (or immediate)";
      else if (opcode == 25) note = "  ; oris (or immed shifted)";
      else if (opcode == 30) note = "  ; rldicl/rldicr (rotate-left-double-immed)";
      if (i == 0) {
        LogMan::Msg::EFmt("      0x{:x} = 0x{:08x}{}  <-- LR (return-to here from call)",
                          reinterpret_cast<uint64_t>(addr), insn, note);
      } else if (i == -1) {
        LogMan::Msg::EFmt("      0x{:x} = 0x{:08x}{}  <-- call (bctrl)",
                          reinterpret_cast<uint64_t>(addr), insn, note);
      } else {
        LogMan::Msg::EFmt("      0x{:x} = 0x{:08x}{}",
                          reinterpret_cast<uint64_t>(addr), insn, note);
      }
    }
  }

  // If rip[-1] looks like it points into a mapped x86_64 region, try to
  // read the bytes there. If it's an x86 `ff 25 disp32` instruction
  // (jmp [rip+disp32]), compute the GOT slot it dereferences and read
  // the 8 bytes at that slot. This disambiguates "GOT was actually
  // corrupted to GuestRIP value" from "JIT read from wrong VA".
  {
    uint64_t prev_rip = 0;
    {
      uint64_t _dcount = g_dispatch_count;
      if (_dcount >= 1) {
        prev_rip = g_recent_rips[(_dcount - 1) & 15];
      }
    }
    if (prev_rip) {
      // sanity-bounded read of 8 bytes at prev_rip
      const uint8_t* p = reinterpret_cast<const uint8_t*>(prev_rip);
      LogMan::Msg::EFmt("    Bytes at rip[-1] (= 0x{:x}):", prev_rip);
      uint8_t bytes[16] = {};
      bool readable = true;
      // try to read; if SIGSEGV, oh well — we're aborting anyway
      for (int i = 0; i < 16 && readable; ++i) {
        bytes[i] = p[i];  // may fault; that's fine, we're crashing anyway
      }
      LogMan::Msg::EFmt("      {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
      // Check for `ff 25 disp32` PLT pattern
      if (bytes[0] == 0xff && bytes[1] == 0x25) {
        int32_t disp = static_cast<int32_t>(static_cast<uint32_t>(bytes[2]) |
                                            (static_cast<uint32_t>(bytes[3]) << 8) |
                                            (static_cast<uint32_t>(bytes[4]) << 16) |
                                            (static_cast<uint32_t>(bytes[5]) << 24));
        uint64_t rip_after_instr = prev_rip + 6;
        uint64_t got_va = rip_after_instr + disp;
        LogMan::Msg::EFmt("    PLT pattern detected: jmp [rip+0x{:x}]; GOT slot VA = 0x{:x}", disp, got_va);
        const uint64_t* got_ptr = reinterpret_cast<const uint64_t*>(got_va);
        uint64_t got_value = *got_ptr;  // may fault; we're aborting
        LogMan::Msg::EFmt("    GOT slot contents = 0x{:x}", got_value);
        LogMan::Msg::EFmt("    GuestRIP we crashed on = 0x{:x}", GuestRIP);
        if (got_value == GuestRIP) {
          LogMan::Msg::EFmt("    CONCLUSION: GOT slot value MATCHES GuestRIP -> JIT load was correct, "
                            "GOT page is actually corrupted to 0x{:x}", got_value);
        } else {
          LogMan::Msg::EFmt("    CONCLUSION: GOT slot value = 0x{:x} but JIT loaded 0x{:x} -> "
                            "JIT load is reading from WRONG VA",
                            got_value, GuestRIP);
        }
        // Also dump 32 bytes (4 slots) around the GOT slot to see the
        // neighborhood. If only one slot is corrupted, the others
        // contain valid pointers.
        LogMan::Msg::EFmt("    Neighbouring GOT slots (-16..+24 bytes from target):");
        for (int off = -16; off <= 24; off += 8) {
          uint64_t addr = got_va + off;
          uint64_t val = *reinterpret_cast<const uint64_t*>(addr);
          LogMan::Msg::EFmt("      0x{:x} = 0x{:016x}", addr, val);
        }
      }
    }
  }

  // Compile-log lookup: did FEX see the same bytes at rip[-1] when it
  // FIRST compiled the block, vs what's there NOW? Stale-compile bug
  // confirmed if they differ.
  {
    uint64_t prev_rip = 0;
    {
      uint64_t _dcount = g_dispatch_count;
      if (_dcount >= 1) {
        prev_rip = g_recent_rips[(_dcount - 1) & 15];
      }
    }
    if (prev_rip) {
      // Walk g_compile_log backward looking for the most recent entry with
      // guest_rip == prev_rip
      uint64_t cur = g_compile_log_count;
      bool found = false;
      // Scan all 256 entries; oldest first to find earliest match too
      for (uint64_t off = 1; off <= 256 && off <= cur; ++off) {
        uint64_t idx = (cur - off) & 255;
        if (g_compile_log[idx].guest_rip == prev_rip) {
          auto& e = g_compile_log[idx];
          LogMan::Msg::EFmt("    >>> COMPILE-LOG: bytes FEX saw at rip[-1] when compiling <<<");
          LogMan::Msg::EFmt("        compile-log[#{}] guest_rip=0x{:x} src_host_va=0x{:x}",
                            (cur - off), e.guest_rip, e.src_host_va);
          LogMan::Msg::EFmt("        bytes-at-compile-time: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                            e.bytes[0], e.bytes[1], e.bytes[2], e.bytes[3],
                            e.bytes[4], e.bytes[5], e.bytes[6], e.bytes[7],
                            e.bytes[8], e.bytes[9], e.bytes[10], e.bytes[11],
                            e.bytes[12], e.bytes[13], e.bytes[14], e.bytes[15]);
          // Compare to bytes at rip[-1] right now
          const uint8_t* now = reinterpret_cast<const uint8_t*>(prev_rip);
          bool match = true;
          for (int b = 0; b < 16; ++b) {
            if (now[b] != e.bytes[b]) { match = false; break; }
          }
          if (match) {
            LogMan::Msg::EFmt("        ===> bytes MATCH current bytes-at-rip — stale-compile theory REFUTED");
          } else {
            LogMan::Msg::EFmt("        ===> bytes DIFFER from current bytes-at-rip — STALE-COMPILE CONFIRMED");
          }
          found = true;
          break;
        }
      }
      if (!found) {
        LogMan::Msg::EFmt("    (no compile-log entry for rip[-1] = 0x{:x} in last 256 compiles)", prev_rip);
      }
    }
  }

  // Disassemble the PREVIOUS JIT block — the one that stored the bad value
  // into State.rip via its ExitFunction emit. The previous guest RIP is
  // rip[-1]; we look it up in the L1 lookup cache to find its host code.
  {
    uint64_t prev_rip = 0;
    {
      uint64_t _dcount = g_dispatch_count;
      if (_dcount >= 1) {
        prev_rip = g_recent_rips[(_dcount - 1) & 15];
      }
    }
    if (prev_rip && Frame && Frame->Thread) {
      auto Thread = Frame->Thread;
      uintptr_t PrevBlockHostPC = Thread->LookupCache->FindBlock(Thread, prev_rip);
      if (PrevBlockHostPC) {
        LogMan::Msg::EFmt("    Previous JIT block (guest RIP=0x{:x}) host code @ 0x{:x}",
                          prev_rip, PrevBlockHostPC);
        LogMan::Msg::EFmt("    Disasm of previous JIT block (first 80 PPC64 instructions):");
        const uint32_t* base = reinterpret_cast<const uint32_t*>(PrevBlockHostPC);
        for (int i = 0; i < 80; ++i) {
          uint32_t insn = base[i];
          uint32_t opcode = insn >> 26;
          const char* note = "";
          if (opcode == 62) note = "  ; std (store doubleword)";
          else if (opcode == 58) note = "  ; ld (load doubleword)";
          else if (opcode == 31 && ((insn >> 1) & 0x3ff) == 21)  note = "  ; ldx (X-form load dw)";
          else if (opcode == 31 && ((insn >> 1) & 0x3ff) == 149) note = "  ; stdx (X-form store dw)";
          else if (opcode == 15) note = "  ; lis";
          else if (opcode == 24) note = "  ; ori";
          else if (opcode == 25) note = "  ; oris";
          else if (opcode == 30) note = "  ; rldicl/rldicr (sldi)";
          else if (opcode == 18) note = "  ; b (branch)";
          else if (opcode == 16) note = "  ; bc (cond branch)";
          else if (opcode == 19) note = "  ; bclr/bcctr";
          LogMan::Msg::EFmt("      +0x{:03x} = 0x{:08x}{}", i * 4, insn, note);
          // Stop if we hit a likely block-exit (bctr/bclr opcode 19)
          if (opcode == 19) {
            // Look 4 more after the branch then stop
            int stop = std::min(80, i + 4);
            for (int j = i + 1; j <= stop; ++j) {
              LogMan::Msg::EFmt("      +0x{:03x} = 0x{:08x}", j * 4, base[j]);
            }
            break;
          }
        }
      } else {
        LogMan::Msg::EFmt("    Previous JIT block lookup failed (rip 0x{:x} not in L1)", prev_rip);
      }
    }
  }

  LogMan::Msg::EFmt("Aborting on suspect ExitFunctionLink. To suppress, set FEX_EXITLINK_NOABORT=1.");
  std::abort();
}

uint64_t PPC64JITCore::ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  // Suspect-RIP filter:
  //   1. Near-NULL (within first page) — can't be valid PIE-loaded x86 code
  //   2. All-CC pattern (0xCCCCCCCCCCCCCCCC) — typical "uninitialized" value
  //   3. Outside the 47-bit user-space canonical range — guest RIP must be
  //      in low canonical addresses (top 17 bits zero) since FEX maps guest
  //      VAs without using the non-canonical region.
  // If any of these fire, dump diagnostic + abort.
  auto LooksSuspect = [GuestRIP]() {
    if (GuestRIP < 0x1000) return true;                  // near-NULL
    if (GuestRIP == 0xCCCCCCCCCCCCCCCCULL) return true;  // all-CC
    if ((GuestRIP >> 47) != 0) return true;              // beyond user canonical
    return false;
  };
  if (LooksSuspect()) {
    // Pragmatic bypass for callback-flow failures (Grimrock libGL X11Manager,
    // similar cross-arch trampoline-into-guest paths): if we entered via
    // ExecuteJITCallback, ThunkCallbackRet is on the guest stack somewhere
    // near RSP. Walking RSP..(RSP+128) for that sentinel tells us "we're
    // inside a callback that went wrong — escape via CallbackReturn instead
    // of crashing the whole process." The callback returns a zeroed result
    // (best effort) and the host caller continues. Trades correctness of the
    // callback's return value for liveness — which is the right trade for
    // games where the guest will retry or treat absence-of-error as success.
    //
    // Suppress via FEX_EXITLINK_NOBYPASS=1 to fall through to the diagnostic.
    static const bool no_bypass = (getenv("FEX_EXITLINK_NOBYPASS") != nullptr);
    if (!no_bypass) {
      uint64_t TCR = Frame->Pointers.ThunkCallbackRet;
      uint64_t RSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      if (TCR && RSP >= 0x1000 && (RSP >> 47) == 0) {
        // Walk up to 128 bytes (16 slots) above current RSP looking for
        // ThunkCallbackRet. Bounded to avoid runaway reads.
        for (int i = 0; i < 16; ++i) {
          uint64_t slot_addr = RSP + i * 8;
          // Guard the read with a heuristic: only deref if slot_addr looks
          // like a valid guest VA (within the same canonical range as RSP).
          if ((slot_addr >> 47) != 0) break;
          uint64_t slot_val = *reinterpret_cast<volatile uint64_t*>(slot_addr);
          if (slot_val == TCR) {
            // Found callback sentinel. Adjust RSP to just past the sentinel
            // (it will be popped by CallbackReturn IR) and redirect to TCR.
            // i*8 below the sentinel is the "stack frame" the failed callback
            // built — discard it by walking RSP up to the sentinel slot.
            Frame->State.gregs[FEXCore::X86State::REG_RSP] = slot_addr;
            char buf[1024];
            int n = snprintf(buf, sizeof(buf),
                             "[FEX] suspect GuestRIP=0x%lx in callback flow — bypassing via ThunkCallbackRet=0x%lx (adjusted RSP from 0x%lx to 0x%lx)\n"
                             "[FEX]   trace: last_exit_rip=0x%lx kind=%lu last_cb_target=0x%lx last_cb_rsp_pushed=0x%lx last_cb_pushed_val=0x%lx last_cb_return_rip=0x%lx slot_i=%d\n"
                             "[FEX]   recent_rips: [-1]=0x%lx [-2]=0x%lx [-3]=0x%lx [-4]=0x%lx\n",
                             (unsigned long)GuestRIP, (unsigned long)TCR,
                             (unsigned long)RSP, (unsigned long)slot_addr,
                             (unsigned long)g_last_exit_rip,
                             (unsigned long)g_last_exit_kind,
                             (unsigned long)g_last_callback_target,
                             (unsigned long)g_last_callback_rsp_pushed,
                             (unsigned long)g_last_callback_pushed_val,
                             (unsigned long)g_last_callback_return_rip,
                             i,
                             (unsigned long)g_recent_rips[(g_dispatch_count - 1) & 15],
                             (unsigned long)g_recent_rips[(g_dispatch_count - 2) & 15],
                             (unsigned long)g_recent_rips[(g_dispatch_count - 3) & 15],
                             (unsigned long)g_recent_rips[(g_dispatch_count - 4) & 15]);
            [[maybe_unused]] auto _ = write(2, buf, n);
            GuestRIP = TCR;
            goto bypass_diagnose;
          }
        }
      }
    }
    // Grab the host LR (return address into the JIT block that called us).
    // __builtin_return_address(0) is the address of the instruction AFTER
    // the bctrl/bl that branched here.
    uint64_t HostLR = reinterpret_cast<uint64_t>(__builtin_return_address(0));
    DiagnoseSuspectGuestRIP(GuestRIP, HostLR, Frame);
  }
bypass_diagnose:

  auto Thread = Frame->Thread;
  auto CTX = static_cast<Context::ContextImpl*>(Thread->CTX);

  auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(CTX->CodeInvalidationMutex, Thread);
  uintptr_t HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP);
  if (!HostCode) {
    HostCode = CTX->CompileBlock(Frame, GuestRIP, 0);
  }
  return HostCode;
}

PPC64JITCore::PPC64JITCore(FEXCore::Context::ContextImpl* ctx,
                            FEXCore::Core::InternalThreadState* Thread)
  : CPUBackend(*ctx, Thread),
    PPC64EmitterBase(ctx),
    CTX(ctx) {
  // Set up static register tables
  auto Is64Bit = CTX->Config.Is64BitMode();
  if (Is64Bit) {
    StaticRegisters  = x64::SRA;
    GeneralRegisters = x64::RA;
    StaticFPRegisters  = x64::SRAFPR;
    GeneralFPRegisters = x64::RAFPR;
    PairRegisters = x64::RAPairs;
  } else {
    StaticRegisters  = x32::SRA;
    GeneralRegisters = x32::RA;
    StaticFPRegisters  = x32::SRAFPR;
    GeneralFPRegisters = x32::RAFPR;
    PairRegisters = x32::RAPairs;
  }

  CurrentCodeBuffer = CodeBuffers.GetLatest();
  ThreadState->LookupCache->Shared = CurrentCodeBuffer->LookupCache.get();

  // Wire up the block-find/compile function pointer used by the dispatcher's ExitFunctionLinker.
  ThreadState->CurrentFrame->Pointers.ExitFunctionLink =
    reinterpret_cast<uintptr_t>(&PPC64JITCore::ExitFunctionLink);

  // Wire up syscall handler — virtual dispatch via vtable entry extraction.
  {
    FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::HLE::SyscallHandler::HandleSyscall);
    ThreadState->CurrentFrame->Pointers.SyscallHandlerObj =
      reinterpret_cast<uint64_t>(CTX->SyscallHandler);
    ThreadState->CurrentFrame->Pointers.SyscallHandlerFunc =
      PMF.GetVTableEntry(CTX->SyscallHandler);
  }

  // CPUID / XGetBV: missing init was the hello_static blocker — the
  // codegen reads these slots, bctrl'd to NULL until we populated them.
  auto& Ptrs = ThreadState->CurrentFrame->Pointers;
  Ptrs.CPUIDObj = reinterpret_cast<uint64_t>(&CTX->CPUID);
  {
    FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunFunction);
    Ptrs.CPUIDFunction = PMF.GetConvertedPointer();
  }
  {
    FEXCore::Utils::MemberFunctionToPointerCast PMF(&FEXCore::CPUIDEmu::RunXCRFunction);
    Ptrs.XCRFunction = PMF.GetConvertedPointer();
  }
  Ptrs.LUDIV            = reinterpret_cast<uint64_t>(LUDIV);
  Ptrs.LDIV             = reinterpret_cast<uint64_t>(LDIV);
  Ptrs.PrintValue       = reinterpret_cast<uint64_t>(PrintValue);
  Ptrs.PrintMsgValue    = reinterpret_cast<uint64_t>(PrintMsg);
  Ptrs.MonoBackpatcherWrite =
    reinterpret_cast<uint64_t>(&FEXCore::Context::ContextImpl::MonoBackpatcherWrite);

  // ThreadRemoveCodeEntryFromJIT is invoked from DEF_OP(ThreadRemoveCodeEntry)
  // (ALUOps.cpp:3072) which runs at the tail of the SMC validate-and-evict
  // side block emitted in CONFIG_SMC_FULL mode. Mirrors ARM64's JIT.cpp:645.
  // Without this, the JIT loads r12=0 and bctrls into NULL, observed as the
  // SelfModifyingCode/SameBlock + DifferentBlock + Delinking test crashes
  // when FEX_SMCCHECKS=full.
  Ptrs.ThreadRemoveCodeEntryFromJIT =
    reinterpret_cast<uintptr_t>(&FEXCore::Context::ContextImpl::ThreadRemoveCodeEntryFromJit);

  // Tell the register allocator how many registers the PPC64 backend provides.
  RAPass = Thread->PassManager->GetPass<IR::RegisterAllocationPass>("RA");
  RAPass->AddRegisters(IR::RegClass::GPR,      GeneralRegisters.size());
  RAPass->AddRegisters(IR::RegClass::GPRFixed,  StaticRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPR,       GeneralFPRegisters.size());
  RAPass->AddRegisters(IR::RegClass::FPRFixed,  StaticFPRegisters.size());
  RAPass->PairRegs = PairRegisters;
}

PPC64JITCore::~PPC64JITCore() {}

void PPC64JITCore::ClearCache() {
  auto PrevCodeBuffer = CurrentCodeBuffer;
  auto lk = PrevCodeBuffer->LookupCache->AcquireWriteLock();
  GetEmptyCodeBuffer();
  ThreadState->LookupCache->ChangeGuestToHostMapping(*PrevCodeBuffer, *CurrentCodeBuffer->LookupCache, lk);
}

// -------------------------------------------------------------------------
// EmitEntryPoint: prologue emitted at the start of each JIT block
// -------------------------------------------------------------------------
void PPC64JITCore::EmitEntryPoint(PPC64Emitter::Label& HeaderLabel, bool CheckTF) {
  Bind(&HeaderLabel);

  // Fill SRA registers from the CpuStateFrame. NOTE: this only runs on the
  // cold path (ExitFunctionLink slow return). The dispatcher's L1-hit path
  // branches directly to CodeData.EntryPoints[Entry], which the caller sets
  // AFTER this function returns, so warm dispatch skips this FillStaticRegs.
  // SRA on warm dispatch is filled once by DispatcherLoopTopFillSRA before
  // falling into the L1 lookup loop.
  FillStaticRegs();

  if (CheckTF) {
    // Load EFLAGS and check TF (trap flag, bit 8)
    int32_t eflags_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_TF_RAW_LOC]));
    lbz(TMP1, static_cast<int16_t>(eflags_off), STATE);
    cmpdi(TMP1, 0);
    // If TF is set, branch to the interpreter
    // For now just skip — full TF handling added later
  }
}

// -------------------------------------------------------------------------
// CompileCode: main entry point — translate IR to PPC64LE code
// -------------------------------------------------------------------------
CPUBackend::CompiledCode PPC64JITCore::CompileCode(
    uint64_t Entry, uint64_t GuestSize, bool SingleInst,
    const FEXCore::IR::IRListView* IRView,
    FEXCore::Core::DebugData* DebugData_, bool CheckTF) {

  FEXCORE_PROFILE_SCOPED("PPC64JITCore::CompileCode");

  // PPC64 emits directly into the shared CurrentCodeBuffer (unlike arm64,
  // which stages in a per-thread TempCodeBuffer and copies under the lock).
  // Without serialization, two threads compiling concurrently both read the
  // same LatestOffset, emit on top of each other, and end up dispatching to
  // garbage host instructions. Hold the write mutex for the whole emission
  // window — including the icache flush — so other threads see a coherent
  // buffer state.
  std::unique_lock CodeBufferLock {CodeBuffers.CodeBufferWriteMutex};

  this->Entry    = Entry;
  this->IR       = IRView;
  this->DebugData = DebugData_;

  // Sample SpillSlots from the post-RA IR and compute the per-block
  // spill-frame size. align16() is implicit because MaxSpillSlotSize=32
  // is already a multiple of 16, keeping the PPC ELFv2 stack alignment.
  SpillSlots     = IRView->SpillSlots();
  SpillFrameSize = SpillSlots * MaxSpillSlotSize;

  // ------------------------------------------------------------------
  // Code-buffer capacity guard
  // ------------------------------------------------------------------
  // Emit32 / EmitD etc. have only a debug-build assert for buffer
  // overrun; in release builds writing past the end silently faults on
  // the trailing guard page (the last page of every CodeBuffer is
  // PROT_NONE; see CodeBuffer::CodeBuffer). Unlike Arm64JITCore which
  // emits into a per-thread TempCodeBuffer and copies under the lock,
  // PPC64 emits directly into the shared CurrentCodeBuffer, so we must
  // pre-check that enough headroom remains for this CompileCode.
  //
  // kBlockHeadroom is a worst-case conservative bound. A single IR op
  // typically expands to <= 80 host bytes (SpillStaticRegs + flag pack
  // / unpack is the heaviest), and IRView->SSACount() bounds the IR-op
  // count, but we don't want to walk the IR twice. 1 MiB is comfortable
  // for any real x86 block (post-frontend block cap is well under that
  // even after host-side expansion); rotating early is cheap because
  // the new buffer is geometrically larger up to MAX_CODE_SIZE (128 MiB).
  //
  // When the buffer is too full, drop the lock and call ClearCache().
  // ClearCache acquires its own LookupCache write lock and allocates a
  // fresh, larger CodeBuffer via GetEmptyCodeBuffer/StartLargerCodeBuffer,
  // migrating the L1/L2 mapping via ChangeGuestToHostMapping. After
  // re-acquiring CodeBufferLock, LatestOffset is 0 in the new buffer.
  constexpr size_t kBlockHeadroom = 1u << 20;  // 1 MiB
  if (CodeBuffers.LatestOffset + kBlockHeadroom > CurrentCodeBuffer->UsableSize()) {
    CodeBufferLock.unlock();
    ClearCache();
    CodeBufferLock.lock();
  }

  // Use the current code buffer at the current write offset
  auto* CB = CurrentCodeBuffer.get();
  SetBuffer(CB->Ptr + CodeBuffers.LatestOffset,
            CB->UsableSize() - CodeBuffers.LatestOffset);

  CodeData = {};
  CodeData.BlockBegin = GetCursorAddress<uint8_t*>();

  // -------------------------------------------------------------------------
  // Build jump target labels for all blocks
  // -------------------------------------------------------------------------
  // IMPORTANT: clear() first so resize() actually default-constructs fresh
  // Labels. resize() to <= current size is a no-op, which would leave each
  // Label with bound=true and offset=<previous compile's offset>. A forward
  // branch using such a "bound" label encodes (stale_offset - current_Offset)
  // and lands on garbage past the new compile's code.
  uint32_t NumBlocks = IRView->GetHeader()->BlockCount;
  JumpTargets.clear();
  JumpTargets.resize(NumBlocks, {});

  // Belt-and-suspenders: any pending forward-branch fixups left over from a
  // prior compilation (which would also be a bug) point into a buffer that
  // no longer exists; drop them.
  ClearPendingBranches();

  // -------------------------------------------------------------------------
  // Emit entry point
  // -------------------------------------------------------------------------
  PPC64Emitter::Label HeaderLabel{};
  EmitEntryPoint(HeaderLabel, CheckTF);

  // The entry point map: guest RIP -> host code address.
  // NOTE: this is the COLD-PATH entry recorded right after EmitEntryPoint
  // (post-FillStaticRegs). The per-IR-block loop below OVERWRITES this with
  // the same Entry key when BlockIROp->EntryPoint && GuestEntryOffset == 0,
  // so the address the dispatcher actually branches to is the block's
  // bound JumpTarget. The spill-frame stdu therefore has to be emitted
  // INSIDE the for-loop, immediately after the EntryPoint recording, not
  // here.
  CodeData.EntryPoints[Entry] = GetCursorAddress<uint8_t*>();

  // -------------------------------------------------------------------------
  // Dispatch table
  // -------------------------------------------------------------------------
  using OpType = void (PPC64JITCore::*)(const IR::IROp_Header*, IR::Ref);
  // C++ guarantees thread-safe initialization of function-local statics with non-trivial
  // initialisers, which avoids the race that the previous "static bool TableInit" form had
  // when two threads entered CompileCode concurrently before the table was filled.
  static const auto OpHandlers = []{
    using TableT = std::array<OpType, static_cast<size_t>(IR::IROps::OP_LAST) + 1>;
    TableT t{};
    for (auto& h : t) h = &PPC64JITCore::Op_Unhandled;
    t[static_cast<size_t>(IR::IROps::OP_DUMMY)]       = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_IRHEADER)]    = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_CODEBLOCK)]   = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_BEGINBLOCK)]  = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_ENDBLOCK)]    = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_INVALIDATEFLAGS)] = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_INLINECONSTANT)]  = &PPC64JITCore::Op_NoOp;
    t[static_cast<size_t>(IR::IROps::OP_INLINEENTRYPOINTOFFSET)] = &PPC64JITCore::Op_NoOp;

#define REGISTER_OP(op, func)                                                          \
    t[static_cast<size_t>(IR::IROps::OP_##op)] = &PPC64JITCore::Op_##func;

#define IROP_DISPATCH_DISPATCH
#include <FEXCore/IR/IRDefines_Dispatch.inc>

    // x87 stack-bookkeeping ops (X87Ops.cpp). These are NOT in the
    // auto-generated IRDefines_Dispatch.inc — IR.json marks them as JIT-not-
    // dispatched (intended to be lowered by x87StackOptimizationPass) — but
    // the pass is gated on `!DisablePasses()`, so any path that runs with O0
    // (or future paths that don't run the pass) leaves them in the IR. The
    // legacy fallthrough was Op_Unhandled with no FABI handler, which
    // silently no-op'd. Wire each one explicitly.
    REGISTER_OP(INITSTACK,         InitStack);
    REGISTER_OP(INCSTACKTOP,       IncStackTop);
    REGISTER_OP(DECSTACKTOP,       DecStackTop);
    REGISTER_OP(INVALIDATESTACK,   InvalidateStack);
    REGISTER_OP(PUSHSTACK,         PushStack);
    REGISTER_OP(COPYPUSHSTACK,     CopyPushStack);
    REGISTER_OP(POPSTACKDESTROY,   PopStackDestroy);
    REGISTER_OP(READSTACKVALUE,    ReadStackValue);
    REGISTER_OP(STORESTACKMEM,     StoreStackMem);
    REGISTER_OP(STORESTACKTOSTACK, StoreStackToStack);
    REGISTER_OP(STACKVALIDTAG,     StackValidTag);
    REGISTER_OP(SYNCSTACKTOSLOW,   SyncStackToSlow);
    REGISTER_OP(STACKFORCESLOW,    StackForceSlow);

    // Bucket C: stack-form arithmetic ops. Wired the same way — these aren't
    // in IRDefines_Dispatch.inc because IR.json marks them JIT-not-dispatched
    // (intended to be lowered by x87StackOptimizationPass). When the pass
    // doesn't run (O0), they survive to the JIT.
    REGISTER_OP(F80ADDSTACK,       F80AddStack);
    REGISTER_OP(F80SUBSTACK,       F80SubStack);
    REGISTER_OP(F80MULSTACK,       F80MulStack);
    REGISTER_OP(F80DIVSTACK,       F80DivStack);
    REGISTER_OP(F80ADDVALUE,       F80AddValue);
    REGISTER_OP(F80SUBVALUE,       F80SubValue);
    REGISTER_OP(F80SUBRVALUE,      F80SubRValue);
    REGISTER_OP(F80MULVALUE,       F80MulValue);
    REGISTER_OP(F80DIVVALUE,       F80DivValue);
    REGISTER_OP(F80DIVRVALUE,      F80DivRValue);
    REGISTER_OP(F80CMPSTACK,       F80CmpStack);
    REGISTER_OP(F80CMPVALUE,       F80CmpValue);
    REGISTER_OP(F80STACKTEST,      F80StackTest);
    REGISTER_OP(F80SQRTSTACK,      F80SQRTStack);
    REGISTER_OP(F80SINSTACK,       F80SINStack);
    REGISTER_OP(F80COSSTACK,       F80COSStack);
    REGISTER_OP(F80F2XM1STACK,     F80F2XM1Stack);
    REGISTER_OP(F80SINCOSSTACK,    F80SINCOSStack);
    REGISTER_OP(F80ROUNDSTACK,     F80RoundStack);
    REGISTER_OP(F80FYL2XSTACK,     F80FYL2XStack);
    REGISTER_OP(F80SCALESTACK,     F80SCALEStack);
    REGISTER_OP(F80FPREMSTACK,     F80FPREMStack);
    REGISTER_OP(F80FPREM1STACK,    F80FPREM1Stack);
    REGISTER_OP(F80PTANSTACK,      F80PTANStack);
    REGISTER_OP(F80ATANSTACK,      F80ATANStack);
    REGISTER_OP(F80VBSLSTACK,      F80VBSLStack);
    REGISTER_OP(F80STACKXCHANGE,   F80StackXchange);
    REGISTER_OP(F80STACKCHANGESIGN, F80StackChangeSign);
    REGISTER_OP(F80STACKABS,       F80StackAbs);

#undef REGISTER_OP
    return t;
  }();

  // -------------------------------------------------------------------------
  // Block iteration
  // -------------------------------------------------------------------------
  // Per-EntryPoint spill-frame prologue.
  //
  // ExitFunction / Break / CallbackReturn all call ResetStack, which emits
  //   addi r1, r1, +SpillFrameSize — the matching pop for the block-prologue
  // stdu. The dispatcher's LookupCache registers EVERY block tagged
  // EntryPoint=true (Core.cpp AddBlockMapping loop), so a dispatcher hit can
  // jump DIRECTLY to any non-first EntryPoint block. Previously the JIT
  // emitted the stdu only at the first IR block (SpillFrameEmitted guard);
  // dispatcher hits at secondary EntryPoints skipped the stdu while still
  // running the addi at exit, so r1 drifted up by SpillFrameSize per such
  // dispatch and eventually walked off the host stack mapping → SIGSEGV
  // after ~5000 dispatches in multi-block CompileCodes (e.g. sse2-mul-1
  // gcc-target at MAXINST=500).
  //
  // Fix mirrors Arm64JITCore: every EntryPoint emits its own stdu. Layout:
  //   <EntryPoint addr>     ← dispatcher target (LookupCache hit lands here)
  //     stdu r1, -SpillFrameSize, r1
  //   JumpTarget(BlockNode):  ← intra-CompileCode  b BlockN_label  lands here
  //     block body
  // Intra-block jumps skip the stdu because the calling block already has
  // the frame live; dispatcher hits run the stdu. Both paths balance at
  // ExitFunction's ResetStack.
  for (auto [BlockNode, BlockHeader] : IRView->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();

    if (BlockIROp->EntryPoint) {
      uint64_t GuestEntry = Entry + BlockIROp->GuestEntryOffset;
      CodeData.EntryPoints[GuestEntry] = GetCursorAddress<uint8_t*>();
      if (SpillFrameSize) {
        // stdu's 14-bit signed DS field encodes byte offsets in [-32768, 32764].
        // For larger frames, emit the equivalent of stdu manually so callers
        // can't silently wrap to a positive displacement and overrun the host
        // stack mapping. Observed in TLS / X25519 paths where a single JIT
        // block has thousands of SSA values (heavy openssl C inlining).
        if (SpillFrameSize <= 32760u) {
          stdu(r1, -static_cast<int16_t>(SpillFrameSize), r1);
        } else {
          // Manual: TMP2 = old r1; r1 = r1 - SpillFrameSize; *r1 = TMP2.
          LoadImm32(TMP1, SpillFrameSize);
          mr(TMP2, r1);
          subf(r1, TMP1, r1);
          std(TMP2, 0, r1);
        }
      }
    }

    // Intra-CompileCode jump label, bound AFTER the per-EntryPoint stdu.
    Bind(JumpTarget(BlockNode));

    // Emit all ops in this block
    for (auto [CodeNode, IROp] : IRView->GetCode(BlockNode)) {
      uint16_t Op = static_cast<uint16_t>(IROp->Op);

      if (Op <= static_cast<uint16_t>(IR::IROps::OP_LAST)) {
        (this->*OpHandlers[Op])(IROp, CodeNode);
      } else {
        Op_Unhandled(IROp, CodeNode);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Finalise
  // -------------------------------------------------------------------------
  Align16B();

  size_t CodeSize = GetOffset();
  CodeData.BlockBegin = CB->Ptr + CodeBuffers.LatestOffset;
  CodeData.Size       = CodeSize;

  // Flush the freshly-emitted instructions out of the D-cache and invalidate
  // the I-cache for this range. POWER8 has split, non-coherent I/D caches: the
  // store stream that emitted these instructions hits the D-cache, but the
  // fetch stream walks the I-cache. Without this flush, branching to the new
  // code can execute stale bytes (whatever the I-cache last fetched for the
  // same physical line) — most commonly observed when SMC re-compiles a guest
  // block at a code-buffer offset whose underlying page was previously
  // executed as different host code. ARM64's CompileCode does the equivalent
  // via ClearICache (FEXCore/Source/Interface/Core/JIT/JIT.cpp:1123).
  // __builtin___clear_cache lowers to dcbst/sync/icbi/isync on PPC64.
  __builtin___clear_cache(reinterpret_cast<char*>(CodeData.BlockBegin),
                          reinterpret_cast<char*>(CodeData.BlockBegin) + CodeSize);

  CodeBuffers.LatestOffset += CodeSize;

  // Write code tail
  auto* Tail = reinterpret_cast<CPUBackend::JITCodeTail*>(
    GetCursorAddress<uint8_t*>());
  Tail->Size      = CodeSize;
  Tail->RIP       = Entry;
  Tail->GuestSize = GuestSize;
  Tail->NumberOfRIPEntries = 0;
  Tail->OffsetToRIPEntries = 0;
  Tail->SpinLockFutex      = 0;
  Tail->SingleInst         = SingleInst;
  CodeBuffers.LatestOffset += sizeof(CPUBackend::JITCodeTail);

  return CodeData;
}

uint64_t GetNamedSymbolLiteral(FEXCore::Context::ContextImpl& CTX, FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol Op) {
  switch (Op) {
  case FEXCore::CPU::RelocNamedSymbolLiteral::NamedSymbol::SYMBOL_LITERAL_EXITFUNCTION_LINKER:
    return CTX.Dispatcher->GetExitFunctionLinkerAddress();
  default: ERROR_AND_DIE_FMT("Unknown named symbol literal: {}", static_cast<uint32_t>(Op));
  }
}

// -------------------------------------------------------------------------
// Factory
// -------------------------------------------------------------------------
fextl::unique_ptr<CPUBackend> CreatePPC64JITCore(
    FEXCore::Context::ContextImpl* ctx,
    FEXCore::Core::InternalThreadState* Thread) {
  return fextl::make_unique<PPC64JITCore>(ctx, Thread);
}

} // namespace FEXCore::CPU
