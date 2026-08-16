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
#include "Interface/Core/JIT/DebugData.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Core/JIT/Relocations.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Utils/MemberFunctionToPointer.h"
#include "Utils/variable_length_integer.h"

#include <FEXCore/Utils/SignalScopeGuards.h>

#include <FEXCore/Core/Thunks.h>

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/ArchHelpers/PPC64CacheFlush.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <execinfo.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cfenv>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string_view>
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
    //   [r1+ 88..111]  pad (keep frame size a multiple of 16)
    //
    // The helper called by bctrl is a non-leaf C function whose prologue
    // saves the incoming LR to "caller_r1 + 16" per the PPC64LE ELFv2 ABI.
    // After SpillForABICall that lands inside the PushDynamicRegs frame's
    // linkage area, which exists precisely to absorb it: dynamic GPR spill
    // slots start at kDynGPRStart == kDynLinkArea == 96, and nothing reads
    // [r1+16] on this path. No rescue of that slot is needed.
    constexpr int FrameSize = 112;
    const int SpillSaveSize = CTX->Config.Is64BitMode() ? static_cast<int>(x64::kDynRegSaveSize) : static_cast<int>(x32::kDynRegSaveSize);
    constexpr int SlotA   = 32;     // LHS vector
    constexpr int SlotB   = 48;     // RHS vector
    constexpr int SlotRAX = 64;     // ESTRX RAX
    constexpr int SlotRDX = 72;     // ESTRX RDX
    constexpr int SlotR   = 80;     // 64-bit return value
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
      EmitLoadPPC64Helper(r(12), PPC64_HELPER_VPCMPESTRX);
    } else {
      LoadConstant(r5, Control);          // r5 = Control
      EmitLoadPPC64Helper(r(12), PPC64_HELPER_VPCMPISTRX);
    }

    std(r2, Post(24), r1);                // save TOC (helper is intra-DSO,
                                          //   but bctrl semantics are unchanged)
    mtctr(r(12)); bctrl();
    ld(r2, Post(24), r1);                 // restore TOC

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

  // Save LR at the top of a 4096-byte scratch/link frame for the callee.
  // The frame gives HandleFallback's callees (softfloat etc.) headroom
  // for their own stack use without touching the JIT block's spill area
  // above -- that area lives at [r1 + kSpillSlotPrefix + slot*32] and is
  // already above the ELFv2 96B linkage+param block; the additional 4096
  // is defensive against unusually deep callee chains, not required for
  // ABI correctness.
  mflr(TMP2); addi(r1, r1, -4096); std(TMP2, 0, r1);

  // Volatile dynamic VRs are caller-saved around ABIPointers stubs (the stub's
  // own Push/PopDynamicRegs run under an empty VR mask — see the
  // DynVRSpillMask contract in PPC64Emitter.h). Save exactly the pool entries
  // live across this IR op into this scratch frame at [r1+16..]; only [r1+0]
  // (LR) is otherwise in use below. Must precede the source staging in the
  // switch: it clobbers TMP3, which the VPCMPESTRX case loads afterwards.
  SaveDynVRsToFrame(16);

  // Restore mirror + the frame teardown every case below shares. The restore
  // must happen while the frame is still live and must precede the per-case
  // result moves (which target the just-restored pool registers).
  auto FABIFrameLeave = [&]() {
    RestoreDynVRsFromFrame(16);
    ld(TMP2, 0, r1);
    mtlr(TMP2);
    addi(r1, r1, 4096);
    li(r(0), 0);
  };

  // Load ABIHandler into r0, Func into TMP4.
  // Both offsets are FallbackHandlerPointers base + Idx*sizeof(FallbackABIInfo) + (0|8) —
  // 8-byte aligned by construction and bounded well below INT16_MAX (see static_assert), so
  // d-form `ld` is safe. The prior LoadImm32+ldx pair carried a silent uint32_t→int16_t hazard
  // (`ld`'s only assert checks alignment, not range) and serialised TMP2 in front of mtctr/bctrl.
  static_assert(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers,
                   FEXCore::Core::FallbackHandlerIndex::OPINDEX_MAX - 1)
      + offsetof(FEXCore::Core::FallbackABIInfo, Func) <= INT16_MAX,
    "FABI helper offsets must fit int16_t for d-form ld");
  ld(r(0), static_cast<int16_t>(ABIHandlerOff), STATE);
  ld(TMP4, static_cast<int16_t>(FuncOff), STATE);
  // TMP2 is now free to reuse for source setup

  switch (Info.ABI) {

  case FABI_F80_I16_F32_PTR:
  case FABI_F80_I16_F64_PTR: {
    // Stub expects VTMP1 = source float/double vector (LE-element-0)
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F80_I16_I16_PTR: {
    // Stub expects TMP2(r4) = sign-extended int16
    extsh(TMP2, GetReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F80_I16_I32_PTR: {
    // Stub expects TMP2(r4) = sign-extended int32
    extsw(TMP2, GetReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F32_I16_F80_PTR:
  case FABI_F64_I16_F80_PTR:
  case FABI_F64_F64_PTR:
  case FABI_F80_I16_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_F64_F64_F64_PTR:
  case FABI_F80_I16_F80_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    vmr(VTMP2, GetVReg(IROp->Args[1]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    vmr(GetVReg(Node), VTMP1);
    break;
  }

  case FABI_I16_I16_F80_PTR:
  case FABI_I32_I16_F80_PTR:
  case FABI_I64_I16_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_I64_I16_F80_F80_PTR: {
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    vmr(VTMP2, GetVReg(IROp->Args[1]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_F80x2_I16_F80_PTR: {
    // Returns two F80 vectors: VTMP1 (low) and VTMP2 (high)
    const auto DstLo = GetVReg(IROp->Args[1]);
    const auto DstHi = GetVReg(IROp->Args[2]);
    vmr(VTMP1, GetVReg(IROp->Args[0]));
    mtctr(r(0)); bctrl();
    FABIFrameLeave();
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
    FABIFrameLeave();
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
    FABIFrameLeave();
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
    FABIFrameLeave();
    mr(GetReg(Node), TMP1);
    break;
  }

  case FABI_UNKNOWN:
  default:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled IR Fallback ABI: {} {}", FEXCore::IR::GetName(IROp->Op), ToUnderlying(Info.ABI));
#endif
    // Still need to pop LR frame
    FABIFrameLeave();
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

bool PPC64JITCore::IsSplatFormValue(const IR::OrderedNodeWrapper& WNode, IR::OpSize ElementSize) const {
  if (WNode.IsInvalid() || WNode.IsImmediate()) {
    return false;
  }

  auto IROp = IR->GetOp<IR::IROp_Header>(WNode);
  switch (IROp->Op) {
  case IR::IROps::OP_LOADREGISTER:
    // The frontend's per-instruction register-cache flush (Core.cpp:851) means
    // a chain's consumers read their operands back out of the guest XMM's
    // static register rather than off an SSA edge. The pass stamps the element
    // size onto those loads when the value in that register is known splatted;
    // SRAFPR (v0..v15) is disjoint from RAFPR (v16..v29), so nothing but the
    // tracked StoreRegister can have written it.
    return IROp->C<IR::IROp_LoadRegister>()->SplatElementSize == ElementSize;
  case IR::IROps::OP_VFADDSCALARINSERT:
  case IR::IROps::OP_VFSUBSCALARINSERT:
  case IR::IROps::OP_VFMULSCALARINSERT:
  case IR::IROps::OP_VFDIVSCALARINSERT:
    // The element size has to agree: an f32 splat replicates a word, so its
    // doubleword 1 is {value, value} rather than the architectural
    // {Vector1.word2, value} an f64 reader would expect (and vice versa). The
    // IR pass enforces the same match when it marks, this is the backend half
    // of that contract.
    return IROp->ElementSize == ElementSize && IROp->C<IR::IROp_VFAddScalarInsert>()->SplatResult;
  default: return false;
  }
}

// -------------------------------------------------------------------------
// Named thunk relocation
// -------------------------------------------------------------------------
void PPC64JITCore::InsertNamedThunkRelocation(GPR Reg, const IR::SHA256Sum& Sum) {
  Relocation Reloc {};
  Reloc.NamedThunkMove.Header = {
    // S3.7-C0: buffer-relative, not block-relative. GetOffset() is inside the
    // per-block SetBuffer window at JIT.cpp:2250 but ApplyCodeRelocations
    // indexes from CodeBuffer->Ptr. BlockBufferOffset is the snapshot from
    // just before SetBuffer.
    .Offset = BlockBufferOffset + static_cast<uint64_t>(GetOffset()),
    .Type   = FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE,
  };
  Reloc.NamedThunkMove.Symbol        = Sum;
  Reloc.NamedThunkMove.RegisterIndex = Reg.idx;

  uint64_t Pointer = 0;
  if (CTX->ThunkHandler) {
    Pointer = reinterpret_cast<uint64_t>(CTX->ThunkHandler->LookupThunk(Sum));
  }
  // S3.7-C1: use the fixed-width form so ApplyCodeRelocations' PatchEmitter
  // re-emits into the identical 20-byte window. LoadConstant here would take
  // the 1-instruction short-circuit when Pointer is 0 (thunk missing / not
  // registered), and the on-load patch would overrun the emitted window.
  LoadConstantFixed(Reg, Pointer);
  Relocations.emplace_back(Reloc);
}

// S3.7-C2: guest-RIP-derived constant load with relocation record.
// LoadConstantFixed reserves the 20-byte patch window; the recording captures
// the ABSOLUTE guest RIP (TakeRelocations rebases against the section base at
// serialization time). On load, ApplyCodeRelocations at
// CodeCache.cpp::RELOC_GUEST_RIP_MOVE re-emits LoadConstantFixed with
// `GuestEntry + delta` — i.e. the block's current-session guest RIP.
void PPC64JITCore::InsertGuestRIPMove(GPR Reg, uint64_t Constant) {
  Relocation Reloc {};
  Reloc.GuestRIP.Header = {
    .Offset = BlockBufferOffset + static_cast<uint64_t>(GetOffset()),
    .Type   = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE,
  };
  Reloc.GuestRIP.GuestRIP      = Constant;   // TakeRelocations subtracts base
  Reloc.GuestRIP.RegisterIndex = Reg.idx;
  LoadConstantFixed(Reg, Constant);
  Relocations.emplace_back(Reloc);
}

// EntrypointOffset's guest RIP. Structurally identical to the gate in
// InsertExitRIPMove below, and correct for the same reason.
//
// The fixed-width form exists only so CodeCache::ApplyCodeRelocations has a
// 20-byte window to re-emit RELOC_GUEST_RIP_MOVE into with a rebased address.
// Relocations are consumed by nothing else, so when ExitRIPFixedWidth is false
// -- neither code caching nor SMCSemanticPatch is on, which is the default --
// there is no consumer for either the window or the record. Emitting the
// ordinary variable-width load is then both correct and strictly shorter: every
// sub-4GiB guest RIP (all of a 32-bit guest, and non-PIE 64-bit ones) collapses
// to 1-3 instructions instead of always 5, and the sequence is never longer
// than the fixed form.
//
// This matters more than the exit-RIP case it copies: EntrypointOffset is how
// the return address of every guest `call` is materialised, so it is on the
// hot emission path of essentially every block.
//
// Gating on ExitRIPFixedWidth rather than the caching knob alone is deliberate
// conservatism: SMCSemanticPatch never repatches an *entrypoint* window, but
// keeping the two RIP paths on one predicate means a future consumer that
// scans for fixed-width RIP windows cannot find one path converted and the
// other not.
void PPC64JITCore::InsertEntrypointRIPMove(GPR Reg, uint64_t Constant) {
  if (!ExitRIPFixedWidth) {
    LoadConstant(Reg, Constant);
    return;
  }
  InsertGuestRIPMove(Reg, Constant);
}

// SMC Idea 4: see JITClass.h. Records the emitted window so the fault handler
// can repatch it, and (flag on only) verifies that SMCSemanticPatch.h's
// dependency-free re-encoder still agrees with the emitter byte for byte --
// the whole scheme rests on synthesizing an identical 20-byte window, so any
// future change to LoadImm64Fixed must fail here rather than silently turn
// every fault-time match into a miss.
void PPC64JITCore::InsertExitRIPMove(GPR Reg, uint64_t Constant) {
  if (!ExitRIPFixedWidth) {
    // Neither consumer of the fixed-width window exists in this configuration
    // (see the ExitRIPFixedWidth resolution in the constructor), so emit the
    // ordinary variable-width load: 1-5 instructions instead of always 5.
    // Guest RIPs below 4 GiB -- every 32-bit guest, and non-PIE 64-bit ones --
    // collapse to 1-3, and the sequence is never longer than the fixed form.
    //
    // No RELOC_GUEST_RIP_MOVE is recorded here, deliberately: a relocation
    // promises ApplyCodeRelocations a 20-byte window it can re-emit into, and
    // there is no such window now. Recording one anyway would let a cache
    // loader overrun the following instructions. Correct because relocations
    // are only ever consumed by the code cache, which ExitRIPFixedWidth
    // already proved to be off -- the same construction-time assumption
    // BlockLinkingEnabled has always made.
    LoadConstant(Reg, Constant);
    return;
  }

  if (!CTX->Config.SMCSemanticPatch()) {
    InsertGuestRIPMove(Reg, Constant);
    return;
  }

  auto* Window = GetCursorAddress<uint8_t*>();
  InsertGuestRIPMove(Reg, Constant);

  [[maybe_unused]] uint32_t Expected[FEXCore::SMC::kRIPWindowWords];
  FEXCore::SMC::SynthesizeRIPWindow(Reg.idx, Constant, Expected);
  LOGMAN_THROW_A_FMT(::memcmp(Window, Expected, FEXCore::SMC::kRIPWindowBytes) == 0,
                     "SMCSemanticPatch::SynthesizeRIPWindow disagrees with LoadImm64Fixed for {:#x}", Constant);

  if (CodeData.ExitRIPSites.size() >= FEXCore::SMC::kMaxSitesPerBlock) {
    // Over the cap: drop the whole table so the block is ineligible rather than
    // partially described (a partial table would let the handler conclude "this
    // branch has no constant exit" and decline for the wrong reason -- or worse,
    // match a different site).
    CodeData.ExitRIPSites.clear();
    ExitRIPSitesOverflowed = true;
    return;
  }
  if (ExitRIPSitesOverflowed) {
    return;
  }
  CodeData.ExitRIPSites.push_back({reinterpret_cast<uint64_t>(Window)});
}

// SMC Idea 4, mov-immediate half: see JITClass.h.
bool PPC64JITCore::TryInsertPatchableImmMove(GPR Reg, uint64_t Constant, uint32_t PatchSite) {
  if (PatchSite == 0 || !CTX->Config.SMCSemanticPatch()) {
    return false;
  }
  if (MovImmWindowsOverflowed) {
    return false;
  }
  if (CodeData.MovImmWindows.size() >= FEXCore::SMC::kMaxSitesPerBlock) {
    // Over the cap: drop the whole table so the block is ineligible rather than
    // partially described, exactly as InsertExitRIPMove does.
    CodeData.MovImmWindows.clear();
    MovImmWindowsOverflowed = true;
    return false;
  }

  auto* Window = GetCursorAddress<uint8_t*>();
  LoadConstantFixed(Reg, Constant);

  [[maybe_unused]] uint32_t Expected[FEXCore::SMC::kRIPWindowWords];
  FEXCore::SMC::SynthesizeRIPWindow(Reg.idx, Constant, Expected);
  LOGMAN_THROW_A_FMT(::memcmp(Window, Expected, FEXCore::SMC::kRIPWindowBytes) == 0,
                     "SMCSemanticPatch::SynthesizeRIPWindow disagrees with LoadImm64Fixed for {:#x}", Constant);

  CodeData.MovImmWindows.push_back({reinterpret_cast<uint64_t>(Window), PatchSite - 1});
  return true;
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
  // Floating-point conditions on the compare field set by fcmpu / xscmpudp:
  // LT/GT/EQ have IEEE-ordered meaning, SO is set on unordered. FU/FNU test
  // SO directly.
  //
  // KNOWN DEFECT, UNREACHABLE, NOT FIXABLE HERE: FLU and FGE need unordered
  // folded in (CC_LT is false on NaN when it must be true; CC_GE is true on
  // NaN when it must be false — `ucomisd; jae` takes the x86-opposite
  // branch). MapNZCVCC below carries the full four-condition derivation and
  // the fix for its own copy of this defect.
  //
  // It cannot be repeated here. MapCC is `static` — it has no emitter — and
  // its callers REBASE the returned BI onto whatever CR field they compared
  // into (DEF_OP(Select) and DEF_OP(NZCVSelect) both do `CC.BI + 28` for
  // cr7, and EmitCompare takes CRField as a parameter). A crnor/cror
  // composite would have to be emitted by the caller, into a scratch CR bit,
  // after the compare — i.e. this is a caller-side fix, not a table entry.
  // Note that such a caller-side fix reads unordered straight out of the
  // compare's own CR field (SO, at CRField*4 + 3) — NOT the XER projection
  // MapNZCVCC uses, since these callers compare with fcmpu/xscmpudp into cr7
  // and never lift SO into XER.OV.
  //
  // Nothing reaches it today: X86ToArmFloatCond in
  // RedundantFlagCalculationElimination.cpp is the only producer of FLU/FGE
  // and it is only called from FoldBranch's AXFLAG arm, disabled in
  // 68217d849 — and since 61f785c2a the COMIS chain lowers to the fused
  // DEF_OP(FCmpX86), which emits no AXFLAG for that arm to match in the first
  // place. Anyone re-enabling that arm must fix this site (caller-side),
  // MapNZCVCC (already done), and the shared ULE -> SLE identity remap.
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
// ProjectXERToCR1: make XER's carry/overflow state branch-testable in CR1
// without modifying XER. Two sequences, and they do NOT produce the same
// layout — which is why the OV bit index comes from XEROVBitIndex() below
// rather than being written out at each use site.
//
// ISA 3.0 path (POWER9+), one instruction, `mcrxrx 1`:
//   CR1.LT (PPC bit 4) <- XER.OV
//   CR1.GT (PPC bit 5) <- XER.OV32   (32-bit overflow — NOT the V we want)
//   CR1.EQ (PPC bit 6) <- XER.CA
//   CR1.SO (PPC bit 7) <- XER.CA32
//
// Pre-3.0 path (POWER8), three instructions, mfxer / rotlwi / mtocrf:
//   CR1.LT (PPC bit 4) <- XER.SO
//   CR1.GT (PPC bit 5) <- XER.OV
//   CR1.EQ (PPC bit 6) <- XER.CA
//   CR1.SO (PPC bit 7) <- 0 (don't care)
// XER bits in mfspr-result GPR (LSB numbering): SO=31, OV=30, CA=29.
// rotlwi by 28 maps SO 31->27 (PPC 4), OV 30->26 (PPC 5), CA 29->25 (PPC 6).
// mtocrf with FXM=0x40 selects only CR1 (single-field form — uncracked where
// multi-field mtcrf is microcoded; POWER9 UM §4.1.5.6).
//
// Reading the two together: CA lands in CR1.EQ either way, so every C-
// consuming condition is index-stable. OV moves bit 5 -> bit 4. XER.SO is
// projected only by the pre-3.0 path and is read by nothing — no MapNZCVCC
// case returns BI 4 and no composite reads bit 4 on that layout — so the ISA
// 3.0 path losing SO costs nothing.
//
// Register contract: the pre-3.0 path clobbers TMP1/TMP2; the ISA 3.0 path
// clobbers no GPRs at all. Callers may assume the pre-3.0 (larger) clobber
// set unconditionally.
//
// This is the hot path for every C/V-consuming condition, so the form matters.
// Measured on POWER9 DD2.2 (SMT=2, numactl node 0, median of 9): mcrxrx is
// 28.6% faster on a dependent chain (9.08 -> 6.48 ns) and 43.5% faster on four
// independent streams (1.34 -> 0.76 ns). See build-probes/opbench_xer.c, which
// also checks the two layouts against ground truth before reporting timings.
// -------------------------------------------------------------------------
bool PPC64JITCore::ProjectXERUsesMcrxrx() const {
  return EmitterCTX->HostFeatures.SupportsISA30;
}

uint32_t PPC64JITCore::XEROVBitIndex() const {
  // CR1.LT on the mcrxrx layout, CR1.GT on the pre-3.0 layout.
  return ProjectXERUsesMcrxrx() ? 4u : 5u;
}

void PPC64JITCore::ProjectXERToCR1() {
  // Emit-time projection cache: consecutive C/V-consuming conditions within a
  // block (setcc pairs, float-compare consumers — profiled at 2x projections
  // per FCmp consumer in countersunk's hydro heap code and visible in W3's
  // in-world flag traffic) re-project identical XER state. The flag is
  // maintained by CompileCode: reset at block entry, and cleared AFTER every
  // op whose handler is not on the no-XER/CR1-write allowlist — post-handler
  // (not pre) because an op may project and THEN write XER inside one handler
  // (CondAdd/CondSubNZCV's addco_/subfco_ after MapNZCVCC).
  if (XERProjectionValid) {
    return;
  }
  if (ProjectXERUsesMcrxrx()) {
    mcrxrx(1);  // CR1: LT=OV, GT=OV32, EQ=CA, SO=CA32
  } else {
    mfspr(TMP1, 1);
    rlwinm(TMP2, TMP1, 28, 0, 31);  // rotlwi 28
    mtocrf(0x40, TMP2);
  }
  XERProjectionValid = true;
}

// -------------------------------------------------------------------------
// MapNZCVCC: decode an IR CondClass against packed NZCV semantics, where
//   N = CR0.LT (sign of last result), Z = CR0.EQ, C = XER.CA, V = XER.OV.
// For C/V conditions and signed-with-OF conditions we project XER->CR1 and
// optionally synthesize a composite CR3 bit via crand/crxor/crandc/crnor.
//
// CR-bit indices used here (PPC numbering):
//   CR0.LT=0, CR0.GT=1, CR0.EQ=2
//   CR1.EQ=6 (CA/C)   — same on both ProjectXERToCR1 layouts
//   CR1 V bit         — bit 4 (LT) on the ISA 3.0 mcrxrx layout,
//                       bit 5 (GT) on the pre-3.0 mfxer/rotlwi/mtocrf layout.
//                       Never hardcode it; use OVBit below, which is derived
//                       from the same predicate that selects the sequence, so
//                       the two cannot drift apart.
//   CR3.LT=12, CR3.GT=13 (used as scratch for composites)
// -------------------------------------------------------------------------
PPC64Emitter::Cond PPC64JITCore::MapNZCVCC(IR::CondClass Cond) {
  // Must match whatever ProjectXERToCR1() emits below — both come from
  // ProjectXERUsesMcrxrx().
  const uint32_t OVBit = XEROVBitIndex();

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
  case IR::CondClass::VS:  ProjectXERToCR1(); return {12, OVBit};  // V=1
  case IR::CondClass::VC:  ProjectXERToCR1(); return { 4, OVBit};  // V=0

  // UGT = C=1 AND Z=0 ; ULE = !UGT
  case IR::CondClass::UGT: ProjectXERToCR1();
                           crandc(12, 6, 2);   // CR3.LT = C AND NOT Z
                           return {12, 12};
  case IR::CondClass::ULE: ProjectXERToCR1();
                           crandc(12, 6, 2);
                           return { 4, 12};

  // SLT = N!=V ; SGE = N==V
  case IR::CondClass::SLT: ProjectXERToCR1();
                           crxor(12, 0, OVBit);  // CR3.LT = N XOR V
                           return {12, 12};
  case IR::CondClass::SGE: ProjectXERToCR1();
                           crxor(12, 0, OVBit);
                           return { 4, 12};

  // SGT = (N==V) AND Z=0 ; SLE = !SGT
  case IR::CondClass::SGT: ProjectXERToCR1();
                           crxor(12, 0, OVBit);  // CR3.LT = SLT (N XOR V)
                           crnor(13, 12, 2);     // CR3.GT = NOT (SLT OR Z) = SGT
                           return {12, 13};
  case IR::CondClass::SLE: ProjectXERToCR1();
                           crxor(12, 0, OVBit);
                           crnor(13, 12, 2);
                           return { 4, 13};

  // FP conditions on CR0 set by fcmpu / xscmpudp.
  //
  // Unordered must be folded into FLU and FGE, and MUST NOT be folded into
  // FLEU and FGT. Working the four out against the raw compare field, where
  // NaN sets only SO and leaves LT/GT/EQ all clear:
  //
  //   FLU  ("less than or unordered", = Arm LT after fcmp, N!=V)
  //        CC_LT = {12,0} = "CR0.LT set" -> FALSE on NaN.  WRONG.
  //   FGE  ("greater or equal", = Arm GE after fcmp, N==V)
  //        CC_GE = { 4,0} = "CR0.LT clear" -> TRUE on NaN.  WRONG.
  //   FGT  CC_GT = {12,1} = "CR0.GT set"   -> FALSE on NaN.  Correct:
  //        x86 `ja` after comiss must not take on unordered (CF=ZF=1).
  //   FLEU CC_LE = { 4,1} = "CR0.GT clear" -> TRUE on NaN.  Correct:
  //        "less-or-equal-or-unordered" is supposed to include unordered.
  //
  // So exactly FLU and FGE are wrong, and both in the direction that takes
  // the x86-opposite branch on NaN: `ucomisd; jae` was taken on NaN, where
  // x86 sets CF=1 on unordered and JAE must NOT take.
  //
  // Fix: in the packed-NZCV world V = XER.OV, and DEF_OP(FCmp) lifts the
  // compare's SO into XER.OV precisely so this works. Project XER into CR1
  // and fold that bit into the predicate with the same CR3.LT
  // composite-scratch discipline the SLT/UGT/SGT cases above use. The bit is
  // OVBit, never a literal: XER.OV lands in CR1.GT (5) on the pre-3.0
  // mfxer/rotlwi projection but in CR1.LT (4) on the ISA 3.0 mcrxrx one,
  // where 5 is OV32 -- which DEF_OP(FCmp) does not write, so hardcoding 5
  // folded a stale bit in on POWER9. Ported from origin/power9 382d0eb60,
  // which predates the mcrxrx projection.
  //
  // Reachability in THIS tree: X86ToArmFloatCond in
  // RedundantFlagCalculationElimination.cpp is the only producer of FLU/FGE,
  // and it is only called from FoldBranch's AXFLAG arm, which 68217d849
  // disabled outright. Since 61f785c2a there is a second layer: with
  // SupportsFCmpX86 the COMIS chain lowers to the fused DEF_OP(FCmpX86) and
  // emits no AXFLAG at all, so even a re-enabled arm would not see the
  // pattern from that source. So this is defense-in-depth today. Do NOT read
  // it as clearance to re-enable that arm: our own analysis found a SECOND,
  // independent defect there (the ULE -> SLE identity remap, a property of
  // the shared mapping table rather than of this backend) which this hunk
  // does not touch. See the block comment at that `return`.
  //
  // Note also that FCmpX86 is NOT a producer of the state read here: it
  // leaves XER.OV = 0 and folds unordered into ZF, i.e. the x86 layout. These
  // two cases decode the ARM-FCMP layout that DEF_OP(FCmp) produces, and only
  // that.
  case IR::CondClass::FLU:  ProjectXERToCR1();
                            cror (12, 0, OVBit);   // CR3.LT =   LT OR UN
                            return {12, 12};
  case IR::CondClass::FGE:  ProjectXERToCR1();
                            crnor(12, 0, OVBit);   // CR3.LT = !(LT OR UN)
                            return {12, 12};
  case IR::CondClass::FLEU: return CC_LE;
  case IR::CondClass::FGT:  return CC_GT;
  // FU/FNU in NZCV context = integer overflow (XER.OV via CR1), NOT
  // FP-unordered. The shared OpcodeDispatcher reuses these as OF-set /
  // OF-clear codes (OpcodeDispatcher.cpp:564, .h:1929) because on AArch64
  // both alias onto PSTATE.V. ALUOps.cpp::IntegerNZCVCond pre-rewrites
  // FU→VS / FNU→VC for in-file callers, but BranchOps.cpp::CondJump and
  // any other MapNZCVCC consumers (e.g. INTO at OpcodeDispatcher.cpp:4756)
  // need the correct projection here too.
  case IR::CondClass::FU:   ProjectXERToCR1(); return {12, OVBit};   // V=1
  case IR::CondClass::FNU:  ProjectXERToCR1(); return { 4, OVBit};   // V=0
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
    // Register-only compare. The old path spilled both vectors and reloaded
    // element 0 via lfs/lfd — two guaranteed store-hit-load flushes on one of
    // the hottest patterns in game code (every fused ucomiss/comiss + jcc).
    // Element 0 of a guest XMM sits in doubleword 1 (f64) / BE word 3 (f32);
    // xscmpudp compares doubleword 0, so position first. xscvspdp performs
    // the same SP->DP promotion lfs did, so NaN/denormal ordering semantics
    // are unchanged; both paths end in an unordered compare into CRField.
    auto V1 = GetVReg(Src1);
    auto V2 = GetVReg(Src2);
    if (Sz == IR::OpSize::i32Bit) {
      xxsldwi(VTMP1, V1, V1, 3);         // BE w0 <- elem0 (BE w3)
      xscvspdp(VTMP1, VTMP1);
      xxsldwi(VTMP2, V2, V2, 3);
      xscvspdp(VTMP2, VTMP2);
    } else {
      xxpermdi(VTMP1, V1, V1, 0b10);     // dw0 <- dw1
      xxpermdi(VTMP2, V2, V2, 0b10);
    }
    xscmpudp(CRField, VTMP1, VTMP2);
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
// It only exists — and is only maintained by the emitted dispatcher — in
// assertions builds; in Release the dispatcher does not pay for it.
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
extern "C" {
  extern uint64_t g_dispatch_count;
  extern uint64_t g_recent_rips[16];
}
#define FEX_PPC64_RIP_TRACE 1
#else
#define FEX_PPC64_RIP_TRACE 0
#endif

// Nth-most-recent dispatched guest RIP (N >= 1), or 0 if unavailable — either
// because the trace is compiled out or because fewer than N blocks have been
// dispatched. Callers must treat 0 as "no data", never as a real RIP.
[[maybe_unused]] static uint64_t RecentDispatchedRIP([[maybe_unused]] int N) {
#if FEX_PPC64_RIP_TRACE
  const uint64_t Count = g_dispatch_count;
  if (N < 1 || static_cast<uint64_t>(N) > Count) {
    return 0;
  }
  return g_recent_rips[(Count - static_cast<uint64_t>(N)) & 15];
#else
  return 0;
#endif
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
// PRODUCTION DEFAULT: silent forwarding. The dump+abort is a debugging
// tripwire — opt in with FEX_EXITLINK_ABORT=1 when hunting this class (it
// fires during normal Unity/Mono loads, e.g. Ziggurat at ~22s, and would
// otherwise kill known-working titles).
static void DiagnoseSuspectGuestRIP(uint64_t GuestRIP, uint64_t HostLR,
                                     FEXCore::Core::CpuStateFrame* Frame) {
  static const bool abort_wanted = (getenv("FEX_EXITLINK_ABORT") != nullptr);
  if (!abort_wanted) {
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
                     "[FEX] suspect GuestRIP=0x%lx DispatcherRetAddr=0x%lx (const, not the JIT block)\n",
                     (unsigned long)GuestRIP, (unsigned long)HostLR);
    [[maybe_unused]] auto _ = write(2, buf, n);
#if FEX_PPC64_RIP_TRACE
    n = snprintf(buf, sizeof(buf),
                 "[FEX]   recent: [-1]=0x%lx [-2]=0x%lx [-3]=0x%lx [-4]=0x%lx [-5]=0x%lx [-6]=0x%lx\n",
                 (unsigned long)RecentDispatchedRIP(1),
                 (unsigned long)RecentDispatchedRIP(2),
                 (unsigned long)RecentDispatchedRIP(3),
                 (unsigned long)RecentDispatchedRIP(4),
                 (unsigned long)RecentDispatchedRIP(5),
                 (unsigned long)RecentDispatchedRIP(6));
#else
    // Print the absence explicitly. Emitting zeroes here would fabricate a
    // dispatch history during a corruption investigation, which is worse than
    // having none.
    n = snprintf(buf, sizeof(buf),
                 "[FEX]   recent: (RIP trace unavailable - build with -DENABLE_ASSERTIONS=TRUE)\n");
#endif
    _ = write(2, buf, n);
    n = snprintf(buf, sizeof(buf),
                 "[FEX]   RSP=0x%lx RDI=0x%lx RSI=0x%lx RAX=0x%lx ThunkCallbackRet=0x%lx\n",
                 (unsigned long)RSP, (unsigned long)RDI, (unsigned long)RSI,
                 (unsigned long)RAX, (unsigned long)TCR);
    _ = write(2, buf, n);
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
    fsync(2);
  }
  LogMan::Msg::EFmt("=== ExitFunctionLink: suspect GuestRIP=0x{:x} ===", GuestRIP);
  // HostLR is __builtin_return_address(0) taken inside ExitFunctionLink, whose only caller is the
  // dispatcher stub — so this is a fixed dispatcher address, NOT the JIT block that produced the bad
  // exit. Every capture will share the same low bits (0x3cc/0x3d0). Do not disassemble around it —
  // that dumps dispatcher code, not the faulting block. The meaningful disassembly is the previous
  // JIT block's host code, looked up from rip[-1] further down.
  LogMan::Msg::EFmt("    Dispatcher return addr (const, NOT the JIT block) = 0x{:x}", HostLR);
#if FEX_PPC64_RIP_TRACE
  LogMan::Msg::EFmt("    Recent dispatched guest RIPs (g_recent_rips):");
  {
    uint64_t _dcount = g_dispatch_count;
    for (int _ri = 1; _ri <= 16 && _ri <= static_cast<int>(_dcount); ++_ri) {
      LogMan::Msg::EFmt("      rip[-{}] = 0x{:x}", _ri, g_recent_rips[(_dcount - _ri) & 15]);
    }
  }
#else
  LogMan::Msg::EFmt("    Recent dispatched guest RIPs: (RIP trace unavailable - build with -DENABLE_ASSERTIONS=TRUE)");
  LogMan::Msg::EFmt("    Everything below that is derived from rip[-1] -- the GOT/PLT probe, the compile-log");
  LogMan::Msg::EFmt("    comparison, and the previous-JIT-block disasm -- is SKIPPED, not empty.");
#endif

  // If rip[-1] looks like it points into a mapped x86_64 region, try to
  // read the bytes there. If it's an x86 `ff 25 disp32` instruction
  // (jmp [rip+disp32]), compute the GOT slot it dereferences and read
  // the 8 bytes at that slot. This disambiguates "GOT was actually
  // corrupted to GuestRIP value" from "JIT read from wrong VA".
  {
    // 0 when the RIP trace is compiled out; the block below is then skipped
    // (the skip is announced once, above).
    const uint64_t prev_rip = RecentDispatchedRIP(1);
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
    // 0 when the RIP trace is compiled out; the block below is then skipped
    // (the skip is announced once, above).
    const uint64_t prev_rip = RecentDispatchedRIP(1);
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
    // 0 when the RIP trace is compiled out; the block below is then skipped
    // (the skip is announced once, above).
    const uint64_t prev_rip = RecentDispatchedRIP(1);
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

// -------------------------------------------------------------------------
// Block linking (constant-target JUMP exits): linker + delinkers
// -------------------------------------------------------------------------
// See DEF_OP(ExitFunction) in BranchOps.cpp for the exit-site layout and
// CompileCode's tail for the thunk/record layout. Contract summary:
//
//   in-block patch site (CallerAddress = &record + CallerOffset):
//     unlinked           first instruction of the inlined L1 probe
//     linked, in range   b HostCode                       (I-form, ±32MiB)
//     linked, far        b ThunkStart
//   thunk patch site (ThunkStart = &record - PPC64LinkRecordFromThunkStart):
//     unlinked           b LinkPath        (falls into the relink/compile path)
//     linked, far        bcl 20,31,$+4     (PC-discovery; next insns load
//                                           record.HostCode; mtctr; bctr)
//
// Every transition is ONE atomic 4-byte instruction store + icache flush per
// site. Delinking restores the exact pre-link word stashed in the record at
// emit time, so a delinked exit is byte-identical to a never-linked one.
//
// Benign-transient property the patch ORDER relies on: the thunk word is
// patched before the caller word, and the caller's far patch targets the
// thunk's first word. A remote hart that observes the caller patch but a
// stale thunk word executes `b LinkPath` and simply re-enters the linker,
// which is idempotent (AddBlockLink on a duplicate key keeps the existing
// entry; re-patching writes identical words). The reverse order would have
// no unlinked fallback.
namespace {

// bcl 20,31,$+4 — the LK=1 form the link-stack predictor does not push
// (see CodeEmitter Emitter.h::bcl). Verified encoding: opcode 16, BO=20,
// BI=31, BD=+4, AA=0, LK=1.
constexpr uint32_t PPC64_BCL_20_31_PLUS4 = 0x429F0005u;

// I-form `b`: signed 26-bit byte displacement (LI field is 24 bits, <<2).
bool PPC64BranchDisplacementInRange(int64_t Delta) {
  return (Delta & 3) == 0 && Delta >= -0x2000000ll && Delta <= 0x1FFFFFCll;
}

uint32_t PPC64EncodeBranch(int64_t Delta) {
  return 0x48000000u | (static_cast<uint32_t>(Delta) & 0x03FFFFFCu);
}

// Single atomic 4-byte instruction rewrite + icache maintenance. The store
// is naturally atomic (4-byte aligned); atomic_ref documents the intent and
// forbids tearing at the C++ level. FlushICacheRange issues
// dcbst; sync; icbi; sync; isync for the containing cache block — icbi is
// broadcast on POWER9, so remote harts stop fetching the stale word once this
// returns; instructions already in a remote pipeline may still retire as the
// OLD word, which every transition above tolerates (old word is always a
// correct-behaviour path).
//
// This used to call __builtin___clear_cache, which emits NO cache maintenance
// on ppc64le with either compiler in this toolchain (see
// FEXCore/Utils/ArchHelpers/PPC64CacheFlush.h for the measurement). That made
// the broadcast-icbi argument above vacuous, and on the DELINK direction —
// PPC64DirectBlockDelinker / PPC64IndirectBlockDelinker below — a missed
// invalidate can leave a remote hart fetching a live branch INTO a block that
// is being invalidated. That is a correctness hazard, not a lost optimisation.
void PPC64PatchInstruction(uintptr_t Address, uint32_t Word) {
  std::atomic_ref<uint32_t>(*reinterpret_cast<uint32_t*>(Address)).store(Word, std::memory_order_relaxed);
  FEXCore::ArchHelpers::PPC64::FlushICacheRange(reinterpret_cast<void*>(Address), 4);
}

// Both delinkers run under the LookupCache WRITE lock (GuestToHostMap::Erase
// walks BlockLinks under it) and must restore the exact pre-link instruction
// with one atomic 4-byte store. No LOGMAN dependence anywhere on this path.
void PPC64DirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Link) {
  auto* Record = reinterpret_cast<PPC64BlockLinkRecord*>(Link);
  const uintptr_t CallerAddress = reinterpret_cast<uintptr_t>(Record) + Record->CallerOffset;
  PPC64PatchInstruction(CallerAddress, Record->OrigCallerWord);
}

void PPC64IndirectBlockDelinker(FEXCore::Context::ExitFunctionLinkData* Link) {
  auto* Record = reinterpret_cast<PPC64BlockLinkRecord*>(Link);
  const uintptr_t CallerAddress = reinterpret_cast<uintptr_t>(Record) + Record->CallerOffset;
  const uintptr_t ThunkStart = reinterpret_cast<uintptr_t>(Record) - PPC64LinkRecordFromThunkStart;
  // Caller first: stop new arrivals into the thunk's linked leg, then unlink
  // the thunk word itself. A hart already past the caller word can still
  // execute the stale bcl leg and load Record->HostCode — the same in-flight
  // window every delinker on every backend has; the invalidation contract
  // (exclusive CodeInvalidationMutex + guest coherency rules) covers it.
  PPC64PatchInstruction(CallerAddress, Record->OrigCallerWord);
  PPC64PatchInstruction(ThunkStart, Record->OrigThunkWord);
}

} // anonymous namespace

uint64_t PPC64JITCore::ExitFunctionLinkWithRecord(FEXCore::Core::CpuStateFrame* Frame,
                                                  FEXCore::Context::ExitFunctionLinkData* Link) {
  auto* Record = reinterpret_cast<PPC64BlockLinkRecord*>(Link);
  auto Thread = Frame->Thread;
  auto CTX = static_cast<Context::ContextImpl*>(Thread->CTX);
  const uint64_t GuestRIP = Record->GuestRIP;

  // Snapshot the code buffer we would be linking into BEFORE any compile can
  // rotate it — same guard as ExitFunctionLink (commit 9c07619e2). A rotation
  // moves Thread->LookupCache->Shared to the new buffer's map; both the
  // lookup result and this record's patch sites belong to the old buffer and
  // must not be linked or registered against the new map.
  auto CodeBuffer = static_cast<PPC64JITCore*>(Thread->CPUBackend.get())->CurrentCodeBuffer;

  uintptr_t HostCode;
  {
    // Same lock discipline as ExitFunctionLink: the shared invalidation guard
    // MUST be dropped before CompileBlock (non-recursive WritePriorityMutex;
    // see the deadlock comment there).
    auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(CTX->CodeInvalidationMutex, Thread);
    HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP);
  }
  if (!HostCode) {
    HostCode = CTX->CompileBlock(Frame, GuestRIP, 0);
    if (!HostCode || Thread->LookupCache->Shared != CodeBuffer->LookupCache.get()) {
      // Not compilable (dispatch stub stops the thread on 0), or the buffer
      // rotated: dispatch to the result but register/patch nothing.
      return HostCode;
    }
  }

  // ---------------------------------------------------------------------
  // Link. Registration and both patches happen under the SAME exclusive
  // section: CodeInvalidationMutex (shared, so invalidation's exclusive
  // acquisition excludes us) + the LookupCache write lock (so Erase's
  // delink walk and this linker serialize).
  // ---------------------------------------------------------------------
  auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(CTX->CodeInvalidationMutex, Thread);
  auto lk = Thread->LookupCache->AcquireWriteLock();

  // RE-VALIDATE under the final write lock. Everything above ran under (at
  // most) a shared lock and there is a window between it and this point:
  // invalidation takes the exclusive lock and can erase or supersede the
  // GuestRIP -> HostCode mapping in that gap. Patching against the stale
  // HostCode would permanently branch this exit to a translation of guest
  // code that has since been REWRITTEN — callers arriving via the link would
  // diverge from callers arriving via lookup, forever, and the registration
  // would only be consumed by a future Erase that may never come. (The ARM64
  // implementation in this tree patches without re-checking; that is an
  // upstream bug, deliberately not ported.) Refuse to patch on miss or
  // mismatch; the returned HostCode is still correct for this one dispatch
  // when it came from a successful CompileBlock above, and on a stale lookup
  // the dispatch lands on the not-yet-erased old translation exactly as an
  // unlinked exit would have.
  if (Thread->LookupCache->Shared != CodeBuffer->LookupCache.get()) {
    return HostCode;
  }
  auto* Entry = Thread->LookupCache->Shared->FindBlock(GuestRIP, lk);
  if (!Entry || Entry->HostCode != HostCode) {
    return HostCode;
  }

  const uintptr_t CallerAddress = reinterpret_cast<uintptr_t>(Record) + Record->CallerOffset;
  const uintptr_t ThunkStart = reinterpret_cast<uintptr_t>(Record) - PPC64LinkRecordFromThunkStart;
  const int64_t DirectDelta = static_cast<int64_t>(HostCode) - static_cast<int64_t>(CallerAddress);
  const int64_t ThunkDelta = static_cast<int64_t>(ThunkStart) - static_cast<int64_t>(CallerAddress);

  if (PPC64BranchDisplacementInRange(DirectDelta)) {
    // Registration BEFORE patch, under the same locks: once the patched word
    // is observable, the delinker that undoes it is already findable by
    // Erase. The reverse order would leave a patched branch with no
    // registered undo if this thread stalled between the two.
    Thread->LookupCache->AddBlockLink(GuestRIP, Link, PPC64DirectBlockDelinker, lk);
    PPC64PatchInstruction(CallerAddress, PPC64EncodeBranch(DirectDelta));
  } else if (PPC64BranchDisplacementInRange(ThunkDelta)) {
    Thread->LookupCache->AddBlockLink(GuestRIP, Link, PPC64IndirectBlockDelinker, lk);

    // Publish HostCode BEFORE the thunk-word patch, with a full barrier in
    // between. The icache maintenance inside PPC64PatchInstruction runs after
    // BOTH stores, so its own `sync` cannot order one against the other —
    // without the hwsync here a remote hart
    // can fetch the new bcl leg and still read a stale HostCode, branching
    // to garbage. Sequence: store HostCode; hwsync; store patch word;
    // icache maintenance. hwsync's cumulativity guarantees any hart that
    // observes the patched word also observes the HostCode store.
    std::atomic_ref<uint64_t>(Record->HostCode).store(HostCode, std::memory_order_seq_cst);
#ifdef __powerpc64__
    asm volatile("sync" ::: "memory"); // hwsync
#else
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
    PPC64PatchInstruction(ThunkStart, PPC64_BCL_20_31_PLUS4);
    PPC64PatchInstruction(CallerAddress, PPC64EncodeBranch(ThunkDelta));
  }
  // else: even the thunk is out of `b` range of the exit (would need a
  // single compile unit larger than ±32MiB — beyond every intra-block branch
  // this backend already emits). Leave the exit unlinked; it stays on the
  // inlined-probe path forever, which is correct, just slower.

  return HostCode;
}

uint64_t PPC64JITCore::ExitFunctionLink(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  // Mode-dependent widths for the whole routine below. i386 guests have a
  // 4-byte return-address sentinel at 4-byte granularity, and a 32-bit
  // pointer canonical range (top 32 bits zero, not top 17). ExitFunctionLink
  // is a static member so CTX is not directly accessible; walk through Frame->
  // Thread->CTX, matching the pattern at :1880 below.
  auto ExitCTX = static_cast<Context::ContextImpl*>(Frame->Thread->CTX);
  const bool Is64Bit = ExitCTX->Config.Is64BitMode();
  const int  PtrShift = Is64Bit ? 47 : 32;
  const int  SlotStride = Is64Bit ? 8 : 4;

  // Suspect-RIP filter:
  //   1. Near-NULL (within first page) — can't be valid PIE-loaded x86 code
  //   2. All-CC pattern (0xCCCCCCCCCCCCCCCC) — typical "uninitialized" value
  //   3. Outside the guest's canonical range — top (64-PtrShift) bits zero.
  //      64-bit: top 17 bits (>>47); 32-bit: top 32 bits (>>32).
  auto LooksSuspect = [GuestRIP, PtrShift]() {
    if (GuestRIP < 0x1000) return true;                  // near-NULL
    if (GuestRIP == 0xCCCCCCCCCCCCCCCCULL) return true;  // all-CC
    if ((GuestRIP >> PtrShift) != 0) return true;        // beyond user canonical
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
    //
    // Mode dependence: the sentinel is pointer-sized (8 bytes on x86_64,
    // 4 bytes on i386). Walk at the correct stride and compare at the
    // correct width, or the search cannot find it and the fallback below
    // degrades to abort(). 32-bit was silently broken here since forever.
    static const bool no_bypass = (getenv("FEX_EXITLINK_NOBYPASS") != nullptr);
    if (!no_bypass) {
      uint64_t TCR = Frame->Pointers.ThunkCallbackRet;
      uint64_t RSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      if (TCR && RSP >= 0x1000 && (RSP >> PtrShift) == 0) {
        // Walk up to 128 bytes above current RSP looking for
        // ThunkCallbackRet. Bounded to avoid runaway reads. Slot count
        // stays 16 -- 128/8 in 64-bit, 128/4 = 32 more slots in 32-bit
        // if we wanted to cover the same distance, but 16*4 = 64 bytes
        // is enough for the callback frames we see in practice.
        for (int i = 0; i < 16; ++i) {
          uint64_t slot_addr = RSP + i * SlotStride;
          // Guard the read with a heuristic: only deref if slot_addr looks
          // like a valid guest VA (within the same canonical range as RSP).
          if ((slot_addr >> PtrShift) != 0) break;
          uint64_t slot_val = Is64Bit
              ? *reinterpret_cast<volatile uint64_t*>(slot_addr)
              : *reinterpret_cast<volatile uint32_t*>(slot_addr);
          // TCR is stored as full uint64_t but on i386 only its low 32 bits
          // are actually placed on the guest stack -- so mask before compare.
          const uint64_t TCR_cmp = Is64Bit ? TCR : (TCR & 0xFFFFFFFFULL);
          if (slot_val == TCR_cmp) {
            // Found callback sentinel. Adjust RSP to just past the sentinel
            // (it will be popped by CallbackReturn IR) and redirect to TCR.
            // slot_addr below the sentinel is the "stack frame" the failed
            // callback built -- discard it by walking RSP up to the sentinel.
            Frame->State.gregs[FEXCore::X86State::REG_RSP] = slot_addr;
            char buf[256];
            int n = snprintf(buf, sizeof(buf),
                             "[FEX] suspect GuestRIP=0x%lx in callback flow — bypassing via ThunkCallbackRet=0x%lx (adjusted RSP from 0x%lx to 0x%lx)\n",
                             (unsigned long)GuestRIP, (unsigned long)TCR,
                             (unsigned long)RSP, (unsigned long)slot_addr);
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

  // FEX_SMCLAZYSCRUB drain point. This is the L1-miss slow path -- the ONLY
  // way a PPC64LE guest thread can reach a translation it does not already
  // have in L1 (there is no block linking on this backend: every block exit
  // re-probes L1 inline and branches here on a miss, see BranchOps.cpp
  // DEF_OP(ExitFunction); the dispatcher loop top does the same, see
  // PPC64Dispatcher.cpp). The SMC fault handler zeroed this thread's L1 when
  // it deferred an invalidation, so the thread that just patched guest code is
  // guaranteed to arrive here before it can execute anything. Settle the debt
  // now, BEFORE the L2/L3 lookup below, or that lookup would republish exactly
  // the stale translation the scrub was meant to hide.
  //
  // Must stay above the shared CodeInvalidationMutex guard for the same reason
  // ContextImpl::CompileBlock's copy does: the drain takes the exclusive side
  // of that mutex via ReleaseAllPendingSharedLocks. Cost with the option off:
  // one relaxed load of a per-thread bool.
  if (Thread->LookupCache->TakeLazySMCDrainPending()) {
    auto* Handler = CTX->SyscallHandler;
    if (auto* LazyCount = Handler->LazySMCDirtyCount; LazyCount && LazyCount->load(std::memory_order_acquire) != 0) {
      Handler->DrainLazySMCInvalidations(Thread);
    }
  }

  uintptr_t HostCode;
  {
    // Guard the LookupCache lock with the code invalidation mutex, to avoid issues with forking.
    // This MUST be dropped before calling CompileBlock: CompileBlock takes the same shared lock,
    // and WritePriorityMutex is non-recursive. Recursive read acquisition looks harmless until an
    // exclusive waiter queues up (e.g. GuestMunmap invalidating a code range) — write-priority then
    // blocks the inner lock_shared while this thread still owns the outer read slot, deadlocking the
    // thread against itself and stalling every other reader behind the pending writer.
    auto lk_inval = GuardSignalDeferringSection<std::shared_lock>(CTX->CodeInvalidationMutex, Thread);
    HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP);
  }
  if (!HostCode) {
    // Snapshot the code buffer we would be publishing into. CompileBlock can
    // rotate to a fresh buffer if the current one fills up; the LookupCache
    // it publishes to lives on the buffer, so a rotation invalidates the
    // pointer we hold. If that happened, return the freshly-compiled
    // HostCode without registering any link/publish on top of it — the new
    // LookupCache is a clean slate and the old buffer's HostCode is still
    // valid for the caller's immediate dispatch, but must not be recorded.
    // Mirrors Arm64Emitter's ExitFunctionLink at JIT/JIT.cpp:548-555.
    auto CodeBuffer = static_cast<PPC64JITCore*>(Thread->CPUBackend.get())->CurrentCodeBuffer;
    HostCode = CTX->CompileBlock(Frame, GuestRIP, 0);
    if (Thread->LookupCache->Shared != CodeBuffer->LookupCache.get()) {
      return HostCode;
    }
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
  // PPC64JITCore::ExitFunctionLinkWithRecord no longer needs a frame slot —
  // the dispatcher stub materialises its address as an inline constant
  // (PPC64Dispatcher.cpp), so nothing has to be written per-thread.  Retiring
  // that slot keeps CpuStateFrame within its 2-page budget after C4.5/C6/C7
  // consumed the remaining headroom.

  // Resolve the block-linking gate ONCE, at backend construction:
  //   knob on  AND  code caching off.
  // The code-caching hard gate is a correctness requirement, not tuning:
  // CodeCache::SaveData dumps the live code buffer wholesale, and link thunk
  // records hold ABSOLUTE host addresses (Record.HostCode) plus a raw
  // GuestRIP as data inside the code stream, with no relocation records.
  // Serialized in one session and reloaded at a different base, a patched
  // thunk would branch to a dead absolute address. Gating emission off means
  // a caching-enabled process contains zero thunks and zero patched words,
  // so the serialized buffer is bit-identical to the non-linking backend's —
  // strictly safer than trying to delink-walk before SaveData, which would
  // still serialize the (unread-when-unlinked, but stale) HostCode fields
  // and needs a walk ordered against every thread's compile activity.
  BlockLinkingEnabled = CTX->Config.BlockLinking() && !FEXCore::Config::Get_ENABLECODECACHINGWIP();

  // Spin-loop SMT priority hints: pure nop-class emission, safe under every
  // other feature combination, so only the explicit kill switch gates it.
  SpinLoopHintEnabled = !FEXCore::Config::Get_DISABLESPINLOOPHINT();
  // Field bisect switch for the stationary-poll requirement added to the hint
  // (see AnalyzeSpinLoops): FEX_SPINHINT_ANYLOOP=1 restores the old behaviour
  // of hinting every load-carrying backedge, for A/B against a regression.
  {
    const char* AnyEnv = getenv("FEX_SPINHINT_ANYLOOP");
    SpinHintAnyLoop = AnyEnv && AnyEnv[0] == '1';
  }

  // Batched budget decrement for counted spin loops (contract at
  // kSpinCollapseK in JITClass.h). A real config option rather than a bare
  // getenv, so it is reachable from AppConfig -- which is the only per-title
  // mechanism this port has, and the measured -36.8% p50 / -52% p99 on
  // Cyberpunk 2077 was otherwise impossible to persist for that title.
  // FEX_SPINCOLLAPSE keeps working: the option is named SpinCollapse, so the
  // generated environment spelling is unchanged.
  //   0 = off, 1 = on at the default K, 2..1024 = on at that K, >1024 = default K.
  {
    const uint32_t V = FEXCore::Config::Get_SPINCOLLAPSE()();
    SpinCollapseEnabled = V != 0;
    if (V >= 2 && V <= 1024) {
      kSpinCollapseK = static_cast<uint16_t>(V);
    }
  }

  // FEX_MEMCPYDCBZ=1: dcbz cache-line store tier in the REP MOVSB fast path
  // (contract at MemCpyDcbzEnabled in JITClass.h). Opt-in for the alignment-
  // interrupt and fault-granularity reasons documented there. Hashed into the
  // code-cache config id.
  {
    const char* DcbzEnv = getenv("FEX_MEMCPYDCBZ");
    MemCpyDcbzEnabled = DcbzEnv && DcbzEnv[0] != '\0' && DcbzEnv[0] != '0';
  }

  // FEX_MEMSETDCBZ=0: turn OFF the long-shipping memset dcbz path (default on).
  // Only an explicit "0" disables, so an unset/empty value keeps the shipped
  // behaviour. Hashed into the code-cache config id.
  {
    const char* SetDcbzEnv = getenv("FEX_MEMSETDCBZ");
    MemSetDcbzEnabled = !(SetDcbzEnv && SetDcbzEnv[0] == '0');
  }

  // SMC interlocks: two fork features are only sound when every constant-target
  // exit re-probes the lookup path, which is exactly what a established direct
  // link bypasses.
  //  * FEX_SMCSEMANTICPATCH patches the exit's destination-RIP window; a linked
  //    exit never reloads that window, so the patch would be silently
  //    ineffective (worse than a fault — stale target, no error).
  //  * FEX_SMCLAZYINVAL's soundness (FEX_SMCLAZYSCRUB) forces the faulting
  //    thread's next dispatch through ExitFunctionLink to drain; a linked exit
  //    skips ExitFunctionLink entirely, reopening the same-thread stale hole.
  //    EXCEPT under FEX_SMCLAZYLINK: there the SMC fault handler additionally
  //    arms the writer's InterruptFaultPage, and the per-EntryPoint fault-page
  //    poke (EmitSuspendInterruptCheck — executed by linked arrivals too,
  //    since links target block entries) faults the thread into a drain at its
  //    next block transfer. See SignalDelegator's fault-page branch.
  // Soft-invalidate alone stays compatible with linking: it severs inbound
  // links via SeverBlockLinks(), same as legacy Erase.
  const bool LazyLinkArmed = FEXCore::Config::Get_SMCLAZYLINK() && FEXCore::Config::Get_SMCLAZYSCRUB() && !CTX->Config.SMCSemanticPatch();
  if (BlockLinkingEnabled && (CTX->Config.SMCSemanticPatch() || (FEXCore::Config::Get_SMCLAZYINVAL() && !LazyLinkArmed))) {
    LogMan::Msg::IFmt("BlockLinking disabled: incompatible with FEX_SMCSEMANTICPATCH/FEX_SMCLAZYINVAL "
                      "(both need every constant-target exit to re-probe the lookup path; "
                      "FEX_SMCLAZYLINK=1 lifts the LAZYINVAL restriction).");
    BlockLinkingEnabled = false;
  } else if (BlockLinkingEnabled && FEXCore::Config::Get_SMCLAZYINVAL() && LazyLinkArmed) {
    LogMan::Msg::IFmt("FEX_SMCLAZYLINK: BlockLinking stays ON under lazy SMC invalidation; "
                      "same-thread drains ride the InterruptFaultPage poke.");
  }

  // Constant-target CALL exits (BranchHint::Call) link only when block linking
  // is on AND we are not in the lazy-link regime: under FEX_SMCLAZYLINK the SMC
  // scrub severs links so aggressively that linking call-dense guests (32-bit
  // Mono/Unity) turns every call into a relink-and-recompile through
  // ExitFunctionLinkWithRecord -- a compile storm that throttles execution
  // (observed on Dex load). Plain jumps stay linked (BlockLinkingEnabled); only
  // the higher-volume call exits fall back to the L1 probe under lazy linking.
  CallLinkingEnabled = BlockLinkingEnabled && !LazyLinkArmed;

  // Shadow return stack (FEX_SHADOWRETSTACK). Read once here, mirroring
  // BlockLinkingEnabled. Independent of code caching and of SMCSemanticPatch:
  //  * Code caching: the pushed host trampoline is discovered at RUNTIME via
  //    bcl/mflr (position-independent) and lives only in the per-thread
  //    call-ret stack, never serialized into the code stream; a reloaded cache
  //    zeroes the stack (CodeCache.cpp). So unlike BlockLinking's absolute-
  //    address thunk records, nothing here is base-sensitive.
  //  * SMCSemanticPatch rewrites a block's exit-RIP window in place; a RET has
  //    no constant exit window to patch, and the fast path delivers control to
  //    the return block's ENTRY, where its (possibly patched) body runs
  //    normally -- nothing is bypassed that the patch depends on.
  // The ONE lazy-SMC hole is identical to BlockLinking's: the RET fast path
  // skips ExitFunctionLink's drain, so under FEX_SMCLAZYINVAL a same-thread
  // writer's next dispatch would not drain -- UNLESS FEX_SMCLAZYLINK arms the
  // InterruptFaultPage poke that the shadow arrival also runs at the return
  // block entry (EmitSuspendInterruptCheck below). Force off otherwise. This
  // also covers ScrubThreadLookupCacheForLazySMC deliberately not zeroing the
  // call-ret stack: it only runs as part of the LAZYINVAL soundness machinery,
  // exactly the configuration this interlock gates.
  ShadowRetStackEnabled = CTX->Config.ShadowRetStack();
  if (ShadowRetStackEnabled && FEXCore::Config::Get_SMCLAZYINVAL() && !LazyLinkArmed) {
    LogMan::Msg::IFmt("ShadowRetStack disabled: incompatible with FEX_SMCLAZYINVAL without FEX_SMCLAZYLINK "
                      "(the RET fast path skips ExitFunctionLink's same-thread drain).");
    ShadowRetStackEnabled = false;
  }

  // Resolve the exit-RIP constant width ONCE, at backend construction, from
  // the same config sources and with the same "read once" assumption as
  // BlockLinkingEnabled above.
  //
  // DEF_OP(ExitFunction)'s constant destination used to be materialised with
  // LoadConstantFixed unconditionally -- always 5 instructions, whatever the
  // value. Exactly two consumers need that fixed 20-byte window:
  //   * CodeCache::ApplyCodeRelocations re-emits RELOC_GUEST_RIP_MOVE in place
  //     with a rebased address, so the window must be wide enough for any
  //     value it might produce.
  //   * FEX_SMCSEMANTICPATCH's fault handler rewrites this exact window in
  //     place from SMCSemanticPatch.h's dependency-free re-encoder
  //     (SynthesizeRIPWindow); a variable-width site would be unrecognisable
  //     to it, and repatching it would splice a 5-instruction sequence over
  //     whatever followed a shorter one.
  // With BOTH off nothing ever rewrites the emitted bytes, so the ordinary
  // variable-width LoadConstant is correct and shorter. Note the caching gate
  // is deliberately NOT the BlockLinking one: SMCSemanticPatch forces
  // BlockLinkingEnabled off, so testing BlockLinkingEnabled here would silently
  // pick the variable form in exactly the configuration that must not have it.
  ExitRIPFixedWidth = FEXCore::Config::Get_ENABLECODECACHINGWIP() || CTX->Config.SMCSemanticPatch();

  // Announce the decision once per process (this constructor runs per guest
  // thread). This is the only externally observable statement of which form
  // block exits are being emitted in, and the thing to check when a
  // semantic-patch or code-cache run misbehaves.
  {
    static std::once_flag Announce;
    std::call_once(Announce, [this]() {
      LogMan::Msg::IFmt("PPC64 JIT: exit-RIP constants are {} (code caching {}, SMCSemanticPatch {})",
                        ExitRIPFixedWidth ? "FIXED width (5 insns, patchable window)" : "variable width (1-5 insns)",
                        FEXCore::Config::Get_ENABLECODECACHINGWIP() ? "on" : "off", CTX->Config.SMCSemanticPatch() ? "on" : "off");
    });
  }

  // Point the JIT's helper-address table at the static array in VectorOps.cpp.
  // JIT-emitted call sites will (in P2.1 C2..C5) reach C helpers via
  // `ld TMP1, PPC64_HelperTable_off(STATE); ld TMP1, IDX*8(TMP1); mtctr TMP1`
  // — position-independent, code-cache-safe. See CoreState.h and JITClass.h.
  ThreadState->CurrentFrame->PPC64_HelperTable = GetPPC64HelperTable();

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
  // Note: Ptrs.LUDIV / Ptrs.LDIV are intentionally NOT set. Those slots
  // are read by the arm64/x86_64 Dispatcher.cpp EmitLongALUOpHandler
  // trampolines; ppc64le has its own dispatcher (PPC64Dispatcher.cpp)
  // and no JIT emit site reads Pointers.LUDIV/LDIV — grep confirms.
  // The setters ran at every JIT-core construction (per guest thread)
  // to no observable effect. Deletion is safe (P2.1 C6).
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
  // Rotate to a fresh code buffer: any shadow-return entry whose host
  // trampoline lived in PrevCodeBuffer is now stale (the buffer may be reused),
  // so zero the per-thread call-ret stack alongside the mapping swap. Mirrors
  // the CheckCodeBufferUpdate handshake in CompileCode; a no-op when the
  // feature is off (the stack is never written). See the invalidation
  // discussion there.
  Allocator::VirtualDontNeed(ThreadState->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  ThreadState->LookupCache->ChangeGuestToHostMapping(*PrevCodeBuffer, *CurrentCodeBuffer->LookupCache, lk);
}

// -------------------------------------------------------------------------
// FEX_ENTRYWATCH=0xBEGIN-0xEND (diagnostic; docs/ZIGGURAT_FINALIZE_SPIN.md):
// every DISPATCHER entry into a JIT entry-point whose guest RIP falls in the
// range stores host r10 (the SRA home of guest RBX) and a timebase stamp
// into this ring and bumps a counter. Intra-block jumps land past the entry
// prologue and are NOT recorded — so a corrupt RBX appearing here proves the
// corruption arrived through the dispatcher's State fill, while a wedge with
// a clean ring proves in-place register injection (INJIT signal resume).
// Read live from a wedged process: gdb -p PID -batch -ex "p/x FEX_EntryWatch"
extern "C" {
struct FEXEntryWatchSlot {
  uint64_t GuestRIP;
  uint64_t LastRBX;
  uint64_t LastTB;
  uint64_t Count;
};
FEXEntryWatchSlot FEX_EntryWatch[64] {};
}

static std::pair<uint64_t, uint64_t> EntryWatchRange() {
  static const auto Range = []() -> std::pair<uint64_t, uint64_t> {
    const char* Env = getenv("FEX_ENTRYWATCH");
    if (!Env) {
      return {0, 0};
    }
    char* End {};
    const uint64_t Begin = std::strtoull(Env, &End, 0);
    if (*End != '-') {
      return {0, 0};
    }
    return {Begin, std::strtoull(End + 1, nullptr, 0)};
  }();
  return Range;
}
static std::atomic<uint32_t> EntryWatchNextSlot {};

// EmitStoreBlockBeginToInlineHeader
// -------------------------------------------------------------------------
// PPC64LE equivalent of the ARM64 sequence
//     adr TMP1, &HeaderLabel
//     str TMP1, State.InlineJITBlockHeader(STATE)
// PPC64 has no direct PC-relative address load: `bcl 20,31,$+4` puts NIA
// into LR (the CPU does not push to the link-stack for this exact form),
// mflr copies it into TMP1, then we subtract the emit-time delta from
// mflr's location to HeaderLabel to recover the header's absolute address.
//
// The subtraction is folded into the addressing instruction itself rather than
// materialised into a register first. `LoadImm32(TMP2, Delta); subf` was three
// instructions in the common case and four past 32 KB; `addi TMP1, TMP1,
// -Delta` is one, and `addis`+`addi` covers the whole int32 range in two. The
// old form's only justification was that "a naked int16 addi would break past
// 32 KB, which MAXINST=500 readily produces" -- true of a *single* addi, but
// addis carries the other 16 bits, and the immediate is a compile-time
// constant so the split costs nothing at runtime.
//
// This runs on every external arrival into an EntryPoint block -- every
// dispatcher L1 hit, every linked block-to-block branch, every shadow-RET fast
// path -- and Frontend.cpp marks the return address of every guest CALL as an
// EntryPoint, so it is also on the RET leg of every guest call.
//
// LR is dead at any dispatcher/link entry into a ppc64le block (blocks are
// entered via bctr), and we call this in the entry-point prologue before
// any IR op runs, so clobbering LR/TMP1/TMP2 here is safe.
void PPC64JITCore::EmitStoreBlockBeginToInlineHeader(PPC64Emitter::Label& HeaderLabel) {
  // Field kill switch (hashed into the code-cache config id): restores the
  // LoadImm32 + subf shape this replaced.
  static const bool DisableAddiFold = getenv("FEX_NOHDRADDI") != nullptr;

  LOGMAN_THROW_A_FMT(HeaderLabel.bound, "HeaderLabel must be bound before this call");
  const int64_t HeaderOffset = HeaderLabel.offset;
  bcl(20, 31, 4);                                    // LR = &mflr (NIA)
  mflr(TMP1);                                        // TMP1 = &mflr
  const int64_t MFLROffset = static_cast<int64_t>(GetOffset()) - 4;  // mflr's byte offset
  const int64_t Delta = MFLROffset - HeaderOffset;
  LOGMAN_THROW_A_FMT(Delta >= 0 && Delta < (int64_t{1} << 31),
                     "InlineHeader delta out of int32_t range: {}", Delta);
  if (DisableAddiFold) {
    LoadImm32(TMP2, static_cast<uint32_t>(Delta));   // TMP2 = mflr - HeaderLabel
    subf(TMP1, TMP2, TMP1);                          // TMP1 = HeaderLabel address
  } else if (Delta <= 32768) {
    // -Delta lands in [-32768, 0], exactly addi's signed range. Note the bound
    // is 32768 and not 32767: it is the NEGATED value that has to encode.
    addi(TMP1, TMP1, static_cast<int16_t>(-Delta));
  } else {
    // addis + addi. Lo is the sign-extended low half, Hi absorbs the borrow
    // that sign extension introduces, so Hi<<16 + Lo == -Delta exactly.
    // Hi is in [-32768, -1] for every Delta the assert above admits:
    // Hi == floor(-Delta / 65536) or that plus one, and Delta < 2^31 bounds
    // the floor at -32768.
    const int64_t Neg = -Delta;
    const int16_t Lo = static_cast<int16_t>(Neg & 0xFFFF);
    const int16_t Hi = static_cast<int16_t>((Neg - Lo) >> 16);
    addis(TMP1, TMP1, Hi);
    if (Lo) {
      addi(TMP1, TMP1, Lo);
    }
  }
  std(TMP1,
      static_cast<int16_t>(offsetof(FEXCore::Core::CpuStateFrame, State.InlineJITBlockHeader)),
      STATE);
}

// -------------------------------------------------------------------------
// EmitEntryPoint: prologue emitted at the start of each JIT block
// -------------------------------------------------------------------------
// The caller binds HeaderLabel and reserves the JITCodeHeader before calling
// us. This used to emit, unconditionally, an InlineJITBlockHeader store, then
// FillStaticRegs, then the optional TF check -- ~70 instructions / ~280 bytes
// at BlockBegin+4.
//
// None of it is reachable, and as of 2026-08-04 that is verified at runtime,
// not just by inspection (see DeadPrologueMode below). Emission is therefore
// gated OFF by default. The body is kept compiled and re-enablable for the day
// trap-flag support makes it live.
//
// WHY IT IS DEAD
//   The only recorded entry into a compile unit is CodeData.EntryPoints[...],
//   and both sites that write it (the caller's post-EmitEntryPoint record and
//   the per-IR-block loop's `BlockIROp->EntryPoint` record) resolve to the
//   SAME cursor address: nothing is emitted between EmitEntryPoint returning
//   and the first loop iteration. So the dispatcher/link target has always
//   been *past* this sequence, and nothing branches to BlockBegin+4.
//   BlockBegin itself is only ever consumed as a header/tail base and as a
//   bounds check (Core.cpp GetFrameBlockInfo / RestoreRIPFromHostPC, which use
//   it as `InlineJITBlockHeader` and as the low end of the [BlockBegin,
//   BlockBegin+Tail->Size) containment test; CodeCache.cpp likewise walks
//   BlockBegin -> JITCodeHeader::OffsetToBlockTail and range-checks it) --
//   never as a branch target. Both remain valid: the JITCodeHeader at
//   BlockBegin+0 is emitted by the caller and is untouched by this gate.
//   The per-block loop re-emits its own InlineJITBlockHeader store, and SRA is
//   filled by DispatcherLoopTopFillSRA, by ExitFunctionLinker, and by the
//   signal-return path.
//
// HOW IT WAS VERIFIED (2026-08-04)
//   FEX_DEADPROLOGUE=trap builds the full prologue with an unconditional
//   `tw 31,r0,r0` in front of it, so any arrival at BlockBegin+4 SIGTRAPs
//   immediately. The whole jit_1 harness suite plus guest smoke runs completed
//   with zero traps. Re-run that mode before ever concluding otherwise.
namespace {
enum class DeadPrologueModeType {
  Off,   // default: emit nothing (the ~70 dead instructions are not emitted)
  Trap,  // FEX_DEADPROLOGUE=trap: emit the prologue behind an unconditional trap
  Emit,  // FEX_DEADPROLOGUE=emit: emit the prologue exactly as before the gate
};

DeadPrologueModeType DeadPrologueMode() {
  static const DeadPrologueModeType Mode = []() {
    const char* Env = getenv("FEX_DEADPROLOGUE");
    if (!Env) {
      return DeadPrologueModeType::Off;
    }
    if (::strcmp(Env, "trap") == 0) {
      return DeadPrologueModeType::Trap;
    }
    if (::strcmp(Env, "emit") == 0) {
      return DeadPrologueModeType::Emit;
    }
    return DeadPrologueModeType::Off;
  }();
  return Mode;
}
} // namespace

void PPC64JITCore::EmitEntryPoint(PPC64Emitter::Label& HeaderLabel, bool CheckTF) {
  const auto Mode = DeadPrologueMode();
  if (Mode == DeadPrologueModeType::Off) {
    return;
  }

  if (Mode == DeadPrologueModeType::Trap) {
    // TO=31 traps unconditionally. If execution ever reaches BlockBegin+4 the
    // guest dies here with SIGTRAP instead of quietly running a prologue we
    // believe to be dead.
    tw(31, r(0), r(0));
  }

  // Would keep InlineJITBlockHeader pointing at this block's header rather
  // than a stale one from the previous block if a signal arrived during
  // FillStaticRegs -- but see above, execution never gets here.
  EmitStoreBlockBeginToInlineHeader(HeaderLabel);

  // Fill SRA registers from the CpuStateFrame.
  //
  // CORRECTION: an earlier comment here claimed this "only runs on the cold
  // path (ExitFunctionLink slow return)". That is wrong -- see the
  // unreachability analysis above.
  FillStaticRegs();

  if (CheckTF) {
    // Load EFLAGS and check TF (trap flag, bit 8)
    int32_t eflags_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_TF_RAW_LOC]));
    lbz(TMP1, static_cast<int16_t>(eflags_off), STATE);
    // CR7, not CR0. CR0 holds the guest's packed NZCV N/Z bits that
    // FillStaticRegs just wrote immediately above, and bare cmpdi defaults to
    // CR0 (CodeEmitter/PPC64LE/Emitter.h:506). Same CR7 discipline as
    // PPC64Dispatcher.cpp:321-333 and BranchOps.cpp:141-145,249-253.
    cmpdi(cr(7), TMP1, 0);
    // If TF is set, branch to the interpreter
    // For now just skip — full TF handling added later
  }
}

void PPC64JITCore::EmitSuspendInterruptCheck() {
  // Single byte-store poke of the InterruptFaultPage (see JITClass.h and the
  // matching drain logic in SignalDelegator::HandleGuestSignal). The stored
  // value is irrelevant -- the page carries no data, it exists to fault when
  // a deferred signal is pending. r0 is architecturally safe as the source
  // (the r0==0 block invariant makes it dead here, and stb only reads it).
  // The SEGV handler's nested-deferral path skips a faulting store by
  // advancing NIP by 4, which this single fixed-size stb satisfies.
  constexpr int32_t FaultOff = static_cast<int32_t>(
    offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) -
    offsetof(FEXCore::Core::InternalThreadState, BaseFrameState));
  static_assert(offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) >=
                offsetof(FEXCore::Core::InternalThreadState, BaseFrameState),
                "InterruptFaultPage must lie at or after BaseFrameState");
  stb(r(0), FaultOff, STATE);
}

// ---------------------------------------------------------------------------
// Code-buffer reserve constants
// ---------------------------------------------------------------------------
// These were function-local constexprs inside CompileCode. They are at
// namespace scope now purely so the op-size profiler below can print the
// budget it is measuring against; the VALUES ARE UNCHANGED. See the long
// comment at the capacity guard in CompileCode for what they mean and why the
// reserve has to scale with the IR size.
//
// kMaxHostBytesPerIROp is a *claim*, not a measurement. That is what the
// profiler below exists to check.
//
// Raised 128 -> 160 for block linking: each linkable constant-jump
// ExitFunction now also emits an 80-byte jump thunk + record at the tail of
// CompileCode, on top of an inline expansion that already exceeded the
// per-op claim (SpillStaticRegs alone is ~62 instructions). The reserve is
// an AGGREGATE bound — SSACount * per-op — so the heavyweight exits amortize
// against the many small ops in any real block, and the 1MiB floor dominates
// for small blocks anyway; the bump keeps the aggregate honest for
// exit-dense blocks (a block that is a single guest Jcc is ~10 SSA ops for
// two exits: 10*160 = 1600 >= 2*(inline ~420 + thunk 80)).
//
// Since the shared-spill-stub change, exits no longer inline SpillStaticRegs
// (miss legs are a single b), and CompileCode's tail instead carries at most
// TWO ~400-byte shared stubs per compile unit. The single-Jcc worst case is
// now 2*(inline ~60 + thunk 80) + 800 ≈ 1080 <= 1600, and every additional
// exit makes the aggregate cheaper than the pre-stub layout, so 160 stays a
// valid (now conservative) claim.
constexpr size_t kMaxHostBytesPerIROp = 160;
constexpr size_t kMaxRIPEntryBytesPerIROp = 16;

// ---------------------------------------------------------------------------
// IR op host-expansion profiler (diagnostic; off by default)
// ---------------------------------------------------------------------------
// Records, per IROps enum value, how many host bytes the JIT actually emitted
// for that op: count, total, and — the number that matters — the maximum,
// together with the guest RIP of the block the maximum was seen in.
//
// Enabled at build time by default; compiled to nothing with
// -DENABLE_JIT_OPSIZE_PROFILE=OFF (defines FEX_DISABLE_JIT_OPSIZE_PROFILE).
// Enabled at runtime with FEX_JITOPSIZEPROFILE=1. When runtime-off the only
// cost in the emission loop is one already-loaded boolean test per IR op.
//
// Dump mechanism: the whole table is re-serialised and atomically renamed over
// /tmp/fex-jit-opsize-<pid>.txt. This deliberately does NOT go through
// FEXCore::Telemetry, which only writes on a clean exit(0) — the workloads we
// need this for hang or get killed. The rewrite is triggered:
//   * immediately whenever any per-op maximum increases (rare, and it is the
//     only value that can change the conclusion), and
//   * every kDumpIntervalBlocks compiled blocks, to refresh counts/totals.
// So the maxima on disk are always current as of the last time one moved, even
// under SIGKILL. See the caveat list next to Dump() for what this misses.
#ifndef FEX_DISABLE_JIT_OPSIZE_PROFILE
namespace OpSizeProfile {

// Synthetic buckets sit immediately after the real IROps range. IROps::OP_LAST
// is not a dispatchable op (its name is "Last"), so index OP_LAST is reused for
// "op index out of range", which is the Op_Unhandled fallback path in the
// emission loop.
enum Bucket : size_t {
  BUCKET_UNKNOWN_OP = static_cast<size_t>(IR::IROps::OP_LAST),
  BUCKET_COMPILECODE_PREAMBLE,   // JITCodeHeader + EmitEntryPoint, once per CompileCode
  BUCKET_ENTRYPOINT_PROLOGUE,    // per IR block tagged EntryPoint
  BUCKET_TAIL_AND_RIP_ENTRIES,   // JITCodeTail + vl64pair entries + the TAIL's 16-byte pad.
                                 // NOT the Align16B() pad at the end of the code region --
                                 // that is up to 12 bytes of nops charged to no bucket, so
                                 // bucket-sum and block-total legitimately differ by 0-12.
  BUCKET_COUNT,
};

static std::string_view NameOf(size_t Index) {
  switch (Index) {
  case BUCKET_UNKNOWN_OP: return "<UnknownOp>";
  case BUCKET_COMPILECODE_PREAMBLE: return "<CompileCodePreamble>";
  case BUCKET_ENTRYPOINT_PROLOGUE: return "<EntryPointPrologue>";
  case BUCKET_TAIL_AND_RIP_ENTRIES: return "<TailAndRIPEntries>";
  default: break;
  }
  return IR::GetName(static_cast<IR::IROps>(Index));
}

struct Slot {
  std::atomic<uint64_t> Count {0};
  std::atomic<uint64_t> TotalBytes {0};
  std::atomic<uint64_t> MaxBytes {0};
  std::atomic<uint64_t> MaxRIP {0};
};

// Process-wide, not per-thread: the question is about the op, not the thread.
// Every writer below runs inside CompileCode, which holds
// CodeBuffers.CodeBufferWriteMutex for its whole emission window, so these are
// already serialised between JIT threads; the atomics are for the benefit of a
// reader (Dump) that could in principle run from another thread.
static std::array<Slot, static_cast<size_t>(BUCKET_COUNT)> Slots {};

static std::atomic<uint64_t> BlocksCompiled {0};
static std::atomic<uint64_t> MaxBlockBytes {0};
static std::atomic<uint64_t> MaxBlockBytesRIP {0};
static std::atomic<uint64_t> MaxBlockBytesSSA {0};
// Whole-block host bytes divided by SSA count, scaled by 256 so the comparison
// keeps sub-byte resolution without floating point. This is the number the
// reserve arithmetic in CompileCode actually depends on.
static std::atomic<uint64_t> MaxScaledBytesPerSSA {0};
static std::atomic<uint64_t> MaxBytesPerSSARIP {0};
static std::atomic<uint64_t> MaxBytesPerSSABytes {0};
static std::atomic<uint64_t> MaxBytesPerSSACount {0};

static std::atomic<bool> MaximaMoved {false};

static constexpr uint64_t kBytesPerSSAScale = 256;
static constexpr uint64_t kDumpIntervalBlocks = 512;

static void Record(size_t Index, uint64_t Bytes, uint64_t RIP) {
  auto& S = Slots[Index];
  S.Count.fetch_add(1, std::memory_order_relaxed);
  S.TotalBytes.fetch_add(Bytes, std::memory_order_relaxed);

  uint64_t Prev = S.MaxBytes.load(std::memory_order_relaxed);
  while (Bytes > Prev) {
    if (S.MaxBytes.compare_exchange_weak(Prev, Bytes, std::memory_order_relaxed, std::memory_order_relaxed)) {
      S.MaxRIP.store(RIP, std::memory_order_relaxed);
      MaximaMoved.store(true, std::memory_order_relaxed);
      break;
    }
  }
}

// Serialise the whole table and replace the dump file atomically (write to a
// sibling .tmp, then rename). Atomic replace matters because the trigger for
// this is "the guest may be about to be killed": a partially written file
// would be indistinguishable from a short one.
//
// What this does NOT cover:
//   * counts/totals can lag by up to kDumpIntervalBlocks compiles on an abrupt
//     kill. Maxima cannot -- they are flushed the moment they move.
//   * a crash *inside* an op handler: the bytes that handler had emitted so far
//     are never attributed, because the delta is only taken after it returns.
//   * ops emitted outside the per-op dispatch loop that are not one of the
//     three synthetic buckets. There are none today; if the emission loop gains
//     another out-of-band emit site it must get its own bucket, or the bucket
//     totals will silently under-count the block. Note the BLOCK_BUDGET section
//     prints reserve / observed-per-SSA / observed-max-block / verdict -- it
//     does NOT print a bucket-sum residual, so such a gap would not announce
//     itself. Compare bucket totals against block totals by hand if you suspect
//     one, and expect a legitimate 0-12 byte discrepancy from the Align16B()
//     pad (see BUCKET_TAIL_AND_RIP_ENTRIES).
//   * a hang with no further compiles: the file is as of the last compile,
//     which is what we want, but it will not be updated while the guest spins.
static void Dump() {
  static std::mutex DumpMutex;
  std::lock_guard Guard {DumpMutex};

  struct Row {
    size_t Index;
    uint64_t Count;
    uint64_t Total;
    uint64_t Max;
    uint64_t RIP;
  };

  fextl::vector<Row> Rows;
  Rows.reserve(BUCKET_COUNT);
  for (size_t i = 0; i < BUCKET_COUNT; ++i) {
    const uint64_t Count = Slots[i].Count.load(std::memory_order_relaxed);
    if (!Count) {
      continue;
    }
    Rows.push_back(Row {
      .Index = i,
      .Count = Count,
      .Total = Slots[i].TotalBytes.load(std::memory_order_relaxed),
      .Max = Slots[i].MaxBytes.load(std::memory_order_relaxed),
      .RIP = Slots[i].MaxRIP.load(std::memory_order_relaxed),
    });
  }

  std::sort(Rows.begin(), Rows.end(), [](const Row& a, const Row& b) {
    if (a.Max != b.Max) {
      return a.Max > b.Max;
    }
    return a.Total > b.Total;
  });

  const uint64_t Blocks = BlocksCompiled.load(std::memory_order_relaxed);

  fextl::string Out;
  Out += fextl::fmt::format("# FEX PPC64LE JIT per-IR-op host expansion profile\n");
  Out += fextl::fmt::format("# pid={} compiles={} \n", ::getpid(), Blocks);
  Out += fextl::fmt::format("# reserve model in CompileCode: SSACount * ({} + {}) bytes\n", kMaxHostBytesPerIROp, kMaxRIPEntryBytesPerIROp);
  Out += fextl::fmt::format("# max_at_rip is the CompileCode Entry RIP of the block the maximum was seen in,\n"
                            "# not the guest RIP of the individual instruction.\n\n");

  // ---- The deliverable, first and impossible to miss. ----
  // Grep `IROP_OVER_BUDGET ` (trailing space) for real IR ops that blow the
  // budget; `IROP_OVER_BUDGET_INFO` for the synthetic per-block buckets, which
  // are not bound by a per-op constant and are listed for completeness only.
  size_t OverBudget = 0;
  size_t OverBudgetInfo = 0;
  fextl::string OverLines;
  for (const auto& R : Rows) {
    if (R.Max <= kMaxHostBytesPerIROp) {
      continue;
    }
    const bool Synthetic = R.Index > static_cast<size_t>(IR::IROps::OP_LAST);
    if (Synthetic) {
      ++OverBudgetInfo;
    } else {
      ++OverBudget;
    }
    // over_x100 is max*100/budget, i.e. "812" means 8.12x the claimed bound.
    OverLines += fextl::fmt::format("IROP_OVER_BUDGET{} name={} max={} budget={} over_by={} over_x100={} count={} max_at_rip={:#x}\n",
                                    Synthetic ? "_INFO" : "", NameOf(R.Index), R.Max, kMaxHostBytesPerIROp, R.Max - kMaxHostBytesPerIROp,
                                    (R.Max * 100) / kMaxHostBytesPerIROp, R.Count, R.RIP);
  }

  Out += fextl::fmt::format("################################################################################\n"
                            "### OPS EXCEEDING kMaxHostBytesPerIROp ({} bytes): {} real, {} synthetic\n"
                            "################################################################################\n",
                            kMaxHostBytesPerIROp, OverBudget, OverBudgetInfo);
  if (OverBudget || OverBudgetInfo) {
    Out += OverLines;
  } else {
    Out += fextl::fmt::format("IROP_OVER_BUDGET_NONE (no op observed above {} bytes yet)\n", kMaxHostBytesPerIROp);
  }
  Out += "\n";

  // ---- Whole-block budget: what the reserve arithmetic actually needs. ----
  const uint64_t ScaledPerSSA = MaxScaledBytesPerSSA.load(std::memory_order_relaxed);
  const uint64_t ReservePerSSA = kMaxHostBytesPerIROp + kMaxRIPEntryBytesPerIROp;
  Out += fextl::fmt::format("################################################################################\n"
                            "### BLOCK BUDGET (whole-CompileCode, the value the reserve really depends on)\n"
                            "################################################################################\n");
  Out += fextl::fmt::format("BLOCK_BUDGET reserve_bytes_per_ssa={} (kMaxHostBytesPerIROp={} + kMaxRIPEntryBytesPerIROp={})\n", ReservePerSSA,
                            kMaxHostBytesPerIROp, kMaxRIPEntryBytesPerIROp);
  Out += fextl::fmt::format("BLOCK_BUDGET observed_max_bytes_per_ssa={}.{:03} at_rip={:#x} block_bytes={} ssa_count={}\n",
                            ScaledPerSSA / kBytesPerSSAScale, ((ScaledPerSSA % kBytesPerSSAScale) * 1000) / kBytesPerSSAScale,
                            MaxBytesPerSSARIP.load(std::memory_order_relaxed), MaxBytesPerSSABytes.load(std::memory_order_relaxed),
                            MaxBytesPerSSACount.load(std::memory_order_relaxed));
  Out += fextl::fmt::format("BLOCK_BUDGET observed_max_block_bytes={} at_rip={:#x} ssa_count={}\n",
                            MaxBlockBytes.load(std::memory_order_relaxed), MaxBlockBytesRIP.load(std::memory_order_relaxed),
                            MaxBlockBytesSSA.load(std::memory_order_relaxed));
  Out += fextl::fmt::format("BLOCK_BUDGET verdict={}\n\n", ScaledPerSSA > ReservePerSSA * kBytesPerSSAScale ? "SHORT" : "OK");

  // ---- Full table, max descending. ----
  Out += fextl::fmt::format("################################################################################\n"
                            "### PER-OP TABLE (sorted by max host bytes, descending)\n"
                            "################################################################################\n");
  for (const auto& R : Rows) {
    Out += fextl::fmt::format("IROP_SIZE max={:6} avg={:6} count={:10} total={:12} max_at_rip={:#018x} name={}\n", R.Max, R.Total / R.Count,
                              R.Count, R.Total, R.RIP, NameOf(R.Index));
  }

  const auto Path = fextl::fmt::format("/tmp/fex-jit-opsize-{}.txt", ::getpid());
  const auto TmpPath = Path + ".tmp";

  const int FD = ::open(TmpPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (FD == -1) {
    return;
  }

  size_t Written = 0;
  while (Written < Out.size()) {
    const ssize_t Result = ::write(FD, Out.data() + Written, Out.size() - Written);
    if (Result <= 0) {
      break;
    }
    Written += static_cast<size_t>(Result);
  }
  ::close(FD);

  if (Written == Out.size()) {
    ::rename(TmpPath.c_str(), Path.c_str());
  } else {
    ::unlink(TmpPath.c_str());
  }
}

// Called once per CompileCode, after the tail is sized. TotalBytes is the whole
// span the block consumes in the code buffer (code + align + tail + RIP
// entries), i.e. exactly what BlockHeadroom has to have covered.
static void RecordBlockAndMaybeDump(uint64_t Entry, uint64_t SSACount, uint64_t TotalBytes) {
  const uint64_t Blocks = BlocksCompiled.fetch_add(1, std::memory_order_relaxed) + 1;

  uint64_t PrevMax = MaxBlockBytes.load(std::memory_order_relaxed);
  while (TotalBytes > PrevMax) {
    if (MaxBlockBytes.compare_exchange_weak(PrevMax, TotalBytes, std::memory_order_relaxed, std::memory_order_relaxed)) {
      MaxBlockBytesRIP.store(Entry, std::memory_order_relaxed);
      MaxBlockBytesSSA.store(SSACount, std::memory_order_relaxed);
      MaximaMoved.store(true, std::memory_order_relaxed);
      break;
    }
  }

  if (SSACount) {
    const uint64_t Scaled = (TotalBytes * kBytesPerSSAScale) / SSACount;
    uint64_t PrevScaled = MaxScaledBytesPerSSA.load(std::memory_order_relaxed);
    while (Scaled > PrevScaled) {
      if (MaxScaledBytesPerSSA.compare_exchange_weak(PrevScaled, Scaled, std::memory_order_relaxed, std::memory_order_relaxed)) {
        MaxBytesPerSSARIP.store(Entry, std::memory_order_relaxed);
        MaxBytesPerSSABytes.store(TotalBytes, std::memory_order_relaxed);
        MaxBytesPerSSACount.store(SSACount, std::memory_order_relaxed);
        MaximaMoved.store(true, std::memory_order_relaxed);
        break;
      }
    }
  }

  if (MaximaMoved.exchange(false, std::memory_order_relaxed) || (Blocks % kDumpIntervalBlocks) == 0) {
    Dump();
  }
}

} // namespace OpSizeProfile

// The `Enabled` argument is the single boolean test the requirement allows in
// the hot path. It is read once per CompileCode into a local, so this is a
// register test, not a config lookup.
#define PPC64_OPSIZE_RECORD(Enabled, Index, Bytes, RIP) \
  do {                                                  \
    if (Enabled) {                                      \
      OpSizeProfile::Record((Index), (Bytes), (RIP));   \
    }                                                   \
  } while (0)

#define PPC64_OPSIZE_RECORD_BLOCK(Enabled, Entry, SSACount, Bytes)             \
  do {                                                                        \
    if (Enabled) {                                                            \
      OpSizeProfile::RecordBlockAndMaybeDump((Entry), (SSACount), (Bytes));    \
    }                                                                         \
  } while (0)

#else // FEX_DISABLE_JIT_OPSIZE_PROFILE

#define PPC64_OPSIZE_RECORD(Enabled, Index, Bytes, RIP) \
  do {                                                  \
  } while (0)
#define PPC64_OPSIZE_RECORD_BLOCK(Enabled, Entry, SSACount, Bytes) \
  do {                                                             \
  } while (0)

#endif

// -------------------------------------------------------------------------
// AnalyzeSpinLoops: mark spin-loop backedges/exits for SMT priority hints
//
// A "spin loop" here is a tiny backward-branching region that only polls
// memory and computes: <=3 blocks, <=64 IR ops, at least one memory load,
// and no side effects beyond guest register/flag state and control flow.
// No stores, no atomics, no syscalls -- a loop that writes shared state is
// making progress and must not be deprioritized.
//
// For each detected region, the backedge gets `or r31,r31,r31` (SMT very-low
// priority) and every edge leaving the region gets `or r2,r2,r2` (medium,
// the default) so real work never runs deprioritized. Both are architectural
// nops: misdetection cannot alter semantics, only dispatch priority. The
// dispatcher loop top carries a medium-priority safety net for paths that
// leave a spin region through a signal/suspend detour instead of a marked
// edge (the kernel also restores medium on every syscall entry).
//
// Motivation: CP2077's redDispatcher work-steal spin was 25% of the whole
// process's samples across 19 threads; its iteration-counted budget means
// emulation slowness multiplies spin wall time, and on SMT the spin steals
// dispatch bandwidth from the sibling thread (audio). See
// cp2077-reddispatcher-spin-anatomy.
// -------------------------------------------------------------------------
// -------------------------------------------------------------------------
// 32-bit tail-mask elision prepass. See the Elide32MaskSet block comment in
// JITClass.h for the soundness argument (single use + immediately-next-op +
// encoding reads only low 32 bits of that operand position).
//
// Per-consumer verification notes (all against the emitting handler, not
// assumed from the ISA index):
//  * CondJump, !FromNZCV, no VCmp fusion, Cond not TSTZ/TSTNZ, CompareSize
//    i32: EmitCompare's i32 arm emits cmplw/cmplwi/cmpw/cmpwi exclusively —
//    word compares read bits 32:63 only. TSTZ/TSTNZ excluded because the
//    rldicl bit-extract can address a high bit.
//  * Lshl/Lshr/Ashr at Size <= i32: value operand is read by
//    rlwinm/slw/srw/extsw (low word only); the register shift count is
//    pre-masked with rldicl(...,0,59) (low 5 bits).
//  * Mul/UMul at Size <= i32: mullw reads low words; mulli's low-32 product
//    depends only on the low 32 of RA (multiplication mod 2^32). The
//    handler's own tail mask re-canonicalizes the polluted high half.
//  * StoreMem, GPR class, Size <= i32: EmitStoreGPR emits stw/sth/stb for
//    the value. Only the Value operand qualifies — Addr/Offset feed address
//    arithmetic that reads all 64 bits.
// -------------------------------------------------------------------------
void PPC64JITCore::Compute32MaskElision() {
  static const char* ZExtEnv = getenv("FEX_ZEXTOPT");
  static const bool ZExtOff = ZExtEnv && ZExtEnv[0] == '0';
  Elide32MaskSet.assign(IR->GetSSACount(), false);
  if (ZExtOff) {
    return;
  }

  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    IR::Ref PrevNode = nullptr;
    const IR::IROp_Header* PrevOp = nullptr;

    for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
      // Emission no-ops (Op_NoOp table entries) are transparent to the
      // "immediately next op" adjacency test: they emit no host code and, as
      // non-uses, cannot spill or observe the pending def. Without this the
      // inline-constant node between a def and its compare-with-immediate
      // consumer (the LZMA hot-loop shape) defeats every elision.
      switch (IROp->Op) {
      case IR::OP_DUMMY:
      case IR::OP_BEGINBLOCK:
      case IR::OP_ENDBLOCK:
      case IR::OP_INVALIDATEFLAGS:
      case IR::OP_INLINECONSTANT:
      case IR::OP_INLINEENTRYPOINTOFFSET:
      // GuestOpcode markers only record (guest RIP, host PC) table entries —
      // zero host instructions (see DEF_OP(GuestOpcode)). A marker between
      // def and consumer relabels the guest boundary but adds nothing
      // observable: async signals defer to drain points, and the window
      // still contains no faulting host instruction (register-writing
      // consumers cannot fault; faulting consumers like stores have no dest
      // and are excluded for GPRFixed defs). Without this skip, the marker
      // in front of every guest instruction defeats every cross-instruction
      // elision — which is all of them.
      case IR::OP_GUESTOPCODE: continue;
      default: break;
      }

      const IR::Ref DefNode = PrevNode;
      const IR::IROp_Header* DefOp = PrevOp;
      PrevNode = CodeNode;
      PrevOp = IROp;

      if (!DefOp || !IR::GetHasDest(DefOp->Op)) {
        continue;
      }
      // Two def shapes qualify: an i32-sized ALU op (its handler emits the
      // rldicl tail via Mask32Tail — the 32-bit-guest idiom), or the 64-bit
      // frontend's canonicalizing Bfe(#32,#0) itself (the whole op IS the
      // mask; DEF_OP(Bfe) degenerates it to mr/nothing when elided).
      bool DefIsMask = DefOp->Size == IR::OpSize::i32Bit;
      if (!DefIsMask && DefOp->Op == IR::OP_BFE && DefOp->Size == IR::OpSize::i64Bit) {
        auto B = DefOp->C<IR::IROp_Bfe>();
        DefIsMask = B->Width == 32 && B->lsb == 0;
      }
      if (!DefIsMask) {
        continue;
      }
      const IR::PhysicalRegister DefPR(DefNode);
      const auto DefClass = DefPR.AsRegClass();
      if (DefClass != IR::RegClass::GPR && DefClass != IR::RegClass::GPRFixed) {
        continue;
      }
      if (DefNode->GetUses() != 1) {
        continue;
      }
      const auto DefID = IR->GetID(DefNode);
      // Post-RA, consumer args are usually immediate-encoded PhysicalRegisters
      // (see GetReg(OrderedNodeWrapper)) — node identity is gone. Matching by
      // register is exact here BECAUSE of the adjacency precondition: no host
      // instruction is emitted between the def and this consumer, so the
      // register still holds precisely the def's value. Node-ref args (e.g.
      // wrappers to InlineConstant nodes) keep the ID comparison.
      const auto IsDef = [&DefPR, DefID, this](IR::OrderedNodeWrapper Arg) {
        if (Arg.IsInvalid()) {
          return false;
        }
        if (Arg.IsImmediate()) {
          return IR::PhysicalRegister(Arg).Raw == DefPR.Raw;
        }
        return IR->GetID(IR->GetNode(Arg)).Value == DefID.Value;
      };

      bool Elide = false;
      switch (IROp->Op) {
      case IR::OP_CONDJUMP: {
        auto Op = IROp->C<IR::IROp_CondJump>();
        if (!Op->FromNZCV && Op->VCmpElementSize == IR::OpSize::iInvalid &&
            Op->Cond != IR::CondClass::TSTZ && Op->Cond != IR::CondClass::TSTNZ &&
            Op->CompareSize == IR::OpSize::i32Bit) {
          Elide = IsDef(Op->Cmp1) || IsDef(Op->Cmp2);
        }
        break;
      }
      case IR::OP_LSHL:
      case IR::OP_LSHR:
      case IR::OP_ASHR: {
        if (IROp->Size <= IR::OpSize::i32Bit) {
          Elide = IsDef(IROp->Args[0]) || IsDef(IROp->Args[1]);
        }
        break;
      }
      case IR::OP_MUL:
      case IR::OP_UMUL: {
        if (IROp->Size <= IR::OpSize::i32Bit) {
          Elide = IsDef(IROp->Args[0]) || IsDef(IROp->Args[1]);
        }
        break;
      }
      case IR::OP_STOREMEM: {
        auto Op = IROp->C<IR::IROp_StoreMem>();
        if (Op->Class == IR::RegClass::GPR && IROp->Size <= IR::OpSize::i32Bit) {
          Elide = IsDef(Op->Value) && !IsDef(Op->Addr) && !IsDef(Op->Offset);
        }
        break;
      }
      case IR::OP_STOREMEMTSO: {
        // Same narrow-store value path as StoreMem (GetReg(Op->Value) into
        // stw/sth/stb); the lwsync release barrier reads no register.
        auto Op = IROp->C<IR::IROp_StoreMemTSO>();
        if (Op->Class == IR::RegClass::GPR && IROp->Size <= IR::OpSize::i32Bit) {
          Elide = IsDef(Op->Value) && !IsDef(Op->Addr) && !IsDef(Op->Offset);
        }
        break;
      }
      default: break;
      }

      // A GPRFixed def IS an architectural guest register (RA coalesced the
      // write onto the SRA slot — this is the common case in hot loops). The
      // single-use/next-op argument alone is not enough there: the SRA
      // register would keep the unmasked value until something overwrites
      // it, and a synchronous fault in a LATER guest instruction would
      // present garbage high bits as architectural state. Sound iff the
      // consumer overwrites the SAME fixed register in the very next op
      // (the x86 read-modify-write chain shape, e.g. sub edi,X / shr edi,N)
      // — the window between the two host instructions contains no
      // observation point: async signals defer to drain points, and no
      // faulting instruction sits between def and overwrite. Every table
      // consumer with a dest writes it canonically or re-masks (rlwinm/
      // slw/srw are low-32 by construction; mullw keeps its own tail mask
      // unless ITS consumer also passed this same test — induction holds).
      if (Elide && DefClass == IR::RegClass::GPRFixed) {
        if (!IR::GetHasDest(IROp->Op)) {
          Elide = false;
        } else {
          const IR::PhysicalRegister UsePR(CodeNode);
          if (UsePR.Raw != DefPR.Raw) {
            Elide = false;
          }
        }
      }

      if (Elide) {
        Elide32MaskSet[DefID.Value] = true;
      }
    }
  }
}

// -------------------------------------------------------------------------
// TSO load->store adjacent-barrier elision prepass. See the TSOPairElideSet
// block comment in JITClass.h for the mechanism and DEF_OP(StoreMemTSO) for
// the full soundness argument at the elision site.
//
// Walk each block in emission order tracking Fresh = "an lwsync has been
// emitted since the last memory-access host instruction". LoadMemTSO sets it
// (both its FPR and GPR legs end with an unconditional trailing lwsync and
// have no other exit); a StoreMemTSO reached with Fresh set is recorded and
// clears it (the store itself is a post-barrier memory access, so a following
// StoreMemTSO still needs its own release barrier for Store->Store order).
// EVERY op not on the whitelist below clears Fresh — including Spill/Fill
// (RA-inserted spills are IR ops and appear in this same stream), all other
// memory ops, and every op nobody has verified.
//
// Whitelist verification notes — an op may appear here ONLY if its DEF_OP
// emits zero memory-access host instructions, checked against the emitting
// handler (not assumed from the op's name). Branch/label-free is NOT required
// (lwsync orders memory accesses in program order on the executing hart;
// non-memory instructions between the barrier and the store are irrelevant),
// but none of the listed handlers binds a label an external edge can enter
// through — IR jumps only target block heads, so no path can reach the store
// without executing the load's trailing lwsync first.
//  * Emission no-ops, dispatch-table Op_NoOp entries (emit zero bytes):
//    Dummy, IRHeader, CodeBlock, BeginBlock, EndBlock, InvalidateFlags,
//    InlineConstant, InlineEntrypointOffset.
//  * DEF_OP'd no-ops: GuestOpcode (DebugData table entry only, zero host
//    instructions), SetSmallNZV / TelemetrySetValue / WFET (empty bodies).
//  * Constant: TryInsertPatchableImmMove -> LoadConstantFixed
//    (lis/ori/sldi/oris/ori) or LoadConstant -> LoadImm64 (li/lis/ori/sldi/
//    rldic/oris family). EntrypointOffset: InsertEntrypointRIPMove ->
//    LoadConstant or InsertGuestRIPMove -> LoadConstantFixed. All immediate
//    builders, no memory.
//  * Copy: mr only. Bfe/Sbfe: rlwinm/rldicl/extsb/extsh/extsw/neg/sldi/or_/mr.
//  * Add/Sub/Neg/Not/Or/And/Xor/Andn: addi/addis/add/subf/neg/isel/nor/
//    ori/oris/or/and/xor/xori/xoris/andc (+ LoadConstant, + rldicl tail).
//  * Lshl/Lshr/Ashr: rlwinm/sldi/srdi/rldicl/slw/srw/sld/srd/extsw/li/subf/
//    neg/or_ — the XER-safe shift lowerings, register-only by construction.
//  * AddWithFlags/SubWithFlags/AddNZCV/SubNZCV: sldi/LoadConstant/addco_/
//    subfco_/srdi (CR0/XER writes are register state, not memory).
//  * TestNZ/TestZ/AndWithFlags: andi_/and__/addco/extsb_/extsh_/extsw_/cmpdi
//    (+ LoadConstant).
// Deliberately NOT whitelisted despite looking pure: Div/UDiv, Rev, Rbit,
// PDep, ShiftFlags, RotateFlags — their handlers stash through r1 (std/ld
// red-zone slots or stdbrx/stwbrx bounce buffers), which are memory accesses.
// LoadMemRev/StoreMemRev (TSO=1) carry the same barriers as the ops handled
// here but are left out of v1: they conservatively clear Fresh like any other
// memory op (missed elision only).
// -------------------------------------------------------------------------
void PPC64JITCore::ComputeTSOPairElision() {
  static const char* PairEnv = getenv("FEX_TSOPAIRELIDE");
  static const bool PairOff = PairEnv && PairEnv[0] == '0';
  TSOPairElideSet.assign(IR->GetSSACount(), false);
  if (PairOff) {
    return;
  }

  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    // Reset per block: a block can be entered from anywhere, so nothing about
    // the previously emitted block's trailing barrier state may be assumed.
    bool Fresh = false;

    for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
      switch (IROp->Op) {
      case IR::OP_LOADMEMTSO:
        Fresh = true;
        break;

      case IR::OP_STOREMEMTSO:
        if (Fresh) {
          TSOPairElideSet[IR->GetID(CodeNode).Value] = true;
        }
        Fresh = false;
        break;

      // Whitelist — see the verification table above.
      case IR::OP_DUMMY:
      case IR::OP_IRHEADER:
      case IR::OP_CODEBLOCK:
      case IR::OP_BEGINBLOCK:
      case IR::OP_ENDBLOCK:
      case IR::OP_INVALIDATEFLAGS:
      case IR::OP_INLINECONSTANT:
      case IR::OP_INLINEENTRYPOINTOFFSET:
      case IR::OP_GUESTOPCODE:
      case IR::OP_SETSMALLNZV:
      case IR::OP_TELEMETRYSETVALUE:
      case IR::OP_WFET:
      case IR::OP_CONSTANT:
      case IR::OP_ENTRYPOINTOFFSET:
      case IR::OP_COPY:
      case IR::OP_BFE:
      case IR::OP_SBFE:
      case IR::OP_ADD:
      case IR::OP_SUB:
      case IR::OP_NEG:
      case IR::OP_NOT:
      case IR::OP_OR:
      case IR::OP_AND:
      case IR::OP_XOR:
      case IR::OP_ANDN:
      case IR::OP_LSHL:
      case IR::OP_LSHR:
      case IR::OP_ASHR:
      case IR::OP_ADDWITHFLAGS:
      case IR::OP_SUBWITHFLAGS:
      case IR::OP_ADDNZCV:
      case IR::OP_SUBNZCV:
      case IR::OP_TESTNZ:
      case IR::OP_TESTZ:
      case IR::OP_ANDWITHFLAGS:
        break;

      default:
        Fresh = false;
        break;
      }
    }
  }
}

void PPC64JITCore::AnalyzeSpinLoops() {
  struct BlockInfo {
    uint32_t ID = UINT32_MAX;
    uint32_t Targets[2] = {UINT32_MAX, UINT32_MAX};  // CodeBlock IDs
    uint32_t OpCount = 0;
    bool Clean = false;
    bool HasPollLoad = false;
    IR::Ref Node = nullptr;  // for the SpinCollapse pattern re-walk
  };

  // SpinCollapse marks are per-compile; reset before any region matching so
  // a block that stops qualifying can never inherit a stale mark. Bounds
  // checks in the accessors cover compiles where this function never runs.
  SpinCollapseSubs.assign(IR->GetSSACount(), false);
  SpinCollapseBranches.assign(IR->GetSSACount(), false);
  SpinCollapseBranchSigned.assign(IR->GetSSACount(), false);

  fextl::vector<BlockInfo> Blocks;
  const uint32_t NumBlocks = IR->GetHeader()->BlockCount;
  Blocks.reserve(NumBlocks);
  // CodeBlock ID -> layout index (IDs are dense 0..NumBlocks-1, same keying
  // as JumpTargets).
  fextl::vector<uint32_t> IdxOfID(NumBlocks, UINT32_MAX);

  for (auto [BlockNode, BlockHeader] : IR->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    BlockInfo Info {};
    Info.ID = BlockIROp->ID;
    Info.Clean = true;
    Info.Node = BlockNode;

    // The block's branch terminator. NOTE: it is not the final op in the
    // code list -- every block carries a trailing EndBlock marker after the
    // branch -- so capture it when the switch sees it.
    const FEXCore::IR::IROp_Header* Term = nullptr;
    for (auto [CodeNode, IROp] : IR->GetCode(BlockNode)) {
      ++Info.OpCount;
      switch (IROp->Op) {
      case IR::OP_LOADMEM:
      case IR::OP_LOADMEMTSO:
        Info.HasPollLoad = true;
        break;
      // Side-effecting ops that are still pure "this thread's guest state":
      // register/flag/context writes and control flow. Anything else with
      // side effects (stores, atomics, syscalls, cache ops, ...) disqualifies
      // the block.
      case IR::OP_STOREREGISTER:
      case IR::OP_STORECONTEXT:
      case IR::OP_STORENZCV:
      case IR::OP_STOREPF:
      case IR::OP_STOREAF:
      case IR::OP_CONDJUMP:
      case IR::OP_JUMP:
        Term = IROp;
        break;
      case IR::OP_GUESTOPCODE:
      case IR::OP_BEGINBLOCK:
      case IR::OP_ENDBLOCK:
      case IR::OP_INVALIDATEFLAGS:
      // Pseudo-ops that carry HasSideEffects only as an optimizer barrier;
      // they emit no code (InlineConstant/InlineEntrypointOffset are folded
      // into their consumers).
      case IR::OP_INLINECONSTANT:
      case IR::OP_INLINEENTRYPOINTOFFSET:
        break;
      // Flag-producing ALU ops: HasSideEffects=true in IR.json because they
      // write NZCV/PF, but on this backend that is register/CR/XER state
      // only (verified lowering-by-lowering for the TSO pair-elision
      // whitelist) — exactly the "this thread's guest state" the region
      // definition allows. Without these the canonical poll shape
      // (LoadMemTSO + SubWithFlags(test) + CondJump) rejects its own region:
      // the production redDispatcher spin was never getting hints OR
      // collapse until this list existed.
      case IR::OP_SUBWITHFLAGS:
      case IR::OP_ADDWITHFLAGS:
      case IR::OP_SUBNZCV:
      case IR::OP_ADDNZCV:
      case IR::OP_TESTNZ:
      case IR::OP_TESTZ:
      case IR::OP_ANDWITHFLAGS:
        break;
      default:
        if (IR::HasSideEffects(IROp->Op)) {
          Info.Clean = false;
        }
        break;
      }
    }

    if (Term != nullptr && Term->Op == IR::OP_CONDJUMP) {
      auto Op = Term->C<IR::IROp_CondJump>();
      Info.Targets[0] = IR->GetOp<IR::IROp_CodeBlock>(Op->TrueBlock)->ID;
      Info.Targets[1] = IR->GetOp<IR::IROp_CodeBlock>(Op->FalseBlock)->ID;
    } else if (Term != nullptr && Term->Op == IR::OP_JUMP) {
      auto Op = Term->C<IR::IROp_Jump>();
      Info.Targets[0] = IR->GetOp<IR::IROp_CodeBlock>(Op->TargetBlock)->ID;
    } else {
      // Region blocks must end in plain control flow (ExitFunction, Break,
      // ... terminators leave the compile unit and can't be hint-tracked).
      Info.Clean = false;
    }

    if (Info.ID < NumBlocks) {
      IdxOfID[Info.ID] = static_cast<uint32_t>(Blocks.size());
    }
    Blocks.push_back(Info);
  }

  constexpr uint32_t MaxRegionBlocks = 3;
  constexpr uint32_t MaxRegionOps = 64;

  auto PushUnique = [](fextl::vector<uint64_t>& Vec, uint64_t Key) {
    for (const auto V : Vec) {
      if (V == Key) {
        return;
      }
    }
    Vec.push_back(Key);
  };

  for (uint32_t bi = 0; bi < Blocks.size(); ++bi) {
    for (const uint32_t TargetID : Blocks[bi].Targets) {
      if (TargetID == UINT32_MAX || TargetID >= NumBlocks) {
        continue;
      }
      const uint32_t ti = IdxOfID[TargetID];
      if (ti == UINT32_MAX || ti > bi) {
        continue;  // forward edge
      }
      if (bi - ti + 1 > MaxRegionBlocks) {
        continue;
      }
      // Validate the candidate region [ti, bi].
      uint32_t TotalOps = 0;
      bool Clean = true;
      bool HasPollLoad = false;
      for (uint32_t ri = ti; ri <= bi; ++ri) {
        TotalOps += Blocks[ri].OpCount;
        Clean &= Blocks[ri].Clean;
        HasPollLoad |= Blocks[ri].HasPollLoad;
      }
      if (!Clean || !HasPollLoad || TotalOps > MaxRegionOps) {
        continue;
      }
      // Stationary-poll gate, required by BOTH consumers below.
      //
      // For the collapse it separates the redDispatcher spin (polls ONE
      // address every iteration; the leftover budget is dead on the found
      // exit) from a strlen/memchr-class scan (advances a pointer each
      // iteration; the leftover count is LIVE — it becomes a length).
      // Collapsing a scan corrupts that length: CP2077 SIGSEGV'd 7s into
      // bootstrap when the v1 matcher collapsed loader scans.
      //
      // For the SMT hint it separates "spinning" from "working", and getting
      // that wrong is expensive rather than merely wasteful: the backedge
      // hint is `or 31,31,31`, VERY LOW thread priority. The structural
      // tests above (a load, a backedge, no side effects) are equally true of
      // every hash, strlen, and memcpy-shaped loop, so those were all being
      // told to yield the core while doing real work. Measured on CP2077's
      // FNV-1a string hash (the 3.6%-of-profile block once the worker spin
      // was collapsed): 67.7 MB/s hinted vs 170.6 MB/s unhinted with a busy
      // SMT sibling, and 193 MB/s unhinted alone — a 2.5x loss on a loop that
      // was never a spin. A scan must increment something, so require the
      // whole region to contain NO OP_ADD and no integer Sub other than the
      // counted decrement; a genuine poll re-reads a fixed base
      // (EntrypointOffset / SRA register), which this enforces indirectly.
      //
      // False negatives are cheap here (a spin that also increments simply
      // keeps normal priority); false positives cost 2.5x. Gate accordingly.
      bool RegionStationary = true;
      uint32_t RegionSubCount = 0;
      for (uint32_t ri = ti; ri <= bi && RegionStationary; ++ri) {
        for (auto [CodeNode, IROp] : IR->GetCode(Blocks[ri].Node)) {
          if (IROp->Op == IR::OP_ADD || IROp->Op == IR::OP_ADDWITHFLAGS || IROp->Op == IR::OP_ADDNZCV) {
            RegionStationary = false;
            break;
          }
          if (IROp->Op == IR::OP_SUB && ++RegionSubCount > 1) {
            RegionStationary = false;
            break;
          }
        }
      }

      const bool RegionHinted = SpinLoopHintEnabled && (RegionStationary || SpinHintAnyLoop);
      if (RegionHinted) {
        PushUnique(SpinBackedges, SpinEdgeKey(Blocks[bi].ID, TargetID));
      }

      // FEX_SPINCOLLAPSE: within a validated spin region, match the fused
      // counted-decrement shape in the backedge block and mark its Sub +
      // CondJump for batched emission (contract at kSpinCollapseK,
      // JITClass.h). Post-RA, consumer args are immediate-encoded
      // PhysicalRegisters — all value linkage is matched by register, the
      // mask-elision lesson.
      if (SpinCollapseEnabled) {

        IR::Ref SubNode = nullptr;
        const IR::IROp_Header* SubHdr = nullptr;
        IR::PhysicalRegister SubSrcPR = IR::PhysicalRegister::Invalid();
        IR::PhysicalRegister SubDstPR = IR::PhysicalRegister::Invalid();
        IR::PhysicalRegister CopySrcPR = IR::PhysicalRegister::Invalid();
        IR::PhysicalRegister CopyDstPR = IR::PhysicalRegister::Invalid();
        IR::Ref BranchNode = nullptr;
        const IR::IROp_Header* BranchHdr = nullptr;
        IR::Ref CopyNode = nullptr;
        IR::Ref StoreNode = nullptr;
        uint32_t SubCount = 0;
        bool StoreOfSubSeen = false;
        bool CopyIsBfe32 = false;

        const auto ArgPR = [this](IR::OrderedNodeWrapper Arg) {
          return Arg.IsImmediate() ? IR::PhysicalRegister(Arg) : IR::PhysicalRegister(IR->GetNode(Arg));
        };

        for (auto [CodeNode, IROp] : IR->GetCode(Blocks[bi].Node)) {
          switch (IROp->Op) {
          case IR::OP_SUB: {
            ++SubCount;
            auto SOp = IROp->C<IR::IROp_Sub>();
            uint64_t C = 0;
            if ((IROp->Size == IR::OpSize::i32Bit || IROp->Size == IR::OpSize::i64Bit) && IsInlineConstant(SOp->Src2, &C) && C == 1) {
              SubNode = CodeNode;
              SubHdr = IROp;
              SubSrcPR = ArgPR(SOp->Src1);
              SubDstPR = IR::PhysicalRegister(CodeNode);
            }
            break;
          }
          case IR::OP_COPY: {
            auto COp = IROp->C<IR::IROp_Copy>();
            CopySrcPR = ArgPR(COp->Source);
            CopyDstPR = IR::PhysicalRegister(CodeNode);
            CopyNode = CodeNode;
            CopyIsBfe32 = false;
            break;
          }
          case IR::OP_BFE: {
            // The OTHER staging form. `mov eax,ecx` ahead of a 32-bit
            // decrement lowers to Bfe(#32,#0), not OP_COPY — a zero-extend,
            // because the guest write is 32-bit. CP2077's worker loop stages
            // its pre-decrement budget exactly this way, and a matcher that
            // only knew OP_COPY left Cmp1 linked to nothing (live reject
            // trace 2026-08-15, entry=0x37fff3c830a0). Only the full low-32
            // field qualifies: a narrower or shifted extract is some other
            // guest value, not the budget.
            auto BOp = IROp->C<IR::IROp_Bfe>();
            if (BOp->Width == 32 && BOp->lsb == 0) {
              CopySrcPR = ArgPR(BOp->Src);
              CopyDstPR = IR::PhysicalRegister(CodeNode);
              CopyNode = CodeNode;
              CopyIsBfe32 = true;
            }
            break;
          }
          case IR::OP_STOREREGISTER: {
            auto ROp = IROp->C<IR::IROp_StoreRegister>();
            if (SubNode && ArgPR(ROp->Value).Raw == SubDstPR.Raw) {
              StoreOfSubSeen = true;
              StoreNode = CodeNode;
            }
            break;
          }
          case IR::OP_CONDJUMP: {
            BranchNode = CodeNode;
            BranchHdr = IROp;
            break;
          }
          default: break;
          }
        }

        // FEX_SPINCOLLAPSE_TRACE=1: one line per collapsed loop, AND one line
        // per validated spin region the collapse guards REFUSED, naming the
        // guard — the CP2077 worker loop went unmatched for two sessions
        // because there was no way to see which stage walked past it
        // (compile-time events, low volume: only Clean+HasPollLoad regions).
        static const bool Trace = [] {
          const char* T = getenv("FEX_SPINCOLLAPSE_TRACE");
          return T && T[0] == '1';
        }();
        const char* Reject = nullptr;
        int RejectCond = -1;
        int64_t RejectImm = -1;

        // The decrement must genuinely update the guest's budget, not a
        // throwaway temp. Two forms satisfy that, and only one of them emits
        // a store: when the budget is SRA-resident, RA gives the Sub the same
        // physical register for source and destination and the write-back IS
        // the Sub (`addi r8,r8,-1`) — no StoreRegister exists anywhere in the
        // block. Demanding the store rejected CP2077's worker loop for two
        // sessions (live trace 2026-08-15: reason=no-store-of-sub, 9 threads,
        // 41% of process samples), and would reject every other SRA-held
        // budget the same way.
        const bool WritesBack = SubNode && (StoreOfSubSeen || SubDstPR.Raw == SubSrcPR.Raw);
        if (RegionStationary && SubNode && BranchNode && SubCount == 1 && WritesBack) {
          auto JOp = BranchHdr->C<IR::IROp_CondJump>();
          uint64_t JC = 0;
          // Two counted-decrement backedge idioms, identical batched form
          // (keep spinning iff old > K, consuming min(old, K) per iteration):
          //   NEQ-1 : `dec ecx; jne`            — branch on old != 1
          //   SGT-0 : `mov eax,ecx; dec ecx; test eax,eax; jg`
          //           — branch on old >s 0. This is CP2077's redDispatcher
          //           worker loop (the 40-50%-of-profile block); the v1
          //           matcher only knew NEQ-1 and walked straight past it.
          // SGT needs the SIGNED batched compare (see
          // SpinCollapseBranchSigned in JITClass.h).
          const bool CondIsInline = IsInlineConstant(JOp->Cmp2, &JC);
          const bool ShapeNEQ = JOp->Cond == IR::CondClass::NEQ && CondIsInline && JC == 1;
          const bool ShapeSGT = JOp->Cond == IR::CondClass::SGT && CondIsInline && JC == 0;
          const bool ShapeOK = JOp->VCmpElementSize == IR::OpSize::iInvalid && !JOp->FromNZCV &&
                               (ShapeNEQ || ShapeSGT) &&
                               JOp->CompareSize == SubHdr->Size &&
                               IR->GetOp<IR::IROp_CodeBlock>(JOp->TrueBlock)->ID == TargetID;
          if (ShapeOK) {
            const auto Cmp1PR = ArgPR(JOp->Cmp1);
            // A Bfe-staged compare is only meaningful for a 32-bit budget:
            // the staging truncates to the low 32 bits, so pairing it with a
            // 64-bit decrement would batch against a different value than the
            // guest branched on. ShapeOK already ties CompareSize to the Sub.
            const bool StagingOK = CopyNode && Cmp1PR.Raw == CopyDstPR.Raw && CopySrcPR.Raw == SubSrcPR.Raw &&
                                   (!CopyIsBfe32 || SubHdr->Size == IR::OpSize::i32Bit);
            const bool Linked = Cmp1PR.Raw == SubSrcPR.Raw || StagingOK;
            // Complete budget-liveness guard. Inside the region the ONLY
            // permitted readers of the budget register are the decrement
            // itself, the Copy staging the pre-decrement value, and the
            // backedge compare; the only permitted reader of the decrement's
            // RESULT is the StoreRegister writing it back; the staged copy
            // may be read only by the branch. Anything else consuming any of
            // the three (an index-addressed scan's load, a bound check, a
            // shift amount, an exit-path length computation...) observes the
            // coarsened K-step descent and breaks — the v2 load-only version
            // of this guard still let CP2077's bootstrap crash. Conservative
            // by physical register: an unrelated live range that happens to
            // share the register rejects the region, costing only the
            // elision.
            bool ForeignReader = false;
            if (Linked) {
              for (uint32_t ri = ti; ri <= bi && !ForeignReader; ++ri) {
                for (auto [RNode, ROp] : IR->GetCode(Blocks[ri].Node)) {
                  if (RNode == SubNode || RNode == BranchNode || RNode == CopyNode) {
                    continue;
                  }
                  // A second WRITER is as fatal as a foreign reader: the
                  // collapse rewrites one def/use chain, so anything else
                  // driving the budget (or the staged value the backedge
                  // compares) would be handed a K-granular descent it never
                  // agreed to. This is what keeps the relaxed write-back rule
                  // above honest — in-place SRA form is only safe while the
                  // Sub is the sole definition in the region.
                  if (IR::GetHasDest(ROp->Op)) {
                    const auto DefPR = IR::PhysicalRegister(RNode);
                    if (!DefPR.IsInvalid() &&
                        (DefPR.Raw == SubSrcPR.Raw || (ri == bi && !CopyDstPR.IsInvalid() && DefPR.Raw == CopyDstPR.Raw))) {
                      ForeignReader = true;
                      break;
                    }
                  }
                  // Only VALUE args may be interpreted as registers: block
                  // references (branch targets) and InlineConstant nodes have
                  // no RA assignment, and PhysicalRegister() over them reads
                  // garbage that randomly aliases real registers (the v3
                  // guard rejected its own repro through a branch-target
                  // arg). CondJump contributes exactly Cmp1/Cmp2; pure
                  // control/structure ops contribute nothing.
                  IR::OrderedNodeWrapper ValueArgs[2] = {IR::OrderedNodeWrapper::WrapOffset(0), IR::OrderedNodeWrapper::WrapOffset(0)};
                  uint8_t NumCheck = 0;
                  switch (ROp->Op) {
                  case IR::OP_CONDJUMP: {
                    auto J2 = ROp->C<IR::IROp_CondJump>();
                    ValueArgs[NumCheck++] = J2->Cmp1;
                    ValueArgs[NumCheck++] = J2->Cmp2;
                    break;
                  }
                  case IR::OP_JUMP:
                  case IR::OP_BEGINBLOCK:
                  case IR::OP_ENDBLOCK:
                  case IR::OP_GUESTOPCODE:
                  case IR::OP_INLINECONSTANT:
                  case IR::OP_INLINEENTRYPOINTOFFSET:
                    break;
                  default: {
                    const uint8_t NumArgs = IR::GetArgs(ROp->Op);
                    for (uint8_t a = 0; a < NumArgs && NumCheck < 2; a++) {
                      ValueArgs[NumCheck++] = ROp->Args[a];
                    }
                    // Ops with more than two args in a spin region are
                    // exotic; treat them as foreign rather than under-check.
                    if (IR::GetArgs(ROp->Op) > 2) {
                      ForeignReader = true;
                    }
                    break;
                  }
                  }
                  // Live-range scoping: the budget lives in an SRA register
                  // and is meaningful REGION-wide; the Sub result and the
                  // staged Copy are block-local scratch whose physical
                  // registers (r0/r1 pool) are recycled by RA in every other
                  // block — checking those region-wide false-rejects almost
                  // every real loop (the repro's poll-address temp shares r0
                  // with the Sub result). Scope them to the backedge block.
                  uint64_t Scratch;
                  for (uint8_t a = 0; a < NumCheck && !ForeignReader; a++) {
                    if (ValueArgs[a].IsInvalid() || IsInlineConstant(ValueArgs[a], &Scratch)) {
                      continue;
                    }
                    const auto PR = ArgPR(ValueArgs[a]);
                    if (PR.Raw == SubSrcPR.Raw) {
                      ForeignReader = true;
                    } else if (ri == bi && (PR.Raw == CopyDstPR.Raw || (PR.Raw == SubDstPR.Raw && RNode != StoreNode))) {
                      ForeignReader = true;
                    }
                  }
                  if (ForeignReader) {
                    break;
                  }
                }
              }
            }
            if (Linked && !ForeignReader) {
              SpinCollapseSubs[IR->GetID(SubNode).Value] = true;
              SpinCollapseBranches[IR->GetID(BranchNode).Value] = true;
              if (ShapeSGT) {
                SpinCollapseBranchSigned[IR->GetID(BranchNode).Value] = true;
              }
              if (Trace) {
                fprintf(stderr, "SPINCOLLAPSE: entry=0x%lx head-block=%u%s\n",
                        IR->GetHeader()->OriginalRIP, TargetID, ShapeSGT ? " (sgt0)" : "");
              }
            } else {
              Reject = !Linked ? "unlinked" : "foreign-reader";
            }
          } else {
            Reject = "shape";
            RejectCond = static_cast<int>(JOp->Cond);
            uint64_t Imm = 0;
            RejectImm = IsInlineConstant(JOp->Cmp2, &Imm) ? static_cast<int64_t>(Imm) : -1;
          }
        } else {
          Reject = !RegionStationary ? "not-stationary" :
                   !SubNode          ? "no-sub1" :
                   !BranchNode       ? "no-branch" :
                   SubCount != 1     ? "multi-sub" :
                                       "no-writeback";
        }
        if (Reject && Trace) {
          fprintf(stderr, "SPINCOLLAPSE-REJECT: entry=0x%lx head-block=%u reason=%s cond=%d imm=%ld\n",
                  IR->GetHeader()->OriginalRIP, TargetID, Reject, RejectCond, static_cast<long>(RejectImm));
        }
      }
      // Every edge from a region block to a block outside [ti, bi] restores
      // medium priority — but only where a backedge hint actually lowered it.
      // Emitting restores for an unhinted region would be pure padding, and
      // worse, would raise the priority of a thread this region never lowered.
      if (RegionHinted) {
        for (uint32_t ri = ti; ri <= bi; ++ri) {
          for (const uint32_t T : Blocks[ri].Targets) {
            if (T == UINT32_MAX || T >= NumBlocks) {
              continue;
            }
            const uint32_t tidx = IdxOfID[T];
            if (tidx < ti || tidx > bi) {
              PushUnique(SpinRestoreEdges, SpinEdgeKey(Blocks[ri].ID, T));
            }
          }
        }
      }
    }
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

  // Op-size profiler gate. Read once per CompileCode from the already-cached
  // config Getter, so the emission loop below only sees a local boolean.
#ifndef FEX_DISABLE_JIT_OPSIZE_PROFILE
  [[maybe_unused]] const bool OpSizeProfileEnabled = CTX->Config.JITOpSizeProfile();
#else
  [[maybe_unused]] constexpr bool OpSizeProfileEnabled = false;
#endif

  // PPC64 emits directly into the shared CurrentCodeBuffer (unlike arm64,
  // which stages in a per-thread TempCodeBuffer and copies under the lock).
  // Without serialization, two threads compiling concurrently both read the
  // same LatestOffset, emit on top of each other, and end up dispatching to
  // garbage host instructions. Hold the write mutex for the whole emission
  // window — including the icache flush — so other threads see a coherent
  // buffer state.
  // Diagnostic: CodeBufferWriteMutex is non-recursive.  If this thread already
  // owns it we are about to deadlock against ourselves and take every other
  // thread down with us (they all block here on the next compile).  Report the
  // re-entry with a host backtrace instead of hanging silently.
  // Cached per-thread: this used to be a `::syscall(SYS_gettid)` on *every*
  // CompileCode entry — a full kernel round-trip per compiled block, paid only
  // to feed this diagnostic and the OwnerTracker below. A thread's TID is
  // immutable for its lifetime, so fetch it once.
  //
  // Fork caveat: a thread that continues in a forked child keeps the cached
  // parent-side TID (the child's real TID differs). Nothing here depends on
  // the TID being a *real* TID — it is only used as a per-thread identity token
  // compared against CodeBufferWriteOwner, which lives in the same address
  // space and is written by the same cached value. The only observable effect
  // of staleness is the number printed in the re-entrancy log message below.
  static thread_local const uint64_t SelfTID = static_cast<uint64_t>(::syscall(SYS_gettid));
  if (CodeBuffers.CodeBufferWriteOwner.load(std::memory_order_relaxed) == SelfTID) {
    LogMan::Msg::EFmt("PPC64 JIT: re-entrant CompileCode on tid {} for Entry {:#x} -- "
                      "CodeBufferWriteMutex is already held by this thread. Host backtrace:",
                      SelfTID, Entry);
    void* Frames[32];
    const int Count = ::backtrace(Frames, 32);
    ::backtrace_symbols_fd(Frames, Count, 2);
  }

  std::unique_lock CodeBufferLock {CodeBuffers.CodeBufferWriteMutex};

  // Clear the owner on every exit path, including the unlock/lock dance in the
  // capacity guard below.
  struct OwnerTracker {
    std::atomic<uint64_t>& Owner;
    uint64_t TID;
    OwnerTracker(std::atomic<uint64_t>& O, uint64_t T)
      : Owner(O)
      , TID(T) {
      Owner.store(TID, std::memory_order_relaxed);
    }
    ~OwnerTracker() {
      Owner.store(0, std::memory_order_relaxed);
    }
  } OwnerGuard {CodeBuffers.CodeBufferWriteOwner, SelfTID};

  // ------------------------------------------------------------------
  // Pick up a code-buffer rotation performed by another thread
  // ------------------------------------------------------------------
  // Another thread's ClearCache() may have rotated CodeBuffers to a new buffer
  // since this thread last compiled. ClearCache only migrates the *rotating*
  // thread's lookup cache, so without this handshake this thread is left with
  // CurrentCodeBuffer pointing at the old buffer while CodeBuffers.LatestOffset
  // (shared, and reset to 0 by the rotation) describes the new one. We would
  // then emit at old_base + new_offset and publish L1/L2 entries for it, while
  // ThreadState->LookupCache->Shared still refers to the old buffer's map.
  //
  // The observable failure is a guest RIP whose L1 entry resolves into the
  // middle of an unrelated block. Dispatch lands past that block's RIP store,
  // so the block spills and returns to DispatcherLoopTop with State.rip
  // unchanged -- the same lookup hits the same bad pointer forever. Ziggurat
  // wedged exactly this way at 100% CPU on one thread after mono finished
  // loading assemblies.
  //
  // Arm64JITCore does the same handshake before copying its staging buffer out
  // (JIT/JIT.cpp:1085); it matters more here because PPC64 emits directly into
  // the shared buffer rather than staging per-thread.
  //
  // Wipe CallRetStack alongside the code-buffer rotation. When
  // FEX_SHADOWRETSTACK is on, the per-thread call-ret stack holds host
  // trampoline pointers into the OUTGOING buffer; those must never survive a
  // rotation, because the buffer memory is about to be reused and a later RET
  // would fast-path into recycled code. Zeroing self-heals: a zero guest-RIP
  // slot never matches, so every pop falls back to the L1 probe. Cheap and
  // unconditional (a no-op when the feature is off, since the stack is empty).
  // Mirrors JIT/JIT.cpp:1086.
  if (auto Prev = CheckCodeBufferUpdate()) {
    Allocator::VirtualDontNeed(ThreadState->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
    auto CacheLock = ThreadState->LookupCache->AcquireWriteLock();
    ThreadState->LookupCache->ChangeGuestToHostMapping(*Prev, *CurrentCodeBuffer->LookupCache, CacheLock);
  }

  LOGMAN_THROW_A_FMT(CurrentCodeBuffer->LookupCache.get() == ThreadState->LookupCache->Shared,
                     "INVARIANT VIOLATED: SharedLookupCache doesn't match the current code buffer!");

  this->Entry    = Entry;
  this->IR       = IRView;
  this->DebugData = DebugData_;

  // Sample SpillSlots from the post-RA IR and compute the per-block
  // spill-frame size. align16() is implicit because MaxSpillSlotSize=32
  // and kSpillSlotPrefix=96 are both multiples of 16, keeping the PPC
  // ELFv2 stack alignment.
  SpillSlots     = IRView->SpillSlots();
  SpillFrameSize = SpillSlots ? (kSpillSlotPrefix + SpillSlots * MaxSpillSlotSize) : 0;

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
  // The requirement MUST scale with the IR size. A fixed bound (this used to be
  // a flat 1 MiB) is unsafe: with a large MaxInst -- the Unity/mono app configs
  // in the wild use 50000 against a default of 5000 -- the frontend produces
  // blocks of hundreds of KiB of guest code whose host expansion exceeds any
  // constant we could pick. Overrunning is not merely wasted space: emission
  // walks off the end into the PROT_NONE guard page, the SIGSEGV handler
  // redirects this thread back into the dispatcher, and this stack frame is
  // abandoned with CodeBufferWriteMutex still held. The next compile on this
  // thread then deadlocks against itself and every other thread piles up behind
  // it -- the whole process wedges with all threads parked in futex waits.
  //
  // A single IR op expands to at most ~80 host bytes today (SpillStaticRegs plus
  // flag pack/unpack is the heaviest); 128 gives margin without walking the IR
  // twice. GetSSACount() bounds the IR-op count. Keep 1 MiB as a floor.
  //
  // The additional 16 bytes/IR-op covers the worst-case vl64pair RIP entry
  // (sizeof(vl64_enc)) that P3.1's post-tail table can emit for each
  // GuestOpcode marker in the stream. Only a subset of SSA nodes actually
  // become GuestOpcode markers (frontend only emits them for ops with
  // CanHaveSideEffects, per Core.cpp:654-656), so this is a loose upper
  // bound. Adding one JITCodeTail explicitly guards the tail struct too.
  //
  // When the buffer is too full, drop the lock and call ClearCache().
  // ClearCache acquires its own LookupCache write lock and allocates a
  // fresh, larger CodeBuffer via GetEmptyCodeBuffer/StartLargerCodeBuffer,
  // migrating the L1/L2 mapping via ChangeGuestToHostMapping. After
  // re-acquiring CodeBufferLock, LatestOffset is 0 in the new buffer.
  // Loop, because one rotation only grows the buffer geometrically and a very
  // large block may need several before it fits.
  // kMaxHostBytesPerIROp / kMaxRIPEntryBytesPerIROp now live at namespace scope
  // (just above the op-size profiler) so the profiler can print the budget it
  // is checking. Values are unchanged.
  const size_t BlockHeadroom = std::max<size_t>(
    1u << 20,
    IRView->GetSSACount() * (kMaxHostBytesPerIROp + kMaxRIPEntryBytesPerIROp) + sizeof(CPUBackend::JITCodeTail));

  while (CodeBuffers.LatestOffset + BlockHeadroom > CurrentCodeBuffer->UsableSize()) {
    const size_t PrevUsable = CurrentCodeBuffer->UsableSize();

    // Drop ownership across the unlock window so a nested compile from
    // ClearCache() isn't misreported as a re-entrant deadlock.
    CodeBuffers.CodeBufferWriteOwner.store(0, std::memory_order_relaxed);
    CodeBufferLock.unlock();
    ClearCache();
    CodeBufferLock.lock();
    CodeBuffers.CodeBufferWriteOwner.store(SelfTID, std::memory_order_relaxed);

    // ClearCache resets LatestOffset to 0 in the new buffer. If the buffer also
    // stopped growing (MAX_CODE_SIZE reached) and the block still doesn't fit,
    // another rotation will never help -- bail out loudly rather than spin, or
    // silently overrun and reproduce the deadlock described above.
    if (CodeBuffers.LatestOffset + BlockHeadroom > CurrentCodeBuffer->UsableSize() && CurrentCodeBuffer->UsableSize() <= PrevUsable) {
      ERROR_AND_DIE_FMT("PPC64 JIT: block at {:#x} needs {} bytes of code buffer but the maximum buffer only has {}. "
                        "Lower MaxInst (currently producing {} IR ops).",
                        Entry, BlockHeadroom, CurrentCodeBuffer->UsableSize(), IRView->GetSSACount());
    }
  }

  // Use the current code buffer at the current write offset.
  //
  // S3.7-C0: snapshot BlockBufferOffset BEFORE SetBuffer opens the window.
  // Relocations record `.Offset = BlockBufferOffset + GetOffset()` — buffer-
  // relative, matching what CodeCache::ApplyCodeRelocations expects. Doing
  // it here is stable across the LatestOffset bumps at :2486 / :2532.
  // CodeData.BlockBegin down at Finalise (:2474) uses the same snapshot for
  // the same reason.
  auto* CB = CurrentCodeBuffer.get();
  BlockBufferOffset = CodeBuffers.LatestOffset;
  SetBuffer(CB->Ptr + CodeBuffers.LatestOffset,
            CB->UsableSize() - CodeBuffers.LatestOffset);

  CodeData = {};
  ExitRIPSitesOverflowed = false;
  MovImmWindowsOverflowed = false;
  CodeData.BlockBegin = GetCursorAddress<uint8_t*>();

  // -------------------------------------------------------------------------
  // JITCodeHeader (4 bytes, at BlockBegin)
  // -------------------------------------------------------------------------
  // Bind the label at BlockBegin, then reserve 4 bytes for the header. The
  // OffsetToBlockTail field is backpatched after the tail is placed. The
  // (unreachable, and now un-emitted by default) cold-path prologue used to
  // start at BlockBegin+4; dispatcher entries land past it either way. See
  // CPUBackend::JITCodeHeader / JITCodeTail for the layout GetFrameBlockInfo
  // (Core.cpp:132) consumes, and EmitEntryPoint for the gate.
  PPC64Emitter::Label HeaderLabel{};
  Bind(&HeaderLabel);
  auto* CodeHeader = GetCursorAddress<CPUBackend::JITCodeHeader*>();
  Emit32(0);  // placeholder — backpatched below

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

  // Shadow-return entry labels: one per block, indexed by IROp_CodeBlock::ID,
  // same as JumpTargets. Sized (once, here, before any op emits) only when the
  // feature is on so the default path never touches this vector. Element
  // addresses are stable for the rest of CompileCode, which the Call push's
  // pending forward branch to CallReturnEntryLabels[id] relies on.
  CallReturnEntryLabels.clear();
  if (ShadowRetStackEnabled) {
    CallReturnEntryLabels.resize(NumBlocks, {});
  }

  // Detect tiny memory-polling loops and mark their backedges/exit edges for
  // SMT priority hints (see JITClass.h and DEF_OP(CondJump)/DEF_OP(Jump)).
  // The same region walk feeds the FEX_SPINCOLLAPSE matcher; each consumer
  // is gated individually inside.
  SpinBackedges.clear();
  SpinRestoreEdges.clear();
  if (SpinLoopHintEnabled || SpinCollapseEnabled) {
    AnalyzeSpinLoops();
  }

  // Belt-and-suspenders: any pending forward-branch fixups left over from a
  // prior compilation (which would also be a bug) point into a buffer that
  // no longer exists; drop them.
  ClearPendingBranches();

  // Same for pending block-link jump thunks: their LinkPath labels are the
  // targets of miss-leg branches recorded in PendingBranches, so the two
  // lists must be reset together. Ditto the shared spill stub labels, whose
  // fixup chains also live in PendingBranches.
  PendingJumpThunks.clear();
  SharedSpillExitLabel = {};
  SharedSpillLinkLabel = {};
  SharedSpillExitUsed = false;
  SharedSpillLinkUsed = false;

  // -------------------------------------------------------------------------
  // Emit entry point
  // -------------------------------------------------------------------------
  // HeaderLabel is already bound above. EmitEntryPoint is a no-op unless
  // FEX_DEADPROLOGUE re-enables the unreachable cold-path prologue; see the
  // unreachability analysis on its definition.
  EmitEntryPoint(HeaderLabel, CheckTF);

  // The entry point map: guest RIP -> host code address.
  // NOTE: the per-IR-block loop below OVERWRITES this with the same Entry key
  // when BlockIROp->EntryPoint && GuestEntryOffset == 0. Nothing is emitted
  // between here and that first loop iteration, so the two records resolve to
  // the SAME address whether or not the overwrite happens -- which is what
  // makes gating EmitEntryPoint's body off address-neutral. The spill-frame
  // stdu therefore has to be emitted INSIDE the for-loop, immediately after
  // the EntryPoint recording, not here.
  CodeData.EntryPoints[Entry] = GetCursorAddress<uint8_t*>();

  // Everything emitted since SetBuffer (JITCodeHeader + EmitEntryPoint) is
  // per-CompileCode overhead that no IR op pays for. Bucket it separately so
  // the per-op numbers are not polluted and the block-level residual adds up.
  // GetOffset() is block-relative here because SetBuffer reset it to 0.
  PPC64_OPSIZE_RECORD(OpSizeProfileEnabled, OpSizeProfile::BUCKET_COMPILECODE_PREAMBLE, GetOffset(), Entry);

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

    // PPC64LE-only vector ops. IR.json marks them JITDispatch:false (they are
    // emitted by the OpcodeDispatcher only under ARCHITECTURE_ppc64le, so no
    // other backend has to grow a lowering), which keeps them out of
    // IRDefines_Dispatch.inc — wire them up explicitly.
    REGISTER_OP(VMADDPAIRWISE16,   VMaddPairwise16);
    REGISTER_OP(VEXTRACTSIGNBITS,  VExtractSignBits);
    REGISTER_OP(VANYNONZERO,       VAnyNonZero);
    REGISTER_OP(LOADMEMREV,        LoadMemRev);
    REGISTER_OP(STOREMEMREV,       StoreMemRev);

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

    // Native f64→f80 conversion. Unlike the ops above this one IS hot on the
    // normal (passes-enabled) path: ReducedPrecisionMode FXSAVE/FST-m80
    // convert through it, and the FABI softfloat bridge (f64_to_extF80) was
    // ~4.5% of Cyberpunk 2077's game thread. The DEF_OP delegates non-i64
    // sources back to Op_Unhandled's FABI call.
    REGISTER_OP(F80CVTTO,          F80CVTTo);

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
  //
  // Per-op live-in masks for the dynamic FPR pool (bit i = RAFPR pool index
  // i), keyed by node ID. Feeds DynVRSpillMask so helper calls save only the
  // vector values actually live across them. Exact, not heuristic: RA is
  // strictly block-local (every class starts each block with all registers
  // available — RegisterAllocationPass.cpp Run()), so a backward
  // physical-register scan per block sees every live range. The op's own dest
  // is defensively INCLUDED (some handler shapes write the dest before the
  // helper call; saving a possibly-garbage register is harmless, losing a
  // written one is not). FEX_NO_ABI_LIVEMASK reverts to full saves for A/B.
  static const bool DisableABILiveMask = getenv("FEX_NO_ABI_LIVEMASK") != nullptr;
  fextl::vector<uint32_t> DynVRLiveIn;
  if (!DisableABILiveMask) {
    DynVRLiveIn.assign(IRView->GetSSACount(), ~0u);
  }

  Compute32MaskElision();
  ComputeTSOPairElision();

  // Emission-order prepass for fallthrough elision: {CodeBlock ID, EntryPoint}
  // per block, in the exact order the loop below emits them. See the
  // FallthroughBlockID comment in JITClass.h for why EntryPoint successors
  // are never fallthrough candidates.
  // Fallthrough elision measured a ~4.7% REGRESSION on a tight RMW microloop:
  // removing the loop terminator branch shifts loop-top alignment, and POWER8
  // fetch groups punish that more than the saved branch pays. Opt-in via
  // FEX_FALLTHROUGH=1 until backward-branch-target alignment lands.
  static const bool DisableFallthrough = getenv("FEX_FALLTHROUGH") == nullptr;
  fextl::vector<std::pair<uint32_t, bool>> BlockEmissionOrder;
  if (!DisableFallthrough) {
    BlockEmissionOrder.reserve(IRView->GetHeader()->BlockCount);
    for (auto [BlockNode, BlockHeader] : IRView->GetBlocks()) {
      auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
      BlockEmissionOrder.emplace_back(BlockIROp->ID, BlockIROp->EntryPoint);
    }
  }
  size_t BlockEmissionIdx = 0;

  for (auto [BlockNode, BlockHeader] : IRView->GetBlocks()) {
    auto BlockIROp = BlockHeader->CW<FEXCore::IR::IROp_CodeBlock>();
    CurrentBlockID = BlockIROp->ID;

    FallthroughBlockID = UINT32_MAX;
    if (!DisableFallthrough) {
      const size_t Next = BlockEmissionIdx + 1;
      if (Next < BlockEmissionOrder.size() && !BlockEmissionOrder[Next].second) {
        FallthroughBlockID = BlockEmissionOrder[Next].first;
      }
      ++BlockEmissionIdx;
    }

    if (!DynVRLiveIn.empty()) {
      // Backward scan: Live holds the live-after set of the op under the
      // cursor; live-before = (live-after − def) ∪ uses. Args of inline
      // constants and other non-RA'd references carry an Invalid class byte
      // and fall out of the RegClass::FPR test; a stray false positive would
      // only add a redundant save, never lose one.
      uint32_t Live = 0;
      auto CodeBegin = IRView->at(BlockIROp->Begin);
      auto CodeLast = IRView->at(BlockIROp->Last);
      while (1) {
        auto [CodeNode, IROp] = CodeLast();

        uint32_t Def = 0;
        if (IR::GetHasDest(IROp->Op)) {
          const IR::PhysicalRegister PR(CodeNode);
          if (PR.AsRegClass() == IR::RegClass::FPR) {
            Def = 1u << PR.Reg;
          }
        }

        uint32_t Use = 0;
        const int NumArgs = IR::GetRAArgs(IROp->Op);
        for (int i = 0; i < NumArgs; ++i) {
          const auto Arg = IROp->Args[i];
          if (Arg.IsInvalid()) {
            continue;
          }
          const IR::PhysicalRegister PR =
            Arg.IsImmediate() ? IR::PhysicalRegister(Arg) : IR::PhysicalRegister(IRView->GetNode(Arg));
          if (PR.AsRegClass() == IR::RegClass::FPR) {
            Use |= 1u << PR.Reg;
          }
        }

        Live = (Live & ~Def) | Use;
        DynVRLiveIn[IRView->GetID(CodeNode).Value] = Live | Def;

        if (CodeLast == CodeBegin) {
          break;
        }
        --CodeLast;
      }
    }

    // Start of this IR block's out-of-band prologue (EntryPoint marker store,
    // suspend check, spill-frame stdu). Attributed to a synthetic bucket, not
    // to whichever IR op happens to be first in the block.
    [[maybe_unused]] const size_t BlockPrologueStart = GetOffset();

    if (BlockIROp->EntryPoint) {
      uint64_t GuestEntry = Entry + BlockIROp->GuestEntryOffset;
      CodeData.EntryPoints[GuestEntry] = GetCursorAddress<uint8_t*>();
      // Shadow-return fast-path entry: bind this block's CallReturnEntryLabels
      // slot at the SAME cursor a dispatcher L1 hit lands on (this EntryPoints
      // value), i.e. BEFORE EmitStoreBlockBeginToInlineHeader / the suspend
      // poke / the stdu below. A shadow RET that matched then behaves exactly
      // like an L1 hit into this block, including running the deferred-signal
      // poke (which is what keeps the lazy-SMC interlock sound). All real
      // call-return targets are EntryPoints, so every label a Call push
      // referenced is bound here. Binding blocks no push referenced is a no-op.
      if (ShadowRetStackEnabled) {
        Bind(&CallReturnEntryLabels[BlockIROp->ID]);
      }
      // Seed the RIP-entry table with this entry-point's guest offset. Mirrors
      // Arm64JITCore's push_back at JIT/JIT.cpp:939 — HostPCOffset here points
      // at the entry-point prologue's first byte, which is what a signal fault
      // in the prologue should map back to (block-entry guest RIP).
      DebugData->GuestOpcodes.push_back({BlockIROp->GuestEntryOffset,
                                         GetCursorAddress<uint8_t*>() - CodeData.BlockBegin});
      // Warm-path store: dispatcher L1 hits land here. This is the ONLY
      // InlineJITBlockHeader store that ever executes (EmitEntryPoint's copy is
      // unreachable and gated off). Re-emit so it is refreshed on every entry.
      EmitStoreBlockBeginToInlineHeader(HeaderLabel);
      // FEX_ENTRYWATCH ring store (see the definition above). TMP1/TMP2 are
      // clobberable here per the EmitStoreBlockBeginToInlineHeader contract;
      // r10 already holds guest RBX (dispatcher FillStaticRegs ran before the
      // bctr into this prologue).
      if (const auto [WatchBegin, WatchEnd] = EntryWatchRange(); WatchEnd != 0 && GuestEntry >= WatchBegin && GuestEntry < WatchEnd) {
        auto* Slot = &FEX_EntryWatch[EntryWatchNextSlot++ % std::size(FEX_EntryWatch)];
        Slot->GuestRIP = GuestEntry;
        LoadConstant(TMP1, reinterpret_cast<uint64_t>(Slot));
        std(r10, static_cast<int16_t>(offsetof(FEXEntryWatchSlot, LastRBX)), TMP1);
        mftb(TMP2);
        std(TMP2, static_cast<int16_t>(offsetof(FEXEntryWatchSlot, LastTB)), TMP1);
        ld(TMP2, static_cast<int16_t>(offsetof(FEXEntryWatchSlot, Count)), TMP1);
        addi(TMP2, TMP2, 1);
        std(TMP2, static_cast<int16_t>(offsetof(FEXEntryWatchSlot, Count)), TMP1);
        LogMan::Msg::IFmt("EntryWatch: slot {} watching dispatcher entries at guest RIP 0x{:x}", (EntryWatchNextSlot.load() - 1) % std::size(FEX_EntryWatch),
                          GuestEntry);
      }
      // Drain any deferred async signal at this guest instruction boundary.
      // Every dispatcher hit and linked block-to-block jump lands here, so a
      // guest loop spanning compile units cannot orbit without passing a
      // fault-page poke. Placed before the stdu so intra-unit jumps (bound
      // below) skip it -- backward intra-unit edges emit their own poke in
      // DEF_OP(Jump)/DEF_OP(CondJump).
      EmitSuspendInterruptCheck();
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
    // Bind() only patches already-emitted forward branches; it does not move
    // the cursor, so the prologue delta is complete here.
    Bind(JumpTarget(BlockNode));

    // A block can be entered from anywhere; nothing about the previously
    // emitted block's trailing register contents may be assumed here.
    InvalidateAESCache();
    XERProjectionValid = false;
    LastConstantCache.Valid = false;

    // Load-and-splat pre-pass (see SplatCandidateLoads in JITClass.h): mark
    // single-use f64 FPR loads whose only consumer is an FMA-family scalar
    // insert multiplicand/addend, so DEF_OP(LoadMem) can emit lxvdsx and the
    // FMA handler can skip its splat. Same-block pairs only by construction.
    SplatCandidateLoads.clear();
    SplatFormLoadNodes.clear();
    // Field kill switch (hashed into the code-cache config id).
    static const bool DisableSplatFusion = getenv("FEX_NOSPLATFUSION") != nullptr;
    if (!DisableSplatFusion)
    for (auto [CandNode, CandIROp] : IRView->GetCode(BlockNode)) {
      switch (CandIROp->Op) {
      case IR::OP_VFMLASCALARINSERT:
      case IR::OP_VFMLSSCALARINSERT:
      case IR::OP_VFNMLASCALARINSERT:
      case IR::OP_VFNMLSSCALARINSERT: {
        auto FOp = CandIROp->C<IR::IROp_VFMLAScalarInsert>();
        if (FOp->Header.ElementSize != IR::OpSize::i64Bit) {
          break;
        }
        for (auto Arg : {FOp->Vector1, FOp->Vector2, FOp->Addend}) {
          if (Arg.IsImmediate() || Arg == FOp->Upper) {
            continue;
          }
          auto DefNode = IRView->GetNode(Arg);
          auto DefHdr = IRView->GetOp<IR::IROp_Header>(Arg);
          if (DefHdr->Op == IR::OP_LOADMEM && DefHdr->Size == IR::OpSize::i64Bit &&
              DefHdr->C<IR::IROp_LoadMem>()->Class == IR::RegClass::FPR && DefNode->GetUses() == 1) {
            SplatCandidateLoads.push_back(Arg.ID().Value);
          }
        }
        break;
      }
      default: break;
      }
    }

    PPC64_OPSIZE_RECORD(OpSizeProfileEnabled, OpSizeProfile::BUCKET_ENTRYPOINT_PROLOGUE, GetOffset() - BlockPrologueStart, Entry);

    // Emit all ops in this block
    for (auto [CodeNode, IROp] : IRView->GetCode(BlockNode)) {
      uint16_t Op = static_cast<uint16_t>(IROp->Op);

      // AES mask-cache: only the AES-family handlers keep the vs12-parked
      // byte-reverse mask alive (see EmitAESLoadMask). Any other op may
      // clobber VTMP3_VSX or emit a host call, so the park dies here. The
      // AES handlers' own Op_Unhandled bail paths invalidate explicitly.
      switch (IROp->Op) {
      case IR::OP_VAESENC:
      case IR::OP_VAESENCLAST:
      case IR::OP_VAESDEC:
      case IR::OP_VAESDECLAST:
      case IR::OP_VAESIMC: break;
      default: InvalidateAESCache(); break;
      }

      // Op-size profiler: the emitter cursor is the only ground truth for how
      // much host code a handler produced. Sampling it immediately either side
      // of the handler call is exact for this backend because PPC64 emits
      // straight into the block's buffer window with no staging, no reordering
      // and no post-hoc insertion — every byte a handler writes moves Offset,
      // and nothing else moves Offset between these two reads. (Backpatching
      // via Bind()/PatchPending rewrites bytes in place without advancing the
      // cursor, so a forward branch resolved by a later op is still charged to
      // the op that emitted it, which is what we want.)
      [[maybe_unused]] const size_t OpStart = GetOffset();

      // Any helper call this op emits saves only the dynamic VRs live across
      // it (DynVRSpillMask contract, PPC64Emitter.h). Reset right after the
      // handler: everything emitted outside a per-op context (block-link
      // thunks, deferred stubs at the CompileCode tail) must stay
      // conservative.
      if (!DynVRLiveIn.empty()) {
        DynVRSpillMask = DynVRLiveIn[IRView->GetID(CodeNode).Value];
      }
      if (Op <= static_cast<uint16_t>(IR::IROps::OP_LAST)) {
        (this->*OpHandlers[Op])(IROp, CodeNode);
      } else {
        Op_Unhandled(IROp, CodeNode);
      }
      DynVRSpillMask = ~0u;

      // XER->CR1 projection cache lifecycle (see ProjectXERToCR1): cleared
      // AFTER the handler — an op may project then write XER within one
      // handler (CondAdd/CondSubNZCV), so a pre-dispatch clear would leave a
      // stale projection visible to an allowlisted successor. The allowlist
      // is ops verified to write neither XER nor any CR field: the NZCVSelect
      // family (MapNZCVCC writes CR3 composites and CR1 only via the
      // projection itself), plain register moves, and constants.
      switch (IROp->Op) {
      case IR::OP_NZCVSELECT:
      case IR::OP_NZCVSELECTV:
      case IR::OP_NZCVSELECTINCREMENT:
      case IR::OP_STOREREGISTER:
      case IR::OP_LOADREGISTER:
      case IR::OP_CONSTANT:
      case IR::OP_INLINECONSTANT: break;
      default: XERProjectionValid = false; break;
      }

      // Last-constant cache lifecycle (see LastConstantCache in JITClass.h).
      // Set by materialized constants; survives only across ops verified to
      // write no dynamic GPR (FPR-class loads and the scalar-FP inserts —
      // their GPR usage is TMP1-4/r0 only, never RA registers); everything
      // else invalidates. Reset at block entry alongside the AES cache.
      switch (IROp->Op) {
      case IR::OP_CONSTANT: {
        // Field kill switch (hashed into the code-cache config id).
        static const bool DisableConstCache = getenv("FEX_NOCONSTCACHE") != nullptr;
        auto COp = IROp->C<IR::IROp_Constant>();
        const auto PR = IR::PhysicalRegister(CodeNode);
        if (!DisableConstCache && COp->PatchSite == 0 && PR.AsRegClass() == IR::RegClass::GPR) {
          LastConstantCache = {static_cast<uint64_t>(COp->Constant), PR.Reg, true};
        } else {
          LastConstantCache.Valid = false;
        }
        break;
      }
      case IR::OP_LOADMEM:
      case IR::OP_LOADMEMTSO:
        // FPR-class loads leave dynamic GPRs untouched; GPR-class loads
        // write an RA register and must invalidate.
        if (IROp->C<IR::IROp_LoadMem>()->Class != IR::RegClass::FPR) {
          LastConstantCache.Valid = false;
        }
        break;
      case IR::OP_VFADDSCALARINSERT:
      case IR::OP_VFSUBSCALARINSERT:
      case IR::OP_VFMULSCALARINSERT:
      case IR::OP_VFDIVSCALARINSERT:
      case IR::OP_VFMINSCALARINSERT:
      case IR::OP_VFMAXSCALARINSERT:
      case IR::OP_VFMLASCALARINSERT:
      case IR::OP_VFMLSSCALARINSERT:
      case IR::OP_VFNMLASCALARINSERT:
      case IR::OP_VFNMLSSCALARINSERT:
      case IR::OP_LOADNAMEDVECTORCONSTANT: break;
      default: LastConstantCache.Valid = false; break;
      }

      PPC64_OPSIZE_RECORD(OpSizeProfileEnabled,
                          Op <= static_cast<uint16_t>(IR::IROps::OP_LAST) ? static_cast<size_t>(Op) :
                                                                            static_cast<size_t>(OpSizeProfile::BUCKET_UNKNOWN_OP),
                          GetOffset() - OpStart, Entry);
    }
  }

  // -------------------------------------------------------------------------
  // Block-link jump thunks (one per linkable constant-jump exit)
  // -------------------------------------------------------------------------
  // Layout, offsets from ThunkStart (8-byte aligned):
  //   +0x00  b +0x14                ThunkPatchSite. Unlinked -> LinkPath.
  //                                 Linked out-of-range -> bcl 20,31,$+4.
  //   +0x04  mflr TMP1              (runs only when patched) TMP1 = ThunkStart+4
  //   +0x08  ld   TMP2, 0x2C(TMP1)  TMP2 = record.HostCode (at ThunkStart+0x30)
  //   +0x0c  mtctr TMP2
  //   +0x10  bctr
  //   +0x14  LinkPath: bcl 20,31,$+4     LR = ThunkStart+0x18 (no link-stack push)
  //   +0x18  mflr TMP2              TMP2 = ThunkStart+0x18
  //   +0x1c  addi TMP2, TMP2, 0x18  TMP2 = r4 = &record (linker stub argument)
  //   +0x20  ld   TMP1, 32(TMP2)    TMP1 = record.StubAddr — dispatcher stub
  //                                 addr cached in the record so no per-thread
  //                                 CpuStateFrame slot is needed
  //   +0x24  mtctr TMP1
  //   +0x28  bctr
  //   +0x2c  nop                    pad so the record is 8-byte aligned
  //   +0x30  PPC64BlockLinkRecord   (5 x dc64; HostCode field atomically
  //                                 rewritten by the linker; StubAddr is the
  //                                 dispatcher stub's fixed address, written
  //                                 once at emit time)
  //
  // Register discipline: only TMP1/TMP2 (r3/r4, non-SRA scratch) and LR are
  // touched. LR clobbering on the linked leg matches the established hot-path
  // precedent (EmitStoreBlockBeginToInlineHeader runs bcl/mflr at every
  // dispatcher-reachable block entry). r0 is NOT touched — the exit site
  // re-zeroed it above its patch site, and the target block relies on it.
  // The LinkPath leg runs after the exit's SpillStaticRegs, mirroring the
  // classic miss leg's state at the ExitFunctionLinker stub boundary.
  //
  // Emitted BEFORE Align16B/CodeSize capture so the thunk bytes are included
  // in CodeData.Size and in the icache flush below.
  const uint64_t StubAddr = CTX->Dispatcher->GetExitFunctionLinkerWithRecordAddress();
  for (auto& Thunk : PendingJumpThunks) {
    static_assert(offsetof(PPC64BlockLinkRecord, StubAddr) <= 32764 &&
                    (offsetof(PPC64BlockLinkRecord, StubAddr) & 3) == 0,
                  "thunk's d-form ld must reach the record's StubAddr field");
    // 8-align the thunk start; SetBuffer lands on a 16-byte boundary so
    // buffer offsets equal address alignment. The record at +0x30 inherits
    // 8-byte alignment for the linker's atomic u64 HostCode store.
    while (GetOffset() % 8) {
      nop();
    }
    const uint64_t ThunkStart = GetCursorAddress<uint64_t>();
    b(0x14);                                                        // +0x00
    mflr(TMP1);                                                     // +0x04
    ld(TMP2, static_cast<int16_t>(PPC64LinkRecordFromThunkStart - 0x4), TMP1); // +0x08
    mtctr(TMP2);                                                    // +0x0c
    bctr();                                                         // +0x10
    Bind(&Thunk.LinkPath);                                          // +0x14
    bcl(20, 31, 4);
    mflr(TMP2);                                                     // +0x18
    addi(TMP2, TMP2, static_cast<int16_t>(PPC64LinkRecordFromThunkStart - 0x18)); // +0x1c
    // TMP2 now holds &record. Tail-branch to the shared spill stub, which
    // runs SpillStaticRegs (TMP2 survives it via the f0 stash) and then
    // dispatches through record.StubAddr. The miss leg no longer spills
    // inline, so the spill happens exactly once, here, per compile unit.
    SharedSpillLinkUsed = true;
    b(&SharedSpillLinkLabel);                                       // +0x20
    nop();                                                          // +0x24
    nop();                                                          // +0x28
    nop();                                                          // +0x2c
    // Release-visible layout check (LOGMAN_* compiles to nothing in Release
    // and the failure mode of a drifted record offset is silent wrong-code:
    // the linked leg's ld would read instruction bytes as a host address).
    if (GetCursorAddress<uint64_t>() != ThunkStart + PPC64LinkRecordFromThunkStart) {
      ERROR_AND_DIE_FMT("PPC64 block-link thunk layout drifted: record lands at {:#x}, expected {:#x}",
                        GetCursorAddress<uint64_t>(), ThunkStart + PPC64LinkRecordFromThunkStart);
    }
    const uint64_t RecordAddress = GetCursorAddress<uint64_t>();
    // Stash the exact pre-link words for the delinkers. Read back from the
    // buffer rather than re-encoded: the caller word is the probe's first
    // instruction (already final — it is a direct emission, not a pending
    // branch), the thunk word is the b +0x14 emitted just above.
    const uint32_t OrigCallerWord = *reinterpret_cast<const uint32_t*>(Thunk.CallerAddress);
    const uint32_t OrigThunkWord = *reinterpret_cast<const uint32_t*>(ThunkStart);
    dc64(0);                                                          // HostCode
    dc64(Thunk.GuestRIP);                                             // GuestRIP
    dc64(static_cast<uint64_t>(Thunk.CallerAddress - RecordAddress)); // CallerOffset
    dc64(static_cast<uint64_t>(OrigCallerWord) |
         (static_cast<uint64_t>(OrigThunkWord) << 32));               // Orig{Caller,Thunk}Word
    dc64(StubAddr);                                                   // StubAddr — dispatcher
                                                                      // stub cached per record
  }

  // -------------------------------------------------------------------------
  // Shared miss-leg spill stubs (see SharedSpill*Label in JITClass.h). Cold
  // by construction — an exit reaches these only on an L1 miss / unlinked
  // path. Both live inside the code buffer, which is what the signal
  // delegator's IsAddressInCodeBuffer "SRA may be live" proxy requires of the
  // spill; the guest CR0/XER arrive here unclobbered (miss-leg compares use
  // cr7, the thunk leg touches only LR/TMP1/TMP2) so SpillStaticRegs's NZCV
  // pack still observes the block's final flags.
  // -------------------------------------------------------------------------
  if (SharedSpillExitUsed) {
    Bind(&SharedSpillExitLabel);
    SpillStaticRegs(TMP1);
    const int32_t exit_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, Pointers.ExitFunctionLinker));
    ld(TMP1, exit_off, STATE);
    mtctr(TMP1);
    bctr();
  }
  if (SharedSpillLinkUsed) {
    // Entered from a jump thunk's LinkPath leg with TMP2 = &record;
    // SpillStaticRegs preserves TMP2 (f0 stash) precisely for contracts like
    // this one, so the WithRecord dispatcher stub still receives r4 = &record.
    Bind(&SharedSpillLinkLabel);
    SpillStaticRegs(TMP1);
    ld(TMP1, static_cast<int16_t>(offsetof(PPC64BlockLinkRecord, StubAddr)), TMP2);
    mtctr(TMP1);
    bctr();
  }

  // -------------------------------------------------------------------------
  // Finalise
  // -------------------------------------------------------------------------
  Align16B();

  size_t CodeSize = GetOffset();
  // S3.7-C0: use the block-start snapshot, not the live LatestOffset. The
  // original recompute was numerically identical only because nothing else
  // mutates LatestOffset between :2250 (SetBuffer) and this line — but
  // that's an invariant nothing enforces, and reading the snapshot is
  // strictly cleaner. Same rationale as the InsertNamedThunkRelocation
  // change above.
  CodeData.BlockBegin = CB->Ptr + BlockBufferOffset;
  CodeData.Size       = CodeSize;

  // DebugData::HostCodeSize has never been populated on this port, and PPC64LE
  // is the only backend left in the tree, so the field was dead: every consumer
  // read a zero. That silently broke both of them - FEX_LIBRARYJITNAMING wrote
  // perf-map entries of length 0 (perf attributes no samples to a zero-length
  // symbol, so profiles degraded to raw addresses), and GDBJIT computed
  // block end == block start. Code only, excluding the tail: this is the range
  // that is actually executed.
  DebugData->HostCodeSize = CodeSize;

  // Flush the freshly-emitted instructions out of the D-cache and invalidate
  // the I-cache for this range. POWER8 has split, non-coherent I/D caches: the
  // store stream that emitted these instructions hits the D-cache, but the
  // fetch stream walks the I-cache. Without this flush, branching to the new
  // code can execute stale bytes (whatever the I-cache last fetched for the
  // same physical line) — most commonly observed when SMC re-compiles a guest
  // block at a code-buffer offset whose underlying page was previously
  // executed as different host code. ARM64's CompileCode does the equivalent
  // via ClearICache (FEXCore/Source/Interface/Core/JIT/JIT.cpp:1123).
  //
  // This was __builtin___clear_cache until 2026-08-13. On ppc64le that builtin
  // emits nothing with gcc and an empty libgcc stub call with clang, i.e. this
  // — the primary code-publication point of the whole backend — performed no
  // cache maintenance at all. See FEXCore/Utils/ArchHelpers/PPC64CacheFlush.h.
  FEXCore::ArchHelpers::PPC64::FlushICacheRange(reinterpret_cast<void*>(CodeData.BlockBegin), CodeSize);

  CodeBuffers.LatestOffset += CodeSize;

  // Write code tail. Layout produced here:
  //   [BlockBegin ..]                    header, code (Align16B'd), CodeSize bytes
  //   [BlockBegin + CodeSize]            JITCodeTail (40 bytes; 4-byte aligned)
  //   [BlockBegin + CodeSize + sizeof]   vl64pair entries (variable length, 1/2/9/17 bytes each)
  //   [BlockBegin + CodeSize + sizeof + entries -> align to 16]
  //
  // Tail and entries are written via direct pointer arithmetic; the
  // emitter's cursor is not advanced (we finalise the compile here and
  // never GetCursorAddress again). CodeBuffers.LatestOffset is bumped for
  // both regions PLUS a 16-byte alignment pad — vl64pair records are 1/2/9/17
  // bytes each, so their sum is not instruction-aligned; the next compile's
  // SetBuffer must land on a 16-byte boundary or its Emit32 writes are
  // misaligned and every emitted instruction reads back as garbage.
  auto* Tail = reinterpret_cast<CPUBackend::JITCodeTail*>(
    GetCursorAddress<uint8_t*>());
  // Zero the whole struct before assigning fields. This is a raw cast over
  // whatever the code buffer previously held, not a fresh aggregate, and
  // JITCodeTail carries a `uint8_t _Pad[3]` that no assignment below touches.
  // Leaving it as stale buffer bytes makes CodeCache::Validate compare
  // nondeterministic data: the validation context reuses a single code buffer
  // across Validate calls (its reset clears the offset, not the memory) while
  // the cache side is always a fresh zero-filled mapping, so from the second
  // call onward the reference side carries garbage where the cache has zeros.
  // ARM64 gets this for free — it builds the tail as a designated-initialiser
  // aggregate, which value-initialises _Pad.
  ::memset(Tail, 0, sizeof(*Tail));
  Tail->RIP       = Entry;
  Tail->GuestSize = GuestSize;
  Tail->NumberOfRIPEntries = static_cast<uint32_t>(DebugData->GuestOpcodes.size());
  Tail->OffsetToRIPEntries = sizeof(CPUBackend::JITCodeTail);
  Tail->SpinLockFutex      = 0;
  Tail->SingleInst         = SingleInst;

  // S3.7-C3: RELOC_GUEST_RIP_LITERAL for Tail->RIP so cache save/load
  // rewrites it across sessions with different ASLR. Runtime reads the plain
  // uint64_t written above; the relocation only kicks in when Relocations
  // are retained (IsGeneratingCache || EnableCodeCacheValidation) and applied
  // via ApplyCodeRelocations.
  //
  // Offset arithmetic: BlockBufferOffset (block start in whole buffer) plus
  // CodeSize (bytes emitted before the tail — Align16B has already run at
  // :2501, and CodeSize was captured at :2503 before this point; nothing else
  // emits between there and here) plus offsetof(JITCodeTail, RIP). Do NOT
  // use CodeBuffers.LatestOffset — it is bumped at :2526 and would be off by
  // CodeSize. Do NOT port PlaceNamedSymbolLiteral: nothing in emitted code
  // reads Tail->RIP (only C++ does), so there is no literal-pool label.
  //
  // Gated on ExitRIPFixedWidth (the same predicate the RIP-move sites use):
  // the comment above already says this record only "kicks in" when
  // relocations are retained, i.e. when code caching is on. With it off the
  // push was pure overhead -- a Relocation appended to a vector on every
  // single compiled block, for a consumer that does not exist -- and the
  // vector is discarded unread at the end of CompileCode.
  if (ExitRIPFixedWidth) {
    Relocation Reloc {};
    Reloc.GuestRIP.Header = {
      .Offset = BlockBufferOffset + static_cast<uint64_t>(CodeSize) + offsetof(CPUBackend::JITCodeTail, RIP),
      .Type   = FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL,
    };
    Reloc.GuestRIP.GuestRIP      = Entry;
    Reloc.GuestRIP.RegisterIndex = 0;   // unused for literals
    Relocations.emplace_back(Reloc);
  }

  auto* EntryLoc = reinterpret_cast<uint8_t*>(Tail) + sizeof(CPUBackend::JITCodeTail);
  auto* EntryBase = EntryLoc;
  uintptr_t PrevPCOffset  = 0;
  uintptr_t PrevRIPOffset = 0;
  for (const auto& GuestOpcode : DebugData->GuestOpcodes) {
    LOGMAN_THROW_A_FMT(static_cast<uintptr_t>(GuestOpcode.HostEntryOffset) >= PrevPCOffset,
                       "GuestOpcodes must be in ascending host order for vl64pair delta walk");
    const uint64_t HostDelta  = static_cast<uintptr_t>(GuestOpcode.HostEntryOffset) - PrevPCOffset;
    const uint64_t GuestDelta = static_cast<uintptr_t>(GuestOpcode.GuestEntryOffset) - PrevRIPOffset;
    EntryLoc += FEXCore::Utils::vl64pair::Encode(EntryLoc, HostDelta, GuestDelta);
    PrevPCOffset  = static_cast<uintptr_t>(GuestOpcode.HostEntryOffset);
    PrevRIPOffset = static_cast<uintptr_t>(GuestOpcode.GuestEntryOffset);
  }
  const size_t EntriesSize = static_cast<size_t>(EntryLoc - EntryBase);
  const size_t TailAndEntries = sizeof(CPUBackend::JITCodeTail) + EntriesSize;
  // Round up to 16 bytes so the next block starts on a 16-byte boundary,
  // matching Align16B() at the end of the code region above.
  const size_t TailAndEntriesAligned = (TailAndEntries + 15) & ~size_t{15};
  // Zero the 0-15 byte alignment pad. Nothing else writes it, yet
  // LatestOffset advances past it below, so it is part of the block's byte
  // range as far as CodeCache::Validate is concerned. Same reasoning as the
  // struct memset above; ARM64's Align() memsets its equivalent gap.
  ::memset(reinterpret_cast<uint8_t*>(Tail) + TailAndEntries, 0,
           TailAndEntriesAligned - TailAndEntries);

  // Total block span from BlockBegin including tail + entries + padding. The
  // range check in Core.cpp:RestoreRIPFromHostPC uses this to gate the walk.
  Tail->Size = CodeSize + TailAndEntriesAligned;
  CodeBuffers.LatestOffset += TailAndEntriesAligned;

  // Backpatch the JITCodeHeader reserved at BlockBegin. The tail was just
  // written at BlockBegin + CodeSize (Align16B has already run, so CodeSize
  // is the aligned pre-tail total). Cast is safe: the code buffer is
  // capacity-checked against BlockHeadroom above so no compile can exceed
  // 4 GiB.
  CodeHeader->OffsetToBlockTail = static_cast<uint32_t>(CodeSize);

  // Op-size profiler: charge the out-of-band tail region (JITCodeTail plus the
  // vl64pair RIP entries plus the 16-byte alignment pad) to its own bucket —
  // it is written by pointer arithmetic, never through the emitter cursor, so
  // no per-op delta can see it. Then record the whole-CompileCode span, which
  // is exactly what BlockHeadroom had to cover, and let the profiler decide
  // whether to rewrite the dump.
  PPC64_OPSIZE_RECORD(OpSizeProfileEnabled, OpSizeProfile::BUCKET_TAIL_AND_RIP_ENTRIES, TailAndEntriesAligned, Entry);
  PPC64_OPSIZE_RECORD_BLOCK(OpSizeProfileEnabled, Entry, IRView->GetSSACount(), CodeSize + TailAndEntriesAligned);

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
