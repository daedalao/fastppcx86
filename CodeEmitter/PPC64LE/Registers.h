// SPDX-License-Identifier: MIT
// PPC64LE register definitions for FEX JIT backend
#pragma once
#include <cstdint>

namespace PPC64Emitter {

// General-purpose registers r0-r31
struct Reg {
  uint32_t Idx() const { return idx; }
  uint32_t idx;

  bool operator==(Reg o) const { return idx == o.idx; }
  bool operator!=(Reg o) const { return idx != o.idx; }
};

// Typed wrappers so callers can express r0 vs v0 distinctly
struct GPR  : Reg {};
struct FPR  : Reg {};  // FPR0-FPR31 (also VSR0-VSR31 low 64 bits)
struct VR   : Reg {};  // VMX v0-v31 (VSR32-VSR63)

// Condition register fields CR0-CR7
struct CRField { uint32_t idx; };

// Condition register bits
enum class CRBit : uint32_t {
  LT = 0,  // less than (relative to CR field base)
  GT = 1,  // greater than
  EQ = 2,  // equal
  SO = 3,  // summary overflow
};

static constexpr GPR r(uint32_t n) { return GPR{{n}}; }
static constexpr FPR f(uint32_t n) { return FPR{{n}}; }
static constexpr VR  v(uint32_t n) { return VR {{n}}; }
static constexpr CRField cr(uint32_t n) { return CRField{n}; }

// Named GPRs
namespace GPRegs {
  static constexpr GPR r0  = r(0);
  static constexpr GPR r1  = r(1);   // stack pointer
  static constexpr GPR r2  = r(2);   // TOC pointer (preserve!)
  static constexpr GPR r3  = r(3);   // arg/return, TMP1
  static constexpr GPR r4  = r(4);   // arg, TMP2
  static constexpr GPR r5  = r(5);   // arg, TMP3
  static constexpr GPR r6  = r(6);   // arg, TMP4
  static constexpr GPR r7  = r(7);
  static constexpr GPR r8  = r(8);
  static constexpr GPR r9  = r(9);
  static constexpr GPR r10 = r(10);
  static constexpr GPR r11 = r(11);
  static constexpr GPR r12 = r(12);
  static constexpr GPR r13 = r(13);  // thread pointer (preserve!)
  static constexpr GPR r14 = r(14);
  static constexpr GPR r15 = r(15);
  static constexpr GPR r16 = r(16);
  static constexpr GPR r17 = r(17);
  static constexpr GPR r18 = r(18);
  static constexpr GPR r19 = r(19);
  static constexpr GPR r20 = r(20);
  static constexpr GPR r21 = r(21);
  static constexpr GPR r22 = r(22);
  static constexpr GPR r23 = r(23);
  static constexpr GPR r24 = r(24);
  static constexpr GPR r25 = r(25);
  static constexpr GPR r26 = r(26);
  static constexpr GPR r27 = r(27);  // STATE (CpuStateFrame*)
  static constexpr GPR r28 = r(28);  // REG_PF
  static constexpr GPR r29 = r(29);  // REG_AF
  static constexpr GPR r30 = r(30);  // RA pool
  static constexpr GPR r31 = r(31);  // RA pool
}

// Floating-point / vector register names
namespace FPRegs {
  static constexpr FPR f0  = f(0);
  static constexpr FPR f1  = f(1);
  // VTMP registers
  static constexpr FPR f2  = f(2);
  static constexpr FPR f3  = f(3);
}

namespace VRegs {
  // v0-v15 used as SRAFPR (x86 XMM0-XMM15)
  static constexpr VR v0  = v(0);
  static constexpr VR v1  = v(1);
  static constexpr VR v2  = v(2);
  static constexpr VR v3  = v(3);
  static constexpr VR v4  = v(4);
  static constexpr VR v5  = v(5);
  static constexpr VR v6  = v(6);
  static constexpr VR v7  = v(7);
  static constexpr VR v8  = v(8);
  static constexpr VR v9  = v(9);
  static constexpr VR v10 = v(10);
  static constexpr VR v11 = v(11);
  static constexpr VR v12 = v(12);
  static constexpr VR v13 = v(13);
  static constexpr VR v14 = v(14);
  static constexpr VR v15 = v(15);
  // v16-v29 used as RAFPR (dynamic FPR allocation)
  static constexpr VR v16 = v(16);
  static constexpr VR v17 = v(17);
  static constexpr VR v18 = v(18);
  static constexpr VR v19 = v(19);
  static constexpr VR v20 = v(20);
  static constexpr VR v21 = v(21);
  static constexpr VR v22 = v(22);
  static constexpr VR v23 = v(23);
  static constexpr VR v24 = v(24);
  static constexpr VR v25 = v(25);
  static constexpr VR v26 = v(26);
  static constexpr VR v27 = v(27);
  static constexpr VR v28 = v(28);
  static constexpr VR v29 = v(29);
  // v30, v31 = VTMP vector temporaries
  static constexpr VR v30 = v(30);
  static constexpr VR v31 = v(31);
}

} // namespace PPC64Emitter
