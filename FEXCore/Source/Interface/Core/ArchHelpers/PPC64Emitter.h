// SPDX-License-Identifier: MIT
// PPC64LE (POWER8) FEX JIT emitter helper.
// Analogous to Arm64Emitter.h — provides register layout, spill/fill,
// and utility methods shared by both the JIT and the Dispatcher.
#pragma once

#include <PPC64LE/Emitter.h>
#include <PPC64LE/Registers.h>

#include <FEXCore/Config/Config.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace FEXCore::Context { class ContextImpl; }

namespace FEXCore::CPU {

using namespace PPC64Emitter;
using namespace PPC64Emitter::GPRegs;
using namespace PPC64Emitter::VRegs;

// -------------------------------------------------------------------------
// Pinned registers
// -------------------------------------------------------------------------

// Pointer to CpuStateFrame (equivalent of ARM64 x28)
constexpr auto STATE     = r27;

// Pinned to allow fast emulation of x86 PF/AF flags
constexpr auto REG_PF    = r28;
constexpr auto REG_AF    = r29;

// Scratch / temporaries (ABI argument registers — fine in JIT code)
constexpr auto TMP1 = r3;
constexpr auto TMP2 = r4;
constexpr auto TMP3 = r5;
constexpr auto TMP4 = r6;

// Vector temporaries
constexpr auto VTMP1 = VR{30};
constexpr auto VTMP2 = VR{31};

// -------------------------------------------------------------------------
// Register allocation tables (x86-64 mode)
// -------------------------------------------------------------------------
namespace x64 {
  // Static register allocation: 16 x86 GPRs + PF + AF = 18 host GPRs
  // Order matches ARM64 backend: RAX, RDX, RCX, RBX, RSP, RBP, RSI, RDI,
  //                                R8,  R9,  R10, R11, R12, R13, R14, R15, PF, AF
  constexpr std::array<GPR, 18> SRA = {
    r7,  r8,  r9,  r10, r11, r12, r14, r15,
    r16, r17, r18, r19, r20, r21, r22, r23,
    REG_PF, REG_AF,
  };

  // Dynamic (non-static) GPR allocation pool
  constexpr std::array<GPR, 5> RA = {
    r24, r25, r26, r30, r31,
  };

  constexpr unsigned RAPairs = 2;

  // SRA FPR: 16 x86 XMM registers mapped to VMX v0-v15
  constexpr std::array<VR, 16> SRAFPR = {
    VR{0},  VR{1},  VR{2},  VR{3},
    VR{4},  VR{5},  VR{6},  VR{7},
    VR{8},  VR{9},  VR{10}, VR{11},
    VR{12}, VR{13}, VR{14}, VR{15},
  };

  // Dynamic FPR pool: VMX v16-v29 (v30, v31 are VTMP1/VTMP2)
  constexpr std::array<VR, 14> RAFPR = {
    VR{16}, VR{17}, VR{18}, VR{19},
    VR{20}, VR{21}, VR{22}, VR{23},
    VR{24}, VR{25}, VR{26}, VR{27},
    VR{28}, VR{29},
  };

  // PushDynamicRegs/PopDynamicRegs spill-frame layout (ELFv2, x64 guest).
  // 32-byte link area at bottom, then GPRs, then 16-byte-aligned FPRs.
  static constexpr size_t kDynLinkArea  = 32;
  static constexpr size_t kDynGPRStart  = kDynLinkArea;                               // 32
  static constexpr size_t kDynFPRStart  = (kDynGPRStart + RA.size() * 8 + 15u) & ~15u; // 80
  static constexpr size_t kDynRegSaveSize =
      (kDynFPRStart + RAFPR.size() * 16 + 15u) & ~15u;                                // 304
}

// -------------------------------------------------------------------------
// x86-32 mode uses fewer GPRs
// -------------------------------------------------------------------------
namespace x32 {
  constexpr std::array<GPR, 10> SRA = {
    r7, r8, r9, r10, r11, r12, r14, r15, REG_PF, REG_AF,
  };
  constexpr std::array<GPR, 13> RA = {
    r16, r17, r18, r19, r20, r21, r22, r23, r24, r25, r26, r30, r31,
  };
  constexpr unsigned RAPairs = 6;
  constexpr std::array<VR, 8> SRAFPR = {
    VR{0}, VR{1}, VR{2}, VR{3}, VR{4}, VR{5}, VR{6}, VR{7},
  };
  constexpr std::array<VR, 22> RAFPR = {
    VR{8},  VR{9},  VR{10}, VR{11}, VR{12}, VR{13}, VR{14}, VR{15},
    VR{16}, VR{17}, VR{18}, VR{19}, VR{20}, VR{21}, VR{22}, VR{23},
    VR{24}, VR{25}, VR{26}, VR{27}, VR{28}, VR{29},
  };

  static constexpr size_t kDynLinkArea  = 32;
  static constexpr size_t kDynGPRStart  = kDynLinkArea;
  static constexpr size_t kDynFPRStart  = (kDynGPRStart + RA.size() * 8 + 15u) & ~15u; // 144
  static constexpr size_t kDynRegSaveSize =
      (kDynFPRStart + RAFPR.size() * 16 + 15u) & ~15u;                                // 496
}

// Caller-saved GPR mask: r3-r12 (bits 3..12 set)
static constexpr uint32_t CALLER_GPR_MASK =
    (1u << 3)  | (1u << 4)  | (1u << 5)  | (1u << 6)  |
    (1u << 7)  | (1u << 8)  | (1u << 9)  | (1u << 10) |
    (1u << 11) | (1u << 12);

// Caller-saved VMX mask: v0-v19 (per PPC64LE ELFv2 ABI)
static constexpr uint32_t CALLER_FPR_MASK = 0x000FFFFFu;  // bits 0..19

// -------------------------------------------------------------------------
// PPC64Emitter: shared utility class for JIT + Dispatcher
// -------------------------------------------------------------------------
class PPC64EmitterBase : public PPC64Emitter::Emitter {
public:
  explicit PPC64EmitterBase(FEXCore::Context::ContextImpl* ctx,
                            void* EmitPtr = nullptr, size_t Size = 0);

  // Materialise an arbitrary 64-bit constant into rt.
  void LoadConstant(GPR rt, uint64_t Constant);

  // Fill/spill x86 SRA registers from/to the CpuStateFrame.
  // These are called on entry/exit from the JIT dispatcher.
  void SpillStaticRegs(GPR tmp);
  void FillStaticRegs();

  // Push/pop all callee-saved registers per PPC64LE ELFv2 ABI.
  void PushCalleeSavedRegisters();
  void PopCalleeSavedRegisters();

  // Push/pop all dynamic (non-SRA) registers.
  size_t PushDynamicRegs(GPR tmp);
  void   PopDynamicRegs();

  // Spill/fill everything before/after a C ABI call (clobbers r3-r12, v0-v19).
  void SpillForABICall(GPR tmp, bool FPRs = true);
  void FillForABICall(bool FPRs = true);

  // Ensure code is aligned to 16-byte boundary (fill with nops).
  void Align16B();

  // Unaligned 128-bit vector load/store. lvx/stvx silently mask the low 4 bits
  // of the effective address, so x86 movdqu / movups can't use them directly.
  // We bounce through a 16-byte slot in the protected zone below r1 (ELFv2
  // §2.2.2.4 reserves 288 bytes there for leaf use).  Clobbers TMP1, TMP2, TMP3.
  void LoadUnalignedV128(VR dst, GPR ea);
  void StoreUnalignedV128(VR src, GPR ea);

  // Size-correct FPR memory ops (x86 movd/movq/movdqu semantics): for size <16
  // the load zero-extends the upper bits of dst, and the store writes only the
  // low `size` bytes to *ea. Sizes accepted: 1, 2, 4, 8, 16. Clobbers TMP1..TMP3.
  void LoadFPRSized(VR dst, GPR ea, uint32_t size);
  void StoreFPRSized(VR src, GPR ea, uint32_t size);

  // 32-bit guest support helpers.
  // MaybeClrUpper32: emit `rldicl reg, reg, 0, 32` (zero the high 32 bits of
  // `reg`) when the guest is 32-bit, and a nop otherwise.  Used for RIP and
  // for memory effective-address masking — the host computes 64-bit results
  // but i686 guests must wrap pointer arithmetic at the 32-bit boundary.
  void MaybeClrUpper32(GPR reg);

protected:
  FEXCore::Context::ContextImpl* EmitterCTX {};

  std::span<const GPR> StaticRegisters {};
  std::span<const GPR> GeneralRegisters {};
  std::span<const VR>  StaticFPRegisters {};
  std::span<const VR>  GeneralFPRegisters {};
  uint32_t PairRegisters {};
};

} // namespace FEXCore::CPU
