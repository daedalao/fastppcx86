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

// Third vector temporary, taken from the FPR-aliased half of the VSX file
// (vs0-vs31) instead of the VMX pool, so it costs the register allocator
// nothing. vs12 == f12, which this backend never names (only f0, f1, f2, f13
// and f16 appear anywhere in the JIT).
//
// TWO RULES, both different from VTMP1/VTMP2:
//
//  1. VSX-form instructions ONLY (xx*, xv*, lxv, stxv). VMX-form ops - vperm,
//     vsel, vcmp*, vmladduhm, lvx/stvx - have no bit to encode vs0-vs31 and
//     physically cannot address it. This is enforced by type: the VSXR
//     overloads exist only for VSX-form ops, so a wrong use fails to compile
//     rather than silently encoding the wrong register.
//
//  2. NOT live across a host call. f12 is volatile under ELFv2 §2.2, unlike
//     v30/v31 which are non-volatile and therefore survive calls. Signals are
//     fine either way - delivery goes through the kernel, which saves and
//     restores the whole register file, and resume is via sigreturn.
constexpr auto VTMP3_VSX = VSXR{12};

// Pinned all-zeroes vector, from the same RA-free FPR-aliased half of the VSX
// file as VTMP3_VSX. vs14 == f14, which the backend never names otherwise.
// The dispatcher zeroes it once, right after PushCalleeSavedRegisters (which
// already saves/restores f14 as part of the f14-f31 callee-saved block), and
// it stays zero for the life of the dispatcher frame:
//
//  * f14 is NON-volatile under ELFv2 §2.2, so every host C++ call the JIT or
//    dispatcher makes preserves it by ABI - no re-materialisation needed.
//  * Signal delivery/resume goes through the kernel, which saves and restores
//    the whole register file.
//  * Nothing in the backend may ever WRITE it (it is not a temp). VSX-form
//    reads only, same type-enforcement as VTMP3_VSX rule 1.
//
// Use it wherever a lowering needs a known-zero vector operand instead of
// burning an xxlxor + a vector temp per op (the scalar-load zero-merge in
// LoadFPRSized was ~one xxlxor per guest movss/movsd before this existed).
constexpr auto VZERO_VSX = VSXR{14};

// -------------------------------------------------------------------------
// ELFv2 volatility boundaries, plus the compile-time checks that keep each
// mode's "which pool registers survive a host call" answer honest.
//
// PPC64LE ELFv2 §2.2: r0-r13 and v0-v19 are volatile (caller-saved); r14-r31
// and v20-v31 are non-volatile (callee-saved). CALLER_GPR_MASK /
// CALLER_FPR_MASK below encode the same fact for the mask-driven paths.
//
// These predicates exist because a register pool edit that pulls a volatile
// register into RA or RAFPR turns every host call that does not save it into
// a silent miscompiler. Nothing in the backend would notice at runtime; the
// symptom is rare, non-deterministic wrong results. Fail the build instead.
// -------------------------------------------------------------------------
namespace RegVolatility {
  constexpr uint32_t kFirstNonVolatileGPR = 14;  // r14-r31 callee-saved
  constexpr uint32_t kFirstNonVolatileVR  = 20;  // v20-v31 callee-saved

  // Every element of a GPR pool is callee-saved.
  template<size_t N>
  constexpr bool AllGPRsNonVolatile(const std::array<GPR, N>& Pool) {
    for (const auto& R : Pool) {
      if (R.idx < kFirstNonVolatileGPR) { return false; }
    }
    return true;
  }

  template<size_t N>
  constexpr bool ContainsVR(const std::array<VR, N>& Set, uint32_t Idx) {
    for (const auto& R : Set) {
      if (R.idx == Idx) { return true; }
    }
    return false;
  }

  // Every pool element NOT named in the declared volatile list is callee-saved
  // — i.e. the list does not under-report.
  template<size_t N, size_t M>
  constexpr bool UnlistedVRsAreNonVolatile(const std::array<VR, N>& Pool,
                                           const std::array<VR, M>& Volatile) {
    for (const auto& R : Pool) {
      if (!ContainsVR(Volatile, R.idx) && R.idx < kFirstNonVolatileVR) { return false; }
    }
    return true;
  }

  // The declared volatile list is EXACTLY the pool's volatile elements, in
  // pool order — i.e. it neither under- nor over-reports. This is what stops
  // the two lists drifting apart under a future pool edit.
  template<size_t N, size_t M>
  constexpr bool VolatileListIsExact(const std::array<VR, N>& Pool,
                                     const std::array<VR, M>& Volatile) {
    size_t i = 0;
    for (const auto& R : Pool) {
      if (R.idx >= kFirstNonVolatileVR) { continue; }
      if (i >= M || Volatile[i].idx != R.idx) { return false; }
      ++i;
    }
    return i == M;
  }
}

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

  // The subset of RAFPR that ELFv2 does NOT preserve across a call. Any host
  // call that does not save these destroys the JIT-internal vector SSA values
  // living in them — and the register allocator hands out the lowest free
  // index first (RegisterAllocationPass.cpp:479), so RAFPR[0] = v16 is the
  // FIRST vector value allocated in any block. Drive every such save/restore
  // loop off THIS array so there is exactly one list.
  constexpr std::array<VR, 4> RAFPRVolatile = {
    VR{16}, VR{17}, VR{18}, VR{19},
  };

  // There is deliberately NO RAVolatile. RA is r24, r25, r26, r30, r31 — all
  // >= r14, hence all callee-saved — so the volatile GPR subset is empty in
  // this mode (and in x32). Asserted below rather than declared as an empty
  // array that every callsite would have to iterate zero times.
  static_assert(RegVolatility::AllGPRsNonVolatile(RA),
                "x64 RA contains an ELFv2-volatile GPR. It would be destroyed across any "
                "host call that saves only static registers (DEF_OP(Syscall)). Move it "
                "back above r14, or add an RAVolatile array plus save/restore loops.");
  static_assert(RegVolatility::UnlistedVRsAreNonVolatile(RAFPR, RAFPRVolatile),
                "x64 RAFPR contains an ELFv2-volatile vector register that RAFPRVolatile "
                "does not list. DEF_OP(Syscall) would not save it.");
  static_assert(RegVolatility::VolatileListIsExact(RAFPR, RAFPRVolatile),
                "x64 RAFPRVolatile has drifted from RAFPR. It must be exactly the RAFPR "
                "entries with index < 20, in pool order.");

  // PushDynamicRegs/PopDynamicRegs spill-frame layout (ELFv2, x64 guest).
  //
  // ELFv2 requires the CALLER to reserve 32 bytes of linkage area + 64 bytes
  // of parameter save area = 96 bytes at the BOTTOM of any frame from which
  // it issues a bctrl. A gcc-emitted callee writes its saved LR at
  // [caller_r1+16] unconditionally, and any callee that spills its incoming
  // argument registers writes [caller_r1+32 .. caller_r1+96) without a frame
  // of its own -- verified against gcc 14.2 output.
  //
  // Was 32 bytes. That put the FIRST dynamic FPR slot at [r1+80], which is
  // parameter slots 6 and 7 (the r9/r10 homes). A callee that spilled its
  // incoming args issued `std r9,80(r1); std r10,88(r1)`, and PopDynamicRegs'
  // `lvx v16, [r1+80]` then loaded {r9_value, r10_value} into RAFPR[0] --
  // a live guest vector SSA value. The next StoreMem of it wrote 16 bytes
  // (two adjacent qwords, 16-byte aligned) of the wrong pointer values into
  // guest memory, third qword intact. That is the +0/+8 clobbered / +16
  // intact fingerprint observed in the std::thread bring-up SIGSEGV.
  static constexpr size_t kDynLinkArea  = 96;
  static constexpr size_t kDynGPRStart  = kDynLinkArea;                               // 96
  static constexpr size_t kDynFPRStart  = (kDynGPRStart + RA.size() * 8 + 15u) & ~15u; // 144
  static constexpr size_t kDynRegSaveSize =
      (kDynFPRStart + RAFPR.size() * 16 + 15u) & ~15u;                                // 368
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

  // As x64::RAFPRVolatile — the ELFv2-volatile subset of the pool. x32's pool
  // starts at v8, so twelve of its twenty-two entries are volatile, and
  // RAFPR[0] = v8 is the first vector value the allocator hands out.
  constexpr std::array<VR, 12> RAFPRVolatile = {
    VR{8},  VR{9},  VR{10}, VR{11}, VR{12}, VR{13}, VR{14}, VR{15},
    VR{16}, VR{17}, VR{18}, VR{19},
  };

  // No RAVolatile here either — x32 RA is r16-r26, r30, r31, all callee-saved.
  static_assert(RegVolatility::AllGPRsNonVolatile(RA),
                "x32 RA contains an ELFv2-volatile GPR. It would be destroyed across any "
                "host call that saves only static registers (DEF_OP(Syscall)). Move it "
                "back above r14, or add an RAVolatile array plus save/restore loops.");
  static_assert(RegVolatility::UnlistedVRsAreNonVolatile(RAFPR, RAFPRVolatile),
                "x32 RAFPR contains an ELFv2-volatile vector register that RAFPRVolatile "
                "does not list. DEF_OP(Syscall) would not save it.");
  static_assert(RegVolatility::VolatileListIsExact(RAFPR, RAFPRVolatile),
                "x32 RAFPRVolatile has drifted from RAFPR. It must be exactly the RAFPR "
                "entries with index < 20, in pool order.");

  // ELFv2 96-byte reservation as x64 above. Same reasoning; the x32 numbers
  // work out to 208 for kDynFPRStart and 560 for kDynRegSaveSize.
  static constexpr size_t kDynLinkArea  = 96;
  static constexpr size_t kDynGPRStart  = kDynLinkArea;
  static constexpr size_t kDynFPRStart  = (kDynGPRStart + RA.size() * 8 + 15u) & ~15u; // 208
  static constexpr size_t kDynRegSaveSize =
      (kDynFPRStart + RAFPR.size() * 16 + 15u) & ~15u;                                // 560
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

  // Fixed-width 5-instruction / 20-byte materialisation of a 64-bit constant.
  // ONLY for relocation sites — see PPC64LE/Emitter.h::LoadImm64Fixed for the
  // full rationale. Must be on PPC64EmitterBase (not PPC64JITCore) because
  // CodeCache::ApplyCodeRelocations constructs a bare PPC64EmitterBase to
  // re-emit patched constants in place.
  void LoadConstantFixed(GPR rt, uint64_t Constant);

  // Which slice of the SRA a fill reloads.
  //
  // `SkipNonVolatileGPRs` and `NonVolatileGPRsOnly` are exact complements:
  // emitting both, in either order, is equivalent to `All`. That is the whole
  // point — DEF_OP(Syscall) emits the non-volatile half under a runtime
  // branch and the rest unconditionally, so the two halves must partition the
  // work with no overlap and no gap.
  //
  // PF/AF deliberately live in the `SkipNonVolatileGPRs` half even though
  // REG_PF/REG_AF (r28/r29) are ELFv2 callee-saved: they are 32-bit fields
  // filled with `lwz`, i.e. the fill is what guarantees their upper halves are
  // zero, and no caller may skip that. Same for the XMM (v0-v15, all volatile)
  // and NZCV (CR0/XER, both volatile) restores.
  enum class FillMode {
    All,                 // every SRA GPR, PF/AF, XMM0-15, NZCV
    SkipNonVolatileGPRs, // All minus the SRA GPRs ELFv2 preserves across a call
    NonVolatileGPRsOnly, // ONLY the SRA GPRs ELFv2 preserves across a call
  };

  // Fill/spill x86 SRA registers from/to the CpuStateFrame.
  // These are called on entry/exit from the JIT dispatcher.
  void SpillStaticRegs(GPR tmp);
  void FillStaticRegs(FillMode Mode = FillMode::All);

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
  // Emit-time selected: lxvx/stxvx (1 insn) when HostFeatures.SupportsISA30,
  // else lxvd2x/stxvd2x + xxpermdi (2 insns, ISA 2.06). CLOBBER CONTRACT
  // (superset across paths — callers must assume all of it): TMP1, TMP2, TMP3
  // (historical bounce contract, kept so callsites stay conservative), plus
  // VTMP2 (or VTMP1 when src==VTMP2) on the pre-3.0 store path. `ea` must not
  // be r0 (RA=0 encodes literal zero).
  void LoadUnalignedV128(VR dst, GPR ea);
  void StoreUnalignedV128(VR src, GPR ea);

  // Size-correct FPR memory ops (x86 movd/movq/movdqu semantics): for size <16
  // the load zero-extends the upper bits of dst, and the store writes only the
  // low `size` bytes to *ea. Sizes accepted: 1, 2, 4, 8, 16 (load also 10).
  // Same superset clobber contract as above: TMP1..TMP3, plus VTMP2 (or VTMP1
  // on aliasing) on the pre-3.0 scalar-load, scalar-store and V128 store
  // paths. Sizes 4/8 take a register-only path on both load and store and
  // clobber no TMP GPR at all, but callers must keep assuming the superset.
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
