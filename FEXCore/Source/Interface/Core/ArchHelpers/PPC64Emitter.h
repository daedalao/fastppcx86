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
#include <cstdlib>
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
// nothing. vs12 == f12, which this backend never names (only f0, f1 and f2
// appear as FPRs anywhere in the JIT — see CodeEmitter Registers.h FPRegs).
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
//
// HAZARD, learned the hard way (Steam 32-bit manifest decryption, 2026-08-12):
// ELFv2 preserves only the FPR half (dw0) of vs14-vs31 across calls; the
// vector half is volatile, and a host callee's scalar `lfd f14` epilogue
// restore leaves dw1 UNDEFINED per the ISA (glibc alone has eight such
// sites for f14/f15). Consequences, binding on all backend code:
//   * VZERO_VSX guarantees ONLY dw0 == 0 after an arbitrary host call.
//     Consumers must not read its full 128 bits across one (xxpermdi
//     selecting B.dw0 is fine; a full-width xxlor copy is not).
//   * Do NOT pin any full-width vector constant in vs14-vs31. An AES
//     byte-reverse mask briefly lived in vs15 on this theory and produced
//     garbage AES for any guest code path that had made the wrong host call
//     first. Materialize such constants per-use (see EmitAESLoadMask:
//     vspltisb + lvsl@0 + vsububm, 4 instructions, no memory).
//   * The AVX-high bank below has the same exposure for YMM highs whenever
//     host calls occur without a SpillStaticRegs sync - audit before
//     enabling AVX by default.

// -------------------------------------------------------------------------
// AVX-high VSX bank: guest YMM_hi[i] pinned in vs(16+i) == f(16+i).
//
// Active ONLY when HostFeatures.SupportsAVX (default OFF on this tree).
// The AVX_128 frontend splits YMM into two 128-bit halves; the low half is
// SRA (v0-15) and the high half historically lived in State.avx_high[]
// context MEMORY — every VEX-encoded op paid a load/store round trip. The
// FPR-aliased low VSX bank is idle from vs16 up, and f16-f31 are ELFv2
// callee-saved, so the halves live in registers instead:
//
//  * In-register layout matches the VR convention exactly (dw0 = guest high
//    qword, dw1 = guest low qword) — moves between the bank and VRs are a
//    single full-VSX xxlor, and the memory image written by the spill path
//    below is byte-identical to a stvx of the same value.
//  * Host C calls preserve the bank by ABI (callee-saved), so
//    SpillForABICall needs nothing; only SpillStaticRegs/FillStaticRegs
//    sync bank <-> State.avx_high[] (gated on SupportsAVX) so context
//    memory is authoritative whenever the thread is outside JIT code.
//  * Mid-JIT signals: the host-side SpillSRA reads the bank straight out of
//    the mcontext (fp_regs dw0 + the VSX-dw1 area) — see
//    MContext_ppc64le.h. Because the bank is callee-saved this is valid
//    even for signals landing inside a host helper call.
//  * VSX-form instructions only (same rule as VTMP3_VSX/VZERO_VSX);
//    PushCalleeSavedRegisters already saves/restores f14-f31 on dispatcher
//    entry, protecting the host caller's values.
//
// Both guest modes bank SRAFPR.size() entries (16 in x64, 8 in x32).
constexpr uint32_t AVXHIGH_BANK_FIRST = 16;
constexpr VSXR AVXHighBankReg(size_t i) {
  return VSXR{static_cast<uint32_t>(AVXHIGH_BANK_FIRST + i)};
}

// A VMX register's name in the full 64-entry VSX file (VR n == vs(32+n)),
// for the VSX-form ops that move values between the banks.
constexpr VSXR AsVSX(VR v) {
  return VSXR{32u + v.idx};
}

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

// Value parked in CpuStateFrame::InSyscallInfo for the duration of a JIT
// host-call crossing whose tail wants the sentinel-guarded partial SRA GPR
// refill: DEF_OP(Syscall), DEF_OP(Thunk) (64-bit) and the FABI bridge stubs
// (GenerateABICall, 64-bit, FEX_NO_THUNK_PARTIAL_FILL=1 kill switch for the
// latter two).
//
//   bits 0..15  : the SpillSRA IgnoreMask. 0xFFFF = "all x64 SRA GPRs are
//                 already spilled to the frame". This is the only part any
//                 consumer outside the backend looks at (SignalDelegator.cpp
//                 and SyscallsSMCTracking.cpp both mask with 0xFFFF). SpillSRA
//                 tests bits by HOST register number, so 0xFFFF skips the SRA
//                 members numbered r7-r15 and re-spills r16-r23 from the
//                 ucontext — harmless, those are ELFv2 callee-saved and still
//                 hold the frame's values throughout the armed window.
//   bits 16..23 : deliberately ZERO. GdbServer.cpp passes the raw
//                 InSyscallInfo into SpillSRA's `uint32_t IgnoreMask` with no
//                 masking, and r16..r23 are SRA members — a sentinel bit in
//                 this window would silently suppress their re-spill. Bit 24
//                 is above every SRA register number (max r23) and therefore
//                 inert in that path.
//   bit  24     : the tripwire. ArchHelpers::Context::ContextBackup stores
//                 InSyscallInfo as a *uint16_t* (MContext_ppc64le.h), so this
//                 bit CANNOT survive a signal-delivery round trip: both
//                 HandleDispatcherGuestSignal branches stash the (truncated)
//                 value and zero the field, and RestoreThreadState reinstates
//                 it truncated to 0xFFFF. The dispatcher's CallbackPtr entry
//                 additionally zeroes the field outright before a host callee
//                 re-enters guest code. Any value read back with no bit above
//                 15 set therefore means "the guest state in the frame was
//                 republished by somebody while we were inside the host call"
//                 — the exact condition under which the callee-saved host
//                 copies of SRA r14+ are stale and a full refill is required.
static constexpr uint64_t kInSyscallSentinel = 0x0100'FFFFull;

// FABI-crossing variant: bit 25 instead of bit 24, identical low mask and
// identical uint16 death-by-truncation. The distinct bit lets the signal
// delegator DEFER async signals landing mid-FABI-crossing (F80 softfloat
// helpers never block, so deferral always drains) without deferring
// syscall crossings, where a thread may be parked in a blocking host
// syscall that needs immediate delivery. Bits 16..23 stay zero for the
// GdbServer raw-mask reason documented above; bit 25 is equally inert
// there (> r23).
static constexpr uint64_t kInFABISentinel = 0x0200'FFFFull;

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

  // -----------------------------------------------------------------------
  // XER.CA / XER.OV writes WITHOUT the serializing mtspr.
  //
  // mtspr XER is execution-serializing on POWER8 (the reason DEF_OP(CarryInvert)
  // grew its subfe/addic form), yet the flag machinery accumulated ~15
  // mfspr/modify/mtspr round-trips. These helpers generate the target bit with
  // arithmetic instead:
  //   CA = b   : addic(scratch, b, -1)      b=1: 1+(-1) carries; b=0: no carry
  //   CA = 1   : subfc(scratch, r0, r0)     0-0 = no borrow = CA 1 (PPC rule)
  //   CA = 0   : addic(scratch, b0, 0)      needs a known-zero register
  //   OV = b   : sldi 62 + addo(x, x, x)    2^62+2^62 overflows iff bit set
  //   OV = 0   : addo(scratch, b0, b0)      0+0 never overflows
  //   CA=OV=0  : addco(scratch, b0, b0)
  // None of these touch CR0, and each writes ONLY its named XER bit (addic:
  // CA; addo: OV — plus sticky SO when it sets OV, which every existing OE
  // user already does and nothing reads; see the ProjectXERToCR1 block
  // comment). OV32 is left stale — both XER->CR1 projection layouts read OV,
  // never OV32 (XEROVBitIndex).
  //
  // Register contract: `b` must be EXACTLY 0 or 1 (isolate with rldicl/rlwinm
  // first). `zero` must be a register currently holding 0 — pass r0 only from
  // JIT DEF_OP context where the r0=0 invariant holds; dispatcher-side callers
  // (FillStaticRegs) must not pass r0 (ExitFunctionLinker smuggles a pointer
  // through it) and instead use the from-bit forms, which read no zero reg.
  // `scratch` is clobbered; it may alias `b`.
  //
  // FEX_NOXERARITH (presence-enabled kill switch, hashed into the code-cache
  // config id) reverts every helper to the old mfspr/rlwimi/mtspr RMW shape.
  // -----------------------------------------------------------------------
  static bool XERArithDisabled() {
    static const bool Disabled = getenv("FEX_NOXERARITH") != nullptr;
    return Disabled;
  }

  // CA <- b (0/1). OV, CR0 preserved.
  void SetCAFromBit(GPR b, GPR scratch) {
    if (XERArithDisabled()) {
      mfspr(scratch, 1);
      rlwimi(scratch, b, 29, 2, 2);   // b LSB0 -> LSB29 (CA), other bits kept
      mtspr(1, scratch);
      return;
    }
    addic(scratch, b, -1);
  }

  // OV <- b (0/1). CA, CR0 preserved. Sets sticky SO when b=1 (harmless).
  void SetOVFromBit(GPR b, GPR scratch) {
    if (XERArithDisabled()) {
      mfspr(scratch, 1);
      rlwimi(scratch, b, 30, 1, 1);   // b LSB0 -> LSB30 (OV)
      mtspr(1, scratch);
      return;
    }
    sldi(scratch, b, 62);
    addo(scratch, scratch, scratch);
  }

  // CA <- 0 and OV <- 0 in one instruction. CR0 preserved.
  // `zero` must hold 0 (r0 from JIT context only — see contract above).
  void ZeroCAOV(GPR zero, GPR scratch) {
    if (XERArithDisabled()) {
      mfspr(scratch, 1);
      rlwinm(scratch, scratch, 0, 3, 0);  // wrap mask keeps 3..31,0: clears OV,CA
      mtspr(1, scratch);
      return;
    }
    addco(scratch, zero, zero);
  }

  // CA <- compile-time constant. OV, CR0 preserved.
  // `zero` must hold 0 (r0 from JIT context only).
  void SetCAConstant(bool CA, GPR zero, GPR scratch) {
    if (XERArithDisabled()) {
      mfspr(scratch, 1);
      if (CA) {
        oris(scratch, scratch, 0x2000);   // set LSB29
      } else {
        rlwinm(scratch, scratch, 0, 3, 1); // wrap mask keeps 3..31,0,1: clears CA
      }
      mtspr(1, scratch);
      return;
    }
    if (CA) {
      subfc(scratch, zero, zero);
    } else {
      addic(scratch, zero, 0);
    }
  }

  // OV <- compile-time constant. CA, CR0 preserved.
  // `zero` must hold 0 (r0 from JIT context only).
  void SetOVConstant(bool OV, GPR zero, GPR scratch) {
    if (XERArithDisabled()) {
      mfspr(scratch, 1);
      if (OV) {
        oris(scratch, scratch, 0x4000);   // set LSB30
      } else {
        rlwinm(scratch, scratch, 0, 2, 0); // wrap mask keeps 2..31,0: clears OV
      }
      mtspr(1, scratch);
      return;
    }
    if (OV) {
      LoadConstant(scratch, 1ull << 62);
      addo(scratch, scratch, scratch);
    } else {
      addo(scratch, zero, zero);
    }
  }

  // Push/pop all callee-saved registers per PPC64LE ELFv2 ABI.
  void PushCalleeSavedRegisters();
  void PopCalleeSavedRegisters();

  // Push/pop all dynamic (non-SRA) registers.
  size_t PushDynamicRegs(GPR tmp);
  void   PopDynamicRegs();

  // Which dynamic-pool FPRs Push/PopDynamicRegs (and the FABI callsite
  // caller-save helpers below) actually store, as a bitmask of RAFPR POOL
  // INDICES (bit i = RAFPR[i], NOT VR numbers). The effective saved set is
  // always additionally intersected with the ELFv2-volatile subset
  // (RAFPRVolatile, idx < 20) — callee-saved pool entries are never stored
  // regardless of this mask.
  //
  // Contract:
  //   * ~0u (default) = save every volatile pool entry. Anything that emits
  //     Push/Pop outside a per-IR-op context (dispatcher stubs, CompileCode
  //     tail thunks) runs under this default and stays conservative.
  //   * CompileCode sets it per IR op to the RA live-in set ∪ dest before
  //     dispatching the op handler and resets it to ~0u right after, so any
  //     SpillForABICall/FillForABICall pair emitted inside a handler saves
  //     only vector values that are actually live across the call.
  //   * GenerateABICall (FABI bridge stubs) emits under mask 0: the volatile
  //     dynamic VRs are CALLER-saved at the two FABI callsite emitters
  //     (JIT.cpp Op_Unhandled, X87Ops.cpp EmitFABICall) via the helpers
  //     below, because only the callsite knows the live set at emit time.
  //     Every new path that branches into an ABIPointers stub MUST emit the
  //     caller-save pair.
  //
  // Frame layout is deliberately unaffected — masked-out registers keep
  // their (unwritten) slots, so kDynFPRStart/kDynRegSaveSize arithmetic and
  // every consumer of those constants stay valid.
  uint32_t DynVRSpillMask = ~0u;

  // FABI-callsite caller-save pair: store/reload the DynVRSpillMask-selected
  // volatile dynamic VRs at [r1 + BaseOffset + k*16] (16-byte aligned slots,
  // one per SAVED register, densely packed). Clobbers TMP3. Worst case needs
  // BaseOffset + 12*16 bytes of frame (x32's full volatile set).
  void SaveDynVRsToFrame(int32_t BaseOffset);
  void RestoreDynVRsFromFrame(int32_t BaseOffset);

  // Spill/fill everything before/after a C ABI call (clobbers r3-r12, v0-v19).
  void SpillForABICall(GPR tmp, bool FPRs = true);
  void FillForABICall(bool FPRs = true);

  // Sentinel-guarded partial-refill pair for host-call crossings (see
  // kInSyscallSentinel above; DEF_OP(Syscall) carries the original inline
  // copy of this scheme interleaved with its RAX handling).
  //
  // ArmInSyscallSentinel: store the sentinel to Frame->InSyscallInfo. MUST be
  // emitted strictly AFTER the crossing's SRA spill completes (the mask's
  // bits claim "already spilled"; raising it earlier would let a signal
  // handler skip spilling registers whose frame copies are still stale) and
  // never from inside SpillForABICall itself (see the NB there). Clobbers
  // TMP1 only.
  //
  // FillForABICallChecked: PopDynamicRegs, then refill SRA — skipping the ten
  // ELFv2-callee-saved GPR loads (r14-r23) when the sentinel survived, i.e.
  // when provably nothing republished the frame during the call — then
  // restore r0=0 and disarm the sentinel. The two FillMode halves are exact
  // complements, so the sentinel-dead path is a full fill; XMM/PF/AF/NZCV
  // restores run unconditionally in both paths (v0-v15 are ELFv2-volatile and
  // the frame copy is also what signal delivery reads mid-call — never
  // elidable). 64-bit guests only: the 32-bit lwz zero-extension invariant
  // forbids partial GPR fills (asserted in FillStaticRegs). Clobbers TMP1 and
  // CR0 before the NZCV restore rebuilds CR0 from the frame.
  void ArmInSyscallSentinel(uint64_t Sentinel = kInSyscallSentinel);
  void FillForABICallChecked();

  // Ensure code is aligned to 16-byte boundary (fill with nops).
  void Align16B();

  // Unaligned 128-bit vector load/store. lvx/stvx silently mask the low 4 bits
  // of the effective address, so x86 movdqu / movups can't use them directly.
  // Emit-time selected: lxvx/stxvx (1 insn) when HostFeatures.SupportsISA30,
  // else lxvd2x/stxvd2x + xxpermdi (2 insns, ISA 2.06). CLOBBER CONTRACT
  // (superset across paths — callers must assume all of it): TMP1, TMP2, TMP3
  // (historical bounce contract, kept so callsites stay conservative), plus
  // VTMP3_VSX (vs12, RA-invisible low bank) on the pre-3.0 store path. No
  // VMX register (VTMP1/VTMP2 included) is clobbered on any path. `ea` must
  // not be r0 (RA=0 encodes literal zero).
  void LoadUnalignedV128(VR dst, GPR ea);
  void StoreUnalignedV128(VR src, GPR ea);

  // Size-correct FPR memory ops (x86 movd/movq/movdqu semantics): for size <16
  // the load zero-extends the upper bits of dst, and the store writes only the
  // low `size` bytes to *ea. Sizes accepted: 1, 2, 4, 8, 16 (load also 10).
  // Same superset clobber contract as above: TMP1..TMP3 plus VTMP3_VSX; no
  // VMX register is clobbered on any path (the pre-3.0 scalar/V128 store swap
  // goes through VTMP3_VSX, the pre-3.0 scalar load merges against VZERO_VSX).
  // Sizes 4/8 take a register-only path on both load and store and clobber no
  // TMP GPR at all, but callers must keep assuming the superset.
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
