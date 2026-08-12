// SPDX-License-Identifier: MIT
// PPC64LE emitter helper implementation.
#include "Interface/Core/ArchHelpers/PPC64Emitter.h"
#include "Interface/Context/Context.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Utils/LogManager.h>

#include <array>
#include <cstddef>

namespace FEXCore::CPU {

PPC64EmitterBase::PPC64EmitterBase(FEXCore::Context::ContextImpl* ctx,
                                   void* EmitPtr, size_t Size)
  : EmitterCTX(ctx) {
  if (EmitPtr) {
    SetBuffer(static_cast<uint8_t*>(EmitPtr), Size);
  }
}

void PPC64EmitterBase::LoadConstant(GPR rt, uint64_t Constant) {
  LoadImm64(rt, Constant);
}

void PPC64EmitterBase::LoadConstantFixed(GPR rt, uint64_t Constant) {
  LoadImm64Fixed(rt, Constant);
}

// Mask the upper 32 bits of `reg` to zero when running a 32-bit guest.
// `rldicl reg, reg, 0, 32` is the canonical PPC 32-bit zero-extend (rotate
// by 0, mask bits 32..63 of source — leaving the low 32 bits intact in
// big-endian bit numbering, with the high 32 bits cleared).
void PPC64EmitterBase::MaybeClrUpper32(GPR reg) {
  if (!EmitterCTX->Config.Is64BitMode()) {
    rldicl(reg, reg, 0, 32);
  }
}

// Align to 16-byte boundary with NOPs
void PPC64EmitterBase::Align16B() {
  while ((GetOffset() & 0xF) != 0) {
    nop();
  }
}

// Spill static (SRA) registers from host regs → CpuStateFrame
void PPC64EmitterBase::SpillStaticRegs(GPR tmp) {
  // SRA[i] holds the host-side register dedicated to x86 GPR i. The RA pass
  // emits StoreRegister/LoadRegister with PhysicalRegister.Reg = X86Reg
  // index, and DecodeSRAReg in the RA pass builds PhysicalRegister{GPRFixed,
  // Op->Reg} — so the i-th SRA slot must hold gregs[i] (= the i-th x86 GPR).
  // ARM64Emitter does the same: SRA[i] ↔ gregs[i].
  // 64-bit guest: 16 GPRs spilled via std (8 bytes each).
  // 32-bit guest:  8 GPRs spilled via stw (4 bytes — only the low 32 bits are
  //                architecturally defined; upper 32 of gregs[] are clobbered
  //                with 0 below to avoid feeding stale bits back through
  //                FillStaticRegs's lwz/ld on the next entry).
  // PF/AF are always 32-bit, handled below outside this loop.
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto& SRA = Is64Bit ? std::span<const GPR>(x64::SRA)
                            : std::span<const GPR>(x32::SRA);
  // First N entries are x86 GPRs (16 in 64-bit, 8 in 32-bit). The remaining 2
  // SRA slots are PF/AF (uint32_t), handled separately.
  const size_t NumGuestGPRs = Is64Bit ? 16u : 8u;
  for (size_t i = 0; i < NumGuestGPRs; ++i) {
    int32_t off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame,
                                                 State.gregs[i]));
    if (Is64Bit) {
      if (off >= -32768 && off <= 32764 && (off & 3) == 0) {
        std(SRA[i], off, STATE);
      } else {
        LoadImm32(tmp, static_cast<uint32_t>(off));
        stdx(SRA[i], STATE, tmp);
      }
    } else {
      // i686 guest: store the low 32 bits via stw, clear the high half via a
      // 4-byte zero store at +4 so a subsequent ld would still produce a
      // zero-extended 64-bit value.  Use std with a clrldi-trimmed source —
      // single 8-byte store, equally fast, and avoids assuming the SRA reg
      // already has a zero upper half.
      rldicl(tmp, SRA[i], 0, 32);   // tmp = SRA[i] & 0xFFFFFFFF
      if (off >= -32768 && off <= 32764 && (off & 3) == 0) {
        std(tmp, off, STATE);
      } else {
        LoadImm32(TMP3, static_cast<uint32_t>(off));
        stdx(tmp, STATE, TMP3);
      }
    }
  }

  // Spill PF/AF — these are uint32_t in CPUState (offsets 16, 20 with rip
  // immediately after at 24). Using std (8-byte store) here is wrong: it
  // overwrites adjacent fields. In particular `std REG_AF, 20` clobbers
  // RIP[0..3] — and on the next FillStaticRegs cycle the old RIP value
  // gets shuttled into the high 32 bits of REG_AF and *restored* over any
  // freshly-stored RIP, causing dispatch loops on every ExitFunction.
  int32_t pf_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.pf_raw));
  int32_t af_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.af_raw));
  stw(REG_PF, static_cast<int16_t>(pf_off), STATE);
  stw(REG_AF, static_cast<int16_t>(af_off), STATE);

  // Spill SRA FPRs (XMM0-XMM15 in 64-bit, XMM0-XMM7 in 32-bit) to State.xmm.sse.data
  const auto& SRAFPR = Is64Bit ? std::span<const VR>(x64::SRAFPR)
                               : std::span<const VR>(x32::SRAFPR);
  for (size_t i = 0; i < SRAFPR.size(); ++i) {
    int32_t xmm_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.xmm.sse.data[i][0]));
    LoadImm32(tmp, static_cast<uint32_t>(xmm_off));
    stvx(SRAFPR[i], STATE, tmp);
  }

  // Save NZCV across the dispatcher / C++ slow paths. Pack CR0 + XER into the
  // ARM-style 32-bit NZCV layout (N=LSB31, Z=30, C=29, V=28) and store at
  // flags[RFLAG_NZCV_LOC..NZCV_3_LOC]. Mirrors DEF_OP(LoadNZCV) bit shuffles.
  // ARM64 doesn't need this because PSTATE.NZCV is a hardware register that
  // survives across the dispatcher's C++ calls; PPC's CR0 + XER do not.
  //
  // Every ppc64le caller passes tmp = TMP1 (the {TMP1, TMP4} choice this
  // comment used to describe is the ARM64 emitter's; those files are not
  // compiled here). tmp aliases scratch we used in the SRA loop above, so we
  // need two non-aliased scratches (TMP2/TMP3) for the
  // CR/XER pack — but TMP2 (=r4) is also load-bearing for the FABI int-arg
  // contract: the dispatcher's per-FABI stubs (FABI_F80_I16_I16/I32_PTR)
  // expect TMP2 to still hold the int argument set by the JIT's Op_Unhandled
  // dispatch when SpillForABICall returns.
  //
  // Save TMP2 through FPR f0 via mtfprd/mffprd. Why f0:
  //   * ELFv2 nominally reserves a 288B red zone below r1, but a
  //     previous `std TMP2, -8(r1)` save faulted whenever r1 sat within
  //     8 bytes of a stack-mapping boundary (Steam bash subshells with
  //     tight clone()-allocated stacks SEGV'd here at si_addr = r1-8,
  //     one byte past the [stack] mapping -- the caller's mapping was
  //     smaller than the ABI red zone.)
  //   * f0 is volatile (caller-saved) per ELFv2 FP register conventions, and
  //     not in any FEX SRA/RA pool — it is used only as an op-local scratch
  //     by a few VectorOps emitters (lfd/fdiv/fsqrt sequences) and is
  //     guaranteed dead between IR ops.
  //   * Unlike VTMP1 / VR{0..15}, f0 carries no FABI-stub cross-call state.
  //     FABI bridges pass FP args in f1..f13 and read vector args from
  //     VTMP1/VTMP2 -- f0 is never read by any stub.
  //   * mtfprd/mffprd are POWER8 ISA 2.07 instructions; available on host.
  //
  // Earlier abandoned approaches:
  //   - mtvsrd VTMP1, TMP2: VTMP1 is the FABI vector source 1 and is
  //     read AFTER SpillForABICall in stubs like FABI_F32_I16_F80_PTR
  //     (`vmr VR{2}, VTMP1` runs post-spill). Broke 535 ASM tests.
  //   - mtvsrd VR{0}, TMP2: VR{0} would have been free in isolation but
  //     the broader regression suggests the FPR loop's `stvx VR{0}` had
  //     not yet committed by the time later code re-read v0 -- whatever the
  //     mechanism, breaks 1949 ASM tests. f0 sidesteps this entirely by
  //     using a non-VSR-aliased FPR slot.
  mtfprd(FPR{0}, TMP2);                         // save TMP2 in f0 (no memory)
  // mfocrf 0x80 (single-field, uncracked): the rlwinm extracts below read
  // only CR0.LT (PPC bit 0) and CR0.EQ (PPC bit 2), both inside the defined
  // field-0 nibble; the masks discard the pre-3.0C-undefined remainder.
  mfocrf(TMP2, 0x80);                           // TMP2 = CR0 (LT@LSB31, EQ@LSB29)
  rlwinm(TMP3, TMP2, 0, 0, 0);                 // TMP3 = N @ LSB31
  rlwinm(TMP2, TMP2, 1, 1, 1);                 // TMP2 = Z (CR0.EQ@LSB29 → LSB30)
  or_(TMP3, TMP3, TMP2);                        // TMP3 = N | Z
  mfspr(TMP2, 1);                               // TMP2 = XER (CA@LSB29, OV@LSB30)
  rlwinm(tmp, TMP2, 0, 2, 2);                  // tmp  = C @ LSB29 (XER.CA)
  or_(TMP3, TMP3, tmp);
  rlwinm(TMP2, TMP2, 30, 3, 3);                 // TMP2 = V (XER.OV@LSB30 → LSB28)
  or_(TMP3, TMP3, TMP2);
  int32_t nzcv_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_NZCV_LOC]));
  stw(TMP3, static_cast<int16_t>(nzcv_off), STATE);
  mffprd(TMP2, FPR{0});                         // restore TMP2 from f0
}

// Fill static registers from CpuStateFrame → host regs
void PPC64EmitterBase::FillStaticRegs(FillMode Mode) {
  // SRA[i] ↔ gregs[i]; see SpillStaticRegs comment.
  // 64-bit guest: 16 GPRs filled via ld (8 bytes each).
  // 32-bit guest:  8 GPRs filled via lwz (4 bytes, zero-extending) so the
  //                upper 32 bits of each host SRA register are forced to zero
  //                on every block entry.  This is the foundation of the
  //                "ignore upper 32 bits" invariant for i686 ALU/MEM ops.
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto& SRA = Is64Bit ? std::span<const GPR>(x64::SRA)
                            : std::span<const GPR>(x32::SRA);
  const size_t NumGuestGPRs = Is64Bit ? 16u : 8u;

  // A 32-bit guest may never elide a GPR fill. The `lwz` above is not just a
  // value transfer: it is what re-establishes "upper 32 bits are zero" for
  // ALU/MEM ops. A host register that merely survived a call untouched keeps
  // whatever garbage the JIT left in its upper half (SpillStaticRegs even
  // masks on the way out precisely because it cannot assume otherwise), so
  // "callee-saved, therefore still correct" does not hold in i686 mode.
  LOGMAN_THROW_A_FMT(Mode == FillMode::All || Is64Bit,
                     "Partial SRA fill requested for a 32-bit guest; the lwz "
                     "zero-extension invariant forbids it");

  const bool WantVolatile    = Mode != FillMode::NonVolatileGPRsOnly;
  const bool WantNonVolatile = Mode != FillMode::SkipNonVolatileGPRs;

  for (size_t i = 0; i < NumGuestGPRs; ++i) {
    const bool NonVolatile = SRA[i].idx >= RegVolatility::kFirstNonVolatileGPR;
    if (NonVolatile ? !WantNonVolatile : !WantVolatile) {
      continue;
    }
    int32_t off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame,
                                                 State.gregs[i]));
    if (Is64Bit) {
      if (off >= -32768 && off <= 32764 && (off & 3) == 0) {
        ld(SRA[i], off, STATE);
      } else {
        LoadImm32(TMP1, static_cast<uint32_t>(off));
        ldx(SRA[i], STATE, TMP1);
      }
    } else {
      // i686 guest: lwz zero-extends to 64.  CpuStateFrame.gregs is uint64_t
      // little-endian, so the low 4 bytes hold the architectural value.
      if (off >= -32768 && off <= 32764) {
        lwz(SRA[i], static_cast<int16_t>(off), STATE);
      } else {
        LoadImm32(TMP1, static_cast<uint32_t>(off));
        lwzx(SRA[i], STATE, TMP1);
      }
    }
  }

  if (Mode == FillMode::NonVolatileGPRsOnly) {
    // Everything below belongs to the complementary half. Returning here is
    // what makes NonVolatileGPRsOnly + SkipNonVolatileGPRs == All.
    return;
  }

  // Symmetric to SpillStaticRegs — use lwz so we don't load adjacent fields.
  int32_t pf_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.pf_raw));
  int32_t af_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.af_raw));
  lwz(REG_PF, static_cast<int16_t>(pf_off), STATE);
  lwz(REG_AF, static_cast<int16_t>(af_off), STATE);

  // Fill SRA FPRs (XMM0-XMM15 in 64-bit, XMM0-XMM7 in 32-bit)
  const auto& SRAFPR = Is64Bit ? std::span<const VR>(x64::SRAFPR)
                               : std::span<const VR>(x32::SRAFPR);
  for (size_t i = 0; i < SRAFPR.size(); ++i) {
    int32_t xmm_off = static_cast<int32_t>(
      offsetof(FEXCore::Core::CpuStateFrame, State.xmm.sse.data[i][0]));
    LoadImm32(TMP1, static_cast<uint32_t>(xmm_off));
    lvx(SRAFPR[i], STATE, TMP1);
  }

  // Restore NZCV across the dispatcher / C++ slow paths. Inverse of the
  // SpillStaticRegs save: load packed NZCV from flags[RFLAG_NZCV_LOC..NZCV_3_LOC]
  // and unpack into CR0.LT/EQ + XER.CA/OV. Mirrors DEF_OP(StoreNZCV).
  int32_t nzcv_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_NZCV_LOC]));
  lwz(TMP2, static_cast<int16_t>(nzcv_off), STATE);
  // Build CR0 input in TMP1: CR0.LT @ LSB31 ← packed N @ LSB31 (no shift),
  // CR0.EQ @ LSB29 ← packed Z @ LSB30 (rotl 31).
  rlwinm(TMP1, TMP2, 0,  0, 0);              // N → LSB31 (CR0.LT)
  rlwinm(TMP3, TMP2, 31, 2, 2);              // Z → LSB29 (CR0.EQ)
  or_(TMP1, TMP1, TMP3);
  mtocrf(0x80, TMP1);                         // CR0 ← bits 31..28 of TMP1 (single-field form)
  // Build XER: clear OV+CA, OR in C @ LSB29 (no shift) + V @ LSB30 (rotl 2).
  mfspr(TMP1, 1);
  LoadImm32(TMP3, 0x60000000u);
  andc(TMP1, TMP1, TMP3);
  rlwinm(TMP3, TMP2, 0, 2, 2);                // C → XER.CA @ LSB29
  or_(TMP1, TMP1, TMP3);
  rlwinm(TMP3, TMP2, 2, 1, 1);                // V → XER.OV @ LSB30
  or_(TMP1, TMP1, TMP3);
  mtspr(1, TMP1);

  // NOTE: this routine deliberately does NOT touch r0. ExitFunctionLinker
  // smuggles the resolved host-code pointer through r0 across FillStaticRegs
  // (see PPC64Dispatcher.cpp). Direct callers that need the JIT's r0=0
  // zero-index invariant must set it themselves; FillForABICall and the
  // Syscall return path both do.
}

// PPC64LE ELFv2 callee-saved registers: r14-r31, f14-f31, v20-v31, LR, CR2/3/4.
// Per ELFv2 §2.2.1.1, LR / CR / TOC save slots live in the *caller's* frame at fixed
// offsets from the caller's SP:
//   [old_SP + 8]  CR save (4 bytes)
//   [old_SP + 16] LR save (8 bytes)
//   [old_SP + 24] TOC save (8 bytes; only used by the callee around indirect calls)
// After `stdu r1, -576, r1` these become [r1+584], [r1+592], [r1+600] respectively.
//
// Local-frame layout (grows down from old_r1, 16-byte aligned, 576 bytes total).
// Offsets shown are from old_r1; after stdu r1, -576, r1 the same offsets
// expressed from the NEW r1 add 576 (so the back-chain at [old_r1-576] is
// [r1+0] post-stdu).
//
// This frame MUST reserve the ELFv2 96-byte linkage + parameter-save block at
// the bottom, because the dispatcher issues several ELFv2 C-ABI bctrls out of
// it (SleepThread, CompileSingleStep, ExitFunctionLink, ThreadPauseHandler,
// and the C++ signal-restart trampoline).  Any of those callees will write
// LR into [caller_r1+16] and CR into [caller_r1+8]; the dispatcher itself
// writes TOC into [caller_r1+24] at :391/:465 around every bctrl.
// PPC64Dispatcher.cpp:391 in particular runs on every L1 miss.
//
// The earlier 512-byte frame put VMX v20 at [new_r1+16], directly on top of
// the callee's LR save slot.  On return from any bctrl, PopCalleeSavedRegisters'
// `lvx v20, [r1+16]` reloaded {orig_v20_lo, callee_LR_or_TOC} into v20, silently
// corrupting a live host non-volatile vector register that C++ callers of the
// dispatcher (typically libstdc++/libc paths during thread bring-up) can rely on.
//
// New layout:
//   [new_r1 +   0]:            back chain (= old_r1)
//   [new_r1 +   8]: (CR)       our callee's CR save slot per ELFv2
//   [new_r1 +  16]: (LR)       our callee's LR save slot per ELFv2
//   [new_r1 +  24]: (TOC)      our callee's TOC save slot (dispatcher writes r2 here)
//   [new_r1 +  32.. 95]:       parameter save area (8 doublewords, for our callees)
//   [old_r1 - 480..-288]:      VMX v20..v31  (12 × 16 = 192 bytes)  — [new_r1 +  96..287]
//   [old_r1 - 288..-144]:      FPR f14..f31  (18 ×  8 = 144 bytes)  — [new_r1 + 288..431]
//   [old_r1 - 144..   0]:      GPR r14..r31  (18 ×  8 = 144 bytes)  — [new_r1 + 432..575]
//
// The FRAME_GPR_SAVE / FRAME_FPR_SAVE / FRAME_VMX_SAVE constants give the FIRST
// (lowest-numbered-reg) slot's offset FROM OLD_R1: -144 / -288 / -480.
static constexpr int32_t FRAME_GPR_SAVE   = -(8 * 18);                  // -144
static constexpr int32_t FRAME_FPR_SAVE   = FRAME_GPR_SAVE - 8 * 18;    // -288
static constexpr int32_t FRAME_VMX_SAVE   = FRAME_FPR_SAVE - 16 * 12;   // -480
static constexpr int32_t FRAME_TOTAL      = -576;
// ABI save slots in the caller's linkage area, expressed as offsets from r1
// after the stdu has decremented r1 by FRAME_TOTAL (576 bytes).
static constexpr int16_t LR_SAVE_OFFSET   = -FRAME_TOTAL + 16;  //  592
static constexpr int16_t CR_SAVE_OFFSET   = -FRAME_TOTAL + 8;   //  584

void PPC64EmitterBase::PushCalleeSavedRegisters() {
  // Use r0 for LR save: TMP1=r3 is the first C-ABI argument and must not be clobbered.
  mflr(r(0));

  // Save CR (only CR2/3/4 are non-volatile per ABI; we save the whole CR for simplicity).
  // Must be done before stdu so we can use the caller's CR save slot.
  mfcr(TMP2);

  // Allocate stack frame (back-chain at offset 0).
  stdu(r1, FRAME_TOTAL, r1);

  // Save LR and CR into the caller's linkage area (now at r1 + 528 / r1 + 520).
  std(r(0), LR_SAVE_OFFSET, r1);
  stw(TMP2, CR_SAVE_OFFSET, r1);

  for (int i = 14; i <= 31; ++i) {
    int32_t off = FRAME_GPR_SAVE + (i - 14) * 8;
    std(r(i), static_cast<int16_t>(off - FRAME_TOTAL), r1);
  }
  for (int i = 14; i <= 31; ++i) {
    int32_t off = FRAME_FPR_SAVE + (i - 14) * 8;
    stfd(f(i), static_cast<int16_t>(off - FRAME_TOTAL), r1);
  }
  for (int i = 20; i <= 31; ++i) {
    int32_t off = FRAME_VMX_SAVE + (i - 20) * 16;
    LoadImm32(TMP2, static_cast<uint32_t>(off - FRAME_TOTAL));
    stvx(VR{static_cast<uint32_t>(i)}, r1, TMP2);
  }
}

void PPC64EmitterBase::PopCalleeSavedRegisters() {
  for (int i = 20; i <= 31; ++i) {
    int32_t off = FRAME_VMX_SAVE + (i - 20) * 16;
    LoadImm32(TMP2, static_cast<uint32_t>(off - FRAME_TOTAL));
    lvx(VR{static_cast<uint32_t>(i)}, r1, TMP2);
  }
  for (int i = 14; i <= 31; ++i) {
    int32_t off = FRAME_FPR_SAVE + (i - 14) * 8;
    lfd(f(i), static_cast<int16_t>(off - FRAME_TOTAL), r1);
  }
  for (int i = 14; i <= 31; ++i) {
    int32_t off = FRAME_GPR_SAVE + (i - 14) * 8;
    ld(r(i), static_cast<int16_t>(off - FRAME_TOTAL), r1);
  }

  // Restore CR (caller's linkage area) and LR.
  lwz(TMP2, CR_SAVE_OFFSET, r1);
  ld(r(0), LR_SAVE_OFFSET, r1);
  // Per ELFv2 ABI only CR2/3/4 are callee-saved (FXM=0x38).  Restoring all
  // 8 fields would overwrite CR0 (the JIT block may have packed post-spill
  // NZCV before exiting) and CR1/5/6/7 (volatile per ABI but cleaner to
  // leave alone).  Only-CR2/3/4 is faster and ABI-correct.
  mtcrf(0x38, TMP2);
  mtlr(r(0));

  // Deallocate frame.
  addi(r1, r1, static_cast<int16_t>(-FRAME_TOTAL));
}

// Push dynamic (non-SRA) registers before an ABI call
//
// PPC64LE ELFv2 requires the *caller* to leave a 32-byte frame header at the
// top of the new stack frame for the *callee*'s use: back-chain (+0), CR (+8),
// LR (+16), TOC (+24). A typical C++ callee's prologue is
// `mflr r0; std r0, 16(r1)` — that store lands in *its caller's* r1+16.
// If we spilled a register at offset 16 of our dynamic-spill area, the
// callee's LR-save would silently corrupt the spill and PopDynamicRegs would
// then read back the bogus LR (≈ a JIT-trampoline code address). The result
// was an obscure SEGV the next time the JIT used the affected SRA register
// as a memory base — first reproduced by the precision_test_* x87 cases that
// exercise multiple FLDCW + FABI-helper sequences in one block.
// Spill GPRs at [r1+32..] and FPRs at the next 16-byte boundary above.
size_t PPC64EmitterBase::PushDynamicRegs(GPR tmp) {
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto RAFPR = Is64Bit ? std::span<const VR>(x64::RAFPR) : std::span<const VR>(x32::RAFPR);

  const size_t FPRStart = Is64Bit ? x64::kDynFPRStart  : x32::kDynFPRStart;
  const size_t SaveSize = Is64Bit ? x64::kDynRegSaveSize : x32::kDynRegSaveSize;

  // stdu writes the back-chain at [new_r1+0] = old r1, so traceback walkers
  // can step past this frame.  SaveSize fits the signed-16-bit displacement.
  stdu(r1, -static_cast<int16_t>(SaveSize), r1);

  // Save ONLY what an ELFv2 callee may clobber. RA is entirely callee-saved
  // in both modes (x64: r24-r26/r30/r31; x32: r16-r26/r30/r31 — the
  // static_asserts by the pool definitions in PPC64Emitter.h pin this), and
  // of RAFPR only v0-v19 are volatile, so v20+ survive any C call. That
  // includes host calls that RE-ENTER the JIT via a guest callback: the
  // dispatcher's C entry runs PushCalleeSavedRegisters, which saves
  // r14-r31/f14-f31/v20-v31 before any JIT code runs. Frame layout is
  // deliberately UNCHANGED — the skipped registers keep their (now unwritten)
  // slots, so kDynGPRStart/kDynFPRStart arithmetic and the DEF_OP(Thunk)
  // linkage-area assumption stay valid, and stack cost is the only thing not
  // reclaimed (240 bytes of dead frame, irrelevant).
  //
  // Previously this saved all of RA + all of RAFPR: ~50 wasted instructions
  // per SpillForABICall/FillForABICall pair on every host C call (thunks,
  // CPUID, atomic/crypto helpers, x87 fallbacks). DEF_OP(Syscall) already
  // relied on exactly this reasoning for the GPR half (BranchOps.cpp).
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    if (RAFPR[i].idx >= 20) {
      continue;  // v20-v31: ELFv2 callee-saved
    }
    if (!(DynVRSpillMask & (1u << i))) {
      continue;  // not live across this call (see DynVRSpillMask contract)
    }
    int32_t off = static_cast<int32_t>(FPRStart + i * 16);
    LoadImm32(tmp, static_cast<uint32_t>(off));
    stvx(RAFPR[i], r1, tmp);
  }
  return SaveSize;
}

void PPC64EmitterBase::PopDynamicRegs() {
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto RAFPR = Is64Bit ? std::span<const VR>(x64::RAFPR) : std::span<const VR>(x32::RAFPR);

  const size_t FPRStart = Is64Bit ? x64::kDynFPRStart  : x32::kDynFPRStart;
  const size_t SaveSize = Is64Bit ? x64::kDynRegSaveSize : x32::kDynRegSaveSize;

  // Mirror of PushDynamicRegs: only the ELFv2-volatile subset was saved, so
  // only that subset is reloaded. Everything else was preserved by the callee.
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    if (RAFPR[i].idx >= 20) {
      continue;  // v20-v31: ELFv2 callee-saved, never spilled
    }
    if (!(DynVRSpillMask & (1u << i))) {
      continue;  // not spilled by PushDynamicRegs (mask unchanged in between)
    }
    int32_t off = static_cast<int32_t>(FPRStart + i * 16);
    LoadImm32(TMP1, static_cast<uint32_t>(off));
    lvx(RAFPR[i], r1, TMP1);
  }

  addi(r1, r1, static_cast<int16_t>(SaveSize));
}

// FABI-callsite caller-save of the live volatile dynamic VRs. The FABI bridge
// stubs (PPC64Dispatcher::GenerateABICall) are shared across every callsite,
// so they cannot know which dynamic VRs are live — their Push/PopDynamicRegs
// run under mask 0 and the two callsite emitters bracket the bctrl with this
// pair instead, storing into the callsite's own scratch frame. Slots are
// packed by SAVED register (k counts set mask bits, not pool indices) so the
// save/restore loops must stay in lockstep — both iterate the same mask.
void PPC64EmitterBase::SaveDynVRsToFrame(int32_t BaseOffset) {
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto RAFPR = Is64Bit ? std::span<const VR>(x64::RAFPR) : std::span<const VR>(x32::RAFPR);

  int32_t off = BaseOffset;
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    if (RAFPR[i].idx >= 20 || !(DynVRSpillMask & (1u << i))) {
      continue;
    }
    LoadImm32(TMP3, static_cast<uint32_t>(off));
    stvx(RAFPR[i], r1, TMP3);
    off += 16;
  }
}

void PPC64EmitterBase::RestoreDynVRsFromFrame(int32_t BaseOffset) {
  const bool Is64Bit = EmitterCTX->Config.Is64BitMode();
  const auto RAFPR = Is64Bit ? std::span<const VR>(x64::RAFPR) : std::span<const VR>(x32::RAFPR);

  int32_t off = BaseOffset;
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    if (RAFPR[i].idx >= 20 || !(DynVRSpillMask & (1u << i))) {
      continue;
    }
    LoadImm32(TMP3, static_cast<uint32_t>(off));
    lvx(RAFPR[i], r1, TMP3);
    off += 16;
  }
}

// Unaligned 128-bit load/store.
//
// Historical shape: bounce through STATE+JITScratch — ld/ld + std/std + lvx
// (7 instructions) — because lvx/stvx silently mask EA to a 16-byte boundary.
// Both replacement paths below were verified to produce the byte-identical
// register image (mem[EA+i] → BE byte element 15-i, i.e. guest XMM byte i in
// element 15-i):
//   * lxvx/stxvx (ISA 3.0): LE semantics place mem[EA+i] into element 15-i
//     directly — 1 instruction, any alignment, no scratch, no memory bounce.
//     Emit-time gated on HostFeatures.SupportsISA30 (POWER8 would SIGILL).
//   * lxvd2x/stxvd2x (ISA 2.06, POWER8-legal): produce/consume the
//     DOUBLEWORD-SWAPPED image (dword[0] = LE int mem[EA..7], dword[1] =
//     LE int mem[EA+8..15]); xxpermdi DM=2 (T.dw0 = A.dw1, T.dw1 = B.dw0)
//     swaps the halves — 2 instructions.
// Register-contract change vs the bounce: these paths clobber NO TMP GPRs
// and NO VMX registers. The store's pre-3.0 path swaps through VTMP3_VSX
// (vs12, the RA-invisible low bank) — it used to burn VTMP2/VTMP1.
// Fault behaviour: si_addr/DAR precision for lxvx/stxvx across protected page
// boundaries was measured good on the target (POWER9 DD2.2, Radix) in all
// first/second/both-page patterns — see docs/POWER9_PORT_PLAN.md §2.1.
// NOTE: `ea` must not be r0 — RA=0 in the encoding reads literal zero (the
// same constraint the old D-form ld/std bounce had).
void PPC64EmitterBase::LoadUnalignedV128(VR dst, GPR ea) {
  if (EmitterCTX->HostFeatures.SupportsISA30) {
    lxvx(dst, ea, GPRegs::r0);          // EA = GPR[ea] + GPR[r0], r0 ≡ 0
    return;
  }
  // Pre-3.0 VSX fallback (POWER7/POWER8): swapped-image load + fixup.
  lxvd2x(dst, ea, GPRegs::r0);
  xxpermdi(dst, dst, dst, 2);           // swap dword[0] <-> dword[1]
}

void PPC64EmitterBase::StoreUnalignedV128(VR src, GPR ea) {
  if (EmitterCTX->HostFeatures.SupportsISA30) {
    stxvx(src, ea, GPRegs::r0);
    return;
  }
  // Pre-3.0 VSX fallback: stxvd2x writes the doubleword-swapped image, so
  // swap into a scratch first (src must be preserved for the caller). The
  // scratch is VTMP3_VSX from the RA-invisible low bank — both consumers
  // (xxpermdi, stxvd2x) are VSX-form so they can encode it, and using it
  // instead of VTMP1/VTMP2 means this path clobbers NO VMX register at all.
  xxpermdi(VTMP3_VSX, toVSX(src), toVSX(src), 2);
  stxvd2x(VTMP3_VSX, ea, GPRegs::r0);
}

// x86 sub-128-bit FPR memory ops (vmovd/vmovq/vmov{ss,sd}) write/read only
// `size` bytes and the load form zero-extends the upper bits. Naively using
// stvx/lvx writes/reads 16 bytes and corrupts adjacent stack/structure slots
// (root cause of hello_static SEGV at __tls_init_tp). The store bounces
// through STATE+JITScratch (16 bytes, alignas(16) in CpuStateFrame -- ELFv2
// nominally has a 288B red zone below r1, but an r1-relative slot faulted
// on tight clone-allocated stacks where the mapping ended before the ABI
// red zone did): spill the V128 there with stvx, then
// emit a size-correct GPR store from the slot to *ea. The load form has
// scalar-VSX fast paths (see LoadFPRSized) and falls back to the mirrored
// bounce. CRITICAL: the bounce paths clobber TMP1/TMP2/TMP3, so capture
// `ea` into TMP4 first if it aliases.
void PPC64EmitterBase::StoreFPRSized(VR src, GPR ea, uint32_t size) {
  if (size == 16) {
    StoreUnalignedV128(src, ea);
    return;
  }

  // Scalar VSX fast path for the two sizes the guest actually hits in bulk
  // (movss/movd = 4, movsd/movq = 8). The bounce below costs 5 instructions
  // plus a store-to-load-forwarding stall through JITScratch; this is 2.
  //
  // Register image convention (see the LoadFPRSized block comment): the guest
  // value lives in the LOW bits of dword[1] — BE bytes (16-size)..15 — as an
  // LE integer. Both stxsdx and stxsiwx read out of dword[0] instead
  // (stxsdx the whole doubleword, stxsiwx word element 1 = the low word of
  // dword[0]), so one xxpermdi with DM=2 moves dword[1] into dword[0]:
  //   T.dw0 = A.dw1 = the guest value, T.dw1 = B.dw0 = don't-care.
  // That is the exact inverse of the load path's xxpermdi(dst,dst,dst,2),
  // and for size 4 the guest's low word lands in bits 32:63 of dw0 — the
  // half stxsiwx stores — because it was the low word of the LE integer in
  // dword[1]. Nothing outside the `size` bytes is written, which is the
  // whole point of not using stvx here (hello_static __tls_init_tp SEGV).
  //
  // src must be preserved for the caller, so permute into VTMP3_VSX (the
  // RA-invisible low-bank scratch) — same choice, and therefore the same
  // clobbers-no-VMX-register contract, as the pre-3.0 StoreUnalignedV128
  // path. All three consumers here are VSX-form, which is what makes the
  // low bank encodable at all.
  // stxsdx is ISA 2.06 and stxsiwx ISA 2.07, so both are POWER8-legal with
  // no feature gate — matching the ungated lxsdx/lxsiwzx on the load side.
  // `ea` sits in RA (where RA=0 would mean literal zero), so it must not be
  // r0; that is already the documented precondition for these helpers.
  if (size == 4 || size == 8) {
    xxpermdi(VTMP3_VSX, toVSX(src), toVSX(src), 2);
    if (size == 8) {
      stxsdx(VTMP3_VSX, ea, GPRegs::r0);
    } else {
      stxsiwx(VTMP3_VSX, ea, GPRegs::r0);
    }
    return;
  }

  // Sizes 1/2 (and anything else that reaches here) keep the JITScratch
  // bounce: pre-3.0 has no single-byte/halfword scalar VSX store.
  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  // Spill V128 into STATE+JITScratch (see block comment above).
  constexpr int32_t kScratchOff = offsetof(FEXCore::Core::CpuStateFrame, JITScratch);
  static_assert(kScratchOff >= -32768 && kScratchOff <= 32767,
                "JITScratch offset must fit in int16 for addi-based addressing");
  addi(TMP3, STATE, static_cast<int16_t>(kScratchOff));
  li(TMP1, 0);
  stvx(src, TMP3, TMP1);
  // Pull the low `size` bytes from the slot and store them to *ea.
  switch (size) {
  case 1:
    lbz(TMP1, 0, TMP3);
    stbx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 2:
    lhz(TMP1, 0, TMP3);
    sthx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 4:
    lwz(TMP1, 0, TMP3);
    stwx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 8:
    ld(TMP1, 0, TMP3);
    stdx(TMP1, EaSafe, GPRegs::r0);
    break;
  default: break;
  }
}

void PPC64EmitterBase::LoadFPRSized(VR dst, GPR ea, uint32_t size) {
  if (size == 16) {
    LoadUnalignedV128(dst, ea);
    return;
  }

  // Scalar VSX fast paths. Target image (matches the historical zero-fill
  // bounce): guest value in BE byte elements (16-size)..15 as an LE integer
  // — i.e. the value in the LOW bits of dword[1] — with every other byte 0.
  // All four lxs* loads deposit the (zero-extended) value into dword[0], so
  // one xxpermdi moves it to dword[1] with a zero in dword[0]:
  //   * ISA 3.0 (gated):    lxs*  +  xxpermdi(dst,dst,dst,2).  v3.0 defines
  //     dword[1] <- 0 for these loads, so the DM=2 swap (T.dw0 = A.dw1 = 0,
  //     T.dw1 = B.dw0 = value) finishes the job in 2 instructions.
  //   * pre-3.0 (sizes 4/8): lxsiwzx/lxsdx leave dword[1] UNDEFINED on
  //     2.06/2.07 hardware, so merge against the pinned zero with DM=0
  //     (T.dw0 = VZERO_VSX.dw0 = 0, T.dw1 = B.dw0 = value) — never reading
  //     the undefined half.  2 instructions.  Sizes 1/2 have no pre-3.0
  //     scalar load; they keep the JITScratch bounce below.
  // These paths clobber no TMP GPR and no vector temp.
  const bool ISA30 = EmitterCTX->HostFeatures.SupportsISA30;
  if (ISA30 && (size == 1 || size == 2 || size == 4 || size == 8)) {
    switch (size) {
    case 1: lxsibzx(dst, ea, GPRegs::r0); break;
    case 2: lxsihzx(dst, ea, GPRegs::r0); break;
    case 4: lxsiwzx(dst, ea, GPRegs::r0); break;
    case 8: lxsdx  (dst, ea, GPRegs::r0); break;
    }
    xxpermdi(dst, dst, dst, 2);
    return;
  }
  if (!ISA30 && (size == 4 || size == 8)) {
    if (size == 4) {
      lxsiwzx(dst, ea, GPRegs::r0);
    } else {
      lxsdx(dst, ea, GPRegs::r0);
    }
    // DM=0: T.dw0 = VZERO_VSX.dw0 = 0, T.dw1 = B.dw0 = value — the undefined
    // dword[1] of the scalar load is never read. The pinned zero replaces a
    // per-load xxlxor + vector temp (one per guest movss/movsd in DSP-heavy
    // blocks); the dispatcher maintains vs14 == 0 (see VZERO_VSX).
    xxpermdi(toVSX(dst), VZERO_VSX, toVSX(dst), 0);
    return;
  }

  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  // Zero the 16-byte JITScratch slot, then write `size` bytes from *ea into
  // its low end so the upper bits are zero (matches x86 vmovd/vmovq
  // zero-extend semantics).  See StoreFPRSized for why we bounce through
  // STATE+JITScratch instead of r1-redzone (ELFv2 has no red zone; r1-relative
  // scratch faulted at stack-mapping boundaries).
  constexpr int32_t kScratchOff = offsetof(FEXCore::Core::CpuStateFrame, JITScratch);
  addi(TMP3, STATE, static_cast<int16_t>(kScratchOff));
  std(GPRegs::r0, 0, TMP3);
  std(GPRegs::r0, 8, TMP3);
  switch (size) {
  case 1:
    lbzx(TMP1, EaSafe, GPRegs::r0);
    stb(TMP1, 0, TMP3);
    break;
  case 2:
    lhzx(TMP1, EaSafe, GPRegs::r0);
    sth(TMP1, 0, TMP3);
    break;
  case 4:
    lwzx(TMP1, EaSafe, GPRegs::r0);
    stw(TMP1, 0, TMP3);
    break;
  case 8:
    ldx(TMP1, EaSafe, GPRegs::r0);
    std(TMP1, 0, TMP3);
    break;
  case 10:
    // 80-bit float (FLD tword [mem]): read 8+2 bytes from EA into scratch's
    // low 10 bytes, leaving the upper 6 zeroed by the std r0 prelude above.
    ldx(TMP1, EaSafe, GPRegs::r0);
    std(TMP1, 0, TMP3);
    li(TMP2, 8);
    lhzx(TMP1, EaSafe, TMP2);
    sth(TMP1, 8, TMP3);
    break;
  case 16:
    // Should be unreachable (early return at top of fn for size==16), but
    // matches the IR contract for f128. Fall to default break to avoid silent
    // mis-load.
    break;
  default: break;
  }
  li(TMP1, 0);
  lvx(dst, TMP3, TMP1);
}

void PPC64EmitterBase::SpillForABICall(GPR tmp, bool FPRs) {
  SpillStaticRegs(tmp);
  PushDynamicRegs(tmp);
  // NB. Do NOT set InSyscallInfo=0xFFFF here. That marker means "we are
  // currently in a JIT-emitted Syscall op" and only DEF_OP(Syscall) is
  // allowed to raise it (ARM64 parity: `JIT/BranchOps.cpp:278`, plus
  // ARM64's DEF_OP(ProcessorID) which is a real getcpu syscall at
  // `JIT/MiscOps.cpp:260`; ppc64le's DEF_OP(ProcessorID) does `li r,0`
  // and needs no marker). SpillForABICall serves every host-C-call site
  // in the backend (thunks, CPUID, atomic helpers, AES/SHA/CRC32
  // helpers, x87 fallbacks) and thunks in particular RE-ENTER the guest
  // via CallbackPtr -- with the marker set, callback code runs with
  // SpillSRA IgnoreMask=0xFFFF, so any signal arriving in the callback
  // skips all 16 x86-64 SRA GPR spills. State.rip then gets a
  // ContextBackup* interpreted as guest-stack, and the guest resumes
  // with a garbage RIP. That was the 2026-07-31 Factorio crash
  // (SIGTRACE showed isi=0xffff on every DELIVER; PC=0xaacb584c2489d700).
}

void PPC64EmitterBase::FillForABICall(bool FPRs) {
  PopDynamicRegs();
  FillStaticRegs();
  // Paired clear removed with the set above. r0 is volatile per the ELFv2
  // ABI; the JIT relies on r0=0 as the zero-index for `ldx`/`stdx`-style
  // instructions, so restore that invariant explicitly. Not a store to
  // InSyscallInfo any more.
  li(GPRegs::r0, 0);
}

} // namespace FEXCore::CPU
