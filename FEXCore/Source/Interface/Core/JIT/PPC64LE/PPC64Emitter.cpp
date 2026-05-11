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
  auto& SRA = x64::SRA;
  for (int i = 0; i < 16; ++i) {
    int32_t off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame,
                                                 State.gregs[i]));
    if (off >= -32768 && off <= 32764 && (off & 3) == 0) {
      std(SRA[i], off, STATE);
    } else {
      LoadImm32(tmp, static_cast<uint32_t>(off));
      stdx(SRA[i], STATE, tmp);
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

  // Spill SRA FPRs (XMM0-XMM15) to State.xmm.sse.data
  auto& SRAFPR = x64::SRAFPR;
  for (int i = 0; i < 16; ++i) {
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
  mfcr(tmp);                                    // tmp = mfcr (CR0.LT@LSB31, CR0.EQ@LSB29)
  rlwinm(TMP4, tmp, 0, 0, 0);                  // N → packed LSB31
  rlwinm(tmp, tmp, 1, 1, 1);                   // Z (CR0.EQ@LSB29 → LSB30)
  or_(TMP4, TMP4, tmp);
  mfspr(tmp, 1);                                // tmp = XER (CA@LSB29, OV@LSB30)
  rlwinm(TMP1, tmp, 0, 2, 2);                  // C → packed LSB29 (no shift)
  or_(TMP4, TMP4, TMP1);
  rlwinm(TMP1, tmp, 30, 3, 3);                 // V (OV@LSB30 → LSB28)
  or_(TMP4, TMP4, TMP1);
  int32_t nzcv_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.flags[FEXCore::X86State::RFLAG_NZCV_LOC]));
  stw(TMP4, static_cast<int16_t>(nzcv_off), STATE);
}

// Fill static registers from CpuStateFrame → host regs
void PPC64EmitterBase::FillStaticRegs() {
  // SRA[i] ↔ gregs[i]; see SpillStaticRegs comment.
  auto& SRA = x64::SRA;
  for (int i = 0; i < 16; ++i) {
    int32_t off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame,
                                                 State.gregs[i]));
    if (off >= -32768 && off <= 32764 && (off & 3) == 0) {
      ld(SRA[i], off, STATE);
    } else {
      LoadImm32(TMP1, static_cast<uint32_t>(off));
      ldx(SRA[i], STATE, TMP1);
    }
  }

  // Symmetric to SpillStaticRegs — use lwz so we don't load adjacent fields.
  int32_t pf_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.pf_raw));
  int32_t af_off = static_cast<int32_t>(offsetof(FEXCore::Core::CpuStateFrame, State.af_raw));
  lwz(REG_PF, static_cast<int16_t>(pf_off), STATE);
  lwz(REG_AF, static_cast<int16_t>(af_off), STATE);

  // Fill SRA FPRs
  auto& SRAFPR = x64::SRAFPR;
  for (int i = 0; i < 16; ++i) {
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
  mtcrf(0x80, TMP1);                          // CR0 ← bits 31..28 of TMP1
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
// After `stdu r1, -512, r1` these become [r1+520], [r1+528], [r1+536] respectively.
//
// Local-frame layout (grows down from old_r1, 16-byte aligned, 512 bytes total):
//   [r1 -  16]: VMX v20-v31 (12 × 16 = 192 bytes)
//   [r1 - 208]: FPR f14-f31 (18 × 8  = 144 bytes)
//   [r1 - 352]: GPR r14-r31 (18 × 8  = 144 bytes)
//   [r1 - 496]: 16 bytes padding to keep r1 16-byte aligned
//   [r1 +   0]: back chain (= old_r1)
static constexpr int32_t FRAME_GPR_SAVE   = -(16 + 8 * 18);   // -160
static constexpr int32_t FRAME_FPR_SAVE   = FRAME_GPR_SAVE - 8 * 18;  // -304
static constexpr int32_t FRAME_VMX_SAVE   = FRAME_FPR_SAVE - 16 * 12; // -496
static constexpr int32_t FRAME_TOTAL      = -512;
// ABI save slots in the caller's linkage area, expressed as offsets from r1
// after the stdu has decremented r1 by FRAME_TOTAL (512 bytes).
static constexpr int16_t LR_SAVE_OFFSET   = -FRAME_TOTAL + 16;  //  528
static constexpr int16_t CR_SAVE_OFFSET   = -FRAME_TOTAL + 8;   //  520

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
  // mtcrf with FXM=0xFF restores all 8 CR fields (only 2/3/4 are required, but
  // restoring all is harmless and matches the mfcr above).
  mtcrf(0xFF, TMP2);
  mtlr(r(0));

  // Deallocate frame.
  addi(r1, r1, static_cast<int16_t>(-FRAME_TOTAL));
}

// Push dynamic (non-SRA) registers before an ABI call
size_t PPC64EmitterBase::PushDynamicRegs(GPR tmp) {
  const auto& RA    = x64::RA;
  const auto& RAFPR = x64::RAFPR;

  // GPRs occupy RA.size()*8 bytes starting at r1+0.
  // FPRs must be 16-byte aligned (stvx silently masks the low 4 bits of the EA
  // to a 16-byte boundary — if the FPR area starts at an unaligned offset the
  // first stvx rounds DOWN and overwrites the last GPR save slot).
  // Round the FPR start offset up to the next 16-byte boundary.
  const size_t GPRBytes  = RA.size() * 8;                     // 40 for x64
  const size_t FPROffset = (GPRBytes + 15u) & ~15u;            // 48 for x64
  size_t SaveSize = FPROffset + RAFPR.size() * 16;
  SaveSize = (SaveSize + 15) & ~15u;  // align total to 16

  addi(r1, r1, -static_cast<int16_t>(SaveSize));

  for (size_t i = 0; i < RA.size(); ++i) {
    std(RA[i], static_cast<int16_t>(i * 8), r1);
  }
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    int32_t off = static_cast<int32_t>(FPROffset + i * 16);
    LoadImm32(tmp, static_cast<uint32_t>(off));
    stvx(RAFPR[i], r1, tmp);
  }
  return SaveSize;
}

void PPC64EmitterBase::PopDynamicRegs() {
  const auto& RA    = x64::RA;
  const auto& RAFPR = x64::RAFPR;

  const size_t GPRBytes  = RA.size() * 8;
  const size_t FPROffset = (GPRBytes + 15u) & ~15u;
  size_t SaveSize = FPROffset + RAFPR.size() * 16;
  SaveSize = (SaveSize + 15) & ~15u;

  for (size_t i = 0; i < RA.size(); ++i) {
    ld(RA[i], static_cast<int16_t>(i * 8), r1);
  }
  for (size_t i = 0; i < RAFPR.size(); ++i) {
    int32_t off = static_cast<int32_t>(FPROffset + i * 16);
    LoadImm32(TMP1, static_cast<uint32_t>(off));
    lvx(RAFPR[i], r1, TMP1);
  }

  addi(r1, r1, static_cast<int16_t>(SaveSize));
}

// Unaligned 128-bit load: two scalar `ld` from `ea`, store to the 16-byte-
// aligned protected zone below r1, then `lvx`. CRITICAL: the helper internally
// clobbers TMP1, TMP2, and TMP3, so if `ea` aliases any of them the second
// `ld(...,ea)` loads from a corrupted base. Always stash into TMP4 first.
// Callers may pass `ea = TMP4` (e.g. StoreMemPair); detect and skip the copy.
void PPC64EmitterBase::LoadUnalignedV128(VR dst, GPR ea) {
  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  ld(TMP1, 0, EaSafe);
  ld(TMP2, 8, EaSafe);
  std(TMP1, -16, r1);
  std(TMP2,  -8, r1);
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  lvx(dst, TMP3, TMP1);
}

void PPC64EmitterBase::StoreUnalignedV128(VR src, GPR ea) {
  // Aligned vector store to scratch slot, two scalar loads, two scalar stores
  // back to `ea`. The internal sequence clobbers TMP1/TMP2/TMP3 (li TMP1,0
  // alone is enough to wreck `ea` when ea==TMP1, which is the common case
  // when LoadMemPair's offset fits int16 and Base = addi(TMP1,...)). Capture
  // into TMP4 if ea aliases any internal scratch.
  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  stvx(src, TMP3, TMP1);
  ld(TMP1, -16, r1);
  ld(TMP2,  -8, r1);
  std(TMP1, 0, EaSafe);
  std(TMP2, 8, EaSafe);
}

// x86 sub-128-bit FPR memory ops (vmovd/vmovq/vmov{ss,sd}) write/read only
// `size` bytes and the load form zero-extends the upper bits. Naively using
// stvx/lvx writes/reads 16 bytes and corrupts adjacent stack/structure slots
// (root cause of hello_static SEGV at __tls_init_tp). Bounce through the 16B
// red-zone slot at r1-16: for stores spill the V128 there with stvx, then
// emit a size-correct GPR store from that slot to *ea; for loads zero the
// slot, scalar-load `size` bytes from *ea into the slot's low end, then lvx
// into dst. CRITICAL: the redzone path clobbers TMP1/TMP2/TMP3, so capture
// `ea` into TMP4 first if it aliases.
void PPC64EmitterBase::StoreFPRSized(VR src, GPR ea, uint32_t size) {
  if (size == 16) {
    StoreUnalignedV128(src, ea);
    return;
  }
  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  // Spill V128 to aligned 16B redzone slot at r1-16.
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  stvx(src, TMP3, TMP1);
  // Pull the low `size` bytes from the slot and store them to *ea.
  switch (size) {
  case 1:
    lbz(TMP1, -16, r1);
    stbx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 2:
    lhz(TMP1, -16, r1);
    sthx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 4:
    lwz(TMP1, -16, r1);
    stwx(TMP1, EaSafe, GPRegs::r0);
    break;
  case 8:
    ld(TMP1, -16, r1);
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
  GPR EaSafe = ea;
  if (ea == TMP1 || ea == TMP2 || ea == TMP3) {
    mr(TMP4, ea);
    EaSafe = TMP4;
  }
  // Zero the 16B redzone slot, then write `size` bytes from *ea into its
  // low end so the upper bits are zero (matches x86 vmovd/vmovq semantics).
  std(GPRegs::r0, -16, r1);
  std(GPRegs::r0,  -8, r1);
  switch (size) {
  case 1:
    lbzx(TMP1, EaSafe, GPRegs::r0);
    stb(TMP1, -16, r1);
    break;
  case 2:
    lhzx(TMP1, EaSafe, GPRegs::r0);
    sth(TMP1, -16, r1);
    break;
  case 4:
    lwzx(TMP1, EaSafe, GPRegs::r0);
    stw(TMP1, -16, r1);
    break;
  case 8:
    ldx(TMP1, EaSafe, GPRegs::r0);
    std(TMP1, -16, r1);
    break;
  default: break;
  }
  addi(TMP3, r1, -16);
  li(TMP1, 0);
  lvx(dst, TMP3, TMP1);
}

void PPC64EmitterBase::SpillForABICall(GPR tmp, bool FPRs) {
  SpillStaticRegs(tmp);
  PushDynamicRegs(tmp);
}

void PPC64EmitterBase::FillForABICall(bool FPRs) {
  PopDynamicRegs();
  FillStaticRegs();
  // r0 is volatile per the C ABI; the JIT relies on r0=0 as a "zero index" for
  // stdx/ldx-style instructions. Re-establish that invariant after every
  // host-ABI call.
  li(GPRegs::r0, 0);
}

} // namespace FEXCore::CPU
