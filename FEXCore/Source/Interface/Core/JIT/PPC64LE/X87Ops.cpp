// SPDX-License-Identifier: MIT
// PPC64LE x87 stack-bookkeeping IR ops for FEX JIT backend.
//
// Background
// ----------
// These ops (OP_INITSTACK / OP_INCSTACKTOP / OP_DECSTACKTOP / OP_INVALIDATESTACK
// / OP_PUSHSTACK / OP_COPYPUSHSTACK / OP_POPSTACKDESTROY / OP_READSTACKVALUE
// / OP_STOREMEMSTACK / OP_STORESTACKTOSTACK / OP_STACKVALIDTAG /
// OP_SYNCSTACKTOSLOW / OP_STACKFORCESLOW) are normally rewritten by
// Interface/IR/Passes/x87StackOptimizationPass.cpp into LoadContext /
// StoreContext / LoadMem / StoreMem primitives that the JIT already
// understands. The pass is gated on `!DisablePasses()`, so when the user runs
// with `O0` (or in any future configuration that doesn't run the pass) these
// ops survive to the JIT.
//
// In the previous PPC64LE backend none of them had a JIT handler nor a FABI
// fallback — they all routed to `Op_Unhandled` and silently did nothing,
// leaving destination registers (for OP_READSTACKVALUE / OP_STACKVALIDTAG /
// OP_SYNCSTACKTOSLOW) uninitialised. That's a quiet correctness landmine.
//
// This file implements the slow-path semantics directly in PPC64LE assembly,
// mirroring exactly what the optimisation pass would have emitted on its slow
// path. Conventions match `x87StackOptimizationPass.cpp`:
//
//   * x87 TOP register lives in `flags[X87FLAG_TOP_LOC]` (one byte, low 3 bits).
//   * Stack registers live in `mm[8][2]` (8 entries of 16 bytes). Logical st(N)
//     maps to physical mm[(TOP + N) & 7].
//   * `AbridgedFTW` is a one-byte register-indexed valid-tag bitmap: bit `i`
//     corresponds to mm[i] (NOT st(i)). Bit set = valid, bit clear = invalid.
//
// Sizes: every handler in this file assumes full precision — 80-bit values
// stored in the 16-byte mm slots. PushStack / ReadStackValue / etc. move full
// 16-byte vectors.
//
// This file does NOT assume ReducedPrecisionMode is absent, and an earlier
// version of this comment claiming it is "an upstream config we don't expect
// to encounter on PPC64LE" was wrong: `Source/Steam/ConfigTemplate.json` sets
// `X87ReducedPrecision: 1` for every Steam title, and the InstructionCountCI
// suite runs seven JSON files with `FEX_X87REDUCEDPRECISION=1`.
//
// What is actually true is narrower and is what protects us: nothing in this
// file executes outside `FEX_O0`. x87StackOptimizationPass rewrites every
// X87:true op unconditionally and the pass is gated only on `!DisablePasses()`
// (see JIT.cpp:2359-2364), which is why ARM64 implements none of these ops at
// all. Reduced precision therefore never reaches these handlers on any normal
// configuration.
//
// If it ever did — `O0` together with reduced precision — the result would be
// silent numeric garbage, not a trap, because the stack slots would hold
// doubles while these handlers keep reading them as 80-bit values:
//   * F80StackChangeSign / F80StackAbs XOR/AND against the 80-bit sign bit at
//     byte 9 bit 7 (~:724); a double's sign bit is at byte 7 bit 7.
//   * StoreStackMem's inline path (~:371) splits the slot into an 8-byte
//     mantissa plus a 2-byte sign+exponent halfword read from bytes 8..9.
//   * Every arithmetic and transcendental handler routes through the
//     `OPINDEX_F80*` FABI helpers, which interpret their operands as 80-bit.
//   * F80PTANStack (~:694) pushes a literal 80-bit encoding of 1.0.
// Making this file reduced-precision-correct means a second set of handlers,
// not a size parameter. Nobody has needed one; the O0 gate is the reason.
//
// Note on r0 / addressing
// -----------------------
// PPC64LE indexed loads/stores treat RA=r0 as the literal value 0. We don't
// rely on r0 here — the formulas are all `STATE + computed_offset_in_TMP3`,
// so we use `... STATE, TMP3`.

#include "Interface/Context/Context.h"
#include "Interface/Core/JIT/PPC64LE/JITClass.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>

namespace FEXCore::CPU {

// Byte offset of the x87 TOP nibble inside CpuStateFrame.
static constexpr uint32_t X87_TOP_OFFSET =
    static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, flags) +
                          FEXCore::X86State::X87FLAG_TOP_LOC);

// Byte offset of AbridgedFTW (the per-register valid-tag bitmap).
static constexpr uint32_t X87_FTW_OFFSET =
    static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, AbridgedFTW));

// Byte offset of the x87 register file.
static constexpr uint32_t X87_MM_OFFSET =
    static_cast<uint32_t>(offsetof(FEXCore::Core::CPUState, mm));

// Compute (TOP + Offset) & 7 into `dst`. Loads TOP byte from CpuStateFrame
// and ANDs with 7 to be safe (the TOP byte is supposed to be 3 bits already
// but cannot trust the high nibble bits).
//   dst <- (load TOP) + Offset
//   dst <- dst & 7
// Clobbers TMP1 (only when X87_TOP_OFFSET is encoded via LoadConstant).
static inline void EmitLoadTopPlus(PPC64JITCore* self, GPR dst, uint8_t offset) {
  // X87_TOP_OFFSET fits in i16, so use lbz directly.
  self->lbz(dst, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  if (offset != 0) {
    self->addi(dst, dst, static_cast<int16_t>(offset));
  }
  // rldicl(dst, dst, 0, 61) masks low 3 bits without writing CR0.  Using
  // andi_ here would silently clobber the canonical packed-NZCV scratch
  // (CR0) on every x87 stack-top read.
  self->rldicl(dst, dst, 0, 61);
}

// Compute STATE + X87_MM_OFFSET + ((TOP + Offset) & 7) * 16 into `dst_ea`.
// Uses TMP3 internally for the multiplied index. Caller-owned `dst_ea` must
// not alias TMP3. Uses `tmp_idx` for the (TOP+Offset)&7 staging.
static inline void EmitMmEa(PPC64JITCore* self, GPR dst_ea, GPR tmp_idx, uint8_t offset) {
  // tmp_idx = (TOP + offset) & 7
  EmitLoadTopPlus(self, tmp_idx, offset);
  // dst_ea = STATE + X87_MM_OFFSET + tmp_idx*16
  self->sldi(dst_ea, tmp_idx, 4);                               // dst_ea = idx*16
  self->addi(dst_ea, dst_ea, static_cast<int16_t>(X87_MM_OFFSET)); // dst_ea += MMBase
  self->add(dst_ea, dst_ea, STATE);                             // dst_ea += STATE
}

// =========================================================================
// Trivial top-pointer manipulation
// =========================================================================

// OP_INITSTACK: reset TOP=0 and AbridgedFTW=0 (all tags invalid).
//
// Strictly conservative: when reached via a surviving InitStack op it implies
// the upstream FNINIT may not have flushed the slow-path state. Even if it
// did, a redundant zeroing is harmless.
DEF_OP(InitStack) {
  li(TMP1, 0);
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// OP_INCSTACKTOP: TOP = (TOP + 1) & 7.
DEF_OP(IncStackTop) {
  lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  addi(TMP1, TMP1, 1);
  rldicl(TMP1, TMP1, 0, 61);  // mask low 3 bits without writing CR0
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
}

// OP_DECSTACKTOP: TOP = (TOP - 1) & 7.
DEF_OP(DecStackTop) {
  lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  addi(TMP1, TMP1, -1);
  rldicl(TMP1, TMP1, 0, 61);  // mask low 3 bits without writing CR0
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
}

// OP_INVALIDATESTACK $StackLocation: clear the FTW bit corresponding to
// mm[(TOP+StackLocation)&7]. If $StackLocation == 0xff, clear all tags.
DEF_OP(InvalidateStack) {
  auto Op = IROp->C<IR::IROp_InvalidateStack>();
  if (Op->StackLocation == 0xff) {
    li(TMP1, 0);
    stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
    return;
  }
  // mask = ~(1u << ((TOP + StackLocation) & 7))
  // FTW &= mask
  EmitLoadTopPlus(this, TMP2, Op->StackLocation);   // TMP2 = (TOP+loc)&7
  li(TMP3, 1);
  sld(TMP3, TMP3, TMP2);                            // TMP3 = 1 << TMP2
  lbz(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  andc(TMP1, TMP1, TMP3);                           // TMP1 = TMP1 & ~TMP3
  stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// =========================================================================
// Tag query
// =========================================================================

// OP_STACKVALIDTAG $StackLocation -> GPR
//   Result = (FTW >> ((TOP + StackLocation) & 7)) & 1
DEF_OP(StackValidTag) {
  auto Op  = IROp->C<IR::IROp_StackValidTag>();
  auto Dst = GetReg(Node);

  EmitLoadTopPlus(this, TMP2, Op->StackLocation);
  lbz(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  srd(Dst, TMP1, TMP2);
  andi_(Dst, Dst, 1);
}

// =========================================================================
// Stack push/pop helpers (slow-path)
// =========================================================================

// Helper: set the FTW bit for register mm[(TOP+offset)&7] to 1 (valid).
// Clobbers TMP1, TMP2, TMP3.
static inline void EmitSetTagValid(PPC64JITCore* self, uint8_t offset) {
  EmitLoadTopPlus(self, /*tmp_idx=*/TMP2, offset);
  self->li(TMP3, 1);
  self->sld(TMP3, TMP3, TMP2);                                // TMP3 = 1 << idx
  self->lbz(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  self->or_(TMP1, TMP1, TMP3);
  self->stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// OP_PUSHSTACK X80Src, OriginalValue, LoadSize
//   - First decrement TOP (TOP = (TOP - 1) & 7).
//   - Store X80Src (an FPR) to mm[TOP].
//   - Mark the corresponding FTW bit valid.
//
// OriginalValue is a tracking field used only on the fast path of the
// optimisation pass; the slow path discards it. LoadSize is informational.
// We store the full 128-bit FPR — the IR's OP_PUSHSTACK FPR is 128-bit when
// not in ReducedPrecisionMode (which is the only mode supported here).
DEF_OP(PushStack) {
  auto Op  = IROp->C<IR::IROp_PushStack>();
  auto Src = GetVReg(Op->X80Src);

  // Decrement TOP
  lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  addi(TMP1, TMP1, -1);
  andi_(TMP1, TMP1, 7);
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);

  // Store at mm[TMP1]: EA = STATE + X87_MM_OFFSET + TMP1*16
  // We can reuse TMP1 (the new TOP value) directly as the index.
  sldi(TMP2, TMP1, 4);                            // TMP2 = TMP1 * 16
  addi(TMP2, TMP2, static_cast<int16_t>(X87_MM_OFFSET));
  // mm is 16-byte aligned; stvx with EA = STATE + TMP2 lands on a 16B boundary.
  stvx(Src, STATE, TMP2);

  // Mark valid: FTW |= (1 << TMP1).
  // TMP1 still holds the index.
  li(TMP3, 1);
  sld(TMP3, TMP3, TMP1);
  lbz(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  or_(TMP2, TMP2, TMP3);
  stb(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// OP_COPYPUSHSTACK $StackLocation
//   tmp = mm[(TOP + StackLocation) & 7]   ; load before modifying TOP
//   TOP = (TOP - 1) & 7
//   mm[TOP] = tmp
//   FTW |= (1 << TOP)
DEF_OP(CopyPushStack) {
  auto Op = IROp->C<IR::IROp_CopyPushStack>();

  // 1. Load value from logical st(StackLocation) into VTMP1.
  EmitMmEa(this, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, Op->StackLocation);
  lvx(VTMP1, r(0), TMP4);                         // RA=0 → EA = TMP4

  // 2. Decrement TOP.
  lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  addi(TMP1, TMP1, -1);
  andi_(TMP1, TMP1, 7);
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);

  // 3. Store VTMP1 at mm[TMP1]. EA = STATE + X87_MM_OFFSET + TMP1*16.
  sldi(TMP2, TMP1, 4);
  addi(TMP2, TMP2, static_cast<int16_t>(X87_MM_OFFSET));
  stvx(VTMP1, STATE, TMP2);

  // 4. FTW |= 1 << TMP1.
  li(TMP3, 1);
  sld(TMP3, TMP3, TMP1);
  lbz(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  or_(TMP2, TMP2, TMP3);
  stb(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// OP_POPSTACKDESTROY: invalidate st(0), then TOP = (TOP+1)&7.
//
// Mirrors x87StackOptimizationPass slow-path: SetX87ValidTag(0, false);
// StackPop() (which is UpdateTopForPop_Slow → GetOffsetTopWithCache_Slow(1)).
DEF_OP(PopStackDestroy) {
  // 1. Clear the FTW bit for the current TOP.
  lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  andi_(TMP1, TMP1, 7);                              // TMP1 = TOP
  li(TMP3, 1);
  sld(TMP3, TMP3, TMP1);                             // TMP3 = 1 << TOP
  lbz(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  andc(TMP2, TMP2, TMP3);
  stb(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);

  // 2. TOP = (TOP + 1) & 7.
  addi(TMP1, TMP1, 1);
  andi_(TMP1, TMP1, 7);
  stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
}

// =========================================================================
// Stack reads & cross-stack stores
// =========================================================================

// OP_READSTACKVALUE $StackLocation -> FPR (128-bit)
//   Dst = mm[(TOP + StackLocation) & 7]
DEF_OP(ReadStackValue) {
  auto Op  = IROp->C<IR::IROp_ReadStackValue>();
  auto Dst = GetVReg(Node);

  EmitMmEa(this, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, Op->StackLocation);
  lvx(Dst, r(0), TMP4);
}

// OP_STORESTACKTOSTACK $StackLocation
//   if (StackLocation == 0) no-op
//   else mm[(TOP + StackLocation) & 7] = mm[TOP]
//        ; FTW bit for the destination becomes valid.
DEF_OP(StoreStackToStack) {
  auto Op = IROp->C<IR::IROp_StoreStackToStack>();
  if (Op->StackLocation == 0) {
    // Optimisation pass does the same early-out.
    return;
  }

  // 1. Load mm[TOP] into VTMP1.
  EmitMmEa(this, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, /*offset=*/0);
  lvx(VTMP1, r(0), TMP4);

  // 2. Compute EA for st(StackLocation) destination.
  EmitMmEa(this, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, Op->StackLocation);
  stvx(VTMP1, r(0), TMP4);

  // 3. Mark destination valid. TMP2 still holds (TOP+loc)&7 from EmitMmEa.
  li(TMP3, 1);
  sld(TMP3, TMP3, TMP2);
  lbz(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  or_(TMP1, TMP1, TMP3);
  stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// OP_STORESTACKMEM (a.k.a. StoreMemStack) — store the top of the x87 stack
// to memory.
//
// Conservatism note: full ARM64 implementation handles three SourceSize ×
// three StoreSize × ReducedPrecision combinations, plus 80→32/64 rounding via
// F80 helper functions. The 80→64/32 conversions in particular require
// `softfloat`-style helper calls that we don't have wired up on PPC64LE.
//
// To avoid silently producing incorrect numeric results we trap loudly on
// the conversion paths and only inline the same-size (raw 80-bit blob)
// store path. That covers `fstp tword [mem]` from a stack value that's
// already 80-bit, while loudly rejecting `fstp dword`/`fstp qword` that
// would need rounding. Better a clear SIGTRAP than silent FP corruption.
//
// SourceSize is f80Bit, not i128Bit. IR.json's prose says "SourceSize is
// 128bit for F80 values", but the sole emitter — OpcodeDispatcher/X87.cpp
// FST() at :129-133 — passes `ReducedPrecisionMode ? OpSize::i64Bit :
// OpSize::f80Bit`. f80Bit is 10 and i128Bit is 16 (IR/IR.h:498-508), so
// testing against i128Bit made the guard unsatisfiable and trapped every
// fst/fstp to memory.
DEF_OP(StoreStackMem) {
  auto Op = IROp->C<IR::IROp_StoreStackMem>();

  if (Op->StoreSize != IR::OpSize::f80Bit || Op->SourceSize != IR::OpSize::f80Bit) {
    // Unsupported conversion path — emit a trap. 0x7FE00008 is `trap` (tw 31,r0,r0),
    // an unconditional program-check on PPC64. This is the project-wide
    // convention for "I don't know what this means; fail loudly".
    Emit32(0x7FE00008);
    return;
  }

  // Build EA = Addr + Offset (scaled).
  auto Addr = GetReg(Op->Addr);
  GPR EA;
  if (Op->Offset.IsInvalid()) {
    EA = Addr;
  } else {
    EA = ComputeAddress(Addr, Op->Offset, Op->OffsetType, Op->OffsetScale);
  }

  // Load mm[TOP] into VTMP1.
  EmitMmEa(this, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, /*offset=*/0);
  lvx(VTMP1, r(0), TMP4);

  // 80-bit store = 10 bytes (mantissa 8 + sign+exp 2). PPC64LE has no 10-byte
  // memory-store, so split: spill VTMP1 to a 16-byte aligned host scratch at
  // r1-16, then read 8+2 bytes from the LSB end and write those exactly to EA.
  // Done after EmitMmEa/lvx so they cannot clobber EA (which may be TMP3 from
  // ComputeAddress); EmitMmEa writes only TMP4/TMP2 per its contract.
  addi(TMP1, r1, -16);
  stvx(VTMP1, r(0), TMP1);
  ld(TMP4, 0, TMP1);                 // LE bytes 0..7 (mantissa)
  lhz(TMP2, 8, TMP1);                // LE bytes 8..9 (sign + exponent)
  std(TMP4, 0, EA);
  sth(TMP2, 8, EA);
}

// =========================================================================
// SyncStackToSlow / StackForceSlow
// =========================================================================

// OP_SYNCSTACKTOSLOW -> GPR (current stack top).
//
// Per the optimisation pass: this op is normally consumed during the pass
// itself (it materialises the cached TOP value if any, otherwise loads from
// the context). When it survives to the JIT — meaning the pass didn't run —
// there's no virtual stack to flush; everything already lives in the slow
// path's CpuStateFrame. The semantics reduce to "return current TOP value".
DEF_OP(SyncStackToSlow) {
  auto Dst = GetReg(Node);
  lbz(Dst, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  andi_(Dst, Dst, 7);
}

// OP_STACKFORCESLOW: side-effect-only marker that tells the optimisation
// pass to abandon the fast path. After the pass runs everything is already
// "slow-path", so when this op survives to the JIT it has no remaining
// observable effect. Emit nothing.
DEF_OP(StackForceSlow) {
  // No-op.
}

// =========================================================================
// Bucket C: stack-form arithmetic ops
// =========================================================================
//
// These ops normally vanish via x87StackOptimizationPass; under O0 (or any
// path that skips the pass) they survive to the JIT. They're thin wrappers
// around the existing F80* fallback handlers — load operand(s) from x87
// stack slot(s), call the FABI handler, store result(s) back.
//
// All semantics mirror x87StackOptimizationPass.cpp's slow-path lowering.
// Stack reads/writes assume non-reduced precision (full 16-byte slots).

// Helper: load mm[(TOP+offset)&7] into the given vector register.
// Clobbers TMP2, TMP4.
static inline void LoadStackSlot(PPC64JITCore* self, VR dst, uint8_t offset) {
  EmitMmEa(self, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, offset);
  self->lvx(dst, r(0), TMP4);
}

// Helper: store the given vector to mm[(TOP+offset)&7] AND set its FTW tag
// valid. If `set_tag_valid` is false, only the store happens.
// Clobbers TMP1, TMP2, TMP3, TMP4.
static inline void StoreStackSlot(PPC64JITCore* self, VR src, uint8_t offset, bool set_tag_valid = true) {
  EmitMmEa(self, /*dst_ea=*/TMP4, /*tmp_idx=*/TMP2, offset);
  self->stvx(src, r(0), TMP4);
  if (set_tag_valid) {
    // TMP2 still holds (TOP+offset)&7.
    self->li(TMP3, 1);
    self->sld(TMP3, TMP3, TMP2);
    self->lbz(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
    self->or_(TMP1, TMP1, TMP3);
    self->stb(TMP1, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  }
}

// Helper: emit a call to a fallback handler whose ABIHandler/Func live in
// CpuStateFrame.Pointers.FallbackHandlerPointers[OpIndex]. Mirrors the
// frame-build pattern in Op_Unhandled (JIT.cpp). Source vectors must already
// be staged in VTMP1 (and VTMP2 for binary handlers). Result returns:
//   - vector handlers (FABI_F80_I16_F80*) → VTMP1
//   - GPR handlers (FABI_I64_I16_F80_F80_PTR for F80Cmp) → TMP1
//   - SINCOS pair (FABI_F80x2_I16_F80_PTR) → VTMP1 (sin), VTMP2 (cos)
//
// Clobbers r0, TMP1, TMP2, TMP3, TMP4. Caller is responsible for moving the
// result out of VTMP1/TMP1 if it needs to be preserved across subsequent ops.
static inline void EmitFABICall(PPC64JITCore* self, FEXCore::Core::FallbackHandlerIndex Idx) {
  const uint32_t ABIHandlerOff = static_cast<uint32_t>(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, Idx) +
    offsetof(FEXCore::Core::FallbackABIInfo, ABIHandler));
  const uint32_t FuncOff = static_cast<uint32_t>(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers, Idx) +
    offsetof(FEXCore::Core::FallbackABIInfo, Func));

  // Save LR via TMP2; use 512-byte frame to protect JIT spill slots.
  self->mflr(TMP2); self->addi(r1, r1, -512); self->std(TMP2, 0, r1);
  // Volatile dynamic VRs are caller-saved around ABIPointers stubs (the stubs
  // emit Push/PopDynamicRegs under an empty VR mask — DynVRSpillMask contract,
  // PPC64Emitter.h). Live set at [r1+16..]: worst case 12 regs = 208 bytes,
  // inside the 512-byte frame. Clobbers TMP3 (already in this helper's
  // contract); sources were staged in VTMP1/VTMP2 before this call and VTMPs
  // are not in the saved pool.
  self->SaveDynVRsToFrame(16);
  // See JIT.cpp Op_Unhandled for the identical rationale; d-form `ld` here removes a silent
  // uint32_t→int16_t hazard and the TMP2 serialisation in front of mtctr/bctrl.
  static_assert(
    ARRAY_OFFSETOF(FEXCore::Core::CpuStateFrame, Pointers.FallbackHandlerPointers,
                   FEXCore::Core::FallbackHandlerIndex::OPINDEX_MAX - 1)
      + offsetof(FEXCore::Core::FallbackABIInfo, Func) <= INT16_MAX,
    "FABI helper offsets must fit int16_t for d-form ld");
  self->ld(r(0), static_cast<int16_t>(ABIHandlerOff), STATE);
  self->ld(TMP4, static_cast<int16_t>(FuncOff), STATE);
  // Sources are already in VTMP1 / (VTMP2 for binary) per the contract above.
  self->mtctr(r(0)); self->bctrl();
  self->RestoreDynVRsFromFrame(16);
  self->ld(TMP2, 0, r1); self->mtlr(TMP2); self->addi(r1, r1, 512); self->li(r(0), 0);
}

// Binary stack-form: dst_stack = op(stack[s1], stack[s2]).
static inline void BinaryStackOp(PPC64JITCore* self, FEXCore::Core::FallbackHandlerIndex Idx,
                                  uint8_t dst_stack, uint8_t src1, uint8_t src2) {
  LoadStackSlot(self, VTMP1, src1);
  LoadStackSlot(self, VTMP2, src2);
  EmitFABICall(self, Idx);
  StoreStackSlot(self, VTMP1, dst_stack);
}

// Binary value-form: dst_stack = op(stack[src_stack], value)  (or reversed).
// `reverse` swaps the operands for SubR/DivR.
static inline void BinaryValueOp(PPC64JITCore* self, FEXCore::Core::FallbackHandlerIndex Idx,
                                  uint8_t dst_stack, uint8_t src_stack, VR value, bool reverse) {
  if (reverse) {
    self->vmr(VTMP1, value);
    LoadStackSlot(self, VTMP2, src_stack);
  } else {
    LoadStackSlot(self, VTMP1, src_stack);
    self->vmr(VTMP2, value);
  }
  EmitFABICall(self, Idx);
  StoreStackSlot(self, VTMP1, dst_stack);
}

// Unary stack-form: stack[0] = op(stack[0]).
static inline void UnaryStack0Op(PPC64JITCore* self, FEXCore::Core::FallbackHandlerIndex Idx) {
  LoadStackSlot(self, VTMP1, 0);
  EmitFABICall(self, Idx);
  StoreStackSlot(self, VTMP1, 0);
}

// Stack pop helper: invalidate st(0) tag, TOP = (TOP+1)&7. Mirrors
// PopStackDestroy. Clobbers TMP1, TMP2, TMP3.
static inline void EmitStackPop(PPC64JITCore* self) {
  self->lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  self->andi_(TMP1, TMP1, 7);
  self->li(TMP3, 1);
  self->sld(TMP3, TMP3, TMP1);
  self->lbz(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  self->andc(TMP2, TMP2, TMP3);
  self->stb(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  self->addi(TMP1, TMP1, 1);
  self->andi_(TMP1, TMP1, 7);
  self->stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
}

// Stack push helper: TOP = (TOP-1)&7, store src at new TOP, set tag valid.
// Clobbers TMP1, TMP2, TMP3.
static inline void EmitStackPush(PPC64JITCore* self, VR src) {
  self->lbz(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  self->addi(TMP1, TMP1, -1);
  self->andi_(TMP1, TMP1, 7);
  self->stb(TMP1, static_cast<int16_t>(X87_TOP_OFFSET), STATE);
  self->sldi(TMP2, TMP1, 4);
  self->addi(TMP2, TMP2, static_cast<int16_t>(X87_MM_OFFSET));
  self->stvx(src, STATE, TMP2);
  self->li(TMP3, 1);
  self->sld(TMP3, TMP3, TMP1);
  self->lbz(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
  self->or_(TMP2, TMP2, TMP3);
  self->stb(TMP2, static_cast<int16_t>(X87_FTW_OFFSET), STATE);
}

// -------------------------------------------------------------------------
// Priority 1: Add/Sub/Mul/Div stack-form & value-form
// -------------------------------------------------------------------------

DEF_OP(F80AddStack) {
  auto Op = IROp->C<IR::IROp_F80AddStack>();
  // Pass mirrors: HandleBinopStack(..., DstStack=Op->SrcStack1, Op->SrcStack1, Op->SrcStack2)
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80ADD, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
}

DEF_OP(F80SubStack) {
  auto Op = IROp->C<IR::IROp_F80SubStack>();
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80SUB, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
}

DEF_OP(F80MulStack) {
  auto Op = IROp->C<IR::IROp_F80MulStack>();
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80MUL, Op->SrcStack1, Op->SrcStack1, Op->SrcStack2);
}

DEF_OP(F80DivStack) {
  auto Op = IROp->C<IR::IROp_F80DivStack>();
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80DIV, Op->DstStack, Op->SrcStack1, Op->SrcStack2);
}

DEF_OP(F80AddValue) {
  auto Op = IROp->C<IR::IROp_F80AddValue>();
  // Pass: HandleBinopValue(..., DstStack=0, ..., Op->SrcStack, X80Src). Result lands at TOP (=stack[0]).
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80ADD, /*dst*/0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/false);
}

DEF_OP(F80SubValue) {
  auto Op = IROp->C<IR::IROp_F80SubValue>();
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80SUB, 0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/false);
}

DEF_OP(F80SubRValue) {
  auto Op = IROp->C<IR::IROp_F80SubRValue>();
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80SUB, 0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/true);
}

DEF_OP(F80MulValue) {
  auto Op = IROp->C<IR::IROp_F80MulValue>();
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80MUL, 0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/false);
}

DEF_OP(F80DivValue) {
  auto Op = IROp->C<IR::IROp_F80DivValue>();
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80DIV, 0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/false);
}

DEF_OP(F80DivRValue) {
  auto Op = IROp->C<IR::IROp_F80DivRValue>();
  BinaryValueOp(this, FEXCore::Core::OPINDEX_F80DIV, 0, Op->SrcStack, GetVReg(Op->X80Src), /*reverse*/true);
}

// -------------------------------------------------------------------------
// Priority 2: compare/test (return GPR)
// -------------------------------------------------------------------------

// F80CmpStack: compare st(0) with st(SrcStack), return packed flag GPR.
// Underlying handler is F80CMP (FABI_I64_I16_F80_F80_PTR) → result in TMP1.
DEF_OP(F80CmpStack) {
  auto Op = IROp->C<IR::IROp_F80CmpStack>();
  auto Dst = GetReg(Node);
  LoadStackSlot(this, VTMP1, 0);
  LoadStackSlot(this, VTMP2, Op->SrcStack);
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80CMP);
  mr(Dst, TMP1);
}

DEF_OP(F80CmpValue) {
  auto Op = IROp->C<IR::IROp_F80CmpValue>();
  auto Dst = GetReg(Node);
  LoadStackSlot(this, VTMP1, 0);
  vmr(VTMP2, GetVReg(Op->X80Src));
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80CMP);
  mr(Dst, TMP1);
}

// F80StackTest: compare st(SrcStack) with 0, return packed flag GPR.
// We synthesise the zero by xor'ing VTMP2 with itself.
DEF_OP(F80StackTest) {
  auto Op = IROp->C<IR::IROp_F80StackTest>();
  auto Dst = GetReg(Node);
  LoadStackSlot(this, VTMP1, Op->SrcStack);
  vxor(VTMP2, VTMP2, VTMP2);
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80CMP);
  mr(Dst, TMP1);
}

// -------------------------------------------------------------------------
// Priority 3: transcendentals & long-latency on st(0)
// -------------------------------------------------------------------------

DEF_OP(F80SQRTStack)  { UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80SQRT); }
DEF_OP(F80SINStack)   { UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80SIN); }
DEF_OP(F80COSStack)   { UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80COS); }
DEF_OP(F80F2XM1Stack) { UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80F2XM1); }
DEF_OP(F80RoundStack) { UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80ROUND); }

// F80SINCOSStack: sin → st(0), then push cos.
// FABI_F80x2_I16_F80_PTR returns sin in VTMP1, cos in VTMP2.
DEF_OP(F80SINCOSStack) {
  LoadStackSlot(this, VTMP1, 0);
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80SINCOS);
  // VTMP1 = sin, VTMP2 = cos. StoreStackSlot/EmitStackPush only clobber TMPx
  // GPRs, so VTMP2 survives until we push it.
  StoreStackSlot(this, VTMP1, 0);
  EmitStackPush(this, VTMP2);
}

// F80FYL2XStack: st(1) = st(1) * log2(st(0)); pop. Result therefore goes to
// the *new* st(0) post-pop, i.e. mm[(TOP+1)&7] before the pop.
DEF_OP(F80FYL2XStack) {
  // VTMP1 = st(0), VTMP2 = st(1) per F80FYL2X handler signature (X80Src1 is
  // the multiplier — st(1) — and X80Src2 is the log argument — st(0)).
  // Actually pass: HandleBinopStack(..., F80FYL2X, dst=1, src1=0, src2=1)
  // means handler called with VTMP1=stack[0], VTMP2=stack[1], result→stack[1].
  LoadStackSlot(this, VTMP1, 0);
  LoadStackSlot(this, VTMP2, 1);
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80FYL2X);
  StoreStackSlot(this, VTMP1, 1);
  EmitStackPop(this);
}

// F80ATANStack: st(1) = atan(st(1)/st(0)); pop. Pass: dst=1, src1=1, src2=0.
DEF_OP(F80ATANStack) {
  LoadStackSlot(this, VTMP1, 1);
  LoadStackSlot(this, VTMP2, 0);
  EmitFABICall(this, FEXCore::Core::OPINDEX_F80ATAN);
  StoreStackSlot(this, VTMP1, 1);
  EmitStackPop(this);
}

// F80SCALEStack: HandleBinopStack(..., F80SCALE, dst=0, src1=0, src2=1).
DEF_OP(F80SCALEStack) {
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80SCALE, 0, 0, 1);
}

DEF_OP(F80FPREMStack) {
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80FPREM, 0, 0, 1);
}

DEF_OP(F80FPREM1Stack) {
  BinaryStackOp(this, FEXCore::Core::OPINDEX_F80FPREM1, 0, 0, 1);
}

// F80PTANStack: st(0) = tan(st(0)); push 1.0.
DEF_OP(F80PTANStack) {
  // Compute tan into st(0).
  UnaryStack0Op(this, FEXCore::Core::OPINDEX_F80TAN);
  // Push 1.0 in 80-bit form. Encoding (little-endian byte layout in 128b slot):
  //   bytes 0-7  = mantissa 0x8000000000000000
  //   bytes 8-9  = exponent 0x3FFF
  //   bytes 10-15 = padding 0
  // r1 is 16B-aligned per ELFv2, so r1-16 is too — safe for lvx.
  addi(r1, r1, -16);
  li(TMP1, 0);     std(TMP1, 8, r1);                  // zero high half (incl. exp slot)
  li(TMP1, 1);     sldi(TMP1, TMP1, 63);
  std(TMP1, 0, r1);                                   // mantissa
  li(TMP1, 0x3FFF);
  sth(TMP1, 8, r1);                                   // exponent half-word
  lvx(VTMP1, r(0), r1);
  addi(r1, r1, 16);
  EmitStackPush(this, VTMP1);
}

// -------------------------------------------------------------------------
// Priority 4: rare ops & sign manipulation
// -------------------------------------------------------------------------

// F80StackXchange: swap st(0) with st(SrcStack).
DEF_OP(F80StackXchange) {
  auto Op = IROp->C<IR::IROp_F80StackXchange>();
  if (Op->SrcStack == 0) return;
  LoadStackSlot(this, VTMP1, 0);
  LoadStackSlot(this, VTMP2, Op->SrcStack);
  StoreStackSlot(this, VTMP2, 0);
  StoreStackSlot(this, VTMP1, Op->SrcStack);
}

// F80StackChangeSign: flip sign bit of st(0); return new st(0) value.
// 80-bit sign bit lives at byte offset 9 bit 7 (the high bit of the exponent
// half-word). Easiest: XOR with the F80_SIGN_MASK named-vector constant. We
// don't have a clean way to load that constant inline here without the IR
// emitter, so build the mask manually: a 16-byte vector with byte 9 = 0x80,
// other bytes 0.
DEF_OP(F80StackChangeSign) {
  auto Dst = GetVReg(Node);
  LoadStackSlot(this, VTMP1, 0);
  // Build sign-mask in VTMP2 on stack.
  addi(r1, r1, -16);
  li(TMP1, 0); std(TMP1, 0, r1); std(TMP1, 8, r1);
  li(TMP1, 0x80);
  stb(TMP1, 9, r1);
  lvx(VTMP2, r(0), r1);
  addi(r1, r1, 16);
  vxor(VTMP1, VTMP1, VTMP2);
  StoreStackSlot(this, VTMP1, 0);
  vmr(Dst, VTMP1);
}

// F80StackAbs: clear sign bit of st(0); return new st(0) value.
DEF_OP(F80StackAbs) {
  auto Dst = GetVReg(Node);
  LoadStackSlot(this, VTMP1, 0);
  // Build mask = ~SIGN in VTMP2: byte 9 = 0x7F, all other bytes 0xFF.
  addi(r1, r1, -16);
  li(TMP1, -1); std(TMP1, 0, r1); std(TMP1, 8, r1);
  li(TMP1, 0x7F);
  stb(TMP1, 9, r1);
  lvx(VTMP2, r(0), r1);
  addi(r1, r1, 16);
  vand(VTMP1, VTMP1, VTMP2);
  StoreStackSlot(this, VTMP1, 0);
  vmr(Dst, VTMP1);
}

// F80VBSLStack: vector bit-select used by FXAM classification —
//   stack[SrcStack1] = (mask & stack[SrcStack1]) | (~mask & stack[SrcStack2])
// Tag-validity rule from pass: mark valid only if both stack offsets nonzero.
DEF_OP(F80VBSLStack) {
  auto Op = IROp->C<IR::IROp_F80VBSLStack>();
  auto Mask = GetVReg(Op->VectorMask);
  LoadStackSlot(this, VTMP1, Op->SrcStack1);
  LoadStackSlot(this, VTMP2, Op->SrcStack2);
  // Want stack[SrcStack1] = (Mask & VTMP1) | (~Mask & VTMP2). vsel encoding:
  // vsel rT, rA, rB, rC  →  rT[i] = rC[i] ? rB[i] : rA[i]. So we need
  // vsel(dst, VTMP2, VTMP1, Mask) — dst can safely alias VTMP1 since the
  // computation reads its inputs before writing the output.
  vsel(VTMP1, VTMP2, VTMP1, Mask);
  // Store back; the pass writes to TOP (offset 0), but conditionally tags
  // valid based on (SrcStack1 && SrcStack2). Match that.
  bool SetValid = (Op->SrcStack1 != 0) && (Op->SrcStack2 != 0);
  StoreStackSlot(this, VTMP1, 0, SetValid);
}

// -------------------------------------------------------------------------
// Native conversions
// -------------------------------------------------------------------------

// F80CVTTo: f64 (or f32) → f80, no rounding involved — every binary64 value
// is exactly representable in binary80, so this is pure bit manipulation.
// Lowered natively because it is the hottest fallback in ReducedPrecisionMode:
// FXSAVE/FNSAVE convert all eight f64 stack slots to the 80-bit memory format,
// and wine's syscall dispatcher runs FXSAVE on every win32↔unix transition,
// so the softfloat helper call (f64_to_extF80) showed up at ~4.5% of
// Cyberpunk 2077's game thread.
//
// Output layout matches VLoadTwoGPRs: mantissa (explicit integer bit at 63)
// in LE element 0, sign|15-bit-exponent halfword in LE element 1.
//
// Deliberate divergence from the softfloat helper: an SNaN's quiet bit is NOT
// set during the conversion (softfloat forces bit 62 and raises invalid; see
// s_commonNaNToExtF80UI.c). That matches hardware FSTP-m80 (raw register
// store) and is the correct behaviour for FXSAVE — a context save must
// round-trip the register file exactly — but it would change full-precision
// FLD m64 of an SNaN, where hardware (and the helper) quiet on conversion.
// So the native path is gated to ReducedPrecisionMode, whose f64 pipeline
// already keeps SNaN bits intact at loads.
DEF_OP(F80CVTTo) {
  auto Op = IROp->C<IR::IROp_F80CVTTo>();

  if (Op->SrcSize != IR::OpSize::i64Bit || !CTX->Config.x87ReducedPrecision()) {
    // f32 sources and full-precision mode keep the FABI softfloat fallback
    // (full precision needs the SNaN-quieting FLD semantics).
    Op_Unhandled(IROp, Node);
    return;
  }

  const auto Dst = GetVReg(Node);
  const auto Src = GetVReg(Op->X80Src);

  // Scalar f64 lives at LE element 0 = physical bytes [8..15]; rotate so
  // mfvsrd (which reads physical [0..7]) sees it.
  vsldoi(VTMP1, Src, Src, 8);
  mfvsrd(TMP1, VTMP1);

  // TMP2 = sign bit moved from bit 63 to bit 15.
  srdi(TMP2, TMP1, 48);
  andi_(TMP2, TMP2, 0x8000);

  rldicl(TMP3, TMP1, 12, 53); // TMP3 = biased 11-bit exponent (bits 62:52)
  rldicl(TMP4, TMP1, 0, 12);  // TMP4 = 52-bit fraction (bits 51:0)

  Label ZeroOrDenormal, Normal, Merge, Done;
  cmpdi(TMP3, 0);
  bc(CC_EQ, &ZeroOrDenormal);
  cmpdi(TMP3, 0x7ff);
  bc(CC_NE, &Normal);

  // Inf/NaN: exponent saturates; mantissa path below preserves the payload
  // (f64 quiet bit 51 lands on f80 quiet bit 62 after the <<11).
  li(TMP3, 0x7fff);
  b(&Merge);

  Bind(&Normal);
  addi(TMP3, TMP3, 16383 - 1023); // rebias

  Bind(&Merge);
  // Mantissa = (fraction << 11) | explicit integer bit.
  sldi(TMP4, TMP4, 11);
  li(TMP1, 1);
  sldi(TMP1, TMP1, 63);
  or_(TMP4, TMP4, TMP1);
  or_(TMP2, TMP2, TMP3);
  b(&Done);

  Bind(&ZeroOrDenormal);
  cmpdi(TMP4, 0);
  bc(CC_EQ, &Done); // ±0: mantissa 0, exponent 0, sign already in TMP2.
  // Denormal: value = fraction × 2^-1074. Normalise the fraction to bit 63;
  // the result is always a normal f80 (its exponent range is far wider).
  //   mantissa = fraction << n            (n = clz, ≥ 12 since fraction < 2^52)
  //   exponent = 16383 + 63 - 1074 - n = 15372 - n
  cntlzd(TMP3, TMP4);
  sld(TMP4, TMP4, TMP3);
  subfic(TMP3, TMP3, 15372);
  or_(TMP2, TMP2, TMP3);

  Bind(&Done);
  // Assemble per VLoadTwoGPRs: Hi (sign|exp) → LE element 1, Lo (mantissa) →
  // LE element 0.
  mtvsrd(VTMP1, TMP2);
  mtvsrd(VTMP2, TMP4);
  xxpermdi(Dst, VTMP1, VTMP2, 0);
}

} // namespace FEXCore::CPU
