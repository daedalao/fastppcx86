// SPDX-License-Identifier: MIT
// PPC64LE immediate-encodability predicates for the IR frontend.
#pragma once

#include "Interface/IR/IR.h"

#include <bit>
#include <cstdint>
#include <cstdlib>

namespace FEXCore::IR::PPC64 {

// ===========================================================================
// WHY THIS FILE EXISTS
// ===========================================================================
// IREmitter's `Inline*` helpers decide which constants become _InlineConstant
// nodes -- operands folded into whatever the backend can encode -- and which
// stay `Constant` nodes, materialised once into an ALLOCATED register and
// CSE'd through IREmitter::Constant's dedup table.
//
// That decision used to be made entirely with AArch64 encodability tests
// (ARMEmitter::IsImmAddSub, ARM's repeating-bitmask IsImmLogical), which is
// wrong for this backend in both directions at once:
//
//  * STARVATION. IsImmAddSub accepts only 0..0xFFF and multiples of 0x1000 up
//    to 0xFFF000. PPC's D-form immediate is a SIGNED 16-bit field, so every
//    negative compare immediate (`cmp eax,-1`), everything in [0x1000,0x7FFF]
//    that is not a multiple of 0x1000 (loop bounds, struct offsets past 4K),
//    and every unsigned compare up to 0xFFFF was rejected and forced into a
//    register. In x86-64 mode this backend has exactly FIVE dynamic GPRs --
//    r24, r25, r26, r30, r31 (ArchHelpers/PPC64Emitter.h, x64::RA) -- so a
//    constant pinned in one of those is 20% of the pool, and the marginal one
//    spills.
//
//  * OVER-FEEDING. ARM's logical-immediate encoding accepts every rotation of
//    a repeated run of ones, including shapes such as 0x0000FFFF0000FFFF that
//    PPC cannot express in any single instruction. Those were inlined and then
//    rebuilt with a 4-5 instruction LoadImm64 on EVERY EXECUTION of the block,
//    where a Constant node would have paid for it exactly once.
//
// ===========================================================================
// THE CRITERION
// ===========================================================================
// Inline iff the backend lowers the operand in AT MOST ONE EXTRA host
// instruction versus the register form, using only scratch registers and never
// an allocatable one. "One extra instruction, one fewer allocatable register"
// is the trade these predicates are calibrated to; anything past that loses,
// because on this port emitted instruction count tracks wall clock roughly 1:1
// (docs: the emulation tax is instruction expansion at ~97.7% of native IPC),
// while a Constant node's materialisation is paid once and shared.
//
// Concretely, a constant is "one instruction to materialise" when LoadImm64
// lowers it to a single `li` or a single `lis` (CodeEmitter/PPC64LE/Emitter.h):
//   li  rt, X          X is a sign-extended signed 16-bit value
//   lis rt, X >> 16    X is a sign-extended signed 32-bit value with the low
//                      16 bits clear
// Everything else in LoadImm64 costs two or more, and is deliberately declined
// unless a D-form or rotate-and-mask form absorbs it for free.
//
// These predicates must agree exactly with what JIT/PPC64LE lowers -- an
// inlined constant the backend cannot fold is strictly worse than no inlining
// at all -- so ClassifyAndMask below is shared verbatim with DEF_OP(And) /
// DEF_OP(Andn) rather than restated there.
// ===========================================================================

// ---------------------------------------------------------------------------
// Field-fit helpers. All take the raw 64-bit constant; PPC sign-extends every
// D-form SI field, so "fits" always means "is the sign extension of".
// ---------------------------------------------------------------------------
constexpr bool IsSImm16(uint64_t X) {
  const int64_t V = static_cast<int64_t>(X);
  return V >= -32768 && V <= 32767;
}

constexpr bool IsSImm32(uint64_t X) {
  const int64_t V = static_cast<int64_t>(X);
  return V >= INT32_MIN && V <= INT32_MAX;
}

// Materialises in exactly one host instruction: `li` or `lis`.
constexpr bool IsOneInsnConstant(uint64_t X) {
  return IsSImm16(X) || (IsSImm32(X) && (X & 0xFFFFull) == 0);
}

// The ones of V form a single contiguous run. Same identity LoadImm64 uses for
// its `li -1 ; rldic` path: for a non-zero V, popcount + leading zeros +
// trailing zeros sums to the width iff there is exactly one run.
constexpr bool IsRun64(uint64_t V) {
  return V != 0 && (std::popcount(V) + std::countl_zero(V) + std::countr_zero(V)) == 64;
}

constexpr bool IsRun32(uint32_t V) {
  return V != 0 && (std::popcount(V) + std::countl_zero(V) + std::countr_zero(V)) == 32;
}

// ---------------------------------------------------------------------------
// AND-mask classification.
//
// PPC does contiguous-run masking in ONE instruction with no scratch register
// and -- unlike andi./andis. -- with Rc=0, so it does not wipe the packed NZCV
// that LoadNZCV consumers read out of CR0. See the ban on andi./andis. in
// DEF_OP(And).
//
// Bit numbering: the Power ISA numbers bits big-endian (bit 0 = MSB) and MB /
// ME / SH are all BE indices, while every mask below is reasoned about in LE
// (bit 0 = LSB). BE i == LE 63-i for the doubleword forms, BE i == LE 31-i for
// the word form. The conversions are spelled out per case.
// ---------------------------------------------------------------------------
enum class AndMaskKind : uint8_t {
  None = 0,
  // li Dst, 0                                       -- mask is 0
  Zero,
  // mr Dst, S1 (elided when Dst == S1)              -- mask is all ones
  Move,
  // rldicl Dst, S1, 0, MB                           -- keep the low bits
  ClearLeft,
  // rldicr Dst, S1, 0, ME                           -- keep the high bits
  ClearRight,
  // rlwinm Dst, S1, 0, MB, ME                       -- word mask, MB <= ME only
  //                                                    (never wrapping), i32 ops
  //                                                    only, zero-extends
  Word,
  // [mr Dst, S1 ;] rldimi Dst, r0, SH, MB           -- punch a field of zeros
  InsertZeroField,
  // rldicl Dst, S1, 0, MB ; rldicr Dst, Dst, 0, ME  -- keep a middle field
  ClearBoth,
};

struct AndMaskForm {
  AndMaskKind Kind {AndMaskKind::None};
  uint8_t MB {0};
  uint8_t ME {0};
  uint8_t SH {0};
};

// AllowWord gates the 32-bit `rlwinm` form; see the long note at that case.
constexpr AndMaskForm ClassifyAndMask64(uint64_t M, bool AllowWord) {
  if (M == 0) {
    return {AndMaskKind::Zero, 0, 0, 0};
  }
  if (M == ~0ull) {
    return {AndMaskKind::Move, 0, 0, 0};
  }

  // Low run, M == 2^k - 1. rldicl RA,RS,0,MB keeps BE MB..63 == LE (63-MB)..0,
  // i.e. the low 64-MB bits, so MB = 64 - k. M is neither 0 nor ~0 here, so
  // k is in 1..63 and MB lands in 1..63.
  if ((M & (M + 1)) == 0) {
    const unsigned k = static_cast<unsigned>(std::countr_one(M));
    return {AndMaskKind::ClearLeft, static_cast<uint8_t>(64 - k), 0, 0};
  }

  // High run, M == ~(2^t - 1). rldicr RA,RS,0,ME keeps BE 0..ME == LE
  // 63..(63-ME), i.e. clears the low 63-ME bits, so ME = 63 - t. t is in 1..63
  // for the same reason as above, so ME lands in 0..62.
  {
    const uint64_t NotM = ~M;
    if ((NotM & (NotM + 1)) == 0) {
      const unsigned t = static_cast<unsigned>(std::countr_one(NotM));
      return {AndMaskKind::ClearRight, 0, static_cast<uint8_t>(63 - t), 0};
    }
  }

  // Word form. i32-SIZED OPS ONLY, and NON-WRAPPING ONLY. Both restrictions are
  // load-bearing; `rlwinm` is not a 64-bit AND and it is easy to believe it is.
  //
  //   rlwinm RA,RS,SH,MB,ME:  r <- ROTL32((RS)[32:63], SH)
  //                           m <- MASK(MB+32, ME+32)
  //                           RA <- r & m
  //
  // ROTL32 rotates the 64-bit value word||word, so r carries the rotated word
  // in BOTH halves. MASK(x,y) with x > y wraps -- it sets BE x..63 AND BE 0..y.
  // MB and ME are 5-bit, so MB+32 and ME+32 both land in [32,63]:
  //
  //   MB <= ME  the mask lies entirely in BE 32..63, BE 0..31 are masked off,
  //             and the result is zext32(word & mask32).
  //   MB >  ME  the wrapped half is BE 0..(ME+32), which covers ALL of BE 0..31,
  //             so the duplicated copy of the rotated word survives up there:
  //             `rlwinm RA,RS,0,28,23` computes (RS_lo << 32) | (RS_lo &
  //             0xFFFFFF0F), NOT 0x00000000_xxxxxx0F. It cannot preserve or
  //             clear an upper half and so cannot implement a 64-bit AND at all.
  //
  // The wrapping form is therefore never generated. The masks it would have
  // served -- a field of zeros inside the word -- are reached in one instruction
  // through the rldimi case below, via ClassifyAndMask's "keep the high half"
  // completion.
  //
  // The non-wrapping form IS an exact 64-bit AND whenever M has no bits above
  // 31 (both sides zero the upper half), and that was verified by simulating
  // the ISA pseudocode over every 32-bit run. It is still restricted to i32
  // here: at i32 the zero-extension is the required result anyway, whereas at
  // i64 it buys exactly one instruction over the rldicl+rldicr pair below and
  // makes every future reader re-derive the ROTL32 duplication argument. Every
  // other rlwinm this backend emits has MB <= ME; nothing anywhere emits a
  // wrapping one.
  if (AllowWord && M <= 0xFFFF'FFFFull) {
    const uint32_t W = static_cast<uint32_t>(M);
    if (IsRun32(W)) {
      // Ones at LE [lo..hi] -> BE [31-hi .. 31-lo]. hi >= lo gives MB <= ME, so
      // this branch structurally cannot construct a wrapped mask.
      const unsigned lo = static_cast<unsigned>(std::countr_zero(W));
      const unsigned hi = 31u - static_cast<unsigned>(std::countl_zero(W));
      return {AndMaskKind::Word, static_cast<uint8_t>(31 - hi), static_cast<uint8_t>(31 - lo), 0};
    }
  }

  // Punch a field of zeros. rldimi RA,RS,SH,MB inserts ROTL64(RS,SH) into RA
  // over BE MB..(63-SH) and leaves the rest of RA alone, so with RS = r0 (the
  // JIT's pinned zero register) it clears LE [SH .. 63-MB]. For zeros at LE
  // [lo..hi] that is SH = lo and MB = 63-hi; the encoding's MB <= 63-SH
  // requirement reduces to lo <= hi and so always holds.
  //
  // This is the shape OpcodeDispatcher's 8/16-bit AND promotion produces:
  // `and al,0x0F` becomes _And(i64, dst, 0xFFFFFFFFFFFFFF0F), whose zeros are
  // the single run LE 4..7 -> `rldimi Dst, r0, 4, 56`.
  {
    const uint64_t Z = ~M;
    if (IsRun64(Z)) {
      const unsigned lo = static_cast<unsigned>(std::countr_zero(Z));
      const unsigned hi = 63u - static_cast<unsigned>(std::countl_zero(Z));
      return {AndMaskKind::InsertZeroField, static_cast<uint8_t>(63 - hi), 0, static_cast<uint8_t>(lo)};
    }
  }

  // Keep a middle field: clear above hi with rldicl, then clear below lo with
  // rldicr. Two instructions, no scratch and no allocatable register, versus
  // LoadImm64's own two-instruction contiguous-ones path plus a separate `and`.
  // Only runs that touch neither end reach here (both ends were handled by the
  // ClearLeft / ClearRight cases), so lo >= 1 and hi <= 62.
  if (IsRun64(M)) {
    const unsigned lo = static_cast<unsigned>(std::countr_zero(M));
    const unsigned hi = 63u - static_cast<unsigned>(std::countl_zero(M));
    return {AndMaskKind::ClearBoth, static_cast<uint8_t>(63 - hi), static_cast<uint8_t>(63 - lo), 0};
  }

  return {};
}

// Host instructions the form costs, worst case (InsertZeroField and Move may
// need an `mr` when the allocator did not coalesce Dst with Src1).
constexpr unsigned AndMaskCost(AndMaskKind K) {
  switch (K) {
  case AndMaskKind::None: return 99;
  case AndMaskKind::Zero:
  case AndMaskKind::Move:
  case AndMaskKind::ClearLeft:
  case AndMaskKind::ClearRight:
  case AndMaskKind::Word: return 1;
  case AndMaskKind::InsertZeroField:
  case AndMaskKind::ClearBoth: return 2;
  }
  return 99;
}

// Is32Bit means the IR op is i32Bit, where the handler's trailing Mask32Tail
// makes the upper 32 bits of the result unobservable -- it either zero-extends
// them or Compute32MaskElision proved the single consumer reads only the low 32
// (JITClass.h, rules 1-3). The mask's own upper half is therefore a free
// choice, and the two completions find different one-instruction forms:
//
//   & 0xFFFFFFFF ("clear the high half")  -> rldicl / rlwinm, which also supply
//                                            the zero-extension for free.
//   | 0xFFFFFFFF00000000 ("keep it")      -> rldimi, the only single-instruction
//                                            form for a mask whose zeros sit in
//                                            the middle of the word.
//
// Both are tried and the cheaper wins, ties going to the clearing completion
// because it makes the tail mask redundant. This is what lets a 32-bit-guest
// `and al,0x0F` -- promoted to mask 0xFFFFFFFFFFFFFF0F -- reach one `rldimi`
// instead of a LoadConstant, even though its low 32 bits alone are not a run.
constexpr AndMaskForm ClassifyAndMask(uint64_t M, bool Is32Bit) {
  if (!Is32Bit) {
    // rlwinm is off the table at i64 (see the Word case); the doubleword forms
    // are the only ones that can be trusted to get the upper half right.
    return ClassifyAndMask64(M, /*AllowWord=*/false);
  }
  const AndMaskForm Clear = ClassifyAndMask64(M & 0xFFFF'FFFFull, /*AllowWord=*/true);
  // The "keep" completion is always > 0xFFFFFFFF, so it can never reach the
  // Word case regardless of what is passed here.
  const AndMaskForm Keep = ClassifyAndMask64(M | 0xFFFF'FFFF'0000'0000ull, /*AllowWord=*/false);
  return AndMaskCost(Keep.Kind) < AndMaskCost(Clear.Kind) ? Keep : Clear;
}

// ---------------------------------------------------------------------------
// InlineAddSub: CondJump, Select, CondAddNZCV, CondSubNZCV.
//
// Every one of these routes its second operand into a compare -- EmitCompare
// (JIT.cpp) or, for CondAddNZCV at i64, `addic.` -- whose immediate field is
// either the signed 16-bit SI of cmpdi/cmpwi/addic. or the unsigned 16-bit UI
// of cmpldi/cmplwi. Both are free; the operand disappears into the instruction.
//
// The third clause covers constants that need one `lis` in a scratch and then
// the register-form compare: two instructions, no allocatable register. That
// keeps everything ARM's IsImmAddSub used to accept at 0x10000 and above from
// regressing to a register.
//
// DECLINED: constants needing lis+ori (e.g. `cmp eax,0x12345678`, and ARM's
// non-page-aligned multiples such as 0x11000). Those cost three instructions
// per execution against one instruction plus a shared register, and the
// register wins even at five dynamic GPRs.
// ---------------------------------------------------------------------------
constexpr bool IsAddSubImm(uint64_t X) {
  return IsSImm16(X)                              // cmpdi / cmpwi / addic. SI
         || X <= 0xFFFFull                        // cmpldi / cmplwi UI
         || (IsSImm32(X) && (X & 0xFFFFull) == 0); // one `lis`, then reg-form cmp
}

// ---------------------------------------------------------------------------
// InlineLargeAddSub: Add, Sub, AddWithFlags, SubWithFlags, AddNZCV, SubNZCV.
//
// Add/Sub fold a signed 16-bit constant straight into `addi` for free, and
// SplitAddisAddi (ALUOps.cpp) covers the whole signed-32 range in `addis`+
// `addi` with no scratch and no register.
//
// The four flag-producing members do NOT share that luck. AddWithFlags,
// SubWithFlags, AddNZCV and SubNZCV must all use addco./subfco. -- addic. does
// not write XER.OV, which is the documented cause of the stale-OF bug in
// FEX_bugs/add_sub_inline_imm_of.asm -- so they materialise the inline operand
// with LoadConstant unconditionally, and the constant costs exactly its
// LoadImm64 length on every execution.
//
// So the predicate is bounded by the flag variants, not by Add/Sub: accept only
// what materialises in ONE instruction. That is uniformly "+1 host instruction,
// -1 allocatable register" across all six consumers.
//
// DECLINED, deliberately: the general signed-32 `addis`+`addi` form. It really
// is a win for plain Add/Sub, but x86 `add`/`sub`/`cmp` with an imm32 lower to
// the *flags* forms far more often than to bare Add/Sub (bare Add/Sub is mostly
// LEA and address arithmetic, plus whatever DFCE has cleaned), and there the
// same constant costs two to three extra instructions instead of one. If the
// Inline attachment in IR.json is ever split so Add/Sub carry their own kind,
// widen that kind to plain IsSImm32 and this comment is the reason why.
//
// The size floor is inherited unchanged from the ARM predicate: below i32Bit
// the operand-size shims in these handlers pre-shift the constant, which is a
// separate question from encodability and is not relitigated here.
// ---------------------------------------------------------------------------
constexpr bool IsLargeAddSubImm(IR::OpSize Size, uint64_t X) {
  return IsOneInsnConstant(X) && Size >= IR::OpSize::i32Bit;
}

// ---------------------------------------------------------------------------
// InlineLogical: Or, Xor, And, AndWithFlags, Andn, TestNZ.
//
// Clause by clause, and what each costs on the WORST of the six:
//
//  1. X <= 0xFFFF          ori / xori / andi. take it as a D-form UI. And/Andn
//                          either match a mask class (free) or pay one `li`.
//  2. X == (n << 16)       oris / xoris / andis. likewise.
//  3. IsSImm16(X)          one `li` into a scratch, then the register form.
//                          This is the whole family of "clear the low k bits"
//                          masks, 0xFFFFFFFFFFFFFF00 and friends.
//  4. a PPC mask class     one or two rotate-and-mask instructions for And and
//                          Andn, which is the entire point of the exercise.
//
// Clause 4 is the only one that is not uniformly cheap for the other four
// consumers: an Or or Xor against, say, 0xFFFFFF00FFFFFFFF still pays a five
// instruction LoadImm64. That is not a regression -- every mask this clause
// admits above 32 bits is a rotation of a contiguous run, so ARM's IsImmLogical
// admitted it too and it was already being materialised at exactly that cost --
// and the shapes are vanishingly rare, because x86-64 immediates are imm32
// sign-extended and therefore always land in clause 3 or in LoadImm32.
//
// DECLINED: the general signed-32 constant (`and rax,0x12345678`). It is not a
// mask, so And gains nothing, and lis+ori+and beats a shared register only if
// registers were free. Also declined, and this is the over-feeding half of the
// fix: every ARM logical immediate that is not one of the above -- the repeated
// patterns like 0x5555555555555555 and 0x0000FFFF0000FFFF, which PPC needs four
// or five instructions to rebuild.
// ---------------------------------------------------------------------------
constexpr bool IsLogicalImm(IR::OpSize Size, uint64_t X) {
  if (X <= 0xFFFFull || (X & 0xFFFF0000ull) == X || IsSImm16(X)) {
    return true;
  }
  return ClassifyAndMask(X, Size == IR::OpSize::i32Bit).Kind != AndMaskKind::None;
}

// ---------------------------------------------------------------------------
// FEX_PPCINLINECONST=0 reverts all three predicates to the AArch64 tests they
// replaced. Presence of any other value, or absence, leaves them enabled.
// Hashed into the code-cache config id (CodeCache.cpp): it changes the operands
// of essentially every arithmetic and logical instruction FEX emits, so a cache
// built with it flipped is not interchangeable with one built without.
// ---------------------------------------------------------------------------
inline bool InlineConstEnabled() {
  static const bool Enabled = [] {
    const char* Env = ::getenv("FEX_PPCINLINECONST");
    return !(Env && Env[0] == '0');
  }();
  return Enabled;
}

} // namespace FEXCore::IR::PPC64
