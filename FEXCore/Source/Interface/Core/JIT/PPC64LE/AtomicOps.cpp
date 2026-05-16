// SPDX-License-Identifier: MIT
// PPC64LE atomic operations for FEX JIT backend.
// Uses POWER8 lwarx/stwcx./ldarx/stdcx. load-link/store-conditional primitives.
// Also lbarx/stbcx_ and lharx/sthcx_ for sub-word atomics (POWER8).
//
// x86 LOCK-prefixed RMW operations are sequentially consistent. To emulate that
// on PPC64LE's relaxed memory model, every atomic primitive in this file is
// wrapped with `hwsync` before the load-reserved and `isync` after the
// successful store-conditional — the standard mapping for memory_order_seq_cst
// on POWER. lwsync is insufficient because it doesn't order earlier stores
// against the LL/SC's load.
//
// Misalignment: lwarx/lharx/ldarx all require natural alignment, so an x86
// `lock add dword [r15+3]` would raise SIGBUS if dispatched straight to the
// LL/SC path. Each RMW op below emits a runtime alignment check; aligned EAs
// take the LL/SC fast path (atomic across cores), misaligned EAs fall back to
// a plain load-op-store sequence (single-core/single-thread correct, matches
// the implementation-defined behavior x86 already has for cross-cache-line
// LOCK ops). The 8-bit (lbarx) path is always aligned by definition.
#include "Interface/Core/JIT/PPC64LE/JITClass.h"

namespace FEXCore::CPU {

#define LOAD_RESERVED(dst, addr, sz) \
  do { \
    switch (sz) { \
    case IR::OpSize::i8Bit:  lbarx(dst, r0, addr); break; \
    case IR::OpSize::i16Bit: lharx(dst, r0, addr); break; \
    case IR::OpSize::i32Bit: lwarx(dst, r0, addr); break; \
    default:                 ldarx(dst, r0, addr); break; \
    } \
  } while (0)

#define STORE_COND(val, addr, sz) \
  do { \
    switch (sz) { \
    case IR::OpSize::i8Bit:  stbcx_(val, r0, addr); break; \
    case IR::OpSize::i16Bit: sthcx_(val, r0, addr); break; \
    case IR::OpSize::i32Bit: stwcx_(val, r0, addr); break; \
    default:                 stdcx_(val, r0, addr); break; \
    } \
  } while (0)

#define LOAD_NONATOMIC(dst, addr, sz) \
  do { \
    switch (sz) { \
    case IR::OpSize::i8Bit:  lbzx(dst, r0, addr); break; \
    case IR::OpSize::i16Bit: lhzx(dst, r0, addr); break; \
    case IR::OpSize::i32Bit: lwzx(dst, r0, addr); break; \
    default:                 ldx (dst, r0, addr); break; \
    } \
  } while (0)

#define STORE_NONATOMIC(val, addr, sz) \
  do { \
    switch (sz) { \
    case IR::OpSize::i8Bit:  stbx(val, r0, addr); break; \
    case IR::OpSize::i16Bit: sthx(val, r0, addr); break; \
    case IR::OpSize::i32Bit: stwx(val, r0, addr); break; \
    default:                 stdx(val, r0, addr); break; \
    } \
  } while (0)

// ---------------------------------------------------------------------------
// AtomicSwap — exchange, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicSwap) {
  const auto Op   = IROp->C<IR::IROp_AtomicSwap>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 XCHG / LOCK XCHG preserve flags per Intel SDM.  Save CR0 (the
  // canonical packed-NZCV scratch) before the alignment-check andi_ and
  // the LL/SC loop's stdcx_, restore at op end.  Unlike other LOCK ops
  // where a flag-setter follows and fully overwrites CR0, XCHG has no
  // such follower — any leaked CR0 state from the andi_/stdcx_ would
  // contaminate downstream NZCVSelect / LAHF / Jcc reads.
  mfcr(TMP4);
  std(TMP4, -8, r1);

  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    STORE_NONATOMIC(Val, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  STORE_COND(Val, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 — XCHG preserves flags.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchAdd — fetch-and-add, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchAdd) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchAdd>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  // RA may tie Dst to Val (lock add to mem) or to Addr; in either case
  // LOAD_RESERVED's lbarx/lwarx/etc. will overwrite Dst's register and we
  // need the original Val/Addr untouched for the body and STORE_COND.
  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  //
  // Use TMP4 — NOT TMP3 — because the `Addr == Dst` stash above may have just
  // parked the address in TMP3.  `mfcr(TMP3)` would silently overwrite the
  // address, and every subsequent andi_/LOAD/STORE that uses `A` (=TMP3) would
  // dereference CR0 bits instead.  This is the same constraint AtomicSwap has
  // used since f6db15238; the seven Fetch* ops in 8743eb4f5 originally used
  // TMP3 and corrupted the address whenever RA aliased Dst onto Addr — which
  // happens routinely in jit_500/jit_500_m blocks (e.g. `lock not [r15+1]`).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    add(TMP2, Dst, Val);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  add(TMP2, Dst, Val);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchSub — fetch-and-sub, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchSub) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchSub>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    subf(TMP2, Val, Dst);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  subf(TMP2, Val, Dst);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchAnd — fetch-and-and, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchAnd) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchAnd>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    and_(TMP2, Dst, Val);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  and_(TMP2, Dst, Val);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchCLR — fetch-and-andnot (clear bits set in Val), returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchCLR) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchCLR>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    andc(TMP2, Dst, Val);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  andc(TMP2, Dst, Val);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchOr — fetch-and-or, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchOr) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchOr>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    or_(TMP2, Dst, Val);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  or_(TMP2, Dst, Val);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchXor — fetch-and-xor, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchXor) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchXor>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  GPR Val         = GetReg(Op->Value);
  const auto Dst  = GetReg(Node);

  if (Val == Dst)  { mr(TMP1, Val);  Val = TMP1; }
  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    xor_(TMP2, Dst, Val);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  xor_(TMP2, Dst, Val);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// AtomicFetchNeg — fetch-and-negate, returns old value
// ---------------------------------------------------------------------------
DEF_OP(AtomicFetchNeg) {
  const auto Op   = IROp->C<IR::IROp_AtomicFetchNeg>();
  const auto Sz   = IROp->Size;
  const auto Addr = GetReg(Op->Addr);
  const auto Dst  = GetReg(Node);

  GPR A = Addr;
  if (Addr == Dst) { mr(TMP3, Addr); A = TMP3; }

  // x86 LOCK ops set flags via a SEPARATE IR op after the atomic.  Save CR0
  // here to defend against any IR-pipeline path that inserts a CR0-reader
  // between the atomic and the flag-setter (Select01, branch fold, etc.).
  mfcr(TMP4);
  std(TMP4, -8, r1);
  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    andi_(TMP4, A, AlignMask);
    bc(CC_EQ, &aligned);
    // x86 LOCK semantics require full SC; the aligned LL/SC path
    // already supplies hwsync;...;isync, but the misaligned fallback
    // was barrier-less, dropping the release/acquire fences.  Bracket
    // with hwsync to match the aligned path's ordering.
    hwsync();
    LOAD_NONATOMIC(Dst, A, Sz);
    neg(TMP2, Dst);
    STORE_NONATOMIC(TMP2, A, Sz);
    hwsync();
    b(&done);
  }
  Bind(&aligned);
  auto loop = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  neg(TMP2, Dst);
  STORE_COND(TMP2, A, Sz);
  bc(CC_NE, &loop);
  isync();
  Bind(&done);
  // Restore CR0 saved at op entry — x86 LOCK <op> conceptually preserves
  // any prior NZCV state up until the following flag-setter writes its own.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

// ---------------------------------------------------------------------------
// CAS — compare and swap. Returns current memory value.
// On success: memory updated, Dst = Expected.
// On failure: memory unchanged, Dst = actual current value.
// ---------------------------------------------------------------------------
DEF_OP(CAS) {
  const auto Op       = IROp->C<IR::IROp_CAS>();
  const auto Sz       = IROp->Size;
  const auto Addr     = GetReg(Op->Addr);
  const auto Expected = GetReg(Op->Expected);
  const auto Desired  = GetReg(Op->Desired);
  const auto Dst      = GetReg(Node);

  // RA may assign Dst to any of Addr/Expected/Desired — LOAD_RESERVED's lbarx
  // writes Dst's register, clobbering the input we need later for comparison
  // or the store-conditional. Capture each input into a stable temp if it
  // aliases Dst.
  GPR A = Addr, E = Expected, D = Desired;
  if (Addr == Dst)     { mr(TMP1, Addr);     A = TMP1; }
  if (Expected == Dst) { mr(TMP4, Expected); E = TMP4; }
  if (Desired == Dst)  { mr(TMP2, Desired);  D = TMP2; }

  // CAS body: compare loaded value against Expected (mask Expected to width
  // first since lbarx/lharx zero-extend the loaded value but Expected may
  // carry stale upper bits from a wider compute). On mismatch, leave Dst as
  // the current memory value and skip the store.
  auto EmitCmp = [&]() {
    GPR ExpCmp = E;
    switch (Sz) {
    case IR::OpSize::i8Bit:
      clrldi(TMP3, E, 56);
      ExpCmp = TMP3;
      cmpw(Dst, ExpCmp);
      break;
    case IR::OpSize::i16Bit:
      clrldi(TMP3, E, 48);
      ExpCmp = TMP3;
      cmpw(Dst, ExpCmp);
      break;
    case IR::OpSize::i32Bit:
      cmpw(Dst, E);
      break;
    default:
      cmpd(Dst, E);
      break;
    }
  };

  const unsigned AlignMask = static_cast<unsigned>(IR::OpSizeToSize(Sz)) - 1;
  PPC64Emitter::Label aligned, done;
  if (AlignMask) {
    auto na_skip = PPC64Emitter::Label{};
    // CRITICAL: andi_ writes its dest to TMP3 (NOT TMP4). TMP4 may hold the
    // stashed Expected (from line 370 when Expected==Dst); the prior code used
    // TMP4 here and clobbered E in both the misaligned and aligned paths.
    // The aligned path re-stashed at line 419 but the misaligned path didn't
    // — leaving EmitCmp comparing against (Addr & AlignMask) instead of the
    // expected value, so e.g. a 64-bit `cmpxchg [unaligned], rcx` with RAX
    // matching memory would NOT take the store branch (compared against 0..7
    // instead of RAX), silently leaving memory unchanged. TMP3 is free at this
    // point (no caller path stashes through TMP3) so we use it for the test.
    andi_(TMP3, A, AlignMask);
    bc(CC_EQ, &aligned);
    // Misaligned: plain load → compare → conditional store.
    LOAD_NONATOMIC(Dst, A, Sz);
    EmitCmp();
    bc(CC_NE, &na_skip);
    STORE_NONATOMIC(D, A, Sz);
    Bind(&na_skip);
    b(&done);
  }
  Bind(&aligned);

  auto loop = PPC64Emitter::Label{};
  auto fail = PPC64Emitter::Label{};
  hwsync();
  Bind(&loop);
  LOAD_RESERVED(Dst, A, Sz);
  EmitCmp();
  bc(CC_NE, &fail);   // mismatch: leave Dst = current value, reservation drops
  STORE_COND(D, A, Sz);
  bc(CC_NE, &loop);   // SC failed (reservation lost): retry
  Bind(&fail);
  isync();
  Bind(&done);
}

// ---------------------------------------------------------------------------
// CASPair — paired CAS for CMPXCHG8B (Size=i32Bit, 64-bit memory) and
// CMPXCHG16B (Size=i64Bit, 128-bit memory). x86 mandates natural alignment
// (#GP on misuse) so no misalignment fallback is emitted.
//
// CMPXCHG8B path: combine ExpHi:ExpLo and DesHi:DesLo into 64-bit values
// and use ldarx/stdcx_. Earlier impl always used lqarx — that's a 16-byte
// LL/SC and silently corrupted memory beyond the 8-byte target whenever
// CMPXCHG8B was invoked.
//
// CMPXCHG16B path: lqarx/stqcx_. require an even/odd register pair RTp:RTp+1.
// In LE storage: RTp <- mem[EA+8] (high half), RTp+1 <- mem[EA+0] (low half).
// TMP1:TMP2 = r3:r4 is even:odd and lies outside the RA-allocated GPR pool
// (which starts at r7), so we use it as the LL/SC pair and reuse it for the
// store after capturing the loaded values into the caller-supplied Dst regs.
// ---------------------------------------------------------------------------
DEF_OP(CASPair) {
  const auto Op      = IROp->C<IR::IROp_CASPair>();
  const auto Sz      = IROp->Size;
  const auto Addr    = GetReg(Op->Addr);
  const auto ExpLo   = GetReg(Op->ExpectedLo);
  const auto ExpHi   = GetReg(Op->ExpectedHi);
  const auto DesLo   = GetReg(Op->DesiredLo);
  const auto DesHi   = GetReg(Op->DesiredHi);
  const auto DstLo   = GetReg(Op->OutLo);
  const auto DstHi   = GetReg(Op->OutHi);

  // CASPair clobbers CR0 (stdcx_/stqcx_ unconditionally; cmpd/andi_ implicitly).
  // The dispatcher pattern is CASPair → CmpPairZ → pushfq's LoadNZCV which
  // reads CR0.LT directly as x86 SF. Without preservation, every cmpxchg8b/16b
  // leaks the CAS's internal compare result into SF (and similarly for OF/CF
  // via XER, though stdcx_ doesn't touch XER). Save CR0 to red zone on entry
  // and restore on exit so CmpPairZ's crmove(CR0.EQ ← CR1.EQ) is the only
  // visible CR0 change. -8(r1) is reserved within this op (no recursion).
  mfcr(TMP4);
  std(TMP4, -8, r1);

  if (Sz == IR::OpSize::i32Bit) {
    // CMPXCHG8B: 64-bit CAS. Combine the 32-bit halves into a 64-bit word.
    // TMP1 = ExpFull = (ExpHi[31:0] << 32) | ExpLo[31:0]
    rldicl(TMP4, ExpLo, 0, 32);     // ExpLo & 0xFFFFFFFF
    sldi  (TMP1, ExpHi, 32);        // (ExpHi & 0xFFFFFFFF) << 32
    or_   (TMP1, TMP1, TMP4);

    // TMP3 = DesFull
    rldicl(TMP4, DesLo, 0, 32);
    sldi  (TMP3, DesHi, 32);
    or_   (TMP3, TMP3, TMP4);

    auto aligned = PPC64Emitter::Label{};
    auto loop = PPC64Emitter::Label{};
    auto fail = PPC64Emitter::Label{};
    auto done = PPC64Emitter::Label{};

    // x86 cmpxchg8b ALLOWS misaligned addresses (locked bus on x86; we degrade
    // to a non-atomic ld/cmp/conditional-std in that case — matches single-
    // threaded semantics and avoids the POWER `ldarx` SIGBUS on unaligned EA).
    andi_(TMP4, Addr, 7);
    bc(CC_EQ, &aligned);
    {
      ld(TMP2, 0, Addr);            // TMP2 = current 8 bytes (non-atomic)
      cmpd(TMP2, TMP1);
      auto na_skip = PPC64Emitter::Label{};
      bc(CC_NE, &na_skip);
      std(TMP3, 0, Addr);           // store desired
      Bind(&na_skip);
      b(&done);
    }

    Bind(&aligned);
    hwsync();
    Bind(&loop);
    ldarx(TMP2, r0, Addr);          // TMP2 = current 8 bytes
    cmpd (TMP2, TMP1);
    bc   (CC_NE, &fail);
    stdcx_(TMP3, r0, Addr);
    bc   (CC_NE, &loop);
    b    (&done);

    Bind(&fail);
    // Mismatch: return loaded value via TMP2; reservation drops.

    Bind(&done);
    isync();

    // Split TMP2 into DstLo (low 32, zero-extended) and DstHi (high 32).
    rldicl(DstLo, TMP2, 0, 32);
    srdi  (DstHi, TMP2, 32);

    // Restore CR0 (entry-save above). mtcrf 0x80 writes only field 0.
    ld(TMP4, -8, r1);
    mtcrf(0x80, TMP4);
    return;
  }

  // CMPXCHG16B: 128-bit CAS via lqarx/stqcx_. lqarx requires the destination
  // register pair (RT, RT+1) where RT is EVEN. r3 (TMP1) is odd; the pair
  // must start at r4 (TMP2). Empirically on this POWER8 + LE toolchain:
  //   RT   (even, TMP2) <- mem[EA+8..+15] (HIGH half)
  //   RT+1 (odd,  TMP3) <- mem[EA+0..+7]  (LOW half)
  // i.e. opposite of the BE doubleword ordering described in the ISA prose.
  //
  // Earlier impl used r3:r4 as the pair — RT=r3 is odd, an invalid form that
  // raised SIGILL on the host whenever a guest CMPXCHG16B was executed. All
  // 16-byte CAS tests dumped core. Fix: r4:r5 with r4=high, r5=low.
  const auto PairHi = TMP2;   // r4 (even, RTp)   <- mem[EA+8..+15]
  const auto PairLo = TMP3;   // r5 (odd,  RTp+1) <- mem[EA+0..+7]
  const auto SaveDesLo = TMP1;
  const auto SaveDesHi = TMP4;

  auto loop  = PPC64Emitter::Label{};
  auto fail  = PPC64Emitter::Label{};
  auto done  = PPC64Emitter::Label{};

  // Stage Desired into scratch — DesHi/DesLo may alias DstHi/DstLo and would
  // be clobbered by the post-load mr(Dst*, Pair*) sequence below.
  mr(SaveDesLo, DesLo);
  mr(SaveDesHi, DesHi);

  hwsync();
  Bind(&loop);
  lqarx(PairHi, r0, Addr);   // RT=PairHi(even); also loads PairLo=RT+1

  cmpd(PairLo, ExpLo);
  bc(CC_NE, &fail);
  cmpd(PairHi, ExpHi);
  bc(CC_NE, &fail);

  // Match: capture loaded values to Dst, then refill the pair with Desired
  // and attempt the conditional store.
  mr(DstLo, PairLo);
  mr(DstHi, PairHi);
  mr(PairLo, SaveDesLo);
  mr(PairHi, SaveDesHi);
  stqcx_(PairHi, r0, Addr);  // RT=PairHi(even); writes both halves
  bc(CC_NE, &loop);   // SC failed: retry
  b(&done);

  Bind(&fail);
  // Mismatch: return loaded value, no store. Reservation drops naturally.
  mr(DstLo, PairLo);
  mr(DstHi, PairHi);

  Bind(&done);
  isync();

  // Restore CR0 (entry-save in the 128-bit body shares the same red-zone slot).
  // TMP4 is free here — the 128-bit body's SaveDesHi(=TMP4) is dead after stqcx_.
  ld(TMP4, -8, r1);
  mtcrf(0x80, TMP4);
}

#undef LOAD_RESERVED
#undef STORE_COND
#undef LOAD_NONATOMIC
#undef STORE_NONATOMIC

} // namespace FEXCore::CPU
