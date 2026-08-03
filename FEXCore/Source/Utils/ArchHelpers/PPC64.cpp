// SPDX-License-Identifier: MIT
//
// PPC64LE split-lock / SIGBUS infrastructure.
//
// Background
// ----------
// x86 LOCK-prefixed RMW instructions accept arbitrary alignment; the CPU just
// locks the bus (or cache line, or split lines) for the duration. POWER8's
// ldarx / lwarx / lharx / lbarx, in contrast, *require* natural alignment;
// a misaligned reservation address raises SIGBUS with si_code=BUS_ADRALN.
//
// The existing JIT/PPC64LE/AtomicOps.cpp emits a runtime alignment check
// inline and falls back to a plain LD->op->ST (bracketed by hwsync) on
// misaligned addresses. That fallback is single-thread correct but NOT
// atomic across cores: two threads racing on the same misaligned EA can
// observe a torn result.
//
// ARM64-FEX's solution is to optimistically emit the unaligned-fault-prone
// LL/SC, catch the SIGBUS, identify it as JIT-emitted atomic code, and
// either backpatch to a "half-barrier" variant or call a serialized
// emulation helper. That is more correct than our static non-atomic
// fallback.
//
// This file builds the infrastructure half of that approach:
//
//   - PPC64_SplitLockEmulate(): a process-wide striped-mutex-serialised RMW,
//     wired in from `JIT/PPC64LE/AtomicOps.cpp` on every misaligned Fetch* /
//     Swap / CAS path (Phase 3), and on misaligned `CMPXCHG8B` since
//     `001b9afde` (Tier D atomics C2).
//   - HandleUnalignedAtomicSIGBUS(): SIGBUS instruction decoder that
//     recognises a reservation-load opcode (primary=31, XO in
//     {52, 116, 20, 84}) and increments telemetry. Currently has NO in-tree
//     call site — the container loads are aligned by construction so the
//     signal path is not hit. Kept for the eventual container-in-helper
//     (Tier D atomics C3/C4) work; that fix must revisit its fixed
//     `Advance = 12/16` before wiring it up.

#include <FEXCore/Utils/ArchHelpers/PPC64.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Telemetry.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace FEXCore::ArchHelpers::PPC64 {

namespace {
// 64-way striped mutexes keyed by (addr >> 6) -- one stripe per cacheline.
// Mono GC barrier traffic (Unity-managed games) emits hundreds of misaligned
// LOCK RMW ops at startup; a single global mutex serialised all of them
// across all threads, stalling GC initialisation enough that no window ever
// opens. Striping by cacheline lets unrelated cachelines proceed in
// parallel. For 8-byte misaligned atomics that span two cachelines we
// acquire both stripes in canonical order via std::scoped_lock to preserve
// atomicity. 64 stripes -> 6 low bits of the cacheline key, which keeps the
// table at 64 * sizeof(std::mutex) (~3 KiB), trivially cache-friendly.
static constexpr size_t SPLIT_LOCK_STRIPES = 64;
std::array<std::mutex, SPLIT_LOCK_STRIPES> g_SplitLockMutexes;

// Telemetry: incremented every time we recognize a SIGBUS as a split-lock
// reservation-load fault. Counted even though Phase 1 doesn't yet recover
// from it, so we get visibility into how often the case fires once Phase 3
// lands.
std::atomic<uint64_t> g_SplitLockDetectedCount {0};

// Helper: read `size` bytes from `addr` byte-by-byte into a uint64_t, LE.
// We use memcpy rather than a typed load so we don't trip the C++ object
// model on a misaligned pointer.
inline uint64_t LoadMis(const void* addr, uint32_t size) {
  uint64_t v = 0;
  std::memcpy(&v, addr, size);
  return v;
}

inline void StoreMis(void* addr, uint64_t v, uint32_t size) {
  std::memcpy(addr, &v, size);
}

// Mask for `size` bytes.
inline uint64_t SizeMask(uint32_t size) {
  if (size >= 8) {
    return ~uint64_t {0};
  }
  return (uint64_t {1} << (size * 8)) - 1;
}

// Compute the RMW result value from op / current-Old / operand. CAS is
// excluded from this dispatch — it needs Expected and a "did we store"
// signal, so callers handle it inline.
static inline uint64_t ApplyRmwOp(SplitLockOp op, uint64_t Old, uint64_t Operand, uint64_t Mask) {
  switch (op) {
  case SplitLockOp::Swap:     return Operand;
  case SplitLockOp::FetchAdd: return (Old + Operand) & Mask;
  case SplitLockOp::FetchSub: return (Old - Operand) & Mask;
  case SplitLockOp::FetchAnd: return (Old & Operand) & Mask;
  case SplitLockOp::FetchOr:  return (Old | Operand) & Mask;
  case SplitLockOp::FetchXor: return (Old ^ Operand) & Mask;
  case SplitLockOp::FetchCLR: return (Old & ~Operand) & Mask;
  case SplitLockOp::FetchNeg: return static_cast<uint64_t>(-static_cast<int64_t>(Old)) & Mask;
  default:                    return Old; // CAS is handled by the caller
  }
}

// C3 — doubleword container fast path. Contract:
//   - Caller has already taken the stripe mutex(es) covering this EA.
//   - HostAddr is byte-misaligned but (EA & 7) + size <= 8, so the entire
//     size-byte operand lives inside one host doubleword and we can drive
//     the RMW through an aligned uint64_t ldarx/stdcx. loop instead of
//     memcpy+memcpy.
//
// Why this exists on top of the mutex: the mutex only composes with other
// misaligned callers going through this helper. It does NOT compose with
// aligned lwarx/stwcx./ldarx/stdcx. issued by the JIT in another FEX thread
// against overlapping bytes of the same doubleword — the aligned path holds
// no mutex and can lose its reservation to our helper's plain-store window.
// Real ldarx/stdcx. here uses the same reservation channel as the JIT's
// aligned path, so aligned↔contained composes correctly.  Contained↔crossing
// composition is preserved by the stripe mutex the caller still holds:
// crossing ops execute their StoreMis inside that mutex.
//
// CAS mismatch does NOT issue a store — the existing memcpy path's
// unconditional write-back on mismatch is the bug PA called out as widening
// the clobber window to failed CASes, and this path deliberately doesn't
// replicate it.
//
// Sizes: valid sizes are {1,2,4,8}.  size==8 with (EA&7)==0 is naturally
// aligned and never lands here (the JIT emits ldarx/stdcx. directly), so
// the interesting cases are size {1,2,4} at any non-crossing offset.
static inline void ContainerDoubleword(SplitLockOp op, void* HostAddr, uint64_t Operand,
                                       uint64_t* result, uint32_t size, uint64_t Mask) {
  const uintptr_t EA = reinterpret_cast<uintptr_t>(HostAddr);
  const uintptr_t Aligned = EA & ~uintptr_t{7};
  const uint32_t ByteOffset = static_cast<uint32_t>(EA & 7u);
  const uint32_t BitShift = ByteOffset * 8u;
  const uint64_t FieldMask = Mask << BitShift;
  uint64_t* AlignedPtr = reinterpret_cast<uint64_t*>(Aligned);

  uint64_t Expected_dword = __atomic_load_n(AlignedPtr, __ATOMIC_ACQUIRE);
  while (true) {
    const uint64_t Old = (Expected_dword >> BitShift) & Mask;
    if (op == SplitLockOp::CAS) {
      const uint64_t GuestExpected = (*result) & Mask;
      if (Old != GuestExpected) {
        // Guest CAS mismatch: report observed Old to caller and DO NOT
        // store.  A memory barrier equivalent to the successful path is
        // still owed to the guest because x86 LOCK is seq_cst regardless
        // of the mismatch outcome; the JIT's hwsync bracket provides it.
        *result = Old;
        return;
      }
    }
    const uint64_t New = (op == SplitLockOp::CAS) ? (Operand & Mask)
                                                  : ApplyRmwOp(op, Old, Operand, Mask);
    const uint64_t New_dword = (Expected_dword & ~FieldMask) | ((New & Mask) << BitShift);
    if (__atomic_compare_exchange_n(AlignedPtr, &Expected_dword, New_dword,
                                    /*weak=*/false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
      *result = Old;
      return;
    }
    // CAS failed: Expected_dword was overwritten with the current value.
    // Loop; nothing else to reset.
  }
}
} // namespace

extern "C" void PPC64_SplitLockEmulate(uint8_t op, uint64_t* addr, uint64_t* value, uint64_t* result, uint32_t size) {
  // Counts every entry into the misaligned locked-operation path. The slot is
  // shared with ARM64 (Arm64.cpp) and is dumped at process shutdown as
  // "64byte Split Locks" (Telemetry.cpp:21). Telemetry is on by default.
  FEXCORE_TELEMETRY_INC(TYPE_HAS_SPLIT_LOCKS);

  if (addr == nullptr || result == nullptr) {
    LogMan::Msg::EFmt("PPC64_SplitLockEmulate: null addr/result");
    return;
  }
  if (size != 1 && size != 2 && size != 4 && size != 8) {
    LogMan::Msg::EFmt("PPC64_SplitLockEmulate: bad size {}", size);
    return;
  }

  const uint64_t Mask = SizeMask(size);
  void* HostAddr = reinterpret_cast<void*>(addr);
  const uint64_t Operand = value ? (*value & Mask) : 0;

  // Stripe selection: 1/2/4-byte misaligned atomics always live within one
  // cacheline so a single stripe suffices. 8-byte misaligned atomics CAN
  // span two cachelines; in that case acquire both stripes in canonical
  // order (low-index first) so concurrent threads can't deadlock and any
  // other thread touching the same cacheline pair serialises with us.
  //
  // The stripe mutex is UNCONDITIONAL, including when we then hand off to
  // the doubleword container: dropping it in the container case would
  // introduce a NEW race — a 2-byte contained op at offset 12 would race
  // an 8-byte crossing op at offset 12 against the same 16 bytes, with the
  // crossing op holding only the mutex and the contained op holding only a
  // stdcx. reservation.  Adversarial-review-mandated per POWER9_PORT_PLAN +
  // TASK_QUEUE Tier D correction #2.
  const uintptr_t HostAddrVal = reinterpret_cast<uintptr_t>(HostAddr);
  const size_t StripeLo = (HostAddrVal >> 6) & (SPLIT_LOCK_STRIPES - 1);
  const size_t StripeHi = ((HostAddrVal + size - 1) >> 6) & (SPLIT_LOCK_STRIPES - 1);
  std::unique_lock<std::mutex> LockLo;
  std::unique_lock<std::mutex> LockHi;
  if (StripeLo == StripeHi) {
    LockLo = std::unique_lock<std::mutex>(g_SplitLockMutexes[StripeLo]);
  } else {
    // Acquire both via std::lock to avoid deadlocks; std::lock takes
    // mutexes in any order safely. unique_lock with std::defer_lock holds
    // the slot without acquiring, then we transfer ownership after std::lock.
    const size_t SLo = std::min(StripeLo, StripeHi);
    const size_t SHi = std::max(StripeLo, StripeHi);
    LockLo = std::unique_lock<std::mutex>(g_SplitLockMutexes[SLo], std::defer_lock);
    LockHi = std::unique_lock<std::mutex>(g_SplitLockMutexes[SHi], std::defer_lock);
    std::lock(LockLo, LockHi);
  }

  // C3 — doubleword container: if the entire operand lives in one host
  // doubleword, run a real ldarx/stdcx. loop against that doubleword. This
  // composes with aligned LL/SC on overlapping bytes in other threads,
  // which the plain-memcpy path below cannot.
  if ((HostAddrVal & 7u) + size <= 8u) {
    ContainerDoubleword(static_cast<SplitLockOp>(op), HostAddr, Operand, result, size, Mask);
    return;
  }

  // Load the current value at the (possibly misaligned) EA.
  const uint64_t Old = LoadMis(HostAddr, size) & Mask;
  uint64_t New = Old;

  switch (static_cast<SplitLockOp>(op)) {
  case SplitLockOp::Swap:     New = Operand;             break;
  case SplitLockOp::FetchAdd: New = (Old + Operand);     break;
  case SplitLockOp::FetchSub: New = (Old - Operand);     break;
  case SplitLockOp::FetchAnd: New = (Old & Operand);     break;
  case SplitLockOp::FetchOr:  New = (Old | Operand);     break;
  case SplitLockOp::FetchXor: New = (Old ^ Operand);     break;
  case SplitLockOp::FetchCLR: New = (Old & ~Operand);    break;
  case SplitLockOp::FetchNeg: New = static_cast<uint64_t>(-static_cast<int64_t>(Old)); break;
  case SplitLockOp::CAS:
    // For CAS the contract is:
    //   - *result was pre-populated with the caller's expected value.
    //   - Operand (= *value) is the new value to install on a match.
    //   - We compare the loaded `Old` against `*result & Mask`; only
    //     store `Operand` on a match.
    //   - Either way write the actually-observed `Old` back into *result
    //     so the caller can compute ZF.
    {
      const uint64_t Expected = (*result) & Mask;
      if (Old == Expected) {
        New = Operand;
      } else {
        New = Old; // no-op store keeps memory contents identical
      }
    }
    break;
  default:
    LogMan::Msg::EFmt("PPC64_SplitLockEmulate: unknown op {}", op);
    return;
  }

  StoreMis(HostAddr, New & Mask, size);
  *result = Old; // pre-RMW value (CAS returns observed-old too)
}

// PPC64LE X-form field extractors (bits numbered per PowerISA big-endian
// convention; bit 0 = MSB of the 32-bit word).
namespace {
constexpr uint32_t XFormPrimary(uint32_t I) { return (I >> 26) & 0x3F; }
constexpr uint32_t XFormRT(uint32_t I)      { return (I >> 21) & 0x1F; } // bits 6..10
constexpr uint32_t XFormRA(uint32_t I)      { return (I >> 16) & 0x1F; } // bits 11..15
constexpr uint32_t XFormRB(uint32_t I)      { return (I >> 11) & 0x1F; } // bits 16..20
constexpr uint32_t XFormXO(uint32_t I)      { return (I >> 1)  & 0x3FF; }

// Match the (Primary=31, XO) reservation-load opcodes. Returns the operand
// size in bytes, or 0 on no match.
constexpr uint32_t LLLoadSize(uint32_t XO) {
  switch (XO) {
  case 20:  return 4; // lwarx
  case 52:  return 1; // lbarx
  case 84:  return 8; // ldarx
  case 116: return 2; // lharx
  default:  return 0;
  }
}

// Match the (Primary=31, XO) reservation-store opcodes.
constexpr bool IsStoreConditional(uint32_t XO) {
  switch (XO) {
  case 150: // stwcx.
  case 214: // stdcx.
  case 694: // stbcx.
  case 726: // sthcx.
    return true;
  default:
    return false;
  }
}
} // namespace

std::optional<int32_t> HandleUnalignedAtomicSIGBUS(FEXCore::Core::InternalThreadState* Thread, uintptr_t ProgramCounter, uint64_t* GPRs) {
  (void)Thread;

  if (ProgramCounter == 0 || (ProgramCounter & 3u) != 0) {
    // PowerISA instructions are 4-byte aligned; a misaligned PC means our
    // caller's IsAddressInCodeBuffer check was lying.
    return std::nullopt;
  }

  uint32_t LLInsn = 0;
  std::memcpy(&LLInsn, reinterpret_cast<const void*>(ProgramCounter), sizeof(uint32_t));

  if (XFormPrimary(LLInsn) != 31) {
    return std::nullopt;
  }
  const uint32_t Size = LLLoadSize(XFormXO(LLInsn));
  if (Size == 0) {
    return std::nullopt;
  }

  g_SplitLockDetectedCount.fetch_add(1, std::memory_order_relaxed);

  // Compute EA from the LL's X-form encoding. The JIT emits the LL with
  // RA=r0 (which Power's indexed addressing treats as the literal 0,
  // not GPRs[0]) and RB=addr_reg, so EA == GPRs[RB] in practice -- but
  // we honour the full RA?GPRs[RA]:0 convention for safety.
  const uint32_t LL_RT = XFormRT(LLInsn);
  const uint32_t LL_RA = XFormRA(LLInsn);
  const uint32_t LL_RB = XFormRB(LLInsn);
  const uint64_t EA    = (LL_RA ? GPRs[LL_RA] : 0) + GPRs[LL_RB];

  // Decode the body instruction at PC+4. Two patterns match what
  // JIT/PPC64LE/AtomicOps.cpp emits:
  //   AtomicSwap          : LL -> SC -> bc                  (no body)
  //   AtomicFetch{Add,Sub,And,Or,Xor,CLR,Neg}
  //                       : LL -> <body> -> SC -> bc        (body @ PC+4)
  // CAS interposes a cmp+bc-fail between LL and SC; we don't recognize
  // it here and let the fault escape (CAS already has an explicit
  // alignment check in the JIT and is rare enough as a fault source).
  uint32_t Body = 0;
  std::memcpy(&Body, reinterpret_cast<const void*>(ProgramCounter + 4), sizeof(uint32_t));
  if (XFormPrimary(Body) != 31) {
    return std::nullopt;
  }
  const uint32_t BodyXO = XFormXO(Body);

  SplitLockOp Op {};
  uint32_t ValueReg = 0;
  int32_t Advance   = 0;

  if (IsStoreConditional(BodyXO)) {
    // AtomicSwap: PC+0 LL ; PC+4 SC ; PC+8 bc.NE -> loop ; advance past bc.
    // SC X-form puts the source register (RS) in bits 6..10, same slot as
    // RT in load-form encodings, so we reuse XFormRT().
    Op = SplitLockOp::Swap;
    ValueReg = XFormRT(Body);
    Advance = 12; // skip LL + SC + bc
  } else {
    // Atomic-with-body. Decode the body's XO to map to a SplitLockOp,
    // and pick the operand register from the body's field layout.
    //
    //   add  RT, RA, RB  (primary 31, XO 266)         -- Val = RB
    //   subf RT, RA, RB  (primary 31, XO 40)          -- Val = RA (RT = RB - RA)
    //   and  RA, RS, RB  (primary 31, XO 28,  Rc=1)   -- Val = RB
    //   or   RA, RS, RB  (primary 31, XO 444, Rc=1)   -- Val = RB
    //   xor  RA, RS, RB  (primary 31, XO 316, Rc=1)   -- Val = RB
    //   andc RA, RS, RB  (primary 31, XO 60)          -- Val = RB
    //   neg  RT, RA      (primary 31, XO 104)         -- no Val operand
    switch (BodyXO) {
    case 266: Op = SplitLockOp::FetchAdd; ValueReg = XFormRB(Body); break;
    case 40:  Op = SplitLockOp::FetchSub; ValueReg = XFormRA(Body); break;
    case 28:  Op = SplitLockOp::FetchAnd; ValueReg = XFormRB(Body); break;
    case 444: Op = SplitLockOp::FetchOr;  ValueReg = XFormRB(Body); break;
    case 316: Op = SplitLockOp::FetchXor; ValueReg = XFormRB(Body); break;
    case 60:  Op = SplitLockOp::FetchCLR; ValueReg = XFormRB(Body); break;
    case 104: Op = SplitLockOp::FetchNeg; ValueReg = 0;             break;
    default:
      return std::nullopt;
    }
    // Verify the SC at PC+8 to defend against XO collisions with random
    // 31-primary instructions that might trip our pattern match.
    uint32_t SC = 0;
    std::memcpy(&SC, reinterpret_cast<const void*>(ProgramCounter + 8), sizeof(uint32_t));
    if (XFormPrimary(SC) != 31 || !IsStoreConditional(XFormXO(SC))) {
      return std::nullopt;
    }
    Advance = 16; // skip LL + body + SC + bc
  }

  // Stage Val on the C stack (SplitLockEmulate takes value by pointer).
  // FetchNeg has no operand, so leave Val zero.
  uint64_t Val    = (Op == SplitLockOp::FetchNeg) ? 0u : GPRs[ValueReg];
  uint64_t Result = 0;

  LogMan::Msg::DFmt("PPC64 split-lock SIGBUS recovery: PC=0x{:x} LL=0x{:08x} op={} size={} EA=0x{:x} RT={} VR={}",
                    ProgramCounter, LLInsn, static_cast<uint32_t>(Op), Size, EA, LL_RT, ValueReg);

  PPC64_SplitLockEmulate(static_cast<uint8_t>(Op),
                         reinterpret_cast<uint64_t*>(EA),
                         &Val,
                         &Result,
                         Size);

  // Deliver the pre-RMW value into the LL's RT register; advance PC past
  // the entire LL/SC body so the bc.NE back-edge doesn't loop.
  GPRs[LL_RT] = Result;
  return Advance;
}

} // namespace FEXCore::ArchHelpers::PPC64
