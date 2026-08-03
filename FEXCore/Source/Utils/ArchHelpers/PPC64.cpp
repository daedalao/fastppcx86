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
//     {52, 116, 20, 84}), routes the decoded operation through
//     PPC64_SplitLockEmulate, and returns the PC advance past the JIT's
//     LL/SC sequence. Wired in from SignalDelegator.cpp's SigbusHandlerPPC64
//     (the RegisterHostSignalHandler(SIGBUS, ...) block), which applies the
//     returned Advance to the faulting PC. (An earlier note here claimed it
//     had no in-tree call site — false since that wiring landed.)

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

// Mask for `size` bytes.
inline uint64_t SizeMask(uint32_t size) {
  if (size >= 8) {
    return ~uint64_t {0};
  }
  return (uint64_t {1} << (size * 8)) - 1;
}

// Update the retry-count high-water telemetry slot with a fetch-max.  Called
// with the retry count observed by a single container LL/SC pass; the slot
// itself lives on TelemetryValues[TYPE_SPLIT_LOCK_MAX_RETRIES] and monotonically
// climbs to the largest retry-count any single split-lock event has ever seen.
// Zero-cost when TYPE_LAST is compiled out or when Retries == 0.
static inline void UpdateSplitLockRetryHighWater(uint32_t Retries) {
#ifndef FEX_DISABLE_TELEMETRY
  if (Retries == 0) {
    return;
  }
  auto& Slot = Telemetry::TelemetryValues[Telemetry::TYPE_SPLIT_LOCK_MAX_RETRIES];
  uint64_t Prev = Slot.load(std::memory_order_relaxed);
  const uint64_t R = Retries;
  while (R > Prev && !Slot.compare_exchange_weak(Prev, R, std::memory_order_relaxed, std::memory_order_relaxed)) {
    // Prev was updated by compare_exchange_weak; loop until either we win
    // the fetch-max race or Prev >= R.
  }
#else
  (void)Retries;
#endif
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

// Shared field-splice arithmetic for C4 (quadword container) and C4.5
// (crossing dual-doubleword): a size-byte operand at byte offset
// Offset ∈ {1..7} inside the LOW doubleword, spilling its remaining
// size-(8-Offset) bytes into the bottom of the HIGH doubleword. Both
// callers guarantee Offset >= 1 and Offset + size > 8, so the field always
// genuinely spans the pair and every shift below stays inside [8..56] bits.
//
// ExtractSpanningField: pull the operand field out of the (Lo, Hi) pair.
static inline uint64_t ExtractSpanningField(uint64_t Lo, uint64_t Hi, uint32_t Offset, uint64_t Mask) {
  const uint32_t LoBits = (8u - Offset) * 8u; // bits of the field held by Lo
  return ((Lo >> (Offset * 8u)) | (Hi << LoBits)) & Mask;
}

// SpliceSpanningField: write the operand field `New` back into the (Lo, Hi)
// pair, preserving every neighbour byte outside the field.
struct SpannedPair {
  uint64_t Lo;
  uint64_t Hi;
};
static inline SpannedPair SpliceSpanningField(uint64_t Lo, uint64_t Hi, uint64_t New, uint32_t Offset, uint32_t size) {
  const uint32_t LoLen = 8u - Offset;  // field bytes held by Lo
  const uint32_t HiLen = size - LoLen; // field bytes held by Hi
  const uint64_t LoFieldMask = ((uint64_t {1} << (LoLen * 8u)) - 1u) << (Offset * 8u);
  // HiLen ∈ {1..7} for every caller (Offset >= 1 caps it at 7); the ternary
  // guards the undefined 64-bit shift all the same.
  const uint64_t HiFieldMask = (HiLen >= 8u) ? ~uint64_t {0} : ((uint64_t {1} << (HiLen * 8u)) - 1u);
  const uint64_t LoPart = New & ((uint64_t {1} << (LoLen * 8u)) - 1u);
  const uint64_t HiPart = New >> (LoLen * 8u);
  return {
    .Lo = (Lo & ~LoFieldMask) | (LoPart << (Offset * 8u)),
    .Hi = (Hi & ~HiFieldMask) | (HiPart & HiFieldMask),
  };
}

// C4 — quadword container fast path via lqarx/stqcx..  Contract:
//   - Caller holds the stripe mutex.
//   - `(EA & 15) + size <= 16`  AND  `(EA & 7) + size > 8` (else C3 got it).
//     The operand lives inside one host quadword but crosses the internal
//     doubleword boundary.
//   - Register pinning is deliberate — the pair used by lqarx / stqcx.
//     must be an even/odd doubleword pair (RTp must have RT even). We hard-
//     code r6/r7 for the load pair and r8/r9 for the store pair inside the
//     inline asm, and list them as clobbers so GCC will not schedule any
//     other value into them across the block. GCC's ppc64le backend has
//     no portable "even-pair" constraint, so numeric-register clobbers +
//     numeric register names in the asm string are the only reliable way.
//   - LE half-ordering: lqarx on little-endian POWER places the HIGH-order
//     doubleword (memory bytes 8..15) into RTp and the LOW-order doubleword
//     (memory bytes 0..7) into RTp+1. We name those OldHi / OldLo to match.
//   - The compile does NOT go through __atomic on __int128 — that GCC path
//     may emit calls into libatomic on this triple (no -mcpu is set, see
//     CMakeLists.txt:527-532), and libatomic uses a lock table which would
//     silently re-introduce the exact non-atomicity this helper is fixing.
//   - CAS mismatch abandons the reservation without stqcx. — the reservation
//     naturally expires on the next atomic anywhere; leaving it live wastes
//     no correctness and a negligible amount of hardware bookkeeping.
//
// Retry: the loop is unbounded in the sound sense (every aligned JIT LL/SC
// path is unbounded too, so this adds no new livelock class). A bounded
// retry with fallback to memcpy would silently re-introduce the crossing-
// mutex vs aligned-LL/SC race precisely when contention is highest, which
// is the class of bug PA explicitly warned against.
static uint32_t ContainerQuadword(SplitLockOp op, void* HostAddr, uint64_t Operand,
                                  uint64_t* result, uint32_t size, uint64_t Mask) {
  const uintptr_t EA = reinterpret_cast<uintptr_t>(HostAddr);
  uint64_t* AlignedPtr = reinterpret_cast<uint64_t*>(EA & ~uintptr_t{15});
  const uint32_t Offset = static_cast<uint32_t>(EA & 15u);
  const uint64_t GuestExpected = (op == SplitLockOp::CAS) ? ((*result) & Mask) : 0;
  uint32_t Retries = 0;

  while (true) {
    uint64_t OldHi = 0, OldLo = 0;

    // lqarx r6, 0, RB    ==>  r6 = mem[EA+8..EA+15]   (high dword, LE)
    //                          r7 = mem[EA..EA+7]      (low  dword, LE)
    asm volatile(
      "lqarx 6, 0, %2\n\t"
      "std 6, %0\n\t"
      "std 7, %1\n\t"
      : "=m"(OldHi), "=m"(OldLo)
      : "r"(AlignedPtr)
      : "r6", "r7", "memory");

    // Extract the size-byte field at Offset from the (OldHi, OldLo) pair.
    // C4 only ever runs when the field crosses the doubleword boundary
    // (Offset < 8 && Offset + size > 8) — the size==8 misaligned case at
    // Offset ∈ {1..7} is the main producer.  Handle just that shape.
    const uint64_t Old = ExtractSpanningField(OldLo, OldHi, Offset, Mask);

    if (op == SplitLockOp::CAS && Old != GuestExpected) {
      // Guest CAS mismatch — abandon reservation, no store.
      *result = Old;
      return Retries;
    }

    uint64_t New;
    if (op == SplitLockOp::CAS) {
      New = Operand & Mask;
    } else {
      New = ApplyRmwOp(op, Old, Operand, Mask);
    }

    // Splice New back.  8-Offset bytes of New land in OldLo[Offset..7], the
    // remaining bytes land at the bottom of OldHi (shared arithmetic with
    // the C4.5 crossing path — see SpliceSpanningField).
    const auto Spliced = SpliceSpanningField(OldLo, OldHi, New, Offset, size);
    const uint64_t NewLo = Spliced.Lo;
    const uint64_t NewHi = Spliced.Hi;

    // stqcx. r8, 0, RB   ==>  writes r8:r9 = new hi:lo back to mem[EA..EA+15]
    uint64_t Success = 0;
    asm volatile(
      "ld 8, %1\n\t"
      "ld 9, %2\n\t"
      "stqcx. 8, 0, %3\n\t"
      "li %0, 0\n\t"
      "bne 1f\n\t"
      "li %0, 1\n\t"
      "1:\n\t"
      : "=r"(Success)
      : "m"(NewHi), "m"(NewLo), "r"(AlignedPtr)
      : "r8", "r9", "cr0", "memory");

    if (Success) {
      *result = Old;
      return Retries;
    }
    // stqcx. failed — reservation was stolen by another aligned atomic
    // on the same 128-byte reservation granule.  Retry the whole loop.
    ++Retries;
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
// composition is preserved by the stripe mutex the caller still holds (and,
// since C4.5, additionally by the crossing path committing through aligned
// doubleword CAS on the same reservation channel).
//
// CAS mismatch does NOT issue a store — the existing memcpy path's
// unconditional write-back on mismatch is the bug PA called out as widening
// the clobber window to failed CASes, and this path deliberately doesn't
// replicate it.
//
// Sizes: valid sizes are {1,2,4,8}.  size==8 with (EA&7)==0 is naturally
// aligned and never lands here (the JIT emits ldarx/stdcx. directly), so
// the interesting cases are size {1,2,4} at any non-crossing offset.
static inline uint32_t ContainerDoubleword(SplitLockOp op, void* HostAddr, uint64_t Operand,
                                           uint64_t* result, uint32_t size, uint64_t Mask) {
  const uintptr_t EA = reinterpret_cast<uintptr_t>(HostAddr);
  const uintptr_t Aligned = EA & ~uintptr_t{7};
  const uint32_t ByteOffset = static_cast<uint32_t>(EA & 7u);
  const uint32_t BitShift = ByteOffset * 8u;
  const uint64_t FieldMask = Mask << BitShift;
  uint64_t* AlignedPtr = reinterpret_cast<uint64_t*>(Aligned);
  uint32_t Retries = 0;

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
        return Retries;
      }
    }
    const uint64_t New = (op == SplitLockOp::CAS) ? (Operand & Mask)
                                                  : ApplyRmwOp(op, Old, Operand, Mask);
    const uint64_t New_dword = (Expected_dword & ~FieldMask) | ((New & Mask) << BitShift);
    if (__atomic_compare_exchange_n(AlignedPtr, &Expected_dword, New_dword,
                                    /*weak=*/false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
      *result = Old;
      return Retries;
    }
    // CAS failed: Expected_dword was overwritten with the current value.
    // Loop; nothing else to reset.
    ++Retries;
  }
}

// C4.5 — crossing dual-doubleword path.  Contract:
//   - Caller holds the stripe mutex(es) covering EA..EA+size-1.
//   - `(EA & 15) + size > 16`: the operand crosses a 16-byte boundary.  With
//     size <= 8 (entry guard) that means it spans exactly the two adjacent
//     aligned doublewords D0 = EA & ~7 and D0 + 8, at byte offset
//     o = EA & 7 ∈ {1..7}.  lqarx cannot reach this shape — the pair
//     straddles two reservation quadwords — which is why C4 rejected it.
//
// Shape: snapshot both doublewords, extract the operand field, compute the
// new value, then commit with one aligned 8-byte CAS per doubleword.  Each
// CAS lowers inline to ldarx/stdcx. on this target (the same guarantee C3
// already ships on), i.e. the same reservation channel as the JIT's aligned
// path — so aligned↔crossing now composes for everything except the window
// between the two commits.  A conflict inside that window is detected and
// counted as a tear; the guest is NEVER told a torn CAS succeeded (see the
// tear block below).  This replaces the memcpy load/op/store fallback,
// whose whole load→store window was invisible to aligned LL/SC in other
// threads and whose failure mode was silent.
//
// Commit order — LOW doubleword (the operand's low-order bytes) first,
// chosen on its own merits:
//   * Contention on a crossing operand lands overwhelmingly on its
//     low-order bytes — pointer identity and counter increments live there,
//     while the high-order bytes of heap pointers and counters are
//     near-constant in practice.
//   * A conflicting write to those low field bytes BEFORE our commit fails
//     the first CAS: clean restart, nothing written anywhere.
//   * A conflicting write to them AFTER our commit was computed from a
//     doubleword we had already fully committed (any atomic whose footprint
//     includes our low field bytes but is not itself crossing is contained
//     in D0, and crossing ops serialise on the stripe mutex), so it simply
//     serialises after this operation — a legal x86 LOCK interleaving, not
//     a tear.
//   * Only a write to the rarely-varying HIGH field bytes inside the commit
//     window can produce a genuine tear.
// So low-first minimises tear frequency.  The trade-off is severity: when a
// tear does fire, the abandoned committed half is the low (varying) half.
// High-first would invert that — the common low-byte conflict would then
// tear on every occurrence (for RMW, a half-applied operation each time) in
// exchange for the abandoned half usually being value-identical to what was
// already in memory.  Keeping the common case fully correct beats softening
// the rare case.
//
// Retry: unbounded, like C3/C4 and every aligned JIT LL/SC loop — a bounded
// retry with a mutex-only fallback would re-introduce the aligned-vs-mutex
// race precisely under contention.  The count feeds the same
// TYPE_SPLIT_LOCK_MAX_RETRIES high-water as the containers.
static uint32_t ContainerCrossing(SplitLockOp op, void* HostAddr, uint64_t Operand, uint64_t* result, uint32_t size, uint64_t Mask) {
  const uintptr_t EA = reinterpret_cast<uintptr_t>(HostAddr);
  const uint32_t Offset = static_cast<uint32_t>(EA & 7u); // ∈ {1..7}
  uint64_t* LoPtr = reinterpret_cast<uint64_t*>(EA & ~uintptr_t {7});
  uint64_t* HiPtr = LoPtr + 1;
  // Byte footprint of the operand inside the high doubleword: its low
  // size-(8-Offset) bytes.  The crossing precondition pins that length to
  // {1..7}, so the shift stays below 64.
  const uint32_t HiLen = size - (8u - Offset);
  const uint64_t HiFieldMask = (uint64_t {1} << (HiLen * 8u)) - 1u;
  const uint64_t GuestExpected = (op == SplitLockOp::CAS) ? ((*result) & Mask) : 0;
  uint32_t Retries = 0;

  while (true) {
    // Snapshot.  Nothing is committed until the low-doubleword CAS below
    // succeeds, so every failure before that point restarts here safely.
    const uint64_t OldLo = __atomic_load_n(LoPtr, __ATOMIC_ACQUIRE);
    const uint64_t OldHi = __atomic_load_n(HiPtr, __ATOMIC_ACQUIRE);
    const uint64_t Old = ExtractSpanningField(OldLo, OldHi, Offset, Mask);

    if (op == SplitLockOp::CAS && Old != GuestExpected) {
      // Guest CAS mismatch: report observed Old and DO NOT store — the old
      // memcpy path's write-back on mismatch widened the clobber window to
      // failed CASes, and no container path replicates it.  The seq_cst
      // barrier x86 owes on a failed LOCK CMPXCHG is provided by the JIT's
      // hwsync/isync bracket around the helper call.
      *result = Old;
      return Retries;
    }

    const uint64_t New = (op == SplitLockOp::CAS) ? (Operand & Mask) : ApplyRmwOp(op, Old, Operand, Mask);
    const auto Spliced = SpliceSpanningField(OldLo, OldHi, New, Offset, size);

    // First commit: low doubleword.  Whole-doubleword compare — a failure
    // means D0 moved (field or neighbour bytes alike); restart from the
    // snapshot, nothing has been written.
    uint64_t ExpectedLo = OldLo;
    if (!__atomic_compare_exchange_n(LoPtr, &ExpectedLo, Spliced.Lo,
                                     /*weak=*/false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
      ++Retries;
      continue;
    }

    // Second commit: high doubleword.  From here on the operation is
    // half-committed; a full restart is FORBIDDEN (it would re-apply the
    // RMW — e.g. a double-applied FetchAdd carry — or re-run a CAS whose
    // low half is already in memory).
    uint64_t ExpectedHi = OldHi;
    uint64_t NewHi = Spliced.Hi;
    while (!__atomic_compare_exchange_n(HiPtr, &ExpectedHi, NewHi,
                                        /*weak=*/false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE)) {
      // ExpectedHi now holds the freshly observed doubleword.
      if ((ExpectedHi & HiFieldMask) == (OldHi & HiFieldMask)) {
        // Field-byte-aware retry of the SECOND CAS only.  The compare above
        // failed on the whole doubleword, but the operand's own bytes are
        // untouched — a neighbouring atomic moved disjoint bytes of the
        // same doubleword.  That disjoint-neighbour case completed
        // correctly under the old memcpy path and must not regress: splice
        // our precomputed field bytes into the fresh neighbour bytes and
        // retry just this CAS.
        //
        // Why re-committing the precomputed high half is sound for every
        // ApplyRmwOp operation: New = f(Old, Operand) depends only on the
        // operand's own field bytes, never on neighbour bytes — Swap and
        // CAS ignore Old entirely; FetchAnd/Or/Xor/CLR are bitwise within
        // the field; FetchAdd/Sub/Neg propagate carries only within the
        // field, seeded from the low field bytes we ourselves committed.
        // The high field bytes still equal Old's (verified by the mask
        // compare above), so New is still the correct completion.  Caveat
        // shared with every value-compare CAS loop in this file and with
        // ARM64's DoCAS64: "untouched" is a value comparison, so an A→B→A
        // rewrite of the high field bytes inside the window is
        // indistinguishable from no write and is absorbed.
        NewHi = (ExpectedHi & ~HiFieldMask) | (Spliced.Hi & HiFieldMask);
        ++Retries;
        continue;
      }

      // Genuine tear: the operand's own bytes in the high doubleword moved
      // after the low doubleword committed.  Rolling back the low half is
      // not an option (a compensating CAS can fail the same way, and the
      // committed bytes may already have been observed), so record the tear
      // and get the guest report right:
      //
      // A tear must NEVER report success.  For CAS the JIT synthesises ZF
      // by comparing *result against the saved Expected (AtomicOps.cpp:
      // cmpd(Dst, TMP4) on the CAS path; CmpPairZ over the Dst pair on the
      // CASPair-8B route), and this point is only reachable after the
      // Old == GuestExpected check passed — returning the pre-op snapshot
      // would therefore yield ZF=1 and tell the guest a half-committed CAS
      // succeeded (a wild pointer in a lock-free structure that nothing
      // self-heals).  Instead splice *result from the FRESHLY observed
      // bytes: the high field bytes provably differ from the snapshot's
      // (that is the tear condition) and Expected equals the snapshot, so
      // *result != Expected and ZF comes out 0 on both the CAS and
      // CASPair-8B paths.  This guarantee is carried entirely by the value
      // returned here — deliberately not by any LOGMAN assert, which
      // compiles to nothing in Release.
      if (op == SplitLockOp::CAS) {
        FEXCORE_TELEMETRY_INC(TYPE_SPLIT_LOCK_CROSSING_CAS_TEAR);
        const uint64_t FreshLo = __atomic_load_n(LoPtr, __ATOMIC_ACQUIRE);
        *result = ExtractSpanningField(FreshLo, ExpectedHi, Offset, Mask);
      } else {
        // RMW tear: the operation is half-applied.  Return the pre-op
        // snapshot the committed half was computed from, so the Fetch*
        // result (and any flags the JIT derives from it) describe the
        // operation actually attempted.
        FEXCORE_TELEMETRY_INC(TYPE_SPLIT_LOCK_CROSSING_RMW_TEAR);
        *result = Old;
      }
      return Retries;
    }

    // Both halves committed: the operation is atomic as far as any
    // value-compare observer can tell.  Report the pre-op field (for CAS
    // this equals GuestExpected, so the JIT's compare yields ZF=1).
    *result = Old;
    return Retries;
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
  // which the pre-C3 memcpy path could not.
  if ((HostAddrVal & 7u) + size <= 8u) {
    FEXCORE_TELEMETRY_INC(TYPE_SPLIT_LOCK_DWORD_CONTAINED);
    const uint32_t Retries = ContainerDoubleword(static_cast<SplitLockOp>(op), HostAddr, Operand, result, size, Mask);
    UpdateSplitLockRetryHighWater(Retries);
    return;
  }

  // C4 — quadword container: operand crosses the internal doubleword boundary
  // but stays inside one host quadword. Run a real lqarx/stqcx. loop against
  // the quadword; composes with aligned LL/SC in other threads for the same
  // reason as C3.
  if ((HostAddrVal & 15u) + size <= 16u) {
    FEXCORE_TELEMETRY_INC(TYPE_SPLIT_LOCK_QWORD_CONTAINED);
    const uint32_t Retries = ContainerQuadword(static_cast<SplitLockOp>(op), HostAddr, Operand, result, size, Mask);
    UpdateSplitLockRetryHighWater(Retries);
    return;
  }

  // C4.5 — crossing: everything both containers rejected spans a 16-byte
  // boundary, i.e. exactly the two adjacent aligned doublewords EA & ~7 and
  // (EA & ~7) + 8.  Commit through one 8-byte CAS per doubleword, still
  // under the stripe mutex.  This composes with aligned LL/SC in other
  // threads except for the window between the two commits, where a conflict
  // is detected and counted as a tear instead of the old memcpy fallback's
  // silent corruption.  Residual producers: 8-byte ops at (EA & 15) > 8 and
  // i386 4-aligned `cmpxchg8b` at offset 12 mod 16.
  FEXCORE_TELEMETRY_INC(TYPE_SPLIT_LOCK_CROSSING_MUTEX);
  const uint32_t Retries = ContainerCrossing(static_cast<SplitLockOp>(op), HostAddr, Operand, result, size, Mask);
  UpdateSplitLockRetryHighWater(Retries);
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
