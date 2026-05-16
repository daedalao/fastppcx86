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
//   - PPC64_SplitLockEmulate(): a process-wide mutex-serialized RMW.
//   - HandleUnalignedAtomicSIGBUS(): SIGBUS instruction decoder that
//     recognizes a reservation-load opcode (primary=31, XO in
//     {52, 116, 20, 84}) and increments telemetry.
//
// Plug-in (calling PPC64_SplitLockEmulate from the misaligned fallback in
// AtomicOps.cpp) is intentionally deferred: it changes hot-path codegen
// and must not be done while another agent is concurrently fixing failing
// atomic tests in the same file.

#include <FEXCore/Utils/ArchHelpers/PPC64.h>
#include <FEXCore/Utils/LogManager.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace FEXCore::ArchHelpers::PPC64 {

namespace {
// Process-wide serialization for split-lock emulation. A single global mutex
// is the simplest correct option; under typical x86 workloads misaligned
// LOCK RMW is so rare that contention on this mutex is irrelevant. If it
// ever becomes a hot path, a 64-way striped mutex keyed by (addr >> 6) would
// reduce contention without changing semantics.
std::mutex g_SplitLockMutex;

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
} // namespace

extern "C" void PPC64_SplitLockEmulate(uint8_t op, uint64_t* addr, uint64_t* value, uint64_t* result, uint32_t size) {
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

  std::lock_guard<std::mutex> Lock(g_SplitLockMutex);

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

std::optional<int32_t> HandleUnalignedAtomicSIGBUS(FEXCore::Core::InternalThreadState* Thread, uintptr_t ProgramCounter, uint64_t* GPRs) {
  (void)Thread;
  (void)GPRs;

  if (ProgramCounter == 0 || (ProgramCounter & 3u) != 0) {
    // PowerISA instructions are 4-byte aligned; a misaligned PC means our
    // caller's IsAddressInCodeBuffer check was lying.
    return std::nullopt;
  }

  uint32_t Insn = 0;
  std::memcpy(&Insn, reinterpret_cast<const void*>(ProgramCounter), sizeof(uint32_t));

  const uint32_t Primary = (Insn >> 26) & 0x3f;
  const uint32_t XO      = (Insn >> 1) & 0x3ff;

  // Reservation-load X-form opcodes (PowerISA 3.0 Book II):
  //   lbarx -- primary 31, XO 52
  //   lharx -- primary 31, XO 116
  //   lwarx -- primary 31, XO 20
  //   ldarx -- primary 31, XO 84
  if (Primary != 31) {
    return std::nullopt;
  }
  switch (XO) {
  case 20:  // lwarx
  case 52:  // lbarx
  case 84:  // ldarx
  case 116: // lharx
    break;
  default:
    return std::nullopt;
  }

  g_SplitLockDetectedCount.fetch_add(1, std::memory_order_relaxed);
  LogMan::Msg::DFmt("PPC64 split-lock SIGBUS detected at PC=0x{:x} insn=0x{:08x} XO={} (Phase 1: log-only)", ProgramCounter, Insn, XO);

  // TODO Phase 3: wire to PPC64_SplitLockEmulate here.
  //
  // Sketch of the eventual logic:
  //   1. Identify the RA/RB GPRs from the X-form encoding (bits 11:15
  //      and 16:20) -- Insn was loaded above. EA = (RA?GPRs[RA]:0) + GPRs[RB].
  //   2. Walk forward from PC up to N (probably 16) instructions to find
  //      the matching stbcx_/sthcx_/stwcx_/stdcx_, learning the value
  //      register and the LL/SC body in between (which encodes the RMW
  //      op tag).
  //   3. Backpatch the LL through the bc-loop branch to a `bl` of a
  //      runtime stub that marshals (op, addr, value, result) into the
  //      ABI and calls PPC64_SplitLockEmulate, then `b`'s over the
  //      original LL/SC body.
  //   4. Return the byte count to roll PC backwards so the patched LL
  //      instruction re-executes via the stub.
  //
  // Phase 1 returns nullopt so the SIGBUS escapes to the guest as a
  // genuine fault rather than looping forever on the unmodified LL.
  return std::nullopt;
}

} // namespace FEXCore::ArchHelpers::PPC64
