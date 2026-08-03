// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/CompilerDefs.h>

#include <cstdint>
#include <optional>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEXCore::ArchHelpers::PPC64 {

// Op tags for PPC64_SplitLockEmulate(). Mirror the IR atomic ops we may
// eventually backpatch a split-lock fault into.
enum class SplitLockOp : uint8_t {
  Swap     = 0,
  FetchAdd = 1,
  FetchSub = 2,
  FetchAnd = 3,
  FetchOr  = 4,
  FetchXor = 5,
  FetchNeg = 6,
  CAS      = 7,
  FetchCLR = 8, // x86 LOCK BTR/BTC mask-clear semantics: New = Old & ~Operand
};

/**
 * @brief Process-wide serialized emulation of a misaligned x86 LOCK RMW.
 *
 * Acquires the striped cacheline mutex, then dispatches by containment:
 *   - `(EA & 7) + size <= 8`  → real ldarx/stdcx. against the doubleword (C3)
 *   - `(EA & 15) + size <= 16` → real lqarx/stqcx. against the quadword (C4)
 *   - crossing                 → dual-doubleword CAS under the mutex (C4.5)
 *
 * The container paths compose with FEX's own aligned LL/SC path on
 * overlapping bytes in another FEX thread — both use real hardware
 * reservations on the same 128-byte granule. The crossing path commits one
 * aligned 8-byte CAS per doubleword, so it composes too except for the
 * window between its two commits; a conflict there is detected, counted as
 * a tear, and reported to the guest as CAS failure / half-applied RMW —
 * never as success. (Residual of Tier D atomics defect 1, narrowed by C4.5
 * from silent corruption to a detected tear, for 8-byte ops at
 * (EA & 15) > 8 and i386 `cmpxchg8b` at offset 12 mod 16.)
 * Earlier phrasing that called the mutex-vs-external-LL/SC case "external"
 * misidentified the failure — the real exposure is FEX-internal, between
 * two FEX threads.
 *
 * @param op     Which RMW operation to perform (see SplitLockOp).
 * @param addr   Host-virtual pointer to guest memory. May be misaligned.
 * @param value  Pointer to the RMW operand (e.g. addend, AND mask, or
 *               for CAS, the new value).
 * @param result Pointer to where the pre-RMW value is written. For CAS,
 *               written value is the loaded value (which the caller
 *               compares with their expected to decide ZF).
 * @param size   Operand size in bytes (1, 2, 4, or 8).
 *
 * Called from AtomicOps.cpp on every misaligned RMW dispatch and from the
 * SIGBUS handler in SignalDelegator.cpp when a JIT-emitted lwarx/ldarx
 * faults on a misaligned EA.
 */
extern "C" FEX_DEFAULT_VISIBILITY void
PPC64_SplitLockEmulate(uint8_t op, uint64_t* addr, uint64_t* value, uint64_t* result, uint32_t size);

/**
 * @brief Decoder + dispatcher for a SIGBUS that landed inside JIT code.
 *
 * Caller must have already verified that `ProgramCounter` is inside a JIT
 * code buffer (CPUBackend::IsAddressInCodeBuffer). This routine inspects
 * the instruction at PC, classifies it as a reservation-load (lbarx/lharx/
 * lwarx/ldarx), decodes the JIT's surrounding LL/SC sequence, and routes
 * the operation through PPC64_SplitLockEmulate. Wired in from
 * SignalDelegator.cpp's SIGBUS handler, which applies the returned advance
 * to the faulting PC. (Earlier phrasing here described a log-only Phase 1
 * with no in-tree call site — both stale.)
 *
 * @return std::nullopt if the SIGBUS was not from a recognised JIT LL/SC
 *         sequence (the caller should treat the fault as unhandled).
 *         Otherwise the byte count to advance the faulting PC by, so
 *         execution resumes past the emulated LL/SC sequence.
 */
[[nodiscard]] FEX_DEFAULT_VISIBILITY std::optional<int32_t>
HandleUnalignedAtomicSIGBUS(FEXCore::Core::InternalThreadState* Thread, uintptr_t ProgramCounter, uint64_t* GPRs);

} // namespace FEXCore::ArchHelpers::PPC64
