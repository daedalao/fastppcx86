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
};

/**
 * @brief Process-wide serialized emulation of a misaligned x86 LOCK RMW.
 *
 * Phase-2 building block for the SIGBUS-driven split-lock path. Acquires a
 * process-wide std::mutex, performs a plain load -> modify -> store on
 * `addr`, and writes the pre-RMW value (or CAS result) to `*result`.
 *
 * Genuinely atomic w.r.t. other threads going through this same helper.
 * Not atomic w.r.t. lock-free accesses to the same line from non-FEX code,
 * but x86 LOCK semantics on a misaligned cache-line-spanning EA are already
 * implementation-defined, so this matches the x86 contract closely enough.
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
 * Phase 3 (not yet wired) will replace the non-atomic misaligned fallback
 * in JIT/PPC64LE/AtomicOps.cpp with calls to this helper. For now it is
 * only called from the SIGBUS signal handler when split-lock detection
 * fires, which is itself currently logging-only -- see SignalDelegator.cpp.
 */
extern "C" FEX_DEFAULT_VISIBILITY void
PPC64_SplitLockEmulate(uint8_t op, uint64_t* addr, uint64_t* value, uint64_t* result, uint32_t size);

/**
 * @brief Decoder + dispatcher for a SIGBUS that landed inside JIT code.
 *
 * Caller must have already verified that `ProgramCounter` is inside a JIT
 * code buffer (CPUBackend::IsAddressInCodeBuffer). This routine inspects
 * the instruction at PC, classifies it as a reservation-load (lbarx/lharx/
 * lwarx/ldarx), and -- if it is -- increments the split-lock telemetry
 * counter and logs. It does NOT yet backpatch or emulate; that is Phase 3.
 *
 * @return std::nullopt if the SIGBUS was not from a reservation load (the
 *         caller should treat the fault as unhandled). On a recognized
 *         split-lock LL the return value is also std::nullopt for now,
 *         since Phase 1 is log-only -- letting the fault escape avoids
 *         spinning forever on the unmodified LL instruction.
 */
[[nodiscard]] FEX_DEFAULT_VISIBILITY std::optional<int32_t>
HandleUnalignedAtomicSIGBUS(FEXCore::Core::InternalThreadState* Thread, uintptr_t ProgramCounter, uint64_t* GPRs);

} // namespace FEXCore::ArchHelpers::PPC64
