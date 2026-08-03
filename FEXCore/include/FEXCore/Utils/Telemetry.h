// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/fextl/string.h>

#include <array>
#include <atomic>
#include <stdint.h>

namespace FEXCore::Telemetry {
enum TelemetryType {
  TYPE_HAS_SPLIT_LOCKS,
  TYPE_16BYTE_SPLIT,
  TYPE_USES_EVEX_OPS,
  TYPE_CAS_16BIT_TEAR,
  TYPE_CAS_32BIT_TEAR,
  TYPE_CAS_64BIT_TEAR,
  TYPE_CAS_128BIT_TEAR,
  TYPE_CRASH_MASK,
  // If a 32-bit application is writing a non-zero value to segments.
  TYPE_WRITES_32BIT_SEGMENT_ES,
  TYPE_WRITES_32BIT_SEGMENT_SS,
  TYPE_WRITES_32BIT_SEGMENT_CS,
  TYPE_WRITES_32BIT_SEGMENT_DS,
  // If a 32-bit application is prefix/using a non-zero segment on memory access.
  TYPE_USES_32BIT_SEGMENT_ES,
  TYPE_USES_32BIT_SEGMENT_SS,
  TYPE_USES_32BIT_SEGMENT_CS,
  TYPE_USES_32BIT_SEGMENT_DS,
  TYPE_UNHANDLED_NONCANONICAL_ADDRESS,
  // Sentinel: entries at or above this index are C-helper-only and are NOT
  // exposed via the per-thread CpuStateFrame::TelemetryValueAddresses table.
  // The JIT indexes that table via TelemetryValueIndex, so growing it costs
  // 8 bytes per new slot per thread and tightens the InternalThreadState
  // ≤ 2·PAGE_SIZE invariant (see CoreState.h:362 and
  // InternalThreadState.h:133). Only add above this marker if you actually
  // need JIT-emitted access.
  TYPE_JIT_ADDRESSABLE_LAST,
  // PPC64 split-lock helper path breakdown (C5). PPC64_SplitLockEmulate
  // dispatches by containment inside the striped mutex; these three counters
  // let us tell how much of the split-lock traffic lands on each path from
  // the shutdown dump, rather than inferring it from a single
  // TYPE_HAS_SPLIT_LOCKS total. (Since C4.5 the crossing path is a
  // dual-doubleword CAS under the stripe mutex, no longer a plain memcpy;
  // the counter keeps its name because the mutex is still held there.)
  // TYPE_HAS_SPLIT_LOCKS remains the always-incremented top-level counter.
  TYPE_SPLIT_LOCK_DWORD_CONTAINED = TYPE_JIT_ADDRESSABLE_LAST,
  TYPE_SPLIT_LOCK_QWORD_CONTAINED,
  TYPE_SPLIT_LOCK_CROSSING_MUTEX,
  // High-water mark of the container LL/SC retry count observed by any
  // helper invocation. Container livelocks are the class of failure this
  // instrument exists to make diagnosable — a normal run shows single-digit
  // retries; a livelock shows an unbounded climb.
  TYPE_SPLIT_LOCK_MAX_RETRIES,
  // C4.5 crossing-path tear counters, CAS and RMW separately. A tear is the
  // crossing path's second doubleword commit finding the operand's own bytes
  // changed after the first doubleword already committed — the one window a
  // dual-doubleword CAS cannot make atomic against the JIT's mutex-free
  // aligned LL/SC path. A CAS tear is reported to the guest as CAS failure
  // (never success — see ContainerCrossing in PPC64.cpp); an RMW tear leaves
  // the operation half-applied. Any nonzero value in a shutdown dump is a
  // real guest-visible atomicity violation, not noise.
  TYPE_SPLIT_LOCK_CROSSING_CAS_TEAR,
  TYPE_SPLIT_LOCK_CROSSING_RMW_TEAR,
  TYPE_LAST,
};

#ifndef FEX_DISABLE_TELEMETRY
using Value = std::atomic<uint64_t>;

FEX_DEFAULT_VISIBILITY extern std::array<Value, FEXCore::Telemetry::TelemetryType::TYPE_LAST> TelemetryValues;
// This returns the internal structure to the telemetry data structures
// One must be careful with placing these in the hot path of code execution
// It can be fairly costly, especially in the static version where it puts barriers in the code
inline Value& GetTelemetryValue(TelemetryType Type) {
  return FEXCore::Telemetry::TelemetryValues[Type];
}

FEX_DEFAULT_VISIBILITY void Initialize();
FEX_DEFAULT_VISIBILITY void Shutdown(const fextl::string& ApplicationName);

// Telemetry object declaration
// Telemetry ALU operations
// These are typically 3-4 instructions depending on what you're doing
#define FEXCORE_TELEMETRY_SET(Type, Value)                                      \
  do {                                                                          \
    auto& Name = FEXCore::Telemetry::TelemetryValues[FEXCore::Telemetry::Type]; \
    Name = Value;                                                               \
  } while (0)
#define FEXCORE_TELEMETRY_OR(Type, Value)                                       \
  do {                                                                          \
    auto& Name = FEXCore::Telemetry::TelemetryValues[FEXCore::Telemetry::Type]; \
    Name |= Value;                                                              \
  } while (0)
// Takes only the type -- an increment has no operand. This previously
// declared a second `Value` parameter that the body ignored, which did not
// match the FEX_DISABLE_TELEMETRY definition below and so made the macro
// uncallable: the one-argument form failed to compile with telemetry on, the
// two-argument form failed with it off. It had no callers, so nothing had
// forced the contradiction to the surface.
#define FEXCORE_TELEMETRY_INC(Type)                                             \
  do {                                                                          \
    auto& Name = FEXCore::Telemetry::TelemetryValues[FEXCore::Telemetry::Type]; \
    Name++;                                                                     \
  } while (0)

#else
static inline void Initialize() {}
static inline void Shutdown(const fextl::string& ApplicationName) {}

#define FEXCORE_TELEMETRY_INIT(Name, Type)
#define FEXCORE_TELEMETRY(Name, Value) \
  do {                                 \
  } while (0)
#define FEXCORE_TELEMETRY_SET(Name, Value) \
  do {                                     \
  } while (0)
#define FEXCORE_TELEMETRY_OR(Name, Value) \
  do {                                    \
  } while (0)
#define FEXCORE_TELEMETRY_INC(Name) \
  do {                              \
  } while (0)
#endif
} // namespace FEXCore::Telemetry
