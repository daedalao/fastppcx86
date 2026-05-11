// SPDX-License-Identifier: MIT
#pragma once
#include <FEXCore/Utils/CompilerDefs.h>

#include <cstdint>

// Reimplementation of longjmp without glibc fortification checks.
// This is useful when false positives need to be avoided or when using
// a libc implementation that does not implement std::longjmp.
namespace FEXCore::UncheckedLongJump {
// JumpBuf definition needs to be public because the frontend needs to understand it.
#if defined(ARCHITECTURE_arm64)
struct JumpBuf {
  // All the registers that are required by AAPCS64 to save.
  // GPRs
  // X19, X20, X21, X22,
  // X23, X24, X25, X26,
  // X27, X28, X29, X30,
  //
  // Lower 64-bits:
  //  V8,  V9, V10, V11,
  // V12, V13, V14, V15,
  //
  // SP,
  uint64_t Registers[21];
};
#elif defined(ARCHITECTURE_ppc64le)
struct JumpBuf {
  // ELFv2 ABI: save r14-r31, r1 (SP), LR, CR.
  // FPRs (f14-f31) and VMX (v20-v31) are omitted — FEX's own C++ control paths
  // do not rely on callee-saved FP/vector state across a longjmp recovery.
  // Same slot count as ARM64 (21) so InternalThreadState stays within 2 pages.
  // Layout: [r14..r31]=0..17, SP=18, LR=19, CR=20
  uint64_t Registers[21];
};
#else
struct JumpBuf {
  // Registers to preserve
  // RBX, RSP, RBP, R12, R13, R14, R15,
  // <return address>
  uint64_t Registers[8];
};
#endif

[[nodiscard]] FEX_DEFAULT_VISIBILITY uint64_t SetJump(JumpBuf& Buffer);
[[noreturn]] FEX_DEFAULT_VISIBILITY void LongJump(const JumpBuf& Buffer, uint64_t Value);
FEX_DEFAULT_VISIBILITY void ManuallyLoadJumpBuf(const JumpBuf& Buffer, uint64_t Value, uint64_t* GPRs, __uint128_t* FPRs, uint64_t* PC);
} // namespace FEXCore::UncheckedLongJump
