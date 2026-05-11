// SPDX-License-Identifier: MIT
// Signal context helpers — architecture-neutral dispatcher.
//
// Pulls in the per-arch implementation based on the compile-time architecture.
// Each arch file defines:
//   - ContextBackup struct and `using ContextBackup = ...`
//   - GetSp/SetSp, GetPc/SetPc, GetState/SetState
//   - GetArmReg/SetArmReg, GetArmGPRs, GetArmFPR, GetArmPState (or stubs)
//   - GetProtectFlags
//   - BackupContext<T> / RestoreContext<T>
#pragma once

#include "UContext.h"

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>

#include <signal.h>
#include <string.h>
#ifndef _WIN32
#include <ucontext.h>
#endif
#include <stdint.h>
#include <type_traits>

namespace FEX::ArchHelpers::Context {
#ifndef _WIN32

enum ContextFlags : uint32_t {
  CONTEXT_FLAG_INJIT = (1U << 0),
};

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
constexpr uint64_t STACK_COOKIE_MAGIC = 0x4142434445464748ULL;
#endif

// ---------------------------------------------------------------------------
// Common helpers available on all architectures
// ---------------------------------------------------------------------------

static inline ucontext_t* GetUContext(void* ucontext) {
  return static_cast<ucontext_t*>(ucontext);
}

static inline mcontext_t* GetMContext(void* ucontext) {
  return &static_cast<ucontext_t*>(ucontext)->uc_mcontext;
}

// ---------------------------------------------------------------------------
// Per-architecture implementations
// ---------------------------------------------------------------------------
#if defined(ARCHITECTURE_arm64)
#  include "MContext_arm64.h"
#elif defined(ARCHITECTURE_ppc64le)
#  include "MContext_ppc64le.h"
#elif defined(ARCHITECTURE_x86_64)
#  include "MContext_x86_64.h"
#endif

#else // _WIN32

#endif // _WIN32
} // namespace FEX::ArchHelpers::Context
