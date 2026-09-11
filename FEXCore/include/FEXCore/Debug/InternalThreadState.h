// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/LongJump.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/vector.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <shared_mutex>
#include <type_traits>

#ifndef _WIN32
#include <sys/mman.h>
#endif

namespace FEXCore {
class LookupCache;
class CompileService;
struct JITSymbolBuffer;
} // namespace FEXCore

namespace FEXCore::Context {
class Context;
}

namespace FEXCore::CPU {
class CPUBackend;
} // namespace FEXCore::CPU

namespace FEXCore::Frontend {
class Decoder;
}

namespace FEXCore::IR {
class OpDispatchBuilder;
class PassManager;
} // namespace FEXCore::IR

namespace FEXCore::SHMStats {
struct ThreadStats;
};

namespace FEXCore::Core {

// Special-purpose replacement for std::unique_ptr to allow InternalThreadState to be standard layout.
// Since a NonMovableUniquePtr is neither copyable nor movable, its only function is to own and release the contained object.
template<typename T>
struct NonMovableUniquePtr {
  NonMovableUniquePtr() noexcept = default;
  NonMovableUniquePtr(const NonMovableUniquePtr&) = delete;
  NonMovableUniquePtr& operator=(const NonMovableUniquePtr& UPtr) = delete;

  NonMovableUniquePtr& operator=(fextl::unique_ptr<T> UPtr) noexcept {
    Ptr = UPtr.release();
    return *this;
  }

  ~NonMovableUniquePtr() {
    fextl::default_delete<T> {}(Ptr);
  }

  T* operator->() const noexcept {
    return Ptr;
  }

  std::add_lvalue_reference_t<T> operator*() const noexcept {
    return *Ptr;
  }

  T* get() const noexcept {
    return Ptr;
  }

  explicit operator bool() const noexcept {
    return Ptr != nullptr;
  }

private:
  T* Ptr = nullptr;
};
static_assert(!std::is_move_constructible_v<NonMovableUniquePtr<int>>);
static_assert(!std::is_move_assignable_v<NonMovableUniquePtr<int>>);

// Store used for unaligned LDAXR*/STLXR* emulation.
struct UnalignedExclusiveStore {
  uint64_t Addr;
  uint64_t Store;
  uint8_t Size;
};

struct InternalThreadState : public FEXCore::Allocator::FEXAllocOperators {
  FEXCore::Core::CpuStateFrame* const CurrentFrame = &BaseFrameState;

  FEXCore::Context::Context* const CTX;

  NonMovableUniquePtr<FEXCore::IR::OpDispatchBuilder> OpDispatcher;

  NonMovableUniquePtr<FEXCore::CPU::CPUBackend> CPUBackend;
  NonMovableUniquePtr<FEXCore::LookupCache> LookupCache;

  NonMovableUniquePtr<FEXCore::Frontend::Decoder> FrontendDecoder;
  NonMovableUniquePtr<FEXCore::IR::PassManager> PassManager;
  NonMovableUniquePtr<JITSymbolBuffer> SymbolBuffer;

  std::shared_ptr<FEXCore::CompileService> CompileService;

  std::shared_mutex ObjectCacheRefCounter {};

  // This pointer is owned by the frontend.
  FEXCore::SHMStats::ThreadStats* ThreadStats {};

  UnalignedExclusiveStore ExclusiveStore;

  ///< Data pointer for exclusive use by the frontend
  void* FrontendPtr;

  static constexpr size_t CALLRET_STACK_SIZE {0x400000};

  // The low address of the call-ret stack allocation (not including guard pages)
  void* CallRetStackBase {};

  uintptr_t JITGuardPage {};
  uint64_t JITGuardOverflowArgument {};
  FEXCore::UncheckedLongJump::JumpBuf RestartJump;

  // Result of the most recent arm/disarm mprotect of the interrupt fault page.
  // The arming sites run in signal context, where LogMan is not async-signal-safe
  // and errors used to be discarded outright (and a discarded EINVAL here means
  // async signals silently never drain). They store errno here instead; anything
  // running outside signal context can read it and complain.
  // sig_atomic_t so the store is a single instruction with no library call.
  volatile sig_atomic_t InterruptFaultPageProtectErrno {};

#ifndef _WIN32
  /**
   * @brief Arm (PROT_NONE) or disarm (PROT_READ|PROT_WRITE) the interrupt fault page.
   *
   * ASYNC-SIGNAL-SAFE. Every caller but one runs inside a signal handler, so this
   * must never log and never allocate: one mprotect, and on failure one
   * sig_atomic_t store that somebody outside signal context can read.
   * Returns true on success.
   */
  bool ProtectInterruptFaultPage(bool Arm) {
    auto* Page = BaseFrameState.InterruptFaultPagePtr;
    if (!Page) [[unlikely]] {
      return false;
    }
    if (::mprotect(Page, FEXCore::HostPage::Size(), Arm ? PROT_NONE : (PROT_READ | PROT_WRITE)) != 0) [[unlikely]] {
      InterruptFaultPageProtectErrno = errno;
      return false;
    }
    return true;
  }
#endif

  // BaseFrameState should always be at the end.
  // NOTE: the interrupt fault page used to be an embedded array immediately after
  // this member, which is why the struct was alignas(page) and asserted to be
  // exactly two pages. It is now an mmap'd host page whose address lives in
  // BaseFrameState.InterruptFaultPagePtr (see CoreState.h), so neither the
  // alignment nor the size constraint applies any more.
  FEXCore::Core::CpuStateFrame BaseFrameState {};
};
static_assert(std::is_standard_layout_v<FEXCore::Core::InternalThreadState>);
// BaseFrameState reachability: the JIT addresses everything it needs through
// STATE == &BaseFrameState with signed 16-bit D-form displacements, so the frame
// must still be the last member (nothing may be placed after it that the JIT
// would have to reach) and must be 8-byte aligned for the ld/std forms.
static_assert(offsetof(FEXCore::Core::InternalThreadState, BaseFrameState) + sizeof(FEXCore::Core::CpuStateFrame) ==
                sizeof(FEXCore::Core::InternalThreadState),
              "BaseFrameState must be the last member of InternalThreadState");
static_assert(offsetof(FEXCore::Core::InternalThreadState, BaseFrameState) % 8 == 0,
              "BaseFrameState must be 8-byte aligned for the JIT's D-form accesses");

} // namespace FEXCore::Core
