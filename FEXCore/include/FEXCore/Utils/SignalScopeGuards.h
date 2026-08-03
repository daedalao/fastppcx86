// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/WritePriorityMutex.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <signal.h>
#ifndef _WIN32
#include <sys/syscall.h>
#endif
#include <type_traits>
#include <unistd.h>
#include <variant>

namespace FEXCore {
#ifndef _WIN32
// Replacement for std::mutexes to deal with unlocking issues in the face of Linux fork() semantics.
//
// A fork() only clones the parent's calling thread. Other threads are silently dropped, which permanently leaves any mutexes owned by them locked.
// To address this issue, ForkableUniqueMutex and ForkableSharedMutex provide a way to forcefully remove any dangling locks and reset the mutexes to their default state.
class ForkableUniqueMutex final {
public:
  ForkableUniqueMutex()
    : Mutex(PTHREAD_MUTEX_INITIALIZER) {}

  // Move-only type
  ForkableUniqueMutex(const ForkableUniqueMutex&) = delete;
  ForkableUniqueMutex& operator=(const ForkableUniqueMutex&) = delete;
  ForkableUniqueMutex(ForkableUniqueMutex&& rhs) = default;
  ForkableUniqueMutex& operator=(ForkableUniqueMutex&&) = default;

  void lock() {
    const auto Result = pthread_mutex_lock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == 0, "{} failed to lock with {}", __func__, Result);
  }
  // Non-blocking acquire, for callers that may not wait (signal handlers).
  // Returns false both when the mutex is held by another thread and when this
  // thread already owns it (this mutex is not recursive).
  [[nodiscard]]
  bool try_lock() {
    return pthread_mutex_trylock(&Mutex) == 0;
  }
  void unlock() {
    const auto Result = pthread_mutex_unlock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == 0, "{} failed to unlock with {}", __func__, Result);
  }
  // Initialize the internal pthread object to its default initializer state.
  // Should only ever be used in the child process when a Linux fork() has occured.
  void StealAndDropActiveLocks() {
    Mutex = PTHREAD_MUTEX_INITIALIZER;
  }

  // Asserts that the mutex isn't exclusively owned by the calling thread.
  void check_lock_owned_by_self() {
    const auto Result = pthread_mutex_lock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == EDEADLK, "User of unique lock must have already locked mutex as write!");
  }

private:
  pthread_mutex_t Mutex;
};

class ForkableSharedMutex final {
public:
  ForkableSharedMutex()
    : Mutex(PTHREAD_RWLOCK_INITIALIZER) {}

  // Move-only type
  ForkableSharedMutex(const ForkableSharedMutex&) = delete;
  ForkableSharedMutex& operator=(const ForkableSharedMutex&) = delete;
  ForkableSharedMutex(ForkableSharedMutex&& rhs) = default;
  ForkableSharedMutex& operator=(ForkableSharedMutex&&) = default;

  void lock() {
    const auto Result = pthread_rwlock_wrlock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == 0, "{} failed to lock with {}", __func__, Result);
  }
  void unlock() {
    const auto Result = pthread_rwlock_unlock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == 0, "{} failed to unlock with {}", __func__, Result);
  }
  void lock_shared() {
    const auto Result = pthread_rwlock_rdlock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == 0, "{} failed to lock with {}", __func__, Result);
  }

  void unlock_shared() {
    unlock();
  }

  bool try_lock() {
    const auto Result = pthread_rwlock_trywrlock(&Mutex);
    return Result == 0;
  }

  bool try_lock_shared() {
    const auto Result = pthread_rwlock_tryrdlock(&Mutex);
    return Result == 0;
  }

  // Asserts that the rwlock isn't exclusively owned by the calling thread.
  void check_lock_owned_by_self_as_write() {
    const auto Result = pthread_rwlock_wrlock(&Mutex);
    LOGMAN_THROW_A_FMT(Result == EDEADLK, "User of rwlock must have already locked mutex as write!");
  }

  // Initialize the internal pthread object to its default initializer state.
  // Should only ever be used in the child process when a Linux fork() has occured.
  void StealAndDropActiveLocks() {
    Mutex = PTHREAD_RWLOCK_INITIALIZER;
  }
private:
  pthread_rwlock_t Mutex;
};

// Helper class to manage deferred signal refcounting within a block scope
class DeferredSignalRefCountGuard final {
public:
  explicit DeferredSignalRefCountGuard(FEXCore::Core::InternalThreadState* Thread)
    : Thread(Thread) {
    // Needs to be atomic so that operations can't end up getting reordered around this.
    Thread->CurrentFrame->State.DeferredSignalRefCount.Increment(1);
  }

  // Move-only type
  DeferredSignalRefCountGuard(const DeferredSignalRefCountGuard&) = delete;
  DeferredSignalRefCountGuard& operator=(DeferredSignalRefCountGuard&) = delete;
  DeferredSignalRefCountGuard(DeferredSignalRefCountGuard&& rhs)
    : Thread(rhs.Thread) {
    rhs.Thread = nullptr;
  }

  ~DeferredSignalRefCountGuard() {
    if (Thread) {
#ifdef ARCHITECTURE_x86_64
      // Needs to be atomic so that operations can't end up getting reordered around this.
      // Without this, the refcount and the signal access could get reordered.
      auto Result = Thread->CurrentFrame->State.DeferredSignalRefCount.Decrement(1);

      // X86-64 must do an additional check around the store.
      if ((Result - 1) == 0) {
        // Must happen after the refcount store
        auto InterruptFaultPage = reinterpret_cast<Core::NonAtomicRefCounter<uint64_t>*>(&Thread->InterruptFaultPage);
        InterruptFaultPage->Store(0);
      }
#else
      Thread->CurrentFrame->State.DeferredSignalRefCount.Decrement(1);
      auto InterruptFaultPage = reinterpret_cast<Core::NonAtomicRefCounter<uint64_t>*>(&Thread->InterruptFaultPage);
      InterruptFaultPage->Store(0);
#endif
    }
  }
private:
  FEXCore::Core::InternalThreadState* Thread;
};

// Helper class to mask POSIX signals within a block scope
class ScopedSignalMasker final {
public:
  explicit ScopedSignalMasker(uint64_t Mask)
    : OriginalMask(0) {
    // Mask all signals, storing the original incoming mask
    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &Mask, &*OriginalMask, sizeof(*OriginalMask));
  }

  // Move-only type
  ScopedSignalMasker(const ScopedSignalMasker&) = delete;
  ScopedSignalMasker& operator=(ScopedSignalMasker&) = delete;
  ScopedSignalMasker(ScopedSignalMasker&& rhs)
    : OriginalMask(rhs.OriginalMask) {
    rhs.OriginalMask.reset();
  }

  ~ScopedSignalMasker() {
    if (OriginalMask) {
      ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &OriginalMask, nullptr, sizeof(*OriginalMask));
    }
  }
private:
  std::optional<uint64_t> OriginalMask {};
};

// Per-thread bookkeeping of WritePriorityMutex::Mutex shared locks held via
// GuardSignalDeferringSection<std::shared_lock>.  Solves two related issues:
//
//  1. A guest thread can terminate without unwinding the host C++ stack
//     (e.g. guest _exit() syscall path: LongjumpDeallocateAndExit longjmps
//     past the scope guard dtors; SIGKILL kills the thread; etc).  The
//     reader-count slot inside the mutex stays incremented forever, and
//     every future writer hangs.
//
//  2. A synchronous signal (SIGSEGV for SMC tracking) can interrupt a JIT
//     block currently executing under a CompileBlock or ExitFunctionLink
//     scope guard.  The signal handler then attempts to acquire the WRITE
//     side of CodeInvalidationMutex via InvalidateGuestCodeRange -- which
//     self-deadlocks because the same thread holds the read side, and
//     WritePriorityMutex is non-recursive.  ReleaseAllPendingSharedLocks()
//     called from the SMC handler before InvalidateGuestCodeRange clears
//     this thread's outstanding read locks so the write acquisition can
//     proceed.  The interrupted scope guard is then either abandoned
//     (signal handler redirects PC away from the original block) or its
//     dtor is converted into a no-op via TrackedSharedLock::TakeOver().
//
// Depth bound: WritePriorityMutex is non-recursive, so at most one shared
// lock per Mutex per thread.  Today only one mutex hits this path
// (ContextImpl::CodeInvalidationMutex); observed max depth in practice = 1.
// Capacity 8 is ample headroom.  Overflow silently skips registration --
// in that pathological case behavior degrades to pre-patch (the original
// std::shared_lock dtor still runs the unlock).
inline constexpr std::size_t PendingSharedLockCapacity = 8;

// Forward declaration -- defined below.
class TrackedSharedLock;

inline thread_local TrackedSharedLock* PendingSharedLockStack[PendingSharedLockCapacity] {};
inline thread_local std::size_t PendingSharedLockDepth {0};

// RAII shared lock on a WritePriorityMutex::Mutex.  Replaces std::shared_lock
// inside the GuardSignalDeferringSection<std::shared_lock, WritePriorityMutex>
// path so that:
//   - On normal scope exit, dtor unlocks_shared and pops from the stack.
//   - On forced sweep (TakeOver), the mutex is unlocked AND ownership
//     is cleared so the later dtor is a no-op.
// "TakeOver" semantics intentionally mirror std::shared_lock::release() but
// also perform the actual unlock_shared, because the stack-stored pointer
// cannot live longer than the lock owner.
class TrackedSharedLock final {
public:
  explicit TrackedSharedLock(FEXCore::Utils::WritePriorityMutex::Mutex& mutex)
    : Mutex(&mutex) {
    Mutex->lock_shared();
    if (PendingSharedLockDepth < PendingSharedLockCapacity) {
      PendingSharedLockStack[PendingSharedLockDepth++] = this;
    }
    // If full: not tracked.  Lock is still held and will be unlocked by
    // this object's dtor on normal scope exit.  Worst case (leak via
    // signal-handler death with depth >= cap) matches pre-patch behavior.
  }

  TrackedSharedLock(const TrackedSharedLock&) = delete;
  TrackedSharedLock& operator=(const TrackedSharedLock&) = delete;
  // Non-movable: the stack-stored pointer is stable only while this object
  // stays in place.  Callers must use it as a stack/struct member.
  TrackedSharedLock(TrackedSharedLock&&) = delete;
  TrackedSharedLock& operator=(TrackedSharedLock&&) = delete;

  ~TrackedSharedLock() {
    if (!Mutex) {
      // Already swept by an external ReleaseAllPendingSharedLocks() --
      // mutex has already been unlocked, stack already drained.
      return;
    }
    // Normal RAII path.  Pop from the stack (LIFO expected; defensive scan
    // to tolerate non-stack release order) then unlock.
    for (std::size_t i = PendingSharedLockDepth; i > 0; --i) {
      if (PendingSharedLockStack[i - 1] == this) {
        for (std::size_t j = i - 1; j + 1 < PendingSharedLockDepth; ++j) {
          PendingSharedLockStack[j] = PendingSharedLockStack[j + 1];
        }
        --PendingSharedLockDepth;
        PendingSharedLockStack[PendingSharedLockDepth] = nullptr;
        break;
      }
    }
    Mutex->unlock_shared();
  }

  // External-sweep entry point: unlock the mutex and disassociate.  After
  // TakeOver(), this object's dtor is a no-op.  Called from
  // ReleaseAllPendingSharedLocks() below.
  void TakeOverAndUnlock() {
    if (Mutex) {
      auto* m = Mutex;
      Mutex = nullptr;
      m->unlock_shared();
    }
  }
private:
  FEXCore::Utils::WritePriorityMutex::Mutex* Mutex;
};

// Forcibly releases every shared lock currently registered on this thread's
// PendingSharedLockStack.  Idempotent (no-op on empty stack).  Must be called
// FROM THE OWNING THREAD; the stack is thread_local storage.
//
// Two correct call sites:
//   - The dying-thread cleanup path (ThreadHandler/SYS_exit/SYS_exit_group)
//     where C++ destructors may not run.
//   - The SMC SIGSEGV handler in HandleSegfault, before InvalidateGuestCodeRange
//     attempts to acquire the write lock -- otherwise the same thread
//     self-deadlocks.
inline void ReleaseAllPendingSharedLocks() {
  while (PendingSharedLockDepth > 0) {
    --PendingSharedLockDepth;
    auto* lk = PendingSharedLockStack[PendingSharedLockDepth];
    PendingSharedLockStack[PendingSharedLockDepth] = nullptr;
    if (lk) {
      lk->TakeOverAndUnlock();
    }
  }
}

/**
 * @brief Produces a wrapper object around a scoped lock of the given mutex
 * while ensuring POSIX signals are masked while the mutex is locked
 *
 * Use this to prevent reentrancy issues of C++ mutexes with certain signal handlers.
 * Common examples of such issues are:
 * - C++ mutexes not unlocking due to a signal handler calling longjmp from within a scope owning the mutex
 * - The signal handler itself using a mutex that would be re-locked if the handler gets invoked
 *   again before unlocking
 *
 * Ownership of the returned object may be moved, but it is NOT SAFE to move across threads.
 */
template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto MaskSignalsAndLockMutex(MutexType& mutex, uint64_t Mask = ~0ULL) {
  // Signals are masked first, and then the lock is acquired
  struct {
    ScopedSignalMasker mask;
    LockType<MutexType> lock;
  } scope_guard {ScopedSignalMasker {Mask}, LockType<MutexType> {mutex}};
  return scope_guard;
}

/**
 * @brief Produces a wrapper object around a scoped lock of the given mutex
 * while bumping the Thread's deferred signal refcount while the mutex is
 * locked.
 *
 * When invoked as GuardSignalDeferringSection<std::shared_lock>(...) on a
 * WritePriorityMutex::Mutex, the returned scope guard ALSO registers the
 * mutex on this thread's PendingSharedLockStack so that
 * ReleaseAllPendingSharedLocks() can recover the reader-count slot if the
 * thread terminates without unwinding the host C++ stack (the canonical
 * cause of the CodeInvalidationMutex phantom-reader deadlock observed in
 * Steam under PPC64LE FEX).
 */
template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto GuardSignalDeferringSection(MutexType& mutex, FEXCore::Core::InternalThreadState* Thread, uint64_t Mask = ~0ULL) {
  if constexpr (std::is_same_v<LockType<MutexType>, std::shared_lock<MutexType>> &&
                std::is_same_v<MutexType, FEXCore::Utils::WritePriorityMutex::Mutex>) {
    // Tracked variant.  Replaces std::shared_lock with TrackedSharedLock,
    // which both acquires/releases the mutex AND registers in
    // PendingSharedLockStack so ReleaseAllPendingSharedLocks() can unlock
    // it externally without a later dtor double-unlocking.
    //
    // Move/copy semantics: this scope_guard cannot be moved/copied because
    // TrackedSharedLock is non-movable -- the registered pointer must stay
    // stable.  This matches the only existing callers (Core.cpp:844, :946;
    // PPC64LE/JIT.cpp:1490) which use `auto lk = ...;` and never move it.
    struct ScopeGuard {
      std::optional<DeferredSignalRefCountGuard> refcount;
      TrackedSharedLock lock;
      ScopeGuard(FEXCore::Core::InternalThreadState* T, MutexType& m)
        : refcount(DeferredSignalRefCountGuard {T})
        , lock(m) {}
      ScopeGuard(const ScopeGuard&) = delete;
      ScopeGuard& operator=(const ScopeGuard&) = delete;
      ScopeGuard(ScopeGuard&&) = delete;
      ScopeGuard& operator=(ScopeGuard&&) = delete;
    };
    return ScopeGuard {Thread, mutex};
  } else {
    // Refcount is incremented first, and then the lock is acquired.
    struct {
      std::optional<DeferredSignalRefCountGuard> refcount;
      LockType<MutexType> lock;
    } scope_guard = {DeferredSignalRefCountGuard {Thread}, LockType<MutexType> {mutex}};
    return scope_guard;
  }
}

// Like GuardSignalDeferringSection but falls back to masking signals when Thread is nullptr
template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto GuardSignalDeferringSectionWithFallback(MutexType& mutex, FEXCore::Core::InternalThreadState* Thread, uint64_t Mask = ~0ULL) {
  using ExtraGuard = std::variant<ScopedSignalMasker, DeferredSignalRefCountGuard>;

  struct {
    ExtraGuard refcount_or_mask;
    LockType<MutexType> lock;
  } scope_guard {Thread ? ExtraGuard {DeferredSignalRefCountGuard {Thread}} : ExtraGuard {ScopedSignalMasker {Mask}}};
  scope_guard.lock = LockType<MutexType> {mutex};
  return scope_guard;
}

#else

// Dummy implementations as Windows doesn't support forking or async signals.
class ForkableUniqueMutex final : public std::mutex {
public:
  void StealAndDropActiveLocks() {
    LogMan::Msg::AFmt("{} is unsupported on WIN32 builds!", __func__);
  }
};

class ForkableSharedMutex final : public std::shared_mutex {
public:
  void StealAndDropActiveLocks() {
    LogMan::Msg::AFmt("{} is unsupported on WIN32 builds!", __func__);
  }
};

template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto MaskSignalsAndLockMutex(MutexType& mutex, uint64_t Mask = ~0ULL) {
  return LockType<MutexType> {mutex};
}

template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto GuardSignalDeferringSection(MutexType& mutex, FEXCore::Core::InternalThreadState* Thread, uint64_t Mask = ~0ULL) {
  return LockType<MutexType> {mutex};
}

template<template<typename> class LockType = std::unique_lock, typename MutexType>
[[nodiscard]]
static auto GuardSignalDeferringSectionWithFallback(MutexType& mutex, FEXCore::Core::InternalThreadState* Thread, uint64_t Mask = ~0ULL) {
  return LockType<MutexType> {mutex};
}

#endif
} // namespace FEXCore
