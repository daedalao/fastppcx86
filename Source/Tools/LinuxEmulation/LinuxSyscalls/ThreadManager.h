// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|ThreadManager
desc: Frontend thread management
$end_info$
*/

#pragma once

#include "Common/SHMStats.h"

#include "LinuxSyscalls/Types.h"
#include "LinuxSyscalls/x32/IoctlEmulation.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/Utils/InterruptableConditionVariable.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unistd.h>
#include <FEXCore/Utils/LogManager.h>
#include <sys/stat.h>

#include <bits/types/sigset_t.h>
#include <linux/seccomp.h>

namespace FEX::HLE {
class SignalDelegator;
class SyscallHandler;
struct SeccompFilterInfo;

enum class SignalEvent : uint32_t {
  Nothing, // If the guest uses our signal we need to know it was errant on our end
  Pause,
  Stop,
  Return,
  ReturnRT,
};

struct ThreadStateObject : public FEXCore::Allocator::FEXAllocOperators {
  struct DeferredSignalState {
    siginfo_t Info;
    int Signal;
    uint64_t SigMask;
  };

  FEXCore::Core::InternalThreadState* Thread;

  struct {
    uint32_t parent_tid;
    uint32_t PID;
    std::atomic<uint32_t> TID;
    // Set by DestroyThread once the ThreadStateObject slab is being leaked
    // for signal-delivery UAF mitigation. Kept SEPARATE from TID because
    // TID is a data field the parent's CLONE_THREAD return path reads for
    // its guest-visible syscall result; overloading TID as the marker
    // races the parent's read when a short-lived child exits before the
    // parent's post-notify readback. See Syscalls/Thread.cpp CreateNewThread
    // and Syscalls.cpp CloneHandler for the reader that this write races.
    std::atomic<bool> IsZombie {false};
    int32_t* set_child_tid {0};
    int32_t* clear_child_tid {0};
    uint64_t robust_list_head {0};
  } ThreadInfo {};

  struct {
    SignalDelegator* Delegator {};

    void* AltStackPtr {};
    stack_t GuestAltStack {
      .ss_sp = nullptr,
      .ss_flags = SS_DISABLE, // By default the guest alt stack is disabled
      .ss_size = 0,
    };
    // This is the thread's current signal mask
    FEX::HLE::GuestSAMask CurrentSignalMask {};
    // The mask prior to a suspend
    FEX::HLE::GuestSAMask PreviousSuspendMask {};

    uint64_t PendingSignals {};

    // Guest SA_RESTART bookkeeping.
    //
    // A guest signal delivered while this thread sits inside a host syscall is
    // dispatched from the DeferredSignalRefCountGuard destructor at the tail of
    // HandleSyscall (the InterruptFaultPage poke faults, the queue drains, the
    // guest handler runs on this same host thread and sigreturns back into that
    // destructor). Only after that does HandleSyscall return -EINTR to the JIT.
    // The restart loop in HandleSyscall therefore needs to know, once the guard
    // has destructed, whether any guest handler ran and whether every handler
    // that ran was registered SA_RESTART.
    //
    // Both counters are monotonic and never reset: HandleSyscall snapshots them
    // before an attempt and diffs afterwards. That is what makes them re-entrant
    // -- guest signal handlers issue syscalls of their own, and a nested
    // HandleSyscall must not be able to clear the outer frame's evidence.
    //
    // Written and read only by the owning thread (delivery happens on the same
    // thread that is executing the syscall), so plain integers are sufficient.
    uint32_t DeliveredGuestSignals {};
    uint32_t DeliveredGuestSignalsWithoutRestart {};

    // Queue of thread local signal frames that have been deferred.
    // Async signals aren't guaranteed to be delivered in any particular order, but FEX treats them as FILO.
    fextl::vector<DeferredSignalState> DeferredSignalFrames;
  } SignalInfo {};

  // Seccomp thread specific data.
  uint32_t SeccompMode {SECCOMP_MODE_DISABLED};
  fextl::vector<FEX::HLE::SeccompFilterInfo*> Filters {};

  // Per-thread seccomp verdict cache (owned and touched only by this thread;
  // see SeccompEmulator::ExecuteFilter). A cBPF verdict is a pure function of
  // the seccomp_data fields the installed programs actually load (discovered
  // at install time), so an ALLOW verdict can be replayed without running the
  // BPF interpreter when every loaded field is part of the cache key:
  //  - NrOnly:  no filter reads ip or args -> key is the syscall number.
  //  - NrRIP:   filters read ip but not args (wine's syscall-dispatch filter)
  //             -> key is (guest RIP, nr). Guest RIPs are stable across JIT
  //             recompiles, unlike host JITPCs.
  // Only ALLOW is cached: it is the only action with no side effects (no
  // audit log, no signal, no errno).
  struct SeccompVerdictCache {
    constexpr static uint32_t MAX_CACHED_NR = 512;
    constexpr static uint32_t RIP_WAYS = 64;
    enum class CacheMode : uint8_t {
      None,   // Some filter reads args; every syscall interprets.
      NrOnly, // AllowedNrs bitmap is usable.
      NrRIP,  // RIPAllowed direct-mapped table is usable.
    };
    // Compared against SeccompEmulator::FilterGeneration; mismatch clears.
    uint64_t Generation {};
    CacheMode Mode {CacheMode::None};
    bool NeedsRIP {}; // Some filter loads instruction_pointer.
    uint64_t AllowedNrs[MAX_CACHED_NR / 64] {};
    struct RIPEntry {
      uint64_t RIP;
      uint64_t NrPlusOne; // 0 = empty
    };
    RIPEntry RIPAllowed[RIP_WAYS] {};
  } SeccompCache {};

  // personality emulation.
  uint32_t persona {};

  FEXCore::Core::NonMovableUniquePtr<FEXCore::Threads::Thread> ExecutionThread;

  // Thread signaling information
  std::atomic<SignalEvent> SignalReason {SignalEvent::Nothing};

  // Thread pause handling
  std::atomic_bool ThreadSleeping {false};
  FEXCore::InterruptableConditionVariable ThreadPaused;

  // GDB signal information
  struct GdbInfoStruct {
    int Signal {};
  };
  std::optional<GdbInfoStruct> GdbInfo;

  int StatusCode {};

  struct CallRetStackInfo {
    uint64_t AllocationBase;
    uint64_t AllocationEnd;
    uint64_t DefaultLocation;
  };

  CallRetStackInfo GetCallRetStackInfo() {
    uint64_t Base = reinterpret_cast<uint64_t>(Thread->CallRetStackBase);
    // Leave some room from the base for the default location to allow for underflows without constant exceptions
    return {Base - FEXCore::Utils::FEX_PAGE_SIZE, Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + FEXCore::Utils::FEX_PAGE_SIZE,
            Base + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4};
  }

  // GDT and LDT tracking
  FEXCore::Core::CPUState::gdt_segment gdt[32] {};
  size_t ldt_entry_count {};
  FEXCore::Core::CPUState::gdt_segment* ldt_entries {};

  // 32-bit FD cache for DRM handlers.
  fextl::unique_ptr<x32::DRMLRUCacheFDCache> DRMLRUCache {};
};

class ThreadManager final {
public:

  ThreadManager(FEXCore::Context::Context* CTX, FEX::HLE::SignalDelegator* SignalDelegation)
    : CTX {CTX}
    , SignalDelegation {SignalDelegation} {}

  ~ThreadManager();

  class StatAlloc final : public FEX::SHMStats::StatAllocBase {
  public:
    StatAlloc();

    void LockBeforeFork();
    void UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child);

    void CleanupForExit();

    FEXCore::SHMStats::ThreadStats* AllocateSlot(uint32_t TID);
    void DeallocateSlot(FEXCore::SHMStats::ThreadStats* AllocatedSlot);

  private:
    void Initialize();

    uint32_t FrontendAllocateSlots(uint32_t NewSize) override;
    FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
    FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);

    constexpr static int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
    FEXCore::ForkableUniqueMutex StatMutex;
  };

  void CleanupForExit() {
    Stat.CleanupForExit();
  }

  /**
   * @brief Sets the calling thread's signal mask to the one provided
   *
   * @param Mask The new 64-bit signal mask to set
   *
   * @return The previous signal mask
   */
  static uint64_t SetSignalMask(uint64_t Mask);
  static void SetThreadName(const char* name);

  ///< Returns the ThreadStateObject from a CpuStateFrame object.
  static inline FEX::HLE::ThreadStateObject* GetStateObjectFromCPUState(FEXCore::Core::CpuStateFrame* Frame) {
    return static_cast<FEX::HLE::ThreadStateObject*>(Frame->Thread->FrontendPtr);
  }

  static inline FEX::HLE::ThreadStateObject* GetStateObjectFromFEXCoreThread(FEXCore::Core::InternalThreadState* Thread) {
    return static_cast<FEX::HLE::ThreadStateObject*>(Thread->FrontendPtr);
  }

  FEX::HLE::ThreadStateObject* CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState = nullptr,
                                            uint64_t ParentTID = 0, FEX::HLE::ThreadStateObject* InheritThread = nullptr);
  void TrackThread(FEX::HLE::ThreadStateObject* Thread) {
    std::lock_guard lk(ThreadCreationMutex);
    Threads.emplace_back(Thread);
  }

  void DestroyThread(FEX::HLE::ThreadStateObject* Thread, bool NeedsTLSUninstall = false);
  void StopThread(FEX::HLE::ThreadStateObject* Thread);
  void UnpauseThread(FEX::HLE::ThreadStateObject* Thread);

  void Pause();
  void Run();
  void Step();
  void Stop(bool IgnoreCurrentThread = false);

  void WaitForIdle();
  void WaitForIdleWithTimeout();
  void WaitForThreadsToRun();

  void SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame);

  void LockBeforeFork();
  void UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child);

  void IncrementIdleRefCount() {
    ++IdleWaitRefCount;
  }

  // Bounded exclusive acquire of CodeInvalidationMutex from the invalidation
  // helpers (syscall layer and the SIGSEGV handler).
  //
  // History: this was a try_lock() poll every 50 us for 4 s, then a steal, then
  // (co-dev findings §1.2) a fatal instead of the steal because stealing
  // outside fork() corrupts the mutex word. The poll itself was wrong for a
  // different reason: try_lock() is a bare CAS from 0 that never registers as
  // a write waiter, so the mutex's writer priority never engaged -- every
  // CompileBlock / ExitFunctionLink on every other thread kept taking the
  // shared side, and with a JIT worker producing code for 8+ executing threads
  // the reader count could stay non-zero across every sample until the
  // deadline (reader-starvation livelock, indistinguishable from the deadlock
  // this was meant to catch). It also cost 10-20k wakeups/s per waiter.
  //
  // try_lock_for registers as a writer (readers then drain as designed) and
  // sleeps on the futex with a real deadline, so the 4 s is now a deadlock
  // detector rather than a contention detector. The fatal stays: a genuine
  // stall here is a lock-order bug (see the VMATracking LOCK ORDER note in
  // HandleSegfault) and must be reported, not hidden.
  static constexpr int InvalidateGuestCodeRangeStealTimeoutSec = 4;

  void TakeCodeInvalidationWriteLockOrSteal(FEXCore::Utils::WritePriorityMutex::Mutex& M) {
    if (M.try_lock_for(std::chrono::seconds(InvalidateGuestCodeRangeStealTimeoutSec))) {
      return;
    }
    ERROR_AND_DIE_FMT("InvalidateGuestCodeRange: write-lock stalled {}s "
                      "(phantom reader / lock inversion). Refusing the "
                      "corrupting steal; report this with the workload.",
                      InvalidateGuestCodeRangeStealTimeoutSec);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* CallingThread, uint64_t Start, uint64_t Length) {
    FEXCore::ReleaseAllPendingSharedLocks();
    std::lock_guard lk(ThreadCreationMutex);

    auto& InvalMutex = CTX->GetCodeInvalidationMutex();
    TakeCodeInvalidationWriteLockOrSteal(InvalMutex);
    struct UniqueGuard {
      FEXCore::Utils::WritePriorityMutex::Mutex& M;
      ~UniqueGuard() { M.unlock(); }
    } CodeInvalidationlk {InvalMutex};

    CTX->InvalidateCodeBuffersCodeRange(Start, Length);
    for (auto& Thread : Threads) {
      CTX->InvalidateThreadCachedCodeRange(Thread->Thread, Start, Length);
    }
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* CallingThread, uint64_t Start, uint64_t Length,
                                FEXCore::Context::CodeRangeInvalidationFn after_callback) {
    FEXCore::ReleaseAllPendingSharedLocks();
    std::lock_guard lk(ThreadCreationMutex);

    auto& InvalMutex = CTX->GetCodeInvalidationMutex();
    TakeCodeInvalidationWriteLockOrSteal(InvalMutex);
    struct UniqueGuard {
      FEXCore::Utils::WritePriorityMutex::Mutex& M;
      ~UniqueGuard() { M.unlock(); }
    } CodeInvalidationlk {InvalMutex};

    CTX->InvalidateCodeBuffersCodeRange(Start, Length);
    for (auto& Thread : Threads) {
      CTX->InvalidateThreadCachedCodeRange(Thread->Thread, Start, Length);
    }

    after_callback(Start, Length);
  }

  // Several ranges under ONE exclusive acquisition. A shared mapping's SMC
  // fault used to take (and convoy on) the exclusive lock once per mirror
  // page; the per-range Unprotect flag preserves the "writable mirrors get the
  // after_callback, read-only mirrors do not" split of the single-range form.
  struct InvalidateRange {
    uint64_t Start;
    uint64_t Length;
    bool Unprotect;
  };

  void InvalidateGuestCodeRanges(FEXCore::Core::InternalThreadState* CallingThread, const InvalidateRange* Ranges, size_t Count,
                                 FEXCore::Context::CodeRangeInvalidationFn after_callback) {
    FEXCore::ReleaseAllPendingSharedLocks();
    std::lock_guard lk(ThreadCreationMutex);

    auto& InvalMutex = CTX->GetCodeInvalidationMutex();
    TakeCodeInvalidationWriteLockOrSteal(InvalMutex);
    struct UniqueGuard {
      FEXCore::Utils::WritePriorityMutex::Mutex& M;
      ~UniqueGuard() { M.unlock(); }
    } CodeInvalidationlk {InvalMutex};

    for (size_t i = 0; i < Count; ++i) {
      CTX->InvalidateCodeBuffersCodeRange(Ranges[i].Start, Ranges[i].Length);
      for (auto& Thread : Threads) {
        CTX->InvalidateThreadCachedCodeRange(Thread->Thread, Ranges[i].Start, Ranges[i].Length);
      }
    }
    for (size_t i = 0; i < Count; ++i) {
      if (Ranges[i].Unprotect) {
        after_callback(Ranges[i].Start, Ranges[i].Length);
      }
    }
  }

  // SMC v3 (FEX_SMCSOFTINVALIDATE): identical lock protocol and call shape to
  // the callback overload above -- ReleaseAllPendingSharedLocks, then
  // ThreadCreationMutex, then the steal-capable exclusive CodeInvalidationMutex
  // -- but retains the affected blocks' compiled code and content hashes so
  // that a later dispatch can revalidate and relink them. The per-thread
  // L1/L2 + CallRet-stack flush is the unmodified legacy one: soft-invalidated
  // blocks must be unreachable from every fast path, only their code survives.
  // See FEXCore/Source/Interface/Core/SMCSoftInvalidate.h.
  void SoftInvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* CallingThread, uint64_t Start, uint64_t Length,
                                    FEXCore::Context::CodeRangeInvalidationFn after_callback) {
    FEXCore::ReleaseAllPendingSharedLocks();
    std::lock_guard lk(ThreadCreationMutex);

    auto& InvalMutex = CTX->GetCodeInvalidationMutex();
    TakeCodeInvalidationWriteLockOrSteal(InvalMutex);
    struct UniqueGuard {
      FEXCore::Utils::WritePriorityMutex::Mutex& M;
      ~UniqueGuard() { M.unlock(); }
    } CodeInvalidationlk {InvalMutex};

    CTX->SoftInvalidateCodeBuffersCodeRange(Start, Length);
    for (auto& Thread : Threads) {
      CTX->InvalidateThreadCachedCodeRange(Thread->Thread, Start, Length);
    }

    after_callback(Start, Length);
  }

  // SMC Idea 4 (FEX_SMCSEMANTICPATCH): same lock protocol as
  // SoftInvalidateGuestCodeRange above -- ReleaseAllPendingSharedLocks, then
  // ThreadCreationMutex, then the steal-capable exclusive CodeInvalidationMutex
  // -- but instead of invalidating anything it rewrites the destination RIP
  // baked into the affected blocks' translated exits. Holding the exclusive
  // CodeInvalidationMutex is what makes writing into a live code buffer from
  // the SIGSEGV handler safe: it excludes ClearCodeCache and every concurrent
  // compile. Nothing is delinked, no per-thread L1/L2 flush is needed (the
  // blocks stay valid), and the page is left write-protected by the caller.
  // (Same for a guest mov-immediate, whose patch site is the fixed-width
  // materialisation window the backend emitted for that immediate.)
  // Returns false with *Reason set if the write is not a recognised patch, in
  // which case nothing was modified; on success *Reason receives the shape that
  // was patched ("rel32", "movimm" or "mixed"). See
  // FEXCore/Source/Interface/Core/SMCSemanticPatch.h.
  bool SemanticPatchGuestCodeRange(uint64_t Start, uint64_t Length, const void* NewBytes, const char** Reason) {
    FEXCore::ReleaseAllPendingSharedLocks();
    std::lock_guard lk(ThreadCreationMutex);

    auto& InvalMutex = CTX->GetCodeInvalidationMutex();
    TakeCodeInvalidationWriteLockOrSteal(InvalMutex);
    struct UniqueGuard {
      FEXCore::Utils::WritePriorityMutex::Mutex& M;
      ~UniqueGuard() { M.unlock(); }
    } CodeInvalidationlk {InvalMutex};

    return CTX->TrySemanticPatchCodeRange(Start, Length, NewBytes, Reason);
  }

  const fextl::vector<FEX::HLE::ThreadStateObject*>* GetThreads() const {
    return &Threads;
  }

  // FEX_SMCLAZYCROSSPOKE: run `fn` over every live thread under
  // ThreadCreationMutex, acquired NON-BLOCKING.
  //
  // Unlike the invalidation helpers above this deliberately does not take (or
  // steal) the CodeInvalidationMutex: the only per-thread state it is used to
  // touch is the lazy-drain flag and the InterruptFaultPage protection, neither
  // of which races a compile. The caller is the SIGSEGV handler, and returning
  // false rather than blocking lets it fall back to a fully synchronous drain
  // instead of gambling on the lock. Note that try_lock also returns false when
  // this very thread already owns the mutex (it is not recursive), which is the
  // one case where blocking here would self-deadlock.
  template<typename F>
  [[nodiscard]]
  bool TryForEachThread(F&& fn) {
    if (!ThreadCreationMutex.try_lock()) {
      return false;
    }
    struct UniqueGuard {
      FEXCore::ForkableUniqueMutex& M;
      ~UniqueGuard() {
        M.unlock();
      }
    } lk {ThreadCreationMutex};

    for (auto& Thread : Threads) {
      fn(Thread);
    }
    return true;
  }

private:
  StatAlloc Stat;
  FEXCore::Context::Context* CTX;
  FEX::HLE::SignalDelegator* SignalDelegation;

  FEXCore::ForkableUniqueMutex ThreadCreationMutex;
  fextl::vector<FEX::HLE::ThreadStateObject*> Threads;

  // Thread idling support.
  bool Running {};
  std::mutex IdleWaitMutex;
  std::condition_variable IdleWaitCV;
  std::atomic<uint32_t> IdleWaitRefCount {};

  void HandleThreadDeletion(FEX::HLE::ThreadStateObject* Thread, bool NeedsTLSUninstall = false);
  void NotifyPause();
  FEX_CONFIG_OPT(ProfileStats, PROFILESTATS);
  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
};

} // namespace FEX::HLE
