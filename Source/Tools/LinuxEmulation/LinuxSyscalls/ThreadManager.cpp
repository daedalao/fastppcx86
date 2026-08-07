// SPDX-License-Identifier: MIT

#include "LinuxSyscalls/ThreadManager.h"

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Seccomp/SeccompEmulator.h"

#include <FEXHeaderUtils/Syscalls.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/fextl/fmt.h>

#include <chrono>
#include <limits>
#include <cstdio>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#if defined(__powerpc64__) || defined(ARCHITECTURE_ppc64le)
#include <sys/platform/ppc.h>  // __ppc_get_timebase_freq
#endif
#include <linux/futex.h>
#include <fcntl.h>
#include <git_version.h>

namespace FEX::HLE {

namespace {
// Manual robust-futex cleanup for 32-bit guests on a 64-bit FEX host.
// On real Linux, set_robust_list registers the list with the kernel and the
// kernel walks it on thread exit to mark each held futex with FUTEX_OWNER_DIED
// and wake any waiter. For 32-bit guests we cannot register the list with the
// host kernel (the kernel parses it as a native pointer-width list, but the
// guest's list uses 4-byte pointers/offsets), so the cleanup never runs and
// any pthread mutexes the dying thread still held leak as locked forever.
// Result on heavily-threaded i686 programs (Steam client, 65+ pthreads with
// frequent mutex hand-off): glibc's malloc arena metadata is held in such a
// mutex; subsequent free() in another thread sees a stale list head and
// aborts with "free(): invalid pointer".
//
// Implementation mirrors the kernel's `exit_robust_list` walk, restricted to
// the 32-bit list-head and list-entry layout.
//
// Every read of this list must be fault-tolerant. It used to dereference the
// guest pointers directly, on the reasoning that we share the address space
// and the thread had already exited so nothing could mutate concurrently.
// Both halves of that are wrong: the nodes live in guest memory that *other*
// threads can unmap or recycle (a detached thread's stack is freed by the
// guest, not by us), and the list itself is guest-controlled data that may be
// torn or stale. The kernel walks the same list with get_user() and tolerates
// -EFAULT for exactly this reason.
//
// The consequence of getting it wrong is not a guest fault: FEX owns SIGSEGV,
// so a bad load here is taken as a *guest* fault while executing host code and
// takes the whole process down. Observed as SIGSEGV in HandleThreadDeletion on
// i686 titles during worker-thread teardown, with the faulting instruction
// being the `rldicl` zero-extend of a guest address followed by its load.
//
// process_vm_readv against our own pid returns -EFAULT for an unmapped source
// rather than raising a signal, which gives us the get_user() semantics the
// kernel has. It is a syscall per read, but this runs once per thread exit
// over a handful of nodes, not on any hot path.

constexpr uint32_t FEX_FUTEX_TID_MASK = 0x3FFFFFFFu;
constexpr uint32_t FEX_FUTEX_WAITERS = 0x80000000u;
constexpr uint32_t FEX_FUTEX_OWNER_DIED = 0x40000000u;
constexpr int ROBUST_LIST_MAX_ITERS = 2048;

struct robust_list_head_32 {
  uint32_t next;
  int32_t  futex_offset;
  uint32_t list_op_pending;
};

// Fault-tolerant read of `Len` bytes of guest memory. Returns false (leaving
// *Out untouched) if the source is not readable, instead of raising SIGSEGV.
bool SafeReadGuest(uint32_t GuestAddr, void* Out, size_t Len) {
  if (!GuestAddr) {
    return false;
  }
  const iovec Local {.iov_base = Out, .iov_len = Len};
  const iovec Remote {.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(GuestAddr)), .iov_len = Len};
  return ::process_vm_readv(::getpid(), &Local, 1, &Remote, 1, 0) == static_cast<ssize_t>(Len);
}

bool SafeRead32(uint32_t GuestAddr, uint32_t* Out) {
  return SafeReadGuest(GuestAddr, Out, sizeof(*Out));
}

void HandleFutexDeath(uint32_t* uaddr, uint32_t exiting_tid) {
  // Probe first: an unreadable futex word means the guest already tore this
  // mapping down, and there is nothing left to hand off. The CAS below still
  // races in principle, but the window is now a mapping being unmapped between
  // the probe and the CAS rather than the whole list being suspect.
  uint32_t Probe;
  if (!SafeReadGuest(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(uaddr)), &Probe, sizeof(Probe))) {
    return;
  }

  uint32_t val = __atomic_load_n(uaddr, __ATOMIC_RELAXED);
  while ((val & FEX_FUTEX_TID_MASK) == exiting_tid) {
    uint32_t new_val = (val & FEX_FUTEX_WAITERS) | FEX_FUTEX_OWNER_DIED;
    if (__atomic_compare_exchange_n(uaddr, &val, new_val, false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
      if (new_val & FEX_FUTEX_WAITERS) {
        ::syscall(SYS_futex, uaddr, FUTEX_WAKE, 1, nullptr, nullptr, 0);
      }
      return;
    }
  }
}

void WalkAndCleanupRobustList32(uint32_t head_addr, uint32_t exiting_tid) {
  if (!head_addr) return;

  // Read the head as one unit. If it is gone there is no list to walk.
  robust_list_head_32 head {};
  if (!SafeReadGuest(head_addr, &head, sizeof(head))) {
    return;
  }

  uint32_t pending = head.list_op_pending;
  int32_t  offset  = head.futex_offset;
  uint32_t cur     = head.next;
  int iters = 0;
  while (cur != head_addr && cur != 0 && iters++ < ROBUST_LIST_MAX_ITERS) {
    // The link read is the one that faulted in the field: a node whose memory
    // the guest has already reclaimed. Stop the walk rather than die.
    uint32_t next;
    if (!SafeRead32(cur, &next)) {
      return;
    }
    if (cur != pending) {
      // offset is guest-controlled and signed; compute in 64-bit so a hostile
      // or corrupt value cannot wrap the address, and require the result to
      // still be a 32-bit guest address.
      const int64_t FutexAddr = static_cast<int64_t>(cur) + static_cast<int64_t>(offset);
      if (FutexAddr > 0 && FutexAddr <= std::numeric_limits<uint32_t>::max()) {
        HandleFutexDeath(reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(FutexAddr)), exiting_tid);
      }
    }
    cur = next;
  }

  // list_op_pending captures a mutex that was being added/removed when the
  // thread died — must be handled even though it's not yet in the linked list.
  if (pending) {
    const int64_t FutexAddr = static_cast<int64_t>(pending) + static_cast<int64_t>(offset);
    if (FutexAddr > 0 && FutexAddr <= std::numeric_limits<uint32_t>::max()) {
      HandleFutexDeath(reinterpret_cast<uint32_t*>(static_cast<uintptr_t>(FutexAddr)), exiting_tid);
    }
  }
}
} // namespace

// Recorded once at first StatAlloc construction (early in process startup), used
// by CleanupForExit to report wall time for the P5.1 JIT-fraction dump. Not
// exact-startup — StatAlloc is built during ContextImpl init, which is after
// argv parsing but before the guest runs a single instruction — accurate enough
// to bound the JIT/wall ratio to <5% error on runs longer than a second.
static const auto P5_1_ProcessStart = std::chrono::steady_clock::now();

ThreadManager::StatAlloc::StatAlloc() {
  (void)P5_1_ProcessStart;  // force init at first StatAlloc construction
  Initialize();
  SaveHeader(Is64BitMode() ? FEXCore::SHMStats::AppType::LINUX_64 : FEXCore::SHMStats::AppType::LINUX_32);
}

void ThreadManager::StatAlloc::Initialize() {
  if (!ProfileStats()) {
    return;
  }

  int fd = shm_open(fextl::fmt::format("fex-{}-stats", ::getpid()).c_str(), O_CREAT | O_TRUNC | O_RDWR, USER_PERMS);
  if (fd == -1) {
    return;
  }
  CurrentSize = sysconf(_SC_PAGESIZE);
  CurrentSize = CurrentSize > 0 ? CurrentSize : FEXCore::Utils::FEX_PAGE_SIZE;

  if (ftruncate(fd, CurrentSize) == -1) {
    LogMan::Msg::EFmt("[StatAlloc] ftruncate failed");
    goto err;
  }

  // Reserve a region of MAX_STATS_SIZE so we can grow the allocation buffer.
  // Number of thread slots when ThreadStatsHeader == 64bytes and ThreadStats == 40bytes:
  // 1 page: 99 slots
  // 1 MB: 26211 slots
  // 128 MB: 3355440 slots
  Base = FEXCore::Allocator::mmap(nullptr, MAX_STATS_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (Base == MAP_FAILED) {
    LogMan::Msg::EFmt("[StatAlloc] mmap base failed");
    Base = nullptr;
    goto err;
  }

  FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(Base), MAX_STATS_SIZE);

  // Allocate a small working shared space for now, grow as necessary.
  {
    auto SharedBase = FEXCore::Allocator::mmap(Base, CurrentSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      LogMan::Msg::EFmt("[StatAlloc] mmap shm failed");
      FEXCore::Allocator::munmap(Base, MAX_STATS_SIZE);
      Base = nullptr;
      goto err;
    }
  }

err:
  close(fd);
}

uint32_t ThreadManager::StatAlloc::FrontendAllocateSlots(uint32_t NewSize) {
  if (CurrentSize == MAX_STATS_SIZE) {
    // Allocator has reached maximum slots. We can't allocate anymore.
    // New threads won't get stats.
    return CurrentSize;
  }
  NewSize = std::min(MAX_STATS_SIZE, NewSize);

  // When allocating more slots, open the fd without O_TRUNC | O_CREAT.
  int fd = shm_open(fextl::fmt::format("fex-{}-stats", ::getpid()).c_str(), O_RDWR, USER_PERMS);
  if (fd == -1) {
    return CurrentSize;
  }

  if (ftruncate(fd, NewSize) == -1) {
    LogMan::Msg::EFmt("[StatAlloc] ftruncate more failed");

    goto err;
  }

  {
    auto SharedBase = FEXCore::Allocator::mmap(Base, NewSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (SharedBase == MAP_FAILED) {
      LogMan::Msg::EFmt("[StatAlloc] allocate more mmap shm failed");
      goto err;
    }
  }

err:
  close(fd);
  return NewSize;
}

FEXCore::SHMStats::ThreadStats* ThreadManager::StatAlloc::AllocateSlot(uint32_t TID) {
  std::scoped_lock lk(StatMutex);
  return StatAllocBase::AllocateSlot(TID);
}

void ThreadManager::StatAlloc::DeallocateSlot(FEXCore::SHMStats::ThreadStats* AllocatedSlot) {
  if (!AllocatedSlot) {
    return;
  }

  std::scoped_lock lk(StatMutex);
  StatAllocBase::DeallocateSlot(AllocatedSlot);
}

void ThreadManager::StatAlloc::CleanupForExit() {
  // P5.1: sum AccumulatedJITTime / AccumulatedJITCount across all thread slots
  // and dump to stderr before we shm_unlink the segment. Only when
  // FEX_PROFILESTATS is on (else Base is null and there are no slots to walk).
  //
  // Coverage: this runs on normal process exit. It is NOT reached on abnormal
  // exit (SIGKILL, unhandled synchronous fault that aborts the host, oom-kill).
  // Guest crashes that FEX handles cleanly still reach here; guest crashes that
  // dump core via the host handler do not. Workloads that only ever exit
  // abnormally (RimWorld: deterministic SIGSEGV at ~90 s) will produce no line.
  if (ProfileStats() && Base) {
    uint64_t TotalJITTime = 0;
    uint64_t TotalJITCount = 0;
    for (size_t i = 0; i < TotalSlotsFromSize(); ++i) {
      TotalJITTime += Stats[i].AccumulatedJITTime;
      TotalJITCount += Stats[i].AccumulatedJITCount;
    }

    // Timebase frequency via the GCC builtin — reads auxv AT_TIMEBASE_FREQUENCY.
    // POWER9 reports 512000000 Hz, matching /proc/cpuinfo "timebase". Called
    // once at exit — no need to cache.
#if defined(__powerpc64__) || defined(ARCHITECTURE_ppc64le)
    const uint64_t Freq = __ppc_get_timebase_freq();
#else
    const uint64_t Freq = 0;
#endif
    const double Seconds = Freq ? static_cast<double>(TotalJITTime) / static_cast<double>(Freq) : 0.0;

    const auto Now = std::chrono::steady_clock::now();
    const double Wall = std::chrono::duration<double>(Now - P5_1_ProcessStart).count();
    const double Pct = Wall > 0.0 ? Seconds / Wall * 100.0 : 0.0;

    std::fprintf(stderr, "[FEX JIT] blocks=%lu ticks=%lu seconds=%.6f wall=%.6f pct=%.3f freq=%luHz\n",
                 static_cast<unsigned long>(TotalJITCount), static_cast<unsigned long>(TotalJITTime), Seconds, Wall, Pct,
                 static_cast<unsigned long>(Freq));
  }

  shm_unlink(fextl::fmt::format("fex-{}-stats", ::getpid()).c_str());
}

void ThreadManager::StatAlloc::LockBeforeFork() {
  if (!ProfileStats()) {
    return;
  }
  StatMutex.lock();
}

void ThreadManager::StatAlloc::UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child) {
  if (!ProfileStats()) {
    return;
  }

  if (!Child) {
    StatMutex.unlock();
    return;
  }

  StatMutex.StealAndDropActiveLocks();

  // shm_memory ownership is retained by the parent process, so the child must replace it with its own one.
  // Otherwise this process will keep reporting in the original parent thread's stats region.
  FEXCore::Allocator::munmap(Base, MAX_STATS_SIZE);
  Base = nullptr;
  CurrentSize = 0;
  Head = nullptr;
  Stats = nullptr;
  StatTail = nullptr;
  RemainingSlots = 0;

  Thread->ThreadStats = nullptr;

  Initialize();
  SaveHeader(Is64BitMode() ? FEXCore::SHMStats::AppType::LINUX_64 : FEXCore::SHMStats::AppType::LINUX_32);

  // Update this thread's ThreadStats object
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  ThreadObject->Thread->ThreadStats = AllocateSlot(ThreadObject->ThreadInfo.TID);
}

uint64_t ThreadManager::SetSignalMask(uint64_t Mask) {
  ::syscall(SYSCALL_DEF(rt_sigprocmask), SIG_SETMASK, &Mask, &Mask, 8);
  return Mask;
}

void ThreadManager::SetThreadName(const char* name) {
  pthread_setname_np(pthread_self(), name);
}

constexpr size_t CALLRET_STACK_ALLOC_SIZE = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE;

FEX::HLE::ThreadStateObject* ThreadManager::CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState,
                                                         uint64_t ParentTID, FEX::HLE::ThreadStateObject* InheritThread) {
  auto ThreadStateObject = new FEX::HLE::ThreadStateObject;

  ThreadStateObject->ThreadInfo.parent_tid = ParentTID;
  ThreadStateObject->ThreadInfo.PID = ::getpid();

  ThreadStateObject->ThreadInfo.TID = FHU::Syscalls::gettid();

  ThreadStateObject->Thread = CTX->CreateThread(InitialRIP, StackPointer, NewThreadState);
  auto Frame = ThreadStateObject->Thread->CurrentFrame;

  // Allocate the call-ret stack with guard pages on both sides
  auto AllocBase =
    reinterpret_cast<uint64_t>(FEXCore::Allocator::mmap(nullptr, CALLRET_STACK_ALLOC_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

  FEXCore::Allocator::VirtualName("FEXMem_CallRetStacks", reinterpret_cast<void*>(AllocBase), CALLRET_STACK_ALLOC_SIZE);

  // Disable HUGEPAGE on callret stacks.
  FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<void*>(AllocBase), CALLRET_STACK_ALLOC_SIZE, FEXCore::Allocator::THPControl::Disable);

  // Set the base used for invalidation to the start past the guard pages
  ThreadStateObject->Thread->CallRetStackBase = reinterpret_cast<void*>(AllocBase + FEXCore::Utils::FEX_PAGE_SIZE);
  ::mprotect(ThreadStateObject->Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
  Frame->State.callret_sp = ThreadStateObject->GetCallRetStackInfo().DefaultLocation;

  ThreadStateObject->Thread->FrontendPtr = ThreadStateObject;
  if (ProfileStats()) {
    ThreadStateObject->Thread->ThreadStats = Stat.AllocateSlot(ThreadStateObject->ThreadInfo.TID);
  }

  // GDT and LDT are tracked per thread.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &ThreadStateObject->gdt[0];
  // Mirror LDT to the GDT by default. Not technically correctly, but fixes crashes in unittests.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &ThreadStateObject->gdt[0];

  if (InheritThread) {
    // If we are inheriting thread data then we inherit both the gdt and ldt arrays.
    // They are then forked from the parent thread.
    static_assert(sizeof(ThreadStateObject->gdt) == (8 * 32));
    memcpy(ThreadStateObject->gdt, InheritThread->gdt, sizeof(ThreadStateObject->gdt));
    if (InheritThread->ldt_entry_count) {
      const auto new_ldt_size = InheritThread->ldt_entry_count * FEX::HLE::SyscallHandler::LDT_ENTRY_SIZE;
      ThreadStateObject->ldt_entries = reinterpret_cast<FEXCore::Core::CPUState::gdt_segment*>(
        FEXCore::Allocator::mmap(nullptr, new_ldt_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
      FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(ThreadStateObject->ldt_entries), new_ldt_size);

      ThreadStateObject->ldt_entry_count = InheritThread->ldt_entry_count;
      memcpy(ThreadStateObject->ldt_entries, InheritThread->ldt_entries, new_ldt_size);
    }
  } else {
    // Without any thread data to inherit, setup the default gdt.
    // Default code segment indexes match the numbers that the Linux kernel uses.
    Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
    auto GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(GDT, 0);
    FEXCore::Core::CPUState::SetGDTLimit(GDT, 0xF'FFFFU);
    Frame->State.cs_cached =
      FEXCore::Core::CPUState::CalculateGDTBase(*FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx));

    if (Is64BitMode()) {
      GDT->L = 1; // L = Long Mode = 64-bit
      GDT->D = 0; // D = Default Operand SIze = Reserved
    } else {
      GDT->L = 0; // L = Long Mode = 32-bit
      GDT->D = 1; // D = Default Operand Size = 32-bit
    }
  }

  if (InheritThread) {
    FEX::HLE::_SyscallHandler->SeccompEmulator.InheritSeccompFilters(InheritThread, ThreadStateObject);
    ThreadStateObject->persona = InheritThread->persona;
  } else {
    ThreadStateObject->persona = ::personality(0xffffffff);
  }

  ++IdleWaitRefCount;
  return ThreadStateObject;
}

void ThreadManager::DestroyThread(FEX::HLE::ThreadStateObject* Thread, bool NeedsTLSUninstall) {
  {
    std::lock_guard lk(ThreadCreationMutex);
    auto It = std::find(Threads.begin(), Threads.end(), Thread);
    LOGMAN_THROW_A_FMT(It != Threads.end(), "Thread wasn't in Threads");
    Threads.erase(It);
    if (Threads.empty()) {
      Thread->Thread->CTX->FlushAndCloseCodeMap();
    }
  }

  Stat.DeallocateSlot(Thread->Thread->ThreadStats);

  HandleThreadDeletion(Thread, NeedsTLSUninstall);
}

void ThreadManager::StopThread(FEX::HLE::ThreadStateObject* Thread) {
  SignalDelegation->SignalThread(Thread->Thread, SignalEvent::Stop);
}

void ThreadManager::HandleThreadDeletion(FEX::HLE::ThreadStateObject* Thread, bool NeedsTLSUninstall) {
  // Robust-futex cleanup for 32-bit guests. The kernel performs this for
  // 64-bit guests via the native set_robust_list registration (passthrough);
  // 32-bit needs us to walk the list manually because the kernel can't parse
  // the 32-bit list layout from our 64-bit task. See WalkAndCleanupRobustList32.
  if (Thread->ThreadInfo.robust_list_head != 0 && !Is64BitMode()) {
    WalkAndCleanupRobustList32(static_cast<uint32_t>(Thread->ThreadInfo.robust_list_head),
                               static_cast<uint32_t>(Thread->ThreadInfo.TID));
  }

  if (Thread->ExecutionThread) {
    if (Thread->ExecutionThread->joinable()) {
      Thread->ExecutionThread->join(nullptr);
    }

    if (Thread->ExecutionThread->IsSelf()) {
      Thread->ExecutionThread->detach();
    }
  }

  if (NeedsTLSUninstall) {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    // Sanity check. This can only be called from the owning thread.
    {
      const auto pid = ::getpid();
      const auto tid = FHU::Syscalls::gettid();
      LOGMAN_THROW_A_FMT(Thread->ThreadInfo.PID == pid && Thread->ThreadInfo.TID == tid, "Can't delete TLS data from a different thread!");
    }
#endif
    FEXCore::Allocator::UninstallTLSData(Thread->Thread);
  }

  // Free the call-ret stack
  FEXCore::Allocator::munmap(reinterpret_cast<void*>(Thread->GetCallRetStackInfo().AllocationBase), CALLRET_STACK_ALLOC_SIZE);

  // If the LDT segment exists then deallocate it.
  if (Thread->ldt_entry_count) {
    FEXCore::Allocator::munmap(Thread->ldt_entries, Thread->ldt_entry_count * FEX::HLE::SyscallHandler::LDT_ENTRY_SIZE);
  }

  FEX::HLE::_SyscallHandler->SeccompEmulator.FreeSeccompFilters(Thread);

  // UAF mitigation (Steam SteamRT3 teardown race, 2026-05-15):
  // The kernel can deliver an in-flight signal AFTER the thread's
  // sigaltstack has been disabled but BEFORE the ThreadStateObject is
  // reclaimed.  SignalHandlerThunk reads the ThreadStateObject pointer
  // from a fixed offset within the (now-disabled) alt-stack memory and
  // dereferences `ThreadObject->Thread`, causing a UAF crash when both
  // the InternalThreadState and ThreadStateObject have been freed.
  // A clean refcount / epoch reclaim is the right fix but is a real
  // engineering project; meanwhile leak both objects so memory stays
  // valid for any stale signal handler.  Cost ~1MB per ~50 thread
  // create/destroy cycles -- Steam sessions are bounded so this is
  // acceptable until the proper fix lands.
  //
  // Mark the leaked object as zombie via a dedicated flag. DO NOT zero
  // ThreadInfo.TID here: the parent's CLONE_THREAD return path reads
  // TID as the guest-visible syscall result, and short-lived children
  // that exit before the parent finishes CreateNewThread would race the
  // store and hand `0` back to glibc as a "successful" clone. glibc
  // treats non-negative as success, stores `pd->tid = 0`, and the
  // downstream pd/_State recycling produces a use-after-free that
  // presents as libstdc++'s execute_native_thread_routine faulting on
  // `[rax+0x10]` (vtable slot 2 of a recycled _State chunk).
  Thread->ThreadInfo.IsZombie.store(true, std::memory_order_release);

  // Original deallocation (DO NOT re-enable until the signal-delivery
  // race is fixed via refcount or epoch-based reclaim):
  //   CTX->DestroyThread(Thread->Thread);
  //   delete Thread;
  --IdleWaitRefCount;
  IdleWaitCV.notify_all();
}

void ThreadManager::NotifyPause() {
  // Tell all the threads that they should pause
  std::lock_guard lk(ThreadCreationMutex);
  for (auto& Thread : Threads) {
    SignalDelegation->SignalThread(Thread->Thread, SignalEvent::Pause);
  }
}

void ThreadManager::Pause() {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  // Sanity check. This can't be called from an emulation thread.
  {
    const auto pid = ::getpid();
    const auto tid = FHU::Syscalls::gettid();
    std::lock_guard lk(ThreadCreationMutex);
    for (auto& Thread : Threads) {
      LOGMAN_THROW_A_FMT(!(Thread->ThreadInfo.PID == pid && Thread->ThreadInfo.TID == tid), "Can't put threads to sleep from inside "
                                                                                            "emulation thread!");
    }
  }
#endif
  NotifyPause();
  WaitForIdle();
}

void ThreadManager::Run() {
  // Spin up all the threads
  std::lock_guard lk(ThreadCreationMutex);
  for (auto& Thread : Threads) {
    Thread->SignalReason.store(SignalEvent::Return);
  }
}

void ThreadManager::WaitForIdleWithTimeout() {
  std::unique_lock<std::mutex> lk(IdleWaitMutex);
  bool WaitResult = IdleWaitCV.wait_for(lk, std::chrono::milliseconds(1500), [this] { return IdleWaitRefCount.load() == 0; });

  if (!WaitResult) {
    // The wait failed, this will occur if we stepped in to a syscall
    // That's okay, we just need to pause the threads manually
    NotifyPause();
  }

  // We have sent every thread a pause signal
  // Now wait again because they /will/ be going to sleep
  WaitForIdle();
}

void ThreadManager::WaitForThreadsToRun() {
  size_t NumThreads {};
  {
    std::lock_guard lk(ThreadCreationMutex);
    NumThreads = Threads.size();
  }

  // Spin while waiting for the threads to start up
  std::unique_lock<std::mutex> lk(IdleWaitMutex);
  IdleWaitCV.wait(lk, [this, NumThreads] { return IdleWaitRefCount.load() >= NumThreads; });

  Running = true;
}

void ThreadManager::Step() {
  LogMan::Msg::AFmt("ThreadManager::Step currently not implemented");
  {
    std::lock_guard lk(ThreadCreationMutex);
    // Walk the threads and tell them to clear their caches
    // Useful when our block size is set to a large number and we need to step a single instruction
    for (auto& Thread : Threads) {
      CTX->ClearCodeCache(Thread->Thread, false);
    }
  }

  // TODO: Set to single step mode.
  Run();
  WaitForThreadsToRun();
  WaitForIdle();
  // TODO: Set back to full running mode.
}

void ThreadManager::Stop(bool IgnoreCurrentThread) {
  pid_t tid = FHU::Syscalls::gettid();
  FEX::HLE::ThreadStateObject* CurrentThread {};

  // Tell all the threads that they should stop
  {
    std::lock_guard lk(ThreadCreationMutex);
    for (auto& Thread : Threads) {
      if (IgnoreCurrentThread && Thread->ThreadInfo.TID == tid) {
        // If we are calling stop from the current thread then we can ignore sending signals to this thread.
        // This thread is already gone - do NOT send it a stop signal.
        continue;
      } else if (Thread->ThreadInfo.TID == tid) {
        // We need to save the current thread for last to ensure all threads receive their stop signals
        CurrentThread = Thread;
        continue;
      }

      StopThread(Thread);
    }
  }

  // Stop the current thread now if we aren't ignoring it
  if (CurrentThread) {
    StopThread(CurrentThread);
  }
}

void ThreadManager::SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame) {
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame);
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  // Sanity check. This can only be called from the owning thread.
  {
    const auto pid = ::getpid();
    const auto tid = FHU::Syscalls::gettid();
    LOGMAN_THROW_A_FMT(ThreadObject->ThreadInfo.PID == pid && ThreadObject->ThreadInfo.TID == tid, "Can't delete TLS data from a different "
                                                                                                   "thread!");
  }
#endif

  --IdleWaitRefCount;
  IdleWaitCV.notify_all();

  ThreadObject->ThreadSleeping = true;

  // Go to sleep
  ThreadObject->ThreadPaused.Wait();

  ++IdleWaitRefCount;
  ThreadObject->ThreadSleeping = false;

  IdleWaitCV.notify_all();
}

void ThreadManager::UnpauseThread(FEX::HLE::ThreadStateObject* Thread) {
  Thread->ThreadPaused.NotifyOne();
}

void ThreadManager::LockBeforeFork() {
  Stat.LockBeforeFork();
}

void ThreadManager::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Stat.UnlockAfterFork(LiveThread, Child);
  if (!Child) {
    return;
  }

  // This function is called after fork
  // We need to cleanup some of the thread data that is dead
  for (auto& DeadThread : Threads) {
    // The fork parent retains ownership of ThreadStats
    DeadThread->Thread->ThreadStats = nullptr;

    if (DeadThread->Thread == LiveThread) {
      continue;
    }

    // Despite what google searches may susgest, glibc actually has special code to handle forks
    // with multiple active threads.
    // It cleans up the stacks of dead threads and marks them as terminated.
    // It also cleans up a bunch of internal mutexes.

    // FIXME: TLS is probally still alive. Investigate

    // Deconstructing the Interneal thread state should clean up most of the state.
    // But if anything on the now deleted stack is holding a refrence to the heap, it will be leaked
    CTX->DestroyThread(DeadThread->Thread);
    delete DeadThread;

    // FIXME: Make sure sure nothing gets leaked via the heap. Ideas:
    //         * Make sure nothing is allocated on the heap without ref in InternalThreadState
    //         * Surround any code that heap allocates with a per-thread mutex.
    //           Before forking, the the forking thread can lock all thread mutexes.
  }

  // Remove all threads but the live thread from Threads
  Threads.clear();

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromCPUState(LiveThread->CurrentFrame);
  Threads.push_back(ThreadObject);

  // Clean up dead stacks
  FEXCore::Threads::Thread::CleanupAfterFork();

  // We now only have one thread.
  IdleWaitRefCount = 1;
  ThreadCreationMutex.StealAndDropActiveLocks();
}

void ThreadManager::WaitForIdle() {
  std::unique_lock<std::mutex> lk(IdleWaitMutex);
  IdleWaitCV.wait(lk, [this] { return IdleWaitRefCount.load() == 0; });

  Running = false;
}

ThreadManager::~ThreadManager() {
  std::lock_guard lk(ThreadCreationMutex);

  for (auto& Thread : Threads) {
    HandleThreadDeletion(Thread);
  }
  Threads.clear();
}
} // namespace FEX::HLE
