// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/Syscalls/Thread.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/SignalDelegator.h>

#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace SignalDelegator {
struct GuestSigAction;
}

namespace FEX::HLE {
void RegisterSignals(FEX::HLE::SyscallHandler* Handler) {
  // The guest sigset_t is copied in and out here, as the kernel does, so a bad
  // pointer is EFAULT and the delegator only sees host memory. The kernel
  // requires sigsetsize to be exactly sizeof(sigset_t) (rt_sigpending: at most).
  REGISTER_SYSCALL_IMPL(rt_sigprocmask,
                        [](FEXCore::Core::CpuStateFrame* Frame, int how, const uint64_t* set, uint64_t* oldset, size_t sigsetsize) -> uint64_t {
                          if (sigsetsize != sizeof(uint64_t)) {
                            return -EINVAL;
                          }
                          uint64_t NewSet {};
                          if (set && !FaultSafeUserMemAccess::ReadFromUser(&NewSet, set)) {
                            return -EFAULT;
                          }
                          uint64_t OldSet {};
                          const uint64_t Result = FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigProcMask(
                            FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame), how, set ? &NewSet : nullptr, oldset ? &OldSet : nullptr);
                          if (Result == 0 && oldset && !FaultSafeUserMemAccess::WriteToUser(oldset, OldSet)) {
                            return -EFAULT;
                          }
                          return Result;
                        });

  REGISTER_SYSCALL_IMPL(rt_sigpending, [](FEXCore::Core::CpuStateFrame* Frame, uint64_t* set, size_t sigsetsize) -> uint64_t {
    if (sigsetsize > sizeof(uint64_t)) {
      return -EINVAL;
    }
    uint64_t Pending {};
    const uint64_t Result = FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigPending(
      FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame), &Pending, sizeof(Pending));
    if (Result == 0 && FaultSafeUserMemAccess::CopyToUser(set, &Pending, sigsetsize) != 0) {
      return -EFAULT;
    }
    return Result;
  });

  REGISTER_SYSCALL_IMPL(rt_sigsuspend, [](FEXCore::Core::CpuStateFrame* Frame, uint64_t* unewset, size_t sigsetsize) -> uint64_t {
    if (sigsetsize != sizeof(uint64_t)) {
      return -EINVAL;
    }
    uint64_t NewSet {};
    if (!FaultSafeUserMemAccess::ReadFromUser(&NewSet, unewset)) {
      return -EFAULT;
    }
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSigSuspend(FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame),
                                                                            &NewSet, sigsetsize);
  });

  REGISTER_SYSCALL_IMPL(userfaultfd, [](FEXCore::Core::CpuStateFrame* Frame, int flags) -> uint64_t {
    // Disable userfaultfd until we can properly emulate it
    // This is okay because the kernel configuration allows you to disable it at compile time
    return -ENOSYS;
    uint64_t Result = ::syscall(SYSCALL_DEF(userfaultfd), flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(signalfd, [](FEXCore::Core::CpuStateFrame* Frame, int fd, const uint64_t* mask, size_t sigsetsize) -> uint64_t {
    if (sigsetsize != sizeof(uint64_t)) {
      return -EINVAL;
    }
    uint64_t Mask {};
    if (!FaultSafeUserMemAccess::ReadFromUser(&Mask, mask)) {
      return -EFAULT;
    }
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSignalFD(fd, &Mask, sigsetsize, 0);
  });

  REGISTER_SYSCALL_IMPL(signalfd4, [](FEXCore::Core::CpuStateFrame* Frame, int fd, const uint64_t* mask, size_t sigsetsize, int flags) -> uint64_t {
    if (sigsetsize != sizeof(uint64_t)) {
      return -EINVAL;
    }
    uint64_t Mask {};
    if (!FaultSafeUserMemAccess::ReadFromUser(&Mask, mask)) {
      return -EFAULT;
    }
    return FEX::HLE::_SyscallHandler->GetSignalDelegator()->GuestSignalFD(fd, &Mask, sigsetsize, flags);
  });
}
} // namespace FEX::HLE
