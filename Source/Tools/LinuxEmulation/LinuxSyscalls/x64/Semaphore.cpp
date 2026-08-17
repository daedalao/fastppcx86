// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-x86-64
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x64/Types.h"

#include <FEXHeaderUtils/Syscalls.h>

#include <linux/sem.h>
#include <linux/shm.h>
#include <stddef.h>
#include <stdint.h>

namespace FEXCore::Core {
struct CpuStateFrame;
}

ARG_TO_STR(FEX::HLE::x64::semun, "%lx")

namespace FEX::HLE::x64 {
void RegisterSemaphore(FEX::HLE::SyscallHandler* Handler) {
  REGISTER_SYSCALL_IMPL_X64(semctl, [](FEXCore::Core::CpuStateFrame* Frame, int semid, int semnum, int cmd, FEX::HLE::x64::semun semun) -> uint64_t {
    uint64_t Result {};
    switch (cmd) {
    case IPC_SET: {
      struct semid64_ds buf {};
      FaultSafeUserMemAccess::VerifyIsReadable(semun.buf, sizeof(*semun.buf));
      buf = *semun.buf;
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &buf);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.buf, sizeof(*semun.buf));
        *semun.buf = buf;
      }
      break;
    }
    case SEM_STAT:
    case SEM_STAT_ANY:
    case IPC_STAT: {
      struct semid64_ds buf {};
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &buf);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.buf, sizeof(*semun.buf));
        *semun.buf = buf;
      }
      break;
    }
    case SEM_INFO:
    case IPC_INFO: {
      struct fex_seminfo si {};
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, &si);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(semun.__buf, sizeof(si));
        memcpy(semun.__buf, &si, sizeof(si));
      }
      break;
    }
    case GETALL:
    case SETALL: {
      // ptr is just a int32_t* in this case
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun.array);
      break;
    }
    case SETVAL: {
      // ptr is just a int32_t in this case
      Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun.val);
      break;
    }
    case IPC_RMID:
    case GETPID:
    case GETNCNT:
    case GETZCNT:
    case GETVAL: Result = ::syscall(SYSCALL_DEF(semctl), semid, semnum, cmd, semun); break;
    default: LOGMAN_MSG_A_FMT("Unhandled semctl cmd: {}", cmd); return -EINVAL;
    }
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL_X64(shmctl, [](FEXCore::Core::CpuStateFrame* Frame, int shmid, int cmd, FEX::HLE::x64::shmid_ds_64* buf) -> uint64_t {
    uint64_t Result {};
    switch (cmd) {
    case IPC_SET: {
      struct shmid64_ds host {};
      FaultSafeUserMemAccess::VerifyIsReadable(buf, sizeof(*buf));
      host = *buf;
      Result = ::syscall(SYSCALL_DEF(shmctl), shmid, cmd, &host);
      // IPC_SET sets the internal data structure that the kernel uses
      // No need to writeback
      break;
    }
    case SHM_STAT:
    case SHM_STAT_ANY:
    case IPC_STAT: {
      struct shmid64_ds host {};
      Result = ::syscall(SYSCALL_DEF(shmctl), shmid, cmd, &host);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(buf, sizeof(*buf));
        *buf = host;
      }
      break;
    }
    case IPC_INFO: {
      // struct shminfo64 layout matches between x86_64 and the host
      struct shminfo64 si {};
      Result = ::syscall(SYSCALL_DEF(shmctl), shmid, cmd, &si);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(buf, sizeof(si));
        memcpy(buf, &si, sizeof(si));
      }
      break;
    }
    case SHM_INFO: {
      // struct shm_info is arch-independent
      struct shm_info si {};
      Result = ::syscall(SYSCALL_DEF(shmctl), shmid, cmd, &si);
      if (Result != -1) {
        FaultSafeUserMemAccess::VerifyIsWritable(buf, sizeof(si));
        memcpy(buf, &si, sizeof(si));
      }
      break;
    }
    case SHM_LOCK:
    case SHM_UNLOCK:
    case IPC_RMID: Result = ::syscall(SYSCALL_DEF(shmctl), shmid, cmd, nullptr); break;
    default: LOGMAN_MSG_A_FMT("Unhandled shmctl cmd: {}", cmd); return -EINVAL;
    }
    SYSCALL_ERRNO();
  });
}
} // namespace FEX::HLE::x64
