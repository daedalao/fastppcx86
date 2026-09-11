// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-x86-64
$end_info$
*/

#include "LinuxSyscalls/GranuleMemory.h"
#include "LinuxSyscalls/LinuxAllocator.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include <FEXCore/Core/Context.h>
#include <FEXCore/Debug/InternalThreadState.h>

#include <FEXCore/IR/IR.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

#include <FEXCore/Core/Context.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/MathUtils.h>

namespace FEX::HLE::x64 {

void RegisterMemory(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;

  REGISTER_SYSCALL_IMPL_X64(
    mmap, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t length, int prot, int flags, int fd, off_t offset) -> uint64_t {
      // 64K host: a MAP_FIXED the host cannot represent, or an unrepresentable
      // file offset, is emulated here. Returns false on a 4K host and for every
      // request a 64K host can take directly, which is the common case.
      uint64_t Emulated {};
      if (FEX::HLE::Granule::Mmap(Frame->Thread, true, addr, length, prot, flags, fd, offset, &Emulated)) {
        return Emulated;
      }
      return (uint64_t)FEX::HLE::_SyscallHandler->GuestMmap(Frame->Thread, addr, length, prot, flags, fd, offset);
    });

  REGISTER_SYSCALL_IMPL_X64(munmap, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t length) -> uint64_t {
    uint64_t Emulated {};
    if (FEX::HLE::Granule::Munmap(Frame->Thread, addr, length, &Emulated)) {
      return Emulated;
    }
    return FEX::HLE::_SyscallHandler->GuestMunmap(Frame->Thread, addr, length);
  });

  REGISTER_SYSCALL_IMPL_X64(
    mremap, [](FEXCore::Core::CpuStateFrame* Frame, void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) -> uint64_t {
      return FEX::HLE::_SyscallHandler->GuestMremap(true, Frame->Thread, old_address, old_size, new_size, flags, new_address);
    });

  REGISTER_SYSCALL_IMPL_X64(mprotect, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t len, int prot) -> uint64_t {
    uint64_t Emulated {};
    if (FEX::HLE::Granule::Mprotect(Frame->Thread, addr, len, prot, &Emulated)) {
      return Emulated;
    }
    return FEX::HLE::_SyscallHandler->GuestMprotect(Frame->Thread, addr, len, prot);
  });

  REGISTER_SYSCALL_IMPL_X64(shmat, ([](FEXCore::Core::CpuStateFrame* Frame, int shmid, const void* shmaddr, int shmflg) -> uint64_t {
                              return FEX::HLE::_SyscallHandler->GuestShmat(true, Frame->Thread, shmid, shmaddr, shmflg);
                            }));

  REGISTER_SYSCALL_IMPL_X64(shmdt, [](FEXCore::Core::CpuStateFrame* Frame, const void* shmaddr) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GuestShmdt(true, Frame->Thread, shmaddr);
  });
}
} // namespace FEX::HLE::x64
