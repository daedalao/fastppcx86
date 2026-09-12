// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/GranuleMemory.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/IR/IR.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace FEX::HLE {
void RegisterMemory(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;

  REGISTER_SYSCALL_IMPL(brk, [](FEXCore::Core::CpuStateFrame* Frame, void* addr) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->HandleBRK(Frame, addr);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(madvise, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t length, int32_t advice) -> uint64_t {
    // 64K host: a destructive advice on part of a granule would discard a
    // sibling page the guest still owns. The shim never rounds one out; see
    // GranuleMemory.h. No-op on a 4K host and for granule-aligned requests.
    uint64_t Emulated {};
    if (FEX::HLE::Granule::Madvise(Frame->Thread, addr, length, advice, &Emulated)) {
      return Emulated;
    }

    uint64_t Result = ::madvise(addr, length, advice);

    if (Result != -1) {
      FEX::HLE::_SyscallHandler->TrackMadvise(Frame->Thread, (uintptr_t)addr, length, advice);
    }
    SYSCALL_ERRNO();
  });
}
} // namespace FEX::HLE
