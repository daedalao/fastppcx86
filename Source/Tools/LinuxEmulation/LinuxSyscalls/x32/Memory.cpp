// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-x86-32
$end_info$
*/

#include "Common/HostPageMapping.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/MathUtils.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <optional>
#include <system_error>
#include <filesystem>

namespace FEX::HLE::x32 {

// mmap2's offset unit is 4096 by x86 ABI -- that constant is GUEST and never
// changes. The product it forms is a host file offset, though, and a host mmap
// requires it to be a multiple of the host page. On a host whose page is larger
// than the guest's the request has to be emulated the same way the ELF loader
// emulates an unrepresentable PT_LOAD: reserve the containing host pages
// anonymously, pread the file bytes in, apply the protection host-granularly
// (Source/Common/HostPageMapping.h, design Part 2 sections 2 and 3).
//
// Returns std::nullopt when the request is representable and the caller should
// just forward it to GuestMmap, which is always the case on a 4K host.
static std::optional<uint64_t>
GuestMmapMisalignedFile(FEXCore::Core::CpuStateFrame* Frame, uint32_t addr, uint32_t length, int prot, int flags, int fd, uint64_t offset) {
  if (!FEX::HostPageMapping::RequiresFallback(addr, offset, flags, fd)) {
    return std::nullopt;
  }

  if (flags & (MAP_SHARED | MAP_SHARED_VALIDATE)) {
    // A shared mapping cannot be emulated by copying: the guest would stop
    // seeing other writers. Refuse loudly rather than silently diverge.
    LogMan::Msg::EFmt("mmap: MAP_SHARED at offset {:#x}, which the {} byte host page cannot represent. Refusing.", offset,
                      FEXCore::HostPage::Size());
    return static_cast<uint64_t>(-EINVAL);
  }

  auto DoMmap = [Frame](void* Addr, size_t Length, int Prot, int Flags, int FD, off_t Offset) {
    return FEX::HLE::_SyscallHandler->GuestMmap(false, Frame->Thread, Addr, Length, Prot, Flags, FD, Offset);
  };
  auto DoMprotect = [Frame](void* Addr, size_t Length, int Prot) {
    return FEX::HLE::_SyscallHandler->GuestMprotect(Frame->Thread, Addr, Length, Prot);
  };

  return reinterpret_cast<uint64_t>(
    FEX::HostPageMapping::MapFilePrivate(DoMmap, DoMprotect, reinterpret_cast<void*>(addr), length, prot, flags, fd, offset));
}

void RegisterMemory(FEX::HLE::SyscallHandler* Handler) {
  struct old_mmap_struct {
    uint32_t addr;
    uint32_t len;
    uint32_t prot;
    uint32_t flags;
    uint32_t fd;
    uint32_t offset;
  };
  REGISTER_SYSCALL_IMPL_X32(mmap, [](FEXCore::Core::CpuStateFrame* Frame, const old_mmap_struct* arg) -> uint64_t {
    if (auto Emulated = GuestMmapMisalignedFile(Frame, arg->addr, arg->len, arg->prot, arg->flags, arg->fd, arg->offset)) {
      return *Emulated;
    }
    return reinterpret_cast<uint64_t>(FEX::HLE::_SyscallHandler->GuestMmap(false, Frame->Thread, reinterpret_cast<void*>(arg->addr),
                                                                           arg->len, arg->prot, arg->flags, arg->fd, arg->offset));
  });

  REGISTER_SYSCALL_IMPL_X32(
    mmap2, [](FEXCore::Core::CpuStateFrame* Frame, uint32_t addr, uint32_t length, int prot, int flags, int fd, uint32_t pgoffset) -> uint64_t {
      // GUEST: the 4096 is the mmap2 ABI's offset unit and stays.
      const uint64_t Offset = (uint64_t)pgoffset * FEXCore::Utils::FEX_GUEST_PAGE_SIZE;
      if (auto Emulated = GuestMmapMisalignedFile(Frame, addr, length, prot, flags, fd, Offset)) {
        return *Emulated;
      }
      return reinterpret_cast<uint64_t>(
        FEX::HLE::_SyscallHandler->GuestMmap(false, Frame->Thread, reinterpret_cast<void*>(addr), length, prot, flags, fd, Offset));
    });

  REGISTER_SYSCALL_IMPL_X32(munmap, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t length) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GuestMunmap(Frame->Thread, addr, length);
  });

  REGISTER_SYSCALL_IMPL_X32(mprotect, [](FEXCore::Core::CpuStateFrame* Frame, void* addr, uint32_t len, int prot) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GuestMprotect(Frame->Thread, addr, len, prot);
  });

  REGISTER_SYSCALL_IMPL_X32(
    mremap, [](FEXCore::Core::CpuStateFrame* Frame, void* old_address, size_t old_size, size_t new_size, int flags, void* new_address) -> uint64_t {
      return FEX::HLE::_SyscallHandler->GuestMremap(false, Frame->Thread, old_address, old_size, new_size, flags, new_address);
    });

  REGISTER_SYSCALL_IMPL_X32(mlockall, [](FEXCore::Core::CpuStateFrame* Frame, int flags) -> uint64_t {
    uint64_t Result = ::syscall(SYSCALL_DEF(mlock2), reinterpret_cast<void*>(0x1'0000), 0x1'0000'0000ULL - 0x1'0000, flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL_X32(munlockall, [](FEXCore::Core::CpuStateFrame* Frame) -> uint64_t {
    uint64_t Result = ::munlock(reinterpret_cast<void*>(0x1'0000), 0x1'0000'0000ULL - 0x1'0000);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL_X32(shmat, [](FEXCore::Core::CpuStateFrame* Frame, int shmid, const void* shmaddr, int shmflg) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GuestShmat(false, Frame->Thread, shmid, shmaddr, shmflg);
  });

  REGISTER_SYSCALL_IMPL_X32(shmdt, [](FEXCore::Core::CpuStateFrame* Frame, const void* shmaddr) -> uint64_t {
    return FEX::HLE::_SyscallHandler->GuestShmdt(false, Frame->Thread, shmaddr);
  });
}

} // namespace FEX::HLE::x32
