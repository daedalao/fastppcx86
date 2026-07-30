// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"

#include <FEXCore/IR/IR.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/xattr.h>

namespace FEX::HLE {
void RegisterFS(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;

  REGISTER_SYSCALL_IMPL(rename, [](FEXCore::Core::CpuStateFrame* Frame, const char* oldpath, const char* newpath) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Rename(oldpath, newpath);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(mkdir, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, mode_t mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Mkdir(pathname, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(rmdir, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Rmdir(pathname);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(link, [](FEXCore::Core::CpuStateFrame* Frame, const char* oldpath, const char* newpath) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Link(oldpath, newpath);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(unlink, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Unlink(pathname);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(symlink, [](FEXCore::Core::CpuStateFrame* Frame, const char* target, const char* linkpath) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Symlink(target, linkpath);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(readlink, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, char* buf, size_t bufsiz) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Readlink(pathname, buf, bufsiz);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(chmod, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, mode_t mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Chmod(pathname, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(mknod, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, mode_t mode, dev_t dev) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Mknod(pathname, mode, dev);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(creat, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, mode_t mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Creat(pathname, mode);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(truncate, [](FEXCore::Core::CpuStateFrame* Frame, const char* pathname, off_t length) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Truncate(pathname, length);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(
    setxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name, const void* value, size_t size, int flags) -> uint64_t {
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.Setxattr(path, name, value, size, flags);
      SYSCALL_ERRNO();
    });

  REGISTER_SYSCALL_IMPL(
    lsetxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name, const void* value, size_t size, int flags) -> uint64_t {
      uint64_t Result = FEX::HLE::_SyscallHandler->FM.LSetxattr(path, name, value, size, flags);
      SYSCALL_ERRNO();
    });

  REGISTER_SYSCALL_IMPL(getxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name, void* value, size_t size) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Getxattr(path, name, value, size);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(lgetxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name, void* value, size_t size) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.LGetxattr(path, name, value, size);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(listxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, char* list, size_t size) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Listxattr(path, list, size);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(llistxattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, char* list, size_t size) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.LListxattr(path, list, size);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(removexattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Removexattr(path, name);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(lremovexattr, [](FEXCore::Core::CpuStateFrame* Frame, const char* path, const char* name) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.LRemovexattr(path, name);
    SYSCALL_ERRNO();
  });
  if (Handler->IsHostKernelVersionAtLeast(6, 13, 0)) {
    REGISTER_SYSCALL_IMPL(setxattrat,
                          [](FEXCore::Core::CpuStateFrame* Frame, int dfd, const char* pathname, uint32_t at_flags, const char* name,
                             const FileManager::xattr_args* uargs, size_t usize) -> uint64_t {
                            uint64_t Result = FEX::HLE::_SyscallHandler->FM.SetxattrAt(dfd, pathname, at_flags, name, uargs, usize);
                            SYSCALL_ERRNO();
                          });
    REGISTER_SYSCALL_IMPL(getxattrat,
                          [](FEXCore::Core::CpuStateFrame* Frame, int dfd, const char* pathname, uint32_t at_flags, const char* name,
                             const FileManager::xattr_args* uargs, size_t usize) -> uint64_t {
                            uint64_t Result = FEX::HLE::_SyscallHandler->FM.GetxattrAt(dfd, pathname, at_flags, name, uargs, usize);
                            SYSCALL_ERRNO();
                          });

    REGISTER_SYSCALL_IMPL(
      listxattrat, [](FEXCore::Core::CpuStateFrame* Frame, int dfd, const char* pathname, uint32_t at_flags, char* list, size_t size) -> uint64_t {
        uint64_t Result = FEX::HLE::_SyscallHandler->FM.ListxattrAt(dfd, pathname, at_flags, list, size);
        SYSCALL_ERRNO();
      });
    REGISTER_SYSCALL_IMPL(
      removexattrat, [](FEXCore::Core::CpuStateFrame* Frame, int dfd, const char* pathname, uint32_t at_flags, const char* name) -> uint64_t {
        uint64_t Result = FEX::HLE::_SyscallHandler->FM.RemovexattrAt(dfd, pathname, at_flags, name);
        SYSCALL_ERRNO();
      });
  } else {
    REGISTER_SYSCALL_IMPL(setxattrat, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(getxattrat, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(listxattrat, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(removexattrat, UnimplementedSyscallSafe);
  }

  // *at() syscall handlers — overlay-aware. Replaces the bare passthrough
  // registrations in Passthrough.cpp (which were causing split state between
  // file-creation paths and *at() resolution targets).
  REGISTER_SYSCALL_IMPL(fchmodat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, mode_t mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Fchmodat(dirfd, pathname, mode, 0);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(fchownat,
                        [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, uid_t owner, gid_t group, int flags) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Fchownat(dirfd, pathname, owner, group, flags);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL(unlinkat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, int flags) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Unlinkat(dirfd, pathname, flags);
    SYSCALL_ERRNO();
  });

  REGISTER_SYSCALL_IMPL(mkdirat, [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, mode_t mode) -> uint64_t {
    uint64_t Result = FEX::HLE::_SyscallHandler->FM.Mkdirat(dirfd, pathname, mode);
    SYSCALL_ERRNO();
  });

  // X64 only: x32 already registers its own utimensat in x32/Time.cpp, which
  // converts the guest's 32-bit timespec pair before the call. REGISTER_SYSCALL_IMPL
  // writes BOTH tables (Syscalls.h:704-708), so using it here double-registers:
  // x32/Time.cpp runs later (x32/Syscalls.cpp:81 vs :56) and wins, so this
  // handler never applied to 32-bit anyway -- and on an assertions build the
  // duplicate trips LOGMAN_THROW_A_FMT in x32/Syscalls.h:62, aborting every
  // 32-bit process at startup.
  // The 32-bit path still needs RootFS translation; tracked separately so the
  // timespec32 conversion is not lost.
  REGISTER_SYSCALL_IMPL_X64(utimensat,
                        [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, const struct timespec* times, int flags) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Utimensat(dirfd, pathname, times, flags);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL(linkat,
                        [](FEXCore::Core::CpuStateFrame* Frame, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Linkat(olddirfd, oldpath, newdirfd, newpath, flags);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL(symlinkat,
                        [](FEXCore::Core::CpuStateFrame* Frame, const char* target, int newdirfd, const char* linkpath) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Symlinkat(target, newdirfd, linkpath);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL(renameat,
                        [](FEXCore::Core::CpuStateFrame* Frame, int olddirfd, const char* oldpath, int newdirfd, const char* newpath) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Renameat(olddirfd, oldpath, newdirfd, newpath);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL(renameat2,
                        [](FEXCore::Core::CpuStateFrame* Frame, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) -> uint64_t {
                          uint64_t Result = FEX::HLE::_SyscallHandler->FM.Renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
                          SYSCALL_ERRNO();
                        });

  REGISTER_SYSCALL_IMPL_X64(fchmodat2,
                            [](FEXCore::Core::CpuStateFrame* Frame, int dirfd, const char* pathname, mode_t mode, unsigned int flags) -> uint64_t {
                              uint64_t Result = FEX::HLE::_SyscallHandler->FM.Fchmodat2(dirfd, pathname, mode, flags);
                              SYSCALL_ERRNO();
                            });
}
} // namespace FEX::HLE
