// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/fmt.h>

#include <algorithm>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/resource.h>
#include <unistd.h>

namespace FEX {

[[nodiscard]]
inline int get_fdpath(int fd, char* SymlinkPath) {
  auto Path = fextl::fmt::format("/proc/self/fd/{}", fd);
  return readlinkat(AT_FDCWD, Path.c_str(), SymlinkPath, PATH_MAX);
}

// Moves a descriptor the emulator keeps for itself (FEXServer socket, log,
// rootfs and /proc directories) up out of the range the guest's own
// descriptors use, and closes the original. On Linux the guest's descriptors
// are numbered from the lowest free slot, so emulator descriptors sitting at
// 3, 4, ... shifted every guest open (a first open returned 5 instead of 3).
//
// The target range sits just below min(RLIMIT_NOFILE soft limit, 1024), not
// below the soft limit itself: the kernel sizes a process's descriptor table
// to its highest open descriptor, and launchers such as Wine raise the soft
// limit to the hard limit (524288 or more), which put every child's table at
// megabytes. 1024 is the kernel's default soft limit, so the table stays at
// the size an ordinary process has. Returns the new descriptor, or the
// original one if it cannot be moved (a small limit, or already high).
inline int MoveFDOutOfGuestRange(int FD) {
  if (FD < 0) {
    return FD;
  }
  constexpr rlim_t Ceiling = 1024;
  constexpr rlim_t Reserved = 64;
  struct rlimit Limit {};
  if (getrlimit(RLIMIT_NOFILE, &Limit) != 0) {
    return FD;
  }
  const rlim_t Top = std::min<rlim_t>(Limit.rlim_cur, Ceiling);
  if (Top < 256) {
    return FD;
  }
  const int Base = static_cast<int>(Top - Reserved);
  if (FD >= Base) {
    return FD;
  }
  const bool CloExec = (fcntl(FD, F_GETFD) & FD_CLOEXEC) != 0;
  const int NewFD = fcntl(FD, CloExec ? F_DUPFD_CLOEXEC : F_DUPFD, Base);
  if (NewFD < 0) {
    return FD;
  }
  close(FD);
  return NewFD;
}

} // namespace FEX
