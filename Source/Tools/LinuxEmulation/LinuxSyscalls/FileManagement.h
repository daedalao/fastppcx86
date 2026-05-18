// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|common
$end_info$
*/

#pragma once
#include <FEXCore/Config/Config.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/unordered_set.h>
#include <FEXCore/fextl/vector.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <linux/limits.h>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>

#include "LinuxSyscalls/EmulatedFiles/EmulatedFiles.h"

namespace FEXCore::Context {
class Context;
}

namespace FEX::HLE {
[[maybe_unused]]
static bool IsSymlink(int FD, const char* Filename) {
  // Checks to see if a filepath is a symlink.
  struct stat Buffer {};
  int Result = fstatat(FD, Filename, &Buffer, AT_SYMLINK_NOFOLLOW);
  return Result == 0 && S_ISLNK(Buffer.st_mode);
}

[[maybe_unused]]
static ssize_t GetSymlink(int FD, const char* Filename, char* ResultBuffer, size_t ResultBufferSize) {
  return readlinkat(FD, Filename, ResultBuffer, ResultBufferSize);
}

struct open_how;

class FileManager final {
public:
  FileManager() = delete;
  FileManager(FileManager&&) = delete;

  FileManager(FEXCore::Context::Context* ctx);
  ~FileManager();
  uint64_t Open(const char* pathname, int flags, uint32_t mode);
  uint64_t Close(int fd);
  uint64_t CloseRange(unsigned int first, unsigned int last, unsigned int flags);
  uint64_t Stat(const char* pathname, void* buf);
  uint64_t Lstat(const char* path, void* buf);
  uint64_t Access(const char* pathname, int mode);
  uint64_t FAccessat(int dirfd, const char* pathname, int mode);
  uint64_t FAccessat2(int dirfd, const char* pathname, int mode, int flags);
  uint64_t Readlink(const char* pathname, char* buf, size_t bufsiz);
  uint64_t Chmod(const char* pathname, mode_t mode);
  uint64_t Chown(const char* pathname, uid_t owner, gid_t group);
  uint64_t Lchown(const char* pathname, uid_t owner, gid_t group);
  uint64_t Unlink(const char* pathname);
  uint64_t Mkdir(const char* pathname, mode_t mode);
  uint64_t Rmdir(const char* pathname);
  uint64_t Link(const char* oldpath, const char* newpath);
  uint64_t Symlink(const char* target, const char* linkpath);
  uint64_t Rename(const char* oldpath, const char* newpath);
  uint64_t Creat(const char* pathname, mode_t mode);
  uint64_t Truncate(const char* pathname, off_t length);
  uint64_t Fchmodat(int dirfd, const char* pathname, mode_t mode, int flags);
  uint64_t Fchmodat2(int dirfd, const char* pathname, mode_t mode, unsigned int flags);
  uint64_t Fchownat(int dirfd, const char* pathname, uid_t owner, gid_t group, int flags);
  uint64_t Unlinkat(int dirfd, const char* pathname, int flags);
  uint64_t Mkdirat(int dirfd, const char* pathname, mode_t mode);
  uint64_t Linkat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags);
  uint64_t Symlinkat(const char* target, int newdirfd, const char* linkpath);
  uint64_t Renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath);
  uint64_t Renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags);
  uint64_t Readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz);
  uint64_t Openat(int dirfs, const char* pathname, int flags, uint32_t mode);
  uint64_t Openat2(int dirfs, const char* pathname, FEX::HLE::open_how* how, size_t usize);
  uint64_t Statx(int dirfd, const char* pathname, int flags, uint32_t mask, struct statx* statxbuf);
  uint64_t Mknod(const char* pathname, mode_t mode, dev_t dev);
  uint64_t NewFSStatAt(int dirfd, const char* pathname, struct stat* buf, int flag);
  uint64_t NewFSStatAt64(int dirfd, const char* pathname, struct stat64* buf, int flag);
  uint64_t Setxattr(const char* path, const char* name, const void* value, size_t size, int flags);
  uint64_t LSetxattr(const char* path, const char* name, const void* value, size_t size, int flags);
  uint64_t Getxattr(const char* path, const char* name, void* value, size_t size);
  uint64_t LGetxattr(const char* path, const char* name, void* value, size_t size);
  uint64_t Listxattr(const char* path, char* list, size_t size);
  uint64_t LListxattr(const char* path, char* list, size_t size);
  uint64_t Removexattr(const char* path, const char* name);
  uint64_t LRemovexattr(const char* path, const char* name);
  struct xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
  };

  uint64_t SetxattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name, const xattr_args* uargs, size_t usize);
  uint64_t GetxattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name, const xattr_args* uargs, size_t usize);
  uint64_t ListxattrAt(int dfd, const char* pathname, uint32_t at_flags, char* list, size_t size);
  uint64_t RemovexattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name);

  // vfs
  uint64_t Statfs(const char* path, void* buf);

  void UpdatePID(uint32_t PID);
  // Helper to detect FEX-internal files from their inode and parent directory FD.
  // This is useful to deal with Chromium/CEF, which closes any FDs reported in /proc/self/fd/.
  bool IsProtectedFile(int ParentDirFD, uint64_t inode) const;
  void SetProtectedCodeMapFD(int FD);

  fextl::string GetEmulatedPath(const char* pathname, bool FollowSymlink = false) const;
  fextl::string GetHostPath(fextl::string& Path, bool AliasedOnly) const;

  bool ReplaceEmuFd(int fd, int flags, uint32_t mode);

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  void TrackFEXFD(int FD) noexcept {
    std::lock_guard lk(FEXTrackingFDMutex);
    FEXTrackingFDs.emplace(FD);
  }

  void RemoveFEXFD(int FD) noexcept {
    std::lock_guard lk(FEXTrackingFDMutex);
    FEXTrackingFDs.erase(FD);
  }

  void RemoveFEXFDRange(int begin, int end) noexcept {
    std::lock_guard lk(FEXTrackingFDMutex);

    std::erase_if(FEXTrackingFDs, [begin, end](int FD) { return FD >= begin && (FD <= end || end == -1); });
  }

  bool CheckIfFDInTrackedSet(int FD) const noexcept {
    std::lock_guard lk(FEXTrackingFDMutex);
    return FEXTrackingFDs.contains(FD);
  }

  bool CheckIfFDRangeInTrackedSet(int begin, int end) const noexcept {
    std::lock_guard lk(FEXTrackingFDMutex);
    // Just linear scan since the number of tracking FDs is low.
    for (auto it : FEXTrackingFDs) {
      if (it >= begin && (it <= end || end == -1)) {
        return true;
      }
    }
    return false;
  }

#else
  void TrackFEXFD(int FD) const noexcept {}
  bool CheckIfFDInTrackedSet(int FD) const noexcept {
    return false;
  }
  void RemoveFEXFD(int FD) const noexcept {}
  void RemoveFEXFDRange(int begin, int end) const noexcept {}
  bool CheckIfFDRangeInTrackedSet(int begin, int end) const noexcept {
    return false;
  }
#endif

private:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  mutable std::mutex FEXTrackingFDMutex;
  fextl::set<int> FEXTrackingFDs;
#endif

  using FDPathTmpData = std::array<char[PATH_MAX], 2>;
  struct EmulatedFDPathResult final {
    int FD;
    const char* Path;
  };
  EmulatedFDPathResult GetEmulatedFDPath(int dirfd, const char* pathname, bool FollowSymlink, FDPathTmpData& TmpFilename) const;

  // Opens a path scoped strictly to RootFS via openat2(RESOLVE_IN_ROOT).
  // Returns an O_PATH fd whose symlink resolution (intermediate AND leaf) is
  // confined to the rootfs namespace, preventing absolute symlinks from
  // escaping into the host filesystem (e.g. an x86 libtinfo.so.6 in the
  // rootfs accidentally resolving through to the host's PowerPC libncursesw).
  // FollowSymlink: true follows the leaf symlink, false uses O_NOFOLLOW.
  // Returns -1 on error (errno is set). Caller owns returned fd.
  int OpenPathInRootFS(const EmulatedFDPathResult& Path, bool FollowSymlink) const;

  std::optional<std::string_view> GetSelf(const char* Pathname) const;
  bool IsSelfNoFollow(const char* Pathname, int flags) const;

  bool RootFSPathExists(const char* Filepath) const;
  size_t GetRootFSPrefixLen(const char* pathname, size_t len, bool AliasedOnly) const;
  ssize_t StripRootFSPrefix(char* pathname, ssize_t len, bool leaky) const;

  struct ThunkDBObject {
    fextl::string LibraryName;
    fextl::unordered_set<fextl::string> Depends;
    fextl::vector<fextl::string> Overlays;
    bool Enabled {};
  };
  void LoadThunkDatabase(fextl::unordered_map<fextl::string, ThunkDBObject>& ThunkDB, bool Global);
  FEX::EmulatedFile::EmulatedFDManager EmuFD;

  fextl::map<fextl::string, fextl::string, std::less<>> ThunkOverlays;

  FEX_CONFIG_OPT(Filename, APP_FILENAME);
  FEX_CONFIG_OPT(LDPath, ROOTFS);
  FEX_CONFIG_OPT(ThunkGuestLibs, THUNKGUESTLIBS);
  FEX_CONFIG_OPT(ThunkConfig, THUNKCONFIG);
  FEX_CONFIG_OPT(AppConfigName, APP_CONFIG_NAME);
  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
  uint32_t CurrentPID {};
  int RootFSFD {AT_FDCWD};
  int ProcFD {0};
  int64_t RootFSFDInode = 0;
  int64_t ProcFDInode = 0;
  int64_t CodeMapInode = 0;
  dev_t ProcFSDev;
};
} // namespace FEX::HLE
