// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|common
desc: Rootfs overlay logic
$end_info$
*/

#include "Common/Config.h"
#include "Common/FDUtils.h"
#include "Common/JSONPool.h"

#include "FEXCore/Config/Config.h"
#include <sys/syscall.h>
#include "LinuxSyscalls/FileManagement.h"
#include "LinuxSyscalls/EmulatedFiles/EmulatedFiles.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/FileLoading.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/list.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <FEXHeaderUtils/SymlinkChecks.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <errno.h>
#include <cstring>
#include <linux/openat2.h>
#include <fcntl.h>
#include <filesystem>
#include <optional>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <syscall.h>
#include <system_error>
#include <unistd.h>
#include <utility>

#include <tiny-json.h>

namespace FEX::HLE {
bool FileManager::RootFSPathExists(const char* Filepath) const {
  LOGMAN_THROW_A_FMT(Filepath && Filepath[0] == '/', "Filepath needs to be absolute");
  return FHU::Filesystem::ExistsAt(RootFSFD, Filepath + 1);
}

void FileManager::LoadThunkDatabase(fextl::unordered_map<fextl::string, ThunkDBObject>& ThunkDB, bool Global) {
  auto ThunkDBPath = FEXCore::Config::GetConfigDirectory(Global) + "ThunksDB.json";
  fextl::vector<char> FileData;
  if (FEXCore::FileLoading::LoadFile(FileData, ThunkDBPath)) {

    // If the thunksDB file exists then we need to check if the rootfs supports multi-arch or not.
    const bool RootFSIsMultiarch = RootFSPathExists("/usr/lib/x86_64-linux-gnu/") || RootFSPathExists("/usr/lib/i386-linux-gnu/");

    fextl::vector<fextl::string> PathPrefixes {};
    if (RootFSIsMultiarch) {
      // Multi-arch debian distros have a fairly complex arrangement of filepaths.
      // These fractal out to the combination of library prefixes with arch suffixes.
      constexpr static std::array<std::string_view, 4> LibPrefixes = {
        "/usr/lib",
        "/usr/local/lib",
        "/lib",
        "/usr/lib/pressure-vessel/overrides/lib",
      };

      // We only need to generate 32-bit or 64-bit depending on the operating mode.
      const auto ArchPrefix = Is64BitMode() ? "x86_64-linux-gnu" : "i386-linux-gnu";

      for (auto Prefix : LibPrefixes) {
        PathPrefixes.emplace_back(fextl::fmt::format("{}/{}", Prefix, ArchPrefix));
      }
    } else {
      // Non multi-arch supporting distros like Fedora and Debian have a much more simple layout.
      // lib/ folders refer to 32-bit library folders.
      // li64/ folders refer to 64-bit library folders.
      constexpr static std::array<std::string_view, 4> LibPrefixes = {
        "/usr",
        "/usr/local",
        "", // root, the '/' will be appended in the next step.
        "/usr/lib/pressure-vessel/overrides",
      };

      // We only need to generate 32-bit or 64-bit depending on the operating mode.
      const auto ArchPrefix = Is64BitMode() ? "lib64" : "lib";

      for (auto Prefix : LibPrefixes) {
        PathPrefixes.emplace_back(fextl::fmt::format("{}/{}", Prefix, ArchPrefix));
      }
      // Arch Linux ships 64-bit libraries in /usr/lib (with /usr/lib64 as a symlink
      // to /usr/lib). Without an explicit "lib" entry in 64-bit mode, the thunk
      // overlay map never matches the rootfs's actual paths and FEX silently loads
      // the real x86 library instead of substituting our guest thunk stub.
      if (Is64BitMode()) {
        for (auto Prefix : LibPrefixes) {
          PathPrefixes.emplace_back(fextl::fmt::format("{}/{}", Prefix, "lib"));
        }
      } else {
        // The mirror image of the above: Arch ships 32-bit libraries in /usr/lib32
        // (with /lib32 symlinked to it), not in the "lib" folder this branch
        // assumes for 32-bit. Without an explicit "lib32" entry the overlay map
        // never matches, so a 32-bit guest loads the rootfs's own libGL/libvulkan
        // and runs the entire Mesa driver stack under emulation - correct output,
        // but the host GPU is never reached and the frame loop is CPU-bound.
        // Measured on a 32-bit Unity title before this fix: ~99% of cycles in
        // translated code with the GPU at ~5%.
        for (auto Prefix : LibPrefixes) {
          PathPrefixes.emplace_back(fextl::fmt::format("{}/{}", Prefix, "lib32"));
        }
      }
    }

    FEX::JSON::JsonAllocator Pool {};
    const json_t* json = FEX::JSON::CreateJSON(FileData, Pool);

    if (!json) {
      ERROR_AND_DIE_FMT("Failed to parse JSON from ThunkDB file '{}' - invalid JSON format", ThunkDBPath);
    }

    const json_t* DB = json_getProperty(json, "DB");
    if (!DB || JSON_OBJ != json_getType(DB)) {
      return;
    }

    auto HomeDirectory = FEX::Config::GetHomeDirectory();

    for (const json_t* Library = json_getChild(DB); Library != nullptr; Library = json_getSibling(Library)) {
      // Get the user defined name for the library
      const char* LibraryName = json_getName(Library);
      auto DBObject = ThunkDB.insert_or_assign(LibraryName, ThunkDBObject {}).first;

      // Walk the libraries items to get the data
      for (const json_t* LibraryItem = json_getChild(Library); LibraryItem != nullptr; LibraryItem = json_getSibling(LibraryItem)) {
        std::string_view ItemName = json_getName(LibraryItem);

        if (ItemName == "Library") {
          // "Library": "libGL-guest.so"
          DBObject->second.LibraryName = json_getValue(LibraryItem);
        } else if (ItemName == "Depends") {
          jsonType_t PropertyType = json_getType(LibraryItem);
          if (PropertyType == JSON_TEXT) {
            DBObject->second.Depends.emplace(json_getValue(LibraryItem));
          } else if (PropertyType == JSON_ARRAY) {
            for (const json_t* Depend = json_getChild(LibraryItem); Depend != nullptr; Depend = json_getSibling(Depend)) {
              DBObject->second.Depends.emplace(json_getValue(Depend));
            }
          }
        } else if (ItemName == "Overlay") {
          auto AddWithReplacement = [HomeDirectory, &PathPrefixes](ThunkDBObject& DBObject, std::string_view LibraryItem) {
            // Walk through template string and fill in prefixes from right to left

            using namespace std::string_view_literals;
            const std::pair PrefixHome {"@HOME@"sv, LibraryItem.find("@HOME@")};
            const std::pair PrefixLib {"@PREFIX_LIB@"sv, LibraryItem.find("@PREFIX_LIB@")};

            fextl::string::size_type PrefixPositions[] = {
              PrefixHome.second,
              PrefixLib.second,
            };
            // Sort offsets in descending order to enable safe in-place replacement
            std::sort(std::begin(PrefixPositions), std::end(PrefixPositions), std::greater<> {});

            for (const auto& LibPrefix : PathPrefixes) {
              fextl::string Replacement(LibraryItem);
              for (auto PrefixPos : PrefixPositions) {
                if (PrefixPos == fextl::string::npos) {
                  continue;
                } else if (PrefixPos == PrefixHome.second) {
                  Replacement.replace(PrefixPos, PrefixHome.first.size(), HomeDirectory);
                } else if (PrefixPos == PrefixLib.second) {
                  Replacement.replace(PrefixPos, PrefixLib.first.size(), LibPrefix);
                }
              }
              DBObject.Overlays.emplace_back(std::move(Replacement));

              if (PrefixLib.second == fextl::string::npos) {
                // Don't repeat for other LibPrefixes entries if the prefix wasn't used
                break;
              }
            }
          };

          jsonType_t PropertyType = json_getType(LibraryItem);
          if (PropertyType == JSON_TEXT) {
            AddWithReplacement(DBObject->second, json_getValue(LibraryItem));
          } else if (PropertyType == JSON_ARRAY) {
            for (const json_t* Overlay = json_getChild(LibraryItem); Overlay != nullptr; Overlay = json_getSibling(Overlay)) {
              AddWithReplacement(DBObject->second, json_getValue(Overlay));
            }
          }
        }
      }
    }
  }
}

FileManager::FileManager(FEXCore::Context::Context* ctx)
  : EmuFD {ctx} {
  const auto& ThunkConfigFile = ThunkConfig();

  // We try to load ThunksDB from:
  // - FEX global config
  // - FEX user config
  // - Defined ThunksConfig option
  // - Steam AppConfig Global
  // - AppConfig Global
  // - Steam AppConfig Local
  // - AppConfig Local
  // - AppConfig override
  // This doesn't support the classic thunks interface.

  const auto& AppName = AppConfigName();
  fextl::vector<fextl::string> ConfigPaths {
    FEXCore::Config::GetConfigFileLocation(true),
    FEXCore::Config::GetConfigFileLocation(false),
    ThunkConfigFile,
  };

  auto SteamID = getenv("SteamAppId");
  if (SteamID) {
    // If a SteamID exists then let's search for Steam application configs as well.
    // We want to key off both the SteamAppId number /and/ the executable since we may not want to thunk all binaries.
    fextl::string SteamAppName = fextl::fmt::format("Steam_{}_{}", SteamID, AppName);

    // Steam application configs interleaved with non-steam for priority sorting.
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(SteamAppName, true));
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(AppName, true));
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(SteamAppName, false));
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(AppName, false));
  } else {
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(AppName, true));
    ConfigPaths.emplace_back(FEXCore::Config::GetApplicationConfig(AppName, false));
  }

  const char* AppConfig = getenv("FEX_APP_CONFIG");
  if (AppConfig) {
    ConfigPaths.emplace_back(AppConfig);
  }

  if (!LDPath().empty()) {
    RootFSFD = open(LDPath().c_str(), O_DIRECTORY | O_PATH | O_CLOEXEC);
    if (RootFSFD == -1) {
      RootFSFD = AT_FDCWD;
    } else {
      TrackFEXFD(RootFSFD);
    }
  }

  fextl::unordered_map<fextl::string, ThunkDBObject> ThunkDB;
  LoadThunkDatabase(ThunkDB, true);
  LoadThunkDatabase(ThunkDB, false);

  for (const auto& Path : ConfigPaths) {
    fextl::vector<char> FileData;
    if (FEXCore::FileLoading::LoadFile(FileData, Path)) {
      FEX::JSON::JsonAllocator Pool {};

      // If a thunks DB property exists then we pull in data from the thunks database
      const json_t* json = FEX::JSON::CreateJSON(FileData, Pool);
      if (!json) {
        continue;
      }

      const json_t* ThunksDB = json_getProperty(json, "ThunksDB");
      if (!ThunksDB) {
        continue;
      }

      for (const json_t* Item = json_getChild(ThunksDB); Item != nullptr; Item = json_getSibling(Item)) {
        const char* LibraryName = json_getName(Item);
        bool LibraryEnabled = json_getInteger(Item) != 0;
        // If the library is enabled then find it in the DB
        auto DBObject = ThunkDB.find(LibraryName);
        if (DBObject != ThunkDB.end()) {
          DBObject->second.Enabled = LibraryEnabled;
        }
      }
    }
  }

  // Now that we loaded the thunks object, walk through and ensure dependencies are enabled as well
  auto ThunkGuestPath = ThunkGuestLibs();
  while (ThunkGuestPath.ends_with('/')) {
    ThunkGuestPath.pop_back();
  }
  if (!Is64BitMode()) {
    ThunkGuestPath += "_32";
  }
  for (const auto& DBObject : ThunkDB) {
    if (!DBObject.second.Enabled) {
      continue;
    }

    // Recursively add paths for this thunk library and its dependencies to ThunkOverlays.
    // Using a local struct for this is slightly less ugly than using self-capturing lambdas
    struct {
      decltype(FileManager::ThunkOverlays)& ThunkOverlays;
      decltype(ThunkDB)& DB;
      const fextl::string& ThunkGuestPath;
      bool Is64BitMode;

      void SetupOverlay(const ThunkDBObject& DBDepend) {
        auto ThunkPath = fextl::fmt::format("{}/{}", ThunkGuestPath, DBDepend.LibraryName);
        if (!FHU::Filesystem::Exists(ThunkPath)) {
          if (!Is64BitMode) {
            // Not every guest library is thunked on 32-bit; the whole thunk
            // set may also simply not have been built (BUILD_THUNKS_32BIT=OFF
            // is the default when the toolchain lacks 32-bit multilib). Log
            // so an unbuilt thunk set does not fail silently -- the guest
            // silently loads its own rootfs library instead, which for
            // libGL/libvulkan means never reaching the host GPU and no
            // symptom other than "gldriverquery returns nothing".
            LogMan::Msg::DFmt("32-bit thunk not present: {} (guest will use its "
                              "own copy in the rootfs; host acceleration not "
                              "available for this library)",
                              ThunkPath);
            return;
          }
          ERROR_AND_DIE_FMT("Requested thunking via guest library \"{}\" that does not exist", ThunkPath);
        }

        for (const auto& Overlay : DBDepend.Overlays) {
          // Direct full path in guest RootFS to our overlay file
          ThunkOverlays.emplace(Overlay, ThunkPath);
        }
      };

      void InsertDependencies(const fextl::unordered_set<fextl::string>& Depends) {
        for (const auto& Depend : Depends) {
          auto& DBDepend = DB.at(Depend);
          if (DBDepend.Enabled) {
            continue;
          }

          SetupOverlay(DBDepend);

          // Mark enabled and recurse into dependencies
          DBDepend.Enabled = true;
          InsertDependencies(DBDepend.Depends);
        }
      };
    } DBObjectHandler {ThunkOverlays, ThunkDB, ThunkGuestPath, Is64BitMode()};

    DBObjectHandler.SetupOverlay(DBObject.second);
    DBObjectHandler.InsertDependencies(DBObject.second.Depends);
  }

  if (false) {
    // Useful for debugging
    if (ThunkOverlays.size()) {
      LogMan::Msg::IFmt("Thunk Overlays:");
      for (const auto& [Overlay, ThunkPath] : ThunkOverlays) {
        LogMan::Msg::IFmt("\t{} -> {}", Overlay, ThunkPath);
      }
    }
  }

  // Keep an fd open for /proc, to bypass chroot-style sandboxes
  ProcFD = open("/proc", O_RDONLY | O_CLOEXEC);
  if (ProcFD != -1) {
    // Track the st_dev of /proc, to check for inode equality
    struct stat Buffer;
    auto Result = fstat(ProcFD, &Buffer);
    if (Result >= 0) {
      ProcFSDev = Buffer.st_dev;
    }
  } else {
    LogMan::Msg::EFmt("Couldn't open `/proc`. Is ProcFS mounted? FEX won't be able to track FD conflicts");
  }

  UpdatePID(::getpid());
}

FileManager::~FileManager() {
  close(RootFSFD);
}

size_t FileManager::GetRootFSPrefixLen(const char* pathname, size_t len, bool AliasedOnly) const {
  if (len < 2 ||            // If no pathname or root
      pathname[0] != '/') { // If we are getting root
    return 0;
  }

  const auto& RootFSPath = LDPath();
  if (RootFSPath.empty()) { // If RootFS doesn't exist
    return 0;
  }

  auto RootFSLen = RootFSPath.length();
  if (RootFSPath.ends_with("/")) {
    RootFSLen -= 1;
  }

  if (RootFSLen > len) {
    return 0;
  }

  if (memcmp(pathname, RootFSPath.c_str(), RootFSLen) || (len > RootFSLen && pathname[RootFSLen] != '/')) {
    return 0; // If the path is not within the RootFS
  }

  if (AliasedOnly) {
    fextl::string Path(pathname, len); // Need to nul-terminate so copy

    struct stat HostStat {};
    struct stat RootFSStat {};
    if (lstat(Path.c_str(), &RootFSStat)) {
      LogMan::Msg::DFmt("GetRootFSPrefixLen: lstat on RootFS path failed: {}", std::string_view(pathname, len));
      return 0; // RootFS path does not exist?
    }
    if (lstat(Path.c_str() + RootFSLen, &HostStat)) {
      return 0; // Host path does not exist or not accessible
    }
    // Note: We do not check st_dev, since the RootFS might be
    // an overlayfs mount that changes it. This means there could
    // be false positives. However, since we check the size too,
    // this is highly unlikely (an overlaid file would need to
    // have the same exact size and coincidentally the same
    // inode number as on the host, which is implausible for things
    // like binaries and libraries).
    if (RootFSStat.st_size != HostStat.st_size || RootFSStat.st_ino != HostStat.st_ino || RootFSStat.st_mode != HostStat.st_mode) {
      return 0; // Host path is a different file
    }
  }

  return RootFSLen;
}

ssize_t FileManager::StripRootFSPrefix(char* pathname, ssize_t len, bool leaky) const {
  if (len < 0) {
    return len;
  }

  auto Prefix = GetRootFSPrefixLen(pathname, len, false);
  if (Prefix == 0) {
    return len;
  }

  if (Prefix == len) {
    if (leaky) {
      // Getting the root, without a trailing /. This is a hack pressure-vessel uses to get the FEX RootFS,
      // so we have to leak it here...
      LogMan::Msg::DFmt("Leaking RootFS path for pressure-vessel");
      return len;
    } else {
      ::strcpy(pathname, "/");
      return 1;
    }
  }

  ::memmove(pathname, pathname + Prefix, len - Prefix);
  pathname[len - Prefix] = '\0';

  return len - Prefix;
}

fextl::string FileManager::GetHostPath(fextl::string& Path, bool AliasedOnly) const {
  auto Prefix = GetRootFSPrefixLen(Path.c_str(), Path.length(), AliasedOnly);

  if (Prefix == 0) {
    return {};
  }

  auto ret = Path.substr(Prefix);
  if (ret.empty()) { // Getting the root
    ret = "/";
  }

  return ret;
}

fextl::string FileManager::GetEmulatedPath(const char* pathname, bool FollowSymlink) const {
  if (!pathname ||                  // If no pathname
      pathname[0] != '/' ||         // If relative
      strcmp(pathname, "/") == 0) { // If we are getting root
    return {};
  }

  auto thunkOverlay = ThunkOverlays.find(pathname);
  if (thunkOverlay != ThunkOverlays.end()) {
    return thunkOverlay->second;
  }

  const auto& RootFSPath = LDPath();
  if (RootFSPath.empty()) { // If RootFS doesn't exist
    return {};
  }

  fextl::string Path = RootFSPath + pathname;
  if (FollowSymlink) {
    char Filename[PATH_MAX];
    while (FEX::HLE::IsSymlink(AT_FDCWD, Path.c_str())) {
      auto SymlinkSize = FEX::HLE::GetSymlink(AT_FDCWD, Path.c_str(), Filename, PATH_MAX - 1);
      if (SymlinkSize > 0 && Filename[0] == '/') {
        Path = RootFSPath;
        Path += std::string_view(Filename, SymlinkSize);
      } else {
        break;
      }
    }
  }
  return Path;
}

FileManager::EmulatedFDPathResult
FileManager::GetEmulatedFDPath(int dirfd, const char* pathname, bool FollowSymlink, FDPathTmpData& TmpFilename) const {
  constexpr auto NoEntry = EmulatedFDPathResult {-1, nullptr};

  if (!pathname) {
    // No pathname.
    return NoEntry;
  }

  if (pathname[0] == '/') {
    // If the path is absolute then dirfd is ignored.
    dirfd = AT_FDCWD;
  }

  if (pathname[0] != '/' || // If relative
      pathname[1] == 0 ||   // If we are getting root
      dirfd != AT_FDCWD) {  // If dirfd isn't special FDCWD
    return NoEntry;
  }

  auto thunkOverlay = ThunkOverlays.find(pathname);
  if (thunkOverlay != ThunkOverlays.end()) {
    return EmulatedFDPathResult {AT_FDCWD, thunkOverlay->second.c_str()};
  }

  if (RootFSFD == AT_FDCWD) {
    // If RootFS doesn't exist
    return NoEntry;
  }

  // Starting subpath is the pathname passed in.
  const char* SubPath = pathname;

  // Current index for the temporary path to use.
  uint32_t CurrentIndex {};

  // The two temporary paths.
  const std::array<char*, 2> TmpPaths = {
    TmpFilename[0],
    TmpFilename[1],
  };

  if (FollowSymlink) {
    // Check if the combination of RootFS FD and subpath with the front '/' stripped off is a symlink.
    bool HadAtLeastOne {};
    struct stat Buffer {};
    for (;;) {
      // We need to check if the filepath exists and is a symlink.
      // If the initial filepath doesn't exist then early exit.
      // If it did exist at some state then trace it all all the way to the final link.
      int Result = fstatat(RootFSFD, &SubPath[1], &Buffer, AT_SYMLINK_NOFOLLOW);
      if (Result != 0 && errno == ENOENT && !HadAtLeastOne) {
        // Initial file didn't exist at all
        return NoEntry;
      }

      const bool IsLink = Result == 0 && S_ISLNK(Buffer.st_mode);

      HadAtLeastOne = true;

      if (IsLink) {
        // Choose the current temporary working path.
        auto CurrentTmp = TmpPaths[CurrentIndex];

        // Get the symlink of RootFS FD + stripped subpath.
        auto SymlinkSize = FEX::HLE::GetSymlink(RootFSFD, &SubPath[1], CurrentTmp, PATH_MAX - 1);

        // This might be a /proc symlink into the RootFS, so strip it in that case.
        SymlinkSize = StripRootFSPrefix(CurrentTmp, SymlinkSize, false);

        if (SymlinkSize > 1 && CurrentTmp[0] == '/') {
          // If the symlink is absolute and not the root:
          // 1) Zero terminate it.
          // 2) Set the path as our current subpath.
          // 3) Switch to the next temporary index. (We don't want to overwrite the current one on the next loop iteration).
          // 4) Run the loop again.
          CurrentTmp[SymlinkSize] = 0;
          SubPath = CurrentTmp;
          CurrentIndex ^= 1;
        } else {
          // If the path wasn't a symlink or wasn't absolute.
          // 1) Break early, returning the previous found result.
          // 2) If first iteration then we return `pathname`.
          break;
        }
      } else {
        break;
      }
    }
  }

  // Return the pair of rootfs FD plus relative subpath by stripping off the front '/'
  return EmulatedFDPathResult {RootFSFD, &SubPath[1]};
}

int FileManager::OpenPathInRootFS(const EmulatedFDPathResult& Path, bool FollowSymlink) const {
  // Path.FD == -1 means GetEmulatedFDPath returned NoEntry; nothing to do.
  if (Path.FD == -1) {
    errno = ENOENT;
    return -1;
  }

  // Path.FD == AT_FDCWD means a thunk overlay; just open it from the host
  // namespace (the overlay path is a real host file we control).
  if (Path.FD == AT_FDCWD) {
    int OpenFlags = O_PATH | O_CLOEXEC;
    if (!FollowSymlink) {
      OpenFlags |= O_NOFOLLOW;
    }
    return ::open(Path.Path, OpenFlags);
  }

  // For everything else we have a rootfs-relative path and we want the
  // kernel to perform the entire walk (including any symlinks it
  // encounters) scoped to the rootfs FD. RESOLVE_IN_ROOT does exactly
  // that, including reinterpreting absolute symlinks as if dirfd were /.
  FEX::HLE::open_how how = {
    .flags = static_cast<uint64_t>(O_PATH | O_CLOEXEC | (FollowSymlink ? 0 : O_NOFOLLOW)),
    .mode = 0,
    .resolve = RESOLVE_IN_ROOT,
  };

  // EAGAIN is not a failure: openat2(2) documents that RESOLVE_IN_ROOT may
  // return it when the kernel spots a concurrent rename or mount that could
  // break the scoping guarantee, and expects the caller to retry. Bounded so a
  // pathological rename storm can't spin here forever; callers treat the
  // eventual -1/EAGAIN as a semantic error, which is the honest answer.
  int fd = -1;
  for (int Attempt = 0; Attempt < 16; ++Attempt) {
    fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
    if (fd != -1 || errno != EAGAIN) {
      break;
    }
  }

  if (fd != -1) {
    return fd;
  }

  const int SavedErrno = errno;

  // EXDEV: a magic /proc symlink (or similar) crossed the rootfs boundary.
  // ENOSYS: no openat2(2) at all (pre-5.6 kernel), so RESOLVE_IN_ROOT scoping
  // is simply unavailable rather than the path being unreachable.
  // In both cases fall back to a plain openat() so callers can still see the
  // file; we accept the (small) risk of a host leak in those narrow cases,
  // matching the existing Openat() fallback policy. Every other errno is a
  // real answer about the path and is returned as-is — degrading those to a
  // host lookup is precisely the containment breach this function exists to
  // prevent.
  if (SavedErrno == EXDEV || SavedErrno == ENOSYS) {
    int OpenFlags = O_PATH | O_CLOEXEC | (FollowSymlink ? 0 : O_NOFOLLOW);
    int Fallback = ::syscall(SYSCALL_DEF(openat), Path.FD, Path.Path, OpenFlags);
    if (Fallback == -1 && errno == ENOSYS) {
      // Shouldn't happen (openat predates every kernel we support), but don't
      // report a missing syscall as a missing file.
      errno = SavedErrno;
    }
    return Fallback;
  }

  errno = SavedErrno;
  return -1;
}

///< Returns true if the pathname is self and symlink flags are set NOFOLLOW.
bool FileManager::IsSelfNoFollow(const char* Pathname, int flags) const {
  const bool Follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
  if (Follow) {
    // If we are following the self symlink then we don't care about this.
    return false;
  }

  if (!Pathname) {
    return false;
  }

  char PidSelfPath[50];
  snprintf(PidSelfPath, sizeof(PidSelfPath), "/proc/%i/exe", CurrentPID);

  return strcmp(Pathname, "/proc/self/exe") == 0 || strcmp(Pathname, "/proc/thread-self/exe") == 0 || strcmp(Pathname, PidSelfPath) == 0;
}

std::optional<std::string_view> FileManager::GetSelf(const char* Pathname) const {
  if (!Pathname) {
    return std::nullopt;
  }

  char PidSelfPath[50];
  snprintf(PidSelfPath, sizeof(PidSelfPath), "/proc/%i/exe", CurrentPID);

  if (strcmp(Pathname, "/proc/self/exe") == 0 || strcmp(Pathname, "/proc/thread-self/exe") == 0 || strcmp(Pathname, PidSelfPath) == 0) {
    return Filename();
  }

  return Pathname;
}

// O_TMPFILE is a *composite*: __O_TMPFILE | O_DIRECTORY. A bare `flags &
// O_TMPFILE` is therefore true for any ordinary O_DIRECTORY open, so it must
// be tested for containment.
static bool IsTmpFile(uint64_t flags) {
  return (flags & O_TMPFILE) == O_TMPFILE;
}

// Normalize guest open flags before handing them to openat2().
//
// The guest called open()/openat(), which are lenient: the kernel ignores the
// access mode and most other bits when O_PATH is set, and ignores `mode`
// entirely unless the open actually creates something. openat2() is strict and
// answers EINVAL instead. Since FEX upgrades overlay probes to openat2() to get
// RESOLVE_IN_ROOT scoping, it has to apply the leniency the guest was promised,
// or legal guest opens fail with an errno they can never see natively.
//
// Seen live: libcapsule's capture-libs (Steam pressure-vessel) opens directories
// with O_RDWR|O_DIRECTORY|O_CLOEXEC|O_PATH; the unmasked O_RDWR made openat2()
// return EINVAL, which aborted container setup (2026-07-30).
static uint64_t SanitizeOpenat2Flags(uint64_t flags) {
  if (flags & O_PATH) {
    // Under O_PATH only these bits are meaningful; the rest are ignored by
    // open() but rejected by openat2().
    flags &= (O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  }
  return flags;
}

// openat2() requires mode == 0 unless the open can create a file.
static uint64_t Openat2Mode(uint64_t flags, uint32_t mode) {
  const bool Creates = (flags & O_CREAT) || IsTmpFile(flags);
  return Creates ? (mode & 07777) : 0;
}

static bool ShouldSkipOpenInEmu(int flags) {
  if (flags & O_CREAT) {
    // If trying to create a file then skip checking in emufd
    return true;
  }

  if (flags & O_WRONLY) {
    // If the file is trying to be open with write permissions then skip.
    return true;
  }

  if (flags & O_APPEND) {
    // If the file is trying to be open with append options then skip.
    return true;
  }

  return false;
}

bool FileManager::ReplaceEmuFd(int fd, int flags, uint32_t mode) {
  char Tmp[PATH_MAX + 1];

  if (fd < 0) {
    return false;
  }

  // Get the path of the file we just opened
  auto PathLength = FEX::get_fdpath(fd, Tmp);
  if (PathLength == -1) {
    return false;
  }
  Tmp[PathLength] = '\0';

  // And try to open via EmuFD
  auto EmuFd = EmuFD.Open(Tmp, flags, mode);
  if (EmuFd == -1) {
    return false;
  }

  // If we succeeded, swap out the fd
  ::dup2(EmuFd, fd);
  ::close(EmuFd);
  return true;
}

uint64_t FileManager::Open(const char* pathname, int flags, uint32_t mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;
  int fd = -1;
  bool OverlayAttempted = false;

  // Always try rootfs overlay first regardless of write flags. Previously
  // gating on ShouldSkipOpenInEmu (intended only for EmuFD mocks) made
  // writeable opens bypass to host /tmp while readable opens went to
  // <rootfs>/tmp, producing split-state files. open()/creat() both flow
  // through here, so the split caused creat_test.CreatTruncatesExistingFile
  // and the *at() ENOENT cluster.
  {
    FDPathTmpData TmpFilename;
    auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, false, TmpFilename);
    if (Path.FD != -1) {
      OverlayAttempted = true;
      // Never CREATE new files inside the rootfs overlay: probe with O_CREAT
      // (and O_EXCL) masked so existing rootfs files still open in place, and
      // let genuinely-new files fall through to the host create below. The
      // overlay only virtualizes what exists; syscalls that bypass it (mount,
      // rename across trees) see the real namespace — bwrap creates its
      // bind-mount source files at / and then mount()s them, which returned
      // ENOENT when the creation had been diverted into <rootfs>/.
      const bool WantsCreate = (flags & O_CREAT) && !IsTmpFile((uint64_t)flags);
      uint64_t ProbeFlags = SanitizeOpenat2Flags((uint64_t)flags);
      if (WantsCreate) {
        ProbeFlags &= ~(uint64_t)(O_CREAT | O_EXCL);
      }
      FEX::HLE::open_how how = {
        .flags = ProbeFlags,
        .mode = Openat2Mode(ProbeFlags, mode),
        .resolve = (Path.FD == AT_FDCWD) ? 0u : RESOLVE_IN_ROOT,
      };
      fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
      if (fd == -1 && (errno == EXDEV || errno == EINVAL)) {
        // EXDEV: magic symlink (/proc/foo) crossed the rootfs boundary.
        // EINVAL: openat2() rejected a flag combination that open() accepts.
        // Both punt to the lenient syscall the guest actually called, which
        // gives up RESOLVE_IN_ROOT scoping but keeps the overlay dirfd.
        fd = ::syscall(SYSCALL_DEF(openat), Path.FD, Path.Path, (int)ProbeFlags, mode);
      }
      if (fd != -1 && WantsCreate && (flags & O_EXCL)) {
        // O_CREAT|O_EXCL on a file that already exists in the rootfs.
        ::close(fd);
        errno = EEXIST;
        fd = -1;
        return -1;
      }
    }
  }

  // Fall back when overlay was never attempted (NoEntry) or the path was
  // genuinely absent (ENOENT). Other errnos must propagate.
  if (fd == -1 && (!OverlayAttempted || errno == ENOENT)) {
    fd = ::open(SelfPath, flags, mode);
  }

  // Host create returned ENOENT because the parent only exists in the rootfs
  // (Factorio's /opt/factorio/.lock, apt's /var/cache/apt/*). Mirror the
  // chdir host-first/rootfs-on-ENOENT pattern from 6c79ed559: fall back to
  // creating inside the rootfs when the host tree has no such parent.
  // f674ed515's motivating cases (bwrap writing bind-mount source files at /
  // that mount() then reads through the real namespace) resolve on the host
  // first and never reach this branch, so containment holds.
  if (fd == -1 && errno == ENOENT && (flags & O_CREAT) && !IsTmpFile((uint64_t)flags)) {
    FDPathTmpData TmpFilename;
    auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, false, TmpFilename);
    if (Path.FD != -1) {
      FEX::HLE::open_how how = {
        .flags = (uint64_t)flags,
        .mode = mode & 07777,
        .resolve = (Path.FD == AT_FDCWD) ? 0u : RESOLVE_IN_ROOT,
      };
      fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
      if (fd == -1 && errno == EXDEV) {
        fd = ::syscall(SYSCALL_DEF(openat), Path.FD, Path.Path, flags, mode);
      }
    }
  }

  // EmuFD overlay (read-only mocks of /proc/cpuinfo etc.) only applies to
  // non-write opens; this is the original ShouldSkipOpenInEmu intent.
  if (!ShouldSkipOpenInEmu(flags)) {
    ReplaceEmuFd(fd, flags, mode);
  }

  return fd;
}

uint64_t FileManager::Close(int fd) {
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  if (CheckIfFDInTrackedSet(fd)) {
    LogMan::Msg::EFmt("{} closing FEX FD {}", __func__, fd);
    RemoveFEXFD(fd);
  }
#endif

  return ::close(fd);
}

uint64_t FileManager::CloseRange(unsigned int first, unsigned int last, unsigned int flags) {
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
  if (!(flags & CLOSE_RANGE_CLOEXEC) && CheckIfFDRangeInTrackedSet(first, last)) {
    LogMan::Msg::EFmt("{} closing FEX FDs in range ({}, {})", __func__, first, last);
    RemoveFEXFDRange(first, last);
  }
#endif

  return ::syscall(SYSCALL_DEF(close_range), first, last, flags);
}

uint64_t FileManager::Stat(const char* pathname, void* buf) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // Stat follows symlinks
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, true, TmpFilename);
  if (Path.FD != -1) {
    int RootScopedFD = OpenPathInRootFS(Path, true);
    if (RootScopedFD != -1) {
      uint64_t Result = ::fstatat(RootScopedFD, "", reinterpret_cast<struct stat*>(buf), AT_EMPTY_PATH);
      int SavedErrno = errno;
      ::close(RootScopedFD);
      // Propagate semantic errors as-is; only fall back if the file is
      // genuinely missing from rootfs (ENOENT).
      if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
        errno = SavedErrno;
        return Result;
      }
    } else if (errno != ENOENT) {
      // OpenPathInRootFS itself failed with a non-ENOENT semantic result
      // (e.g. EACCES when parent perms forbid search). Propagate.
      return -1;
    }
  }
  return ::stat(SelfPath, reinterpret_cast<struct stat*>(buf));
}

uint64_t FileManager::Lstat(const char* pathname, void* buf) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // lstat does not follow symlinks
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, false, TmpFilename);
  if (Path.FD != -1) {
    int RootScopedFD = OpenPathInRootFS(Path, false);
    if (RootScopedFD != -1) {
      uint64_t Result = ::fstatat(RootScopedFD, "", reinterpret_cast<struct stat*>(buf), AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
      int SavedErrno = errno;
      ::close(RootScopedFD);
      if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
        errno = SavedErrno;
        return Result;
      }
    } else if (errno != ENOENT) {
      return -1;
    }
  }

  return ::lstat(pathname, reinterpret_cast<struct stat*>(buf));
}

uint64_t FileManager::Access(const char* pathname, [[maybe_unused]] int mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // Access follows symlinks
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, true, TmpFilename);
  int RootScopedFD = OpenPathInRootFS(Path, true);
  if (RootScopedFD != -1) {
    // Use faccessat2 so we can pass AT_EMPTY_PATH on the pre-resolved fd.
    uint64_t Result = ::syscall(SYSCALL_DEF(faccessat2), RootScopedFD, "", mode, AT_EMPTY_PATH);
    int SavedErrno = errno;
    ::close(RootScopedFD);
    // Propagate semantic errors as-is; only fall back if the file is
    // genuinely missing from rootfs (ENOENT). An EACCES answered out of the
    // rootfs is the correct answer about the file the guest can see; asking
    // the host path instead answers out of host permissions, or worse out of
    // a different file that happens to live at the same host path.
    if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
      errno = SavedErrno;
      return Result;
    }
  } else if (errno != ENOENT) {
    // OpenPathInRootFS itself failed with a non-ENOENT semantic result
    // (e.g. EACCES when parent perms forbid search). Propagate.
    return -1;
  }
  return ::access(SelfPath, mode);
}

uint64_t FileManager::FAccessat(int dirfd, const char* pathname, int mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, true, TmpFilename);
  int RootScopedFD = OpenPathInRootFS(Path, true);
  if (RootScopedFD != -1) {
    // faccessat takes no flags; emulate via faccessat2 + AT_EMPTY_PATH on the
    // pre-resolved fd to ensure the rootfs scoping isn't undone.
    uint64_t Result = ::syscall(SYSCALL_DEF(faccessat2), RootScopedFD, "", mode, AT_EMPTY_PATH);
    int SavedErrno = errno;
    ::close(RootScopedFD);
    // See FM.Access: only a genuinely absent rootfs entry justifies re-asking
    // the host.
    if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
      errno = SavedErrno;
      return Result;
    }
  } else if (errno != ENOENT) {
    return -1;
  }

  return ::syscall(SYS_faccessat, dirfd, SelfPath, mode);
}

uint64_t FileManager::FAccessat2(int dirfd, const char* pathname, int mode, int flags) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  int RootScopedFD = OpenPathInRootFS(Path, (flags & AT_SYMLINK_NOFOLLOW) == 0);
  if (RootScopedFD != -1) {
    uint64_t Result = ::syscall(SYSCALL_DEF(faccessat2), RootScopedFD, "", mode, flags | AT_EMPTY_PATH);
    int SavedErrno = errno;
    ::close(RootScopedFD);
    // See FM.Access: only a genuinely absent rootfs entry justifies re-asking
    // the host.
    if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
      errno = SavedErrno;
      return Result;
    }
  } else if (errno != ENOENT) {
    return -1;
  }

  return ::syscall(SYSCALL_DEF(faccessat2), dirfd, SelfPath, mode, flags);
}

uint64_t FileManager::Readlink(const char* pathname, char* buf, size_t bufsiz) {
  // calculate the non-self link to exe
  // Some executables do getpid, stat("/proc/$pid/exe")
  char PidSelfPath[50];
  snprintf(PidSelfPath, 50, "/proc/%i/exe", CurrentPID);

  if (strcmp(pathname, "/proc/self/exe") == 0 || strcmp(pathname, "/proc/thread-self/exe") == 0 || strcmp(pathname, PidSelfPath) == 0) {
    const auto& App = Filename();
    strncpy(buf, App.c_str(), bufsiz);
    return std::min(bufsiz, App.size());
  }

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, pathname, false, TmpFilename);
  uint64_t Result = -1;
  int RootScopedFD = OpenPathInRootFS(Path, false);
  if (RootScopedFD != -1) {
    Result = ::readlinkat(RootScopedFD, "", buf, bufsiz);
    int SavedErrno = errno;
    ::close(RootScopedFD);

    if (Result == static_cast<uint64_t>(-1)) {
      // The fd resolved, so the file does exist in the RootFS and this is a
      // semantic result about it. Propagate it as-is; retrying against the
      // host path would answer out of host permissions instead (a guest
      // /root/... lookup came back EACCES from the host's mode-700 /root).
      //
      // One translation is needed: readlinkat(2) with an empty pathname
      // reports "not a symlink" as ENOENT rather than the EINVAL that
      // readlink(2) gives for a named non-symlink (fs/stat.c do_readlinkat:
      // `error = empty ? -ENOENT : -EINVAL`). Both mean the same thing here,
      // and the guest must see EINVAL because realpath(3) reads EINVAL as
      // "this component is not a symlink, keep walking" while any other
      // errno is a hard failure.
      errno = (SavedErrno == ENOENT) ? EINVAL : SavedErrno;
      return -1;
    }
  } else if (errno != ENOENT) {
    // OpenPathInRootFS itself failed with a non-ENOENT semantic result
    // (e.g. EACCES when parent perms forbid search). Propagate.
    return -1;
  }

  // Still -1 only when the RootFS lookup found nothing (or there was no RootFS
  // translation at all, which OpenPathInRootFS also reports as ENOENT). Fall
  // back to the host path so genuinely host-resident paths the guest can
  // legitimately reach still work.
  if (Result == static_cast<uint64_t>(-1)) {
    Result = ::readlink(pathname, buf, bufsiz);
  }

  // We might have read a /proc/self/fd/* link. If so, strip the RootFS prefix from it.
  return StripRootFSPrefix(buf, Result, true);
}

uint64_t FileManager::Chmod(const char* pathname, mode_t mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // chmod() follows symlinks per POSIX; pre-resolve scoped to rootfs.
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, true, TmpFilename);
  int RootScopedFD = OpenPathInRootFS(Path, true);
  if (RootScopedFD != -1) {
    // fchmodat with AT_EMPTY_PATH operates on the fd directly.
    char ProcSelfFd[64];
    snprintf(ProcSelfFd, sizeof(ProcSelfFd), "/proc/self/fd/%d", RootScopedFD);
    uint64_t Result = ::chmod(ProcSelfFd, mode);
    int SavedErrno = errno;
    ::close(RootScopedFD);
    // Propagate semantic errors (EPERM on a file we don't own, EROFS, ...)
    // as-is; only fall back when nothing was there to chmod. Note ENOENT here
    // also covers /proc not being mounted, in which case the host path is
    // genuinely the only way to service the call.
    if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
      errno = SavedErrno;
      return Result;
    }
  } else if (errno != ENOENT) {
    // OpenPathInRootFS itself failed with a non-ENOENT semantic result. Propagate.
    return -1;
  }
  return ::chmod(SelfPath, mode);
}

uint64_t FileManager::Readlinkat(int dirfd, const char* pathname, char* buf, size_t bufsiz) {
  // calculate the non-self link to exe
  // Some executables do getpid, stat("/proc/$pid/exe")
  // Can't use `GetSelf` directly here since readlink{at,} returns EINVAL if it isn't a symlink
  // Self is always a symlink and isn't expected to fail

  fextl::string Path {};
  if (((pathname && pathname[0] != '/') || // If pathname exists then it must not be absolute
       !pathname) &&
      dirfd != AT_FDCWD) {
    // Passed in a dirfd that isn't magic FDCWD
    // We need to get the path from the fd now
    char Tmp[PATH_MAX] = "";
    auto PathLength = FEX::get_fdpath(dirfd, Tmp);
    if (PathLength != -1) {
      Path = fextl::string(Tmp, PathLength);
    }

    if (pathname) {
      if (!Path.empty()) {
        // If the path returned empty then we don't need a separator
        Path += "/";
      }
      Path += pathname;
    }
  } else {
    if (!pathname || strlen(pathname) == 0) {
      return -1;
    } else if (pathname) {
      Path = pathname;
    }
  }

  char PidSelfPath[50];
  snprintf(PidSelfPath, 50, "/proc/%i/exe", CurrentPID);

  if (Path == "/proc/self/exe" || Path == "/proc/thread-self/exe" || Path == PidSelfPath) {
    const auto& App = Filename();
    strncpy(buf, App.c_str(), bufsiz);
    return std::min(bufsiz, App.size());
  }

  FDPathTmpData TmpFilename;
  auto NewPath = GetEmulatedFDPath(dirfd, pathname, false, TmpFilename);
  uint64_t Result = -1;

  int RootScopedFD = OpenPathInRootFS(NewPath, false);
  if (RootScopedFD != -1) {
    Result = ::readlinkat(RootScopedFD, "", buf, bufsiz);
    int SavedErrno = errno;
    ::close(RootScopedFD);

    if (Result == static_cast<uint64_t>(-1)) {
      // See FM.Readlink: the fd resolved, so this is a semantic result about a
      // file that does exist in the RootFS and must be propagated rather than
      // re-asked of the host path. ENOENT out of an empty-pathname
      // readlinkat(2) is the kernel's "not a symlink" and has to reach the
      // guest as EINVAL.
      errno = (SavedErrno == ENOENT) ? EINVAL : SavedErrno;
      return -1;
    }
  } else if (errno != ENOENT) {
    // OpenPathInRootFS itself failed with a non-ENOENT semantic result. Propagate.
    return -1;
  }

  // Still -1 only when the RootFS lookup found nothing, so the caller's
  // literal dirfd/pathname is the remaining candidate.
  if (Result == static_cast<uint64_t>(-1)) {
    Result = ::readlinkat(dirfd, pathname, buf, bufsiz);
  }

  // We might have read a /proc/self/fd/* link. If so, strip the RootFS prefix from it.
  return StripRootFSPrefix(buf, Result, true);
}

uint64_t FileManager::Openat([[maybe_unused]] int dirfs, const char* pathname, int flags, uint32_t mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  int32_t fd = -1;
  bool OverlayAttempted = false;

  // Always try rootfs overlay first, regardless of O_CREAT/O_WRONLY/O_APPEND.
  // Previously the rootfs attempt was gated on ShouldSkipOpenInEmu (intended
  // only for the EmuFD lookup), which produced split state: write/create
  // opens went bare-syscall to host /tmp while read/O_PATH opens went via
  // openat2(RESOLVE_IN_ROOT) to <rootfs>/tmp. Subsequent *at() calls then
  // saw dirfd in rootfs but target in host, returning ENOENT (observed in
  // gvisor chmod_test/chown_test/unlink_test FchmodatFile etc.).
  {
    FDPathTmpData TmpFilename;
    auto Path = GetEmulatedFDPath(dirfs, SelfPath, false, TmpFilename);
    if (Path.FD != -1) {
      OverlayAttempted = true;
      uint64_t How_flags = SanitizeOpenat2Flags((uint64_t)flags);
      // Never CREATE new files inside the rootfs overlay (see Open() above):
      // probe with O_CREAT/O_EXCL masked; a genuine ENOENT falls through to
      // the host create in the fallback below.
      const bool WantsCreate = (How_flags & O_CREAT) && !IsTmpFile(How_flags);
      if (WantsCreate) {
        How_flags &= ~(uint64_t)(O_CREAT | O_EXCL);
      }
      FEX::HLE::open_how how = {
        .flags = How_flags,
        .mode = Openat2Mode(How_flags, mode),
        .resolve = (Path.FD == AT_FDCWD) ? 0u : RESOLVE_IN_ROOT,
      };
      fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
      if (fd == -1 && (errno == EXDEV || errno == EINVAL)) {
        // See Open(): EXDEV is a magic symlink, EINVAL an openat2()-only flag
        // rejection. Both fall back to the lenient syscall the guest called.
        fd = ::syscall(SYSCALL_DEF(openat), Path.FD, Path.Path, (int)How_flags, mode);
      }
      if (fd != -1 && WantsCreate && (flags & O_EXCL)) {
        // O_CREAT|O_EXCL on a file that already exists in the rootfs.
        ::close(fd);
        errno = EEXIST;
        return -1;
      }
    }
  }

  // Fall back to bare host openat when:
  //   - Overlay was not attempted (GetEmulatedFDPath returned NoEntry; e.g.
  //     real dirfd, no RootFS, or relative path). In this case errno is stale
  //     from prior calls, so we must NOT inspect it.
  //   - Overlay was attempted but the path was genuinely absent in rootfs
  //     (ENOENT). Semantic errors (EACCES, EPERM, ENOTDIR, EISDIR, EEXIST,
  //     etc.) must propagate as-is — falling back on any -1 silently turned
  //     EACCES into ENOENT and broke gvisor chmod_test/write_test.
  if (fd == -1 && (!OverlayAttempted || errno == ENOENT)) {
    fd = ::syscall(SYSCALL_DEF(openat), dirfs, SelfPath, flags, mode);
  }

  // Host create returned ENOENT because the parent only exists in the rootfs
  // (Factorio's /opt/factorio/.lock, apt's /var/cache/apt/*). Same host-first/
  // rootfs-on-ENOENT pattern as FM.Open above (mirroring chdir 6c79ed559).
  if (fd == -1 && errno == ENOENT && (flags & O_CREAT) && !IsTmpFile((uint64_t)flags)) {
    FDPathTmpData TmpFilename;
    auto Path = GetEmulatedFDPath(dirfs, SelfPath, false, TmpFilename);
    if (Path.FD != -1) {
      uint64_t How_flags = (uint64_t)flags;
      if (How_flags & O_PATH) {
        How_flags &= (O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
      }
      FEX::HLE::open_how how = {
        .flags = How_flags,
        .mode = mode & 07777,
        .resolve = (Path.FD == AT_FDCWD) ? 0u : RESOLVE_IN_ROOT,
      };
      fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
      if (fd == -1 && errno == EXDEV) {
        fd = ::syscall(SYSCALL_DEF(openat), Path.FD, Path.Path, (int)How_flags, mode);
      }
    }
  }

  // EmuFD overlay (read-only mocks of /proc/cpuinfo etc.) only applies for
  // non-write opens. This is the original ShouldSkipOpenInEmu intent.
  if (!ShouldSkipOpenInEmu(flags)) {
    ReplaceEmuFd(fd, flags, mode);
  }

  return fd;
}

uint64_t FileManager::Openat2(int dirfs, const char* pathname, FEX::HLE::open_how* how, size_t usize) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  int32_t fd = -1;
  bool OverlayAttempted = false;

  if (!ShouldSkipOpenInEmu(how->flags)) {
    FDPathTmpData TmpFilename;
    auto Path = GetEmulatedFDPath(dirfs, SelfPath, false, TmpFilename);
    if (Path.FD != -1 && !(how->resolve & RESOLVE_IN_ROOT)) {
      OverlayAttempted = true;
      // AT_FDCWD means it's a thunk and not via RootFS
      if (Path.FD != AT_FDCWD) {
        how->resolve |= RESOLVE_IN_ROOT;
      }
      fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, how, usize);
      how->resolve &= ~RESOLVE_IN_ROOT;
      if (fd == -1 && errno == EXDEV) {
        // This means a magic symlink (/proc/foo) was involved. In this case we
        // just punt and do the access without RESOLVE_IN_ROOT.
        fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, how, usize);
      }
    }

    // Same policy as FM.Openat: fall back to the caller's literal dirfd/path
    // only when the overlay was never attempted (errno is stale then, so it
    // must not be inspected) or the path was genuinely absent from rootfs.
    // Other errnos are semantic results about a RootFS-resident file and must
    // not be re-answered against the host filesystem.
    if (fd == -1 && (!OverlayAttempted || errno == ENOENT)) {
      fd = ::syscall(SYSCALL_DEF(openat2), dirfs, SelfPath, how, usize);
    }

    ReplaceEmuFd(fd, how->flags, how->mode);
  } else {
    fd = ::syscall(SYSCALL_DEF(openat2), dirfs, SelfPath, how, usize);
  }

  return fd;
}

uint64_t FileManager::Statx(int dirfd, const char* pathname, int flags, uint32_t mask, struct statx* statxbuf) {
  if (IsSelfNoFollow(pathname, flags)) {
    // If we aren't following the symlink for self then we need to return data about the symlink itself.
    // Let's just /actually/ return FEX symlink information in this case.
    return FHU::Syscalls::statx(dirfd, pathname, flags, mask, statxbuf);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    int RootScopedFD = OpenPathInRootFS(Path, (flags & AT_SYMLINK_NOFOLLOW) == 0);
    if (RootScopedFD != -1) {
      uint64_t Result = FHU::Syscalls::statx(RootScopedFD, "", flags | AT_EMPTY_PATH, mask, statxbuf);
      int SavedErrno = errno;
      ::close(RootScopedFD);
      if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
        errno = SavedErrno;
        return Result;
      }
    } else if (errno != ENOENT) {
      return -1;
    }
  }
  return FHU::Syscalls::statx(dirfd, SelfPath, flags, mask, statxbuf);
}

uint64_t FileManager::Mknod(const char* pathname, mode_t mode, dev_t dev) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // Node creation belongs to the real filesystem — never create inside the
  // rootfs overlay (see Mkdirat()). Overlay consulted for EEXIST only.
  // Host-first / rootfs-on-ENOENT: if the host tree has no such parent
  // (path only exists in rootfs) fall back to rootfs creation.
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, false, TmpFilename);
  if (Path.FD != -1 && ::faccessat(Path.FD, Path.Path, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
    errno = EEXIST;
    return -1;
  }
  uint64_t Result = ::mknod(SelfPath, mode, dev);
  if (Result == -1 && errno == ENOENT && Path.FD != -1) {
    Result = ::mknodat(Path.FD, Path.Path, mode, dev);
  }
  return Result;
}

// ---------------------------------------------------------------------------
// Overlay-aware path-mutating syscalls.
//
// Pattern: try the rootfs overlay first via the *at() form against
// GetEmulatedFDPath()s (RootFSFD, relative) tuple. On overlay-miss
// (Path.FD == -1, i.e. relative path or dirfd-relative call), fall through
// to the bare host syscall — the kernel resolves the path from the supplied
// dirfd (which is itself overlay-aware, having been produced by FM::Open*).
// On overlay-attempt-fail with the rootfs path, fall back to the bare host
// syscall too, so we degrade to host-FS behaviour rather than hard-erroring.
// ---------------------------------------------------------------------------

uint64_t FileManager::Fchmodat(int dirfd, const char* pathname, mode_t mode, int flags) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = ::syscall(SYSCALL_DEF(fchmodat), Path.FD, Path.Path, mode, flags);
    // Only fall back when the path was genuinely absent from rootfs.
    // EACCES/EPERM/EISDIR/EEXIST/etc. are semantic results that must
    // propagate to the guest as-is.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::syscall(SYSCALL_DEF(fchmodat), dirfd, SelfPath, mode, flags);
}

uint64_t FileManager::Fchmodat2(int dirfd, const char* pathname, mode_t mode, unsigned int flags) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = ::syscall(SYS_fchmodat2, Path.FD, Path.Path, mode, flags);
    // Same policy as FM.Fchmodat: only fall back when the path was genuinely
    // absent from rootfs.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::syscall(SYS_fchmodat2, dirfd, SelfPath, mode, flags);
}

uint64_t FileManager::Fchownat(int dirfd, const char* pathname, uid_t owner, gid_t group, int flags) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = ::syscall(SYSCALL_DEF(fchownat), Path.FD, Path.Path, owner, group, flags);
    // Only fall back when the path was genuinely absent from rootfs.
    // EACCES/EPERM/EISDIR/EEXIST/etc. are semantic results that must
    // propagate to the guest as-is.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::syscall(SYSCALL_DEF(fchownat), dirfd, SelfPath, owner, group, flags);
}

uint64_t FileManager::Unlinkat(int dirfd, const char* pathname, int flags) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  // unlink/rmdir never follow the final symlink — the symlink itself is removed.
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, false, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = ::syscall(SYSCALL_DEF(unlinkat), Path.FD, Path.Path, flags);
    // Only fall back when the path was genuinely absent from rootfs.
    // EACCES/EPERM/EISDIR/EEXIST/etc. are semantic results that must
    // propagate to the guest as-is.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::syscall(SYSCALL_DEF(unlinkat), dirfd, SelfPath, flags);
}

uint64_t FileManager::Utimensat(int dirfd, const char* pathname, const struct timespec* times, int flags) {
  // utimensat was the ONLY path-taking syscall still registered as a raw
  // passthrough (Syscalls/Passthrough.cpp), so the RootFS translation never ran
  // and the guest path went straight to the host kernel.
  //
  // Measured consequence: `apt update` emitted 36 instances of
  // "Failed to set modification time - utimes (2: No such file or directory)".
  // apt downloads an index into /var/lib/apt/lists/partial/, then stamps its
  // mtime; the stamp hit the *host* filesystem where that path does not exist,
  // returned ENOENT, and apt treated every download as failed — re-fetching,
  // retrying, and eventually timing out. The downloads themselves were fine.
  //
  // A NULL pathname is legal here and means "operate on dirfd itself", which is
  // how futimens() is implemented. There is nothing to translate in that case,
  // so pass it straight through.
  if (!pathname) {
    return ::syscall(SYSCALL_DEF(utimensat), dirfd, nullptr, times, flags);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  // AT_SYMLINK_NOFOLLOW means stamp the link itself rather than its target.
  const bool FollowSymlink = (flags & AT_SYMLINK_NOFOLLOW) == 0;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, FollowSymlink, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = ::syscall(SYSCALL_DEF(utimensat), Path.FD, Path.Path, times, flags);
    // Only fall back when the path was genuinely absent from rootfs.
    // EACCES/EPERM/EROFS/etc. are semantic results that must propagate to the
    // guest as-is.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::syscall(SYSCALL_DEF(utimensat), dirfd, SelfPath, times, flags);
}

uint64_t FileManager::Mkdirat(int dirfd, const char* pathname, mode_t mode) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // Directory creation belongs to the real filesystem — never create inside
  // the rootfs overlay (see Openat()). Repeated guest runs were growing a
  // /home/<user> skeleton inside the rootfs, which pressure-vessel then
  // bind-mounted over the container's real /home, hiding the Steam install.
  // The overlay is still consulted for EEXIST fidelity: a directory that
  // exists only in the rootfs must not be shadow-created on the host.
  // Host-first / rootfs-on-ENOENT: if the host has no such parent (path
  // only exists in rootfs) fall back to rootfs creation.
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, false, TmpFilename);
  if (Path.FD != -1 && ::faccessat(Path.FD, Path.Path, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
    errno = EEXIST;
    return -1;
  }
  uint64_t Result = ::syscall(SYSCALL_DEF(mkdirat), dirfd, SelfPath, mode);
  if (Result == -1 && errno == ENOENT && Path.FD != -1) {
    Result = ::syscall(SYSCALL_DEF(mkdirat), Path.FD, Path.Path, mode);
  }
  return Result;
}

uint64_t FileManager::Linkat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags) {
  auto OldNewPath = GetSelf(oldpath);
  const char* OldSelfPath = OldNewPath ? OldNewPath->data() : nullptr;
  auto NewNewPath = GetSelf(newpath);
  const char* NewSelfPath = NewNewPath ? NewNewPath->data() : nullptr;

  FDPathTmpData OldTmp, NewTmp;
  auto OldPath = GetEmulatedFDPath(olddirfd, OldSelfPath, (flags & AT_SYMLINK_FOLLOW) != 0, OldTmp);
  auto NewPath = GetEmulatedFDPath(newdirfd, NewSelfPath, false, NewTmp);

  // Resolve each leg independently so a rootfs-only source and a host-only
  // destination (or vice versa) both land at the tree that actually holds
  // them. Previous logic picked one tree per call and applied it to both
  // legs, which broke apt's dpkg staging: `.deb` at
  // /var/cache/apt/archives/* is rootfs-only, /tmp/apt-dpkg-install-*/ is
  // host-only (my f168b3101 puts mkdirs there because host /tmp exists).
  // Old:  (rootfs_src, rootfs_dst) then (host_src, host_dst) -- both
  //       trees miss the mixed case, so link() returned ENOENT.
  // New:  each leg keeps its host effect if the host path exists (source
  //       leg) or the host parent exists (destination leg), else falls
  //       back to rootfs. If the resolved combination crosses filesystem
  //       boundaries, the kernel returns EXDEV and apt/dpkg copies. That
  //       is the intended semantic per POSIX; the EXDEV path is well-
  //       exercised by every apt install.
  int eff_olddirfd = olddirfd;
  const char* eff_oldpath = OldSelfPath;
  if (OldPath.FD != -1 && OldSelfPath && ::faccessat(AT_FDCWD, OldSelfPath, F_OK, 0) != 0) {
    // Host doesn't have the source; use rootfs.
    eff_olddirfd = OldPath.FD;
    eff_oldpath = OldPath.Path;
  }

  int eff_newdirfd = newdirfd;
  const char* eff_newpath = NewSelfPath;
  // Destination: use host first (host-create discipline from f168b3101).
  // If the host attempt returns ENOENT below, retry against the rootfs.

  uint64_t Result = ::syscall(SYSCALL_DEF(linkat), eff_olddirfd, eff_oldpath, eff_newdirfd, eff_newpath, flags);
  if (Result == -1 && errno == ENOENT && NewPath.FD != -1) {
    Result = ::syscall(SYSCALL_DEF(linkat), eff_olddirfd, eff_oldpath, NewPath.FD, NewPath.Path, flags);
  }

  // Cross-filesystem link → EXDEV. Every real Linux system produces the same
  // errno for this case, but apt-get's dpkg-install staging (verified against
  // rootfs-source /var/cache/apt/archives + host-tmpfs /tmp) does NOT fall
  // back to copy on EXDEV -- dpkg later dies with "cannot stat pathname"
  // because the file never got staged. The overlay is what turned this from
  // an unusual-in-practice scenario into the common case. Satisfy the
  // caller's "file appears at destination" intent by copying when the link
  // legitimately can't cross the boundary. Callers that depend on
  // shared-inode semantics (dedup, cross-hardlink modification tracking)
  // would notice this, but nothing in FEX's guest workloads relies on that,
  // and the alternative is that guest package management just doesn't work.
  if (Result == -1 && errno == EXDEV) {
    int src_fd = ::openat(eff_olddirfd, eff_oldpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (src_fd == -1 && errno == ELOOP && (flags & AT_SYMLINK_FOLLOW)) {
      src_fd = ::openat(eff_olddirfd, eff_oldpath, O_RDONLY | O_CLOEXEC);
    }
    if (src_fd != -1) {
      struct stat st;
      if (::fstat(src_fd, &st) == 0) {
        int dst_fd = ::openat(eff_newdirfd, eff_newpath,
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                              st.st_mode & 07777);
        if (dst_fd == -1 && errno == ENOENT && NewPath.FD != -1) {
          dst_fd = ::openat(NewPath.FD, NewPath.Path,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                            st.st_mode & 07777);
        }
        if (dst_fd != -1) {
          char buf[64 * 1024];
          ssize_t n;
          while ((n = ::read(src_fd, buf, sizeof(buf))) > 0) {
            ssize_t off = 0;
            while (off < n) {
              ssize_t w = ::write(dst_fd, buf + off, n - off);
              if (w < 0) {
                if (errno == EINTR) continue;
                break;
              }
              off += w;
            }
            if (off < n) break;
          }
          Result = (n == 0) ? 0 : uint64_t(-1);
          ::close(dst_fd);
        }
      }
      ::close(src_fd);
    }
  }
  return Result;
}

uint64_t FileManager::Symlinkat(const char* target, int newdirfd, const char* linkpath) {
  // `target` is link CONTENT (opaque string), not a path to resolve.
  // Only `linkpath` (where the symlink lands) gets overlay-translated.
  auto NewLink = GetSelf(linkpath);
  const char* SelfLink = NewLink ? NewLink->data() : nullptr;

  // Symlink creation belongs to the real filesystem — never create inside
  // the rootfs overlay (see Mkdirat()). Overlay consulted for EEXIST only.
  // Host-first / rootfs-on-ENOENT: if the host has no such parent (path
  // only exists in rootfs) fall back to rootfs creation.
  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(newdirfd, SelfLink, false, TmpFilename);
  if (Path.FD != -1 && ::faccessat(Path.FD, Path.Path, F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
    errno = EEXIST;
    return -1;
  }
  uint64_t Result = ::syscall(SYSCALL_DEF(symlinkat), target, newdirfd, SelfLink);
  if (Result == -1 && errno == ENOENT && Path.FD != -1) {
    Result = ::syscall(SYSCALL_DEF(symlinkat), target, Path.FD, Path.Path);
  }
  return Result;
}

uint64_t FileManager::Renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath) {
  return Renameat2(olddirfd, oldpath, newdirfd, newpath, 0);
}

uint64_t FileManager::Renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags) {
  auto OldNewPath = GetSelf(oldpath);
  const char* OldSelfPath = OldNewPath ? OldNewPath->data() : nullptr;
  auto NewNewPath = GetSelf(newpath);
  const char* NewSelfPath = NewNewPath ? NewNewPath->data() : nullptr;

  FDPathTmpData OldTmp, NewTmp;
  auto OldPath = GetEmulatedFDPath(olddirfd, OldSelfPath, false, OldTmp);
  auto NewPath = GetEmulatedFDPath(newdirfd, NewSelfPath, false, NewTmp);

  // Independent per-leg resolution -- same shape as FM.Linkat. Old code
  // picked one tree per call and applied it to both legs, breaking apt's
  // dpkg staging: rootfs-source + host-destination never got tried.
  int eff_olddirfd = olddirfd;
  const char* eff_oldpath = OldSelfPath;
  if (OldPath.FD != -1 && OldSelfPath && ::faccessat(AT_FDCWD, OldSelfPath, F_OK, 0) != 0) {
    eff_olddirfd = OldPath.FD;
    eff_oldpath = OldPath.Path;
  }

  int eff_newdirfd = newdirfd;
  const char* eff_newpath = NewSelfPath;

  uint64_t Result = ::syscall(SYSCALL_DEF(renameat2), eff_olddirfd, eff_oldpath, eff_newdirfd, eff_newpath, flags);
  if (Result == -1 && errno == ENOENT && NewPath.FD != -1) {
    Result = ::syscall(SYSCALL_DEF(renameat2), eff_olddirfd, eff_oldpath, NewPath.FD, NewPath.Path, flags);
  }

  // Cross-filesystem rename → EXDEV. See FM.Linkat for the same discussion:
  // apt-get's dpkg staging routes rootfs-source into host-tmpfs and does not
  // handle EXDEV by falling back to copy. Degrade to copy+unlink so the
  // caller's "file moved" intent is satisfied. Not atomic across the boundary
  // (a real rename is); nothing FEX runs needs the atomicity guarantee for
  // cross-boundary moves. Skip if flags asked for something we can't emulate
  // via copy (RENAME_EXCHANGE, RENAME_NOREPLACE with dest existing).
  if (Result == -1 && errno == EXDEV) {
    int src_fd = ::openat(eff_olddirfd, eff_oldpath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (src_fd == -1 && errno == ELOOP) {
      src_fd = ::openat(eff_olddirfd, eff_oldpath, O_RDONLY | O_CLOEXEC);
    }
    if (src_fd != -1) {
      struct stat st;
      if (::fstat(src_fd, &st) == 0) {
        int dst_fd = ::openat(eff_newdirfd, eff_newpath,
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                              st.st_mode & 07777);
        if (dst_fd == -1 && errno == ENOENT && NewPath.FD != -1) {
          dst_fd = ::openat(NewPath.FD, NewPath.Path,
                            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                            st.st_mode & 07777);
        }
        if (dst_fd != -1) {
          char buf[64 * 1024];
          ssize_t n;
          bool ok = true;
          while ((n = ::read(src_fd, buf, sizeof(buf))) > 0) {
            ssize_t off = 0;
            while (off < n) {
              ssize_t w = ::write(dst_fd, buf + off, n - off);
              if (w < 0) {
                if (errno == EINTR) continue;
                ok = false; break;
              }
              off += w;
            }
            if (!ok) break;
          }
          if (n < 0) ok = false;
          ::close(dst_fd);
          if (ok) {
            // Copy succeeded -- now remove the source, mimicking rename.
            ::unlinkat(eff_olddirfd, eff_oldpath, 0);
            Result = 0;
          }
        }
      }
      ::close(src_fd);
    }
  }
  return Result;
}

// ---------------------------------------------------------------------------
// Plain (non-*at) wrappers: forward to the *at form with AT_FDCWD.
// Eliminates the historical bypass that called glibc ::xxx directly, which
// silently skipped overlay translation and produced split-state where files
// got created in <rootfs>/foo but lookups walked the host /foo.
// ---------------------------------------------------------------------------

uint64_t FileManager::Chown(const char* pathname, uid_t owner, gid_t group) {
  return Fchownat(AT_FDCWD, pathname, owner, group, 0);
}

uint64_t FileManager::Chdir(const char* path) {
  // chdir was a raw passthrough alongside utimensat until dpkg -i tripped it:
  // dpkg-deb creates its extraction workdir via `mkdirat(rootfs_dirfd,
  // "var/lib/dpkg/tmp.ci", 0777)` which lands in the rootfs, then chdir()s to
  // the absolute path "/var/lib/dpkg/tmp.ci". Without translation the host
  // kernel sees a path that only exists inside the rootfs and returns ENOENT
  // — the "dpkg-deb (subprocess): failed to chdir to directory" symptom.
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  // Host first, rootfs only when the host genuinely lacks the directory.
  // The other order broke Steam: almost every absolute chdir target ("/",
  // "/usr", "/tmp") exists inside the rootfs, so preferring it parked the
  // host-visible cwd inside the overlay and pressure-vessel's relative-path
  // re-exec of the client escaped FEX to the system binfmt handler
  // (qemu-x86_64) and died. Host-first still covers the dpkg case that
  // motivated the translation: dpkg-deb's workdir exists only in the rootfs,
  // so the host chdir ENOENTs and the rootfs branch below takes it.
  uint64_t Result = ::chdir(SelfPath);
  if (Result != uint64_t(-1) || errno != ENOENT) {
    return Result;
  }

  auto Path = GetEmulatedPath(SelfPath, true);
  if (!Path.empty()) {
    return ::chdir(Path.c_str());
  }
  errno = ENOENT;
  return -1;
}

uint64_t FileManager::Lchown(const char* pathname, uid_t owner, gid_t group) {
  return Fchownat(AT_FDCWD, pathname, owner, group, AT_SYMLINK_NOFOLLOW);
}

uint64_t FileManager::Unlink(const char* pathname) {
  return Unlinkat(AT_FDCWD, pathname, 0);
}

uint64_t FileManager::Mkdir(const char* pathname, mode_t mode) {
  return Mkdirat(AT_FDCWD, pathname, mode);
}

uint64_t FileManager::Rmdir(const char* pathname) {
  return Unlinkat(AT_FDCWD, pathname, AT_REMOVEDIR);
}

uint64_t FileManager::Link(const char* oldpath, const char* newpath) {
  return Linkat(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0);
}

uint64_t FileManager::Symlink(const char* target, const char* linkpath) {
  return Symlinkat(target, AT_FDCWD, linkpath);
}

uint64_t FileManager::Rename(const char* oldpath, const char* newpath) {
  return Renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

uint64_t FileManager::Creat(const char* pathname, mode_t mode) {
  return Open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

uint64_t FileManager::Truncate(const char* pathname, off_t length) {
  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(AT_FDCWD, SelfPath, true, TmpFilename);
  if (Path.FD != -1) {
    // Open writable scoped to rootfs and ftruncate. OpenPathInRootFS hands
    // back O_PATH which ftruncate(2) rejects with EBADF; open with O_WRONLY
    // so the kernel naturally returns EISDIR (directory) / EACCES
    // (read-only file) / ENOENT etc. as the test expects.
    FEX::HLE::open_how how = {
      .flags = static_cast<uint64_t>(O_WRONLY | O_CLOEXEC),
      .mode = 0,
      .resolve = (Path.FD == AT_FDCWD) ? 0u : RESOLVE_IN_ROOT,
    };
    int fd = ::syscall(SYSCALL_DEF(openat2), Path.FD, Path.Path, &how, sizeof(how));
    if (fd != -1) {
      uint64_t Result = ::ftruncate(fd, length);
      int SavedErrno = errno;
      ::close(fd);
      errno = SavedErrno;
      return Result;
    }
    // Open in rootfs failed. Fall back to bare truncate only on ENOENT;
    // EISDIR / EACCES / etc. are real semantic results.
    if (errno != ENOENT) {
      return -1;
    }
  }
  return ::truncate(SelfPath, length);
}


uint64_t FileManager::Statfs(const char* path, void* buf) {
  auto Path = GetEmulatedPath(path);
  if (!Path.empty()) {
    uint64_t Result = ::statfs(Path.c_str(), reinterpret_cast<struct statfs*>(buf));
    // Only fall back when the path is genuinely absent from the RootFS.
    // GetEmulatedPath does no existence check, so ENOENT here is the normal
    // "this is a host path" signal; anything else is a semantic result about a
    // RootFS-resident path and must not be replaced by an answer describing the
    // host filesystem.
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }
  return ::statfs(path, reinterpret_cast<struct statfs*>(buf));
}

uint64_t FileManager::NewFSStatAt(int dirfd, const char* pathname, struct stat* buf, int flag) {
  if (IsSelfNoFollow(pathname, flag)) {
    // See Statx
    return ::fstatat(dirfd, pathname, buf, flag);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flag & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    int RootScopedFD = OpenPathInRootFS(Path, (flag & AT_SYMLINK_NOFOLLOW) == 0);
    if (RootScopedFD != -1) {
      uint64_t Result = ::fstatat(RootScopedFD, "", buf, flag | AT_EMPTY_PATH);
      int SavedErrno = errno;
      ::close(RootScopedFD);
      if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
        errno = SavedErrno;
        return Result;
      }
    } else if (errno != ENOENT) {
      return -1;
    }
  }
  return ::fstatat(dirfd, SelfPath, buf, flag);
}

uint64_t FileManager::NewFSStatAt64(int dirfd, const char* pathname, struct stat64* buf, int flag) {
  if (IsSelfNoFollow(pathname, flag)) {
    // See Statx
    return ::fstatat64(dirfd, pathname, buf, flag);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dirfd, SelfPath, (flag & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  int RootScopedFD = OpenPathInRootFS(Path, (flag & AT_SYMLINK_NOFOLLOW) == 0);
  if (RootScopedFD != -1) {
    uint64_t Result = ::fstatat64(RootScopedFD, "", buf, flag | AT_EMPTY_PATH);
    int SavedErrno = errno;
    ::close(RootScopedFD);
    // Same policy as FM.NewFSStatAt, which this is the 64-bit twin of:
    // propagate semantic errors, fall back only on a genuinely absent entry.
    if (static_cast<int64_t>(Result) != -1 || SavedErrno != ENOENT) {
      errno = SavedErrno;
      return Result;
    }
  } else if (errno != ENOENT) {
    return -1;
  }
  return ::fstatat64(dirfd, SelfPath, buf, flag);
}

uint64_t FileManager::Setxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, true);
  if (!Path.empty()) {
    uint64_t Result = ::setxattr(Path.c_str(), name, value, size, flags);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::setxattr(SelfPath, name, value, size, flags);
}

uint64_t FileManager::LSetxattr(const char* path, const char* name, const void* value, size_t size, int flags) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, false);
  if (!Path.empty()) {
    uint64_t Result = ::lsetxattr(Path.c_str(), name, value, size, flags);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::lsetxattr(SelfPath, name, value, size, flags);
}

uint64_t FileManager::Getxattr(const char* path, const char* name, void* value, size_t size) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, true);
  if (!Path.empty()) {
    uint64_t Result = ::getxattr(Path.c_str(), name, value, size);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::getxattr(SelfPath, name, value, size);
}

uint64_t FileManager::LGetxattr(const char* path, const char* name, void* value, size_t size) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, false);
  if (!Path.empty()) {
    uint64_t Result = ::lgetxattr(Path.c_str(), name, value, size);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::lgetxattr(SelfPath, name, value, size);
}

uint64_t FileManager::Listxattr(const char* path, char* list, size_t size) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, true);
  if (!Path.empty()) {
    uint64_t Result = ::listxattr(Path.c_str(), list, size);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::listxattr(SelfPath, list, size);
}

uint64_t FileManager::LListxattr(const char* path, char* list, size_t size) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, false);
  if (!Path.empty()) {
    uint64_t Result = ::llistxattr(Path.c_str(), list, size);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::llistxattr(SelfPath, list, size);
}

uint64_t FileManager::Removexattr(const char* path, const char* name) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, true);
  if (!Path.empty()) {
    uint64_t Result = ::removexattr(Path.c_str(), name);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::removexattr(SelfPath, name);
}

uint64_t FileManager::LRemovexattr(const char* path, const char* name) {
  auto NewPath = GetSelf(path);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  auto Path = GetEmulatedPath(SelfPath, false);
  if (!Path.empty()) {
    uint64_t Result = ::lremovexattr(Path.c_str(), name);
    if (Result != -1 || errno != ENOENT) {
      return Result;
    }
  }

  return ::lremovexattr(SelfPath, name);
}

uint64_t FileManager::SetxattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name, const xattr_args* uargs, size_t usize) {
  if (IsSelfNoFollow(pathname, at_flags)) {
    // See Statx
    return syscall(SYSCALL_DEF(setxattrat), dfd, pathname, at_flags, name, uargs, usize);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dfd, SelfPath, (at_flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = syscall(SYSCALL_DEF(setxattrat), Path.FD, Path.Path, at_flags, name, uargs, usize);
    if (Result != -1) {
      return Result;
    }
  }
  return syscall(SYSCALL_DEF(setxattrat), dfd, SelfPath, at_flags, name, uargs, usize);
}

uint64_t FileManager::GetxattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name, const xattr_args* uargs, size_t usize) {
  if (IsSelfNoFollow(pathname, at_flags)) {
    // See Statx
    return syscall(SYSCALL_DEF(getxattrat), dfd, pathname, at_flags, name, uargs, usize);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dfd, SelfPath, (at_flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = syscall(SYSCALL_DEF(getxattrat), Path.FD, Path.Path, at_flags, name, uargs, usize);
    if (Result != -1) {
      return Result;
    }
  }
  return syscall(SYSCALL_DEF(getxattrat), dfd, SelfPath, at_flags, name, uargs, usize);
}

uint64_t FileManager::ListxattrAt(int dfd, const char* pathname, uint32_t at_flags, char* list, size_t size) {
  if (IsSelfNoFollow(pathname, at_flags)) {
    // See Statx
    return syscall(SYSCALL_DEF(listxattrat), dfd, pathname, at_flags, list, size);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dfd, SelfPath, (at_flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = syscall(SYSCALL_DEF(listxattrat), Path.FD, Path.Path, at_flags, list, size);
    if (Result != -1) {
      return Result;
    }
  }
  return syscall(SYSCALL_DEF(listxattrat), dfd, SelfPath, at_flags, list, size);
}

uint64_t FileManager::RemovexattrAt(int dfd, const char* pathname, uint32_t at_flags, const char* name) {
  if (IsSelfNoFollow(pathname, at_flags)) {
    // See Statx
    return syscall(SYSCALL_DEF(removexattrat), dfd, pathname, at_flags, name);
  }

  auto NewPath = GetSelf(pathname);
  const char* SelfPath = NewPath ? NewPath->data() : nullptr;

  FDPathTmpData TmpFilename;
  auto Path = GetEmulatedFDPath(dfd, SelfPath, (at_flags & AT_SYMLINK_NOFOLLOW) == 0, TmpFilename);
  if (Path.FD != -1) {
    uint64_t Result = syscall(SYSCALL_DEF(removexattrat), Path.FD, Path.Path, at_flags, name);
    if (Result != -1) {
      return Result;
    }
  }
  return syscall(SYSCALL_DEF(removexattrat), dfd, SelfPath, at_flags, name);
}

void FileManager::UpdatePID(uint32_t PID) {
  CurrentPID = PID;

  // Track the inode of /proc/self/fd/<RootFSFD>, to be able to hide it
  auto FDpath = fextl::fmt::format("self/fd/{}", RootFSFD);
  struct stat Buffer {};
  int Result = fstatat(ProcFD, FDpath.c_str(), &Buffer, AT_SYMLINK_NOFOLLOW);
  if (Result >= 0) {
    RootFSFDInode = Buffer.st_ino;
  } else {
    // Probably in a strict sandbox
    RootFSFDInode = 0;
    ProcFDInode = 0;
    return;
  }

  // And track the ProcFSFD itself
  FDpath = fextl::fmt::format("self/fd/{}", ProcFD);
  Result = fstatat(ProcFD, FDpath.c_str(), &Buffer, AT_SYMLINK_NOFOLLOW);
  if (Result >= 0) {
    ProcFDInode = Buffer.st_ino;
  } else {
    // ??
    ProcFDInode = 0;
    return;
  }
}

bool FileManager::IsProtectedFile(int ParentDirFD, uint64_t inode) const {
  // Check if we have to hide this entry
  const char* Match = nullptr;
  if (inode == RootFSFDInode) {
    Match = "RootFS";
  } else if (inode == ProcFDInode) {
    Match = "/proc";
  } else if (inode == CodeMapInode) {
    Match = "code map";
  }
  if (Match) {
    struct stat Buffer;
    if (fstat(ParentDirFD, &Buffer) >= 0) {
      if (Buffer.st_dev == ProcFSDev) {
        LogMan::Msg::DFmt("Hiding directory entry for {} FD", Match);
        return true;
      }
    }
  }
  return false;
}

void FileManager::SetProtectedCodeMapFD(int FD) {
  if (FD == -1) {
    CodeMapInode = 0;
    return;
  }

  auto FDPath = fextl::fmt::format("self/fd/{}", FD);
  struct stat Buffer {};
  auto Result = fstatat(ProcFD, FDPath.c_str(), &Buffer, AT_SYMLINK_NOFOLLOW);
  if (Result >= 0) {
    CodeMapInode = Buffer.st_ino;
  } else {
    CodeMapInode = 0;
  }
}

} // namespace FEX::HLE
