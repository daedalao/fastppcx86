// SPDX-License-Identifier: MIT
#include "Runtimes.h"
#include "Discovery.h"

#include <Common/FileFormatCheck.h>

#include <fmt/format.h>

#include <ctime>
#include <sys/stat.h>
#include <unistd.h>

namespace FastPPCx86::Launcher::Runtimes {

namespace {
  std::string Join(std::string_view Dir, std::string_view Leaf) {
    std::string Out {Dir};
    while (!Out.empty() && Out.back() == '/') {
      Out.pop_back();
    }
    Out += '/';
    Out += Leaf;
    return Out;
  }

  Validity Fail(std::string Reason) {
    return Validity {false, std::move(Reason), {}};
  }

  Validity Pass(std::string Note = {}) {
    return Validity {true, {}, std::move(Note)};
  }
} // namespace

bool IsDirectory(const std::string& Path) {
  struct stat Info {};
  return !Path.empty() && ::stat(Path.c_str(), &Info) == 0 && S_ISDIR(Info.st_mode);
}

bool IsRegularFile(const std::string& Path) {
  struct stat Info {};
  return !Path.empty() && ::stat(Path.c_str(), &Info) == 0 && S_ISREG(Info.st_mode);
}

bool IsExecutableFile(const std::string& Path) {
  return IsRegularFile(Path) && ::access(Path.c_str(), X_OK) == 0;
}

std::optional<int64_t> ModificationTime(const std::string& Path) {
  struct stat Info {};
  if (Path.empty() || ::stat(Path.c_str(), &Info) != 0) {
    return std::nullopt;
  }
  return static_cast<int64_t>(Info.st_mtime);
}

std::string DescribeModificationTime(const std::string& Path) {
  const auto When = ModificationTime(Path);
  if (!When) {
    return "(missing)";
  }
  const std::time_t Raw = static_cast<std::time_t>(*When);
  std::tm Broken {};
  if (!::localtime_r(&Raw, &Broken)) {
    return "(unknown)";
  }
  char Buffer[32];
  if (std::strftime(Buffer, sizeof(Buffer), "%Y-%m-%d %H:%M", &Broken) == 0) {
    return "(unknown)";
  }
  return Buffer;
}

std::optional<EmulatorPaths> ResolveEmulator(const RuntimeEntry& Entry) {
  const auto Dir = ExpandPath(Entry.Path);
  if (Dir.empty()) {
    return std::nullopt;
  }
  EmulatorPaths Paths;
  Paths.Dir = Dir;
  Paths.FEX = Join(Dir, "FEX");
  Paths.FEXBash = Join(Dir, "FEXBash");
  if (!IsExecutableFile(Paths.FEX) || !IsExecutableFile(Paths.FEXBash)) {
    return std::nullopt;
  }
  return Paths;
}

std::optional<std::string> ResolveProton(const RuntimeEntry& Entry) {
  const auto Dir = ExpandPath(Entry.Path);
  if (Dir.empty()) {
    return std::nullopt;
  }
  const auto Script = Join(Dir, "proton");
  if (!IsRegularFile(Script)) {
    return std::nullopt;
  }
  return Script;
}

std::optional<std::string> ResolveWine(const RuntimeEntry& Entry) {
  const auto Dir = ExpandPath(Entry.Path);
  if (Dir.empty()) {
    return std::nullopt;
  }
  for (const char* Candidate : {"bin/wine64", "bin/wine"}) {
    const auto Path = Join(Dir, Candidate);
    if (IsExecutableFile(Path)) {
      return Path;
    }
  }
  return std::nullopt;
}

Validity Validate(RuntimeCategory Category, const RuntimeEntry& Entry) {
  // Thunk sets carry three paths instead of one, so they are checked first and
  // never fall through to the single-path handling below.
  if (Category == RuntimeCategory::ThunkSets) {
    const auto Host = ExpandPath(Entry.HostLibs);
    const auto Guest = ExpandPath(Entry.GuestLibs);
    const auto Config = ExpandPath(Entry.ThunkConfig);

    if (Host.empty() && Guest.empty() && Config.empty()) {
      return Pass("uses the emulator's built-in thunk paths");
    }
    if (!Host.empty() && !IsDirectory(Host)) {
      return Fail(fmt::format("host thunk directory '{}' does not exist", Host));
    }
    if (!Guest.empty() && !IsDirectory(Guest)) {
      return Fail(fmt::format("guest thunk directory '{}' does not exist", Guest));
    }
    if (!Config.empty() && !IsRegularFile(Config)) {
      return Fail(fmt::format("thunk config '{}' does not exist", Config));
    }
    // Half a pair is the dangerous state, not the missing state: mismatched
    // host and guest thunk halves fail at the call boundary, far from here.
    if (Host.empty() != Guest.empty()) {
      return Pass("only one half set; the other keeps the emulator's default, which may not match");
    }
    return Pass();
  }

  const auto Path = ExpandPath(Entry.Path);
  if (Path.empty()) {
    return Fail("no path set");
  }

  switch (Category) {
  case RuntimeCategory::Libraries:
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    if (::access(Path.c_str(), R_OK | X_OK) != 0) {
      return Fail("not readable");
    }
    return Pass();

  case RuntimeCategory::EmulatorBuilds: {
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    const bool HasFEX = IsExecutableFile(Join(Path, "FEX"));
    const bool HasBash = IsExecutableFile(Join(Path, "FEXBash"));
    if (!HasFEX && !HasBash) {
      return Fail("contains neither FEX nor FEXBash");
    }
    if (!HasFEX) {
      return Fail("contains FEXBash but no FEX");
    }
    if (!HasBash) {
      // Refused rather than warned: a build directory with only one of the pair
      // is precisely the configuration that runs half a session on the wrong
      // binary without ever saying so.
      return Fail("contains FEX but no FEXBash");
    }
    return Pass();
  }

  case RuntimeCategory::RootFS: {
    if (IsDirectory(Path)) {
      return Pass();
    }
    if (!IsRegularFile(Path)) {
      return Fail("not a directory or image file");
    }
    const fextl::string AsFextl {Path.c_str()};
    if (FEX::FormatCheck::IsSquashFS(AsFextl)) {
      return Pass("squashfs image (needs squashfuse to mount)");
    }
    if (FEX::FormatCheck::IsEroFS(AsFextl)) {
      return Pass("EROFS image (needs erofs-utils to mount)");
    }
    return Fail("not a directory, and not a squashfs or EROFS image");
  }

  case RuntimeCategory::Proton: {
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    if (!IsRegularFile(Join(Path, "proton"))) {
      return Fail("no 'proton' script here");
    }
    return Pass();
  }

  case RuntimeCategory::Wine: {
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    std::string Found;
    for (const char* Candidate : {"bin/wine64", "bin/wine"}) {
      if (IsExecutableFile(Join(Path, Candidate))) {
        Found = Join(Path, Candidate);
        break;
      }
    }
    if (Found.empty()) {
      return Fail("no bin/wine64 or bin/wine here");
    }

    const auto Info = Discovery::InspectBinary(Found);
    if (Info && Info->Kind == Discovery::BinaryKind::HostELF) {
      // A native ppc64le Wine is a legitimate thing to register, but it cannot
      // run PE binaries today: there is no PE ABI for PPC64, so PE_ARCHS comes
      // out empty and wow64/xtajit64 are never built. Say that plainly here
      // rather than letting it fail deep inside a launch.
      return Pass("host-architecture Wine: runs outside the emulator, and cannot load PE binaries on this port");
    }
    return Pass();
  }

  case RuntimeCategory::DXVK: {
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    const bool Has64 = IsRegularFile(Join(Path, "x64/d3d11.dll"));
    const bool Has32 = IsRegularFile(Join(Path, "x32/d3d11.dll"));
    if (!Has64 && !Has32) {
      return Fail("no x64/d3d11.dll or x32/d3d11.dll here");
    }
    if (!Has32) {
      return Pass("64-bit only; 32-bit titles keep the bundled DXVK");
    }
    if (!Has64) {
      return Pass("32-bit only; 64-bit titles keep the bundled DXVK");
    }
    return Pass();
  }

  case RuntimeCategory::VKD3D: {
    if (!IsDirectory(Path)) {
      return Fail("not a directory");
    }
    if (!IsRegularFile(Join(Path, "x64/d3d12.dll"))) {
      return Fail("no x64/d3d12.dll here");
    }
    if (!IsRegularFile(Join(Path, "x64/d3d12core.dll"))) {
      // d3d12core is a separate DLL in every vkd3d-proton since 2.6, and
      // installing d3d12 without it produces a title that fails at device
      // creation with nothing useful in the log.
      return Fail("x64/d3d12.dll present but d3d12core.dll missing");
    }
    return Pass();
  }

  case RuntimeCategory::ThunkSets: break; // handled above
  }

  return Pass();
}

} // namespace FastPPCx86::Launcher::Runtimes
