// SPDX-License-Identifier: MIT
#pragma once

#include "Registry.h"

#include <optional>
#include <string>

/**
 * Validation and resolution for the runtime lists.
 *
 * Every entry is checked against what its category actually needs, and a failure
 * carries the reason. That reason is the point: a launcher that only says "this
 * did not work" makes the user go hunting, and the failures here (a Proton tree
 * with no `proton` script, a thunk set whose guest half is missing) all have a
 * one-line explanation available at the moment the path is entered.
 */
namespace FastPPCx86::Launcher::Runtimes {

struct Validity {
  bool Ok {false};
  /// Empty when Ok. Otherwise a short phrase, e.g. "no 'proton' script here".
  std::string Reason;
  /// Extra context worth showing even when valid, e.g. "32-bit stubs absent".
  std::string Note;
};

Validity Validate(RuntimeCategory Category, const RuntimeEntry& Entry);

/// The pair of binaries an emulator-build entry resolves to. Both or neither:
/// pointing FEX_BIN at a new build while FEXBASH still points at the old one is
/// a documented way to lose an afternoon, so they are never resolved apart.
struct EmulatorPaths {
  std::string Dir;
  std::string FEX;
  std::string FEXBash;
};

std::optional<EmulatorPaths> ResolveEmulator(const RuntimeEntry& Entry);

/// Absolute path to the `proton` script for a Proton entry.
std::optional<std::string> ResolveProton(const RuntimeEntry& Entry);
/// Absolute path to the best `wine` binary for a Wine entry (wine64 preferred).
std::optional<std::string> ResolveWine(const RuntimeEntry& Entry);

bool IsDirectory(const std::string& Path);
bool IsExecutableFile(const std::string& Path);
bool IsRegularFile(const std::string& Path);

/// Seconds since the epoch for a path's mtime, or nullopt. Used to show build
/// freshness next to an emulator selection.
std::optional<int64_t> ModificationTime(const std::string& Path);
/// "2026-08-16 12:04" in local time, or "(missing)".
std::string DescribeModificationTime(const std::string& Path);

} // namespace FastPPCx86::Launcher::Runtimes
