// SPDX-License-Identifier: MIT
#pragma once

#include "Registry.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/**
 * Probes that seed the runtime lists, and the library scanner.
 *
 * Discovery only ever *proposes*. The user's list is authoritative: a rescan
 * adds entries that were not there before and re-validates the rest, and it must
 * never remove or rewrite an entry the user added by hand. A probe whose target
 * is absent is silent -- no Steam is a normal state, not an error.
 */
namespace FastPPCx86::Launcher::Discovery {

enum class BinaryKind {
  Unknown,
  GuestELF64, ///< x86-64 ELF: runs under the emulator.
  GuestELF32, ///< i386 ELF: runs under the emulator.
  HostELF,    ///< This machine's own architecture: runs natively.
  ForeignELF, ///< An ELF for some third architecture.
  WindowsPE64,
  WindowsPE32,
  Script, ///< #! ...
};

struct BinaryInfo {
  BinaryKind Kind {BinaryKind::Unknown};
  uint16_t Machine {}; ///< ELF e_machine, or the PE machine word.
};

/// Reads only the file header. Returns nullopt when the file cannot be opened.
std::optional<BinaryInfo> InspectBinary(const std::string& Path);

/// True when the emulator can run this directly (an x86 or x86-64 guest ELF).
bool IsGuestExecutable(BinaryKind Kind);

// -- Probes ------------------------------------------------------------------

/// Steam installation roots that exist: ~/.steam/steam, ~/.steam/root,
/// ~/.local/share/Steam, and the Flatpak location.
std::vector<std::string> SteamRoots();

/**
 * Every Steam library path, read from each root's steamapps/libraryfolders.vdf.
 * This is the only correct way to find libraries the user put on other drives;
 * assuming the default location is how a launcher ends up seeing a third of
 * someone's collection.
 */
std::vector<std::string> SteamLibraryPaths();

/// Absolute path to steam.sh, for the Steam title kind.
std::optional<std::string> SteamClientScript();

/// Parses a Steam VDF document and returns every "path" value it contains.
/// Exposed for testing against a fixture rather than a live Steam install.
std::vector<std::string> ParseLibraryFoldersVDF(std::string_view Contents);

struct Report {
  std::array<int, RuntimeCategoryCount> Added {};
  /// Where each category looked. Shown when a category comes up empty, so the
  /// user can see what to install or which path to add by hand.
  std::array<std::vector<std::string>, RuntimeCategoryCount> Searched;

  int TotalAdded() const;
};

/// Runs every probe and merges the results into `Reg`.
Report Populate(Registry& Reg);

// -- Library scanning --------------------------------------------------------

struct Candidate {
  std::string Path;
  std::string Name;    ///< Suggested display name.
  std::string WorkDir; ///< Directory holding Path.
  TitleKind Kind {TitleKind::Native};
  BinaryKind Binary {BinaryKind::Unknown};
  int64_t SizeBytes {};
  std::string LibraryRoot; ///< Which enabled library root produced this.
  int64_t SteamAppId {};   ///< 0 when unknown.
};

struct ScanOptions {
  int MaxDepth {6};
  /// Files smaller than this are almost never a game binary and are usually
  /// installer stubs or helper shims.
  int64_t MinSizeBytes {64 * 1024};
  size_t MaxResults {5000};
  /// Candidates kept per install directory, best-ranked first. 0 means no cap.
  int MaxPerTitle {4};
};

std::vector<Candidate> ScanLibraries(const Registry& Reg, const ScanOptions& Options = {});

/// True for the launcher shims, crash handlers and redistributables that must
/// be skipped: launching them instead of the game is a classic wasted evening.
bool IsSkippedExecutable(std::string_view Filename);

/// True when the filename is plausibly a launchable game binary. Rejects DLLs
/// and shared objects, which are PE/ELF too and often carry the executable bit.
bool IsGameCandidateFilename(std::string_view Filename);

/// True for whole subtrees that hold no game: Proton and Steam runtimes, wine
/// prefixes, redistributable bundles. Pruned during the walk, not filtered after.
bool IsSkippedDirectory(std::string_view Name);

} // namespace FastPPCx86::Launcher::Discovery
