// SPDX-License-Identifier: MIT
#pragma once

#include "Registry.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/**
 * Making a DXVK or VKD3D-Proton selection actually take effect.
 *
 * Proton and Wine both bundle their own copies. Selecting a different build
 * means installing its PE DLLs into the title's prefix and overriding the
 * builtins -- the same thing setup_dxvk.sh does. That mechanism was chosen over
 * any particular fork's environment variables because it works across every
 * Proton and Wine version rather than one of them.
 *
 * Each install is recorded in a manifest inside the prefix. That file is what
 * makes the arrangement honest: a Proton update overwrites those DLLs, silently
 * putting the title back on the bundled version, and without a record there is
 * no way to notice that the thing you selected is not the thing running.
 */
namespace FastPPCx86::Launcher::PrefixTools {

/// The directory containing `drive_c`. Proton nests its prefix one level down.
std::string WinePrefixDir(TitleKind Kind, const std::string& PrefixRoot);

struct InstalledFile {
  std::string Name; ///< e.g. "d3d11.dll"
  std::string DestPath;
  int64_t SourceSize {};
  int64_t SourceMTime {};
  int64_t DestSize {};
  int64_t DestMTime {};
};

struct InstalledRuntime {
  std::string Category; ///< "DXVK" or "VKD3D"
  std::string EntryId;
  std::string EntryName;
  std::string SourcePath;
  int64_t InstalledAt {};
  std::vector<InstalledFile> Files;
  std::string Overrides; ///< The WINEDLLOVERRIDES fragment this install needs.
};

struct Manifest {
  std::vector<InstalledRuntime> Entries;
  const InstalledRuntime* Find(std::string_view Category) const;
  void Replace(InstalledRuntime Entry);
  void Remove(std::string_view Category);
};

std::string ManifestPath(const std::string& WinePrefix);
Manifest ReadManifest(const std::string& WinePrefix);
bool WriteManifest(const std::string& WinePrefix, const Manifest& M);

struct InstallResult {
  bool Ok {false};
  std::string Error;
  std::vector<std::string> Installed; ///< File names actually copied.
  /// The WINEDLLOVERRIDES fragment, built from what was installed rather than
  /// from a fixed list: overriding d3d9 to native when the build ships no
  /// d3d9.dll would break every D3D9 title in that prefix.
  std::string Overrides;
};

/**
 * Copies the selected build's DLLs into the prefix and updates the manifest.
 *
 * @param Want32Bit Also install the x32 DLLs into syswow64. Decided by the
 *                  title's own PE architecture, not guessed.
 */
InstallResult Install(RuntimeCategory Category, const RuntimeEntry& Entry, const std::string& WinePrefix, bool Want32Bit);

/// Removes a category's manifest record and its override, leaving the DLLs in
/// place for Proton to overwrite on its next prefix update.
bool Uninstall(RuntimeCategory Category, const std::string& WinePrefix);

enum class DriftState {
  NotSelected,  ///< Nothing chosen and nothing installed: the bundled copy is in use.
  NotInstalled, ///< A selection exists but the prefix has never had it installed.
  Match,        ///< The prefix holds exactly what is selected.
  WrongEntry,   ///< The prefix holds a different build than the one selected.
  Overwritten,  ///< The DLLs in the prefix are not the ones this launcher put there.
  SourceNewer,  ///< The selected build has been rebuilt since it was installed.
};

struct Drift {
  DriftState State {DriftState::NotSelected};
  std::string Description; ///< Empty when State is Match or NotSelected.
};

Drift CheckDrift(const Manifest& M, RuntimeCategory Category, const RuntimeEntry* Selected, const std::string& WinePrefix);

/// Joins every manifest entry's override fragment, for WINEDLLOVERRIDES.
std::string CombinedOverrides(const Manifest& M);

} // namespace FastPPCx86::Launcher::PrefixTools
