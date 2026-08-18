// SPDX-License-Identifier: MIT
#pragma once

#include "Topology.h"

#include <array>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * The launcher's own state: the eight runtime lists, the defaults, and the
 * titles.
 *
 * Two rules run through this file and are worth stating once.
 *
 * Paths are stored exactly as the user typed them -- `~` and `$VAR` survive a
 * save/load cycle intact and are expanded only at the moment of use. That is
 * what lets a registry be copied to another machine, or between users on the
 * same machine, without every entry going stale.
 *
 * Every category of location is a *list*, never a single value, and every list
 * is selectable per title. A single-valued location setting anywhere here would
 * be a bug: it is exactly what ties a launcher to one machine.
 */
namespace FastPPCx86::Launcher {

enum class TitleKind {
  Native, ///< An x86/x86-64 Linux ELF, run directly under FEX.
  Proton, ///< A Windows PE run through a Proton tree inside FEXBash.
  Wine,   ///< A Windows PE run through a plain Wine tree.
  Steam,  ///< The Steam client itself.
};

std::string_view ToString(TitleKind Kind);
std::optional<TitleKind> TitleKindFromString(std::string_view Name);

enum class RenderBackend {
  Native,   ///< Whatever the host's GL stack resolves to.
  Zink,     ///< Mesa's GL-on-Vulkan.
  Llvmpipe, ///< Software rasteriser.
};

std::string_view ToString(RenderBackend Backend);
std::optional<RenderBackend> RenderBackendFromString(std::string_view Name);

enum class RuntimeCategory {
  Libraries,      ///< Game library roots the scanner walks.
  EmulatorBuilds, ///< Directories holding both FEX and FEXBash.
  RootFS,         ///< x86-64 root filesystems -> FEX_ROOTFS.
  ThunkSets,      ///< Host/guest thunk pairs -> FEX_THUNK*.
  Proton,         ///< Proton trees.
  Wine,           ///< Wine trees.
  DXVK,           ///< DXVK builds, installed into a prefix.
  VKD3D,          ///< VKD3D-Proton builds, installed into a prefix.
};

inline constexpr size_t RuntimeCategoryCount = 8;
inline constexpr std::array<RuntimeCategory, RuntimeCategoryCount> AllRuntimeCategories {
  RuntimeCategory::Libraries, RuntimeCategory::EmulatorBuilds, RuntimeCategory::RootFS, RuntimeCategory::ThunkSets,
  RuntimeCategory::Proton,    RuntimeCategory::Wine,           RuntimeCategory::DXVK,   RuntimeCategory::VKD3D,
};

/// Stable key used in Titles.json and by --paths.
std::string_view ToString(RuntimeCategory Category);
std::optional<RuntimeCategory> RuntimeCategoryFromString(std::string_view Name);
/// Human-readable, for UI headings.
std::string_view DisplayName(RuntimeCategory Category);

struct RuntimeEntry {
  std::string Id;   ///< Stable, referenced by Title::Use and Registry::Defaults.
  std::string Name; ///< What the user sees.
  std::string Path; ///< Unexpanded. Empty for a ThunkSet, which uses the three below.

  // ThunkSets only. Any one may be empty, which means "leave FEX's build-time
  // default in place for that component".
  std::string HostLibs;
  std::string GuestLibs;
  std::string ThunkConfig;

  /// True when a probe proposed this entry rather than the user adding it.
  /// A rescan may refresh a discovered entry; it must never delete a user one.
  bool Discovered {false};
  bool Enabled {true};

  /// Set on Wine entries: the tree's own architecture, so the launch path knows
  /// whether it runs inside the emulator or directly on the host.
  bool HostNative {false};
};

/// A title's per-category overrides. Empty means "inherit the registry default".
struct RuntimeSelection {
  std::string EmulatorBuild;
  std::string RootFS;
  std::string ThunkSet;
  std::string Proton;
  std::string Wine;
  std::string DXVK;
  std::string VKD3D;

  std::string& For(RuntimeCategory Category);
  const std::string& For(RuntimeCategory Category) const;
};

struct Title {
  std::string Id;
  std::string Name;
  TitleKind Kind {TitleKind::Native};

  std::string Exe;
  std::string WorkDir; ///< Empty means the directory holding Exe.
  std::vector<std::string> Args;
  std::map<std::string, std::string> Env; ///< Non-FEX environment, e.g. SteamAppId.

  RenderBackend Render {RenderBackend::Native};
  Topology::CagePolicy Cage;

  /// Bare FEX option names -> values. Each becomes FEX_<KEY>=<value>.
  std::map<std::string, std::string> Fex;

  RuntimeSelection Use;
  std::string Prefix; ///< Empty means <prefix root>/<Id>.
  std::string Notes;

  /// 0 means no timeout. Anything else SIGKILLs the title, which is a foot-gun
  /// worth naming in the UI rather than hiding.
  int TimeoutSeconds {0};
};

struct Registry {
  int Version {1};
  std::array<std::vector<RuntimeEntry>, RuntimeCategoryCount> Runtimes;
  RuntimeSelection Defaults;
  std::vector<Title> Titles;

  std::vector<RuntimeEntry>& List(RuntimeCategory Category);
  const std::vector<RuntimeEntry>& List(RuntimeCategory Category) const;

  const RuntimeEntry* Find(RuntimeCategory Category, std::string_view Id) const;
  Title* FindTitle(std::string_view Id);
  const Title* FindTitle(std::string_view Id) const;

  /**
   * Resolves a category for a title through the three tiers: the title's own
   * override, then the registry default, then the first enabled entry.
   * Returns nullptr when the category is empty or nothing enabled remains.
   */
  const RuntimeEntry* Resolve(RuntimeCategory Category, const Title& ForTitle) const;
  const RuntimeEntry* Resolve(RuntimeCategory Category, const RuntimeSelection& Selection) const;

  /// Appends `Entry`, giving it a unique id derived from its name if it has none.
  /// Discovered entries whose path already exists in the list are dropped.
  bool Add(RuntimeCategory Category, RuntimeEntry Entry);

  bool Load(const std::string& Path, std::string& Error);
  bool Save(const std::string& Path, std::string& Error) const;
  std::string Serialise() const;
};

// -- Paths -------------------------------------------------------------------
//
// All of these route through FEX::Config's directory helpers, so the XDG vs
// legacy ~/.fex-emu split, and the FEX_APP_CONFIG_LOCATION override, are handled
// in exactly one place rather than being re-derived here.
//
// Note what FEX_PORTABLE actually does: it relocates the *global* config and
// data directories to sit beside the binary. Per-user config still follows XDG,
// so the launcher's registry does too. That is deliberate -- a launcher whose
// per-user state landed somewhere different from every other per-user FEX config
// would be the surprising option, not the helpful one.

/// `<config dir>/Launcher/Titles.json`
std::string RegistryPath();
/// `<data dir>/Launcher/prefixes`
std::string DefaultPrefixRoot();
/// `$XDG_STATE_HOME/fex-emu/Launcher/logs`, falling back to the cache directory.
std::string DefaultLogDir();

/// Expands a leading `~` and any `$VAR` / `${VAR}`. Unset variables expand empty.
std::string ExpandPath(std::string_view Path);
/// Lower-cases, and replaces every run of non-alphanumerics with a single '-'.
std::string MakeId(std::string_view Text);

} // namespace FastPPCx86::Launcher
