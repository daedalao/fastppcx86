// SPDX-License-Identifier: MIT
#pragma once

#include "HostEnv.h"
#include "Registry.h"
#include "Topology.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

/**
 * Turning a title plus a runtime selection into an exact command.
 *
 * This is the single place launch semantics live. Both frontends and the
 * `--print` mode consume this same function, which is what keeps the headless
 * path from drifting away from what the GUI actually does -- and what makes the
 * emitted command in the UI a truthful record rather than a reconstruction.
 */
namespace FastPPCx86::Launcher {

/// Applied for one run only; never written back to the registry.
struct SessionOverrides {
  std::optional<RenderBackend> Render;
  std::optional<Topology::CagePolicy> Cage;
  std::optional<std::string> EmulatorBuildId;
  /// Added on top of the title's own, winning on conflict.
  std::map<std::string, std::string> ExtraFex;
  /// Route the emulator's own output to stderr instead of a running FEXServer,
  /// which otherwise swallows the startup banner.
  bool DirectLog {false};
};

struct Diagnostic {
  enum class Level {
    Info,
    Warning,
    Error, ///< Launch cannot proceed.
  };

  Level Severity {Level::Info};
  std::string Text;
};

struct LaunchSpec {
  bool Ok {false};

  std::vector<std::string> Argv;
  std::vector<std::string> Envp; ///< Complete environment, ready for execve.
  std::string WorkDir;

  std::vector<int> CageCPUs; ///< Empty means no affinity restriction.
  std::string CageList;
  std::string CageExplanation;

  std::string LogPath;
  int TimeoutSeconds {0};

  /// The wine prefix this launch uses, for the kinds that have one.
  std::string WinePrefix;

  std::vector<Diagnostic> Diagnostics;

  /// The FEX_* subset of Envp, for the UI to show and for --print to compare
  /// against what the running process actually has.
  std::map<std::string, std::string> FexVars() const;

  /// A copy-pasteable shell equivalent. Reproducible in a terminal and useful in
  /// a bug report; it is generated from Argv/Envp rather than assembled
  /// separately, so it cannot describe a different launch than the one performed.
  std::string ShellCommand() const;

  bool HasErrors() const;
};

LaunchSpec Build(const Registry& Reg, const Title& T, const SessionOverrides& Overrides = {});

/// The compatdata/prefix root for a title, whether or not it exists yet.
std::string ResolvePrefixRoot(const Title& T);

/**
 * Performs the side effects a launch needs, and returns what it did.
 *
 * Right now that means installing a selected DXVK or VKD3D build into the
 * title's prefix when the prefix does not already hold it. This is deliberately
 * *not* part of Build(): Build is pure, so `--print` can show what a launch
 * would do without touching the disk, and the UI can rebuild the preview on
 * every keystroke. Call this immediately before Runner::Start, then call Build
 * again so the fresh WINEDLLOVERRIDES is picked up.
 */
struct PrepareResult {
  bool Ok {true};
  std::vector<Diagnostic> Diagnostics;
};

PrepareResult Prepare(const Registry& Reg, const Title& T);

/// Where a title's log for `When` (defaults to now) is written.
std::string LogPathFor(const Title& T);

/// POSIX shell quoting, for ShellCommand() and for the `FEXBash -c` payload.
std::string ShellQuote(std::string_view Value);

/**
 * A title's AppConfig, read only.
 *
 * The launcher stores its own settings and exports them as environment, which
 * outranks AppConfig. But AppConfig still governs everything the launcher leaves
 * unset, and a stale `"SMCChecks": "none"` there disarms every SMC feature with
 * no diagnostic. So it is read, never written, and any overlap is reported.
 */
struct AppConfigInfo {
  std::string Path;
  bool Exists {false};
  std::map<std::string, std::string> Options;
  /// Keys this title's own settings also set. The launcher's value wins.
  std::vector<std::string> Overlapping;
  /// True when AppConfig sets SMCChecks=none, which silently disables the rest.
  bool DisarmsSMC {false};
};

AppConfigInfo InspectAppConfig(const Title& T);

} // namespace FastPPCx86::Launcher
