// SPDX-License-Identifier: MIT
#pragma once

#include <map>
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

/**
 * Reading back what a running guest process actually got.
 *
 * docs/GAMING.md has two triage rituals that people are told to perform by hand:
 *
 *   tr '\0' '\n' < /proc/$(pgrep -n FEX)/environ | grep '^FEX_'
 *   ls -l /proc/<pid>/exe        # "(deleted)" means you rebuilt under it
 *
 * Both exist because config layers, AppConfig files and launcher defaults all
 * sit between an intended setting and the process, and an export that did not
 * arrive looks exactly like a setting that did nothing. This module performs
 * both, so the launcher can show what it *asked* for beside what actually
 * landed instead of asking the user to trust it.
 */
namespace FastPPCx86::Launcher::ProcessProbe {

struct GuestProcess {
  pid_t Pid {};
  std::string Comm;
  std::string Exe;
  /// True when /proc/<pid>/exe resolves with a "(deleted)" suffix, meaning the
  /// binary was replaced since launch and this process is running the old one.
  bool ExeDeleted {false};
  std::map<std::string, std::string> FexVars;
};

/// Every descendant of `Root`, including `Root` itself.
std::vector<pid_t> Descendants(pid_t Root);

std::optional<GuestProcess> Inspect(pid_t Pid);

/// The emulator process under `Root` most worth showing: prefers a process whose
/// executable is an emulator binary, and the deepest such one, since the guest
/// runs under FEXBash's children for the Proton and Steam kinds.
std::optional<GuestProcess> FindGuest(pid_t Root);

struct Difference {
  std::string Key;
  std::string Expected;
  std::string Actual; ///< Empty when the variable is absent from the process.
  bool Missing {false};
};

/// Compares what the launcher intended against what the process has. Extra FEX_*
/// variables in the process are reported too: they come from a config layer or a
/// stale export and are exactly what this check exists to surface.
struct Comparison {
  std::vector<Difference> Differences;
  std::vector<std::string> Unexpected;
  bool Matches() const {
    return Differences.empty() && Unexpected.empty();
  }
};

Comparison Compare(const std::map<std::string, std::string>& Expected, const std::map<std::string, std::string>& Actual);

} // namespace FastPPCx86::Launcher::ProcessProbe
