// SPDX-License-Identifier: MIT
#pragma once

#include "Discovery.h"
#include "Registry.h"
#include "Runtimes.h"

#include <optional>
#include <string>

/**
 * The launcher's loaded state, shared by both frontends.
 *
 * Owning the load/discover/save cycle in one place keeps the GUI and the TUI
 * from developing subtly different ideas about when discovery runs or what a
 * first run looks like.
 */
namespace FastPPCx86::Launcher {

class Session final {
public:
  /**
   * Loads the registry, and on a first run (or when asked) merges in whatever
   * discovery finds. A missing registry is the ordinary first-run state and is
   * not an error.
   */
  bool Load(std::string& Error, bool RunDiscovery = true);

  bool Save(std::string& Error);

  /// Re-runs every probe, adding what is new. Never removes a user's entry.
  Discovery::Report Rescan();

  Registry& Reg() {
    return Registry_;
  }
  const Registry& Reg() const {
    return Registry_;
  }
  const Discovery::Report& LastReport() const {
    return Report_;
  }
  const std::string& Path() const {
    return Path_;
  }

  /// True when this looked like a first run: no registry file existed.
  bool WasFirstRun() const {
    return FirstRun_;
  }
  /// True when there is nothing for the user to launch yet.
  bool IsEmpty() const {
    return Registry_.Titles.empty();
  }

  /// Validity of an entry, cached per call. Convenience for both frontends.
  Runtimes::Validity Check(RuntimeCategory Category, const RuntimeEntry& Entry) const;

  /// A short "N of M valid" summary per category, for the empty-state panel.
  std::string SummariseCategory(RuntimeCategory Category) const;

private:
  Registry Registry_;
  Discovery::Report Report_;
  std::string Path_;
  bool FirstRun_ {false};
};

} // namespace FastPPCx86::Launcher
