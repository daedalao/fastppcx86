// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

/**
 * Shipped per-title tuning hints.
 *
 * These are measurements that hold on any POWER8/9 host, keyed by executable
 * basename and Steam appid, and they are how one person's benchmarking reaches
 * everybody else's install. A hint is offered at import time with its reasoning
 * attached and is never applied silently: the user accepts it or does not, and
 * an existing per-title value is never overwritten.
 *
 * The data lives in a plain JSON file next to the shipped AppConfigs, so it can
 * grow by pull request without touching any code.
 */
namespace FastPPCx86::Launcher::Hints {

struct Hint {
  std::string Basename; ///< Matched case-insensitively.
  int64_t AppId {};     ///< 0 when the hint is not tied to a Steam title.
  std::map<std::string, std::string> Fex;
  std::string Why; ///< Shown to the user. A hint without one is not worth having.
};

/// The packaged file, then a user file of the same name, later entries winning.
std::vector<Hint> Load();

/// Packaged location, from the data directory compiled into the build.
std::string PackagedPath();
/// Per-user overrides and additions.
std::string UserPath();

/// Best match: an appid match beats a basename match.
const Hint* Match(const std::vector<Hint>& All, std::string_view Basename, int64_t AppId);

} // namespace FastPPCx86::Launcher::Hints
