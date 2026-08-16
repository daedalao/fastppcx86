// SPDX-License-Identifier: MIT
#pragma once

#include "Registry.h"

#include <map>
#include <string>
#include <string_view>
#include <vector>

/**
 * Building the environment a guest title is launched into.
 *
 * Three things happen here, and all three are properties of this port rather
 * than of any one machine:
 *
 *  - X11/XCB is forced. XCB is the only working window-system integration for an
 *    x86 guest on a PPC64LE host; the Wayland and Xlib paths break on
 *    cross-architecture guest-callback dispatch.
 *  - DISPLAY and XAUTHORITY are resolved rather than assumed. The xauth filename
 *    changes on every boot, and a stale one fails late, after the guest has
 *    started and linked, as "Unable to open display" -- which reads like a
 *    graphics bug and is not one.
 *  - The render backend's variables are set, and only the ones it owns are
 *    cleared.
 */
namespace FastPPCx86::Launcher::HostEnv {

/// An environment under construction. Starts as a snapshot of the launcher's own
/// and is mutated into what the child receives, so "unset" is a real operation
/// rather than a note to the caller.
class Environment {
public:
  static Environment FromCurrent();

  void Set(std::string Key, std::string Value);
  /// Leaves an existing value alone. Used where the user's own export should win.
  void SetIfUnset(std::string Key, std::string Value);
  void Unset(std::string_view Key);
  bool Has(std::string_view Key) const;
  const std::string* Get(std::string_view Key) const;

  /// "KEY=VALUE" strings, sorted, ready for execve.
  std::vector<std::string> ToEnvp() const;
  const std::map<std::string, std::string>& Vars() const {
    return Values;
  }

private:
  std::map<std::string, std::string> Values;
};

struct DisplayInfo {
  std::string Display;    ///< e.g. ":0"
  std::string XAuthority; ///< May be empty when the server needs no auth file.
  /// How it was found, for the UI: "inherited", "from Xwayland process", ...
  std::string Source;
  /// Non-empty when no display could be found at all. Launching should stop.
  std::string Problem;
};

/// Looks at the inherited environment first, then at the running X servers.
DisplayInfo ResolveDisplay(const Environment& Inherited);

/// Forces the XCB window-system path. Applies to every title kind.
void ApplyWindowSystem(Environment& Env);

void ApplyDisplay(Environment& Env, const DisplayInfo& Display);

void ApplyRender(Environment& Env, RenderBackend Backend);

/// Prepends `Dir` to PATH. Needed so FEXServer can execvp() its helper binaries.
void PrependPath(Environment& Env, const std::string& Dir);
/// Appends to a colon-separated variable, creating it when absent.
void AppendToPathList(Environment& Env, const std::string& Key, const std::string& Value);

} // namespace FastPPCx86::Launcher::HostEnv
