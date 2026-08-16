// SPDX-License-Identifier: MIT
#pragma once

#include <optional>

/**
 * Argument handling shared by both frontends.
 *
 * `--print`, `--list`, `--paths` and `--launch` go through exactly the same
 * Registry, Session and LaunchSpec code the interactive views use, which is what
 * stops the headless path from drifting away from the real one -- and makes the
 * launch semantics testable on a machine with no display attached.
 */
namespace FastPPCx86::Launcher::CLI {

/**
 * @return an exit code when the arguments were fully handled here, or nullopt
 *         when the caller should start its interactive frontend.
 */
std::optional<int> Run(int Argc, char** Argv, bool HaveGUI);

} // namespace FastPPCx86::Launcher::CLI
