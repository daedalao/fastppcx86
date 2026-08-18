// SPDX-License-Identifier: MIT
#include "../CLI.h"
#include "App.h"

#include <Common/Config.h>
#include <PortabilityInfo.h>

int main(int Argc, char** Argv) {
  // Resolves the config and data directories the whole launcher relies on:
  // the XDG vs legacy ~/.fex-emu split, and where FEX_PORTABLE puts the global
  // ones. Per-user state still follows XDG, as it does for every FEX tool.
  FEX::Config::InitializeConfigs(FEX::ReadPortabilityInformation());

  if (const auto ExitCode = FastPPCx86::Launcher::CLI::Run(Argc, Argv, false)) {
    return *ExitCode;
  }

  FastPPCx86::Launcher::TUI::App App;
  return App.Run();
}
