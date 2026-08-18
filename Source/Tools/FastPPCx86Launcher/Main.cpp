// SPDX-License-Identifier: MIT
#include "CLI.h"
#include "MainWindow.h"

#include <Common/Config.h>
#include <PortabilityInfo.h>

#include <QApplication>

#include <cstdio>
#include <cstdlib>

int main(int Argc, char** Argv) {
  // Resolves the config and data directories the whole launcher relies on:
  // the XDG vs legacy ~/.fex-emu split, and where FEX_PORTABLE puts the global
  // ones. Per-user state still follows XDG, as it does for every FEX tool.
  FEX::Config::InitializeConfigs(FEX::ReadPortabilityInformation());

  // The command-line modes run without a display, so they are handled before any
  // Qt object exists. `ppcx86-launch --print <id>` therefore works over a bare
  // ssh connection, which is where a lot of this machine's use happens.
  if (const auto ExitCode = FastPPCx86::Launcher::CLI::Run(Argc, Argv, true)) {
    return *ExitCode;
  }

  const char* Display = std::getenv("DISPLAY");
  const char* Wayland = std::getenv("WAYLAND_DISPLAY");
  if ((!Display || !*Display) && (!Wayland || !*Wayland)) {
    // Failing here with a pointer at the terminal frontend is far better than
    // Qt's own abort, which reads as a broken install.
    std::fprintf(stderr, "No display available, so the graphical launcher cannot start.\n"
                         "Use the terminal frontend instead:\n"
                         "  ppcx86-launch-tui\n"
                         "Or run a command directly:\n"
                         "  ppcx86-launch --list\n");
    return 1;
  }

  QApplication App(Argc, Argv);
  QApplication::setApplicationName(QStringLiteral("ppcx86-launch"));
  QApplication::setApplicationDisplayName(QStringLiteral("FastPPCx86 Launcher"));

  FastPPCx86::Launcher::MainWindow Window;
  Window.show();
  return App.exec();
}
