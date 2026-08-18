// SPDX-License-Identifier: MIT
#pragma once

#include "../Session.h"
#include "UI.h"

#include <string>
#include <vector>

/**
 * The terminal frontend.
 *
 * Runs over ssh with no X and no Qt installed, which matters on this project:
 * the machine doing the emulation is frequently reached remotely, and the
 * graphical frontend needs the same display the games are competing for.
 */
namespace FastPPCx86::Launcher::TUI {

class App final {
public:
  int Run();

private:
  enum class View {
    Titles,
    Paths,
    Empty,
  };

  void Draw();
  void DrawTitles();
  void DrawPaths();
  void DrawEmptyState();
  void DrawDetail(int Row, int Col, int Width, int Height);

  bool HandleKey(int Key);
  bool HandleTitlesKey(int Key);
  bool HandlePathsKey(int Key);

  void RefreshTitleList();
  void RefreshPathList();

  Title* CurrentTitle();
  const Title* CurrentTitle() const;

  void LaunchCurrent();
  void ShowCommand();
  void EditTuning();
  void EditRuntimes();
  void ScanAndImport();
  void AddPathEntry();
  void RemovePathEntry();
  void ToggleEntryEnabled();
  void SetEntryAsDefault();
  void Rescan();
  void ShowHelp();
  void SaveNow();

  void Status(std::string Text, Colour Tint = Colour::Normal);

  Session Sess;
  View Current {View::Titles};

  ListView Titles;
  ListView Paths;
  size_t PathCategory {0};

  std::string StatusText;
  Colour StatusTint {Colour::Normal};
  bool Quit {false};
  bool Dirty {false};
};

} // namespace FastPPCx86::Launcher::TUI
