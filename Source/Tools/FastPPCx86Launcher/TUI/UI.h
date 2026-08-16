// SPDX-License-Identifier: MIT
#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

/**
 * ncurses primitives for the terminal frontend.
 *
 * Deliberately small: a colour scheme, a scrolling list, a few modal prompts and
 * a pager. Everything above this file is launcher logic, so the terminal
 * frontend and the graphical one differ only in how they draw.
 */
namespace FastPPCx86::Launcher::TUI {

enum class Colour {
  Normal,
  Dim,
  Header,
  Selected,
  Ok,
  Warning,
  Error,
  Accent,
};

/// RAII: sets the terminal up on construction and restores it on destruction,
/// including on the way out of an exception, so a crash cannot leave the user
/// with a terminal that has no echo and no cursor.
class Screen final {
public:
  Screen();
  ~Screen();
  Screen(const Screen&) = delete;
  Screen& operator=(const Screen&) = delete;

  int Rows() const;
  int Cols() const;
  bool HasColour() const {
    return Colours;
  }

private:
  bool Colours {false};
};

void Attr(Colour C, bool On);
void Write(int Row, int Col, std::string_view Text, Colour C = Colour::Normal);
/// Writes and pads/truncates to exactly `Width` columns.
void WriteField(int Row, int Col, int Width, std::string_view Text, Colour C = Colour::Normal);
void HorizontalRule(int Row, int Col, int Width, Colour C = Colour::Dim);
void ClearRow(int Row);

/// Truncates on a character boundary, appending an ellipsis when it had to cut.
std::string Ellipsise(std::string_view Text, int Width);

/// Wraps text to `Width`, breaking on spaces where it can.
std::vector<std::string> Wrap(std::string_view Text, int Width);

struct ListItem {
  std::string Left;
  std::string Right;
  Colour Tint {Colour::Normal};
  bool Selectable {true};
};

/**
 * A scrolling list. Keeps its own selection and scroll offset so a caller only
 * has to hand it items and keys.
 */
class ListView final {
public:
  void SetItems(std::vector<ListItem> Items);
  const std::vector<ListItem>& Items() const {
    return Entries;
  }

  /// Returns true when the key moved the selection.
  bool HandleKey(int Key, int VisibleRows);
  void Draw(int Row, int Col, int Width, int Height, bool Focused) const;

  int Selected() const {
    return Cursor;
  }
  void Select(int Index);
  bool Empty() const {
    return Entries.empty();
  }

private:
  void Clamp(int VisibleRows);

  std::vector<ListItem> Entries;
  int Cursor {0};
  mutable int Offset {0};
};

/// Modal single-line text entry. Returns false when cancelled with Escape.
bool Prompt(std::string_view Title, std::string_view Question, std::string& Value);
bool Confirm(std::string_view Title, std::string_view Question);
void Message(std::string_view Title, std::string_view Text);

/// Modal chooser. Returns the chosen index, or -1 when cancelled.
int Choose(std::string_view Title, const std::vector<std::string>& Options, int Initial = 0);

/// Full-screen scrollback viewer, for the command preview and long diagnostics.
void Pager(std::string_view Title, const std::vector<std::string>& Lines);

/// The bottom key-hint bar.
void DrawStatusBar(int Row, int Width, std::string_view Hints);

} // namespace FastPPCx86::Launcher::TUI
