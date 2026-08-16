// SPDX-License-Identifier: MIT
#include "UI.h"

#include <algorithm>
#include <clocale>
#include <ncurses.h>

namespace FastPPCx86::Launcher::TUI {

namespace {
  short PairFor(Colour C) {
    return static_cast<short>(static_cast<int>(C) + 1);
  }

  bool ColourEnabled = false;

  constexpr int MinWidth = 20;
} // namespace

Screen::Screen() {
  // Before initscr, so ncursesw knows the locale and box-drawing plus any
  // non-ASCII in a title name render as characters rather than as bytes.
  std::setlocale(LC_ALL, "");

  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);
  set_escdelay(25);

  if (has_colors()) {
    start_color();
    // Default background, so the launcher sits inside whatever theme the user
    // already has rather than repainting the terminal black.
    use_default_colors();
    init_pair(PairFor(Colour::Normal), -1, -1);
    init_pair(PairFor(Colour::Dim), COLOR_BLUE, -1);
    init_pair(PairFor(Colour::Header), COLOR_CYAN, -1);
    init_pair(PairFor(Colour::Selected), COLOR_BLACK, COLOR_CYAN);
    init_pair(PairFor(Colour::Ok), COLOR_GREEN, -1);
    init_pair(PairFor(Colour::Warning), COLOR_YELLOW, -1);
    init_pair(PairFor(Colour::Error), COLOR_RED, -1);
    init_pair(PairFor(Colour::Accent), COLOR_MAGENTA, -1);
    Colours = true;
    ColourEnabled = true;
  }
}

Screen::~Screen() {
  curs_set(1);
  endwin();
  ColourEnabled = false;
}

int Screen::Rows() const {
  return LINES;
}

int Screen::Cols() const {
  return COLS;
}

void Attr(Colour C, bool On) {
  if (!ColourEnabled) {
    // Without colour, the selection still has to be visible.
    if (C == Colour::Selected) {
      On ? attron(A_REVERSE) : attroff(A_REVERSE);
    } else if (C == Colour::Header) {
      On ? attron(A_BOLD) : attroff(A_BOLD);
    }
    return;
  }
  const auto Attribute = COLOR_PAIR(PairFor(C)) | (C == Colour::Header ? A_BOLD : 0);
  On ? attron(Attribute) : attroff(Attribute);
}

void Write(int Row, int Col, std::string_view Text, Colour C) {
  if (Row < 0 || Row >= LINES || Col >= COLS) {
    return;
  }
  Attr(C, true);
  mvaddnstr(Row, Col, Text.data(), static_cast<int>(std::min<size_t>(Text.size(), static_cast<size_t>(COLS - Col))));
  Attr(C, false);
}

void WriteField(int Row, int Col, int Width, std::string_view Text, Colour C) {
  if (Width <= 0) {
    return;
  }
  std::string Padded = Ellipsise(Text, Width);
  Padded.append(static_cast<size_t>(Width) - std::min<size_t>(Padded.size(), static_cast<size_t>(Width)), ' ');
  Write(Row, Col, Padded, C);
}

void HorizontalRule(int Row, int Col, int Width, Colour C) {
  if (Width <= 0) {
    return;
  }
  Write(Row, Col, std::string(static_cast<size_t>(Width), '-'), C);
}

void ClearRow(int Row) {
  if (Row < 0 || Row >= LINES) {
    return;
  }
  move(Row, 0);
  clrtoeol();
}

std::string Ellipsise(std::string_view Text, int Width) {
  if (Width <= 0) {
    return {};
  }
  if (Text.size() <= static_cast<size_t>(Width)) {
    return std::string {Text};
  }
  if (Width <= 3) {
    return std::string {Text.substr(0, static_cast<size_t>(Width))};
  }
  return std::string {Text.substr(0, static_cast<size_t>(Width) - 3)} + "...";
}

std::vector<std::string> Wrap(std::string_view Text, int Width) {
  std::vector<std::string> Lines;
  if (Width <= 0) {
    return Lines;
  }

  std::string Current;
  size_t Pos {};
  while (Pos < Text.size()) {
    const auto NewLine = Text.find('\n', Pos);
    const auto Paragraph = Text.substr(Pos, NewLine == std::string_view::npos ? std::string_view::npos : NewLine - Pos);

    Current.clear();
    size_t WordStart {};
    while (WordStart <= Paragraph.size()) {
      auto Space = Paragraph.find(' ', WordStart);
      if (Space == std::string_view::npos) {
        Space = Paragraph.size();
      }
      const auto Word = Paragraph.substr(WordStart, Space - WordStart);

      if (!Current.empty() && Current.size() + 1 + Word.size() > static_cast<size_t>(Width)) {
        Lines.push_back(Current);
        Current.clear();
      }
      if (Word.size() > static_cast<size_t>(Width)) {
        // A single word longer than the column: hard-split it rather than
        // letting it run off the edge.
        size_t Offset {};
        while (Offset < Word.size()) {
          Lines.emplace_back(Word.substr(Offset, static_cast<size_t>(Width)));
          Offset += static_cast<size_t>(Width);
        }
      } else {
        if (!Current.empty()) {
          Current += ' ';
        }
        Current += Word;
      }

      if (Space == Paragraph.size()) {
        break;
      }
      WordStart = Space + 1;
    }
    if (!Current.empty()) {
      Lines.push_back(Current);
    }

    if (NewLine == std::string_view::npos) {
      break;
    }
    Pos = NewLine + 1;
  }

  return Lines;
}

void ListView::SetItems(std::vector<ListItem> Items) {
  Entries = std::move(Items);
  if (Cursor >= static_cast<int>(Entries.size())) {
    Cursor = Entries.empty() ? 0 : static_cast<int>(Entries.size()) - 1;
  }
}

void ListView::Select(int Index) {
  if (Entries.empty()) {
    Cursor = 0;
    return;
  }
  Cursor = std::clamp(Index, 0, static_cast<int>(Entries.size()) - 1);
}

void ListView::Clamp(int VisibleRows) {
  if (Entries.empty() || VisibleRows <= 0) {
    Offset = 0;
    return;
  }
  Cursor = std::clamp(Cursor, 0, static_cast<int>(Entries.size()) - 1);
  if (Cursor < Offset) {
    Offset = Cursor;
  }
  if (Cursor >= Offset + VisibleRows) {
    Offset = Cursor - VisibleRows + 1;
  }
  Offset = std::max(0, std::min(Offset, std::max(0, static_cast<int>(Entries.size()) - VisibleRows)));
}

bool ListView::HandleKey(int Key, int VisibleRows) {
  if (Entries.empty()) {
    return false;
  }
  const int Before = Cursor;
  switch (Key) {
  case KEY_UP:
  case 'k': --Cursor; break;
  case KEY_DOWN:
  case 'j': ++Cursor; break;
  case KEY_PPAGE: Cursor -= std::max(1, VisibleRows - 1); break;
  case KEY_NPAGE: Cursor += std::max(1, VisibleRows - 1); break;
  case KEY_HOME:
  case 'g': Cursor = 0; break;
  case KEY_END:
  case 'G': Cursor = static_cast<int>(Entries.size()) - 1; break;
  default: return false;
  }
  Cursor = std::clamp(Cursor, 0, static_cast<int>(Entries.size()) - 1);
  Clamp(VisibleRows);
  return Cursor != Before;
}

void ListView::Draw(int Row, int Col, int Width, int Height, bool Focused) const {
  const_cast<ListView*>(this)->Clamp(Height);

  for (int I = 0; I < Height; ++I) {
    const int Index = Offset + I;
    if (Index >= static_cast<int>(Entries.size())) {
      WriteField(Row + I, Col, Width, "", Colour::Normal);
      continue;
    }

    const auto& Item = Entries[Index];
    const bool IsCursor = Index == Cursor && Focused;
    const Colour Tint = IsCursor ? Colour::Selected : Item.Tint;

    std::string Line = Item.Left;
    if (!Item.Right.empty()) {
      const int RightWidth = std::min<int>(static_cast<int>(Item.Right.size()), std::max(0, Width / 2));
      const int LeftWidth = std::max(MinWidth / 2, Width - RightWidth - 2);
      Line = Ellipsise(Item.Left, LeftWidth);
      Line.append(static_cast<size_t>(std::max(0, LeftWidth - static_cast<int>(Line.size()))), ' ');
      Line += "  ";
      Line += Ellipsise(Item.Right, RightWidth);
    }
    WriteField(Row + I, Col, Width, Line, Tint);
  }

  // Scroll position, so a long list does not feel bottomless.
  if (static_cast<int>(Entries.size()) > Height && Height > 0) {
    const auto Marker = " " + std::to_string(Cursor + 1) + "/" + std::to_string(Entries.size()) + " ";
    Write(Row + Height - 1, Col + std::max(0, Width - static_cast<int>(Marker.size())), Marker, Colour::Dim);
  }
}

namespace {
  /// Draws a centred modal box and returns its interior origin.
  struct Box {
    int Row {};
    int Col {};
    int Width {};
    int Height {};
  };

  Box DrawBox(std::string_view Title, int DesiredWidth, int DesiredHeight) {
    Box B;
    B.Width = std::min(DesiredWidth, COLS - 4);
    B.Height = std::min(DesiredHeight, LINES - 4);
    B.Col = std::max(0, (COLS - B.Width) / 2);
    B.Row = std::max(0, (LINES - B.Height) / 2);

    for (int I = 0; I < B.Height; ++I) {
      WriteField(B.Row + I, B.Col, B.Width, "", Colour::Normal);
    }
    WriteField(B.Row, B.Col, B.Width, " " + std::string {Title}, Colour::Header);
    HorizontalRule(B.Row + 1, B.Col, B.Width);
    return B;
  }
} // namespace

bool Prompt(std::string_view Title, std::string_view Question, std::string& Value) {
  const auto B = DrawBox(Title, 76, 8);
  const auto Lines = Wrap(Question, B.Width - 2);
  for (size_t I = 0; I < Lines.size() && static_cast<int>(I) < B.Height - 5; ++I) {
    Write(B.Row + 2 + static_cast<int>(I), B.Col + 1, Lines[I]);
  }

  const int InputRow = B.Row + B.Height - 2;
  std::string Buffer = Value;
  int Cursor = static_cast<int>(Buffer.size());

  curs_set(1);
  for (;;) {
    const int Width = B.Width - 3;
    // Scroll the visible window so the cursor stays on screen for long paths.
    const int Start = std::max(0, Cursor - Width + 1);
    WriteField(InputRow, B.Col + 1, B.Width - 2, "> " + Buffer.substr(static_cast<size_t>(Start), static_cast<size_t>(Width)));
    move(InputRow, B.Col + 3 + (Cursor - Start));
    refresh();

    const int Key = getch();
    if (Key == 27) { // Escape
      curs_set(0);
      return false;
    }
    if (Key == '\n' || Key == KEY_ENTER) {
      curs_set(0);
      Value = Buffer;
      return true;
    }
    if (Key == KEY_BACKSPACE || Key == 127 || Key == 8) {
      if (Cursor > 0) {
        Buffer.erase(static_cast<size_t>(--Cursor), 1);
      }
      continue;
    }
    if (Key == KEY_DC) {
      if (Cursor < static_cast<int>(Buffer.size())) {
        Buffer.erase(static_cast<size_t>(Cursor), 1);
      }
      continue;
    }
    if (Key == KEY_LEFT) {
      Cursor = std::max(0, Cursor - 1);
      continue;
    }
    if (Key == KEY_RIGHT) {
      Cursor = std::min<int>(static_cast<int>(Buffer.size()), Cursor + 1);
      continue;
    }
    if (Key == KEY_HOME) {
      Cursor = 0;
      continue;
    }
    if (Key == KEY_END) {
      Cursor = static_cast<int>(Buffer.size());
      continue;
    }
    if (Key == 21) { // Ctrl-U
      Buffer.clear();
      Cursor = 0;
      continue;
    }
    if (Key >= 32 && Key < 256) {
      Buffer.insert(static_cast<size_t>(Cursor++), 1, static_cast<char>(Key));
    }
  }
}

bool Confirm(std::string_view Title, std::string_view Question) {
  const auto B = DrawBox(Title, 72, 9);
  const auto Lines = Wrap(Question, B.Width - 2);
  for (size_t I = 0; I < Lines.size() && static_cast<int>(I) < B.Height - 4; ++I) {
    Write(B.Row + 2 + static_cast<int>(I), B.Col + 1, Lines[I]);
  }
  Write(B.Row + B.Height - 2, B.Col + 1, "y = yes    n / Esc = no", Colour::Dim);
  refresh();

  for (;;) {
    const int Key = getch();
    if (Key == 'y' || Key == 'Y') {
      return true;
    }
    if (Key == 'n' || Key == 'N' || Key == 27) {
      return false;
    }
  }
}

void Message(std::string_view Title, std::string_view Text) {
  const auto Lines = Wrap(Text, std::min(76, COLS - 6) - 2);
  const auto B = DrawBox(Title, 78, static_cast<int>(Lines.size()) + 5);
  for (size_t I = 0; I < Lines.size() && static_cast<int>(I) < B.Height - 4; ++I) {
    Write(B.Row + 2 + static_cast<int>(I), B.Col + 1, Lines[I]);
  }
  Write(B.Row + B.Height - 2, B.Col + 1, "any key to continue", Colour::Dim);
  refresh();
  getch();
}

int Choose(std::string_view Title, const std::vector<std::string>& Options, int Initial) {
  if (Options.empty()) {
    return -1;
  }

  ListView List;
  std::vector<ListItem> Items;
  Items.reserve(Options.size());
  for (const auto& Option : Options) {
    Items.push_back({Option, {}, Colour::Normal, true});
  }
  List.SetItems(std::move(Items));
  List.Select(Initial);

  const int Height = std::min<int>(static_cast<int>(Options.size()) + 4, LINES - 4);
  for (;;) {
    const auto B = DrawBox(Title, 78, Height);
    List.Draw(B.Row + 2, B.Col + 1, B.Width - 2, B.Height - 3, true);
    Write(B.Row + B.Height - 1, B.Col + 1, "Enter = choose    Esc = cancel", Colour::Dim);
    refresh();

    const int Key = getch();
    if (Key == 27) {
      return -1;
    }
    if (Key == '\n' || Key == KEY_ENTER) {
      return List.Selected();
    }
    List.HandleKey(Key, Height - 3);
  }
}

void Pager(std::string_view Title, const std::vector<std::string>& Lines) {
  int Offset {};
  for (;;) {
    erase();
    WriteField(0, 0, COLS, " " + std::string {Title}, Colour::Header);

    const int Body = LINES - 2;
    for (int I = 0; I < Body; ++I) {
      const int Index = Offset + I;
      WriteField(I + 1, 0, COLS, Index < static_cast<int>(Lines.size()) ? Lines[static_cast<size_t>(Index)] : std::string {});
    }
    DrawStatusBar(LINES - 1, COLS, "up/down scroll   q close");
    refresh();

    const int Key = getch();
    if (Key == 'q' || Key == 27 || Key == '\n') {
      return;
    }
    const int MaxOffset = std::max(0, static_cast<int>(Lines.size()) - Body);
    switch (Key) {
    case KEY_UP:
    case 'k': Offset = std::max(0, Offset - 1); break;
    case KEY_DOWN:
    case 'j': Offset = std::min(MaxOffset, Offset + 1); break;
    case KEY_PPAGE: Offset = std::max(0, Offset - Body); break;
    case KEY_NPAGE: Offset = std::min(MaxOffset, Offset + Body); break;
    case KEY_HOME:
    case 'g': Offset = 0; break;
    case KEY_END:
    case 'G': Offset = MaxOffset; break;
    default: break;
    }
  }
}

void DrawStatusBar(int Row, int Width, std::string_view Hints) {
  WriteField(Row, 0, Width, " " + std::string {Hints}, Colour::Selected);
}

} // namespace FastPPCx86::Launcher::TUI
