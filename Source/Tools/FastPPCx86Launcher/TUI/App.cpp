// SPDX-License-Identifier: MIT
#include "App.h"

#include "../Discovery.h"
#include "../Hints.h"
#include "../LaunchSpec.h"
#include "../PrefixTools.h"
#include "../ProcessProbe.h"
#include "../Recipes.h"
#include "../Runner.h"
#include "../Runtimes.h"

#include <fmt/format.h>

#include <algorithm>
#include <filesystem>
#include <functional>
#include <ncurses.h>
#include <unistd.h>

namespace FastPPCx86::Launcher::TUI {

namespace {
  namespace fs = std::filesystem;

  constexpr int HeaderRows = 2;
  constexpr int FooterRows = 2;

  std::string KindLabel(TitleKind Kind) {
    switch (Kind) {
    case TitleKind::Native: return "native";
    case TitleKind::Proton: return "proton";
    case TitleKind::Wine: return "wine";
    case TitleKind::Steam: return "steam";
    }
    return "?";
  }
} // namespace

void App::Status(std::string Text, Colour Tint) {
  StatusText = std::move(Text);
  StatusTint = Tint;
}

Title* App::CurrentTitle() {
  if (Sess.Reg().Titles.empty() || Titles.Empty()) {
    return nullptr;
  }
  const int Index = Titles.Selected();
  if (Index < 0 || Index >= static_cast<int>(Sess.Reg().Titles.size())) {
    return nullptr;
  }
  return &Sess.Reg().Titles[static_cast<size_t>(Index)];
}

const Title* App::CurrentTitle() const {
  return const_cast<App*>(this)->CurrentTitle();
}

void App::RefreshTitleList() {
  std::vector<ListItem> Items;
  Items.reserve(Sess.Reg().Titles.size());
  for (const auto& T : Sess.Reg().Titles) {
    const bool Present = T.Kind == TitleKind::Steam || Runtimes::IsRegularFile(ExpandPath(T.Exe));
    Items.push_back({fmt::format("{} {}", Present ? "*" : "!", T.Name.empty() ? T.Id : T.Name), KindLabel(T.Kind),
                     Present ? Colour::Normal : Colour::Error, true});
  }
  Titles.SetItems(std::move(Items));
}

void App::RefreshPathList() {
  const auto Category = AllRuntimeCategories[PathCategory];
  const auto& List = Sess.Reg().List(Category);
  const auto& DefaultId = Sess.Reg().Defaults.For(Category);

  std::vector<ListItem> Items;
  Items.reserve(List.size());
  for (const auto& Entry : List) {
    const auto Result = Runtimes::Validate(Category, Entry);

    std::string Location = Entry.Path;
    if (Category == RuntimeCategory::ThunkSets) {
      Location = fmt::format("host={} guest={}", Entry.HostLibs.empty() ? "(built-in)" : Entry.HostLibs,
                             Entry.GuestLibs.empty() ? "(built-in)" : Entry.GuestLibs);
    }

    const bool IsDefault = !DefaultId.empty() && DefaultId == Entry.Id;
    const char* Mark = !Entry.Enabled ? "-" : Result.Ok ? "+" : "x";
    const Colour Tint = !Entry.Enabled ? Colour::Dim : Result.Ok ? Colour::Normal : Colour::Error;

    Items.push_back({fmt::format("{} {}{}", Mark, Entry.Name.empty() ? Entry.Id : Entry.Name, IsDefault ? "  [default]" : ""),
                     Result.Ok ? Location : Result.Reason, Tint, true});
  }
  Paths.SetItems(std::move(Items));
}

void App::DrawEmptyState() {
  const int Width = std::min(COLS - 4, 76);
  const int Col = std::max(0, (COLS - Width) / 2);
  int Row = 3;

  Write(Row++, Col, "No titles configured yet.", Colour::Header);
  ++Row;

  for (const auto Line : Wrap("This launcher runs x86 games on POWER through FastPPCx86. Nothing here is "
                              "hardcoded: it looks for what you already have installed and lets you add "
                              "anything it missed.",
                              Width)) {
    Write(Row++, Col, Line);
  }
  ++Row;

  Write(Row++, Col, "What was found:", Colour::Header);
  for (const auto Category : AllRuntimeCategories) {
    const auto Summary = Sess.SummariseCategory(Category);
    const bool Any = Summary != "none found";
    Write(Row, Col + 2, fmt::format("{:<20}", DisplayName(Category)));
    Write(Row++, Col + 24, Summary, Any ? Colour::Ok : Colour::Dim);
  }
  ++Row;

  Write(Row++, Col, "s   scan your game libraries and import what you want", Colour::Accent);
  Write(Row++, Col, "p   manage locations: libraries, emulator builds, RootFS, Proton, Wine, DXVK, VKD3D", Colour::Accent);
  Write(Row++, Col, "?   help");
}

void App::DrawDetail(int Row, int Col, int Width, int Height) {
  const Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  int Line = Row;
  const auto Put = [&](std::string_view Label, std::string_view Value, Colour Tint = Colour::Normal) {
    if (Line >= Row + Height) {
      return;
    }
    WriteField(Line, Col, 18, Label, Colour::Dim);
    WriteField(Line, Col + 18, Width - 18, Value, Tint);
    ++Line;
  };

  Put("Name", T->Name);
  Put("Kind", KindLabel(T->Kind));
  const auto Exe = ExpandPath(T->Exe);
  Put("Executable", Exe, Runtimes::IsRegularFile(Exe) || T->Kind == TitleKind::Steam ? Colour::Normal : Colour::Error);
  Put("Render", std::string {ToString(T->Render)});
  ++Line;

  // The resolved runtime stack. This is the answer to "what will actually run",
  // which is the question the whole launcher exists to make answerable.
  if (Line < Row + Height) {
    Write(Line++, Col, "Runtime stack", Colour::Header);
  }
  for (const auto Category : AllRuntimeCategories) {
    if (Category == RuntimeCategory::Libraries) {
      continue;
    }
    if (Category == RuntimeCategory::Proton && T->Kind != TitleKind::Proton) {
      continue;
    }
    if (Category == RuntimeCategory::Wine && T->Kind != TitleKind::Wine) {
      continue;
    }
    const RuntimeEntry* Entry = Sess.Reg().Resolve(Category, *T);
    const bool Explicit = !T->Use.For(Category).empty();
    Put(std::string {DisplayName(Category)}, Entry ? fmt::format("{}{}", Entry->Name, Explicit ? "" : "   (inherited)") : "(none)",
        Entry ? Colour::Normal : Colour::Dim);
  }

  if (const RuntimeEntry* Build = Sess.Reg().Resolve(RuntimeCategory::EmulatorBuilds, *T)) {
    if (const auto Paths = Runtimes::ResolveEmulator(*Build)) {
      Put("  built", Runtimes::DescribeModificationTime(Paths->FEX), Colour::Dim);
    }
  }
  ++Line;

  if (Line < Row + Height) {
    Write(Line++, Col, "Tuning", Colour::Header);
  }
  const auto Recipe = Recipes::ClassifySMC(T->Fex);
  Put("SMC recipe", std::string {Recipe}, Recipe == "custom" ? Colour::Warning : Colour::Normal);
  for (const auto& [Key, Value] : T->Fex) {
    if (Key.rfind("SMC", 0) == 0) {
      continue;
    }
    Put("  FEX_" + Key, Value);
  }
  ++Line;

  // Build the spec to show the cage and every diagnostic. It is cheap and it is
  // the same call the launch itself makes, so what is shown here cannot differ
  // from what happens on Enter.
  const auto Spec = Build(Sess.Reg(), *T);
  if (Line < Row + Height) {
    Write(Line++, Col, "CPU cage", Colour::Header);
  }
  for (const auto& Wrapped : Wrap(Spec.CageExplanation, Width)) {
    if (Line < Row + Height) {
      Write(Line++, Col, Wrapped, Colour::Dim);
    }
  }

  if (!Spec.Diagnostics.empty()) {
    ++Line;
    if (Line < Row + Height) {
      Write(Line++, Col, "Notes", Colour::Header);
    }
    for (const auto& D : Spec.Diagnostics) {
      const Colour Tint = D.Severity == Diagnostic::Level::Error   ? Colour::Error :
                          D.Severity == Diagnostic::Level::Warning ? Colour::Warning :
                                                                     Colour::Dim;
      for (const auto& Wrapped : Wrap(D.Text, Width - 2)) {
        if (Line < Row + Height) {
          Write(Line++, Col + 2, Wrapped, Tint);
        }
      }
    }
  }
}

void App::DrawTitles() {
  const int Body = LINES - HeaderRows - FooterRows;
  const int ListWidth = std::max(24, COLS / 3);

  Titles.Draw(HeaderRows, 0, ListWidth, Body, true);
  for (int I = 0; I < Body; ++I) {
    Write(HeaderRows + I, ListWidth, "|", Colour::Dim);
  }
  DrawDetail(HeaderRows, ListWidth + 2, COLS - ListWidth - 2, Body);
}

void App::DrawPaths() {
  const auto Category = AllRuntimeCategories[PathCategory];

  std::string Tabs;
  for (size_t I = 0; I < AllRuntimeCategories.size(); ++I) {
    if (I) {
      Tabs += "  ";
    }
    Tabs += I == PathCategory ? "[" + std::string {DisplayName(AllRuntimeCategories[I])} + "]" :
                                std::string {DisplayName(AllRuntimeCategories[I])};
  }
  WriteField(HeaderRows, 0, COLS, Ellipsise(Tabs, COLS), Colour::Dim);

  const int Body = LINES - HeaderRows - FooterRows - 3;
  Paths.Draw(HeaderRows + 2, 0, COLS, Body, true);

  // What was searched, so an empty category is actionable rather than blank.
  if (Sess.Reg().List(Category).empty()) {
    const auto& Searched = Sess.LastReport().Searched[static_cast<size_t>(Category)];
    int Line = HeaderRows + 3;
    Write(Line++, 2, "Nothing found here. Searched:", Colour::Dim);
    for (size_t I = 0; I < Searched.size() && Line < LINES - FooterRows; ++I) {
      Write(Line++, 4, Ellipsise(Searched[I], COLS - 6), Colour::Dim);
    }
    Write(Line + 1, 2, "Press a to add a location by hand.", Colour::Accent);
  }
}

void App::Draw() {
  erase();

  const auto Title = Current == View::Paths ? std::string {"FastPPCx86 launcher - locations"} : std::string {"FastPPCx86 launcher"};
  WriteField(0, 0, COLS, " " + Title, Colour::Header);
  HorizontalRule(1, 0, COLS);

  switch (Current) {
  case View::Empty: DrawEmptyState(); break;
  case View::Titles: DrawTitles(); break;
  case View::Paths: DrawPaths(); break;
  }

  ClearRow(LINES - 2);
  if (!StatusText.empty()) {
    Write(LINES - 2, 1, Ellipsise(StatusText, COLS - 2), StatusTint);
  }

  const char* Hints = Current == View::Paths ? "left/right category  a add  e edit  d delete  space enable  * default  r rescan  Esc back  "
                                               "q quit" :
                                               "Enter launch  c command  t tuning  u runtimes  s scan  p paths  e edit  D delete  ? help  "
                                               "q quit";
  DrawStatusBar(LINES - 1, COLS, Hints);
  refresh();
}

void App::LaunchCurrent() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  // Side effects first (installing a selected DXVK/VKD3D into the prefix), then
  // build, so the command picks up any WINEDLLOVERRIDES that produced.
  const auto Prepared = Prepare(Sess.Reg(), *T);

  const auto Spec = Build(Sess.Reg(), *T);
  if (!Spec.Ok) {
    std::vector<std::string> Lines;
    for (const auto& D : Spec.Diagnostics) {
      for (auto& Wrapped : Wrap(D.Text, COLS - 4)) {
        Lines.push_back(std::move(Wrapped));
      }
      Lines.emplace_back();
    }
    Pager("Cannot launch " + T->Name, Lines);
    return;
  }

  Runner Run;
  std::string Error;
  if (!Run.Start(Spec, Error)) {
    Message("Launch failed", Error);
    return;
  }

  // Live output view. Kept to a bounded ring: a chatty title can emit megabytes
  // and the full text is on disk in the log anyway.
  std::vector<std::string> Lines;
  // Anything the prepare step did (a DXVK install, or why one was skipped) goes
  // in above the title's own output rather than into a dialog nobody reads.
  for (const auto& D : Prepared.Diagnostics) {
    for (auto& Wrapped : Wrap(D.Text, COLS - 4)) {
      Lines.push_back("== " + Wrapped);
    }
  }
  std::string Partial;
  constexpr size_t MaxLines = 5000;
  bool Follow = true;
  int Offset {};

  nodelay(stdscr, TRUE);
  const auto Append = [&](std::string_view Chunk) {
    for (const char C : Chunk) {
      if (C == '\n') {
        Lines.push_back(Partial);
        Partial.clear();
        if (Lines.size() > MaxLines) {
          Lines.erase(Lines.begin(), Lines.begin() + static_cast<long>(Lines.size() - MaxLines));
        }
      } else if (C != '\r') {
        Partial += C;
      }
    }
  };

  bool Active = true;
  while (Active) {
    Active = Run.Poll(Append);

    erase();
    WriteField(0, 0, COLS, fmt::format(" Running {}  (pid {})", T->Name, Run.Pid()), Colour::Header);
    HorizontalRule(1, 0, COLS);

    const int Body = LINES - 4;
    const int MaxOffset = std::max(0, static_cast<int>(Lines.size()) - Body);
    if (Follow) {
      Offset = MaxOffset;
    }
    for (int I = 0; I < Body; ++I) {
      const int Index = Offset + I;
      WriteField(2 + I, 0, COLS, Index < static_cast<int>(Lines.size()) ? Lines[static_cast<size_t>(Index)] : std::string {});
    }

    WriteField(LINES - 2, 0, COLS, fmt::format(" log: {}", Spec.LogPath), Colour::Dim);
    DrawStatusBar(LINES - 1, COLS, Active ? "s stop  k kill  v verify environment  up/down scroll  f follow" : "any key to return");
    refresh();

    const int Key = getch();
    switch (Key) {
    case 's':
      Run.RequestStop();
      Status("Asked the title to stop.");
      break;
    case 'k':
      Run.Kill();
      Status("Killed the process group.");
      break;
    case KEY_UP:
      Follow = false;
      Offset = std::max(0, Offset - 1);
      break;
    case KEY_DOWN:
      Follow = false;
      Offset = std::min(MaxOffset, Offset + 1);
      break;
    case KEY_PPAGE:
      Follow = false;
      Offset = std::max(0, Offset - Body);
      break;
    case KEY_NPAGE:
      Follow = false;
      Offset = std::min(MaxOffset, Offset + Body);
      break;
    case 'f': Follow = true; break;
    case 'v': {
      // Read the FEX_* environment back off the live process and compare it
      // with what we asked for. This is the check docs/GAMING.md tells people
      // to do by hand, and the reason it is worth doing is that config layers
      // and AppConfig files sit between an intended setting and the process.
      std::vector<std::string> Report;
      const auto Guest = ProcessProbe::FindGuest(Run.Pid());
      if (!Guest) {
        Report.emplace_back("No emulator process found under this run yet.");
      } else {
        Report.push_back(fmt::format("pid {}  {}", Guest->Pid, Guest->Exe));
        if (Guest->ExeDeleted) {
          Report.emplace_back("");
          Report.emplace_back("WARNING: this process's binary has been deleted or replaced since it started.");
          Report.emplace_back("It is running a build that no longer exists on disk. A rebuild under a running");
          Report.emplace_back("title does this, and any A/B you are measuring is against the old binary.");
        }
        Report.emplace_back("");

        const auto Comparison = ProcessProbe::Compare(Spec.FexVars(), Guest->FexVars);
        if (Comparison.Matches()) {
          Report.emplace_back("Every FEX_* variable matches what the launcher set.");
        }
        for (const auto& D : Comparison.Differences) {
          Report.push_back(D.Missing ? fmt::format("MISSING  {} (expected {})", D.Key, D.Expected) :
                                       fmt::format("DIFFERS  {}: expected {}, process has {}", D.Key, D.Expected, D.Actual));
        }
        for (const auto& Key : Comparison.Unexpected) {
          Report.push_back(fmt::format("EXTRA    {}={}  (from a config layer or a stale export)", Key, Guest->FexVars.at(Key)));
        }
        Report.emplace_back("");
        Report.emplace_back("Full environment of the running process:");
        for (const auto& [Key, Value] : Guest->FexVars) {
          Report.push_back(fmt::format("  {}={}", Key, Value));
        }
      }
      nodelay(stdscr, FALSE);
      Pager("Verify - what the running process actually has", Report);
      nodelay(stdscr, TRUE);
      break;
    }
    default:
      if (!Active && Key != ERR) {
        nodelay(stdscr, FALSE);
        Status(fmt::format("{} {} - log: {}", T->Name, Run.ExitSummary(), Spec.LogPath));
        return;
      }
      break;
    }

    if (Active) {
      ::usleep(40 * 1000);
    }
  }

  if (!Partial.empty()) {
    Lines.push_back(Partial);
  }
  nodelay(stdscr, FALSE);
  Status(fmt::format("{} {} - log: {}", T->Name, Run.ExitSummary(), Spec.LogPath), Colour::Accent);
}

void App::ShowCommand() {
  const Title* T = CurrentTitle();
  if (!T) {
    return;
  }
  const auto Spec = Build(Sess.Reg(), *T);

  std::vector<std::string> Lines;
  Lines.emplace_back("This is exactly what a launch runs. It is generated from the same");
  Lines.emplace_back("command the launcher executes, so it cannot describe a different one.");
  Lines.emplace_back();
  for (auto& Line : Wrap(Spec.ShellCommand(), COLS - 2)) {
    Lines.push_back(std::move(Line));
  }
  Lines.emplace_back();
  Lines.emplace_back("FEX_* variables this sets:");
  for (const auto& [Key, Value] : Spec.FexVars()) {
    Lines.push_back(fmt::format("  {}={}", Key, Value));
  }
  if (!Spec.Diagnostics.empty()) {
    Lines.emplace_back();
    Lines.emplace_back("Notes:");
    for (const auto& D : Spec.Diagnostics) {
      for (auto& Line : Wrap(D.Text, COLS - 4)) {
        Lines.push_back("  " + Line);
      }
    }
  }

  Pager("Command for " + T->Name, Lines);
}

void App::EditTuning() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  for (;;) {
    std::vector<std::string> Options;
    std::vector<std::function<void()>> Actions;

    const auto Recipe = Recipes::ClassifySMC(T->Fex);
    Options.push_back(fmt::format("SMC recipe: {}", Recipe));
    Actions.emplace_back([&] {
      std::vector<std::string> Names {"unset (leave it to the config layers)"};
      std::vector<std::string> Ids {"unset"};
      for (const auto& R : Recipes::SMC()) {
        Names.push_back(fmt::format("{} - {}", R.Name, Ellipsise(R.Summary, std::max(20, COLS - 40))));
        Ids.emplace_back(R.Id);
      }
      const int Choice = Choose("Self-modifying-code recipe", Names);
      if (Choice < 0) {
        return;
      }
      if (const auto* R = Recipes::FindSMC(Ids[static_cast<size_t>(Choice)]); R && R->Risky) {
        if (!Confirm("Are you sure?", std::string {R->Summary})) {
          return;
        }
      }
      Recipes::ApplySMC(T->Fex, Ids[static_cast<size_t>(Choice)]);
      Dirty = true;
    });

    for (const auto& K : Recipes::Knobs()) {
      const bool On = Recipes::KnobIsOn(T->Fex, K);
      const auto Found = T->Fex.find(std::string {K.Key});
      const std::string Value = Found == T->Fex.end() ? std::string {} : Found->second;

      const char* GroupTag = K.Group == Recipes::KnobGroup::Unsound    ? " [UNSOUND]" :
                             K.Group == Recipes::KnobGroup::Diagnostic ? " [diagnostic]" :
                                                                         "";
      Options.push_back(fmt::format("[{}] {}{}{}", On ? "x" : " ", K.Label, GroupTag, On && !Value.empty() ? " = " + Value : ""));

      Actions.emplace_back([&, &Knob = K] {
        const bool CurrentlyOn = Recipes::KnobIsOn(T->Fex, Knob);
        if (CurrentlyOn) {
          Recipes::SetKnob(T->Fex, Knob, false);
          Dirty = true;
          return;
        }

        if (Knob.Group == Recipes::KnobGroup::Unsound && !Confirm("This option is unsound", std::string {Knob.Summary})) {
          return;
        }

        if (Knob.Kind == Recipes::KnobKind::Integer) {
          std::string Entered {Knob.OnValue};
          if (!Prompt(std::string {Knob.Label}, std::string {Knob.Summary}, Entered) || Entered.empty()) {
            return;
          }
          Recipes::SetKnob(T->Fex, Knob, true, Entered);
        } else if (Knob.Kind == Recipes::KnobKind::Choice && !Knob.Values.empty()) {
          std::vector<std::string> Names;
          for (const auto& V : Knob.Values) {
            Names.emplace_back(V);
          }
          const int Choice = Choose(std::string {Knob.Label}, Names);
          if (Choice < 0) {
            return;
          }
          Recipes::SetKnob(T->Fex, Knob, true, Knob.Values[static_cast<size_t>(Choice)]);
        } else {
          Recipes::SetKnob(T->Fex, Knob, true);
        }
        Dirty = true;
      });
    }

    Options.emplace_back("Show what each option does");
    Actions.emplace_back([&] {
      std::vector<std::string> Lines;
      for (const auto& R : Recipes::SMC()) {
        Lines.push_back(R.Name.empty() ? std::string {R.Id} : std::string {R.Name});
        for (auto& Line : Wrap(R.Summary, COLS - 4)) {
          Lines.push_back("  " + Line);
        }
        Lines.emplace_back();
      }
      for (const auto& K : Recipes::Knobs()) {
        Lines.push_back(fmt::format("FEX_{} - {}", K.Key, K.Label));
        for (auto& Line : Wrap(K.Summary, COLS - 4)) {
          Lines.push_back("  " + Line);
        }
        if (K.PresenceTested) {
          Lines.emplace_back("  NOTE: presence-tested. Setting it to 0 enables it; it has to be removed.");
        }
        Lines.emplace_back();
      }
      Pager("What these options do", Lines);
    });

    const int Choice = Choose("Tuning - " + T->Name, Options);
    if (Choice < 0) {
      break;
    }
    Actions[static_cast<size_t>(Choice)]();
  }

  if (Dirty) {
    SaveNow();
  }
}

void App::EditRuntimes() {
  Title* T = CurrentTitle();
  if (!T) {
    return;
  }

  for (;;) {
    std::vector<RuntimeCategory> Categories;
    std::vector<std::string> Options;
    for (const auto Category : AllRuntimeCategories) {
      if (Category == RuntimeCategory::Libraries) {
        continue; // Not a per-title choice: the scanner walks all of them.
      }
      const RuntimeEntry* Resolved = Sess.Reg().Resolve(Category, *T);
      const bool Explicit = !T->Use.For(Category).empty();
      Options.push_back(
        fmt::format("{:<20} {}{}", DisplayName(Category), Resolved ? Resolved->Name : "(none available)", Explicit ? "" : "   (inherited)"));
      Categories.push_back(Category);
    }

    const int Choice = Choose("Runtimes for " + T->Name, Options);
    if (Choice < 0) {
      break;
    }

    const auto Category = Categories[static_cast<size_t>(Choice)];
    const auto& List = Sess.Reg().List(Category);

    std::vector<std::string> Names {"(inherit the default)"};
    std::vector<std::string> Ids {""};
    for (const auto& Entry : List) {
      if (!Entry.Enabled) {
        continue;
      }
      const auto Result = Runtimes::Validate(Category, Entry);
      Names.push_back(fmt::format("{}{}", Entry.Name, Result.Ok ? "" : "  [unusable: " + Result.Reason + "]"));
      Ids.push_back(Entry.Id);
    }

    if (Names.size() == 1) {
      Message(std::string {DisplayName(Category)}, "Nothing is configured in this category yet. Add a location from the locations screen "
                                                   "(p).");
      continue;
    }

    const int Pick = Choose(std::string {DisplayName(Category)}, Names);
    if (Pick < 0) {
      continue;
    }
    T->Use.For(Category) = Ids[static_cast<size_t>(Pick)];
    Dirty = true;
  }

  if (Dirty) {
    SaveNow();
  }
}

void App::ScanAndImport() {
  Status("Scanning game libraries...");
  Draw();

  const auto Candidates = Discovery::ScanLibraries(Sess.Reg());
  if (Candidates.empty()) {
    Message("Scan", "Nothing found. Check the game libraries on the locations screen (p) -- add the "
                    "directory your games live in if it is not listed.");
    Status("");
    return;
  }

  const auto AllHints = Hints::Load();

  std::vector<std::string> Options;
  Options.reserve(Candidates.size());
  for (const auto& C : Candidates) {
    Options.push_back(fmt::format("{:<30} {}", Ellipsise(C.Name, 30), Ellipsise(C.Path, std::max(20, COLS - 40))));
  }

  for (;;) {
    const int Choice = Choose(fmt::format("Scan found {} candidates - pick one to add", Candidates.size()), Options);
    if (Choice < 0) {
      break;
    }

    const auto& C = Candidates[static_cast<size_t>(Choice)];
    Title T;
    T.Name = C.Name;
    T.Id = MakeId(C.Name);
    // Keep ids unique so two titles with the same folder name can coexist.
    int Suffix = 2;
    while (Sess.Reg().FindTitle(T.Id)) {
      T.Id = fmt::format("{}-{}", MakeId(C.Name), Suffix++);
    }
    T.Kind = C.Kind;
    T.Exe = C.Path;
    T.WorkDir = C.WorkDir;

    const auto Basename = fs::path {C.Path}.filename().string();
    if (const Hints::Hint* Hint = Hints::Match(AllHints, Basename, C.SteamAppId)) {
      std::string Summary = Hint->Why + "\n\nThis would set: ";
      for (const auto& [Key, Value] : Hint->Fex) {
        Summary += fmt::format("FEX_{}={} ", Key, Value);
      }
      if (Confirm("Known tuning for " + C.Name, Summary)) {
        T.Fex = Hint->Fex;
      }
    }

    Sess.Reg().Titles.push_back(std::move(T));
    Dirty = true;
    RefreshTitleList();
    Status(fmt::format("Added {}.", C.Name), Colour::Ok);
  }

  if (Dirty) {
    SaveNow();
  }
  if (!Sess.Reg().Titles.empty()) {
    Current = View::Titles;
  }
}

void App::AddPathEntry() {
  const auto Category = AllRuntimeCategories[PathCategory];

  RuntimeEntry Entry;
  if (Category == RuntimeCategory::ThunkSets) {
    if (!Prompt("Host thunk directory",
                "Directory holding the host-side thunk libraries. Leave empty to keep the "
                "emulator's built-in path.",
                Entry.HostLibs)) {
      return;
    }
    if (!Prompt("Guest thunk directory",
                "Directory holding the guest-side stub libraries. These two are one setting "
                "because a host half from one build with a guest half from another fails at "
                "the call boundary, far from anything that points at the cause.",
                Entry.GuestLibs)) {
      return;
    }
    Prompt("Thunk config", "Optional ThunksDB JSON. Leave empty for the default.", Entry.ThunkConfig);
  } else {
    if (!Prompt(std::string {DisplayName(Category)},
                "Path to add. ~ and $VARS are kept as you type them and expanded "
                "when used, so this registry stays valid on another machine.",
                Entry.Path)) {
      return;
    }
    if (Entry.Path.empty()) {
      return;
    }
  }

  Entry.Name = Category == RuntimeCategory::ThunkSets ? "Custom thunks" : fs::path {ExpandPath(Entry.Path)}.filename().string();
  if (Entry.Name.empty()) {
    Entry.Name = Entry.Path;
  }
  Prompt("Name", "A label for this entry.", Entry.Name);

  const auto Result = Runtimes::Validate(Category, Entry);
  if (!Result.Ok && !Confirm("This does not look usable", Result.Reason + "\n\nAdd it anyway?")) {
    return;
  }

  Sess.Reg().Add(Category, std::move(Entry));
  Dirty = true;
  RefreshPathList();
  SaveNow();
  Status("Added.", Colour::Ok);
}

void App::RemovePathEntry() {
  const auto Category = AllRuntimeCategories[PathCategory];
  auto& List = Sess.Reg().List(Category);
  const int Index = Paths.Selected();
  if (Index < 0 || Index >= static_cast<int>(List.size())) {
    return;
  }

  const auto& Entry = List[static_cast<size_t>(Index)];
  if (!Confirm("Remove entry", fmt::format("Remove '{}'? This only forgets the location; nothing on disk is touched.", Entry.Name))) {
    return;
  }

  // Any title pointing at it falls back to the default rather than breaking.
  const auto RemovedId = Entry.Id;
  List.erase(List.begin() + Index);
  for (auto& T : Sess.Reg().Titles) {
    if (T.Use.For(Category) == RemovedId) {
      T.Use.For(Category).clear();
    }
  }
  if (Sess.Reg().Defaults.For(Category) == RemovedId) {
    Sess.Reg().Defaults.For(Category).clear();
  }

  Dirty = true;
  RefreshPathList();
  SaveNow();
  Status("Removed.", Colour::Ok);
}

void App::ToggleEntryEnabled() {
  const auto Category = AllRuntimeCategories[PathCategory];
  auto& List = Sess.Reg().List(Category);
  const int Index = Paths.Selected();
  if (Index < 0 || Index >= static_cast<int>(List.size())) {
    return;
  }
  List[static_cast<size_t>(Index)].Enabled = !List[static_cast<size_t>(Index)].Enabled;
  Dirty = true;
  RefreshPathList();
  SaveNow();
}

void App::SetEntryAsDefault() {
  const auto Category = AllRuntimeCategories[PathCategory];
  const auto& List = Sess.Reg().List(Category);
  const int Index = Paths.Selected();
  if (Index < 0 || Index >= static_cast<int>(List.size())) {
    return;
  }
  Sess.Reg().Defaults.For(Category) = List[static_cast<size_t>(Index)].Id;
  Dirty = true;
  RefreshPathList();
  SaveNow();
  Status("Set as the default for titles that do not choose one.", Colour::Ok);
}

void App::Rescan() {
  const auto Report = Sess.Rescan();
  RefreshPathList();
  Dirty = true;
  SaveNow();
  Status(Report.TotalAdded() > 0 ? fmt::format("Rescan added {} new location(s).", Report.TotalAdded()) :
                                   "Rescan found nothing new. Your own entries were left alone.",
         Report.TotalAdded() > 0 ? Colour::Ok : Colour::Normal);
}

void App::SaveNow() {
  std::string Error;
  if (!Sess.Save(Error)) {
    Status("Could not save: " + Error, Colour::Error);
    return;
  }
  Dirty = false;
}

void App::ShowHelp() {
  std::vector<std::string> Lines {
    "FastPPCx86 launcher",
    "",
    "Titles",
    "  Enter    launch the selected title",
    "  c        show the exact command a launch would run",
    "  t        tuning: SMC recipe and the FEX_* knobs, with what each one does",
    "  u        runtimes: which emulator build, RootFS, thunks, Proton, DXVK this title uses",
    "  e        edit name, executable, arguments and working directory",
    "  D        remove the title from the launcher",
    "  s        scan the game libraries for new titles",
    "  p        locations",
    "",
    "Locations",
    "  left/right   switch category",
    "  a            add a location by hand",
    "  d            remove",
    "  space        enable or disable",
    "  *            make it the default for titles that do not choose",
    "  r            rescan (adds what is new, never removes what you added)",
    "",
    "While a title runs",
    "  v        read the FEX_* environment back off the live process and compare it",
    "           with what was asked for, and flag a binary replaced since launch",
    "  s / k    stop or kill the whole process group",
    "",
    "Everything is stored in:",
    "  " + RegistryPath(),
    "",
    "Paths are saved exactly as typed. ~ and $VARS are expanded when used, so this",
    "file stays valid if you copy it to another machine or another account.",
  };
  Pager("Help", Lines);
}

bool App::HandleTitlesKey(int Key) {
  const int Body = LINES - HeaderRows - FooterRows;
  if (Titles.HandleKey(Key, Body)) {
    return true;
  }

  switch (Key) {
  case '\n':
  case KEY_ENTER: LaunchCurrent(); return true;
  case 'c': ShowCommand(); return true;
  case 't': EditTuning(); return true;
  case 'u': EditRuntimes(); return true;
  case 's': ScanAndImport(); return true;
  case 'p':
    Current = View::Paths;
    RefreshPathList();
    return true;
  case 'e': {
    Title* T = CurrentTitle();
    if (!T) {
      return true;
    }
    Prompt("Name", "Display name.", T->Name);
    Prompt("Executable", "Path to the game binary or .exe.", T->Exe);
    Prompt("Working directory", "Leave empty to use the directory holding the executable.", T->WorkDir);
    std::string Args;
    for (const auto& Arg : T->Args) {
      if (!Args.empty()) {
        Args += ' ';
      }
      Args += Arg;
    }
    if (Prompt("Arguments", "Passed to the title, separated by spaces.", Args)) {
      T->Args.clear();
      size_t Pos {};
      while (Pos < Args.size()) {
        const auto Space = Args.find(' ', Pos);
        const auto Word = Args.substr(Pos, Space == std::string::npos ? std::string::npos : Space - Pos);
        if (!Word.empty()) {
          T->Args.push_back(Word);
        }
        if (Space == std::string::npos) {
          break;
        }
        Pos = Space + 1;
      }
    }
    Dirty = true;
    RefreshTitleList();
    SaveNow();
    return true;
  }
  case 'D': {
    Title* T = CurrentTitle();
    if (T && Confirm("Remove title", fmt::format("Remove '{}' from the launcher? The game itself is not touched.", T->Name))) {
      Sess.Reg().Titles.erase(Sess.Reg().Titles.begin() + Titles.Selected());
      Dirty = true;
      RefreshTitleList();
      SaveNow();
    }
    return true;
  }
  default: return false;
  }
}

bool App::HandlePathsKey(int Key) {
  const int Body = LINES - HeaderRows - FooterRows - 3;
  if (Paths.HandleKey(Key, Body)) {
    return true;
  }

  switch (Key) {
  case KEY_LEFT:
    PathCategory = (PathCategory + AllRuntimeCategories.size() - 1) % AllRuntimeCategories.size();
    Paths.Select(0);
    RefreshPathList();
    return true;
  case KEY_RIGHT:
    PathCategory = (PathCategory + 1) % AllRuntimeCategories.size();
    Paths.Select(0);
    RefreshPathList();
    return true;
  case 'a': AddPathEntry(); return true;
  case 'd': RemovePathEntry(); return true;
  case ' ': ToggleEntryEnabled(); return true;
  case '*': SetEntryAsDefault(); return true;
  case 'r': Rescan(); return true;
  case 'e': {
    const auto Category = AllRuntimeCategories[PathCategory];
    auto& List = Sess.Reg().List(Category);
    const int Index = Paths.Selected();
    if (Index < 0 || Index >= static_cast<int>(List.size())) {
      return true;
    }
    auto& Entry = List[static_cast<size_t>(Index)];
    Prompt("Name", "A label for this entry.", Entry.Name);
    if (Category == RuntimeCategory::ThunkSets) {
      Prompt("Host thunks", "Host-side thunk directory.", Entry.HostLibs);
      Prompt("Guest thunks", "Guest-side stub directory.", Entry.GuestLibs);
      Prompt("Thunk config", "Optional ThunksDB JSON.", Entry.ThunkConfig);
    } else {
      Prompt("Path", "Location.", Entry.Path);
    }
    // Editing a discovered entry makes it the user's: a later rescan must not
    // treat it as something it owns.
    Entry.Discovered = false;
    Dirty = true;
    RefreshPathList();
    SaveNow();
    return true;
  }
  case 27: Current = Sess.Reg().Titles.empty() ? View::Empty : View::Titles; return true;
  default: return false;
  }
}

bool App::HandleKey(int Key) {
  if (Key == 'q') {
    Quit = true;
    return true;
  }
  if (Key == '?') {
    ShowHelp();
    return true;
  }
  if (Key == KEY_RESIZE) {
    return true;
  }

  switch (Current) {
  case View::Paths: return HandlePathsKey(Key);
  case View::Empty:
    if (Key == 's') {
      ScanAndImport();
      return true;
    }
    if (Key == 'p') {
      Current = View::Paths;
      RefreshPathList();
      return true;
    }
    return false;
  case View::Titles: return HandleTitlesKey(Key);
  }
  return false;
}

int App::Run() {
  std::string Error;
  if (!Sess.Load(Error)) {
    fmt::print(stderr, "error: {}\n", Error);
    return 1;
  }

  Screen Term;
  RefreshTitleList();
  RefreshPathList();
  Current = Sess.Reg().Titles.empty() ? View::Empty : View::Titles;

  if (Sess.WasFirstRun()) {
    Status(fmt::format("First run: found {} location(s) on this machine. Press ? for help.", Sess.LastReport().TotalAdded()), Colour::Accent);
  }

  while (!Quit) {
    Draw();
    const int Key = getch();
    if (Key == ERR) {
      continue;
    }
    HandleKey(Key);
    if (Current == View::Empty && !Sess.Reg().Titles.empty()) {
      Current = View::Titles;
      RefreshTitleList();
    }
  }

  if (Dirty) {
    SaveNow();
  }
  return 0;
}

} // namespace FastPPCx86::Launcher::TUI
