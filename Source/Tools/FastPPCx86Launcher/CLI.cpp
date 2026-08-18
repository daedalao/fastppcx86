// SPDX-License-Identifier: MIT
#include "CLI.h"
#include "Discovery.h"
#include "LaunchSpec.h"
#include "Recipes.h"
#include "Runner.h"
#include "Runtimes.h"
#include "Session.h"
#include "Topology.h"

#include <fmt/format.h>

#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

namespace FastPPCx86::Launcher::CLI {

namespace {
  void PrintUsage(const char* Program) {
    fmt::print("Usage: {0} [options]\n"
               "\n"
               "With no options, starts the interactive interface.\n"
               "\n"
               "  -l, --list             List configured titles.\n"
               "      --print <id>       Print the exact command a launch would run, and exit.\n"
               "      --launch <id>      Launch a title and stream its output.\n"
               "      --paths            Show every configured runtime location and whether it is usable.\n"
               "      --scan             Scan the configured game libraries and list what was found.\n"
               "      --cage [sysfs]     Show a host's CPU topology and the cage it produces.\n"
               "                         Defaults to this machine; pass a copied /sys tree to\n"
               "                         inspect another one.\n"
               "      --recipes          List the tuning recipes and knobs, with their rationale.\n"
               "      --no-discover      Skip the discovery probes for this run.\n"
               "  -h, --help             This text.\n"
               "\n"
               "Titles, runtime locations and per-title tuning live in:\n"
               "  {1}\n",
               Program, RegistryPath());
  }

  std::string Describe(Discovery::BinaryKind Kind) {
    switch (Kind) {
    case Discovery::BinaryKind::GuestELF64: return "x86-64 ELF";
    case Discovery::BinaryKind::GuestELF32: return "i386 ELF";
    case Discovery::BinaryKind::HostELF: return "host ELF";
    case Discovery::BinaryKind::ForeignELF: return "foreign ELF";
    case Discovery::BinaryKind::WindowsPE64: return "Windows PE (64-bit)";
    case Discovery::BinaryKind::WindowsPE32: return "Windows PE (32-bit)";
    case Discovery::BinaryKind::Script: return "script";
    case Discovery::BinaryKind::Unknown: break;
    }
    return "unknown";
  }

  void PrintDiagnostics(const LaunchSpec& Spec) {
    for (const auto& D : Spec.Diagnostics) {
      const char* Prefix = D.Severity == Diagnostic::Level::Error ? "error" : D.Severity == Diagnostic::Level::Warning ? "warning" : "note";
      fmt::print(stderr, "{}: {}\n", Prefix, D.Text);
    }
  }

  int DoList(Session& S) {
    if (S.Reg().Titles.empty()) {
      fmt::print("No titles configured yet. Run with --scan to find installed games.\n");
      return 0;
    }
    fmt::print("{:<24} {:<8} {}\n", "ID", "KIND", "EXECUTABLE");
    for (const auto& T : S.Reg().Titles) {
      const auto Exe = ExpandPath(T.Exe);
      const char* Mark = Runtimes::IsRegularFile(Exe) ? "" : "  [missing]";
      fmt::print("{:<24} {:<8} {}{}\n", T.Id, ToString(T.Kind), Exe, Mark);
    }
    return 0;
  }

  int DoPaths(Session& S) {
    for (const auto Category : AllRuntimeCategories) {
      fmt::print("\n{} ({})\n", DisplayName(Category), S.SummariseCategory(Category));

      const auto& List = S.Reg().List(Category);
      if (List.empty()) {
        // Naming where it looked is the difference between "nothing found" and
        // an actionable message.
        const auto& Searched = S.LastReport().Searched[static_cast<size_t>(Category)];
        if (Searched.empty()) {
          fmt::print("  (nothing configured)\n");
        } else {
          fmt::print("  Nothing found. Searched:\n");
          for (const auto& Dir : Searched) {
            fmt::print("    {}\n", Dir);
          }
        }
        continue;
      }

      const auto& DefaultId = S.Reg().Defaults.For(Category);
      for (const auto& Entry : List) {
        const auto Result = Runtimes::Validate(Category, Entry);
        const char* Mark = !Entry.Enabled ? "-" : Result.Ok ? "+" : "x";
        const bool IsDefault = !DefaultId.empty() && DefaultId == Entry.Id;

        std::string Location = Entry.Path;
        if (Category == RuntimeCategory::ThunkSets) {
          Location = fmt::format("host={} guest={}", Entry.HostLibs.empty() ? "(default)" : Entry.HostLibs,
                                 Entry.GuestLibs.empty() ? "(default)" : Entry.GuestLibs);
        }

        fmt::print("  {} {:<20} {}{}\n", Mark, Entry.Id, Location, IsDefault ? "   [default]" : "");
        if (!Result.Ok) {
          fmt::print("      {}\n", Result.Reason);
        } else if (!Result.Note.empty()) {
          fmt::print("      note: {}\n", Result.Note);
        }
      }
    }
    fmt::print("\n  + usable    x unusable    - disabled\n");
    return 0;
  }

  int DoCage(std::string_view SysfsRoot) {
    // The root is settable so a cage can be worked out against a topology copied
    // from another machine -- "tar up /sys/devices/system and send it" is a far
    // better support loop than asking someone to describe their CPU.
    const auto Machine = Topology::ReadMachine(SysfsRoot.empty() ? std::string {"/sys"} : std::string {SysfsRoot});
    if (!Machine.Problem.empty()) {
      fmt::print("Topology: {}\n", Machine.Problem);
    }

    fmt::print("Online CPUs: {}\n", Machine.OnlineCPUs.size());
    const auto Nodes = Machine.Nodes();
    if (Nodes.empty()) {
      fmt::print("NUMA: not reported (treated as a single node)\n");
    } else {
      for (const int Node : Nodes) {
        fmt::print("NUMA node {}: {} cores, up to {} threads each\n", Node, Machine.CoreCount(Node), Machine.MaxThreadsPerCore(Node));
      }
    }

    const auto Cage = Topology::Resolve(Machine, Topology::CagePolicy {});
    fmt::print("\nDefault cage: {}\n", Cage.List.empty() ? "(none)" : Cage.List);
    fmt::print("  {}\n", Cage.Explanation);
    if (!Cage.Warning.empty()) {
      fmt::print("  warning: {}\n", Cage.Warning);
    }
    return 0;
  }

  int DoRecipes() {
    fmt::print("Self-modifying-code recipes (mutually exclusive)\n\n");
    for (const auto& Recipe : Recipes::SMC()) {
      fmt::print("  {:<10} {}\n", Recipe.Id, Recipe.Name);
      fmt::print("             {}\n", Recipe.Summary);
      std::string Options;
      for (const auto& O : Recipe.Options) {
        if (!Options.empty()) {
          Options += ' ';
        }
        Options += fmt::format("FEX_{}={}", O.Key, O.Value);
      }
      fmt::print("             {}\n\n", Options);
    }

    struct Section {
      Recipes::KnobGroup Group;
      const char* Title;
    };
    const Section Sections[] {
      {Recipes::KnobGroup::Performance, "Performance knobs"},
      {Recipes::KnobGroup::Unsound, "Known-unsound knobs -- these make the emulator produce answers x86 forbids"},
      {Recipes::KnobGroup::Diagnostic, "Diagnostics and triage"},
    };

    for (const auto& Section : Sections) {
      fmt::print("{}\n\n", Section.Title);
      for (const auto& K : Recipes::Knobs()) {
        if (K.Group != Section.Group) {
          continue;
        }
        fmt::print("  FEX_{}\n", K.Key);
        fmt::print("      {}\n", K.Label);
        fmt::print("      {}\n", K.Summary);
        if (K.PresenceTested) {
          fmt::print("      NOTE: presence-tested -- setting it to 0 enables it. Unset it to turn it off.\n");
        }
        fmt::print("\n");
      }
    }
    return 0;
  }

  int DoScan(Session& S) {
    const auto Candidates = Discovery::ScanLibraries(S.Reg());
    if (Candidates.empty()) {
      fmt::print("Nothing found. Configured game libraries:\n");
      const auto& List = S.Reg().List(RuntimeCategory::Libraries);
      if (List.empty()) {
        fmt::print("  (none -- add one with the interactive interface)\n");
      }
      for (const auto& Entry : List) {
        fmt::print("  {} {}\n", Entry.Enabled ? "+" : "-", ExpandPath(Entry.Path));
      }
      return 0;
    }

    fmt::print("{:<34} {:<20} {}\n", "NAME", "TYPE", "PATH");
    for (const auto& C : Candidates) {
      fmt::print("{:<34} {:<20} {}\n", C.Name, Describe(C.Binary), C.Path);
    }
    fmt::print("\n{} candidates. Import them with the interactive interface.\n", Candidates.size());
    return 0;
  }

  const Title* Resolve(Session& S, std::string_view Id) {
    if (const Title* T = S.Reg().FindTitle(Id)) {
      return T;
    }
    // Accept an unambiguous prefix, which is what makes these usable by hand.
    const Title* Found = nullptr;
    for (const auto& T : S.Reg().Titles) {
      if (T.Id.rfind(Id, 0) == 0) {
        if (Found) {
          fmt::print(stderr, "error: '{}' matches more than one title.\n", Id);
          return nullptr;
        }
        Found = &T;
      }
    }
    if (!Found) {
      fmt::print(stderr, "error: no title with id '{}'. Use --list to see them.\n", Id);
    }
    return Found;
  }

  int DoPrint(Session& S, std::string_view Id) {
    const Title* T = Resolve(S, Id);
    if (!T) {
      return 1;
    }

    const auto Spec = Build(S.Reg(), *T);
    PrintDiagnostics(Spec);

    if (!Spec.CageList.empty()) {
      fmt::print(stderr, "cage: {}\n", Spec.CageExplanation);
    }
    if (!Spec.Ok) {
      return 1;
    }

    fmt::print("{}\n", Spec.ShellCommand());
    return 0;
  }

  int DoLaunch(Session& S, std::string_view Id) {
    const Title* T = Resolve(S, Id);
    if (!T) {
      return 1;
    }

    // Side effects first (installing a selected DXVK/VKD3D into the prefix),
    // then build, so the command picks up any WINEDLLOVERRIDES that produced.
    const auto Prepared = Prepare(S.Reg(), *T);
    for (const auto& D : Prepared.Diagnostics) {
      fmt::print(stderr, "{}: {}\n", D.Severity == Diagnostic::Level::Warning ? "warning" : "note", D.Text);
    }

    const auto Spec = Build(S.Reg(), *T);
    PrintDiagnostics(Spec);
    if (!Spec.Ok) {
      return 1;
    }

    if (!Spec.CageList.empty()) {
      fmt::print(stderr, "cage: {}\n", Spec.CageList);
    }
    if (!Spec.LogPath.empty()) {
      fmt::print(stderr, "log: {}\n", Spec.LogPath);
    }

    Runner Run;
    std::string Error;
    if (!Run.Start(Spec, Error)) {
      fmt::print(stderr, "error: {}\n", Error);
      return 1;
    }

    while (Run.Poll([](std::string_view Chunk) { std::fwrite(Chunk.data(), 1, Chunk.size(), stdout); })) {
      std::fflush(stdout);
      // The child is a game; a 50ms tick is far below anything perceptible and
      // keeps this loop off the CPU the title wants.
      ::usleep(50 * 1000);
    }
    std::fflush(stdout);

    fmt::print(stderr, "\n=== {} ({})\n", Run.ExitSummary(), Spec.LogPath);
    return Run.ExitCode();
  }
} // namespace

std::optional<int> Run(int Argc, char** Argv, bool HaveGUI) {
  std::string_view Command;
  std::string_view Argument;
  bool Discover = true;

  for (int I = 1; I < Argc; ++I) {
    const std::string_view Arg {Argv[I]};

    if (Arg == "-h" || Arg == "--help") {
      PrintUsage(Argv[0]);
      return 0;
    }
    if (Arg == "--no-discover") {
      Discover = false;
      continue;
    }
    if (Arg == "-l" || Arg == "--list" || Arg == "--paths" || Arg == "--scan" || Arg == "--recipes") {
      Command = Arg == "-l" ? "--list" : Arg;
      continue;
    }
    if (Arg == "--cage") {
      Command = Arg;
      // Optional: a sysfs root to read instead of this machine's.
      if (I + 1 < Argc && Argv[I + 1][0] != '-') {
        Argument = Argv[++I];
      }
      continue;
    }
    if (Arg == "--print" || Arg == "--launch") {
      if (I + 1 >= Argc) {
        fmt::print(stderr, "error: {} needs a title id.\n", Arg);
        return 2;
      }
      Command = Arg;
      Argument = Argv[++I];
      continue;
    }
    if (!Arg.empty() && Arg.front() == '-') {
      fmt::print(stderr, "error: unknown option '{}'. Try --help.\n", Arg);
      return 2;
    }

    // A bare argument is a title id, which makes `ppcx86-launch <title>` work.
    Command = "--launch";
    Argument = Arg;
  }

  if (Command.empty()) {
    if (HaveGUI) {
      return std::nullopt;
    }
    return std::nullopt;
  }

  if (Command == "--recipes") {
    // Needs no registry at all.
    return DoRecipes();
  }
  if (Command == "--cage") {
    return DoCage(Argument);
  }

  Session S;
  std::string Error;
  if (!S.Load(Error, Discover)) {
    fmt::print(stderr, "error: {}\n", Error);
    return 1;
  }

  if (Command == "--list") {
    return DoList(S);
  }
  if (Command == "--paths") {
    return DoPaths(S);
  }
  if (Command == "--scan") {
    return DoScan(S);
  }
  if (Command == "--print") {
    return DoPrint(S, Argument);
  }
  if (Command == "--launch") {
    return DoLaunch(S, Argument);
  }

  return std::nullopt;
}

} // namespace FastPPCx86::Launcher::CLI
