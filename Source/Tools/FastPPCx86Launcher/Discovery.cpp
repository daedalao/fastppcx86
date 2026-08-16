// SPDX-License-Identifier: MIT
#include "Discovery.h"
#include "Json.h"
#include "Runtimes.h"

#include <Common/Config.h>
#include <Common/JSONPool.h>
#include <PortabilityInfo.h>

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <filesystem>
#include <map>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace FastPPCx86::Launcher::Discovery {

namespace {
  namespace fs = std::filesystem;

  constexpr uint16_t HostMachine() {
#if defined(__powerpc64__)
    return EM_PPC64;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__x86_64__)
    return EM_X86_64;
#elif defined(__i386__)
    return EM_386;
#else
    return 0;
#endif
  }

  std::string Join(std::string_view Dir, std::string_view Leaf) {
    std::string Out {Dir};
    while (!Out.empty() && Out.back() == '/') {
      Out.pop_back();
    }
    Out += '/';
    Out += Leaf;
    return Out;
  }

  std::string HomeDir() {
    return std::string {FEX::Config::GetHomeDirectory().c_str()};
  }

  std::string LowerCase(std::string_view Text) {
    std::string Out {Text};
    std::transform(Out.begin(), Out.end(), Out.begin(), [](unsigned char C) { return static_cast<char>(std::tolower(C)); });
    return Out;
  }

  bool EndsWith(std::string_view Text, std::string_view Suffix) {
    return Text.size() >= Suffix.size() && Text.compare(Text.size() - Suffix.size(), Suffix.size(), Suffix) == 0;
  }

  bool StartsWith(std::string_view Text, std::string_view Prefix) {
    return Text.size() >= Prefix.size() && Text.compare(0, Prefix.size(), Prefix) == 0;
  }

  /// Records the directory in the report even when it does not exist, so the UI
  /// can tell the user where it looked.
  bool Note(Report& R, RuntimeCategory Category, std::string Path) {
    const bool Exists = Runtimes::IsDirectory(Path);
    R.Searched[static_cast<size_t>(Category)].push_back(std::move(Path));
    return Exists;
  }

  void Added(Report& R, RuntimeCategory Category, bool DidAdd) {
    if (DidAdd) {
      ++R.Added[static_cast<size_t>(Category)];
    }
  }

  RuntimeEntry MakeEntry(std::string Name, std::string Path) {
    RuntimeEntry Entry;
    Entry.Name = std::move(Name);
    Entry.Path = std::move(Path);
    Entry.Discovered = true;
    Entry.Enabled = true;
    return Entry;
  }

  /// Substitutes $HOME back into a discovered absolute path when it is below the
  /// home directory. Discovery produces absolute paths, but storing them raw is
  /// what makes a registry non-portable between users.
  std::string Relativise(const std::string& Absolute) {
    const auto Home = HomeDir();
    if (!Home.empty() && Home != "/" && StartsWith(Absolute, Home) && (Absolute.size() == Home.size() || Absolute[Home.size()] == '/')) {
      return "~" + Absolute.substr(Home.size());
    }
    return Absolute;
  }

  std::vector<std::string> DirectoryEntries(const std::string& Path) {
    std::vector<std::string> Out;
    std::error_code EC;
    for (fs::directory_iterator It {Path, fs::directory_options::skip_permission_denied, EC}; !EC && It != fs::directory_iterator {};
         It.increment(EC)) {
      Out.push_back(It->path().string());
    }
    std::sort(Out.begin(), Out.end());
    return Out;
  }
} // namespace

int Report::TotalAdded() const {
  int Total {};
  for (const int Count : Added) {
    Total += Count;
  }
  return Total;
}

bool IsGuestExecutable(BinaryKind Kind) {
  return Kind == BinaryKind::GuestELF64 || Kind == BinaryKind::GuestELF32;
}

std::optional<BinaryInfo> InspectBinary(const std::string& Path) {
  const int FD = ::open(Path.c_str(), O_RDONLY | O_CLOEXEC);
  if (FD < 0) {
    return std::nullopt;
  }

  unsigned char Header[64] {};
  const ssize_t Read = ::read(FD, Header, sizeof(Header));
  if (Read < 4) {
    ::close(FD);
    return std::nullopt;
  }

  BinaryInfo Info;

  if (Header[0] == 0x7f && Header[1] == 'E' && Header[2] == 'L' && Header[3] == 'F' && Read >= 20) {
    // e_machine sits at offset 18 in both ELF32 and ELF64, and both of the
    // architectures in play here are little-endian, so one read covers it.
    Info.Machine = static_cast<uint16_t>(Header[18] | (Header[19] << 8));
    const bool Is64 = Header[EI_CLASS] == ELFCLASS64;
    if (Info.Machine == EM_X86_64 && Is64) {
      Info.Kind = BinaryKind::GuestELF64;
    } else if (Info.Machine == EM_386 && !Is64) {
      Info.Kind = BinaryKind::GuestELF32;
    } else if (Info.Machine == HostMachine()) {
      Info.Kind = BinaryKind::HostELF;
    } else {
      Info.Kind = BinaryKind::ForeignELF;
    }
    ::close(FD);
    return Info;
  }

  if (Header[0] == '#' && Header[1] == '!') {
    Info.Kind = BinaryKind::Script;
    ::close(FD);
    return Info;
  }

  if (Header[0] == 'M' && Header[1] == 'Z' && Read >= 0x40) {
    // e_lfanew at 0x3C points at the PE header; the machine word is 4 bytes in.
    const uint32_t PEOffset = static_cast<uint32_t>(Header[0x3c]) | (static_cast<uint32_t>(Header[0x3d]) << 8) |
                              (static_cast<uint32_t>(Header[0x3e]) << 16) | (static_cast<uint32_t>(Header[0x3f]) << 24);
    unsigned char PEHeader[6] {};
    if (::pread(FD, PEHeader, sizeof(PEHeader), PEOffset) == sizeof(PEHeader) && PEHeader[0] == 'P' && PEHeader[1] == 'E' &&
        PEHeader[2] == 0 && PEHeader[3] == 0) {
      Info.Machine = static_cast<uint16_t>(PEHeader[4] | (PEHeader[5] << 8));
      // 0x8664 = AMD64, 0x14c = i386. The distinction decides whether a DXVK
      // selection installs its x64 or x32 DLLs.
      Info.Kind = Info.Machine == 0x8664 ? BinaryKind::WindowsPE64 : BinaryKind::WindowsPE32;
    } else {
      Info.Kind = BinaryKind::WindowsPE32;
    }
    ::close(FD);
    return Info;
  }

  ::close(FD);
  return Info;
}

// -- Steam -------------------------------------------------------------------

std::vector<std::string> SteamRoots() {
  const auto Home = HomeDir();
  if (Home.empty()) {
    return {};
  }

  const std::string Candidates[] {
    Home + "/.steam/steam",
    Home + "/.steam/root",
    Home + "/.local/share/Steam",
    Home + "/.var/app/com.valvesoftware.Steam/data/Steam", // Flatpak
  };

  std::vector<std::string> Roots;
  std::set<std::string> Seen;
  for (const auto& Candidate : Candidates) {
    if (!Runtimes::IsDirectory(Candidate)) {
      continue;
    }
    // ~/.steam/steam and ~/.steam/root are usually symlinks to the same tree.
    std::error_code EC;
    auto Real = fs::canonical(Candidate, EC);
    const std::string Key = EC ? Candidate : Real.string();
    if (Seen.insert(Key).second) {
      Roots.push_back(Candidate);
    }
  }
  return Roots;
}

std::vector<std::string> ParseLibraryFoldersVDF(std::string_view Contents) {
  // VDF is nested quoted key/value text. Rather than model the nesting, walk the
  // token stream: every "path" key is followed by its value, and the pre-2021
  // format writes a numeric key followed directly by the library path.
  std::vector<std::string> Paths;
  std::vector<std::string> Tokens;

  for (size_t I = 0; I < Contents.size(); ++I) {
    const char C = Contents[I];
    if (C == '"') {
      std::string Token;
      ++I;
      while (I < Contents.size() && Contents[I] != '"') {
        if (Contents[I] == '\\' && I + 1 < Contents.size()) {
          ++I;
          switch (Contents[I]) {
          case 'n': Token += '\n'; break;
          case 't': Token += '\t'; break;
          default: Token += Contents[I]; break;
          }
        } else {
          Token += Contents[I];
        }
        ++I;
      }
      Tokens.push_back(std::move(Token));
    } else if (C == '/' && I + 1 < Contents.size() && Contents[I + 1] == '/') {
      while (I < Contents.size() && Contents[I] != '\n') {
        ++I;
      }
    }
  }

  for (size_t I = 0; I + 1 < Tokens.size(); ++I) {
    const auto& Key = Tokens[I];
    const auto& Value = Tokens[I + 1];
    if (Value.empty() || Value[0] != '/') {
      continue;
    }
    const bool IsPathKey = LowerCase(Key) == "path";
    const bool IsNumericKey = !Key.empty() && std::all_of(Key.begin(), Key.end(), [](unsigned char C) { return std::isdigit(C); });
    if (IsPathKey || IsNumericKey) {
      Paths.push_back(Value);
      ++I;
    }
  }

  std::sort(Paths.begin(), Paths.end());
  Paths.erase(std::unique(Paths.begin(), Paths.end()), Paths.end());
  return Paths;
}

std::vector<std::string> SteamLibraryPaths() {
  std::vector<std::string> Libraries;
  std::set<std::string> Seen;

  for (const auto& Root : SteamRoots()) {
    for (const char* Relative : {"steamapps/libraryfolders.vdf", "config/libraryfolders.vdf"}) {
      std::string Contents;
      if (!Json::ReadFile(Join(Root, Relative), Contents)) {
        continue;
      }
      for (auto& Path : ParseLibraryFoldersVDF(Contents)) {
        const auto Common = Join(Path, "steamapps/common");
        if (Runtimes::IsDirectory(Common) && Seen.insert(Common).second) {
          Libraries.push_back(Common);
        }
      }
    }
    // The root's own library is not always listed in its libraryfolders.vdf.
    const auto Own = Join(Root, "steamapps/common");
    if (Runtimes::IsDirectory(Own) && Seen.insert(Own).second) {
      Libraries.push_back(Own);
    }
  }

  return Libraries;
}

std::optional<std::string> SteamClientScript() {
  for (const auto& Root : SteamRoots()) {
    const auto Script = Join(Root, "steam.sh");
    if (Runtimes::IsRegularFile(Script)) {
      return Script;
    }
  }
  return std::nullopt;
}

// -- Population --------------------------------------------------------------

namespace {
  void PopulateEmulatorBuilds(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::EmulatorBuilds;

    // The launcher's own directory first. This is right for a /usr/bin install,
    // for an uninstalled build/Bin tree, and under FEX_PORTABLE=1 alike, which
    // is precisely why it is asked first rather than guessing at prefixes.
    if (auto Self = FEX::GetSelfPath()) {
      std::string Dir {Self->c_str()};
      while (Dir.size() > 1 && Dir.back() == '/') {
        Dir.pop_back();
      }
      if (Note(R, Category, Dir)) {
        auto Entry = MakeEntry("Alongside this launcher", Relativise(Dir));
        if (Runtimes::Validate(Category, Entry).Ok) {
          Added(R, Category, Reg.Add(Category, std::move(Entry)));
        }
      }
    }

    // Then anything on PATH, which is how a packaged install is normally found.
    if (const char* PathEnv = std::getenv("PATH")) {
      std::string_view Remaining {PathEnv};
      while (!Remaining.empty()) {
        const auto Colon = Remaining.find(':');
        const std::string Dir {Remaining.substr(0, Colon)};
        Remaining = Colon == std::string_view::npos ? std::string_view {} : Remaining.substr(Colon + 1);
        if (Dir.empty()) {
          continue;
        }
        auto Entry = MakeEntry(fmt::format("FEX in {}", Dir), Relativise(Dir));
        if (Runtimes::Validate(Category, Entry).Ok) {
          Note(R, Category, Dir);
          Added(R, Category, Reg.Add(Category, std::move(Entry)));
        }
      }
    }
  }

  void PopulateLibraries(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::Libraries;
    const auto Home = HomeDir();

    for (auto& Library : SteamLibraryPaths()) {
      Note(R, Category, Library);
      Added(R, Category, Reg.Add(Category, MakeEntry("Steam library", Relativise(Library))));
    }

    if (Home.empty()) {
      return;
    }

    // Heroic installs wherever the user pointed it, so the root comes out of its
    // own config rather than from a guessed directory. `defaultInstallPath` is
    // the only field that reliably names it.
    const auto HeroicConfig = Join(Home, ".config/heroic/config.json");
    R.Searched[static_cast<size_t>(Category)].push_back(HeroicConfig);
    std::string HeroicContents;
    if (Json::ReadFile(HeroicConfig, HeroicContents)) {
      FEX::JSON::JsonAllocator Pool {};
      if (const json_t* Root = FEX::JSON::CreateJSON(HeroicContents, Pool)) {
        const json_t* Defaults = json_getProperty(Root, "defaultSettings");
        auto Path = Json::GetString(Defaults ? Defaults : Root, "defaultInstallPath");
        if (Path.empty()) {
          Path = Json::GetString(Root, "defaultInstallPath");
        }
        if (!Path.empty() && Runtimes::IsDirectory(Path)) {
          Added(R, Category, Reg.Add(Category, MakeEntry("Heroic library", Relativise(Path))));
        }
      }
    }

    // Lutris's default install root, and the conventional place for hand-managed
    // installs. Probed, never assumed: absent means silence.
    for (const char* Guess : {"Games", "games"}) {
      const auto Path = Join(Home, Guess);
      if (Note(R, Category, Path)) {
        Added(R, Category, Reg.Add(Category, MakeEntry("Local games", Relativise(Path))));
      }
    }

    const char* XDGData = std::getenv("XDG_DATA_HOME");
    const auto DataGames = XDGData && *XDGData ? Join(XDGData, "games") : Join(Home, ".local/share/games");
    if (Note(R, Category, DataGames)) {
      Added(R, Category, Reg.Add(Category, MakeEntry("XDG games directory", Relativise(DataGames))));
    }
  }

  void PopulateRootFS(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::RootFS;
    const auto Portable = FEX::ReadPortabilityInformation();
    std::string DataDir {FEX::Config::GetDataDirectory(false, Portable).c_str()};
    while (DataDir.size() > 1 && DataDir.back() == '/') {
      DataDir.pop_back();
    }

    const auto RootFSDir = Join(DataDir, "RootFS");
    if (!Note(R, Category, RootFSDir)) {
      return;
    }

    for (const auto& Path : DirectoryEntries(RootFSDir)) {
      auto Entry = MakeEntry(fs::path {Path}.filename().string(), Relativise(Path));
      if (Runtimes::Validate(Category, Entry).Ok) {
        Added(R, Category, Reg.Add(Category, std::move(Entry)));
      }
    }
  }

  void PopulateThunkSets(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::ThunkSets;

    // An entry with every field empty means "use the paths compiled into FEX".
    // It always exists so the list is never empty and the default is nameable.
    RuntimeEntry Builtin;
    Builtin.Id = "builtin";
    Builtin.Name = "Emulator defaults";
    Builtin.Discovered = true;
    Added(R, Category, Reg.Add(Category, std::move(Builtin)));

    const auto Portable = FEX::ReadPortabilityInformation();
    std::string DataDir {FEX::Config::GetDataDirectory(false, Portable).c_str()};
    while (DataDir.size() > 1 && DataDir.back() == '/') {
      DataDir.pop_back();
    }

    const auto Host = Join(DataDir, "HostThunks");
    const auto Guest = Join(DataDir, "GuestThunks");
    Note(R, Category, Host);
    Note(R, Category, Guest);
    if (Runtimes::IsDirectory(Host) || Runtimes::IsDirectory(Guest)) {
      RuntimeEntry Entry;
      Entry.Name = "User thunks";
      Entry.HostLibs = Runtimes::IsDirectory(Host) ? Relativise(Host) : std::string {};
      Entry.GuestLibs = Runtimes::IsDirectory(Guest) ? Relativise(Guest) : std::string {};
      Entry.Discovered = true;
      Added(R, Category, Reg.Add(Category, std::move(Entry)));
    }

    // A build tree keeps its guest stubs in Guest/ and its host halves in
    // HostThunks/ next to Bin/, so an emulator entry implies a thunk set.
    for (const auto& Build : Reg.List(RuntimeCategory::EmulatorBuilds)) {
      const auto Bin = ExpandPath(Build.Path);
      const auto Parent = fs::path {Bin}.parent_path().string();
      if (Parent.empty()) {
        continue;
      }
      const auto BuildGuest = Join(Parent, "Guest");
      const auto BuildHost = Join(Parent, "HostThunks");
      if (!Runtimes::IsDirectory(BuildGuest) && !Runtimes::IsDirectory(BuildHost)) {
        continue;
      }
      Note(R, Category, Parent);
      RuntimeEntry Entry;
      Entry.Name = fmt::format("Thunks from {}", fs::path {Parent}.filename().string());
      Entry.HostLibs = Runtimes::IsDirectory(BuildHost) ? Relativise(BuildHost) : std::string {};
      Entry.GuestLibs = Runtimes::IsDirectory(BuildGuest) ? Relativise(BuildGuest) : std::string {};
      Entry.Discovered = true;
      Added(R, Category, Reg.Add(Category, std::move(Entry)));
    }
  }

  void PopulateProton(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::Proton;
    const auto Home = HomeDir();

    std::vector<std::string> SearchDirs;
    for (const auto& Library : SteamLibraryPaths()) {
      SearchDirs.push_back(Library);
    }
    for (const auto& Root : SteamRoots()) {
      SearchDirs.push_back(Join(Root, "compatibilitytools.d"));
    }
    if (!Home.empty()) {
      SearchDirs.push_back(Join(Home, ".local/share/Steam/compatibilitytools.d"));
      SearchDirs.push_back(Join(Home, ".steam/root/compatibilitytools.d"));
      // Heroic keeps downloaded Proton builds of its own.
      SearchDirs.push_back(Join(Home, ".config/heroic/tools/proton"));
    }

    for (const auto& Dir : SearchDirs) {
      if (!Note(R, Category, Dir)) {
        continue;
      }
      for (const auto& Path : DirectoryEntries(Dir)) {
        auto Entry = MakeEntry(fs::path {Path}.filename().string(), Relativise(Path));
        if (Runtimes::Validate(Category, Entry).Ok) {
          Added(R, Category, Reg.Add(Category, std::move(Entry)));
        }
      }
    }
  }

  void PopulateWine(Registry& Reg, Report& R) {
    constexpr auto Category = RuntimeCategory::Wine;
    const auto Home = HomeDir();

    std::vector<std::string> Direct;
    std::vector<std::string> Containers;
    if (!Home.empty()) {
      Containers.push_back(Join(Home, ".local/share/lutris/runners/wine"));
      Containers.push_back(Join(Home, ".config/heroic/tools/wine"));
    }
    Direct.push_back("/usr");
    for (const auto& Path : DirectoryEntries("/opt")) {
      if (StartsWith(fs::path {Path}.filename().string(), "wine")) {
        Direct.push_back(Path);
      }
    }

    for (const auto& Dir : Containers) {
      if (!Note(R, Category, Dir)) {
        continue;
      }
      for (const auto& Path : DirectoryEntries(Dir)) {
        Direct.push_back(Path);
      }
    }

    for (const auto& Path : Direct) {
      auto Entry = MakeEntry(Path == "/usr" ? "System Wine" : fs::path {Path}.filename().string(), Relativise(Path));
      const auto Result = Runtimes::Validate(Category, Entry);
      if (!Result.Ok) {
        continue;
      }
      Note(R, Category, Path);
      if (const auto Wine = Runtimes::ResolveWine(Entry)) {
        const auto Info = InspectBinary(*Wine);
        Entry.HostNative = Info && Info->Kind == BinaryKind::HostELF;
      }
      Added(R, Category, Reg.Add(Category, std::move(Entry)));
    }
  }

  void PopulateDLLRuntimes(Registry& Reg, Report& R) {
    const auto Home = HomeDir();
    if (Home.empty()) {
      return;
    }

    struct Spec {
      RuntimeCategory Category;
      const char* Container;
    };
    const Spec Specs[] {
      {RuntimeCategory::DXVK, ".local/share/lutris/runtime/dxvk"},
      {RuntimeCategory::DXVK, ".local/share/dxvk"},
      {RuntimeCategory::VKD3D, ".local/share/lutris/runtime/vkd3d"},
      {RuntimeCategory::VKD3D, ".local/share/vkd3d-proton"},
    };

    for (const auto& [Category, Container] : Specs) {
      const auto Dir = Join(Home, Container);
      if (!Note(R, Category, Dir)) {
        continue;
      }
      for (const auto& Path : DirectoryEntries(Dir)) {
        auto Entry = MakeEntry(fs::path {Path}.filename().string(), Relativise(Path));
        if (Runtimes::Validate(Category, Entry).Ok) {
          Added(R, Category, Reg.Add(Category, std::move(Entry)));
        }
      }
    }
  }
} // namespace

Report Populate(Registry& Reg) {
  Report R;
  PopulateEmulatorBuilds(Reg, R);
  PopulateLibraries(Reg, R);
  PopulateRootFS(Reg, R);
  PopulateThunkSets(Reg, R);
  PopulateProton(Reg, R);
  PopulateWine(Reg, R);
  PopulateDLLRuntimes(Reg, R);
  return R;
}

// -- Scanning ----------------------------------------------------------------

bool IsSkippedExecutable(std::string_view Filename) {
  const auto Lower = LowerCase(Filename);

  // Exact names: launcher shims that must be bypassed to reach the actual game,
  // plus crash reporters that will happily start and do nothing useful.
  static constexpr std::string_view Exact[] {
    "redprelauncher.exe",
    "loader.exe",
    "launcher.exe",
    "steamerrorreporter.exe",
    "steamerrorreporter",
    "unitycrashhandler.exe",
    "unitycrashhandler32.exe",
    "unitycrashhandler64.exe",
    "crashreportclient.exe",
    "crashsender.exe",
    "uninstall.exe",
    "uninstaller.exe",
    "nvngx_update.exe",
    "touchup.exe",
    "7za.exe",
    "7z.exe",
  };
  for (const auto& Name : Exact) {
    if (Lower == Name) {
      return true;
    }
  }

  static constexpr std::string_view Fragments[] {
    "vcredist", "dxsetup", "directx",    "dotnetfx",    "vc_redist",     "oalinst",      "setup.exe", "install.exe", "unins00",
    "physx",    "xnafx",   "dxwebsetup", "crashreport", "errorreporter", "crashhandler", "crashpad",  "bugreport",   "-cli.exe",
  };
  for (const auto& Fragment : Fragments) {
    if (Lower.find(Fragment) != std::string::npos) {
      return true;
    }
  }

  return false;
}

bool IsSkippedDirectory(std::string_view Name) {
  const auto Lower = LowerCase(Name);

  // Whole subtrees that sit inside a game library but hold no game: the
  // compatibility runtimes themselves, the wine prefixes they create, and the
  // redistributable bundles every Steam library carries.
  static constexpr std::string_view Prefixes[] {
    "proton",
    "steamlinuxruntime",
    "steam linux runtime",
    "steamworks common redist",
  };
  for (const auto& Prefix : Prefixes) {
    if (StartsWith(Lower, Prefix)) {
      return true;
    }
  }

  static constexpr std::string_view Exact[] {
    "drive_c",    // a wine prefix; the interesting binaries were installed elsewhere
    "dosdevices", //
    "prefixes",      "compatdata",   "compatibilitytools.d",
    "workshop",      "downloading",
    "runners", // Lutris/Heroic keep whole wine trees per game here.
    "_commonredist", "commonredist", "redist",
    "directx",       "vcredist",     ".git",
    "shadercache",
  };
  for (const auto& Name2 : Exact) {
    if (Lower == Name2) {
      return true;
    }
  }

  return false;
}

bool IsGameCandidateFilename(std::string_view Filename) {
  const auto Lower = LowerCase(Filename);

  // A DLL is a PE file and frequently carries the executable bit, so identifying
  // by content alone offers every game's whole lib directory as a candidate.
  // Windows titles are launched through a .exe, full stop.
  if (Lower.find('.') != std::string::npos) {
    static constexpr std::string_view Rejected[] {".dll", ".ocx", ".sys", ".cpl", ".drv", ".msi", ".bat", ".cmd", ".ps1"};
    for (const auto& Extension : Rejected) {
      if (EndsWith(Lower, Extension)) {
        return false;
      }
    }
  }

  // Shared objects on the Linux side, including versioned ones (libfoo.so.1.2).
  if (Lower.find(".so.") != std::string::npos || EndsWith(Lower, ".so")) {
    return false;
  }

  return !IsSkippedExecutable(Filename);
}

namespace {
  /// Steam records the appid in each library's appmanifest_<id>.acf, and the
  /// install directory name inside it. Mapping a candidate back to its appid is
  /// what lets the shipped tuning hints match by appid instead of by filename.
  std::map<std::string, int64_t> SteamAppIdsForLibrary(const std::string& CommonDir) {
    std::map<std::string, int64_t> ByInstallDir;
    const auto SteamApps = fs::path {CommonDir}.parent_path().string();
    for (const auto& File : DirectoryEntries(SteamApps)) {
      const auto Name = fs::path {File}.filename().string();
      if (!StartsWith(Name, "appmanifest_") || !EndsWith(Name, ".acf")) {
        continue;
      }
      std::string Contents;
      if (!Json::ReadFile(File, Contents)) {
        continue;
      }
      int64_t AppId {};
      const std::string Digits = Name.substr(std::strlen("appmanifest_"), Name.size() - std::strlen("appmanifest_") - 4);
      if (std::from_chars(Digits.data(), Digits.data() + Digits.size(), AppId).ec != std::errc {}) {
        continue;
      }
      const auto Key = Contents.find("\"installdir\"");
      if (Key == std::string::npos) {
        continue;
      }
      const auto Open = Contents.find('"', Contents.find('"', Key + 12) + 1);
      const auto Close = Contents.find('"', Open + 1);
      if (Open == std::string::npos || Close == std::string::npos) {
        continue;
      }
      ByInstallDir[Contents.substr(Open + 1, Close - Open - 1)] = AppId;
    }
    return ByInstallDir;
  }
} // namespace

std::vector<Candidate> ScanLibraries(const Registry& Reg, const ScanOptions& Options) {
  std::vector<Candidate> Results;
  std::set<std::string> SeenPaths;

  for (const auto& Root : Reg.List(RuntimeCategory::Libraries)) {
    if (!Root.Enabled) {
      continue;
    }
    const auto RootPath = ExpandPath(Root.Path);
    if (!Runtimes::IsDirectory(RootPath)) {
      continue;
    }

    const auto AppIds = SteamAppIdsForLibrary(RootPath);

    std::error_code EC;
    fs::recursive_directory_iterator It {RootPath, fs::directory_options::skip_permission_denied, EC};
    if (EC) {
      continue;
    }

    for (; It != fs::recursive_directory_iterator {} && Results.size() < Options.MaxResults; It.increment(EC)) {
      if (EC) {
        // A single unreadable subtree must not abort the whole scan.
        EC.clear();
        continue;
      }
      if (It.depth() >= Options.MaxDepth) {
        It.disable_recursion_pending();
      }

      const auto& Entry = *It;
      std::error_code StatEC;

      if (Entry.is_directory(StatEC) && !StatEC) {
        // Pruned rather than filtered afterwards: a Proton tree or a wine prefix
        // holds thousands of PE files, and walking them costs far more than the
        // rest of the scan put together.
        if (IsSkippedDirectory(Entry.path().filename().string())) {
          It.disable_recursion_pending();
        }
        continue;
      }
      StatEC.clear();

      if (!Entry.is_regular_file(StatEC) || StatEC) {
        continue;
      }

      const auto Path = Entry.path().string();
      const auto Filename = Entry.path().filename().string();
      if (!IsGameCandidateFilename(Filename)) {
        continue;
      }

      const auto Size = static_cast<int64_t>(Entry.file_size(StatEC));
      if (StatEC || Size < Options.MinSizeBytes) {
        continue;
      }

      const bool LooksWindows = EndsWith(LowerCase(Filename), ".exe");
      if (!LooksWindows && ::access(Path.c_str(), X_OK) != 0) {
        continue;
      }

      const auto Info = InspectBinary(Path);
      if (!Info) {
        continue;
      }
      // A PE is only a candidate if it is actually named .exe. IsGameCandidateFilename
      // rejects the PE extensions we know about (.dll, .ocx, .sys, ...), but a
      // blocklist only removes what it has heard of: a renamed or backed-up library
      // keeps its PE header and walks straight through it, which is how
      // `CChromaEditorLibrary.dll.bak` and `itemtest.com` were offered as games.
      // The rule that file's own comment states -- Windows titles are launched
      // through a .exe, full stop -- is an allowlist, so apply it as one here.
      //
      // ELF candidates deliberately keep the executable-bit test instead. Linux
      // game binaries carry no consistent extension (FTL.amd64,
      // Grimrock.bin.x86_64, Moonlighter.x86_64), so there is nothing to allowlist.
      const bool InterestingPE = (Info->Kind == BinaryKind::WindowsPE64 || Info->Kind == BinaryKind::WindowsPE32) && LooksWindows;
      const bool Interesting = IsGuestExecutable(Info->Kind) || InterestingPE;
      if (!Interesting) {
        continue;
      }

      if (!SeenPaths.insert(Path).second) {
        continue;
      }

      Candidate C;
      C.Path = Path;
      C.WorkDir = Entry.path().parent_path().string();
      C.Binary = Info->Kind;
      C.SizeBytes = Size;
      C.LibraryRoot = RootPath;
      C.Kind = IsGuestExecutable(Info->Kind) ? TitleKind::Native : TitleKind::Proton;

      // Name from the install directory rather than the binary: "Cyberpunk 2077"
      // reads better than "Cyberpunk2077.exe", and matches what the user sees in
      // their store client.
      auto Relative = fs::path {Path}.lexically_relative(RootPath);
      const auto InstallDir = Relative.begin() != Relative.end() ? Relative.begin()->string() : std::string {};
      C.Name = InstallDir.empty() ? Entry.path().stem().string() : InstallDir;
      if (const auto Found = AppIds.find(InstallDir); Found != AppIds.end()) {
        C.SteamAppId = Found->second;
      }

      Results.push_back(std::move(C));
    }
  }

  // Group by install directory, largest binary first within each. The main
  // executable is nearly always the biggest one in an install, so this ranks it
  // above the helper tools without needing to know any game's name.
  std::sort(Results.begin(), Results.end(), [](const Candidate& A, const Candidate& B) {
    if (A.Name != B.Name) {
      return A.Name < B.Name;
    }
    return A.SizeBytes > B.SizeBytes;
  });

  // An executable whose name matches its install directory is almost certainly
  // the one to launch, so promote it to the top of its group.
  for (size_t I = 0; I < Results.size();) {
    size_t End = I;
    while (End < Results.size() && Results[End].Name == Results[I].Name) {
      ++End;
    }
    const auto Wanted = LowerCase(Results[I].Name);
    for (size_t J = I; J < End; ++J) {
      auto Stem = LowerCase(fs::path {Results[J].Path}.stem().string());
      Stem.erase(std::remove_if(Stem.begin(), Stem.end(), [](unsigned char C) { return !std::isalnum(C); }), Stem.end());
      auto Compact = Wanted;
      Compact.erase(std::remove_if(Compact.begin(), Compact.end(), [](unsigned char C) { return !std::isalnum(C); }), Compact.end());
      if (Stem == Compact) {
        std::rotate(Results.begin() + static_cast<long>(I), Results.begin() + static_cast<long>(J), Results.begin() + static_cast<long>(J) + 1);
        break;
      }
    }
    I = End;
  }

  // Cap each install directory. Offering twenty helper binaries per game buries
  // the one the user wants; the top few by the ranking above always contain it.
  if (Options.MaxPerTitle > 0) {
    std::vector<Candidate> Trimmed;
    Trimmed.reserve(Results.size());
    for (size_t I = 0; I < Results.size();) {
      size_t End = I;
      while (End < Results.size() && Results[End].Name == Results[I].Name) {
        ++End;
      }
      const size_t Keep = std::min<size_t>(End - I, static_cast<size_t>(Options.MaxPerTitle));
      Trimmed.insert(Trimmed.end(), Results.begin() + static_cast<long>(I), Results.begin() + static_cast<long>(I + Keep));
      I = End;
    }
    Results = std::move(Trimmed);
  }

  return Results;
}

} // namespace FastPPCx86::Launcher::Discovery
