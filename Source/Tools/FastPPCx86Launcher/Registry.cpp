// SPDX-License-Identifier: MIT
#include "Registry.h"
#include "Json.h"

#include <Common/Config.h>
#include <Common/JSONPool.h>
#include <PortabilityInfo.h>

#include <tiny-json.h>

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>

namespace FastPPCx86::Launcher {

namespace {
  constexpr std::string_view TitleKindNames[] {"native", "proton", "wine", "steam"};
  constexpr std::string_view RenderNames[] {"native", "zink", "llvmpipe"};
  constexpr std::string_view CategoryKeys[] {"Libraries", "EmulatorBuilds", "RootFS", "ThunkSets", "Proton", "Wine", "DXVK", "VKD3D"};
  constexpr std::string_view CategoryDisplay[] {"Game libraries", "Emulator builds", "Root filesystems", "Thunk sets", "Proton", "Wine",
                                                "DXVK",           "VKD3D-Proton"};
  constexpr std::string_view CageModeNames[] {"auto", "custom", "none"};

  size_t Index(RuntimeCategory Category) {
    return static_cast<size_t>(Category);
  }

  FEX::Config::PortableInformation Portable() {
    return FEX::ReadPortabilityInformation();
  }

  std::string EnvOr(const char* Name, std::string_view Fallback) {
    const char* Value = std::getenv(Name);
    if (Value && *Value) {
      return Value;
    }
    return std::string {Fallback};
  }

  /// Trailing slash in, no trailing slash out. FEX's directory helpers include
  /// one; joining onto that produces "//" which is harmless but reads badly in
  /// every log line and error message.
  std::string NoTrailingSlash(std::string Path) {
    while (Path.size() > 1 && Path.back() == '/') {
      Path.pop_back();
    }
    return Path;
  }

  /**
   * A comparison key that sees through symlinks.
   *
   * Steam is the reason this exists: ~/.steam/steam, ~/.steam/root and
   * ~/.local/share/Steam are all symlinks to one directory on a normal install,
   * so probing each of them finds the same Proton builds and the same library
   * three times over. Comparing the typed path cannot tell -- only the resolved
   * one can. The typed path is still what gets stored.
   */
  std::string CanonicalKey(const std::string& Path) {
    if (Path.empty()) {
      return {};
    }
    const auto Expanded = ExpandPath(Path);
    std::error_code EC;
    const auto Resolved = std::filesystem::canonical(Expanded, EC);
    return EC ? Expanded : Resolved.string();
  }

  std::string UniqueId(const std::vector<RuntimeEntry>& Existing, std::string Base) {
    if (Base.empty()) {
      Base = "entry";
    }
    const auto Taken = [&Existing](std::string_view Id) {
      return std::any_of(Existing.begin(), Existing.end(), [Id](const RuntimeEntry& E) { return E.Id == Id; });
    };
    if (!Taken(Base)) {
      return Base;
    }
    for (int Suffix = 2; Suffix < 10000; ++Suffix) {
      auto Candidate = fmt::format("{}-{}", Base, Suffix);
      if (!Taken(Candidate)) {
        return Candidate;
      }
    }
    return Base;
  }

  void WriteSelection(Json::Writer& W, std::string_view Key, const RuntimeSelection& Selection) {
    W.BeginObject(Key);
    W.Str("EmulatorBuild", Selection.EmulatorBuild);
    W.Str("RootFS", Selection.RootFS);
    W.Str("ThunkSet", Selection.ThunkSet);
    W.Str("Proton", Selection.Proton);
    W.Str("Wine", Selection.Wine);
    W.Str("DXVK", Selection.DXVK);
    W.Str("VKD3D", Selection.VKD3D);
    W.EndObject();
  }

  RuntimeSelection ReadSelection(const json_t* Obj) {
    RuntimeSelection Selection;
    Selection.EmulatorBuild = Json::GetString(Obj, "EmulatorBuild");
    Selection.RootFS = Json::GetString(Obj, "RootFS");
    Selection.ThunkSet = Json::GetString(Obj, "ThunkSet");
    Selection.Proton = Json::GetString(Obj, "Proton");
    Selection.Wine = Json::GetString(Obj, "Wine");
    Selection.DXVK = Json::GetString(Obj, "DXVK");
    Selection.VKD3D = Json::GetString(Obj, "VKD3D");
    return Selection;
  }
} // namespace

std::string_view ToString(TitleKind Kind) {
  return TitleKindNames[static_cast<size_t>(Kind)];
}

std::optional<TitleKind> TitleKindFromString(std::string_view Name) {
  for (size_t I = 0; I < std::size(TitleKindNames); ++I) {
    if (TitleKindNames[I] == Name) {
      return static_cast<TitleKind>(I);
    }
  }
  return std::nullopt;
}

std::string_view ToString(RenderBackend Backend) {
  return RenderNames[static_cast<size_t>(Backend)];
}

std::optional<RenderBackend> RenderBackendFromString(std::string_view Name) {
  for (size_t I = 0; I < std::size(RenderNames); ++I) {
    if (RenderNames[I] == Name) {
      return static_cast<RenderBackend>(I);
    }
  }
  return std::nullopt;
}

std::string_view ToString(RuntimeCategory Category) {
  return CategoryKeys[Index(Category)];
}

std::optional<RuntimeCategory> RuntimeCategoryFromString(std::string_view Name) {
  for (size_t I = 0; I < std::size(CategoryKeys); ++I) {
    if (CategoryKeys[I] == Name) {
      return static_cast<RuntimeCategory>(I);
    }
  }
  return std::nullopt;
}

std::string_view DisplayName(RuntimeCategory Category) {
  return CategoryDisplay[Index(Category)];
}

std::string& RuntimeSelection::For(RuntimeCategory Category) {
  switch (Category) {
  case RuntimeCategory::EmulatorBuilds: return EmulatorBuild;
  case RuntimeCategory::RootFS: return RootFS;
  case RuntimeCategory::ThunkSets: return ThunkSet;
  case RuntimeCategory::Proton: return Proton;
  case RuntimeCategory::Wine: return Wine;
  case RuntimeCategory::DXVK: return DXVK;
  case RuntimeCategory::VKD3D: return VKD3D;
  case RuntimeCategory::Libraries: break;
  }
  // Libraries are not selected per title -- the scanner walks all enabled roots
  // at once -- so there is no slot for them. Park it on a scratch string rather
  // than making every caller special-case the enum.
  static std::string Unused;
  Unused.clear();
  return Unused;
}

const std::string& RuntimeSelection::For(RuntimeCategory Category) const {
  return const_cast<RuntimeSelection*>(this)->For(Category);
}

std::vector<RuntimeEntry>& Registry::List(RuntimeCategory Category) {
  return Runtimes[Index(Category)];
}

const std::vector<RuntimeEntry>& Registry::List(RuntimeCategory Category) const {
  return Runtimes[Index(Category)];
}

const RuntimeEntry* Registry::Find(RuntimeCategory Category, std::string_view Id) const {
  if (Id.empty()) {
    return nullptr;
  }
  for (const auto& Entry : List(Category)) {
    if (Entry.Id == Id) {
      return &Entry;
    }
  }
  return nullptr;
}

Title* Registry::FindTitle(std::string_view Id) {
  for (auto& T : Titles) {
    if (T.Id == Id) {
      return &T;
    }
  }
  return nullptr;
}

const Title* Registry::FindTitle(std::string_view Id) const {
  return const_cast<Registry*>(this)->FindTitle(Id);
}

const RuntimeEntry* Registry::Resolve(RuntimeCategory Category, const RuntimeSelection& Selection) const {
  // Tier 1: an explicit per-title choice. A choice that no longer resolves --
  // the entry was removed or disabled -- deliberately falls through rather than
  // failing the launch, but the UI flags it.
  if (const RuntimeEntry* Entry = Find(Category, Selection.For(Category)); Entry && Entry->Enabled) {
    return Entry;
  }
  // Tier 2: the registry default.
  if (const RuntimeEntry* Entry = Find(Category, Defaults.For(Category)); Entry && Entry->Enabled) {
    return Entry;
  }
  // Tier 3: first enabled entry, so a fresh registry works before anything is
  // chosen.
  for (const auto& Entry : List(Category)) {
    if (Entry.Enabled) {
      return &Entry;
    }
  }
  return nullptr;
}

const RuntimeEntry* Registry::Resolve(RuntimeCategory Category, const Title& ForTitle) const {
  return Resolve(Category, ForTitle.Use);
}

bool Registry::Add(RuntimeCategory Category, RuntimeEntry Entry) {
  auto& Target = List(Category);

  // Discovery re-runs on every start, so it must be idempotent. Comparing
  // canonical paths means a user entry typed as "~/foo" suppresses the
  // discovered "/home/me/foo", and a symlinked path suppresses its target.
  const auto Key = CanonicalKey(Entry.Path);
  if (Entry.Discovered && !Key.empty()) {
    for (const auto& Existing : Target) {
      if (CanonicalKey(Existing.Path) == Key) {
        return false;
      }
    }
  }
  if (Category == RuntimeCategory::ThunkSets && Entry.Discovered) {
    for (const auto& Existing : Target) {
      if (CanonicalKey(Existing.HostLibs) == CanonicalKey(Entry.HostLibs) && CanonicalKey(Existing.GuestLibs) == CanonicalKey(Entry.GuestLibs)) {
        return false;
      }
    }
  }

  if (Entry.Id.empty()) {
    Entry.Id = MakeId(Entry.Name.empty() ? Entry.Path : Entry.Name);
  }
  Entry.Id = UniqueId(Target, Entry.Id);
  Target.push_back(std::move(Entry));
  return true;
}

std::string Registry::Serialise() const {
  Json::Writer W;
  W.BeginObject();
  W.Int("Version", Version);

  W.BeginObject("Runtimes");
  for (const auto Category : AllRuntimeCategories) {
    W.BeginArray(ToString(Category));
    for (const auto& Entry : List(Category)) {
      W.BeginObject();
      W.Str("Id", Entry.Id);
      W.Str("Name", Entry.Name);
      if (Category == RuntimeCategory::ThunkSets) {
        W.Str("HostLibs", Entry.HostLibs);
        W.Str("GuestLibs", Entry.GuestLibs);
        W.Str("ThunkConfig", Entry.ThunkConfig);
      } else {
        W.Str("Path", Entry.Path);
      }
      if (Category == RuntimeCategory::Wine) {
        W.Bool("HostNative", Entry.HostNative);
      }
      W.Str("Source", Entry.Discovered ? "discovered" : "user");
      W.Bool("Enabled", Entry.Enabled);
      W.EndObject();
    }
    W.EndArray();
  }
  W.EndObject();

  WriteSelection(W, "Defaults", Defaults);

  W.BeginArray("Titles");
  for (const auto& T : Titles) {
    W.BeginObject();
    W.Str("Id", T.Id);
    W.Str("Name", T.Name);
    W.Str("Kind", ToString(T.Kind));
    W.Str("Exe", T.Exe);
    W.Str("WorkDir", T.WorkDir);

    W.BeginArray("Args");
    for (const auto& Arg : T.Args) {
      W.StrValue(Arg);
    }
    W.EndArray();

    W.BeginObject("Env");
    for (const auto& [Key, Value] : T.Env) {
      W.Str(Key, Value);
    }
    W.EndObject();

    W.Str("Render", ToString(T.Render));

    W.BeginObject("Cage");
    W.Str("Mode", CageModeNames[static_cast<size_t>(T.Cage.Mode)]);
    W.Int("Node", T.Cage.Node);
    W.Int("Cores", T.Cage.Cores);
    W.Int("ThreadsPerCore", T.Cage.ThreadsPerCore);
    W.Int("Reserve", T.Cage.Reserve);
    W.Str("CustomList", T.Cage.CustomList);
    W.EndObject();

    W.BeginObject("Fex");
    for (const auto& [Key, Value] : T.Fex) {
      W.Str(Key, Value);
    }
    W.EndObject();

    WriteSelection(W, "Use", T.Use);

    W.Str("Prefix", T.Prefix);
    W.Int("TimeoutSeconds", T.TimeoutSeconds);
    W.Str("Notes", T.Notes);
    W.EndObject();
  }
  W.EndArray();

  W.EndObject();
  return W.Finish();
}

bool Registry::Save(const std::string& Path, std::string& Error) const {
  if (!Json::WriteFileAtomic(Path, Serialise())) {
    Error = fmt::format("could not write {}", Path);
    return false;
  }
  return true;
}

bool Registry::Load(const std::string& Path, std::string& Error) {
  std::string Contents;
  if (!Json::ReadFile(Path, Contents)) {
    // A missing registry is the ordinary first-run state, not a failure. The
    // caller gets an empty registry and the UI shows its empty state.
    Error.clear();
    return true;
  }
  if (Contents.empty()) {
    Error.clear();
    return true;
  }

  FEX::JSON::JsonAllocator Pool {};
  const json_t* Root = FEX::JSON::CreateJSON(Contents, Pool);
  if (!Root) {
    Error = fmt::format("{} is not valid JSON", Path);
    return false;
  }

  *this = Registry {};
  Version = static_cast<int>(Json::GetInt(Root, "Version", 1));

  if (const json_t* RuntimesObj = json_getProperty(Root, "Runtimes")) {
    for (const auto Category : AllRuntimeCategories) {
      const json_t* Array = json_getProperty(RuntimesObj, std::string {ToString(Category)}.c_str());
      if (!Array || json_getType(Array) != JSON_ARRAY) {
        continue;
      }
      for (const json_t* Item = json_getChild(Array); Item; Item = json_getSibling(Item)) {
        RuntimeEntry Entry;
        Entry.Id = Json::GetString(Item, "Id");
        Entry.Name = Json::GetString(Item, "Name");
        Entry.Path = Json::GetString(Item, "Path");
        Entry.HostLibs = Json::GetString(Item, "HostLibs");
        Entry.GuestLibs = Json::GetString(Item, "GuestLibs");
        Entry.ThunkConfig = Json::GetString(Item, "ThunkConfig");
        Entry.Discovered = Json::GetString(Item, "Source") == "discovered";
        Entry.Enabled = Json::GetBool(Item, "Enabled", true);
        Entry.HostNative = Json::GetBool(Item, "HostNative", false);
        if (Entry.Id.empty()) {
          continue;
        }
        List(Category).push_back(std::move(Entry));
      }
    }
  }

  Defaults = ReadSelection(json_getProperty(Root, "Defaults"));

  if (const json_t* TitlesArray = json_getProperty(Root, "Titles"); TitlesArray && json_getType(TitlesArray) == JSON_ARRAY) {
    for (const json_t* Item = json_getChild(TitlesArray); Item; Item = json_getSibling(Item)) {
      Title T;
      T.Id = Json::GetString(Item, "Id");
      if (T.Id.empty()) {
        continue;
      }
      T.Name = Json::GetString(Item, "Name", T.Id);
      T.Kind = TitleKindFromString(Json::GetString(Item, "Kind", "native")).value_or(TitleKind::Native);
      T.Exe = Json::GetString(Item, "Exe");
      T.WorkDir = Json::GetString(Item, "WorkDir");
      T.Args = Json::GetStringArray(Item, "Args");

      if (const json_t* EnvObj = json_getProperty(Item, "Env")) {
        for (const json_t* E = json_getChild(EnvObj); E; E = json_getSibling(E)) {
          if (const char* Name = json_getName(E); Name && json_getValue(E)) {
            T.Env[Name] = json_getValue(E);
          }
        }
      }

      T.Render = RenderBackendFromString(Json::GetString(Item, "Render", "native")).value_or(RenderBackend::Native);

      if (const json_t* CageObj = json_getProperty(Item, "Cage")) {
        const auto Mode = Json::GetString(CageObj, "Mode", "auto");
        for (size_t I = 0; I < std::size(CageModeNames); ++I) {
          if (CageModeNames[I] == Mode) {
            T.Cage.Mode = static_cast<Topology::CageMode>(I);
            break;
          }
        }
        T.Cage.Node = static_cast<int>(Json::GetInt(CageObj, "Node", -1));
        T.Cage.Cores = static_cast<int>(Json::GetInt(CageObj, "Cores", 0));
        T.Cage.ThreadsPerCore = static_cast<int>(Json::GetInt(CageObj, "ThreadsPerCore", 2));
        T.Cage.Reserve = static_cast<int>(Json::GetInt(CageObj, "Reserve", 2));
        T.Cage.CustomList = Json::GetString(CageObj, "CustomList");
      }

      if (const json_t* FexObj = json_getProperty(Item, "Fex")) {
        for (const json_t* E = json_getChild(FexObj); E; E = json_getSibling(E)) {
          if (const char* Name = json_getName(E); Name && json_getValue(E)) {
            T.Fex[Name] = json_getValue(E);
          }
        }
      }

      T.Use = ReadSelection(json_getProperty(Item, "Use"));
      T.Prefix = Json::GetString(Item, "Prefix");
      T.TimeoutSeconds = static_cast<int>(Json::GetInt(Item, "TimeoutSeconds", 0));
      T.Notes = Json::GetString(Item, "Notes");
      Titles.push_back(std::move(T));
    }
  }

  Error.clear();
  return true;
}

std::string RegistryPath() {
  return NoTrailingSlash(std::string {FEX::Config::GetConfigDirectory(false, Portable()).c_str()}) + "/Launcher/Titles.json";
}

std::string DefaultPrefixRoot() {
  return NoTrailingSlash(std::string {FEX::Config::GetDataDirectory(false, Portable()).c_str()}) + "/Launcher/prefixes";
}

std::string DefaultLogDir() {
  // Logs are state, not cache and not config: XDG puts them under
  // XDG_STATE_HOME. FEX has no state-directory helper, so derive it here and
  // fall back to FEX's cache directory when HOME itself is unavailable.
  const std::string Home = std::string {FEX::Config::GetHomeDirectory().c_str()};
  const std::string State = EnvOr("XDG_STATE_HOME", Home.empty() ? "" : Home + "/.local/state");
  if (!State.empty()) {
    return NoTrailingSlash(State) + "/fex-emu/Launcher/logs";
  }
  return NoTrailingSlash(std::string {FEX::Config::GetCacheDirectory().c_str()}) + "/Launcher/logs";
}

std::string ExpandPath(std::string_view Path) {
  if (Path.empty()) {
    return {};
  }

  std::string Out;
  Out.reserve(Path.size());

  size_t Start {};
  if (Path[0] == '~' && (Path.size() == 1 || Path[1] == '/')) {
    Out += NoTrailingSlash(std::string {FEX::Config::GetHomeDirectory().c_str()});
    Start = 1;
  }

  for (size_t I = Start; I < Path.size(); ++I) {
    if (Path[I] != '$') {
      Out += Path[I];
      continue;
    }

    size_t NameStart = I + 1;
    size_t NameEnd = NameStart;
    bool Braced = false;
    if (NameStart < Path.size() && Path[NameStart] == '{') {
      Braced = true;
      ++NameStart;
      NameEnd = NameStart;
      while (NameEnd < Path.size() && Path[NameEnd] != '}') {
        ++NameEnd;
      }
    } else {
      while (NameEnd < Path.size() && (std::isalnum(static_cast<unsigned char>(Path[NameEnd])) || Path[NameEnd] == '_')) {
        ++NameEnd;
      }
    }

    if (NameEnd == NameStart) {
      // A lone '$' is a literal.
      Out += '$';
      continue;
    }

    const std::string Name {Path.substr(NameStart, NameEnd - NameStart)};
    if (const char* Value = std::getenv(Name.c_str())) {
      Out += Value;
    }
    I = Braced ? NameEnd : NameEnd - 1;
  }

  return Out;
}

std::string MakeId(std::string_view Text) {
  std::string Out;
  Out.reserve(Text.size());
  bool PendingSeparator = false;
  for (const char C : Text) {
    if (std::isalnum(static_cast<unsigned char>(C))) {
      if (PendingSeparator && !Out.empty()) {
        Out += '-';
      }
      PendingSeparator = false;
      Out += static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
    } else {
      PendingSeparator = true;
    }
  }
  if (Out.empty()) {
    Out = "entry";
  }
  return Out;
}

} // namespace FastPPCx86::Launcher
