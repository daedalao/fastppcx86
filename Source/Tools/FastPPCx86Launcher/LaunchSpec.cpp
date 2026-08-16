// SPDX-License-Identifier: MIT
#include "LaunchSpec.h"
#include "Discovery.h"
#include "Json.h"
#include "PrefixTools.h"
#include "Recipes.h"
#include "Runtimes.h"

#include <Common/Config.h>
#include <Common/JSONPool.h>
#include <FEXCore/Config/Config.h>

#include <tiny-json.h>

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <unistd.h>

namespace FastPPCx86::Launcher {

namespace {
  namespace fs = std::filesystem;

  std::string Join(std::string_view Dir, std::string_view Leaf) {
    std::string Out {Dir};
    while (!Out.empty() && Out.back() == '/') {
      Out.pop_back();
    }
    Out += '/';
    Out += Leaf;
    return Out;
  }

  void Add(LaunchSpec& Spec, Diagnostic::Level Level, std::string Text) {
    Spec.Diagnostics.push_back({Level, std::move(Text)});
  }

  std::string BaseName(const std::string& Path) {
    return fs::path {Path}.filename().string();
  }

  std::string Timestamp() {
    const std::time_t Now = std::time(nullptr);
    std::tm Broken {};
    if (!::localtime_r(&Now, &Broken)) {
      return "unknown";
    }
    char Buffer[32];
    std::strftime(Buffer, sizeof(Buffer), "%Y%m%d-%H%M%S", &Broken);
    return Buffer;
  }

  /// Builds one `FEXBash -c` payload: an optional cd, then the command.
  std::string ShellPayload(const std::string& WorkDir, const std::vector<std::string>& Words) {
    std::string Command;
    if (!WorkDir.empty()) {
      Command = "cd " + ShellQuote(WorkDir) + " && ";
    }
    for (size_t I = 0; I < Words.size(); ++I) {
      if (I) {
        Command += ' ';
      }
      Command += ShellQuote(Words[I]);
    }
    return Command;
  }

  /// Reads ThunksDB.asound out of the user's Config.json.
  std::optional<bool> AsoundThunkEnabled() {
    const auto Path = std::string {FEXCore::Config::GetConfigFileLocation(false).c_str()};
    std::string Contents;
    if (!Json::ReadFile(Path, Contents) || Contents.empty()) {
      return std::nullopt;
    }
    FEX::JSON::JsonAllocator Pool {};
    const json_t* Root = FEX::JSON::CreateJSON(Contents, Pool);
    if (!Root) {
      return std::nullopt;
    }
    const json_t* DB = json_getProperty(Root, "ThunksDB");
    if (!DB) {
      return std::nullopt;
    }
    const json_t* Asound = json_getProperty(DB, "asound");
    if (!Asound) {
      return std::nullopt;
    }
    const char* Value = json_getValue(Asound);
    return Value && std::string_view {Value} != "0";
  }
} // namespace

std::string ShellQuote(std::string_view Value) {
  if (!Value.empty() && std::all_of(Value.begin(), Value.end(), [](unsigned char C) {
        return std::isalnum(C) || C == '/' || C == '.' || C == '_' || C == '-' || C == ':' || C == '=' || C == '+' || C == ',' || C == '@';
      })) {
    return std::string {Value};
  }

  // Single quotes, with the standard '\'' dance for embedded ones. This is what
  // printf %q produces for the awkward cases and it survives any byte.
  std::string Out;
  Out.reserve(Value.size() + 2);
  Out += '\'';
  for (const char C : Value) {
    if (C == '\'') {
      Out += "'\\''";
    } else {
      Out += C;
    }
  }
  Out += '\'';
  return Out;
}

std::map<std::string, std::string> LaunchSpec::FexVars() const {
  std::map<std::string, std::string> Out;
  for (const auto& Entry : Envp) {
    const auto Equals = Entry.find('=');
    if (Equals == std::string::npos) {
      continue;
    }
    if (Entry.rfind("FEX", 0) == 0) {
      Out.emplace(Entry.substr(0, Equals), Entry.substr(Equals + 1));
    }
  }
  return Out;
}

bool LaunchSpec::HasErrors() const {
  return std::any_of(Diagnostics.begin(), Diagnostics.end(), [](const Diagnostic& D) { return D.Severity == Diagnostic::Level::Error; });
}

std::string LaunchSpec::ShellCommand() const {
  // Only the variables this launcher decided are shown. Dumping the entire
  // inherited environment would bury them and make the line unusable.
  static constexpr std::string_view Interesting[] {
    "FEX",    "DISPLAY", "XAUTHORITY", "SDL_VIDEODRIVER", "GDK_BACKEND", "QT_QPA_PLATFORM", "VK_USE_PLATFORM_XCB_KHR",
    "MESA_",  "LIBGL_",  "GALLIUM_",   "mesa_glthread",   "__GLX_",      "STEAM_",          "Steam",
    "PROTON", "VKD3D",   "WINE",       "LD_LIBRARY_PATH", "GLIBC_",      "DOTNET_",         "MONO_",
  };

  std::string Out;
  for (const auto& Entry : Envp) {
    const auto Equals = Entry.find('=');
    if (Equals == std::string::npos) {
      continue;
    }
    const auto Key = Entry.substr(0, Equals);
    const bool Show =
      std::any_of(std::begin(Interesting), std::end(Interesting), [&Key](std::string_view Prefix) { return Key.rfind(Prefix, 0) == 0; });
    if (!Show) {
      continue;
    }
    Out += Key + "=" + ShellQuote(Entry.substr(Equals + 1)) + " \\\n  ";
  }

  if (!CageCPUs.empty()) {
    Out += "taskset -c " + CageList + " \\\n  ";
  }
  if (TimeoutSeconds > 0) {
    Out += fmt::format("timeout --signal=KILL {} \\\n  ", TimeoutSeconds);
  }

  for (size_t I = 0; I < Argv.size(); ++I) {
    if (I) {
      Out += ' ';
    }
    Out += ShellQuote(Argv[I]);
  }

  if (!WorkDir.empty()) {
    Out = "cd " + ShellQuote(WorkDir) + " && \\\n  " + Out;
  }
  return Out;
}

std::string ResolvePrefixRoot(const Title& T) {
  // Every title gets its own by default. Proton prefixes carry per-game DLL
  // overrides, installed redistributables and registry state; sharing one
  // between titles is how you end up with a prefix nothing runs in.
  return T.Prefix.empty() ? Join(DefaultPrefixRoot(), T.Id) : ExpandPath(T.Prefix);
}

PrepareResult Prepare(const Registry& Reg, const Title& T) {
  PrepareResult Result;

  if (T.Kind != TitleKind::Proton && T.Kind != TitleKind::Wine) {
    return Result;
  }

  const auto WinePrefix = PrefixTools::WinePrefixDir(T.Kind, ResolvePrefixRoot(T));
  const auto Manifest = PrefixTools::ReadManifest(WinePrefix);

  // A 32-bit title needs the x32 DLLs in syswow64; a 64-bit one does not. Read
  // it from the executable rather than guessing.
  bool Want32Bit = false;
  if (const auto Info = Discovery::InspectBinary(ExpandPath(T.Exe))) {
    Want32Bit = Info->Kind == Discovery::BinaryKind::WindowsPE32;
  }

  for (const auto Category : {RuntimeCategory::DXVK, RuntimeCategory::VKD3D}) {
    const RuntimeEntry* Selected = Reg.Find(Category, T.Use.For(Category));
    if (!Selected) {
      Selected = Reg.Find(Category, Reg.Defaults.For(Category));
    }
    if (!Selected || !Selected->Enabled) {
      continue;
    }

    const auto Drift = PrefixTools::CheckDrift(Manifest, Category, Selected, WinePrefix);
    if (Drift.State == PrefixTools::DriftState::Match) {
      continue;
    }

    const auto Installed = PrefixTools::Install(Category, *Selected, WinePrefix, Want32Bit);
    if (Installed.Ok) {
      std::string Files;
      for (const auto& File : Installed.Installed) {
        if (!Files.empty()) {
          Files += ", ";
        }
        Files += File;
      }
      Result.Diagnostics.push_back(
        {Diagnostic::Level::Info, fmt::format("Installed {} '{}' into the prefix ({}).", DisplayName(Category), Selected->Name, Files)});
    } else {
      // Not fatal. The commonest cause is a prefix that has not been created
      // yet, and the right move there is to let the title run once with the
      // bundled DLLs rather than refusing to start it.
      Result.Diagnostics.push_back({Diagnostic::Level::Warning, fmt::format("Could not install {} '{}': {}. The bundled version will be "
                                                                            "used.",
                                                                            DisplayName(Category), Selected->Name, Installed.Error)});
    }
  }

  return Result;
}

std::string LogPathFor(const Title& T) {
  return Join(DefaultLogDir(), fmt::format("{}_{}.log", T.Id.empty() ? "title" : T.Id, Timestamp()));
}

AppConfigInfo InspectAppConfig(const Title& T) {
  AppConfigInfo Info;
  if (T.Exe.empty()) {
    return Info;
  }

  // The AppConfig name is the guest binary's basename -- for a Wine-hosted title
  // that is the exe name, not the path the emulator actually executed.
  const auto Name = BaseName(ExpandPath(T.Exe));
  Info.Path = std::string {FEXCore::Config::GetApplicationConfig(Name, false).c_str()};

  std::string Contents;
  if (!Json::ReadFile(Info.Path, Contents) || Contents.empty()) {
    return Info;
  }
  Info.Exists = true;

  FEX::JSON::JsonAllocator Pool {};
  const json_t* Root = FEX::JSON::CreateJSON(Contents, Pool);
  if (!Root) {
    return Info;
  }

  // Read the file's own spelling rather than going through a config Layer: the
  // point is to show the user what is written in the file they may need to edit,
  // not a normalised view of it.
  const json_t* Config = json_getProperty(Root, "Config");
  if (!Config) {
    return Info;
  }

  for (const json_t* Option = json_getChild(Config); Option; Option = json_getSibling(Option)) {
    const char* Name2 = json_getName(Option);
    const char* Value = json_getValue(Option);
    if (!Name2 || !Value) {
      continue;
    }
    Info.Options[Name2] = Value;
  }

  // Config keys are compared case-insensitively: the JSON spells them
  // "SMCChecks" while the launcher's own keys are the uppercase env spelling.
  const auto Upper = [](std::string Text) {
    std::transform(Text.begin(), Text.end(), Text.begin(), [](unsigned char C) { return static_cast<char>(std::toupper(C)); });
    return Text;
  };

  for (const auto& [Key, Value] : Info.Options) {
    if (Upper(Key) == "SMCCHECKS" && Value == "none") {
      Info.DisarmsSMC = true;
    }
    for (const auto& [OurKey, OurValue] : T.Fex) {
      if (Upper(Key) == Upper(OurKey)) {
        Info.Overlapping.push_back(Key);
        break;
      }
    }
  }

  return Info;
}

LaunchSpec Build(const Registry& Reg, const Title& T, const SessionOverrides& Overrides) {
  LaunchSpec Spec;
  Spec.TimeoutSeconds = T.TimeoutSeconds;
  Spec.LogPath = LogPathFor(T);

  // -- Emulator build ------------------------------------------------------
  const RuntimeEntry* BuildEntry = nullptr;
  if (Overrides.EmulatorBuildId) {
    BuildEntry = Reg.Find(RuntimeCategory::EmulatorBuilds, *Overrides.EmulatorBuildId);
  }
  if (!BuildEntry) {
    BuildEntry = Reg.Resolve(RuntimeCategory::EmulatorBuilds, T);
  }
  if (!BuildEntry) {
    Add(Spec, Diagnostic::Level::Error,
        "No emulator build is configured. Add a directory containing both FEX and FEXBash under Paths -> Emulator builds.");
    return Spec;
  }

  const auto Emulator = Runtimes::ResolveEmulator(*BuildEntry);
  if (!Emulator) {
    Add(Spec, Diagnostic::Level::Error,
        fmt::format("Emulator build '{}' ({}) does not contain both FEX and FEXBash.", BuildEntry->Name, ExpandPath(BuildEntry->Path)));
    return Spec;
  }

  // -- Target --------------------------------------------------------------
  const auto Exe = ExpandPath(T.Exe);
  if (T.Kind != TitleKind::Steam) {
    if (Exe.empty()) {
      Add(Spec, Diagnostic::Level::Error, "This title has no executable set.");
      return Spec;
    }
    if (!Runtimes::IsRegularFile(Exe)) {
      Add(Spec, Diagnostic::Level::Error, fmt::format("'{}' does not exist.", Exe));
      return Spec;
    }
  }

  Spec.WorkDir = T.WorkDir.empty() ? (Exe.empty() ? std::string {} : fs::path {Exe}.parent_path().string()) : ExpandPath(T.WorkDir);

  // -- Environment ---------------------------------------------------------
  auto Env = HostEnv::Environment::FromCurrent();
  HostEnv::ApplyWindowSystem(Env);

  const auto Display = HostEnv::ResolveDisplay(Env);
  if (!Display.Problem.empty()) {
    Add(Spec, Diagnostic::Level::Error, Display.Problem);
  } else {
    HostEnv::ApplyDisplay(Env, Display);
  }

  HostEnv::ApplyRender(Env, Overrides.Render.value_or(T.Render));

  // Both binaries from one directory. There is deliberately no way to set one
  // without the other: FEX_BIN pointing at a new build while FEXBASH still names
  // the old one runs a whole session on the wrong binary and says nothing.
  Env.Set("FEX_BIN", Emulator->FEX);
  Env.Set("FEXBASH", Emulator->FEXBash);
  // FEXServer spawns helpers such as FEXOfflineCompiler with execvp(), so the
  // build directory has to be reachable on PATH or every cache generation fails.
  HostEnv::PrependPath(Env, Emulator->Dir);

  // -- RootFS and thunks ---------------------------------------------------
  if (const RuntimeEntry* RootFS = Reg.Resolve(RuntimeCategory::RootFS, T)) {
    if (const auto Path = ExpandPath(RootFS->Path); !Path.empty()) {
      Env.Set("FEX_ROOTFS", Path);
    }
  }

  if (const RuntimeEntry* Thunks = Reg.Resolve(RuntimeCategory::ThunkSets, T)) {
    // Each component is only set when the entry names it, so an unset component
    // keeps whatever the emulator was built with rather than being blanked.
    if (const auto Path = ExpandPath(Thunks->HostLibs); !Path.empty()) {
      Env.Set("FEX_THUNKHOSTLIBS", Path);
    }
    if (const auto Path = ExpandPath(Thunks->GuestLibs); !Path.empty()) {
      Env.Set("FEX_THUNKGUESTLIBS", Path);
    }
    if (const auto Path = ExpandPath(Thunks->ThunkConfig); !Path.empty()) {
      Env.Set("FEX_THUNKCONFIG", Path);
    }
  }

  // -- Title environment ---------------------------------------------------
  for (const auto& [Key, Value] : T.Env) {
    Env.Set(Key, ExpandPath(Value) == Value ? Value : ExpandPath(Value));
  }

  // -- FEX tuning ----------------------------------------------------------
  auto Fex = T.Fex;
  for (const auto& [Key, Value] : Overrides.ExtraFex) {
    Fex[Key] = Value;
  }

  // Arm SMCChecks explicitly whenever any SMC option is set. docs/AppConfigRecipes.md
  // asks launchers to do exactly this: an AppConfig with "SMCChecks": "none"
  // turns off mtrack, every SMC feature gates on mtrack, and the recipe then
  // stays off with no diagnostic at all.
  const bool AnySMC = std::any_of(Fex.begin(), Fex.end(), [](const auto& Pair) { return Pair.first.rfind("SMC", 0) == 0; });
  if (AnySMC && Fex.find("SMCCHECKS") == Fex.end()) {
    Fex["SMCCHECKS"] = "mtrack";
    Add(Spec, Diagnostic::Level::Info, "SMCChecks=mtrack was set explicitly, because SMC options only take effect under mtrack.");
  }

  for (const auto& [Key, Value] : Fex) {
    Env.Set("FEX_" + Key, Value);
  }

  Env.SetIfUnset("FEX_SILENTLOG", "0");
  if (Overrides.DirectLog) {
    // A FEXServer left running from an earlier session otherwise receives the
    // log output, and the startup banner lands somewhere the user is not looking.
    Env.Set("FEX_SILENTLOG", "0");
    Env.Set("FEX_OUTPUTLOG", "stderr");
  }

  // -- Cage ----------------------------------------------------------------
  const auto Machine = Topology::ReadMachine();
  const auto Cage = Topology::Resolve(Machine, Overrides.Cage.value_or(T.Cage));
  Spec.CageCPUs = Cage.CPUs;
  Spec.CageList = Cage.List;
  Spec.CageExplanation = Cage.Explanation;
  if (!Cage.Warning.empty()) {
    Add(Spec, Diagnostic::Level::Warning, Cage.Warning);
  }

  // -- Prefix and DLL overrides -------------------------------------------
  const bool NeedsPrefix = T.Kind == TitleKind::Proton || T.Kind == TitleKind::Wine;
  if (NeedsPrefix) {
    const auto Root = ResolvePrefixRoot(T);
    Spec.WinePrefix = PrefixTools::WinePrefixDir(T.Kind, Root);

    const auto Manifest = PrefixTools::ReadManifest(Spec.WinePrefix);
    for (const auto Category : {RuntimeCategory::DXVK, RuntimeCategory::VKD3D}) {
      const RuntimeEntry* Selected = Reg.Find(Category, T.Use.For(Category));
      if (!Selected) {
        Selected = Reg.Find(Category, Reg.Defaults.For(Category));
      }
      const auto Drift = PrefixTools::CheckDrift(Manifest, Category, Selected, Spec.WinePrefix);
      if (!Drift.Description.empty()) {
        Add(Spec, Diagnostic::Level::Warning, Drift.Description);
      }
    }

    if (const auto Overrides2 = PrefixTools::CombinedOverrides(Manifest); !Overrides2.empty()) {
      const std::string* Existing = Env.Get("WINEDLLOVERRIDES");
      Env.Set("WINEDLLOVERRIDES", Existing && !Existing->empty() ? *Existing + ";" + Overrides2 : Overrides2);
    }

    Env.Set("STEAM_COMPAT_DATA_PATH", Root);
  }

  // -- Per-kind command ----------------------------------------------------
  switch (T.Kind) {
  case TitleKind::Native: {
    Spec.Argv.push_back(Emulator->FEX);
    Spec.Argv.push_back(Exe);
    for (const auto& Arg : T.Args) {
      Spec.Argv.push_back(Arg);
    }

    // Games routinely ship their own libraries next to the binary.
    for (const char* Sub : {"lib", "lib64", "game/lib", "game/lib64"}) {
      const auto Dir = Join(Spec.WorkDir, Sub);
      if (Runtimes::IsDirectory(Dir)) {
        HostEnv::AppendToPathList(Env, "LD_LIBRARY_PATH", Dir);
      }
    }
    if (!Spec.WorkDir.empty()) {
      HostEnv::AppendToPathList(Env, "LD_LIBRARY_PATH", Spec.WorkDir);
    }

    if (const auto Info = Discovery::InspectBinary(Exe); Info && !Discovery::IsGuestExecutable(Info->Kind)) {
      Add(Spec, Diagnostic::Level::Warning, fmt::format("'{}' is not an x86 or x86-64 ELF. The emulator will probably refuse it.", BaseName(Exe)));
    }
    break;
  }

  case TitleKind::Proton: {
    const RuntimeEntry* ProtonEntry = Reg.Resolve(RuntimeCategory::Proton, T);
    if (!ProtonEntry) {
      Add(Spec, Diagnostic::Level::Error,
          "No Proton installation is configured. Add one under Paths -> Proton, or install a Proton build through Steam.");
      break;
    }
    const auto Script = Runtimes::ResolveProton(*ProtonEntry);
    if (!Script) {
      Add(Spec, Diagnostic::Level::Error, fmt::format("Proton '{}' has no 'proton' script.", ProtonEntry->Name));
      break;
    }

    if (const auto Roots = Discovery::SteamRoots(); !Roots.empty()) {
      Env.SetIfUnset("STEAM_COMPAT_CLIENT_INSTALL_PATH", Roots.front());
    }
    // GE-Proton takes its umu path when SteamGameId is absent; giving it one
    // keeps it on the plain-Steam path. A title that set its own real appid in
    // Env has already won here, because that was applied above.
    Env.SetIfUnset("SteamGameId", "0");
    // Proton's log is formatted by emulated x86 inside wine and written a line
    // at a time through the emulator's syscall path: measured around 6.3 KB/s
    // during a run, for a file nobody reads unless they asked for it.
    Env.SetIfUnset("PROTON_LOG", "0");
    Env.SetIfUnset("PROTON_LOG_DIR", DefaultLogDir());
    // D3D12 upload heaps land in host-visible VRAM when a large resizable BAR is
    // present, and PROT_SAO cannot be applied to write-combined PCIe MMIO -- so
    // under hardware TSO the hottest store traffic is precisely the traffic not
    // being ordered. Moving the heaps to system RAM measured p99 spread 57.1% ->
    // 10.1% with complete separation, and it is inert where there is no big BAR.
    Env.SetIfUnset("VKD3D_CONFIG", "no_upload_hvv");

    std::vector<std::string> Words {"python3", *Script, "run", Exe};
    for (const auto& Arg : T.Args) {
      Words.push_back(Arg);
    }

    Spec.Argv.push_back(Emulator->FEXBash);
    Spec.Argv.push_back("-c");
    Spec.Argv.push_back(ShellPayload(Spec.WorkDir, Words));
    // FEXBash runs the payload itself; the cd is inside it.
    Spec.WorkDir.clear();
    break;
  }

  case TitleKind::Wine: {
    const RuntimeEntry* WineEntry = Reg.Resolve(RuntimeCategory::Wine, T);
    if (!WineEntry) {
      Add(Spec, Diagnostic::Level::Error, "No Wine installation is configured. Add one under Paths -> Wine.");
      break;
    }
    const auto Wine = Runtimes::ResolveWine(*WineEntry);
    if (!Wine) {
      Add(Spec, Diagnostic::Level::Error, fmt::format("Wine '{}' has no bin/wine64 or bin/wine.", WineEntry->Name));
      break;
    }

    Env.Set("WINEPREFIX", Spec.WinePrefix);

    if (WineEntry->HostNative) {
      // A host-architecture Wine runs outside the emulator entirely. It is
      // accepted here because registering one is legitimate, but on this port it
      // cannot load PE binaries: there is no PE ABI for PPC64, so PE_ARCHS is
      // empty and wow64 is never built.
      Add(Spec, Diagnostic::Level::Warning,
          fmt::format("Wine '{}' is built for this host's architecture. It runs outside the emulator and cannot "
                      "load PE binaries on this port.",
                      WineEntry->Name));
      Spec.Argv.push_back(Wine.value());
      Spec.Argv.push_back(Exe);
      for (const auto& Arg : T.Args) {
        Spec.Argv.push_back(Arg);
      }
      break;
    }

    std::vector<std::string> Words {*Wine, Exe};
    for (const auto& Arg : T.Args) {
      Words.push_back(Arg);
    }
    Spec.Argv.push_back(Emulator->FEXBash);
    Spec.Argv.push_back("-c");
    Spec.Argv.push_back(ShellPayload(Spec.WorkDir, Words));
    Spec.WorkDir.clear();
    break;
  }

  case TitleKind::Steam: {
    auto Script = Exe.empty() ? Discovery::SteamClientScript().value_or(std::string {}) : Exe;
    if (Script.empty()) {
      Add(Spec, Diagnostic::Level::Error, "Steam was not found. Set this title's executable to your steam.sh.");
      break;
    }

    // steam.sh is a shell script and the whole client is a tree of scripts and
    // helpers that all have to end up inside the guest, so it goes through
    // FEXBash rather than being handed to the emulator directly.
    Spec.Argv.push_back(Emulator->FEXBash);
    Spec.Argv.push_back(Script);
    Spec.Argv.push_back("-tcp"); // UDP is emulated more conservatively.
    for (const auto& Arg : T.Args) {
      Spec.Argv.push_back(Arg);
    }

    if (Spec.TimeoutSeconds > 0) {
      // Steam's container setup and logon take a couple of minutes by
      // themselves, so a timeout reads as "Steam crashes after N seconds".
      Add(Spec, Diagnostic::Level::Warning,
          "This title has a timeout set. Steam takes minutes to log in, and a timeout makes that look like a crash.");
    }
    if (AsoundThunkEnabled().value_or(false)) {
      Add(Spec, Diagnostic::Level::Warning,
          "The asound thunk is enabled in your Config.json. It crash-loops steamwebhelper every ten seconds, because "
          "the guest stub exports no ELF symbol versions. Set \"asound\": 0; game audio goes through PulseAudio anyway.");
    }
    break;
  }
  }

  // -- Host-level warnings -------------------------------------------------
  if (Spec.TimeoutSeconds > 0 && T.Kind != TitleKind::Steam) {
    Add(Spec, Diagnostic::Level::Warning, fmt::format("A timeout of {}s is set: the title will be SIGKILLed at that point.", Spec.TimeoutSeconds));
  }

  const long PageSize = ::sysconf(_SC_PAGESIZE);
  const auto SMCMode = Fex.find("SMCCHECKS");
  const bool UsesMtrack = SMCMode != Fex.end() && SMCMode->second == "mtrack";
  if (PageSize > 0 && PageSize != 4096 && UsesMtrack) {
    // The SMC tracker write-protects guest pages at a fixed 4K granularity to
    // match the AT_PAGESZ the guest is told, so a larger host page misbehaves.
    Add(Spec, Diagnostic::Level::Warning,
        fmt::format("This host has {}-byte pages, but SMCChecks=mtrack needs a 4K-page kernel. Boot a 4K kernel, or "
                    "use SMCChecks=full here.",
                    PageSize));
  }

  if (const auto AppConfig = InspectAppConfig(T); AppConfig.Exists) {
    if (AppConfig.DisarmsSMC && AnySMC) {
      Add(Spec, Diagnostic::Level::Warning,
          fmt::format("{} sets SMCChecks=none. This launcher overrides it from the environment, so the recipe still "
                      "arms -- but anything launching this title outside the launcher will silently get no SMC features.",
                      AppConfig.Path));
    } else if (!AppConfig.Overlapping.empty()) {
      std::string Keys;
      for (const auto& Key : AppConfig.Overlapping) {
        if (!Keys.empty()) {
          Keys += ", ";
        }
        Keys += Key;
      }
      Add(Spec, Diagnostic::Level::Info,
          fmt::format("{} also sets {}. Environment outranks AppConfig, so this launcher's values win.", AppConfig.Path, Keys));
    }
  }

  Spec.Envp = Env.ToEnvp();
  Spec.Ok = !Spec.HasErrors() && !Spec.Argv.empty();
  return Spec;
}

} // namespace FastPPCx86::Launcher
