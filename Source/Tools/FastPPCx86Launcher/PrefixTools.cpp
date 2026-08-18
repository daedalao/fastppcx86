// SPDX-License-Identifier: MIT
#include "PrefixTools.h"
#include "Json.h"
#include "Runtimes.h"

#include <Common/JSONPool.h>

#include <tiny-json.h>

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <ctime>
#include <filesystem>
#include <sys/stat.h>

namespace FastPPCx86::Launcher::PrefixTools {

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

  struct DLLSet {
    std::string_view Category;
    std::array<std::string_view, 5> Names;
    size_t Count;
  };

  /// d3d8 is listed for DXVK because recent builds ship it; it is skipped when
  /// the selected build does not have one, like every other name here.
  constexpr DLLSet DXVKSet {"DXVK", {"d3d8", "d3d9", "d3d10core", "d3d11", "dxgi"}, 5};
  constexpr DLLSet VKD3DSet {"VKD3D", {"d3d12", "d3d12core", "", "", ""}, 2};

  const DLLSet& SetFor(RuntimeCategory Category) {
    return Category == RuntimeCategory::VKD3D ? VKD3DSet : DXVKSet;
  }

  std::optional<std::pair<int64_t, int64_t>> SizeAndTime(const std::string& Path) {
    struct stat Info {};
    if (::stat(Path.c_str(), &Info) != 0) {
      return std::nullopt;
    }
    return std::make_pair(static_cast<int64_t>(Info.st_size), static_cast<int64_t>(Info.st_mtime));
  }

  bool CopyFile(const std::string& From, const std::string& To, std::string& Error) {
    std::error_code EC;
    const auto Parent = fs::path {To}.parent_path();
    if (!Parent.empty()) {
      fs::create_directories(Parent, EC);
      EC.clear();
    }
    fs::copy_file(From, To, fs::copy_options::overwrite_existing, EC);
    if (EC) {
      Error = fmt::format("could not copy {} to {}: {}", From, To, EC.message());
      return false;
    }
    return true;
  }

  std::string BuildOverrides(const std::vector<std::string>& Names) {
    if (Names.empty()) {
      return {};
    }
    // WINEDLLOVERRIDES groups names sharing a disposition: "a,b,c=n".
    std::string Out;
    for (const auto& Name : Names) {
      if (!Out.empty()) {
        Out += ',';
      }
      Out += Name;
    }
    Out += "=n";
    return Out;
  }
} // namespace

std::string WinePrefixDir(TitleKind Kind, const std::string& PrefixRoot) {
  // Proton treats its argument as a compatdata directory and creates the actual
  // Wine prefix inside it as `pfx`. A plain Wine tree uses WINEPREFIX directly.
  return Kind == TitleKind::Proton ? Join(PrefixRoot, "pfx") : PrefixRoot;
}

const InstalledRuntime* Manifest::Find(std::string_view Category) const {
  for (const auto& Entry : Entries) {
    if (Entry.Category == Category) {
      return &Entry;
    }
  }
  return nullptr;
}

void Manifest::Replace(InstalledRuntime Entry) {
  Remove(Entry.Category);
  Entries.push_back(std::move(Entry));
}

void Manifest::Remove(std::string_view Category) {
  Entries.erase(std::remove_if(Entries.begin(), Entries.end(), [Category](const InstalledRuntime& E) { return E.Category == Category; }),
                Entries.end());
}

std::string ManifestPath(const std::string& WinePrefix) {
  return Join(WinePrefix, ".fastppcx86-launcher.json");
}

Manifest ReadManifest(const std::string& WinePrefix) {
  Manifest M;
  std::string Contents;
  if (!Json::ReadFile(ManifestPath(WinePrefix), Contents) || Contents.empty()) {
    return M;
  }

  FEX::JSON::JsonAllocator Pool {};
  const json_t* Root = FEX::JSON::CreateJSON(Contents, Pool);
  if (!Root) {
    return M;
  }

  const json_t* Array = json_getProperty(Root, "Installed");
  if (!Array || json_getType(Array) != JSON_ARRAY) {
    return M;
  }

  for (const json_t* Item = json_getChild(Array); Item; Item = json_getSibling(Item)) {
    InstalledRuntime Entry;
    Entry.Category = Json::GetString(Item, "Category");
    Entry.EntryId = Json::GetString(Item, "EntryId");
    Entry.EntryName = Json::GetString(Item, "EntryName");
    Entry.SourcePath = Json::GetString(Item, "SourcePath");
    Entry.InstalledAt = Json::GetInt(Item, "InstalledAt");
    Entry.Overrides = Json::GetString(Item, "Overrides");

    if (const json_t* Files = json_getProperty(Item, "Files"); Files && json_getType(Files) == JSON_ARRAY) {
      for (const json_t* F = json_getChild(Files); F; F = json_getSibling(F)) {
        InstalledFile File;
        File.Name = Json::GetString(F, "Name");
        File.DestPath = Json::GetString(F, "DestPath");
        File.SourceSize = Json::GetInt(F, "SourceSize");
        File.SourceMTime = Json::GetInt(F, "SourceMTime");
        File.DestSize = Json::GetInt(F, "DestSize");
        File.DestMTime = Json::GetInt(F, "DestMTime");
        Entry.Files.push_back(std::move(File));
      }
    }

    if (!Entry.Category.empty()) {
      M.Entries.push_back(std::move(Entry));
    }
  }

  return M;
}

bool WriteManifest(const std::string& WinePrefix, const Manifest& M) {
  Json::Writer W;
  W.BeginObject();
  W.Int("Version", 1);
  W.Str("Comment", "Written by ppcx86-launch. Records which DXVK/VKD3D build was installed into this prefix, "
                   "so a Proton update silently replacing those DLLs can be detected.");
  W.BeginArray("Installed");
  for (const auto& Entry : M.Entries) {
    W.BeginObject();
    W.Str("Category", Entry.Category);
    W.Str("EntryId", Entry.EntryId);
    W.Str("EntryName", Entry.EntryName);
    W.Str("SourcePath", Entry.SourcePath);
    W.Int("InstalledAt", Entry.InstalledAt);
    W.Str("Overrides", Entry.Overrides);
    W.BeginArray("Files");
    for (const auto& File : Entry.Files) {
      W.BeginObject();
      W.Str("Name", File.Name);
      W.Str("DestPath", File.DestPath);
      W.Int("SourceSize", File.SourceSize);
      W.Int("SourceMTime", File.SourceMTime);
      W.Int("DestSize", File.DestSize);
      W.Int("DestMTime", File.DestMTime);
      W.EndObject();
    }
    W.EndArray();
    W.EndObject();
  }
  W.EndArray();
  W.EndObject();

  return Json::WriteFileAtomic(ManifestPath(WinePrefix), W.Finish());
}

InstallResult Install(RuntimeCategory Category, const RuntimeEntry& Entry, const std::string& WinePrefix, bool Want32Bit) {
  InstallResult Result;

  const auto Source = ExpandPath(Entry.Path);
  if (Source.empty() || !Runtimes::IsDirectory(Source)) {
    Result.Error = fmt::format("'{}' is not a directory", Source);
    return Result;
  }

  const auto System32 = Join(WinePrefix, "drive_c/windows/system32");
  const auto SysWOW64 = Join(WinePrefix, "drive_c/windows/syswow64");
  if (!Runtimes::IsDirectory(System32)) {
    // The prefix has not been created yet. Installing into a directory tree that
    // Wine will later populate would be overwritten on first run, so refuse and
    // let the caller run the title once first.
    Result.Error = fmt::format("prefix at '{}' has no drive_c/windows/system32 yet -- run the title once to create it", WinePrefix);
    return Result;
  }

  const DLLSet& Set = SetFor(Category);
  InstalledRuntime Record;
  Record.Category = std::string {Set.Category};
  Record.EntryId = Entry.Id;
  Record.EntryName = Entry.Name;
  Record.SourcePath = Source;
  Record.InstalledAt = static_cast<int64_t>(std::time(nullptr));

  std::vector<std::string> OverrideNames;

  for (size_t I = 0; I < Set.Count; ++I) {
    const std::string Name {Set.Names[I]};
    if (Name.empty()) {
      continue;
    }
    const auto FileName = Name + ".dll";

    struct Variant {
      std::string SourceDir;
      std::string DestDir;
      bool Wanted;
    };
    const Variant Variants[] {
      {Join(Source, "x64"), System32, true},
      {Join(Source, "x32"), SysWOW64, Want32Bit && Runtimes::IsDirectory(SysWOW64)},
    };

    bool AnyInstalled = false;
    for (const auto& V : Variants) {
      if (!V.Wanted) {
        continue;
      }
      const auto From = Join(V.SourceDir, FileName);
      if (!Runtimes::IsRegularFile(From)) {
        // A build that does not ship this DLL simply keeps the bundled one. This
        // is why the override list is built from what was installed.
        continue;
      }
      const auto To = Join(V.DestDir, FileName);
      if (!CopyFile(From, To, Result.Error)) {
        return Result;
      }

      InstalledFile File;
      File.Name = FileName;
      File.DestPath = To;
      if (const auto Src = SizeAndTime(From)) {
        File.SourceSize = Src->first;
        File.SourceMTime = Src->second;
      }
      if (const auto Dest = SizeAndTime(To)) {
        File.DestSize = Dest->first;
        File.DestMTime = Dest->second;
      }
      Record.Files.push_back(std::move(File));
      AnyInstalled = true;
    }

    if (AnyInstalled) {
      OverrideNames.push_back(Name);
      Result.Installed.push_back(FileName);
    }
  }

  if (Record.Files.empty()) {
    Result.Error = fmt::format("'{}' contains none of the expected DLLs", Source);
    return Result;
  }

  Record.Overrides = BuildOverrides(OverrideNames);
  Result.Overrides = Record.Overrides;

  Manifest M = ReadManifest(WinePrefix);
  M.Replace(std::move(Record));
  if (!WriteManifest(WinePrefix, M)) {
    Result.Error = "DLLs were installed, but the manifest could not be written";
    return Result;
  }

  Result.Ok = true;
  return Result;
}

bool Uninstall(RuntimeCategory Category, const std::string& WinePrefix) {
  Manifest M = ReadManifest(WinePrefix);
  M.Remove(SetFor(Category).Category);
  return WriteManifest(WinePrefix, M);
}

Drift CheckDrift(const Manifest& M, RuntimeCategory Category, const RuntimeEntry* Selected, const std::string& WinePrefix) {
  (void)WinePrefix;
  const auto CategoryName = std::string {SetFor(Category).Category};
  const InstalledRuntime* Installed = M.Find(CategoryName);

  if (!Selected) {
    if (!Installed) {
      return {DriftState::NotSelected, {}};
    }
    return {DriftState::WrongEntry, fmt::format("This prefix has {} from '{}' installed, but no {} is selected. "
                                                "The installed DLLs are still in use.",
                                                CategoryName, Installed->EntryName, CategoryName)};
  }

  if (!Installed) {
    return {DriftState::NotInstalled,
            fmt::format("{} '{}' is selected but has not been installed into this prefix yet.", CategoryName, Selected->Name)};
  }

  if (Installed->EntryId != Selected->Id) {
    return {DriftState::WrongEntry,
            fmt::format("This prefix has {} '{}' installed, but '{}' is selected.", CategoryName, Installed->EntryName, Selected->Name)};
  }

  for (const auto& File : Installed->Files) {
    const auto Current = SizeAndTime(File.DestPath);
    if (!Current) {
      return {DriftState::Overwritten, fmt::format("{} is missing from the prefix. A Proton update replaces these files.", File.Name)};
    }
    if (Current->first != File.DestSize || Current->second != File.DestMTime) {
      // The destination changed without going through the launcher, which is
      // what a Proton prefix update does. Silently reverting to the bundled
      // build is the failure this manifest exists to make visible.
      return {DriftState::Overwritten, fmt::format("{} in the prefix is not the file this launcher installed -- something "
                                                   "replaced it, most likely a Proton update.",
                                                   File.Name)};
    }
  }

  for (const auto& File : Installed->Files) {
    const auto SourceFile = Join(Join(ExpandPath(Selected->Path), "x64"), File.Name);
    const auto Current = SizeAndTime(SourceFile);
    if (Current && (Current->first != File.SourceSize || Current->second != File.SourceMTime)) {
      return {DriftState::SourceNewer,
              fmt::format("{} '{}' has been rebuilt since it was installed into this prefix.", CategoryName, Selected->Name)};
    }
  }

  return {DriftState::Match, {}};
}

std::string CombinedOverrides(const Manifest& M) {
  std::string Out;
  for (const auto& Entry : M.Entries) {
    if (Entry.Overrides.empty()) {
      continue;
    }
    if (!Out.empty()) {
      Out += ';';
    }
    Out += Entry.Overrides;
  }
  return Out;
}

} // namespace FastPPCx86::Launcher::PrefixTools
