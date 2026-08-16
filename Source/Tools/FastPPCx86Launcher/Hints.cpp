// SPDX-License-Identifier: MIT
#include "Hints.h"
#include "Json.h"
#include "Registry.h"

#include <Common/Config.h>
#include <Common/JSONPool.h>
#include <PortabilityInfo.h>

#include <tiny-json.h>

#include <algorithm>
#include <cctype>

#ifndef GLOBAL_DATA_DIRECTORY
#define GLOBAL_DATA_DIRECTORY "/usr/share/fex-emu/"
#endif

namespace FastPPCx86::Launcher::Hints {

namespace {
  std::string LowerCase(std::string_view Text) {
    std::string Out {Text};
    std::transform(Out.begin(), Out.end(), Out.begin(), [](unsigned char C) { return static_cast<char>(std::tolower(C)); });
    return Out;
  }

  void LoadInto(std::vector<Hint>& Out, const std::string& Path) {
    std::string Contents;
    if (!Json::ReadFile(Path, Contents) || Contents.empty()) {
      return;
    }

    FEX::JSON::JsonAllocator Pool {};
    const json_t* Root = FEX::JSON::CreateJSON(Contents, Pool);
    if (!Root) {
      return;
    }

    const json_t* Array = json_getProperty(Root, "Hints");
    if (!Array || json_getType(Array) != JSON_ARRAY) {
      return;
    }

    for (const json_t* Item = json_getChild(Array); Item; Item = json_getSibling(Item)) {
      Hint H;
      if (const json_t* MatchObj = json_getProperty(Item, "Match")) {
        H.Basename = Json::GetString(MatchObj, "Basename");
        H.AppId = Json::GetInt(MatchObj, "AppId");
      }
      H.Why = Json::GetString(Item, "Why");
      if (const json_t* FexObj = json_getProperty(Item, "Fex")) {
        for (const json_t* E = json_getChild(FexObj); E; E = json_getSibling(E)) {
          if (const char* Name = json_getName(E); Name && json_getValue(E)) {
            H.Fex[Name] = json_getValue(E);
          }
        }
      }
      if (H.Basename.empty() && H.AppId == 0) {
        continue;
      }
      if (H.Fex.empty()) {
        continue;
      }
      Out.push_back(std::move(H));
    }
  }
} // namespace

std::string PackagedPath() {
  return std::string {GLOBAL_DATA_DIRECTORY} + "LauncherHints.json";
}

std::string UserPath() {
  auto Dir = std::string {FEX::Config::GetDataDirectory(false, FEX::ReadPortabilityInformation()).c_str()};
  while (Dir.size() > 1 && Dir.back() == '/') {
    Dir.pop_back();
  }
  return Dir + "/LauncherHints.json";
}

std::vector<Hint> Load() {
  std::vector<Hint> All;
  LoadInto(All, PackagedPath());
  // Loaded second so a user entry for the same title takes precedence in Match,
  // which scans from the back.
  LoadInto(All, UserPath());
  return All;
}

const Hint* Match(const std::vector<Hint>& All, std::string_view Basename, int64_t AppId) {
  const auto Wanted = LowerCase(Basename);

  // An appid identifies a title exactly; a basename is only a good guess, since
  // plenty of games ship a binary called "game" or "launcher".
  if (AppId != 0) {
    for (auto It = All.rbegin(); It != All.rend(); ++It) {
      if (It->AppId == AppId) {
        return &*It;
      }
    }
  }

  for (auto It = All.rbegin(); It != All.rend(); ++It) {
    if (!It->Basename.empty() && LowerCase(It->Basename) == Wanted) {
      return &*It;
    }
  }

  return nullptr;
}

} // namespace FastPPCx86::Launcher::Hints
