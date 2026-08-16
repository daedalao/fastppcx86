// SPDX-License-Identifier: MIT
#include "Session.h"
#include "Json.h"

#include <fmt/format.h>

namespace FastPPCx86::Launcher {

bool Session::Load(std::string& Error, bool RunDiscovery) {
  Path_ = RegistryPath();

  std::string Existing;
  FirstRun_ = !Json::ReadFile(Path_, Existing) || Existing.empty();

  if (!Registry_.Load(Path_, Error)) {
    return false;
  }

  if (RunDiscovery) {
    // Run on every start, not only the first. Discovery is additive and
    // idempotent, so a Proton build installed since the last run simply shows
    // up, and nothing the user configured is touched.
    Report_ = Discovery::Populate(Registry_);
    if (FirstRun_ || Report_.TotalAdded() > 0) {
      std::string SaveError;
      Save(SaveError);
    }
  }

  return true;
}

bool Session::Save(std::string& Error) {
  if (Path_.empty()) {
    Path_ = RegistryPath();
  }
  return Registry_.Save(Path_, Error);
}

Discovery::Report Session::Rescan() {
  Report_ = Discovery::Populate(Registry_);
  return Report_;
}

Runtimes::Validity Session::Check(RuntimeCategory Category, const RuntimeEntry& Entry) const {
  return Runtimes::Validate(Category, Entry);
}

std::string Session::SummariseCategory(RuntimeCategory Category) const {
  const auto& List = Registry_.List(Category);
  if (List.empty()) {
    return "none found";
  }

  int Valid {};
  for (const auto& Entry : List) {
    if (Entry.Enabled && Runtimes::Validate(Category, Entry).Ok) {
      ++Valid;
    }
  }

  if (Valid == static_cast<int>(List.size())) {
    return fmt::format("{} found", Valid);
  }
  return fmt::format("{} of {} usable", Valid, List.size());
}

} // namespace FastPPCx86::Launcher
