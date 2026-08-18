// SPDX-License-Identifier: MIT
#include "ProcessProbe.h"
#include "Json.h"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <map>
#include <unistd.h>

namespace FastPPCx86::Launcher::ProcessProbe {

namespace {
  namespace fs = std::filesystem;

  std::vector<pid_t> AllPids() {
    std::vector<pid_t> Pids;
    std::error_code EC;
    for (fs::directory_iterator It {"/proc", fs::directory_options::skip_permission_denied, EC}; !EC && It != fs::directory_iterator {};
         It.increment(EC)) {
      const auto Name = It->path().filename().string();
      if (Name.empty() || !std::all_of(Name.begin(), Name.end(), [](unsigned char C) { return std::isdigit(C); })) {
        continue;
      }
      pid_t Pid {};
      if (std::from_chars(Name.data(), Name.data() + Name.size(), Pid).ec == std::errc {}) {
        Pids.push_back(Pid);
      }
    }
    return Pids;
  }

  std::optional<pid_t> ParentOf(pid_t Pid) {
    std::string Contents;
    if (!Json::ReadFile(fmt::format("/proc/{}/status", Pid), Contents)) {
      return std::nullopt;
    }
    const auto Key = Contents.find("PPid:");
    if (Key == std::string::npos) {
      return std::nullopt;
    }
    size_t Pos = Key + 5;
    while (Pos < Contents.size() && std::isspace(static_cast<unsigned char>(Contents[Pos]))) {
      ++Pos;
    }
    pid_t Parent {};
    if (std::from_chars(Contents.data() + Pos, Contents.data() + Contents.size(), Parent).ec != std::errc {}) {
      return std::nullopt;
    }
    return Parent;
  }

  bool LooksLikeEmulator(const GuestProcess& Process) {
    const auto Name = fs::path {Process.Exe}.filename().string();
    return Name == "FEX" || Name == "FEXBash" || Name == "FEXInterpreter" || Process.Comm == "FEX" || Process.Comm == "FEXInterpreter";
  }
} // namespace

std::vector<pid_t> Descendants(pid_t Root) {
  // Build the child lists in one pass over /proc, then walk down. Repeatedly
  // scanning /proc per level is O(n*depth) and races much harder with a process
  // tree that is still starting up.
  std::map<pid_t, std::vector<pid_t>> Children;
  for (const pid_t Pid : AllPids()) {
    if (const auto Parent = ParentOf(Pid)) {
      Children[*Parent].push_back(Pid);
    }
  }

  std::vector<pid_t> Result {Root};
  for (size_t I = 0; I < Result.size(); ++I) {
    const auto Found = Children.find(Result[I]);
    if (Found == Children.end()) {
      continue;
    }
    for (const pid_t Child : Found->second) {
      if (std::find(Result.begin(), Result.end(), Child) == Result.end()) {
        Result.push_back(Child);
      }
    }
  }
  return Result;
}

std::optional<GuestProcess> Inspect(pid_t Pid) {
  const auto Base = fmt::format("/proc/{}", Pid);

  std::string Environ;
  if (!Json::ReadFile(Base + "/environ", Environ)) {
    // Either the process is gone, or it belongs to another user. Both mean there
    // is nothing to report rather than something to warn about.
    return std::nullopt;
  }

  GuestProcess Process;
  Process.Pid = Pid;

  std::string Comm;
  if (Json::ReadFile(Base + "/comm", Comm)) {
    while (!Comm.empty() && (Comm.back() == '\n' || Comm.back() == '\r')) {
      Comm.pop_back();
    }
    Process.Comm = Comm;
  }

  // readlink rather than std::filesystem::read_symlink: the kernel appends
  // " (deleted)" to the target and that suffix is the whole point here.
  char Link[4096];
  const ssize_t Length = ::readlink((Base + "/exe").c_str(), Link, sizeof(Link) - 1);
  if (Length > 0) {
    Process.Exe.assign(Link, static_cast<size_t>(Length));
    static constexpr std::string_view Deleted {" (deleted)"};
    if (Process.Exe.size() > Deleted.size() && Process.Exe.compare(Process.Exe.size() - Deleted.size(), Deleted.size(), Deleted) == 0) {
      Process.ExeDeleted = true;
      Process.Exe.resize(Process.Exe.size() - Deleted.size());
    }
  }

  size_t Start {};
  for (size_t I = 0; I <= Environ.size(); ++I) {
    if (I != Environ.size() && Environ[I] != '\0') {
      continue;
    }
    if (I > Start) {
      const std::string_view Entry {Environ.data() + Start, I - Start};
      if (Entry.rfind("FEX", 0) == 0) {
        if (const auto Equals = Entry.find('='); Equals != std::string_view::npos) {
          Process.FexVars.emplace(std::string {Entry.substr(0, Equals)}, std::string {Entry.substr(Equals + 1)});
        }
      }
    }
    Start = I + 1;
  }

  return Process;
}

std::optional<GuestProcess> FindGuest(pid_t Root) {
  std::optional<GuestProcess> Best;
  for (const pid_t Pid : Descendants(Root)) {
    auto Process = Inspect(Pid);
    if (!Process) {
      continue;
    }
    if (!LooksLikeEmulator(*Process)) {
      continue;
    }
    // Prefer the emulator proper over the FEXBash that spawned it: for the
    // Proton and Steam kinds the interesting environment is the one the guest
    // binary is running under, several processes down.
    const auto Name = fs::path {Process->Exe}.filename().string();
    if (!Best || (Name != "FEXBash" && fs::path {Best->Exe}.filename().string() == "FEXBash")) {
      Best = std::move(Process);
    }
  }
  return Best;
}

Comparison Compare(const std::map<std::string, std::string>& Expected, const std::map<std::string, std::string>& Actual) {
  Comparison Result;

  for (const auto& [Key, Value] : Expected) {
    const auto Found = Actual.find(Key);
    if (Found == Actual.end()) {
      Result.Differences.push_back({Key, Value, {}, true});
    } else if (Found->second != Value) {
      Result.Differences.push_back({Key, Value, Found->second, false});
    }
  }

  for (const auto& [Key, Value] : Actual) {
    if (Expected.find(Key) == Expected.end()) {
      Result.Unexpected.push_back(Key);
    }
  }

  return Result;
}

} // namespace FastPPCx86::Launcher::ProcessProbe
