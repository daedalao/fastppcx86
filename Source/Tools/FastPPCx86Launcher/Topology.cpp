// SPDX-License-Identifier: MIT
#include "Topology.h"
#include "Json.h"

#include <fmt/format.h>

#include <algorithm>
#include <charconv>
#include <iterator>
#include <map>
#include <set>

namespace FastPPCx86::Launcher::Topology {

namespace {
  std::string_view Trim(std::string_view View) {
    while (!View.empty() && (View.back() == '\n' || View.back() == '\r' || View.back() == ' ')) {
      View.remove_suffix(1);
    }
    while (!View.empty() && View.front() == ' ') {
      View.remove_prefix(1);
    }
    return View;
  }

  std::optional<int> ReadIntFile(const std::string& Path) {
    std::string Contents;
    if (!Json::ReadFile(Path, Contents)) {
      return std::nullopt;
    }
    const auto View = Trim(Contents);
    int Value {};
    if (std::from_chars(View.data(), View.data() + View.size(), Value).ec != std::errc {}) {
      return std::nullopt;
    }
    return Value;
  }

  /// A core is only identified by (package, core_id) together: core_id is unique
  /// within a package, not across the machine.
  using CoreKey = std::pair<int, int>;
} // namespace

std::optional<std::vector<int>> ParseCPUList(std::string_view List) {
  std::vector<int> Result;
  List = Trim(List);
  if (List.empty()) {
    return Result;
  }

  size_t Pos {};
  while (Pos <= List.size()) {
    const size_t Comma = List.find(',', Pos);
    std::string_view Item = List.substr(Pos, Comma == std::string_view::npos ? std::string_view::npos : Comma - Pos);
    Item = Trim(Item);
    if (!Item.empty()) {
      const size_t Dash = Item.find('-');
      int Low {};
      int High {};
      const auto* ItemEnd = Item.data() + Item.size();
      if (Dash == std::string_view::npos) {
        if (std::from_chars(Item.data(), ItemEnd, Low).ec != std::errc {}) {
          return std::nullopt;
        }
        High = Low;
      } else {
        if (std::from_chars(Item.data(), Item.data() + Dash, Low).ec != std::errc {}) {
          return std::nullopt;
        }
        if (std::from_chars(Item.data() + Dash + 1, ItemEnd, High).ec != std::errc {}) {
          return std::nullopt;
        }
      }
      if (Low < 0 || High < Low) {
        return std::nullopt;
      }
      for (int I = Low; I <= High; ++I) {
        Result.push_back(I);
      }
    }
    if (Comma == std::string_view::npos) {
      break;
    }
    Pos = Comma + 1;
  }

  std::sort(Result.begin(), Result.end());
  Result.erase(std::unique(Result.begin(), Result.end()), Result.end());
  return Result;
}

std::string FormatCPUList(const std::vector<int>& CPUs) {
  if (CPUs.empty()) {
    return {};
  }

  std::vector<int> Sorted = CPUs;
  std::sort(Sorted.begin(), Sorted.end());
  Sorted.erase(std::unique(Sorted.begin(), Sorted.end()), Sorted.end());

  std::string Out;
  for (size_t I = 0; I < Sorted.size();) {
    size_t J = I;
    while (J + 1 < Sorted.size() && Sorted[J + 1] == Sorted[J] + 1) {
      ++J;
    }
    if (!Out.empty()) {
      Out += ',';
    }
    if (J == I) {
      fmt::format_to(std::back_inserter(Out), "{}", Sorted[I]);
    } else {
      fmt::format_to(std::back_inserter(Out), "{}-{}", Sorted[I], Sorted[J]);
    }
    I = J + 1;
  }
  return Out;
}

std::vector<int> Machine::Nodes() const {
  std::set<int> Unique;
  for (const auto& CPU : OnlineCPUs) {
    if (CPU.Node >= 0) {
      Unique.insert(CPU.Node);
    }
  }
  return {Unique.begin(), Unique.end()};
}

int Machine::CoreCount(int Node) const {
  std::set<CoreKey> Cores;
  for (const auto& CPU : OnlineCPUs) {
    if (Node >= 0 && CPU.Node != Node) {
      continue;
    }
    if (CPU.Package >= 0 && CPU.Core >= 0) {
      Cores.insert({CPU.Package, CPU.Core});
    }
  }
  return static_cast<int>(Cores.size());
}

int Machine::MaxThreadsPerCore(int Node) const {
  std::map<CoreKey, int> Counts;
  for (const auto& CPU : OnlineCPUs) {
    if (Node >= 0 && CPU.Node != Node) {
      continue;
    }
    if (CPU.Package >= 0 && CPU.Core >= 0) {
      ++Counts[{CPU.Package, CPU.Core}];
    }
  }
  int Max {};
  for (const auto& [Key, Count] : Counts) {
    Max = std::max(Max, Count);
  }
  return Max;
}

int Machine::LargestNode() const {
  std::map<int, int> Counts;
  for (const auto& CPU : OnlineCPUs) {
    if (CPU.Node >= 0) {
      ++Counts[CPU.Node];
    }
  }
  int Best {-1};
  int BestCount {};
  for (const auto& [Node, Count] : Counts) {
    // Strictly greater, so the lowest-numbered node wins a tie and the cage is
    // reproducible across launches.
    if (Count > BestCount) {
      Best = Node;
      BestCount = Count;
    }
  }
  return Best;
}

Machine ReadMachine(const std::string& SysfsRoot) {
  Machine Result;

  const std::string CPURoot = SysfsRoot + "/devices/system/cpu";
  std::string OnlineContents;
  if (!Json::ReadFile(CPURoot + "/online", OnlineContents)) {
    Result.Problem = fmt::format("could not read {}/online", CPURoot);
    return Result;
  }

  const auto Online = ParseCPUList(OnlineContents);
  if (!Online || Online->empty()) {
    Result.Problem = fmt::format("{}/online did not parse as a CPU list", CPURoot);
    return Result;
  }

  Result.OnlineCPUs.reserve(Online->size());
  bool AllTopologyRead = true;
  for (const int Id : *Online) {
    CPU Entry;
    Entry.Id = Id;
    const std::string Base = fmt::format("{}/cpu{}/topology", CPURoot, Id);
    const auto Package = ReadIntFile(Base + "/physical_package_id");
    const auto Core = ReadIntFile(Base + "/core_id");
    if (Package && Core) {
      Entry.Package = *Package;
      Entry.Core = *Core;
    } else {
      AllTopologyRead = false;
    }
    Result.OnlineCPUs.push_back(Entry);
  }
  Result.HasTopology = AllTopologyRead;

  // NUMA membership comes from the node side: node<N>/cpulist is the only place
  // it is expressed, there is no per-CPU file for it.
  const std::string NodeRoot = SysfsRoot + "/devices/system/node";
  for (int NodeId = 0; NodeId < 256; ++NodeId) {
    std::string Contents;
    if (!Json::ReadFile(fmt::format("{}/node{}/cpulist", NodeRoot, NodeId), Contents)) {
      continue;
    }
    const auto NodeCPUs = ParseCPUList(Contents);
    if (!NodeCPUs) {
      continue;
    }
    for (const int Id : *NodeCPUs) {
      auto It = std::find_if(Result.OnlineCPUs.begin(), Result.OnlineCPUs.end(), [Id](const CPU& C) { return C.Id == Id; });
      if (It != Result.OnlineCPUs.end()) {
        It->Node = NodeId;
        Result.HasNUMA = true;
      }
    }
  }

  if (!Result.HasTopology) {
    Result.Problem = "CPU topology (physical_package_id / core_id) was not readable for every online CPU";
  } else if (!Result.HasNUMA) {
    // Not an error. A single-node machine exposes no node directories at all,
    // and treating the whole machine as one node is exactly right there.
    Result.Problem.clear();
  }

  return Result;
}

Cage Resolve(const Machine& Host, const CagePolicy& Policy) {
  Cage Result;

  if (Policy.Mode == CageMode::None) {
    Result.Explanation = "No affinity cage: the title may use every online CPU.";
    return Result;
  }

  if (Policy.Mode == CageMode::Custom) {
    const auto Requested = ParseCPUList(Policy.CustomList);
    if (!Requested) {
      Result.Explanation = "No cage applied.";
      Result.Warning = fmt::format("'{}' is not a valid CPU list, so no cage was applied.", Policy.CustomList);
      return Result;
    }

    std::set<int> OnlineSet;
    for (const auto& CPU : Host.OnlineCPUs) {
      OnlineSet.insert(CPU.Id);
    }

    std::vector<int> Offline;
    for (const int Id : *Requested) {
      if (OnlineSet.count(Id)) {
        Result.CPUs.push_back(Id);
      } else {
        Offline.push_back(Id);
      }
    }

    if (!Offline.empty()) {
      // Worth saying out loud: after an SMT mode change a hand-written list
      // keeps its numbers but loses half its CPUs, and the symptom is a title
      // that simply got slower.
      Result.Warning = fmt::format("CPUs {} are not online and were dropped from the cage.", FormatCPUList(Offline));
    }
    if (Result.CPUs.empty()) {
      Result.Warning += " No online CPU remained, so no cage was applied.";
      Result.Explanation = "No cage applied.";
      return Result;
    }

    Result.List = FormatCPUList(Result.CPUs);
    Result.Explanation = fmt::format("Custom cage: {} ({} CPUs).", Result.List, Result.CPUs.size());
    return Result;
  }

  // --- Auto ---------------------------------------------------------------
  if (Host.OnlineCPUs.empty()) {
    Result.Explanation = "No cage applied.";
    Result.Warning = Host.Problem.empty() ? "No online CPUs were found." : Host.Problem;
    return Result;
  }

  if (!Host.HasTopology) {
    // Without package/core there is no way to say "two threads per core", and
    // guessing produces a cage that looks deliberate and is not. Say so instead.
    Result.Explanation = "No cage applied: the host's CPU topology could not be read, so a per-core cage cannot be derived.";
    Result.Warning = Host.Problem;
    return Result;
  }

  int Node = Policy.Node;
  const auto Nodes = Host.Nodes();
  if (Node >= 0 && std::find(Nodes.begin(), Nodes.end(), Node) == Nodes.end()) {
    Result.Warning = fmt::format("NUMA node {} does not exist on this host; using the largest node instead.", Node);
    Node = -1;
  }
  if (Node < 0) {
    Node = Host.LargestNode();
  }

  // Group the node's online CPUs by core, in a deterministic order.
  std::map<CoreKey, std::vector<int>> Cores;
  for (const auto& CPU : Host.OnlineCPUs) {
    if (Node >= 0 && CPU.Node != Node) {
      continue;
    }
    if (CPU.Package < 0 || CPU.Core < 0) {
      continue;
    }
    Cores[{CPU.Package, CPU.Core}].push_back(CPU.Id);
  }
  for (auto& [Key, CPUs] : Cores) {
    std::sort(CPUs.begin(), CPUs.end());
  }

  if (Cores.empty()) {
    Result.Explanation = "No cage applied: no cores were found on the selected NUMA node.";
    return Result;
  }

  const int CoresAvailable = static_cast<int>(Cores.size());
  const int ThreadsAvailable = Host.MaxThreadsPerCore(Node);

  // Reserve is a request, not a guarantee: a small host has to keep at least one
  // core for the title, and the floor is what makes a 4-core machine work.
  const int Reserve = std::max(0, Policy.Reserve);
  int UseCores = Policy.Cores > 0 ? Policy.Cores : CoresAvailable - Reserve;
  UseCores = std::clamp(UseCores, 1, CoresAvailable);

  int UseThreads = Policy.ThreadsPerCore > 0 ? Policy.ThreadsPerCore : 1;
  UseThreads = std::clamp(UseThreads, 1, std::max(1, ThreadsAvailable));

  int Taken {};
  for (const auto& [Key, CPUs] : Cores) {
    if (Taken >= UseCores) {
      break;
    }
    for (size_t I = 0; I < CPUs.size() && static_cast<int>(I) < UseThreads; ++I) {
      Result.CPUs.push_back(CPUs[I]);
    }
    ++Taken;
  }

  std::sort(Result.CPUs.begin(), Result.CPUs.end());
  Result.List = FormatCPUList(Result.CPUs);

  const std::string NodeDesc = Node >= 0 ? fmt::format("NUMA node {}", Node) : std::string {"this host"};
  Result.Explanation = fmt::format("{} has {} online cores x {} threads. Using {} cores x {} threads = {} CPUs ({}).", NodeDesc,
                                   CoresAvailable, ThreadsAvailable, UseCores, UseThreads, Result.CPUs.size(), Result.List);

  if (Policy.Cores == 0 && Reserve > 0 && CoresAvailable - Reserve < 1) {
    Result.Warning = fmt::format("Only {} core(s) available, so the {}-core host reservation was not applied.", CoresAvailable, Reserve);
  }

  return Result;
}

} // namespace FastPPCx86::Launcher::Topology
