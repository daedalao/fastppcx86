// SPDX-License-Identifier: MIT
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

/**
 * Host CPU topology, and the affinity cage derived from it.
 *
 * The cage is not a nicety. Unity sizes its worker and job pools from the CPU
 * count the guest reports, and on a wide host an uncaged guest builds a pool
 * whose park gate is statistically unreachable -- it spins instead of parking
 * and the title crawls (docs/GAMING.md measured Hard West at ~2 fps this way).
 *
 * Everything here is read from sysfs at the moment of launch. Nothing about the
 * machine may be assumed or cached: `ppc64_cpu --smt=N` changes *which* CPUs are
 * online without renumbering them, so a stored CPU list silently changes meaning
 * between one launch and the next.
 */
namespace FastPPCx86::Launcher::Topology {

struct CPU {
  int Id {};
  int Node {-1};    ///< -1 when NUMA information was unreadable.
  int Package {-1}; ///< -1 when topology information was unreadable.
  int Core {-1};    ///< -1 when topology information was unreadable.
};

struct Machine {
  std::vector<CPU> OnlineCPUs;
  bool HasTopology {false}; ///< package/core were readable for every online CPU.
  bool HasNUMA {false};     ///< node membership was readable.
  /// Non-empty when something could not be read. Shown to the user rather than guessed around.
  std::string Problem;

  std::vector<int> Nodes() const;
  /// Distinct (package, core) pairs on a node. `Node < 0` counts the whole machine.
  int CoreCount(int Node) const;
  /// Largest number of online threads any single core on `Node` offers.
  int MaxThreadsPerCore(int Node) const;
  /// Node with the most online CPUs; lowest id wins a tie. -1 when there are none.
  int LargestNode() const;
};

/**
 * @param SysfsRoot Root to read below, so tests can point at a synthetic tree.
 *                  Production callers pass the default.
 */
Machine ReadMachine(const std::string& SysfsRoot = "/sys");

enum class CageMode {
  Auto,   ///< Derive from the machine.
  Custom, ///< Use CagePolicy::CustomList verbatim.
  None,   ///< No affinity restriction at all.
};

struct CagePolicy {
  CageMode Mode {CageMode::Auto};
  int Node {-1};          ///< -1: use the largest node.
  int Cores {0};          ///< 0: use (cores on node - Reserve), floored at 1.
  int ThreadsPerCore {2}; ///< Clamped to what the machine actually offers.
  int Reserve {2};        ///< Cores left to the host: compositor, streaming, IRQ.
  std::string CustomList; ///< Only read when Mode == Custom.
};

struct Cage {
  std::vector<int> CPUs;   ///< Empty means "do not restrict affinity".
  std::string List;        ///< Compressed form, e.g. "0-1,8-9,16-17".
  std::string Explanation; ///< Always populated; displayed before launch.
  std::string Warning;     ///< Non-empty when the request could not be honoured as asked.
};

Cage Resolve(const Machine& Machine, const CagePolicy& Policy);

std::string FormatCPUList(const std::vector<int>& CPUs);
std::optional<std::vector<int>> ParseCPUList(std::string_view List);

} // namespace FastPPCx86::Launcher::Topology
