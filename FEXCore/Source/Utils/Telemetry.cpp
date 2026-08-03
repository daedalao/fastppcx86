// SPDX-License-Identifier: MIT
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/string.h>
#include <FEXHeaderUtils/Filesystem.h>

#include "Utils/Config.h"

#include <array>
#include <stddef.h>
#include <string_view>
#include <system_error>

namespace FEXCore::Telemetry {
#ifndef FEX_DISABLE_TELEMETRY
std::array<Value, FEXCore::Telemetry::TelemetryType::TYPE_LAST> TelemetryValues = {{}};
std::atomic<PreDumpHookType> PreDumpHook {nullptr};
// Deduced size rather than an explicit TYPE_LAST bound: with the size spelled
// out, an entry list that fell behind the enum would still compile and
// value-initialize the tail to empty names. The static_assert below turns
// that into a compile error instead — the hardening deferred from the
// cb57944a3 fix, where a TYPE_LAST/TYPE_JIT_ADDRESSABLE_LAST bound mismatch
// went unnoticed because nothing tied the two together at compile time.
const std::array TelemetryNames = std::to_array<std::string_view>({
  "Split lock helper entries (PPC64: bypassed by JIT-inline C6/C7 when the SplitLockInlineContained knob is on, so doubleword-contained events do not count here — ARM64 semantics unchanged)",
  "16byte Split atomics",
  "EVEX instructions (AVX512)",
  "16bit CAS Tear",
  "32bit CAS Tear",
  "64bit CAS Tear",
  "128bit CAS Tear",
  "Crash mask",
  "Write 32-bit Segment ES",
  "Write 32-bit Segment SS",
  "Write 32-bit Segment CS",
  "Write 32-bit Segment DS",
  "Uses 32-bit Segment ES",
  "Uses 32-bit Segment SS",
  "Uses 32-bit Segment CS",
  "Uses 32-bit Segment DS",
  "Non-Canonical 64-bit address access",
  "PPC64 Split Lock - doubleword-contained (C3 path)",
  "PPC64 Split Lock - quadword-contained (C4 path)",
  "PPC64 Split Lock - crossing (dual-doubleword CAS under stripe mutex, C4.5 path)",
  "PPC64 Split Lock - container LL/SC retry high-water",
  "PPC64 Split Lock - crossing CAS tear (reported to guest as CAS failure)",
  "PPC64 Split Lock - crossing RMW tear (half-applied; pre-op value returned)",
  "CodeBuffer allocations (growth curve lives in the FEX_BUFSTATS timeline)",
  "CodeBuffer rotations (at MAX_CODE_SIZE; each one discards all translated code)",
  "CodeBuffer peak size in bytes (134217728 means MAX_CODE_SIZE was hit)",
  "CodeBuffer total bytes of host code emitted across the session",
  "CodeBuffer peak live bytes (largest fill level of any single buffer)",
  "CodeBuffer translated blocks discarded across all retirements",
});
static_assert(TelemetryNames.size() == TelemetryType::TYPE_LAST, "TelemetryNames must have exactly one entry per TelemetryType slot");

static bool Enabled {true};
void Initialize() {
  FEX_CONFIG_OPT(DisableTelemetry, DISABLETELEMETRY);
  if (DisableTelemetry) {
    Enabled = false;
    return;
  }

  const auto& DataDirectory = Config::GetTelemetryDirectory();

  // Ensure the folder structure is created for our configuration
  if (!FHU::Filesystem::Exists(DataDirectory) && !FHU::Filesystem::CreateDirectories(DataDirectory)) {
    LogMan::Msg::IFmt("Couldn't create telemetry Folder");
  }
}

void Shutdown(const fextl::string& ApplicationName) {
  if (!Enabled) {
    return;
  }

  // Let lazily-maintained counters finalize before the values are read out.
  if (auto Hook = PreDumpHook.load()) {
    Hook();
  }

  auto DataDirectory = Config::GetTelemetryDirectory() + ApplicationName + ".telem";

  // Retain a single backup if the telemetry already existed.
  auto Backup = DataDirectory + ".bck";

  // Failure on rename is okay.
  (void)FHU::Filesystem::RenameFile(DataDirectory, Backup);

  auto File = FEXCore::File::File(DataDirectory.c_str(),
                                  FEXCore::File::FileModes::WRITE | FEXCore::File::FileModes::CREATE | FEXCore::File::FileModes::TRUNCATE);

  if (File.IsValid()) {
    for (size_t i = 0; i < TelemetryType::TYPE_LAST; ++i) {
      auto& Name = TelemetryNames.at(i);
      auto& Data = TelemetryValues.at(i);
      fextl::fmt::print(File, "{}: {}\n", Name, Data.load());
    }
    File.Flush();
  }
}

#endif
} // namespace FEXCore::Telemetry
