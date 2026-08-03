// SPDX-License-Identifier: MIT
#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXHeaderUtils/Filesystem.h>

#include <fmt/compile.h>
#include <fmt/format.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#ifdef _WIN32
#include <thread>
#else
#include <cstdio>
#include <cstring>
#include <linux/limits.h>
#include <sched.h>
#endif

namespace FEX::CPUInfo {
// Optional override for the core count reported to the guest.
//
// Each guest thread costs FEX a large chunk of *address space*: a per-thread
// LookupCache (VirtualMemSize/PAGE_SIZE*8 + CODE_SIZE + L1, 272 MiB with the
// defaults) plus allocator arenas, and those reservations are interleaved with
// the guest's own mappings. On a machine with many cores this is severe: on an
// 80-core POWER8, Unity 4.x sizes its job pool from the reported core count,
// FEX ends up holding ~69 GiB of reservations against the guest's ~6 GiB, and
// the guest's heaps get scattered across ~20 different 4 GiB regions.
// Applications that index their own allocator metadata by (address >> 32) --
// Unity does, with a fixed 5-entry table -- then overflow that table and fail.
//
// Reporting fewer cores keeps the guest's thread count, and therefore FEX's
// address-space footprint, under control. Note taskset/affinity does NOT help
// here, because this count feeds the emulated /proc/cpuinfo the guest reads.
static uint32_t GetCPUCountOverride() {
  FEX_CONFIG_OPT(ReportedCPUs, REPORTED_CPUS);
  const uint32_t Value = ReportedCPUs();
  // Clamp to something sane; 0 or garbage means "no override".
  if (Value == 0 || Value > 4096) {
    return 0;
  }
  LogMan::Msg::IFmt("FEX_REPORTED_CPUS override active: reporting {} CPUs to guest", Value);
  return Value;
}

#ifndef _WIN32
// Parse a Linux CPU-list string like "0-3,8-11,16" and count members.
// Returns 0 if the string is malformed.
static uint32_t ParseCPUList(const char* s) {
  uint32_t count = 0;
  while (*s) {
    char* end = nullptr;
    long lo = std::strtol(s, &end, 10);
    if (end == s) {
      return 0; // malformed
    }
    long hi = lo;
    s = end;
    if (*s == '-') {
      ++s;
      hi = std::strtol(s, &end, 10);
      if (end == s) {
        return 0; // malformed
      }
      s = end;
    }
    if (hi < lo) {
      return 0;
    }
    count += static_cast<uint32_t>(hi - lo + 1);
    if (*s == ',') {
      ++s;
    } else if (*s != '\0' && *s != '\n') {
      return 0; // malformed
    }
  }
  return count;
}

uint32_t CalculateNumberOfCPUs() {
  if (const uint32_t Override = GetCPUCountOverride()) {
    return Override;
  }
  // Prefer /sys/devices/system/cpu/online — this reports only CPUs that are
  // actually online for scheduling. The legacy approach of counting
  // /sys/devices/system/cpu/cpu{N} directory entries incorrectly returns
  // every *configured* CPU, including those parked by SMT-off, cpuset
  // exclusion, or boot-time offlining. On POWER8 with SMT4-of-8, this
  // would report 160 when only 80 are usable; std::thread::hardware_
  // concurrency() then propagates the inflated count to applications,
  // which spawn 2x the threads they should and starve the scheduler.
  if (FILE* f = std::fopen("/sys/devices/system/cpu/online", "r")) {
    char buf[256] = {};
    size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    // Strip trailing newline.
    if (n > 0 && buf[n - 1] == '\n') {
      buf[n - 1] = '\0';
    }
    uint32_t parsed = ParseCPUList(buf);
    if (parsed > 0) {
      return parsed;
    }
  }

  // Fallback: directory-walk every configured CPU. Inflates on SMT-off
  // systems but is correct on machines where all CPUs are online.
  constexpr auto parse_string = FMT_COMPILE("/sys/devices/system/cpu/cpu{}");
  constexpr auto max_parse_size = ::fmt::formatted_size(parse_string, UINT32_MAX);
  char Tmp[max_parse_size];
  size_t CPUs = 1;

  for (;; ++CPUs) {
    auto Size = fmt::format_to_n(Tmp, max_parse_size, parse_string, CPUs);
    Tmp[Size.size] = 0;
    if (!FHU::Filesystem::Exists(Tmp)) {
      break;
    }
  }

  return CPUs;
}
#else
uint32_t CalculateNumberOfCPUs() {
  if (const uint32_t Override = GetCPUCountOverride()) {
    return Override;
  }
  // May not return correct number of cores if some are parked.
  return std::thread::hardware_concurrency();
}
#endif
} // namespace FEX::CPUInfo
