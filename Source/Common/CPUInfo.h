// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

namespace FEX::CPUInfo {
/**
 * @brief Calculate the number of CPUs in the system regardless of affinity mask.
 *
 * @return The number of CPUs in the system.
 */
uint32_t CalculateNumberOfCPUs();

#ifndef _WIN32
/**
 * FEX presents the guest a dense CPU id space [0, N). On hosts with sparse
 * online CPU ids (POWER8 running SMT4-of-8 has online ids up to 155 with only
 * 80 online) or a narrowed affinity mask, raw host CPU ids leak out of that
 * fiction: sched_getcpu() hands back ids >= the count the guest was told, and
 * guests that size per-CPU arrays from the count take out-of-bounds accesses.
 *
 * The map is built once, from the online CPU list intersected with the
 * process affinity mask at startup, right next to the count logic so the two
 * cannot disagree. Every guest-visible producer of CPU ids or CPU masks must
 * go through it.
 */

///< Number of guest-visible CPU ids; every MapHostToGuestCPU result is below this.
uint32_t MappedCPUCount();

///< Translate a raw host CPU id into the guest's dense id space.
uint32_t MapHostToGuestCPU(uint32_t HostCPU);

///< Translate a dense guest CPU id back to the host id it stands for.
///< Returns the id unchanged when it is outside the guest's fiction.
uint32_t MapGuestToHostCPU(uint32_t GuestCPU);
#endif
} // namespace FEX::CPUInfo
