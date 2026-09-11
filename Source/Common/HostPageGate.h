// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Config/Config.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/fextl/fmt.h>

#include <cstdlib>
#include <string_view>
#include <unistd.h>

namespace FEX::HostPageGate {
/**
 * @brief The host-page-size startup gate.
 *
 * FEX's guest contract is AT_PAGESZ=4096 and that never changes. What changes
 * with the host kernel is the granularity real mmap/mprotect/munmap demand, and
 * the port that makes that a runtime quantity is staged (docs/PAGE_SIZE_64K_PLAN.md,
 * docs/PAGE_SIZE_64K_EXECUTION.md). Until the guest memory syscalls and mtrack
 * are granule-aware (stages S4/S5), a host page larger than 4096 is not a
 * supported configuration, and the failure modes are silent: deferred signals
 * that never arm and a guest that hangs with no diagnostic.
 *
 * FEX_HOSTPAGEMODE selects what happens on such a host:
 *   abort   (default) - explain and refuse to start.
 *   degrade           - continue, and force SMCChecks=full, which is the
 *                       correctness fallback that does not depend on host-page
 *                       protection granularity. Log the relaxed contract once.
 *   force             - continue, force nothing. For bring-up work.
 *
 * FEX_ALLOW_UNSUPPORTED_PAGE_SIZE=1 is kept as an alias for `force`.
 *
 * Written straight to stderr rather than through LogMan on purpose. FEX_SILENTLOG
 * defaults to on and every LogMan path is swallowed when it is; a gate whose whole
 * purpose is to replace a silent hang with an explanation cannot be silenceable by
 * the default logging config.
 */
enum class Mode {
  Abort,
  Degrade,
  Force,
};

inline Mode ParseMode(std::string_view Value) {
  if (Value == "degrade") {
    return Mode::Degrade;
  }
  if (Value == "force") {
    return Mode::Force;
  }
  return Mode::Abort;
}

inline Mode GetMode(bool ConfigAvailable) {
  // The config layer is only consulted when the caller says it exists: FEXCore::Config's
  // meta layer is a null global until Initialize() runs, and this gate is deliberately
  // callable from before that point.
  if (ConfigAvailable) {
    if (auto Value = FEXCore::Config::Get(FEXCore::Config::CONFIG_HOSTPAGEMODE); Value && *Value) {
      return ParseMode(std::string_view {(*Value)->c_str()});
    }
  }

  if (const char* Env = ::getenv("FEX_HOSTPAGEMODE")) {
    return ParseMode(std::string_view {Env});
  }

  if (const char* Legacy = ::getenv("FEX_ALLOW_UNSUPPORTED_PAGE_SIZE"); Legacy && Legacy[0] == '1') {
    return Mode::Force;
  }

  return Mode::Abort;
}

/**
 * @brief Call first thing in every tool that hosts guest code.
 *
 * No-op on a 4K host, which is every path the shipping build takes today.
 */
inline void CheckHostPageSize(bool ConfigAvailable = false) {
  const long HostPageSize = ::sysconf(_SC_PAGESIZE);
  if (HostPageSize <= 0 || static_cast<uint64_t>(HostPageSize) == FEXCore::Utils::FEX_GUEST_PAGE_SIZE) {
    // Either the expected 4K host, or sysconf failed and there is nothing
    // meaningful to say -- the rest of FEX already treats a failed _SC_PAGESIZE
    // as "assume the guest page size", so do not invent a second policy here.
    return;
  }

  const Mode SelectedMode = GetMode(ConfigAvailable);

  fextl::fmt::print(stderr,
                    "FEX: {}: host page size is {}, but FEX's guest contract and several of its own\n"
                    "mappings still assume {}.\n"
                    "\n"
                    "Structurally fixed as of stage S2 of the 64K port (docs/PAGE_SIZE_64K_EXECUTION.md):\n"
                    "  * the deferred-signal interrupt fault page is an mmap'd host page,\n"
                    "  * the call-ret shadow stack's guard pages are host-granular,\n"
                    "  * the JIT code-buffer / pool / alt-stack guards are host-granular,\n"
                    "  * the 48-bit steal allocator is parameterised on the host page.\n"
                    "\n"
                    "NOT yet fixed, and these are what you will hit:\n"
                    "  * The ELF loader maps PT_LOAD segments at their 4K-congruent file offsets.\n"
                    "    Host mmap requires the offset to be a multiple of {}, so anything dynamically linked fails\n"
                    "    to load. Static binaries are fine. (stage S4)\n"
                    "  * Guest mmap/mprotect/munmap granularity. The guest is told AT_PAGESZ={} and\n"
                    "    places MAP_FIXED mappings on {}-byte boundaries this host cannot represent.\n"
                    "    (stage S4, the granule table)\n"
                    "  * SMC tracking (SMCChecks=mtrack) drives host mprotect at {}-byte granularity.\n"
                    "    (stage S5)\n"
                    "\n"
                    "FEX_HOSTPAGEMODE=abort (default) refuses to start; =degrade continues and forces\n"
                    "SMCChecks=full; =force continues and forces nothing.\n",
                    SelectedMode == Mode::Abort ? "FATAL" : "WARNING", HostPageSize, FEXCore::Utils::FEX_GUEST_PAGE_SIZE, HostPageSize,
                    FEXCore::Utils::FEX_GUEST_PAGE_SIZE, FEXCore::Utils::FEX_GUEST_PAGE_SIZE, FEXCore::Utils::FEX_GUEST_PAGE_SIZE);

  switch (SelectedMode) {
  case Mode::Degrade:
    // SMCChecks=full validates guest code before every run and never installs a host
    // write-protection, so it is the one SMC mode whose correctness does not depend on
    // the host protection granularity matching the guest's.
    if (ConfigAvailable) {
      FEXCore::Config::Set(FEXCore::Config::CONFIG_SMCCHECKS, "2" /* CONFIG_SMC_FULL */);
    }
    fextl::fmt::print(stderr, "FEX: FEX_HOSTPAGEMODE=degrade -- continuing with SMCChecks forced to full.\n"
                              "Relaxed-correctness contract, stated once: guest protections finer than the host\n"
                              "page are tracked but not enforced, sub-page guard pages do not fault, and freed\n"
                              "sub-page memory stays resident. Do not report performance numbers from this mode.\n");
    return;
  case Mode::Force:
    fextl::fmt::print(stderr, "FEX: FEX_HOSTPAGEMODE=force -- continuing, forcing nothing. This is a bring-up aid\n"
                              "for working on host-page-size support, not a supported configuration.\n");
    return;
  case Mode::Abort:
  default: break;
  }

  fextl::fmt::print(stderr, "\nSet FEX_HOSTPAGEMODE=degrade (or =force) to continue anyway.\n");
  FEX_TRAP_EXECUTION;
}
} // namespace FEX::HostPageGate
