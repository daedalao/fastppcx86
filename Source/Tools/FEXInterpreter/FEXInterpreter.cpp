// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|FEX
desc: Glues the ELF loader, FEXCore and LinuxSyscalls to launch an elf under fex
$end_info$
*/

#include "Common/ArgumentLoader.h"
#include "Common/FEXServerClient.h"
#include "Common/Config.h"
#include "Common/HostFeatures.h"
#include "Common/Linux/SBRKAllocations.h"
#include "PortabilityInfo.h"
#include "ELFCodeLoader.h"
#include "VDSO_Emulation.h"
#include "LinuxSyscalls/GdbServer.h"
#include "LinuxSyscalls/HostOwnedRanges.h"
#include "LinuxSyscalls/LinuxAllocator.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/Utils/Threads.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "Linux/Utils/ELFContainer.h"
#include "Thunks.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
// Explicit rather than transitive: the host-page-size gate takes offsetof/sizeof
// of InternalThreadState, so its definition has to be guaranteed here.
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/FileLoading.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/Telemetry.h>
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/PrctlUtils.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <FEXHeaderUtils/StringArgumentParser.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <mutex>
#include <queue>
#include <set>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

#include <sys/sysinfo.h>
#include <sys/signal.h>

namespace FEX::Logging {
static bool SilentLog {};
static int OutputFD {STDERR_FILENO};

// Set an empty style to disable coloring when FEXServer output is e.g. piped to a file
static bool DisableOutputColors {};

void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  if (SilentLog) {
    return;
  }

  const auto Style = DisableOutputColors ? fmt::text_style {} : LogMan::DebugLevelStyle(Level);
  const auto Output = fextl::fmt::format("{} {}\n", fmt::styled(LogMan::DebugLevelStr(Level), Style), Message);
  write(OutputFD, Output.c_str(), Output.size());
  fsync(OutputFD);
}

void AssertHandler(const char* Message) {
  return MsgHandler(LogMan::ASSERT, Message);
}

namespace FEXServer {
  static int FEXServerFD {-1};

  void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
    FEXServerClient::MsgHandler(FEXServerFD, Level, Message);
  }

  void AssertHandler(const char* Message) {
    FEXServerClient::AssertHandler(FEXServerFD, Message);
  }
} // namespace FEXServer

void Init() {
  FEX_CONFIG_OPT(SilentLog, SILENTLOG);
  FEX_CONFIG_OPT(OutputLog, OUTPUTLOG);
  FEX::Logging::SilentLog = SilentLog();

  if (SilentLog()) {
    LogMan::Throw::UnInstallHandler();
    LogMan::Msg::UnInstallHandler();
  } else {
    const auto& LogFile = OutputLog();
    // If stderr or stdout then we need to dup the FD
    // In some cases some applications will close stderr and stdout
    // then redirect the FD to either a log OR some cases just not use
    // stderr/stdout and the FD will be reused for regular FD ops.
    //
    // We want to maintain the original output location otherwise we
    // can run in to problems of writing to some file
    auto LogFD = OutputFD;
    if (LogFile == "stderr") {
      LogFD = dup(STDERR_FILENO);
    } else if (LogFile == "server") {
      Logging::FEXServer::FEXServerFD = FEXServerClient::RequestLogFD(FEXServerClient::GetServerFD());
      if (FEXServer::FEXServerFD != -1) {
        LogMan::Throw::InstallHandler(Logging::FEXServer::AssertHandler);
        LogMan::Msg::InstallHandler(Logging::FEXServer::MsgHandler);
      }
    } else if (!LogFile.empty()) {
      constexpr int USER_PERMS = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
      // Add O_TRUNC so re-runs don't leave stale trailing bytes when the new
      // run writes fewer bytes than the previous one. Alternative would be
      // O_APPEND (accumulate across runs), but the historical shape here is
      // "one log per run" — matches the stderr/stdout paths above.
      LogFD = open(LogFile.c_str(), O_CREAT | O_TRUNC | O_CLOEXEC | O_WRONLY, USER_PERMS);
    }

    if (LogFD == -1) {
      LogMan::Msg::EFmt("Couldn't open log file. Going Silent.");
      Logging::SilentLog = true;
    } else {
      OutputFD = LogFD;
    }
  }
  DisableOutputColors = !isatty(OutputFD);
}

} // namespace FEX::Logging

namespace FEX::Allocator {

fextl::vector<FEXCore::Allocator::MemoryRegion> InitMemoryRegions(bool Is64Bit) {
  const auto PageSize = sysconf(_SC_PAGESIZE);
  if (Is64Bit) {
    // Destroy the 48th bit if it exists
    return FEXCore::Allocator::Setup48BitAllocatorIfExists(PageSize > 0 ? PageSize : FEXCore::Utils::FEX_PAGE_SIZE);
  }

  // Reserve [0x1_0000_0000, 0x2_0000_0000).
  // Safety net if 32-bit address calculation overflows in to 64-bit range.
  constexpr uint64_t First64BitAddr = 0x1'0000'0000ULL;
  return FEXCore::Allocator::StealMemoryRegion(First64BitAddr, First64BitAddr + First64BitAddr);
}

fextl::unique_ptr<FEX::HLE::MemAllocator> InitAllocator(bool Is64Bit) {
  const auto PageSize = sysconf(_SC_PAGESIZE);

  if (Is64Bit) {
    // A 64-bit guest doesn't need the 4 GiB-constrained allocator, but the
    // bundled allocator still has to be configured: without this rpmalloc uses
    // its own mapper, ignores FEX's placement hint, and strews its arenas
    // (~45 GiB under Unity) through the guest's address space.
    FEXCore::Allocator::InitializeAllocator(PageSize > 0 ? PageSize : FEXCore::Utils::FEX_PAGE_SIZE);
    return {};
  }


  // Setup our userspace allocator
  FEXCore::Allocator::SetupHooks(PageSize > 0 ? PageSize : FEXCore::Utils::FEX_PAGE_SIZE);
  // PassthroughAllocator delegates straight to ::mmap, which on PPC64LE
  // (and any host whose default mmap base sits above 4 GiB) returns
  // addresses outside the 32-bit guest address space. glibc i686 then
  // truncates those pointers when calling through *gs:0x10 (AT_SYSINFO) and
  // SEGVs on first syscall. The real 32-bit allocator tracks a 4 GiB
  // bitmap and only hands out low addresses, which is required for any
  // 32-bit guest binary that consumes AT_SYSINFO.
  auto Allocator = FEX::HLE::Create32BitAllocator();

  // Now that the upper 32-bit address space is blocked for future allocations,
  // exhaust all of jemalloc's remaining internal allocations that it reserved before.
  // TODO: It's unclear how reliably this exhausts those reserves
  // TODO: This will likely consume one arena inside the 32-bit VA space.
  //   - (HdkR): I've noticed jemalloc consuming an 8MB arena commonly.
  //
  // PPC64LE-host caveat: Linux on PPC64LE puts userspace heap entirely in the
  // 0x3fff_xxxx_xxxx range, so jemalloc never returns a low-4 GiB address and
  // the unbounded loop spins forever. Cap the iteration count so we drain
  // whatever's available below 4 GiB and bail out otherwise.
  FEXCore::Allocator::YesIKnowImNotSupposedToUseTheGlibcAllocator glibc;
  void* data = nullptr;
  for (int i = 0; i < (1 << 20); ++i) {
    data = malloc(0x1);
    if (reinterpret_cast<uintptr_t>(data) >> 32 == 0) {
      break;
    }
  }
  if (data) {
    free(data);
  }

  return Allocator;
}

void Shutdown(fextl::vector<FEXCore::Allocator::MemoryRegion>&& MemoryRegions) {
  FEXCore::Allocator::ClearHooks();
  FEXCore::Allocator::ReclaimMemoryRegion(MemoryRegions);
}
} // namespace FEX::Allocator

bool InterpreterHandler(fextl::string* Filename, const fextl::string& RootFS, fextl::vector<fextl::string>* args) {
  int FD {-1};

  // Attempt to open the filename from the rootfs first.
  FD = open(fextl::fmt::format("{}{}", RootFS, *Filename).c_str(), O_RDONLY | O_CLOEXEC);
  if (FD == -1) {
    // Failing that, attempt to open the filename directly.
    FD = open(Filename->c_str(), O_RDONLY | O_CLOEXEC);
    if (FD == -1) {
      return false;
    }
  }

  std::array<char, 257> Header;
  const auto ChunkSize = 257l;
  const auto ReadSize = pread(FD, Header.data(), ChunkSize, 0);
  close(FD);

  const auto Data = std::span<char>(Header.data(), ReadSize);

  // Is the file large enough for shebang
  if (ReadSize <= 2) {
    return false;
  }

  // Handle shebang files
  if (Data[0] == '#' && Data[1] == '!') {
    std::string_view InterpreterLine {Data.begin() + 2, // strip off "#!" prefix
                                      std::find(Data.begin(), Data.end(), '\n')};
    const auto ShebangArguments = FHU::ParseArgumentsFromString(InterpreterLine);

    if (ShebangArguments.empty()) {
      return false;
    }

    // Executable argument
    *Filename = ShebangArguments.at(0);

    // Insert all the arguments at the start
    args->insert(args->begin(), ShebangArguments.begin(), ShebangArguments.end());
  }
  return true;
}

/**
 * @brief Queries if FEX is installed as a binfmt_misc interpreter
 *
 * @param ExecutedWithFD If FEX was executed using a binfmt_misc FD handle from the kernel
 * @param Portable Portability information about FEX being run in portable mode
 *
 * @return true if the binfmt_misc handlers are installed and being used
 */
bool QueryInterpreterInstalled(bool ExecutedWithFD, const FEX::Config::PortableInformation& Portable) {
  if (Portable.IsPortable) {
    // Don't use binfmt interpreter even if it's installed
    return false;
  }

  // Check if FEX's binfmt_misc handlers are both installed.
  // The explicit check can be omitted if FEX was executed from an FD,
  // since this only happens if the kernel launched FEX through binfmt_misc
  return ExecutedWithFD || (access("/proc/sys/fs/binfmt_misc/FEX-x86", F_OK) == 0 && access("/proc/sys/fs/binfmt_misc/FEX-x86_64", F_OK) == 0);
}

namespace FEX::Kernel {
namespace PageSize {
  // FEXCore::Utils::FEX_PAGE_SIZE is a compile-time 4096 that serves two
  // unrelated jobs: the GUEST page granularity (correct at 4096 forever — the
  // guest is x86 and is handed AT_PAGESZ=4096) and the HOST mmap/mprotect
  // granularity (wrong on any kernel whose page is larger). Nothing in the tree
  // distinguishes the two, so on a 16K/64K-page host FEX does not degrade, it
  // wedges — and it wedges without printing anything, which is the part that
  // costs somebody a day. Refuse to start instead.
  //
  // This is deliberately NOT a rounding problem. The archetype is
  // InternalThreadState: the struct is alignas(FEX_PAGE_SIZE), is exactly
  // 2*FEX_PAGE_SIZE bytes, and parks InterruptFaultPage in its second 4K. On a
  // 64K host that member's address is 4K-aligned but not page-aligned, so the
  // mprotect that arms it returns EINVAL. Rounding the length up cannot save it
  // either: a 64K-granular protection would swallow BaseFrameState — the guest
  // register file the JIT reaches through r27/STATE — along with ~56K of
  // whatever the allocator happened to place after the struct. The layout
  // itself encodes a 4K host, so a real port has to change the layout. That is
  // a project; this is the guard rail in front of it (see
  // docs/PAGE_SIZE_AUDIT.md for the full classification and the ordered list of
  // what a 64K port has to fix first).
  //
  // Written straight to stderr rather than through LogMan on purpose. FEX_SILENTLOG
  // defaults to on, and every LogMan path — including ERROR_AND_DIE_FMT, which
  // routes through MsgHandler — is swallowed when it is. A gate whose whole
  // purpose is to replace a silent hang with an explanation cannot be silenceable
  // by the default logging config. Matches the existing fatal startup paths in
  // main() ("command not found", "Invalid or Unsupported elf file") and the
  // PROT_SAO probe in Syscalls.cpp.
  void CheckHostPageSize() {
    const long HostPageSize = sysconf(_SC_PAGESIZE);
    if (HostPageSize <= 0 || static_cast<uint64_t>(HostPageSize) == FEXCore::Utils::FEX_PAGE_SIZE) {
      // Either the expected 4K host, or sysconf failed and there is nothing
      // meaningful to say — the rest of FEX already treats a failed
      // _SC_PAGESIZE as "assume FEX_PAGE_SIZE" (see FEX::Allocator::InitAllocator
      // and ELFCodeLoader), so do not invent a second policy here.
      return;
    }

    const char* AllowEnv = ::getenv("FEX_ALLOW_UNSUPPORTED_PAGE_SIZE");
    const bool Allow = AllowEnv && AllowEnv[0] == '1';

    fextl::fmt::print(stderr,
                      "FEX: {}: host page size is {}, but FEX is built assuming {}.\n"
                      "\n"
                      "This is not a tunable. The {}-byte assumption is baked into struct layouts\n"
                      "and into every host mprotect() FEX issues. What breaks, in the order you hit it:\n"
                      "\n"
                      "  * Deferred signals never arm, and the guest hangs with no diagnostic.\n"
                      "    InternalThreadState::InterruptFaultPage sits at offset {} of a {}-byte\n"
                      "    struct, so its address is {}-aligned but not {}-aligned and the mprotect()\n"
                      "    that arms it returns EINVAL. Rounding the length up cannot fix it: a\n"
                      "    {}-granular protection would also cover BaseFrameState, the guest register\n"
                      "    file the JIT addresses through r27/STATE.\n"
                      "  * The JIT's call-ret shadow stack is never made writable. It is placed one\n"
                      "    {}-byte guard page into a host-aligned mapping, so the mprotect() that\n"
                      "    commits it also returns EINVAL and the first guest CALL faults.\n"
                      "  * SMC tracking (FEX_SMCCHECKS=mtrack) drives host mprotect() at {}-byte\n"
                      "    granularity. Calls that are rejected abort; the ones that go through\n"
                      "    degrade to host-page protection with re-protect races against neighbouring\n"
                      "    guest pages that were never meant to be write-protected.\n"
                      "  * Guest mmap/mprotect/munmap granularity. The guest is told AT_PAGESZ={} and\n"
                      "    will place MAP_FIXED mappings on {}-byte boundaries that this host cannot\n"
                      "    represent, so they fail with EINVAL instead of landing where the guest asked.\n"
                      "\n"
                      "What you can do: boot a kernel configured for {}-byte pages. On ppc64le that is\n"
                      "CONFIG_PPC_4K_PAGES; there is no runtime switch for it.\n",
                      Allow ? "WARNING" : "FATAL", HostPageSize, FEXCore::Utils::FEX_PAGE_SIZE, FEXCore::Utils::FEX_PAGE_SIZE,
                      offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage), sizeof(FEXCore::Core::InternalThreadState),
                      FEXCore::Utils::FEX_PAGE_SIZE, HostPageSize, HostPageSize, FEXCore::Utils::FEX_PAGE_SIZE,
                      FEXCore::Utils::FEX_PAGE_SIZE, FEXCore::Utils::FEX_PAGE_SIZE, FEXCore::Utils::FEX_PAGE_SIZE,
                      FEXCore::Utils::FEX_PAGE_SIZE);

    if (Allow) {
      fextl::fmt::print(stderr, "FEX: FEX_ALLOW_UNSUPPORTED_PAGE_SIZE=1 -- continuing anyway. This is a debugging\n"
                                "aid for working on host-page-size support, not a supported configuration. The\n"
                                "expected outcome is one of the failures above: a crash on the first guest CALL,\n"
                                "or a hang as soon as the first async signal needs delivering.\n");
      return;
    }

    fextl::fmt::print(stderr, "\nSet FEX_ALLOW_UNSUPPORTED_PAGE_SIZE=1 to downgrade this to a warning and continue\n"
                              "anyway, if you are working on host-page-size support and want to see how far it\n"
                              "gets. It is expected to crash or hang.\n");
    FEX_TRAP_EXECUTION;
  }
} // namespace PageSize

namespace TSO {
  void SetupTSOEmulation(FEXCore::Context::Context* CTX) {
    {
      // FEX_HWTSO (ppc64le): PROT_SAO hardware TSO. This must run HERE —
      // before the syscall handler exists, before the ELF loader maps
      // anything and before any guest code is compiled — because
      // HardwareTSO::Live steers every subsequent GuestMmap/GuestMprotect/
      // GuestShmat, and SetHardwareTSOSupport must be seen by the very first
      // compiled block. Litmus-proven on op4k 2026-08-13
      // (notes/tools/sao_litmus.c): MP violations 0/16.3M on SAO pages vs
      // ~1.2%/round on plain pages; SB still observable (TSO, not SC).
      //
      // Enabling it here is not a permanent commitment. If the kernel later
      // refuses PROT_SAO for a range of ordinary guest memory,
      // SyscallHandler::RevokeHardwareTSO gives it back — Live goes false,
      // SetHardwareTSOSupport(false) is called and all compiled code is
      // invalidated, once, from inside the exclusive CodeInvalidationMutex.
      // Nothing on that path runs before the syscall handler exists (it is
      // only reachable from the three mapping choke points, which are members
      // of the handler), so the ordering below is unaffected by it.
      FEX_CONFIG_OPT(HWTSOEnabled, HWTSO);
      FEX_CONFIG_OPT(TSOEnabledForHW, TSOENABLED);
      if (HWTSOEnabled() && TSOEnabledForHW()) {
        if (FEX::HLE::HardwareTSO::ProbeAndEnable()) {
          // Every guest-visible mapping now carries PROT_SAO; stop emitting
          // TSO IR ops entirely (scalar, vector and memcpy).
          CTX->SetHardwareTSOSupport(true);
          return;
        }
        // ProbeAndEnable already warned; fall through to the prctl path
        // (a no-op on ppc64le kernels without PR_GET_MEM_MODEL) and normal
        // atomic/barrier TSO emulation.
      }
    }

    // Check to see if this is supported.
    auto Result = prctl(PR_GET_MEM_MODEL, 0, 0, 0, 0);
    if (Result == -1) {
      // Unsupported, early exit.
      return;
    }

    FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);

    if (!TSOEnabled()) {
      // TSO emulation isn't even enabled, early exit.
      return;
    }

    if (Result == PR_SET_MEM_MODEL_DEFAULT) {
      // Try to set the TSO mode if we are currently default.
      Result = prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO, 0, 0, 0);
      if (Result == 0) {
        // TSO mode successfully enabled. Tell the context to disable TSO emulation through atomics.
        // This flag gets inherited on thread creation, so FEX only needs to set it at the start.
        CTX->SetHardwareTSOSupport(true);
      }
    }
  }
} // namespace TSO

namespace CompatInput {
  void SetupCompatInput(bool enable) {
    // Check to see if this is supported.
    auto Result = prctl(PR_GET_COMPAT_INPUT, 0, 0, 0, 0);
    if (Result == -1) {
      // Unsupported, early exit.
      return;
    }

    if (enable) {
      prctl(PR_SET_COMPAT_INPUT, PR_SET_COMPAT_INPUT_ENABLE, 0, 0, 0);
    } else {
      prctl(PR_SET_COMPAT_INPUT, PR_SET_COMPAT_INPUT_DISABLE, 0, 0, 0);
    }
  }
} // namespace CompatInput

namespace GCS {
  void CheckForGCS() {
    uint64_t ShadowStackWord {};
    if (prctl(PR_GET_SHADOW_STACK_STATUS, &ShadowStackWord, 0, 0, 0) == -1) {
      return;
    }

    // Kernel supports shadow stack.
    if (ShadowStackWord & PR_SHADOW_STACK_ENABLE) {
      // Welp.
      ERROR_AND_DIE_FMT("Shadow stack is enabled which FEX is incompatible with!");
    }

    // Disable if we've gotten this far, to ensure guest can't try.
    prctl(PR_LOCK_SHADOW_STACK_STATUS, ~0ULL, 0, 0, 0);
  }
} // namespace GCS

namespace UnalignedAtomic {
  void SetupKernelUnalignedAtomics() {
#ifndef PR_ARM64_SET_UNALIGN_ATOMIC
#define PR_ARM64_SET_UNALIGN_ATOMIC 0x46455849
#define PR_ARM64_UNALIGN_ATOMIC_EMULATE (1UL << 0)
#define PR_ARM64_UNALIGN_ATOMIC_BACKPATCH (1UL << 1)
#define PR_ARM64_UNALIGN_ATOMIC_STRICT_SPLIT_LOCKS (1UL << 2)
#endif

    // Interfaces with downstream FEX kernel patches to control unaligned atomic handling
    FEX_CONFIG_OPT(StrictInProcessSplitLocks, STRICTINPROCESSSPLITLOCKS);
    FEX_CONFIG_OPT(KernelUnalignedAtomicBackpatching, KERNELUNALIGNEDATOMICBACKPATCHING);

    uint64_t Flags = (StrictInProcessSplitLocks() ? PR_ARM64_UNALIGN_ATOMIC_STRICT_SPLIT_LOCKS : 0) |
                     (KernelUnalignedAtomicBackpatching() ? PR_ARM64_UNALIGN_ATOMIC_BACKPATCH : 0) | PR_ARM64_UNALIGN_ATOMIC_EMULATE;

    prctl(PR_ARM64_SET_UNALIGN_ATOMIC, Flags, 0, 0, 0);
  }
} // namespace UnalignedAtomic

void Init(bool Is64Bit, FEXCore::Context::Context* CTX) {
  // Must be first. This is the last point at which refusing to run is clean:
  // no InternalThreadState exists yet (the first one is built by
  // TM.CreateThread below, after the syscall handler), no guest mapping exists
  // yet (the VDSO and the guest ELF both go down later, via LoadVDSOThunks and
  // Loader.MapMemory), and no guest code has been compiled. Everything that
  // would actually wedge on a non-4K host is downstream of here.
  PageSize::CheckHostPageSize();

  // Setup TSO hardware emulation immediately after initializing the context.
  TSO::SetupTSOEmulation(CTX);
  UnalignedAtomic::SetupKernelUnalignedAtomics();

  if (!Is64Bit) {
    // Tell the kernel we want to use the compat input syscalls even though we're
    // a 64 bit process.
    CompatInput::SetupCompatInput(true);
  } else {
    // Our parent could be an instance running a 32 bit application, so we need
    // to disable compat input if we're running a 64 bit one ourselves.
    CompatInput::SetupCompatInput(false);
  }
}

} // namespace FEX::Kernel

/**
 * @brief Get an FD from an environment variable and then unset the environment variable.
 *
 * @param Env The environment variable to extract the FD from.
 *
 * @return -1 if the variable didn't exist.
 */
static int StealFEXFDFromEnv(const char* Env) {
  int FEXFD {-1};
  const char* FEXFDStr = getenv(Env);
  if (FEXFDStr) {
    const std::string_view FEXFDView {FEXFDStr};
    std::from_chars(FEXFDView.data(), FEXFDView.data() + FEXFDView.size(), FEXFD, 10);
    unsetenv(Env);
  }
  return FEXFD;
}

int main(int argc, char** argv, char** const envp) {
  auto SBRKPointer = FEX::SBRKAllocations::DisableSBRKAllocations();
  FEXCore::Allocator::GLIBCScopedFault GLIBFaultScope;

  const bool ExecutedWithFD = getauxval(AT_EXECFD) != 0;
  const auto PortableInfo = FEX::ReadPortabilityInformation();
  const bool InterpreterInstalled = QueryInterpreterInstalled(ExecutedWithFD, PortableInfo);

  int FEXFD {StealFEXFDFromEnv("FEX_EXECVEFD")};
  int FEXSeccompFD {StealFEXFDFromEnv("FEX_SECCOMPFD")};

  // Early init trivial handlers.
  LogMan::Throw::InstallHandler(FEX::Logging::AssertHandler);
  LogMan::Msg::InstallHandler(FEX::Logging::MsgHandler);

  auto ArgsLoader = fextl::make_unique<FEX::ArgLoader::ArgLoader>(argc, argv);
  auto Args = ArgsLoader->Get();
  auto ParsedArgs = ArgsLoader->GetParsedArgs();
  auto Program = FEX::Config::GetApplicationNames(Args, ExecutedWithFD, FEXFD);
  if (Program.ProgramPath.empty() && FEXFD == -1) {
    // Early exit if we weren't passed an argument
    return 0;
  }

  FEX::Kernel::GCS::CheckForGCS();

  FEX::Config::LoadConfig(Program.ProgramName, envp, PortableInfo);

  // Reload the meta layer
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_INTERPRETER_INSTALLED, InterpreterInstalled ? "1" : "0");
#ifdef VIXL_SIMULATOR
  // If running under the vixl simulator, ensure that indirect runtime calls are enabled.
  FEXCore::Config::Set(FEXCore::Config::CONFIG_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS, "0");
#endif

  if (FEXSeccompFD != -1) {
    // seccomp inheritance happens unconditionally.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_NEEDSSECCOMP, "1");
  }

  // Early check for process stall
  // Doesn't use CONFIG_ROOTFS and we don't want it to spin up a squashfs instance
  FEX_CONFIG_OPT(StallProcess, STALLPROCESS);
  FEX_CONFIG_OPT(StartupSleep, STARTUPSLEEP);
  FEX_CONFIG_OPT(StartupSleepProcName, STARTUPSLEEPPROCNAME);
  if (StallProcess) {
    while (1) {
      // Stall this process out forever
      select(0, nullptr, nullptr, nullptr, nullptr);
    }
  }

  // Ensure FEXServer is setup before config options try to pull CONFIG_ROOTFS
  auto SelfPath = FEX::GetSelfPath();
  if (!FEXServerClient::SetupClient(SelfPath.value_or(argv[0]))) {
    LogMan::Msg::EFmt("FEXServerClient: Failure to setup client");
    return -1;
  }

  FEX_CONFIG_OPT(LDPath, ROOTFS);
  FEX_CONFIG_OPT(Environment, ENV);
  FEX_CONFIG_OPT(HostEnvironment, HOSTENV);

  FEX::Logging::Init();

  if (StartupSleep() && (StartupSleepProcName().empty() || Program.ProgramName == StartupSleepProcName())) {
    LogMan::Msg::IFmt("[{}][{}] Sleeping for {} seconds", ::getpid(), Program.ProgramName, StartupSleep());
    std::this_thread::sleep_for(std::chrono::seconds(StartupSleep()));
  }

  FEXCore::Telemetry::Initialize();

  if (!LDPath().empty() && Program.ProgramPath.starts_with(LDPath())) {
    // From this point on, ProgramPath needs to not have the LDPath prefixed on to it.
    auto RootFSLength = LDPath().size();
    if (Program.ProgramPath.at(RootFSLength) != '/') {
      // Ensure the modified path starts as an absolute path.
      // This edge case can occur when ROOTFS ends with '/' and passed a path like `<ROOTFS>usr/bin/true`.
      --RootFSLength;
    }

    Program.ProgramPath.erase(0, RootFSLength);
  }

  bool ProgramExists = InterpreterHandler(&Program.ProgramPath, LDPath(), &Args);

  if (!ExecutedWithFD && FEXFD == -1 && !ProgramExists) {
    // Early exit if the program passed in doesn't exist
    // Will prevent a crash later
    fextl::fmt::print(stderr, "{}: command not found\n", Program.ProgramPath);
    return -ENOEXEC;
  }

  uint32_t KernelVersion = FEX::HLE::SyscallHandler::CalculateHostKernelVersion();
  if (KernelVersion < FEX::HLE::SyscallHandler::KernelVersion(5, 15)) {
    LogMan::Msg::EFmt("FEX requires kernel 5.15 minimum. Expect problems.");
  }

  // Before we go any further, set all of our host environment variables that the config has provided
  for (auto& HostEnv : HostEnvironment.All()) {
    // We are going to keep these alive in memory.
    // No need to split the string with setenv
    putenv(HostEnv.data());
  }

  ELFCodeLoader Loader {Program.ProgramPath, FEXFD, LDPath(), Args, ParsedArgs, envp, &Environment};
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Loader.Is64BitMode() ? "1" : "0");

  if (!Loader.ELFWasLoaded()) {
    // Loader couldn't load this program for some reason
    fextl::fmt::print(stderr, "Invalid or Unsupported elf file.\n");
#ifndef ARCHITECTURE_x86_64
    fextl::fmt::print(stderr, "This is likely due to a misconfigured x86-64 RootFS\n");
    fextl::fmt::print(stderr, "Current RootFS path set to '{}'\n", LDPath());
    if (LDPath().empty() || FHU::Filesystem::Exists(LDPath()) == false) {
      fextl::fmt::print(stderr, "RootFS path doesn't exist. This is required on non-x86-64 hosts\n");
#ifdef ARCHITECTURE_arm64
      fextl::fmt::print(stderr, "Use FEXRootFSFetcher to download a RootFS\n");
#endif
    }
#endif
    return -ENOEXEC;
  }

  if (ExecutedWithFD) {
    // Don't need to canonicalize Program.ProgramPath, Config loader will have resolved this already.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, Program.ProgramPath);
    FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, Program.ProgramName);
  } else if (FEXFD != -1) {
    // Anonymous program.
    FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, "<Anonymous>");
    FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, "<Anonymous>");
  } else {
    {
      char ExistsTempPath[PATH_MAX];
      char* RealPath = realpath(Program.ProgramPath.c_str(), ExistsTempPath);
      if (RealPath) {
        FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, fextl::string(RealPath));
      } else {
        // Can happen when jumping in to pressure-vessel.
        // `/usr/lib/pressure-vessel/from-host/libexec/steam-runtime-tools-0/pv-adverb` can't get resolved.
        FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_FILENAME, Program.ProgramPath);
      }
    }
    FEXCore::Config::Set(FEXCore::Config::CONFIG_APP_CONFIG_NAME, Program.ProgramName);
  }

  // Setup Thread handlers, so FEXCore can create threads.
  auto StackTracker = FEX::LinuxEmulation::Threads::SetupThreadHandlers();

  auto MemoryRegions = FEX::Allocator::InitMemoryRegions(Loader.Is64BitMode());
  auto Allocator = FEX::Allocator::InitAllocator(Loader.Is64BitMode());

  FEXCore::Profiler::Init(Program.ProgramName, Program.ProgramPath);

  bool SupportsAVX {};
  fextl::unique_ptr<FEXCore::Context::Context> CTX;
  {
    auto HostFeatures = FEX::FetchHostFeatures();
    CTX = FEXCore::Context::Context::CreateNewContext(HostFeatures);
    SupportsAVX = HostFeatures.SupportsAVX;
  }

  FEX::Kernel::Init(Loader.Is64BitMode(), CTX.get());

  auto SignalDelegation = FEX::HLE::CreateSignalDelegator(CTX.get(), Program.ProgramName, SupportsAVX);
  auto ThunkHandler = FEX::HLE::CreateThunkHandler();

  // Record everything host-private that exists right now, BEFORE any guest
  // memory is mapped (the guest ELF goes down in Loader.MapMemory() below).
  // From here on a guest MAP_FIXED/munmap/mprotect/mremap that would destroy
  // FEX's own image is refused instead of executed. See
  // LinuxSyscalls/HostOwnedRanges.h for why this is a ppc64le-specific
  // necessity.
  FEX::HLE::HostOwnedRanges::SnapshotSelf();

  auto SyscallHandler = Loader.Is64BitMode() ?
                          FEX::HLE::x64::CreateHandler(CTX.get(), SignalDelegation.get(), ThunkHandler.get()) :
                          FEX::HLE::x32::CreateHandler(CTX.get(), SignalDelegation.get(), ThunkHandler.get(), std::move(Allocator));
  SyscallHandler->SetCodeLoader(&Loader);
  CTX->SetSignalDelegator(SignalDelegation.get());
  CTX->SetSyscallHandler(SyscallHandler.get());
  CTX->SetThunkHandler(ThunkHandler.get());

  if (FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
    CTX->SetCodeMapWriter(fextl::make_unique<FEXCore::CodeMapWriter>(*SyscallHandler));
  }

  // A process that writes its own cache files has to compile in cache-generation
  // mode from the very first block: relocations must be retained (they are
  // discarded per block otherwise) and decoding must be bounded to the mapped
  // section (otherwise multiblock can pull instructions from another file into
  // a block attributed to this one). Both are properties of every block ever
  // compiled, so this cannot be turned on later.
  //
  // Only when a scope was selected — CodeCacheScope=off keeps the legacy
  // load-only behaviour and pays none of this cost.
  if (SyscallHandler->CodeCacheWriteEnabled()) {
    CTX->GetCodeCache().InitiateCacheGeneration();
  }

  FEX_CONFIG_OPT(GdbServer, GDBSERVER);
  fextl::unique_ptr<FEX::GdbServer> DebugServer;
  if (GdbServer) {
    DebugServer = fextl::make_unique<FEX::GdbServer>(CTX.get(), SignalDelegation.get(), SyscallHandler.get());
  }

  // Now that we have the syscall handler. Track some FDs that are FEX owned.
  if (FEX::Logging::OutputFD > 2) {
    SyscallHandler->FM.TrackFEXFD(FEX::Logging::OutputFD);
  }
  SyscallHandler->FM.TrackFEXFD(FEXServerClient::GetServerFD());
  if (FEX::Logging::FEXServer::FEXServerFD != -1) {
    SyscallHandler->FM.TrackFEXFD(FEX::Logging::FEXServer::FEXServerFD);
  }

  if (!CTX->InitCore()) {
    return 1;
  }

  // Create a thread without a RIP or stack pointer setup initially.
  auto ParentThread = SyscallHandler->TM.CreateThread(0, 0);
  SyscallHandler->TM.TrackThread(ParentThread);
  SignalDelegation->RegisterTLSState(ParentThread);
  ThunkHandler->RegisterTLSState(ParentThread);

  SyscallHandler->DeserializeSeccompFD(ParentThread, FEXSeccompFD);

  // Load VDSO in to memory prior to mapping our ELFs.
  auto VDSOMapping = FEX::VDSO::LoadVDSOThunks(ParentThread->Thread, Loader.Is64BitMode(), SyscallHandler.get());

  // Pass in our VDSO thunks
  ThunkHandler->AppendThunkDefinitions(FEX::VDSO::GetVDSOThunkDefinitions(Loader.Is64BitMode()));
  SignalDelegation->SetVDSOSymbols();

  {
    Loader.SetVDSOBase(VDSOMapping.VDSOBase);
    Loader.CalculateHWCaps(CTX.get());

    if (!Loader.MapMemory(SyscallHandler.get(), ParentThread->Thread)) {
      // failed to map
      LogMan::Msg::EFmt("Failed to map {}-bit elf file.", Loader.Is64BitMode() ? 64 : 32);
      return -ENOEXEC;
    }
  }

  auto BRKInfo = Loader.GetBRKInfo();

  SyscallHandler->DefaultProgramBreak(BRKInfo.Base, BRKInfo.Size);

  // Request code cache generation
  if (FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
    FEXServerClient::PopulateCodeCache(FEXServerClient::GetServerFD(), Loader.GetMainElfFD(), FEXCore::Config::Get_MULTIBLOCK());
  }

  // Pull RIP and stack pointer from loader and set the thread data to it.
  ParentThread->Thread->CurrentFrame->State.rip = Loader.DefaultRIP();
  ParentThread->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP] = Loader.GetStackPointer();

  // Close the loader FDs after everything has been parsed and mapped.
  Loader.CloseFDs();

  CTX->ExecuteThread(ParentThread->Thread);

  DebugServer.reset();
  // The JIT thread (current thread) has already exited — sending SIGRTMIN to
  // ourselves with a stale ReturningStackLocation would corrupt r1 and crash.
  // Pass IgnoreCurrentThread=true so only other (worker) threads are stopped.
  SyscallHandler->TM.Stop(true);

  // Final checkpoint, after every other thread has stopped and before any thread
  // state is torn down. Force it: the periodic trigger only fires from the
  // memory-management syscalls, and a guest that exits shortly after its last
  // mmap would otherwise throw away everything compiled since.
  SyscallHandler->SaveCodeCaches(ParentThread->Thread, true);

  auto ProgramStatus = ParentThread->StatusCode;

  FEX::VDSO::UnloadVDSOMapping(ParentThread->Thread, SyscallHandler.get(), VDSOMapping);

  SignalDelegation->UninstallTLSState(ParentThread);
  SyscallHandler->TM.DestroyThread(ParentThread);

  DebugServer.reset();
  SyscallHandler.reset();
  SignalDelegation.reset();

  FEX::LinuxEmulation::Threads::Shutdown(std::move(StackTracker));

  Loader.FreeSections();

  FEXCore::Config::Shutdown();

  LogMan::Throw::UnInstallHandler();
  LogMan::Msg::UnInstallHandler();

  FEX::Allocator::Shutdown(std::move(MemoryRegions));

  // Allocator is now original system allocator
  FEXCore::Telemetry::Shutdown(Program.ProgramName);
  FEXCore::Profiler::Shutdown();

  FEX::SBRKAllocations::ReenableSBRKAllocations(SBRKPointer);

  return ProgramStatus;
}
