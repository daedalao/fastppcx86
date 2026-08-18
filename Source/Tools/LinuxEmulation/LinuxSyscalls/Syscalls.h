// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|common
desc: Glue logic, STRACE magic
$end_info$
*/

#pragma once

#include "Common/VolatileMetadata.h"
#include "LinuxSyscalls/FileManagement.h"
#include "LinuxSyscalls/LinuxAllocator.h"
#include "LinuxSyscalls/SMCLazyInvalidate.h"
#include "LinuxSyscalls/ThreadManager.h"
#include "LinuxSyscalls/Seccomp/SeccompEmulator.h"
#include "LinuxSyscalls/SyscallsVMATracking.h"
#include "ArchHelpers/MContext.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/functional.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <atomic>
#include <mutex>
#include <shared_mutex>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/socket.h>
#include <type_traits>
#include <list>
#ifdef ARCHITECTURE_x86_64
#define SYSCALL_ARCH_NAME x64
#elif defined(ARCHITECTURE_ppc64le)
#include "LinuxSyscalls/PPC64LE/SyscallsEnum.h"
#define SYSCALL_ARCH_NAME PPC64LE
#endif

#include "LinuxSyscalls/x64/SyscallsEnum.h"
#include "LinuxSyscalls/x32/SyscallsEnum.h"

#define CONCAT_(a, b) a##b
#define CONCAT(a, b) CONCAT_(a, b)
#define SYSCALL_DEF(name) (HLE::SYSCALL_ARCH_NAME::CONCAT(CONCAT(SYSCALL_, SYSCALL_ARCH_NAME), _##name))

// #define DEBUG_STRACE

namespace FEX {
class CodeLoader;
}

namespace FEXCore {
namespace Context {
  class Context;
}
namespace Core {
  struct CpuStateFrame;
}
} // namespace FEXCore

namespace FEX::HLE {

class SyscallHandler;
class SignalDelegator;
class ThunkHandler;

void RegisterEpoll(FEX::HLE::SyscallHandler* Handler);
void RegisterFD(FEX::HLE::SyscallHandler* Handler);
void RegisterFS(FEX::HLE::SyscallHandler* Handler);
void RegisterInfo(FEX::HLE::SyscallHandler* Handler);
void RegisterIO(FEX::HLE::SyscallHandler* Handler);
void RegisterMemory(FEX::HLE::SyscallHandler* Handler);
void RegisterSignals(FEX::HLE::SyscallHandler* Handler);
void RegisterThread(FEX::HLE::SyscallHandler* Handler);
void RegisterTimer(FEX::HLE::SyscallHandler* Handler);
void RegisterNotImplemented(FEX::HLE::SyscallHandler* Handler);
void RegisterStubs(FEX::HLE::SyscallHandler* Handler);

uint64_t UnimplementedSyscall(FEXCore::Core::CpuStateFrame* Frame, uint64_t SyscallNumber);
uint64_t UnimplementedSyscallSafe(FEXCore::Core::CpuStateFrame* Frame, uint64_t SyscallNumber);

// Shared terminal stage of every guest futex entry point (x64 futex, x32
// futex_time64, x32 classic futex after timespec32 conversion): deferred-
// guest-signal guard, sliced untimed waits, internal-EINTR restart, and the
// futex diagnostics. Returns a -errno-encoded result. Defined in
// Syscalls/Passthrough.cpp; see the comment there for the lost-wakeup
// mechanism this closes.
uint64_t ObservedFutexSyscall(FEXCore::Core::CpuStateFrame* Frame, uint64_t uaddr, uint64_t futex_op, uint64_t val,
                              uint64_t timeout, uint64_t uaddr2, uint64_t val3);

// x86 guests use the asm-generic SOL_SOCKET option numbering; powerpc is one
// of the legacy architectures with its own numbers for six of them. Translate
// the guest's optname before handing it to the host kernel — without this,
// e.g. a guest SO_PASSCRED (16) lands as host SO_RCVLOWAT (16), credentials
// never get attached, and Chromium/CEF's unix-socket IPC bootstrap fails
// with "missing credentials" (seen live: steamwebhelper restart loop).
inline int TranslateGuestSockOptName(int level, int optname) {
#ifdef __powerpc64__
  if (level == SOL_SOCKET) {
    switch (optname) {
    case 16: return 20; // x86 SO_PASSCRED     -> ppc SO_PASSCRED
    case 17: return 21; // x86 SO_PEERCRED     -> ppc SO_PEERCRED
    case 18: return 16; // x86 SO_RCVLOWAT     -> ppc SO_RCVLOWAT
    case 19: return 17; // x86 SO_SNDLOWAT     -> ppc SO_SNDLOWAT
    case 20: return 18; // x86 SO_RCVTIMEO_OLD -> ppc SO_RCVTIMEO_OLD
    case 21: return 19; // x86 SO_SNDTIMEO_OLD -> ppc SO_SNDTIMEO_OLD
    default: break;
    }
  }
#endif
  return optname;
}

// FEX_HWTSO: hardware TSO via PROT_SAO pages (ppc64le, default off).
//
// POWER's Strong Access Ordering page attribute makes plain loads/stores to a
// page x86-TSO-ordered in hardware (proven on op4k 2026-08-13: the MP litmus
// fires ~1.2%/round on plain pages, 0 in 16.3M rounds on SAO pages, and SB
// stays observable — TSO-like, not SC; notes/tools/sao_litmus.c). With every
// GUEST-visible page SAO, the JIT's atomic/barrier TSO emulation is
// unnecessary: the frontend calls Context::SetHardwareTSOSupport(true) and no
// TSO IR ops are emitted at all.
//
// Invariants:
//  - Live starts false and is set true EXACTLY ONCE, in FEX::Kernel::Init's TSO
//    setup, before the syscall handler exists and before any guest mapping or
//    compilation. After that it may only ever be DOWNGRADED to false, exactly
//    once, by SyscallHandler::RevokeHardwareTSO; it never goes back up. That
//    downgrade is why it is std::atomic rather than a plain bool that
//    everything after startup could read unsynchronized: writes are release,
//    reads are acquire. The downgrade itself is published from inside the
//    exclusive CodeInvalidationMutex, which is what makes it atomic with
//    respect to every compile — see RevokeHardwareTSO for the whole argument.
//  - Revoked distinguishes "HWTSO was never on" from "HWTSO was on and has been
//    given up mid-run". Both leave Live false, but only the second means this
//    process's compiled code is a mix of barrier-free (pre-revocation) and
//    barrier-carrying (post-revocation) blocks, which is what the code-cache
//    gates in LoadCodeCache/SaveCodeCaches key off.
//
//    It mirrors FEXCore's HardwareTSOState::Revoked, which is the same fact on
//    the other side of the module boundary. Both are written by
//    RevokeHardwareTSO in one step under the exclusive CodeInvalidationMutex
//    (this one directly, FEXCore's via SetHardwareTSOSupport), so they cannot
//    disagree. The duplication is not an oversight and must not be "cleaned
//    up" by deleting either: LinuxEmulation has no FEXCore/Source on its
//    include path and cannot name Interface/Context/Context.h, while
//    ComputeCodeCacheConfigId is FEXCore-internal and cannot name this. They
//    serve different consumers too — FEXCore's feeds the cache FILENAME (frozen
//    at startup, so it can only ever record Off vs Active), this one gates the
//    cache at RUNTIME, which is the only place a mid-run downgrade can act.
//  - Every guest-visible mapping site must route its protection through
//    ApplyGuestProt. The choke points are SyscallHandler::GuestMmap,
//    GuestMprotect and GuestShmat — the ELF/image loader, brk, guest stack,
//    VDSO and both 32-bit/64-bit guest allocators all funnel through them.
//    GuestMremap needs nothing: mremap has no prot argument and the kernel
//    carries VM_SAO on the VMA (grown pages inherit it). pkey_mprotect(2) is
//    only accepted with pkey == -1 and is forwarded to GuestMprotect.
//    KNOWN GAP: remap_file_pages(2) is a raw passthrough (Passthrough.cpp), and
//    the kernel's post-3.16 emulation rebuilds the destination's protection
//    from VM_READ/VM_WRITE/VM_EXEC alone, so VM_SAO is dropped from the range
//    it rebuilds. That mapping is invisible to FEX's VMA and SMC tracking too,
//    which is the older and larger problem; the syscall has been deprecated
//    since 2014 and nothing we run issues it. Fixing the tracking is what would
//    give this a place to hook.
//  - Guest mprotect can never strip SAO, because ApplyGuestProt ORs it back
//    into every guest protection change while Live. That OR is mandatory, not
//    a belt-and-braces restatement of what the kernel already does: VM_SAO is
//    VM_ARCH_1, powerpc lists it in VM_ARCH_CLEAR, and do_mprotect_pkey masks
//    the ARCH_CLEAR bits off the old flags and re-derives them from the
//    incoming prot — so an mprotect without PROT_SAO takes SAO away.
//  - FEX-internal memory (JIT buffers, shadow call/ret stack, host thread
//    stacks/alt-stacks, FEXCore arenas) is deliberately NOT SAO.
namespace HardwareTSO {
  // PROT_SAO from asm/mman.h; spelled here because glibc's sys/mman.h does
  // not export it.
  constexpr int PROT_SAO_BIT = 0x10;

  extern std::atomic<bool> Live;
  extern std::atomic<bool> Revoked;

  // Startup-only: mmap-probe PROT_SAO acceptance; sets Live on success.
  // Returns Live. Warns loudly on stderr when the probe fails, because the
  // user explicitly asked for FEX_HWTSO.
  bool ProbeAndEnable();

  inline int ApplyGuestProt(int prot) {
    return Live.load(std::memory_order_acquire) ? (prot | PROT_SAO_BIT) : prot;
  }

  // Classifies a range the kernel refused PROT_SAO for, and warns about it.
  //
  // Returns true when the caller must revoke hardware TSO process-wide, i.e.
  // when the refusal is on ORDINARY memory. Every such refusal is an ordering
  // hole — the JIT emits no barriers in this mode, so racing plain accesses
  // through that range are weakly ordered with nothing to fix it up. The
  // failure that produces is rare, timing-dependent and leaves no coredump,
  // which is also the signature of the open intermittent Witcher 3 HWTSO crash.
  // Callers must NOT act on a true return inline: revocation has to happen with
  // VMATracking.Mutex released, so it belongs at the tail of the syscall. See
  // SyscallHandler::RevokeHardwareTSO.
  //
  // Device mappings are exempt: a driver that overrides the page's
  // cache-control attribute drops SAO, and x86 makes no TSO promise for WC
  // memory either, so those refusals are legitimate and stay warnings.
  // `fd` < 0 means the caller has no file to classify (anonymous mmap,
  // mprotect, shmat) — ordinary memory, never exempt.
  [[nodiscard]] bool OnRangeRefusedSAO(const char* Site, const void* Addr, size_t Length, int fd);

  // FEX_HWTSO_STRICT=1: abort on an ordinary-memory SAO refusal instead of
  // revoking. Now that revocation makes the refusal survivable, this is purely
  // a debugging mode — it is how you find out WHICH range refuses, with the
  // syscall site, address and length in the abort message and the guest still
  // in a state worth inspecting, instead of only learning after the fact that
  // the process fell back to emitted barriers.
  //
  // Off by default: revocation is the correct production response, and aborting
  // kills a title that would otherwise have carried on (more slowly) with a
  // sound memory model.
  extern bool Strict;
} // namespace HardwareTSO

struct ExecveAtArgs {
  int dirfd;
  int flags;
  static ExecveAtArgs Empty() {
    return ExecveAtArgs {
      .dirfd = AT_FDCWD,
      .flags = 0,
    };
  }
};

uint64_t ExecveHandler(FEXCore::Core::CpuStateFrame* Frame, const char* pathname, char* const* argv, char* const* envp, ExecveAtArgs Args);

class SyscallMmapInterface {
public:
  // does a mmap as if done via a guest syscall
  virtual void* GuestMmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags, int fd, off_t offset) = 0;

  // does a guest munmap as if done via a guest syscall
  virtual uint64_t GuestMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length) = 0;
};

class SyscallHandler : public FEXCore::HLE::SyscallHandler,
                       public SyscallMmapInterface,
                       FEXCore::HLE::SourcecodeResolver,
                       public FEXCore::CodeMapOpener,
                       public FEXCore::Allocator::FEXAllocOperators {
public:
  ThreadManager TM;
  FEX::HLE::SeccompEmulator SeccompEmulator;

  virtual ~SyscallHandler();

  // In the case that the syscall doesn't hit the optimized path then we still need to go here
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) final override;

  // One attempt at a guest syscall, with the async-signal deferral guard scoped
  // to the attempt. Split out of HandleSyscall so guest SA_RESTART semantics can
  // re-run an attempt after the guard destructs (which is where a deferred guest
  // signal for a thread blocked in a host syscall gets delivered).
  // JITPC is the JIT return address, captured by HandleSyscall itself because
  // only that frame is called directly from JIT code.
  uint64_t HandleSyscallImpl(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args, uint64_t JITPC);

  void DefaultProgramBreak(uint64_t Base, uint64_t Size);
  void DeserializeSeccompFD(FEX::HLE::ThreadStateObject* Thread, int FD) {
    if (FD == -1) {
      return;
    }
    SeccompEmulator.DeserializeFilters(Thread->Thread->CurrentFrame, FD);
  }

  using SyscallPtrArg0 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame);
  using SyscallPtrArg1 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t);
  using SyscallPtrArg2 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t, uint64_t);
  using SyscallPtrArg3 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t, uint64_t, uint64_t);
  using SyscallPtrArg4 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t, uint64_t, uint64_t, uint64_t);
  using SyscallPtrArg5 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  using SyscallPtrArg6 = uint64_t (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

  struct SyscallFunctionDefinition {
    union {
      void* Ptr;
      SyscallPtrArg0 Ptr0;
      SyscallPtrArg1 Ptr1;
      SyscallPtrArg2 Ptr2;
      SyscallPtrArg3 Ptr3;
      SyscallPtrArg4 Ptr4;
      SyscallPtrArg5 Ptr5;
      SyscallPtrArg6 Ptr6;
    };
    uint8_t NumArgs;
#ifdef DEBUG_STRACE
    fextl::string StraceFmt;
#endif
  };

  const SyscallFunctionDefinition* GetDefinition(uint64_t Syscall) {
    return &Definitions.at(Syscall);
  }

  virtual void RegisterSyscall_32(int SyscallNumber,
#ifdef DEBUG_STRACE
                                  const fextl::string& TraceFormatString,
#endif
                                  void* SyscallHandler, int ArgumentCount) {
  }

  virtual void RegisterSyscall_64(int SyscallNumber,
#ifdef DEBUG_STRACE
                                  const fextl::string& TraceFormatString,
#endif
                                  void* SyscallHandler, int ArgumentCount) {
  }

  uint64_t HandleBRK(FEXCore::Core::CpuStateFrame* Frame, void* Addr);

  FEX::HLE::FileManager FM;
  FEX::CodeLoader* GetCodeLoader() const {
    return LocalLoader;
  }
  void SetCodeLoader(FEX::CodeLoader* Loader) {
    LocalLoader = Loader;
  }
  FEX::HLE::SignalDelegator* GetSignalDelegator() {
    return SignalDelegation;
  }

  FEX::HLE::ThunkHandler* GetThunkHandler() {
    return ThunkHandler;
  }

  FEX_CONFIG_OPT(IsInterpreterInstalled, INTERPRETER_INSTALLED);
  FEX_CONFIG_OPT(Filename, APP_FILENAME);
  FEX_CONFIG_OPT(RootFSPath, ROOTFS);
  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
  FEX_CONFIG_OPT(SMCChecks, SMCCHECKS);
  FEX_CONFIG_OPT(SMCMarkMemo, SMCMARKMEMO);
  FEX_CONFIG_OPT(SMCStoreEmulation, SMCSTOREEMULATION);
  FEX_CONFIG_OPT(SMCSemanticPatch, SMCSEMANTICPATCH);
  FEX_CONFIG_OPT(SMCStoreBackpatch, SMCSTOREBACKPATCH);
  FEX_CONFIG_OPT(SMCMprotectDefer, SMCMPROTECTDEFER);
  FEX_CONFIG_OPT(SMCSoftInvalidate, SMCSOFTINVALIDATE);
  FEX_CONFIG_OPT(SMCFileImmutable, SMCFILEIMMUTABLE);
  FEX_CONFIG_OPT(SMCLazyInval, SMCLAZYINVAL);
  FEX_CONFIG_OPT(SMCLazyScrub, SMCLAZYSCRUB);
  FEX_CONFIG_OPT(SMCLazyLink, SMCLAZYLINK);
  FEX_CONFIG_OPT(NeedsSeccomp, NEEDSSECCOMP);
  FEX_CONFIG_OPT(EnableCodeCaching, ENABLECODECACHINGWIP);
  FEX_CONFIG_OPT(CodeCacheScopeStr, CODECACHESCOPE);

  // Which guest files the code cache subsystem applies to. See the option's Desc
  // in Config.json.in. EnableCodeCaching stays the master switch: with it off,
  // none of these do anything.
  enum class CodeCacheScopeType {
    // Legacy FEX_ENABLECODECACHINGWIP behaviour: load caches for anything, write
    // nothing (only FEXOfflineCompiler produces cache files).
    Off,
    // Rootfs system libraries only. Immutable in practice and shared between
    // titles, so they are the translations worth persisting.
    RootFS,
    // Everything file-backed, including game-side native libraries.
    All,
  };

  CodeCacheScopeType GetCodeCacheScope() const {
    return CodeCacheScope;
  }

  // True when this process writes cache files itself. Implies the context was
  // put into cache-generation mode at startup (relocations retained,
  // section-bounded decode) — without that, saved code is not relocatable and
  // multiblock can span files.
  bool CodeCacheWriteEnabled() const {
    return EnableCodeCaching() && CodeCacheScope != CodeCacheScopeType::Off;
  }

  // Applies the scope gate to a resolved host path.
  bool IsPathInCodeCacheScope(std::string_view Path) const;

  // Loads (if present and in scope) the on-disk cache for one mapped section.
  void LoadCodeCache(FEXCore::Core::InternalThreadState& Thread, FEXCore::ExecutableFileSectionInfo& Section);

  /**
   * Writes a cache file for every in-scope mapped file that has newly compiled
   * blocks, each through a temp file + rename(2).
   *
   * Must be called from a non-signal context with no VMATracking or FEXCore core
   * lock held; it takes the code buffer and lookup cache locks itself. Cheap to
   * call: returns immediately unless writing is enabled.
   */
  void SaveCodeCaches(FEXCore::Core::InternalThreadState* Thread, bool Force);

  // Polls the FEXCore-side "enough new blocks / enough time" trigger and saves
  // if it fires. Called from the tails of the memory-management syscalls, which
  // are the safe points this process reliably passes through.
  void MaybeSaveCodeCaches(FEXCore::Core::InternalThreadState* Thread) {
    if (!CodeCacheWriteEnabled() || !CTX->GetCodeCache().WantsSave(false)) {
      return;
    }
    SaveCodeCaches(Thread, false);
  }

  uint32_t GetHostKernelVersion() const {
    return HostKernelVersion;
  }
  uint32_t GetGuestKernelVersion() const {
    return GuestKernelVersion;
  }

  bool IsHostKernelVersionAtLeast(uint32_t Major, uint32_t Minor = 0, uint32_t Patch = 0) const {
    return GetHostKernelVersion() >= KernelVersion(Major, Minor, Patch);
  }

  static uint32_t CalculateHostKernelVersion();
  uint32_t CalculateGuestKernelVersion();

  static uint32_t KernelVersion(uint32_t Major, uint32_t Minor = 0, uint32_t Patch = 0) {
    return (Major << 24) | (Minor << 16) | Patch;
  }

  static uint32_t KernelMajor(uint32_t Version) {
    return Version >> 24;
  }
  static uint32_t KernelMinor(uint32_t Version) {
    return (Version >> 16) & 0xFF;
  }
  static uint32_t KernelPatch(uint32_t Version) {
    return Version & 0xFFFF;
  }

  virtual FEX::HLE::MemAllocator* Get32BitAllocator() {
    return Alloc32Handler.get();
  }

  // does a mmap as if done via a guest syscall
  void* GuestMmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags, int fd, off_t offset);
  using SyscallMmapInterface::GuestMmap;

  // does a guest munmap as if done via a guest syscall
  uint64_t GuestMunmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length);
  using SyscallMmapInterface::GuestMunmap;

  uint64_t GuestMremap(bool Is64Bit, FEXCore::Core::InternalThreadState*, void* old_address, size_t old_size, size_t new_size, int flags,
                       void* new_address);
  uint64_t GuestMprotect(FEXCore::Core::InternalThreadState*, void* addr, size_t len, int prot);
  uint64_t GuestShmat(bool Is64Bit, FEXCore::Core::InternalThreadState*, int shmid, const void* shmaddr, int shmflg);
  uint64_t GuestShmdt(bool Is64Bit, FEXCore::Core::InternalThreadState*, const void* shmaddr);

  // FEX_HWTSO: give up hardware TSO for the rest of this process, because a
  // range of ordinary guest memory could not be mapped PROT_SAO. One-way and
  // idempotent. See the definition in Syscalls.cpp for the soundness argument,
  // the quiesce primitive and the required call-site placement (VMATracking
  // released, mapping not yet returned to the guest).
  void RevokeHardwareTSO(FEXCore::Core::InternalThreadState* Thread, const char* Site, const void* Addr, size_t Length);

  ///// Memory Manager tracking /////
  struct LateApplyExtendedVolatileMetadata {
    fextl::set<uint64_t> VolatileInstructions {};
    FEXCore::IntervalList<uint64_t> VolatileValidRanges {};
  };
  std::optional<LateApplyExtendedVolatileMetadata> TrackMmap(FEXCore::Core::InternalThreadState* Thread, uint64_t addr, size_t length,
                                                             int prot, int flags, int fd, off_t offset,
                                                             std::optional<FEXCore::ExecutableFileSectionInfo>& CachedSection);
  void TrackMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length);
  void TrackMremap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, size_t OldSize, size_t NewSize, int flags, uint64_t NewAddress);
  void TrackShmat(FEXCore::Core::InternalThreadState* Thread, int shmid, uint64_t shmaddr, int shmflg, uint64_t Length);
  uint64_t TrackShmdt(FEXCore::Core::InternalThreadState* Thread, uint64_t shmaddr);
  void TrackMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot);
  void TrackMadvise(FEXCore::Core::InternalThreadState* Thread, uintptr_t Base, uintptr_t Size, int advice);

  void InvalidateCodeRangeIfNecessary(FEXCore::Core::InternalThreadState* Thread, uint64_t Base, uint64_t Length) {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_NONE) {
      TM.InvalidateGuestCodeRange(Thread, Base, Length);
    }
  }

  void InvalidateCodeRangeIfNecessaryOnRemap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, uint64_t NewAddress,
                                             size_t OldSize, size_t NewSize) {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_NONE) {
      if (OldAddress != NewAddress) {
        if (OldSize != 0) {
          // This also handles the MREMAP_DONTUNMAP case
          TM.InvalidateGuestCodeRange(Thread, OldAddress, OldSize);
        }
        // Also invalidate the destination. With MREMAP_FIXED landing on a
        // mapping that previously held compiled code, the destination's
        // JIT'd blocks survive while the bytes under them are replaced by
        // the source's. The pre-fix version only invalidated the source
        // range, leaving stale translations at the destination — latent
        // without MREMAP_FIXED only because the kernel otherwise picks an
        // unused address. NewSize covers the full incoming range, so
        // any pre-existing compiled blocks anywhere inside NewAddress ..
        // NewAddress+NewSize get invalidated.
        if (NewSize != 0) {
          TM.InvalidateGuestCodeRange(Thread, NewAddress, NewSize);
        }
      } else {
        // If mapping shrunk, flush the unmapped region
        if (OldSize > NewSize) {
          TM.InvalidateGuestCodeRange(Thread, OldAddress + NewSize, OldSize - NewSize);
        }
      }
    }
  }


  ///// VMA (Virtual Memory Area) tracking /////
  static bool HandleSegfault(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext);
  void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override;

  ///// Mono backpatcher hook (Linux port of Source/Windows/Common/InvalidationTracker.cpp) /////
  //
  // Windows learns the mono runtime's code range from PE module load and, on the
  // first SMC fault raised by an XCHG inside that range, marks the containing
  // guest block as "the mono backpatcher".  That one block is recompiled so its
  // XCHGs go through the MonoBackpatcherWrite IR op (an explicit
  // write-then-invalidate helper), after which mprotect-based SMC detection can
  // be switched off for writable+executable regions entirely.  Without steps 2-4
  // every mono code patch takes the slow path (fault -> full page invalidation ->
  // single-inst recompile -> re-protect), which under mono's patch-heavy startup
  // degenerates into a fault storm.
  //
  // These three functions are the Linux equivalents of, respectively,
  // InvalidationTracker::HandleImageMap's mono branch, DetectMonoBackpatcherBlock
  // and DisableSMCDetection.

  // Called from TrackMmap for executable file-backed mappings.  Grows
  // [MonoBase, MonoEnd) across the runtime library's several PT_LOAD mappings.
  void MaybeRecordMonoMapping(std::string_view Path, uint64_t Base, uint64_t End);

  // Called from HandleSegfault after the invalidation.  Returns true if this
  // fault identified the backpatcher block.
  void DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC);

  // Stop write-protecting writable+executable VMAs, and un-protect the ones we
  // already did.  Must be called with VMATracking.Mutex held (shared is fine --
  // we only mprotect, we don't mutate the tracking structures).
  void DisableSMCDetectionLocked(FEXCore::Core::InternalThreadState* Thread);

  bool IsSMCDetectionDisabled() const {
    return SMCDetectionDisabled.load(std::memory_order_relaxed);
  }

  ///// Deferred SMC invalidation across a guest W^X flip (FEX_SMCMPROTECTDEFER) /////
  //
  // A guest that flips a code page W -> write -> X pays a full
  // invalidate/re-protect round trip on the W transition today, even though
  // nothing on the page can be executed until the X transition arrives.  With
  // the option enabled, the W transition instead records the pages here and
  // leaves them unprotected (the guest's own mprotect already dropped our
  // read-only tracking), and the X transition performs the invalidation before
  // the syscall returns.
  //
  // The deferral is sound only because the intermediate protection lacks
  // PROT_EXEC: the guest may not legally execute from those pages, so no stale
  // block can be legitimately reached while the page sits deferred.  A guest
  // asking for PROT_WRITE|PROT_EXEC in one call gets legacy behaviour.
  //
  // Anything that can retire or re-point the underlying memory (munmap, an
  // mmap over the range, mremap) still invalidates unconditionally and simply
  // drops the deferred record, so a stale block can never outlive its mapping.
  //
  // The atomic count lets the hot paths (and the SIGSEGV handler) skip the
  // mutex entirely in the overwhelmingly common case of an empty set.
  // An mprotect of a very large region is not a W^X code flip; recording it
  // page-by-page would cost more than the invalidation it saves, so ranges
  // above this size keep legacy behaviour.
  static constexpr uint64_t SMCMaxDeferredMprotectSize = 4 * 1024 * 1024;

  std::mutex SMCDeferredDirtyMutex;
  std::atomic<uint64_t> SMCDeferredDirtyCount {0};
  fextl::set<uint64_t> SMCDeferredDirtyPages;

  bool SMCMprotectDeferActive() const {
    return SMCMprotectDefer && SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK;
  }

  void MarkSMCDeferredDirtyRange(uint64_t Base, uint64_t Top) {
    std::lock_guard lk {SMCDeferredDirtyMutex};
    for (uint64_t Page = Base; Page < Top; Page += FEXCore::Utils::FEX_PAGE_SIZE) {
      SMCDeferredDirtyPages.insert(Page);
    }
    SMCDeferredDirtyCount.store(SMCDeferredDirtyPages.size(), std::memory_order_release);
  }

  // Drops every deferred record intersecting [Base, Top).  Returns true if any
  // record existed, i.e. if the caller must make sure an invalidation happens.
  bool ClearSMCDeferredDirtyRange(uint64_t Base, uint64_t Top) {
    if (SMCDeferredDirtyCount.load(std::memory_order_acquire) == 0) {
      return false;
    }
    std::lock_guard lk {SMCDeferredDirtyMutex};
    auto First = SMCDeferredDirtyPages.lower_bound(Base);
    auto Last = SMCDeferredDirtyPages.lower_bound(Top);
    const bool Any = First != Last;
    SMCDeferredDirtyPages.erase(First, Last);
    SMCDeferredDirtyCount.store(SMCDeferredDirtyPages.size(), std::memory_order_release);
    return Any;
  }

  ///// File-backed code treated as immutable (FEX_SMCFILEIMMUTABLE) /////
  //
  // Relaxed-correctness speed option; see the design block comment above
  // SyscallHandler::MarkGuestExecutableRange in SyscallsSMCTracking.cpp for the
  // full argument.  Two pieces of state:
  //
  //  - SMCImmutableSkippedPages: the pages where MarkGuestExecutableRange
  //    declined to install write protection because the code came from a
  //    private file-backed mapping.  This is what makes the guest-mprotect
  //    re-arm (case 2b) precise: only an mprotect that adds PROT_WRITE to a
  //    range we actually skipped has anything to answer for.
  //  - MappedResource::SMCFileImmutableRevoked: set by that re-arm, sticky, so
  //    the mapping goes back to legacy mtrack for the rest of the process.
  //
  // Same atomic-count fast path as the deferred-dirty set above: with the
  // option off the set is permanently empty and every query is one relaxed
  // load.
  std::mutex SMCImmutableSkippedMutex;
  std::atomic<uint64_t> SMCImmutableSkippedCount {0};
  std::atomic<uint64_t> SMCImmutableSkipTotal {0}; // audit counter, never decremented
  fextl::set<uint64_t> SMCImmutableSkippedPages;

  bool SMCFileImmutableActive() const {
    return SMCFileImmutable && SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK;
  }

  // Returns the running total of skipped pages, for the audit line.
  uint64_t MarkSMCImmutableSkippedRange(uint64_t Base, uint64_t Top) {
    std::lock_guard lk {SMCImmutableSkippedMutex};
    uint64_t Added {};
    for (uint64_t Page = Base; Page < Top; Page += FEXCore::Utils::FEX_PAGE_SIZE) {
      Added += SMCImmutableSkippedPages.insert(Page).second ? 1 : 0;
    }
    SMCImmutableSkippedCount.store(SMCImmutableSkippedPages.size(), std::memory_order_release);
    return SMCImmutableSkipTotal.fetch_add(Added, std::memory_order_relaxed) + Added;
  }

  // Drops every skip record intersecting [Base, Top).  Returns true if any
  // existed, i.e. if the caller is looking at a range that currently holds
  // compiled code FEX chose not to protect.
  bool ClearSMCImmutableSkippedRange(uint64_t Base, uint64_t Top) {
    if (SMCImmutableSkippedCount.load(std::memory_order_acquire) == 0) {
      return false;
    }
    std::lock_guard lk {SMCImmutableSkippedMutex};
    auto First = SMCImmutableSkippedPages.lower_bound(Base);
    auto Last = SMCImmutableSkippedPages.lower_bound(Top);
    const bool Any = First != Last;
    SMCImmutableSkippedPages.erase(First, Last);
    SMCImmutableSkippedCount.store(SMCImmutableSkippedPages.size(), std::memory_order_release);
    return Any;
  }

  // Marks every MappedResource intersecting [Base, Top) as no longer eligible
  // for the immutability assumption.
  // - VMATracking.Mutex must be unique_locked before calling
  void RevokeSMCFileImmutabilityLocked(uint64_t Base, uint64_t Top);
  ///// Lazy SMC invalidation (FEX_SMCLAZYINVAL) /////
  //
  // DELIBERATELY UNSOUND FOR SPEED. The full design note, the drain-point
  // list, and the exact statement of what correctness is being traded away
  // live in LinuxSyscalls/SMCLazyInvalidate.h -- read it before touching any
  // of this.
  //
  // Structure mirrors the SMCDeferredDirtyPages block above: a leaf mutex
  // guarding an ordered page set, plus an atomic count so every drain point
  // is a single relaxed-ish load when the set is empty (which is every check
  // in a run with the option off, and the overwhelming majority of checks
  // even with it on). The mutex is a leaf: nothing is called while holding
  // it, and in particular no drain runs under it -- the batch is swapped out
  // first, then soft-invalidated outside, because
  // ThreadManager::SoftInvalidateGuestCodeRange takes ThreadCreationMutex and
  // the exclusive CodeInvalidationMutex and force-releases pending shared
  // locks (ReleaseAllPendingSharedLocks) on its way there.
  //
  // Taking it from the SIGSEGV handler is safe for the same reason
  // SMCDeferredDirtyMutex already is: no guest memory is touched while it is
  // held (only the set's own nodes), so a thread holding it cannot take an SMC
  // fault and re-enter.
  std::mutex SMCLazyDirtyMutex;
  std::atomic<uint64_t> SMCLazyDirtyCount {0};
  fextl::set<uint64_t> SMCLazyDirtyPages;

  // Set once at construction, after the SMCSoftInvalidate + mtrack gate.
  std::atomic<bool> SMCLazyInvalEnabled {false};

  // FEX_SMCLAZYSCRUB. Set at the same point, and only if lazy invalidation
  // itself came up. This is what makes lazy sound for same-thread SMC; see
  // LinuxSyscalls/SMCLazyInvalidate.h, section "SAME-THREAD SOUNDNESS".
  std::atomic<bool> SMCLazyScrubEnabled {false};

  bool SMCLazyInvalActive() const {
    return SMCLazyInvalEnabled.load(std::memory_order_relaxed);
  }

  bool SMCLazyScrubActive() const {
    return SMCLazyScrubEnabled.load(std::memory_order_relaxed);
  }

  // FEX_SMCLAZYLINK. Set only if lazy + scrub came up AND block linking is in
  // play (no semantic patch). When active, the SMC fault handler arms the
  // faulting thread's InterruptFaultPage so a linked block chain still drains
  // at its next block entry; see SMCLazyInvalidate.h "LINKING UNDER LAZY".
  std::atomic<bool> SMCLazyLinkEnabled {false};

  bool SMCLazyLinkActive() const {
    return SMCLazyLinkEnabled.load(std::memory_order_relaxed);
  }

  // Records a page as dirty-but-not-invalidated. Returns true if this is the
  // first time the page entered the set since the last drain (the audit trace
  // logs the lazy unprotect once per page per dirty epoch, not once per
  // store). Called from the SIGSEGV handler.
  bool MarkSMCLazyDirtyPage(uint64_t Page) {
    std::lock_guard lk {SMCLazyDirtyMutex};
    const bool Inserted = SMCLazyDirtyPages.insert(Page).second;
    SMCLazyDirtyCount.store(SMCLazyDirtyPages.size(), std::memory_order_release);
    return Inserted;
  }

  // Forgets every dirty record intersecting [Base, Top) WITHOUT invalidating.
  // Only legal where the caller performs (or has performed) a hard
  // invalidation of the same range, which is strictly stronger. Returns true
  // if any record existed.
  bool ClearSMCLazyDirtyRange(uint64_t Base, uint64_t Top) {
    if (SMCLazyDirtyCount.load(std::memory_order_acquire) == 0) {
      return false;
    }
    std::lock_guard lk {SMCLazyDirtyMutex};
    auto First = SMCLazyDirtyPages.lower_bound(Base);
    auto Last = SMCLazyDirtyPages.lower_bound(Top);
    const bool Any = First != Last;
    SMCLazyDirtyPages.erase(First, Last);
    SMCLazyDirtyCount.store(SMCLazyDirtyPages.size(), std::memory_order_release);
    return Any;
  }

  // Drain: soft-invalidate every dirty page and drop the records. Must not be
  // called with any code-invalidation lock held. No-op when the set is empty.
  void DrainSMCLazyDirtyPages(FEXCore::Core::InternalThreadState* Thread, FEX::HLE::SMCLazy::DrainPoint Point);

  // Drain restricted to [Base, Top). Used by guest mprotect(PROT_EXEC), which
  // must settle the range's debt before it returns.
  void DrainSMCLazyDirtyRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Base, uint64_t Top,
                              FEX::HLE::SMCLazy::DrainPoint Point);

  // FEXCore-side hook for drain point (a), ContextImpl::CompileBlock.
  void DrainLazySMCInvalidations(FEXCore::Core::InternalThreadState* Thread) override {
    DrainSMCLazyDirtyPages(Thread, FEX::HLE::SMCLazy::DrainPoint::CompileBlock);
  }

  void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override;
  std::optional<FEXCore::ExecutableFileSectionInfo>
  LookupExecutableFileSection(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) final override;

  const char* LookupAnonymousExecImageName(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) final override;

  int OpenCodeMapFile() override;

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) override;

  ///// FORK tracking /////
  void LockBeforeFork(FEXCore::Core::InternalThreadState* Thread);
  void UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child);

  void RegisterTLSState(FEX::HLE::ThreadStateObject* Thread);
  void UninstallTLSState(FEX::HLE::ThreadStateObject* Thread);

  SourcecodeResolver* GetSourcecodeResolver() override {
    return this;
  }

  void SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame) override {
    TM.SleepThread(CTX, Frame);
  }

  bool NeedXIDCheck() const {
    return NeedToCheckXID;
  }
  void DisableXIDCheck() {
    NeedToCheckXID = false;
  }
  // Re-arm post-fork: the child inherits NeedToCheckXID=false (parent already
  // captured glibc SETXID handler) but glibc reinstalls SETXID for the child
  // first newly-created thread; we need to capture THAT copy too, otherwise
  // the new handler runs as native code in JIT context the first time guest
  // setuid() fans out and corrupts SRA.
  void EnableXIDCheck() {
    NeedToCheckXID = true;
  }

  constexpr static uint64_t TASK_MAX_64BIT = (1ULL << 48);
  constexpr static size_t MAX_LDT_ENTRIES = 8192;
  constexpr static size_t LDT_ENTRY_SIZE = sizeof(FEXCore::Core::CPUState::gdt_segment);

  VMATracking::VMATracking VMATracking;

  // LookupAnonymousExecImageName caches. Positive entries are keyed by the
  // discovered image base and interned for the process lifetime (the public
  // interface hands out raw const char* — see the contract in
  // FEXCore/include/FEXCore/HLE/SyscallHandler.h). Negative entries are keyed
  // by the VMA base the query landed in, so Mono/JIT arenas don't pay the
  // backward walk on every compiled block. Neither is invalidated on unmap:
  // a stale label on a recycled base mislabels a profile line, it cannot
  // corrupt state.
  std::mutex AnonImageNameMutex;
  fextl::map<uint64_t, fextl::unique_ptr<fextl::string>> AnonImageNames;
  fextl::map<uint64_t, const char*> AnonImageLookupCache;

  // Identifies the code generator, so a cache file is only ever opened by a
  // process whose codegen matches the one that wrote it. Combined with the
  // content-derived FileId in the cache filename (`<FileId>-<ConfigId>`), a
  // stale or mismatched key is a cache MISS — never a load of wrong code.
  const uint64_t CodeCacheConfigId = FEXCore::ComputeCodeCacheConfigId();

  // Parsed once from the CodeCacheScope string option.
  const CodeCacheScopeType CodeCacheScope = [this]() {
    const auto& Value = CodeCacheScopeStr();
    if (Value == "rootfs") {
      return CodeCacheScopeType::RootFS;
    }
    if (Value == "all") {
      return CodeCacheScopeType::All;
    }
    if (Value != "off" && !Value.empty()) {
      LogMan::Msg::EFmt("Unknown CodeCacheScope '{}', treating as 'off'", Value);
    }
    return CodeCacheScopeType::Off;
  }();

  // FileIds this process loaded a cache for. Those blocks were relocated on
  // load and carry no relocation records of their own, so re-serializing them
  // would produce a cache that is only valid at this run's base address. Never
  // write a file we read.
  std::mutex CodeCacheLoadedMutex;
  fextl::set<uint64_t> CodeCacheLoadedFileIds;

  uint64_t read_ldt(FEXCore::Core::CpuStateFrame* Frame, void* ptr, unsigned long bytecount);
  uint64_t write_ldt(FEXCore::Core::CpuStateFrame* Frame, void* ptr, unsigned long bytecount, bool legacy);

protected:
  SyscallHandler(FEXCore::Context::Context* _CTX, FEX::HLE::SignalDelegator* _SignalDelegation, FEX::HLE::ThunkHandler* ThunkHandler);

  fextl::vector<SyscallFunctionDefinition> Definitions {std::max<std::size_t>(FEX::HLE::x64::SYSCALL_x64_MAX, FEX::HLE::x32::SYSCALL_x86_MAX),
                                                        {
                                                          .Ptr = reinterpret_cast<void*>(&UnimplementedSyscall),
                                                          .NumArgs = 255,
                                                        }};
  std::mutex MMapMutex;

  // BRK management
  uint64_t DataSpace {};
  uint64_t DataSpaceSize {};
  uint64_t DataSpaceMappedSize {};

  // (Major << 24) | (Minor << 16) | Patch
  uint32_t HostKernelVersion {};
  uint32_t GuestKernelVersion {};

  FEXCore::Context::Context* CTX;

public:
  // Linux equivalent of Windows InvalidationTracker.cpp's mono-DLL-load
  // detection.  Called from the openat / open / openat2 syscall handlers
  // (Syscalls/FD.cpp) with each guest-opened file path.  If the basename
  // matches a known Mono runtime library (libmono*, libmonosgen*,
  // libmonoboehm*, mono-2.0-bdwgc*) and we haven't already detected,
  // call CTX->MarkMonoDetected() to enable the MonoHacks code paths.
  //
  // Atomic short-circuit on MonoDetectionComplete makes the post-detection
  // cost one relaxed load.  Gated by Config.MonoHacks: if the user hasn't
  // opted in, the check is a no-op so we don't even pay the strstr cost.
  void MaybeDetectMonoFromPath(std::string_view pathname);

  // Returns true if the basename of Path is a known Mono runtime library.
  static bool IsMonoRuntimeLibraryPath(std::string_view Path);

  // Statically-linked Mono fallback (MonoKickstart / Stardew-Valley class
  // games): the mono runtime is compiled directly into the main executable,
  // so no libmono*.so is ever opened and IsMonoRuntimeLibraryPath never
  // matches.  Two independent signals substitute for the dynamic-library
  // open:
  //   - the guest opening one of mono's own data files (mscorlib.dll,
  //     machine.config) -- called from the openat/openat2 handlers exactly
  //     like MaybeDetectMonoFromPath;
  //   - FEX_FORCE_MONO_DETECT=1, an unconditional override for experiments.
  // Either one arms [MonoBase, MonoEnd) from the main executable's own
  // mapped (executable) range instead of a runtime library's, since that's
  // where the statically-linked mono code -- and its XCHG backpatcher --
  // actually lives.  FEX_MONO_DETECT=0 disables just the path-signal half of
  // this (dynamic libmono*.so detection via MaybeDetectMonoFromPath is
  // unaffected either way).
  void MaybeDetectMonoFallbackFromPath(std::string_view pathname);

  // Returns true if the basename of Path is one of mono's canonical data
  // files (mscorlib.dll, machine.config) at a path component boundary --
  // i.e. the path ends with "/mscorlib.dll" or "/machine.config", not
  // merely contains those names as a substring.
  static bool IsMonoDataFilePath(std::string_view Path);

private:
  // Records the main executable's own mapped executable range into
  // [MainExeBase, MainExeEnd), growing across its PT_LOAD segments.  Called
  // unconditionally from TrackMmap (gated only by MonoHacksConfig, since we
  // don't yet know whether a fallback signal will ever fire) so the range is
  // fully known well before the guest can issue its first syscall -- the
  // main ELF finishes loading before Execute() ever runs guest code.
  void MaybeRecordMainExeMapping(uint64_t Dev, uint64_t Ino, uint64_t Base, uint64_t End);

  // Resolves (once) the (dev, ino) identity of the main executable the same
  // way OpenCodeMapFile does: RootFS-prefixed path first, falling back to
  // the bare path.  Returns false if neither could be stat()'d.
  bool ResolveMainExeIdentity();

  // Common one-shot arm: claims [MonoBase, MonoEnd) from [MainExeBase,
  // MainExeEnd) the first time any fallback signal fires, applies the same
  // Multiblock/MaxInst gate as MaybeDetectMonoFromPath, and -- on success --
  // calls CTX->MarkMonoDetected() and flips MonoHacksActive /
  // MonoBackpatcherDetectionPending exactly like the dynamic-library path.
  // A no-op if dynamic-library detection (or a previous fallback call) has
  // already armed a range: MonoFallbackArmed and MonoHacksActive are both
  // checked so the range, once set, is never moved or re-registered.
  void ArmMonoFallbackRange(std::string_view Reason, std::string_view Detail);

  // Checks FEX_FORCE_MONO_DETECT and, if set, arms the fallback range
  // unconditionally (no path signal required).  Called from the same
  // openat/openat2 hook points as the path-based fallback so it fires at
  // the first guest syscall -- by which point the main executable is fully
  // mapped.  Idempotent: MonoFallbackArmed short-circuits every call after
  // the first.
  void MaybeForceMonoDetect();

  std::atomic<bool> MonoDetectionComplete {false};

  // Same short-circuit as MonoDetectionComplete, but for
  // MaybeDetectMonoFallbackFromPath.  Kept separate from
  // MonoDetectionComplete because the two paths can finish in either order
  // (or not at all, independently of each other).
  std::atomic<bool> MonoFallbackDetectionComplete {false};

  // True once MarkMonoDetected has actually fired (i.e. mono was seen *and* the
  // Multiblock/MaxInst gate passed).  Lets the mmap path avoid tracking a range
  // for a config where the hacks would never run.
  std::atomic<bool> MonoHacksActive {false};

  // Guest code range of the mono runtime library, grown across its PT_LOAD
  // mappings.  Zero until MaybeRecordMonoMapping sees an executable mapping.
  std::atomic<uint64_t> MonoBase {0};
  std::atomic<uint64_t> MonoEnd {0};

  // One-shot: set when we have a range and are still looking for the
  // backpatcher block; cleared once we find it (or give up).
  std::atomic<bool> MonoBackpatcherDetectionPending {false};

  // Set by DisableSMCDetectionLocked.  Once set, MarkGuestExecutableRange stops
  // write-protecting VMAs that are both writable and executable.
  std::atomic<bool> SMCDetectionDisabled {false};

  ///// Statically-linked ("MonoKickstart") Mono fallback /////

  // Guest code range of the main executable's own mapped executable PT_LOAD
  // segment(s), grown the same way as MonoBase/MonoEnd.  Populated
  // unconditionally by MaybeRecordMainExeMapping; independent of whether a
  // fallback signal ever fires.
  std::atomic<uint64_t> MainExeBase {0};
  std::atomic<uint64_t> MainExeEnd {0};

  // One-shot: true once ArmMonoFallbackRange has claimed [MonoBase, MonoEnd)
  // from [MainExeBase, MainExeEnd).  Guards the range from ever being
  // re-armed or moved once set, and stops MaybeRecordMonoMapping's dynamic
  // path from clobbering a fallback-armed range if a libmono*.so somehow
  // gets opened afterwards.
  std::atomic<bool> MonoFallbackArmed {false};

  // Guards lazy resolution of the main executable's (dev, ino) identity.
  std::once_flag MainExeIdentityOnce;
  bool MainExeIdentityValid {false};
  uint64_t MainExeDev {};
  uint64_t MainExeIno {};

private:
  FEX::HLE::SignalDelegator* SignalDelegation;
  FEX::HLE::ThunkHandler* ThunkHandler;

  fextl::unordered_map<fextl::string, FEX::VolatileMetadata::ExtendedVolatileMetadata> ExtendedMetaData {};

  std::mutex FutexMutex;
  std::mutex SyscallMutex;
  FEX::CodeLoader* LocalLoader {};
  bool NeedToCheckXID {true};

#ifdef DEBUG_STRACE
  void Strace(FEXCore::HLE::SyscallArguments* Args, uint64_t Ret);
#endif
  fextl::unique_ptr<FEXCore::HLE::SourcecodeMap> GenerateMap(std::string_view GuestBinaryFile, std::string_view GuestBinaryFileId) override;

  fextl::unique_ptr<FEX::HLE::MemAllocator> Alloc32Handler {};
  std::atomic<uint64_t> AnonSharedId {1};
};

#define SYSCALL_ERRNO()              \
  do {                               \
    if (Result == -1) return -errno; \
    return Result;                   \
  } while (0)
#define SYSCALL_ERRNO_NULL()        \
  do {                              \
    if (Result == 0) return -errno; \
    return Result;                  \
  } while (0)

extern FEX::HLE::SyscallHandler* _SyscallHandler;

#ifdef DEBUG_STRACE
//////
/// Templates to map parameters to format string for syscalls
//////

template<typename T>
struct ArgToFmtString;

#define ARG_TO_STR(tpy, str)                      \
  template<>                                      \
  struct FEX::HLE::ArgToFmtString<tpy> {          \
    inline static const char* const Format = str; \
  };

// Base types
ARG_TO_STR(int, "{}")
ARG_TO_STR(unsigned int, "{}")
ARG_TO_STR(long, "{}")
ARG_TO_STR(unsigned long, "{}")

// string types
ARG_TO_STR(char*, "{}")
ARG_TO_STR(const char*, "{}")

// Pointers
template<typename T>
struct ArgToFmtString<T*> {
  inline static const char* const Format = "{:x}";
};

// Use ArgToFmtString and variadic template to create a format string from an args list
template<typename... Args>
fextl::string CollectArgsFmtString() {
  std::array<const char*, sizeof...(Args)> array = {ArgToFmtString<Args>::Format...};
  return fextl::fmt::format("{}", fmt::join(array, ", "));
}
#else
#define ARG_TO_STR(tpy, str)
#endif

struct open_how {
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

struct kernel_clone3_args {
  uint64_t flags;
  uint64_t pidfd;
  uint64_t child_tid;
  uint64_t parent_tid;
  uint64_t exit_signal;
  uint64_t stack;
  uint64_t stack_size;
  uint64_t tls;
  uint64_t set_tid;
  uint64_t set_tid_size;
  uint64_t cgroup;
};

enum TypeOfClone {
  TYPE_CLONE2,
  TYPE_CLONE3,
};

struct clone3_args {
  TypeOfClone Type;
  uint64_t SignalMask;

  uint64_t StackSize;
  void* NewStack;

  kernel_clone3_args args;
};

uint64_t CloneHandler(FEXCore::Core::CpuStateFrame* Frame, FEX::HLE::clone3_args* args);

// open(2) flag remapping — implementation is per-arch, in FlagRemapping.h
#if defined(ARCHITECTURE_x86_64)
#  include "LinuxSyscalls/x64/FlagRemapping.h"
#elif defined(ARCHITECTURE_ppc64le)
#  include "LinuxSyscalls/PPC64LE/FlagRemapping.h"
#else
#  error "RemapFromX86Flags / RemapToX86Flags: unknown host architecture"
#endif

/**
 * @brief Checks raw syscall return for error
 *
 * This should only be used with raw syscall usage
 *
 * This should not be used with glibc wrapped syscall functions
 *   - This includes the glibc ::syscall(...) function
 *   - This is due to glibc already wrapping the return and setting errno
 *
 * This function should not be used with UAPI breaking syscall results
 * ioctl specifically will break this convention.
 *
 * @param Result The raw syscall return
 *
 * @return If the result was an error result
 */

[[maybe_unused]]
static bool HasSyscallError(uint64_t Result) {
  // MAX_ERRNO is part of the Linux Syscall ABI
  // Redefined here since it doesn't exist as a visible define in the UAPI headers
  constexpr uint64_t MAX_ERRNO = 0xFFFF'FFFF'FFFF'0001ULL;
  // Raw syscalls are guaranteed to not return a valid result in the range of [-4095, -1]
  // In cases where FEX needs to use raw syscalls, this helper checks for this idiom
  return reinterpret_cast<uint64_t>(Result) >= MAX_ERRNO;
}

[[maybe_unused]]
static bool HasSyscallError(const void* Result) {
  return HasSyscallError(reinterpret_cast<uintptr_t>(Result));
}

template<bool IncrementOffset, typename T>
uint64_t GetDentsEmulation(int fd, T* dirp, uint32_t count);

namespace FaultSafeUserMemAccess {
  // These are little helper functions for cases when FEX needs to copy data to or from the application in a robust fashion.
  // CopyFromUser and CopyToUser are memcpy routines that expect to safely SIGSEGV when reading or writing application memory respectively.
  // Returns zero if the memcpy completed, or crashes with SIGABRT and a log message if it faults.
  [[nodiscard]]
  size_t CopyFromUser(void* Dest, const void* Src, size_t Size);
  [[nodiscard]]
  size_t CopyToUser(void* Dest, const void* Src, size_t Size);
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED && defined(ARCHITECTURE_arm64)
  // These helpers just check if the user pointer is readable and writable.
  // This is useful in an assert build that can be safely sprinkled through the syscall handler without overhead in release builds.
  void VerifyIsReadable(const void* Src, size_t Size);
  void VerifyIsReadableOrNull(const void* Src, size_t Size);
  void VerifyIsWritable(void* Src, size_t Size);
  void VerifyIsWritableOrNull(void* Src, size_t Size);

  // Iterates a null-terminated string and checks if all bytes are readable
  void VerifyIsStringReadable(const char* Src);

  // Iterates a null-terminated string and checks if all bytes are readable. Up to MaxSize bytes are checked.
  void VerifyIsStringReadableMaxSize(const char* Src, size_t MaxSize);
#else
  inline void VerifyIsReadable(const void* Src, size_t Size) {
    if (Src == nullptr) {
      ERROR_AND_DIE_FMT("Unexpected nullptr syscall argument");
    }
  }
  inline void VerifyIsReadableOrNull(const void* Src, size_t Size) {}
  inline void VerifyIsWritable(void* Src, size_t Size) {
    if (Src == nullptr) {
      ERROR_AND_DIE_FMT("Unexpected nullptr syscall argument");
    }
  }
  inline void VerifyIsWritableOrNull(void* Src, size_t Size) {}
  inline void VerifyIsStringReadable(const char* Src) {
    if (Src == nullptr) {
      ERROR_AND_DIE_FMT("Unexpected nullptr syscall argument");
    }
  }
  inline void VerifyIsStringReadableMaxSize(const char* Src, size_t MaxSize) {
    if (Src == nullptr) {
      ERROR_AND_DIE_FMT("Unexpected nullptr syscall argument");
    }
  }
#endif
  bool IsFaultLocation(uint64_t PC);

  static inline bool TryHandleSafeFault(int Signal, const siginfo_t& SigInfo, void* UContext) {
    if (Signal == SIGSEGV && (SigInfo.si_code == SEGV_MAPERR || SigInfo.si_code == SEGV_ACCERR) &&
        FaultSafeUserMemAccess::IsFaultLocation(ArchHelpers::Context::GetPc(UContext))) {
      // Return from the subroutine, returning EFAULT.
      ArchHelpers::Context::SetArmReg(UContext, 0, EFAULT);
      ArchHelpers::Context::SetPc(UContext, ArchHelpers::Context::GetArmReg(UContext, 30));
      return true;
    }

    return false;
  }
} // namespace FaultSafeUserMemAccess


template<typename T>
inline static uint64_t futimesat_compat(int dirfd, const char* pathname, const T times[2]) {
  FaultSafeUserMemAccess::VerifyIsReadableOrNull(times, sizeof(*times) * 2);

  timespec tvs[2] {};
  timespec* tv_ptr {};
  if (times) {
    constexpr int64_t ONE_SECOND_AS_USEC = 1'000'000LL;

    // Incoming microsecond time must not be negative or be larger than one second.
    if (times[0].tv_usec < 0 || times[1].tv_usec < 0 || times[0].tv_usec >= ONE_SECOND_AS_USEC || times[1].tv_usec >= ONE_SECOND_AS_USEC) {
      return -EINVAL;
    }

    tvs[0].tv_sec = times[0].tv_sec;
    tvs[0].tv_nsec = 1000LL * times[0].tv_usec;
    tvs[1].tv_sec = times[1].tv_sec;
    tvs[1].tv_nsec = 1000LL * times[1].tv_usec;
    tv_ptr = tvs;
  }

  uint64_t Result = ::syscall(SYSCALL_DEF(utimensat), dirfd, pathname, tv_ptr, 0);
  SYSCALL_ERRNO();
}

} // namespace FEX::HLE

// Registers syscall for both 32bit and 64bit
#define REGISTER_SYSCALL_IMPL(name, lambda)                                                      \
  do {                                                                                           \
    FEX::HLE::x64::RegisterSyscall(Handler, FEX::HLE::x64::SYSCALL_x64_##name, #name, (lambda)); \
    FEX::HLE::x32::RegisterSyscall(Handler, FEX::HLE::x32::SYSCALL_x86_##name, #name, (lambda)); \
  } while (false)
