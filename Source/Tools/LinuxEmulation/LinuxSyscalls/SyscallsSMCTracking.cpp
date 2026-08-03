// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: SMC/MMan Tracking
$end_info$
*/

#include <Common/Config.h>
#include "Common/FDUtils.h"
#include "Common/FEXServerClient.h"
#include "Common/FileMappingBaseAddress.h"

#include <filesystem>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/shm.h>

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"

#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <unistd.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <FEXHeaderUtils/Syscalls.h>
#include <fcntl.h>
#include <Linux/Utils/ELFParser.h>

namespace FEX::HLE {

// FEX_SMC_AUDIT: append-only raw-fd trace of the SMC tracking pipeline
// (compile-time page registration lives in Core.cpp with its own copy).
// Raw open/dprintf so the fault-handler call sites stay signal-tolerable.
int SMCAuditFD() {
  static int fd = [] {
    const char* p = getenv("FEX_SMC_AUDIT");
    if (!p) {
      return -1;
    }
    return ::open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
  }();
  return fd;
}
#define SMC_AUDIT(...) \
  do { \
    int fd_ = SMCAuditFD(); \
    if (fd_ >= 0) { \
      dprintf(fd_, __VA_ARGS__); \
    } \
  } while (0)

// SMC interactions
// ---------------------------------------------------------------------------
// SMC store emulation (FEX_SMCSTOREEMULATION=1)
//
// When a guest store faults on an SMC-tracked page but the written bytes do
// not overlap any compiled block, the write is pure data that happens to share
// a page with code (false sharing). Invalidate-unprotect-retry costs a full
// invalidate + recompile round trip per write burst (~22us measured on
// POWER8, smcstorm falseshare: 376x slowdown vs native). Instead: decode the
// faulting host store, perform it via pwrite on /proc/self/mem (kernel
// FOLL_FORCE writes through the read-only protection and breaks CoW
// correctly), advance NIP past the store, and leave the page protected. No
// invalidation, no protection flapping, no recompile.
//
// Scope (v1): plain GPR stores only — D/DS-form stb/sth/stw/std (+update
// forms) and X-form stbx/sthx/stwx/stdx (+update forms). Everything else
// (VSX/VMX stores, byte-reversed forms, store-conditional, dcbz) falls back
// to the legacy invalidate path. Store-conditional MUST fall back: a
// reservation cannot be honored via pwrite.
//
// Known caveat (documented for review): pwrite's kernel-side copy is not
// guaranteed single-copy-atomic for 8-byte aligned stores the way a host
// `std` is. A lock-free guest data structure sharing a page with compiled
// code could observe a torn 8-byte write. Accepted for v1 as a narrow race
// on an already-pathological layout; revisit if telemetry implicates it.

#ifdef ARCHITECTURE_ppc64le
namespace {
struct DecodedStore {
  uint64_t EA;
  uint64_t Value;
  uint32_t Width;    // bytes: 1/2/4/8
  uint32_t UpdateRA; // register to write EA back to for update forms, ~0u if none
};

int SelfMemFD() {
  static int fd = ::open("/proc/self/mem", O_WRONLY | O_CLOEXEC);
  return fd;
}

// Decode a ppc64le GPR store at PC using register state from the ucontext.
// Returns false for anything that is not a recognized plain store.
bool DecodePPCStore(void* ucontext, uint64_t PC, DecodedStore* Out) {
  const uint32_t Insn = *reinterpret_cast<const uint32_t*>(PC);
  const uint32_t Primary = Insn >> 26;
  const uint32_t RS = (Insn >> 21) & 31;
  const uint32_t RA = (Insn >> 16) & 31;
  const uint32_t RB = (Insn >> 11) & 31;
  const int64_t D = static_cast<int16_t>(Insn & 0xFFFF);
  const int64_t DS = static_cast<int16_t>(Insn & 0xFFFC);

  const auto GPR = [ucontext](uint32_t r) {
    return FEX::ArchHelpers::Context::GetPPCGpReg(ucontext, r);
  };
  const uint64_t Base = (RA == 0) ? 0 : GPR(RA);

  uint32_t Width = 0;
  uint64_t EA = 0;
  bool Update = false;

  switch (Primary) {
  case 36: Width = 4; EA = Base + D; break;              // stw
  case 37: Width = 4; EA = GPR(RA) + D; Update = true; break; // stwu
  case 38: Width = 1; EA = Base + D; break;              // stb
  case 39: Width = 1; EA = GPR(RA) + D; Update = true; break; // stbu
  case 44: Width = 2; EA = Base + D; break;              // sth
  case 45: Width = 2; EA = GPR(RA) + D; Update = true; break; // sthu
  case 62: {                                             // std/stdu (DS-form)
    const uint32_t XO = Insn & 3;
    if (XO == 0) {
      Width = 8; EA = Base + DS;
    } else if (XO == 1) {
      Width = 8; EA = GPR(RA) + DS; Update = true;
    } else {
      return false; // stq etc.
    }
    break;
  }
  case 31: {                                             // X-forms
    const uint32_t XO = (Insn >> 1) & 0x3FF;
    switch (XO) {
    case 215: Width = 1; EA = Base + GPR(RB); break;     // stbx
    case 247: Width = 1; EA = GPR(RA) + GPR(RB); Update = true; break; // stbux
    case 407: Width = 2; EA = Base + GPR(RB); break;     // sthx
    case 439: Width = 2; EA = GPR(RA) + GPR(RB); Update = true; break; // sthux
    case 151: Width = 4; EA = Base + GPR(RB); break;     // stwx
    case 183: Width = 4; EA = GPR(RA) + GPR(RB); Update = true; break; // stwux
    case 149: Width = 8; EA = Base + GPR(RB); break;     // stdx
    case 181: Width = 8; EA = GPR(RA) + GPR(RB); Update = true; break; // stdux
    default: return false; // stdcx./byte-reversed/vector/dcbz -> legacy path
    }
    break;
  }
  default: return false;
  }

  if (Update && RA == 0) {
    return false; // invalid form
  }

  Out->EA = EA;
  Out->Value = GPR(RS); // truncation happens at pwrite via Width
  Out->Width = Width;
  Out->UpdateRA = Update ? RA : ~0u;
  return true;
}
} // anonymous namespace
#endif // ARCHITECTURE_ppc64le

bool SyscallHandler::HandleSegfault(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  const auto FaultAddress = (uintptr_t)((siginfo_t*)info)->si_addr;

  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  auto CallRetStackInfo = ThreadObject->GetCallRetStackInfo();
  if (FaultAddress >= CallRetStackInfo.AllocationBase && FaultAddress < CallRetStackInfo.AllocationEnd) {
    // Reset REG_CALLRET_SP to the default location to allow for underflows/overflows
    ArchHelpers::Context::SetArmReg(ucontext, 25, CallRetStackInfo.DefaultLocation);
    return true;
  }

  // The SIGSEGV that brought us here may have interrupted a JIT block
  // currently executing under a shared_lock on CodeInvalidationMutex (taken
  // by ContextImpl::CompileBlock or PPC64LE ExitFunctionLink).  The
  // InvalidateGuestCodeRange call below acquires the WRITE side of the same
  // mutex; since WritePriorityMutex is non-recursive, the same thread holding
  // a read lock would self-deadlock when asking for the write lock.  Force-
  // release any such read locks now; the interrupted scope's TrackedSharedLock
  // dtor becomes a no-op via TakeOverAndUnlock().  Whether or not we end up
  // redirecting PC below (the "intersects current block" path), the
  // interrupted scope is safe to leave with the lock released: if PC is
  // redirected the original frame is abandoned; if PC is NOT redirected the
  // original instruction retries -- it may re-enter CompileBlock/ExitFunction-
  // Link from scratch and acquire a fresh read lock, which is correct.
  FEXCore::ReleaseAllPendingSharedLocks();

  {
    // Can't use the deferred signal lock in the SIGSEGV handler.
    auto lk = FEXCore::MaskSignalsAndLockMutex<std::shared_lock>(_SyscallHandler->VMATracking.Mutex);

    auto VMATracking = &_SyscallHandler->VMATracking;

    // If the write spans two pages, they will be flushed one at a time (generating two faults)
    auto Entry = VMATracking->FindVMAEntry(FaultAddress);

    // If an untracked address, or the mapping wasn't writable, it can't be handled here
    if (Entry == VMATracking->VMAs.end() || !Entry->second.Prot.Writable) {
      SMC_AUDIT("[%d] fault addr=%lx UNHANDLED %s\n", FHU::Syscalls::gettid(), FaultAddress,
                Entry == VMATracking->VMAs.end() ? "untracked" : "vma-not-writable");
      return false;
    }

    auto FaultBase = FEXCore::AlignDown(FaultAddress, FEXCore::Utils::FEX_PAGE_SIZE);

    auto UnprotectRegionCallback = [](uintptr_t Start, uintptr_t Length) {
      auto rv = mprotect((void*)Start, Length, PROT_READ | PROT_WRITE);
      LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", Start, Length);
    };

#ifdef ARCHITECTURE_ppc64le
    // SMC store-emulation fast path: see block comment above HandleSegfault.
    // v1 restriction: private mappings only — a shared mapping's write is
    // visible through every mirror, so the overlap check would have to cover
    // all mirrored VAs; keep mirrors on the proven path for now.
    if (_SyscallHandler->SMCStoreEmulation() && !Entry->second.Flags.Shared) {
      DecodedStore Store;
      if (DecodePPCStore(ucontext, ArchHelpers::Context::GetPc(ucontext), &Store)) {
        // The decoded target must include the faulting address, or we decoded
        // an instruction whose fault this isn't (paranoia; mismatch => legacy).
        const bool CoversFault = FaultAddress >= Store.EA && FaultAddress < Store.EA + Store.Width;
        if (CoversFault && !Thread->CTX->GuestRangeOverlapsCompiledCode(Thread, Store.EA, Store.Width)) {
          const int fd = SelfMemFD();
          if (fd >= 0 && ::pwrite(fd, &Store.Value, Store.Width, static_cast<off_t>(Store.EA)) == static_cast<ssize_t>(Store.Width)) {
            if (Store.UpdateRA != ~0u) {
              ArchHelpers::Context::SetPPCGpReg(ucontext, Store.UpdateRA, Store.EA);
            }
            ArchHelpers::Context::SetPc(ucontext, ArchHelpers::Context::GetPc(ucontext) + 4);
            SMC_AUDIT("[%d] fault addr=%lx EMULATED-STORE ea=%lx w=%u\n", FHU::Syscalls::gettid(), FaultAddress, Store.EA, Store.Width);
            FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
            return true;
          }
        }
      }
    }
#endif // ARCHITECTURE_ppc64le

    if (Entry->second.Flags.Shared) {
      LOGMAN_THROW_A_FMT(Entry->second.Resource, "VMA tracking error");

      auto Offset = FaultBase - Entry->first + Entry->second.Offset;

      auto VMA = Entry->second.Resource->FirstVMA;
      LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

      // Flush all mirrors, remap the page writable as needed
      do {
        if (VMA->Offset <= Offset && (VMA->Offset + VMA->Length) > Offset) {
          auto FaultBaseMirrored = Offset - VMA->Offset + VMA->Base;

          if (VMA->Prot.Writable) {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
          } else {
            _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBaseMirrored, FEXCore::Utils::FEX_PAGE_SIZE);
          }
        }
      } while ((VMA = VMA->ResourceNextVMA));
    } else {
      _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    }

    SMC_AUDIT("[%d] fault addr=%lx INVALIDATED page=%lx shared=%d\n", FHU::Syscalls::gettid(), FaultAddress, FaultBase,
              Entry->second.Flags.Shared ? 1 : 0);

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);

    // Mirror of InvalidationTracker::HandleRWXAccessViolation's tail on Windows:
    // once the page has been invalidated and made writable again, see whether
    // this fault is the mono backpatcher announcing itself.
    _SyscallHandler->DetectMonoBackpatcherBlock(Thread, ArchHelpers::Context::GetPc(ucontext));

    auto CTX = Thread->CTX;
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext)) && !CTX->IsCurrentBlockSingleInst(Thread) &&
        CTX->IsAddressInCurrentBlock(Thread, FaultAddress & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE)) {
      // If we are not in a single-instruction block, and the SMC write address could intersect with the current block,
      // reconstruct the context and repeat the faulting instruction as a single-instruction block so any SMC it performs
      // is immediately picked up.
      ThreadObject->SignalInfo.Delegator->SpillSRA(Thread, ucontext, Thread->CurrentFrame->InSyscallInfo & 0xFFFF);

      // Adjust context to return to the dispatcher, reloading SRA from thread state
      const auto& Config = ThreadObject->SignalInfo.Delegator->GetConfig();
      ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
      ArchHelpers::Context::SetArmReg(ucontext, 1, 1); // Set ENTRY_FILL_SRA_SINGLE_INST_REG to force a single step
    }

    return true;
  }
}

void SyscallHandler::MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  const auto Base = Start & FEXCore::Utils::FEX_PAGE_MASK;
  const auto Top = FEXCore::AlignUp(Start + Length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    if (SMCChecks != FEXCore::Config::CONFIG_SMC_MTRACK) {
      return;
    }

    auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

    // Find the first mapping at or after the range ends, or ::end().
    // Top points to the address after the end of the range
    auto Mapping = VMATracking.VMAs.lower_bound(Top);

    if (SMCAuditFD() >= 0) {
      if (Mapping == VMATracking.VMAs.begin()) {
        SMC_AUDIT("[%d] mark CALL base=%lx AT-BEGIN\n", FHU::Syscalls::gettid(), Base);
      } else {
        auto Prev = std::prev(Mapping);
        SMC_AUDIT("[%d] mark CALL base=%lx prev-vma=%lx+%lx w=%d\n", FHU::Syscalls::gettid(), Base, Prev->first, Prev->second.Length,
                  Prev->second.Prot.Writable ? 1 : 0);
      }
    }

    while (Mapping != VMATracking.VMAs.begin()) {
      Mapping--;

      const auto MapBase = Mapping->first;
      const auto MapTop = MapBase + Mapping->second.Length;

      if (MapTop <= Base) {
        // Mapping ends before the Range start, exit
        break;
      } else {
        const auto ProtectBase = std::max(MapBase, Base);
        const auto ProtectSize = std::min(MapTop, Top) - ProtectBase;

        if (Mapping->second.Flags.Shared) {
          LOGMAN_THROW_A_FMT(Mapping->second.Resource, "VMA tracking error");

          const auto OffsetBase = ProtectBase - Mapping->first + Mapping->second.Offset;
          const auto OffsetTop = OffsetBase + ProtectSize;

          auto VMA = Mapping->second.Resource->FirstVMA;
          LOGMAN_THROW_A_FMT(VMA, "VMA tracking error");

          do {
            auto VMAOffsetBase = VMA->Offset;
            auto VMAOffsetTop = VMA->Offset + VMA->Length;
            auto VMABase = VMA->Base;

            if (VMA->Prot.Writable && VMAOffsetBase < OffsetTop && VMAOffsetTop > OffsetBase) {

              const auto MirroredBase = std::max(VMAOffsetBase, OffsetBase);
              const auto MirroredSize = std::min(OffsetTop, VMAOffsetTop) - MirroredBase;

              auto rv = mprotect((void*)(MirroredBase - VMAOffsetBase + VMABase), MirroredSize, PROT_READ);
              SMC_AUDIT("[%d] mark PROTECT-mirror addr=%lx size=%lx\n", FHU::Syscalls::gettid(),
                        MirroredBase - VMAOffsetBase + VMABase, MirroredSize);
              LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", MirroredBase, MirroredSize);
            }
          } while ((VMA = VMA->ResourceNextVMA));

        } else if (Mapping->second.Prot.Writable) {
          // Once the mono backpatcher hook is installed, writable+executable
          // mappings (mono's JIT arenas) are covered by MonoBackpatcherWrite and
          // per-instruction validation on tailcall sites instead of by faulting,
          // so leave them alone.  Everything else (W^X libraries, the loader)
          // keeps normal mtrack behaviour -- deliberately narrower than the
          // Windows version, which drops tracking for all RWX intervals.
          if (SMCDetectionDisabled.load(std::memory_order_relaxed) && Mapping->second.Prot.Executable) {
            SMC_AUDIT("[%d] mark SKIP-smcdisabled base=%lx size=%lx\n", FHU::Syscalls::gettid(), ProtectBase, ProtectSize);
            continue;
          }

          int rv = mprotect((void*)ProtectBase, ProtectSize, PROT_READ);

          SMC_AUDIT("[%d] mark PROTECT base=%lx size=%lx\n", FHU::Syscalls::gettid(), ProtectBase, ProtectSize);
          LogMan::Throw::AFmt(rv == 0, "mprotect({}, {}) failed", ProtectBase, ProtectSize);
        } else {
          SMC_AUDIT("[%d] mark SKIP base=%lx size=%lx shared=%d writable=%d\n", FHU::Syscalls::gettid(), ProtectBase, ProtectSize,
                    Mapping->second.Flags.Shared ? 1 : 0, Mapping->second.Prot.Writable ? 1 : 0);
        }
      }
    }
  }
}

void SyscallHandler::MaybeRecordMonoMapping(std::string_view Path, uint64_t Base, uint64_t End) {
  if (!IsMonoRuntimeLibraryPath(Path)) {
    return;
  }

  // Mapping the library is a stronger signal than merely opening it, so drive
  // the same detection from here.  No-op if openat already did it.
  MaybeDetectMonoFromPath(Path);

  // If the config gate rejected the hacks there is nothing to hook, so don't
  // track a range or arm the fault-path check.
  if (!MonoHacksActive.load(std::memory_order_acquire)) {
    return;
  }

  // Grow [MonoBase, MonoEnd) across the library's several PT_LOAD mappings.
  uint64_t OldBase = MonoBase.load(std::memory_order_relaxed);
  while (OldBase == 0 || Base < OldBase) {
    if (MonoBase.compare_exchange_weak(OldBase, Base, std::memory_order_relaxed)) {
      break;
    }
  }
  uint64_t OldEnd = MonoEnd.load(std::memory_order_relaxed);
  while (End > OldEnd) {
    if (MonoEnd.compare_exchange_weak(OldEnd, End, std::memory_order_relaxed)) {
      break;
    }
  }

  if (!MonoBackpatcherDetectionPending.exchange(true, std::memory_order_release)) {
    LogMan::Msg::IFmt("Mono runtime mapped at {:#x}-{:#x} ({}) — watching for the backpatcher block.", Base, End, Path);
  }
}

void SyscallHandler::DetectMonoBackpatcherBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  // Cheap relaxed gate: false for every process that isn't mono, and for every
  // fault after the backpatcher has been found.
  if (!MonoBackpatcherDetectionPending.load(std::memory_order_acquire)) {
    return;
  }

  auto CTX = Thread->CTX;
  if (!CTX->IsAddressInCodeBuffer(Thread, HostPC)) {
    return;
  }

  const uint64_t Base = MonoBase.load(std::memory_order_relaxed);
  const uint64_t End = MonoEnd.load(std::memory_order_relaxed);
  const uint64_t RIP = CTX->RestoreRIPFromHostPC(Thread, HostPC);
  if (!RIP || RIP < Base || RIP >= End) {
    return;
  }

  // The backpatcher's store is an XCHG (0x87).  Accept a one-byte prefix (REX,
  // operand-size) before it, exactly as the Windows side does.
  static constexpr uint8_t XChgOp = 0x87;
  if (*reinterpret_cast<uint8_t*>(RIP) != XChgOp && *reinterpret_cast<uint8_t*>(RIP + 1) != XChgOp) {
    return;
  }

  // Claim the one-shot.  A racing thread that also faulted on an XCHG loses here
  // and simply takes the normal SMC path for that one write.
  if (!MonoBackpatcherDetectionPending.exchange(false, std::memory_order_acq_rel)) {
    return;
  }

  const uint64_t BlockEntry = CTX->GetGuestBlockEntry(Thread);
  LogMan::Msg::IFmt("Detected mono backpatcher at {:#x} (faulting RIP {:#x}) — installing write hook, "
                    "disabling fault-based SMC detection for writable+executable mappings.",
                    BlockEntry, RIP);

  DisableSMCDetectionLocked(Thread);

  {
    std::scoped_lock CodeLock(CTX->GetCodeInvalidationMutex());
    CTX->MarkMonoBackpatcherBlock(BlockEntry);
  }

  // Drop the block so it recompiles with IsMonoBackpatcherBlock set (Core.cpp
  // keys the flag off the block entry RIP at BeginFunction time).
  TM.InvalidateGuestCodeRange(Thread, BlockEntry & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::Utils::FEX_PAGE_SIZE);
}

void SyscallHandler::DisableSMCDetectionLocked(FEXCore::Core::InternalThreadState* Thread) {
  if (SMCDetectionDisabled.exchange(true, std::memory_order_release)) {
    return;
  }

  // One-time sweep: anything we already write-protected that the guest asked to
  // be both writable and executable goes back to its requested protection.
  // NOTE: the caller holds VMATracking.Mutex (shared).  We only mprotect here;
  // the tracking structures record the guest's requested protection and are
  // unchanged by mtrack's write-protection, so there is nothing to mutate.
  size_t Restored = 0;
  for (const auto& [MapBase, Entry] : VMATracking.VMAs) {
    if (!Entry.Prot.Writable || !Entry.Prot.Executable) {
      continue;
    }

    const int Prot = (Entry.Prot.Readable ? PROT_READ : 0) | PROT_WRITE | PROT_EXEC;
    if (mprotect(reinterpret_cast<void*>(MapBase), Entry.Length, Prot) == 0) {
      ++Restored;
    } else {
      LogMan::Msg::EFmt("Mono: failed to restore protection on {:#x}-{:#x}: {}", MapBase, MapBase + Entry.Length, strerror(errno));
    }
  }
  LogMan::Msg::IFmt("Mono: restored write+exec protection on {} mapping(s).", Restored);
}

void SyscallHandler::InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  InvalidateCodeRangeIfNecessary(Thread, Start, Length);
}

static FEXCore::ExecutableFileSectionInfo BuildSectionInfo(const VMATracking::MappedResource& Resource, uint64_t Base, uint64_t Size) {
  return FEXCore::ExecutableFileSectionInfo {*Resource.MappedFile, Resource.FirstVMA->Base, Base, Base + Size};
}

std::optional<FEXCore::ExecutableFileSectionInfo>
SyscallHandler::LookupExecutableFileSection(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestAddr) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

  auto EntryIt = VMATracking.FindVMAEntry(GuestAddr);
  if (EntryIt == VMATracking.VMAs.end() || !EntryIt->second.Resource || !EntryIt->second.Resource->MappedFile) {
    return std::nullopt;
  }

  auto& [MappingBaseAddr, Entry] = *EntryIt;
  return BuildSectionInfo(*Entry.Resource, MappingBaseAddr, Entry.Length);
}

FEXCore::HLE::ExecutableRangeInfo SyscallHandler::QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
  auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);

  auto Entry = VMATracking.FindVMAEntry(Address);
  if (Entry == VMATracking.VMAs.end() ||
      (!Entry->second.Prot.Executable && (!(ThreadObject->persona & READ_IMPLIES_EXEC) || !Entry->second.Prot.Readable))) {
    return {0, 0, false};
  }
  return {Entry->first, Entry->second.Length, Entry->second.Prot.Writable};
}

struct ReadELFHeadersResult {
  fextl::vector<Elf64_Phdr> ProgramHeaders;
  fextl::robin_map<uint32_t, FEXCore::GuestRelocationType> Relocations;
  bool HasCodeRelocations;
};

static ReadELFHeadersResult ReadELFHeaders(int FD, std::span<std::byte> HeaderData = {}) {
  std::string_view ELFMagic = ELFMAG;
  if (HeaderData.data()) {
    if (HeaderData.size_bytes() < ELFMagic.size() || std::memcmp(ELFMagic.data(), HeaderData.data(), ELFMagic.size()) != 0) {
      // Not an ELF file
      return {};
    }
  } else {
    // Read from FD in case the caller didn't have a mapped header available
  }

  // Re-open the file with a fresh file descriptor (and let ELFParser close it on return).
  // NOTE: FDs returned by dup() share the same cursor state, so reading from them would have observable side effects.
  auto NewFD = open(fextl::fmt::format("/proc/self/fd/{}", FD).c_str(), O_RDONLY);

  ELFParser Parser;
  if (!Parser.ReadElf(NewFD)) {
    return {};
  }

  auto Relocations = Parser.PopulateRelocations();
  auto HasCodeRelocations = Parser.HasCodeRelocations();
  return ReadELFHeadersResult {std::move(Parser.phdrs), std::move(Relocations), HasCodeRelocations};
}

static void LoadCodeCache(FEXCore::Core::InternalThreadState& Thread, FEXCore::ExecutableFileSectionInfo& Section, uint64_t CodeCacheConfigId) {
  auto CacheFilename = fextl::fmt::format("{}cache/{}-{:016x}", FEX::Config::GetCacheDirectory(),
                                          FEXCore::CodeMap::GetBaseFilename(Section.FileInfo, false), CodeCacheConfigId);
  int CacheFD = open(CacheFilename.c_str(), O_RDONLY);
  if (CacheFD == -1) {
    LogMan::Msg::IFmt("Cache file does not exist: {}", CacheFilename);
    return;
  }

  struct stat buf;
  if (fstat(CacheFD, &buf) != 0) {
    LogMan::Msg::EFmt("Invalid cache file: {}", CacheFilename);
    close(CacheFD);
    return;
  }

  auto CacheFileSize = buf.st_size;
  auto MappedCache = (std::byte*)FEXCore::Allocator::mmap(nullptr, CacheFileSize, PROT_READ, MAP_PRIVATE, CacheFD, 0);
  LOGMAN_THROW_A_FMT(MappedCache, "Failed to map code cache into memory");
  // Pass the file length, not the page-rounded mapping length: LoadData bounds every
  // offset and count it parses out of the (untrusted) cache file against this, and the
  // bytes between the end of the file and the end of its last page are not file data.
  if (!Thread.CTX->GetCodeCache().LoadData(&Thread, MappedCache, static_cast<size_t>(CacheFileSize), Section)) {
    // The cache file was rejected. Delete it so the next run regenerates it: without this, a cache that
    // fails validation is silently ignored and then re-mapped and re-rejected on every single process
    // start, forever, permanently pinning the guest onto the JIT-compile path with no visible symptom.
    //
    // Deleting a file that another process is currently mmap'ing is safe on Linux. The mapping holds a
    // reference to the inode, so an existing MAP_PRIVATE mapping stays valid and readable after the
    // directory entry is gone; concurrent FEX starts keep working on the data they already mapped. If
    // two processes race to unlink the same path, one of them loses with ENOENT, which is not an error
    // condition here.
    LogMan::Msg::EFmt("Rejected invalid code cache, deleting it: {}", CacheFilename);
    if (unlink(CacheFilename.c_str()) != 0 && errno != ENOENT) {
      // Non-fatal: a read-only or permission-restricted cache directory just means we will re-reject
      // this same file on the next start. Falling back to JIT compilation is still correct.
      LogMan::Msg::EFmt("Failed to delete invalid code cache {}: {}", CacheFilename, strerror(errno));
    }
  }
  FEXCore::Allocator::munmap(MappedCache, CacheFileSize);
  close(CacheFD);
}

void* SyscallHandler::GuestMmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, int flags,
                                int fd, off_t offset) {
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  std::optional<LateApplyExtendedVolatileMetadata> LateMetadata = std::nullopt;

  std::optional<FEXCore::ExecutableFileSectionInfo> CachedSection;

  {
    // NOTE: Frontend calls this with a nullptr Thread during initialization, but
    //       providing this code with a valid Thread object earlier would allow
    //       us to be more optimal by using GuardSignalDeferringSection instead
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    bool Map32Bit = !Is64Bit || (flags & FEX::HLE::X86_64_MAP_32BIT);
    if (Map32Bit) {
      Result = (uint64_t)Get32BitAllocator()->Mmap((void*)addr, length, prot, flags, fd, offset);
      if (FEX::HLE::HasSyscallError(Result)) {
        return reinterpret_cast<void*>(Result);
      }
      LOGMAN_THROW_A_FMT(Is64Bit || (Result >> 32) == 0 || (Result >> 32) == 0xFFFFFFFF, "values must fit to 32 bits");
    } else {
      Result = reinterpret_cast<uint64_t>(::mmap(reinterpret_cast<void*>(addr), length, prot, flags, fd, offset));
      if (Result == ~0ULL) {
        return reinterpret_cast<void*>(-errno);
      }
    }

    SMC_AUDIT("[%d] guest-mmap addr=%lx len=%lx prot=%x flags=%x fd=%d\n", FHU::Syscalls::gettid(), Result, length, prot, flags, fd);
    LateMetadata = TrackMmap(Thread, Result, length, prot, flags, fd, offset, CachedSection);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Size);

  if (LateMetadata) {
    auto CodeInvalidationlk = FEXCore::GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->AddForceTSOInformation(LateMetadata->VolatileValidRanges, std::move(LateMetadata->VolatileInstructions));
  }

  if (EnableCodeCaching && CachedSection) {
    LoadCodeCache(*Thread, *CachedSection, CodeCacheConfigId);
  }

  return reinterpret_cast<void*>(Result);
}

uint64_t SyscallHandler::GuestMunmap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* addr, uint64_t length) {
  LOGMAN_THROW_A_FMT(Is64Bit || (reinterpret_cast<uintptr_t>(addr) >> 32) == 0, "values must fit to 32 bits: {}", fmt::ptr(addr));
  LOGMAN_THROW_A_FMT(Is64Bit || (length >> 32) == 0, "values must fit to 32 bits");

  uint64_t Result {};
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);

  {
    // Frontend calls this with nullptr Thread during initialization.
    // This is why `GuardSignalDeferringSectionWithFallback` is used here.
    // To be more optimal the frontend should provide this code with a valid Thread object earlier.
    auto lk = FEXCore::GuardSignalDeferringSectionWithFallback(VMATracking.Mutex, Thread);

    if (reinterpret_cast<uintptr_t>(addr) < 0x1'0000'0000ULL) {
      Result = Get32BitAllocator()->Munmap(addr, length);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    } else {
      Result = ::munmap(addr, length);
      if (Result == -1) {
        return -errno;
      }
    }
    TrackMunmap(Thread, addr, length);
  }
  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), Size);

  if (length) {
    auto CodeInvalidationlk = FEXCore::GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->RemoveForceTSOInformation(reinterpret_cast<uint64_t>(addr), length);
  }

  return Result;
}

uint64_t SyscallHandler::GuestMremap(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, void* old_address, size_t old_size,
                                     size_t new_size, int flags, void* new_address) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::mremap(old_address, old_size, new_size, flags, new_address));
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = reinterpret_cast<uint64_t>(Get32BitAllocator()->Mremap(old_address, old_size, new_size, flags, new_address));
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }
    TrackMremap(Thread, reinterpret_cast<uint64_t>(old_address), old_size, new_size, flags, Result);
  }

  InvalidateCodeRangeIfNecessaryOnRemap(Thread, reinterpret_cast<uint64_t>(old_address), Result, old_size, new_size);
  return Result;
}

int SyscallHandler::OpenCodeMapFile() {
  // Query from FEXServer whether this is the first instance of this executable; if it is, also enable code dumping!
  FEX_CONFIG_OPT(RootFSPath, ROOTFS);
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
  auto ProgramName = FEXCore::Config::Get(FEXCore::Config::CONFIG_APP_FILENAME);
  LOGMAN_THROW_A_FMT(ProgramName && ProgramName.value()->c_str()[0] == '/', "");

  // Check RootFS first, then the plain path
  auto ProgramFD = open((RootFSPath() + ProgramName.value()->c_str()).c_str(), O_RDONLY);
  if (ProgramFD == -1) {
    ProgramFD = open(ProgramName.value()->c_str(), O_RDONLY);
  }
  if (ProgramFD == -1) {
    return -1;
  }

  int CodeMapFD = FEXServerClient::RequestCodeMapFD(FEXServerClient::GetServerFD(), ProgramFD, Multiblock);
  close(ProgramFD);
  if (CodeMapFD == -1) {
    return -1;
  }

  // Acquire exclusive lock to prevent FEXServer from processing this file eagerly
  [[maybe_unused]] auto ret = flock(CodeMapFD, LOCK_EX);
  LOGMAN_THROW_A_FMT(ret == 0, "Could not lock code map");

  FM.SetProtectedCodeMapFD(CodeMapFD);

  // Ensure the file descriptor is closed on exec
  auto flags = fcntl(CodeMapFD, F_GETFD);
  fcntl(CodeMapFD, F_SETFD, flags | FD_CLOEXEC);
  return CodeMapFD;
}

uint64_t SyscallHandler::GuestMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Result {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    Result = ::mprotect(addr, len, prot);
    if (Result == -1) {
      return -errno;
    }

    SMC_AUDIT("[%d] guest-mprotect addr=%lx len=%lx prot=%x\n", FHU::Syscalls::gettid(), reinterpret_cast<uint64_t>(addr), len, prot);
    TrackMprotect(Thread, addr, len, prot);
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), len);

  // Prepare for delayed code cache load after ld/Wine is done applying relocations.
  // Hooking into mprotect is a reliable heuristic that matches behavior of ld (for ELF) and Wine (for PE).
  // False-positives are avoided by setting RequiresDelayedCacheLoad in TrackMmap only for
  // binaries that we know will go through this path.
  fextl::vector<FEXCore::ExecutableFileSectionInfo> CachedSections;
  if (EnableCodeCaching && (prot & PROT_EXEC) && (prot & PROT_WRITE) == 0) {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);

    auto VMAEntry = VMATracking.FindVMAEntry(reinterpret_cast<uint64_t>(addr));
    auto Resource = VMAEntry != VMATracking.VMAs.end() ? VMAEntry->second.Resource : nullptr;
    if (Resource && Resource->MappedFile && Resource->RequiresDelayedCacheLoad) {
      Resource->RequiresDelayedCacheLoad = false;
      LogMan::Msg::IFmt("Triggering delayed cache load for {} after mprotect of {:#x}-{:#x}", Resource->MappedFile->Filename,
                        VMAEntry->first, VMAEntry->first + VMAEntry->second.Length);

      for (auto VMA = Resource->FirstVMA; VMA; VMA = VMA->ResourceNextVMA) {
        CachedSections.push_back(BuildSectionInfo(*Resource, VMA->Base, VMA->Length));
      }
    }
  }

  // Trigger delayed cache load. This must be done separately since
  // LoadCodeCache will call interfaces that acquire the VMATracking mutex.
  for (auto& CachedSection : CachedSections) {
    LoadCodeCache(*Thread, CachedSection, CodeCacheConfigId);
  }

  return Result;
}

uint64_t SyscallHandler::GuestShmat(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, int shmid, const void* shmaddr, int shmflg) {
  uint64_t Result {};
  uint64_t Length {};

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = reinterpret_cast<uint64_t>(::shmat(shmid, shmaddr, shmflg));
      if (Result == -1) {
        return -errno;
      }
    } else {
      uint32_t Addr;
      Result = Get32BitAllocator()->Shmat(shmid, shmaddr, shmflg, &Addr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
      Result = Addr;
    }

    shmid_ds stat;

    auto res = shmctl(shmid, IPC_STAT, &stat);
    LOGMAN_THROW_A_FMT(res != -1, "shmctl IPC_STAT failed");

    Length = stat.shm_segsz;
    TrackShmat(Thread, shmid, Result, shmflg, Length);
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Length);
  return Result;
}

uint64_t SyscallHandler::GuestShmdt(bool Is64Bit, FEXCore::Core::InternalThreadState* Thread, const void* shmaddr) {
  uint64_t Result {};
  uint64_t Length {};
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    if (Is64Bit) {
      Result = ::shmdt(shmaddr);
      if (Result == -1) {
        return -errno;
      }
    } else {
      Result = Get32BitAllocator()->Shmdt(shmaddr);
      if (FEX::HLE::HasSyscallError(Result)) {
        return Result;
      }
    }

    Length = TrackShmdt(Thread, reinterpret_cast<uintptr_t>(shmaddr));
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uintptr_t>(shmaddr), Length);
  return Result;
}

// MMan Tracking
std::optional<SyscallHandler::LateApplyExtendedVolatileMetadata>
SyscallHandler::TrackMmap(FEXCore::Core::InternalThreadState* Thread, uint64_t addr, size_t length, int prot, int flags, int fd,
                          off_t offset, std::optional<FEXCore::ExecutableFileSectionInfo>& CachedSection) {
  size_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  const auto ProtMapping = VMATracking::VMAProt::fromProt(prot);

  VMATracking::MappedResource* Resource = nullptr;

  std::optional<SyscallHandler::LateApplyExtendedVolatileMetadata> VolatileMetadata = std::nullopt;

  if (!(flags & MAP_ANONYMOUS)) {
    struct stat64 buf;
    fstat64(fd, &buf);

    const VMATracking::MRID mrid {buf.st_dev, buf.st_ino};

    char Tmp[PATH_MAX];
    auto PathLength = FEX::get_fdpath(fd, Tmp);

    auto [ResourceIt, ResourceEnd] = VMATracking.FindResources(mrid);
    bool Inserted = false;
    const bool MappedELFHeaderAgain = ResourceIt != ResourceEnd && offset == 0 && !ResourceIt->second.ProgramHeaders.empty();
    if (ResourceIt == ResourceEnd || MappedELFHeaderAgain) {
      // Create a new MappedResource for previously unseen file and for re-mappings of an ELF header
      ResourceIt = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
      ResourceIt->second.Iterator = ResourceIt;
      Inserted = true;
    }
    Resource = &ResourceIt->second;

    // Record the mono runtime's code range for the backpatcher hook.  This is
    // the Linux stand-in for the PE-module-load path Windows uses, and it is a
    // stronger signal than the openat-based detection in MaybeDetectMonoFromPath
    // because it also gives us [MonoBase, MonoEnd).
    if (PathLength != -1 && ProtMapping.Executable) {
      MaybeRecordMonoMapping(std::string_view(Tmp, PathLength), addr, addr + Size);
    }

    // Only handle FDs that are backed by regular files that are executable
    if (PathLength != -1 && S_ISREG(buf.st_mode) && (buf.st_mode & S_IXUSR)) {
      // ELF files that are mapped multiple times get a separate MappedResource for each base virtual address
      if ((prot & PROT_READ) && Inserted) {
        Resource->MappedFile = fextl::make_unique<FEXCore::ExecutableFileInfo>();
        Resource->MappedFile->Filename = fextl::string(Tmp, PathLength);
        Resource->MappedFile->FileId = CTX->GetCodeCache().ComputeCodeMapId(Resource->MappedFile->Filename, fd);

        // Read ELF headers if applicable and needed for code caching.
        // For performance, skip ELF checks if we're not mapping the file header
        bool CheckForElfFile = (offset == 0) && EnableCodeCaching;
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
        CheckForElfFile = true;
#endif
        if (CheckForElfFile) {
          auto ELFResult = ReadELFHeaders(fd, std::span {reinterpret_cast<std::byte*>(addr), length});
          Resource->ProgramHeaders = std::move(ELFResult.ProgramHeaders);
          Resource->MappedFile->Relocations = std::move(ELFResult.Relocations);
          Resource->RequiresDelayedCacheLoad = ELFResult.HasCodeRelocations;

          // GuestRelocationType::Skip indicates to FEXOfflineCompiler that
          // any blocks covered by the relocation may not be cached.
          // At runtime, we can safely drop these relocations.
          for (auto it = Resource->MappedFile->Relocations.begin(); it != Resource->MappedFile->Relocations.end();) {
            if (it->second == FEXCore::GuestRelocationType::Skip) {
              it = Resource->MappedFile->Relocations.erase(it);
            } else {
              ++it;
            }
          }

          LOGMAN_THROW_A_FMT(Resource->ProgramHeaders.empty() || offset == 0, "Expected file offset 0 for the first mapping of an ELF "
                                                                              "file");
        }
      } else if (ResourceIt->second.ProgramHeaders.empty()) {
        // Not an ELF file, so we don't need to distinguish between different base addresses
      } else {
        // Mapped a non-header section of an ELF file.
        // Look up the corresponding MappedResource using the expected base address.

        ResourceIt = std::find_if(ResourceIt, ResourceEnd, [&](const VMATracking::MappedResource::ContainerType::value_type& ResourcePair) {
          auto& Resource = ResourcePair.second;
          auto ExpectedBases = FEXCore::InferMappingBaseAddress(
            Resource.ProgramHeaders, addr, Size, offset,
            (ProtMapping.Executable ? PF_X : 0) | (ProtMapping.Writable ? PF_W : 0) | (ProtMapping.Readable ? PF_R : 0));
          return std::ranges::find(ExpectedBases, Resource.FirstVMA->Base) != ExpectedBases.end();
        });
        if (ResourceIt == ResourceEnd) {
          // This isn't necessarily a fatal exception. It just means the ELF section isn't a part of the ELF Program headers.
          // Node.js hits this as it maps a section of itself that isn't a part of the program headers.
          LogMan::Msg::IFmt("Warning: Could not find base for file mapping at {:#x} (offset {:#x}): {}", addr, offset,
                            std::string_view(Tmp, PathLength));
        } else {
          Resource = &ResourceIt->second;
        }
      }

      if (Resource->MappedFile) {
        const fextl::string Filename = FHU::Filesystem::GetFilename(Resource->MappedFile->Filename);

        // We now have the filename and the offset in the filename getting mapped.
        // Check for extended volatile metadata.
        auto it = ExtendedMetaData.find(Filename);
        if (it != ExtendedMetaData.end()) {
          SyscallHandler::LateApplyExtendedVolatileMetadata LateMetadata;
          FEX::VolatileMetadata::ApplyFEXExtendedVolatileMetadata(
            it->second, LateMetadata.VolatileInstructions, LateMetadata.VolatileValidRanges, addr, addr + length, offset, offset + length);

          if (!LateMetadata.VolatileInstructions.empty() || !LateMetadata.VolatileValidRanges.Empty()) {
            VolatileMetadata.emplace(std::move(LateMetadata));
          }
        }
      }
    }
  } else if (flags & MAP_SHARED) {
    VMATracking::MRID mrid {VMATracking::SpecialDev::Anon, AnonSharedId++};

    auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
    LOGMAN_THROW_A_FMT(Iter == IterEnd, "VMA tracking error");

    Iter = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, 0, {}, {}});
    Resource = &Iter->second;
    Resource->Iterator = Iter;
  }

  VMATracking.TrackVMARange(CTX, Resource, addr, offset, Size, VMATracking::VMAFlags::fromFlags(flags), VMATracking::VMAProt::fromProt(prot));

  // Load code cache if present.
  // FEXServer was requested to generate library caches on program launch.
  if (EnableCodeCaching && Resource && Resource->MappedFile && VMATracking::VMAProt::fromProt(prot).Executable) {
    if (Thread) {
      if (!Resource->RequiresDelayedCacheLoad) {
        CachedSection.emplace(BuildSectionInfo(*Resource, addr, Size));
      } else {
        LogMan::Msg::IFmt("Delaying code cache load for {} until mprotect {:#x}-{:#x}", Resource->MappedFile->Filename, addr, addr + Size);
      }
    } else {
      // Cache can't be loaded with a thread; skip this for now
      LogMan::Msg::DFmt("Oops, tried caching without a thread: {}", Resource->MappedFile->Filename);
    }
  }

  return VolatileMetadata;
}

void SyscallHandler::TrackMunmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length) {
  uint64_t Size = FEXCore::AlignUp(length, FEXCore::Utils::FEX_PAGE_SIZE);
  VMATracking.DeleteVMARange(CTX, reinterpret_cast<uintptr_t>(addr), Size);
}

void SyscallHandler::TrackMprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t len, int prot) {
  uint64_t Size = FEXCore::AlignUp(len, FEXCore::Utils::FEX_PAGE_SIZE);

  VMATracking.ChangeProtectionFlags(reinterpret_cast<uintptr_t>(addr), Size, VMATracking::VMAProt::fromProt(prot));
}

void SyscallHandler::TrackMremap(FEXCore::Core::InternalThreadState* Thread, uint64_t OldAddress, size_t OldSize, size_t NewSize, int flags,
                                 uint64_t NewAddress) {
  OldSize = FEXCore::AlignUp(OldSize, FEXCore::Utils::FEX_PAGE_SIZE);
  NewSize = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE);

  const auto OldVMA = VMATracking.FindVMAEntry(OldAddress);

  const auto OldResource = OldVMA->second.Resource;
  const auto OldOffset = OldVMA->second.Offset + OldAddress - OldVMA->first;
  const auto OldFlags = OldVMA->second.Flags;
  const auto OldProt = OldVMA->second.Prot;

  LOGMAN_THROW_A_FMT(OldVMA != VMATracking.VMAs.end(), "VMA Tracking corruption");

  if (OldSize == 0) {
    // Mirror existing mapping
    // must be a shared mapping
    LOGMAN_THROW_A_FMT(OldResource != nullptr, "VMA Tracking error");
    LOGMAN_THROW_A_FMT(OldFlags.Shared, "VMA Tracking error");
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  } else {

#ifndef MREMAP_DONTUNMAP
// MREMAP_DONTUNMAP is kernel 5.7+ and might not exist
#define MREMAP_DONTUNMAP 4
#endif
    if (!(flags & MREMAP_DONTUNMAP)) {
      VMATracking.DeleteVMARange(CTX, OldAddress, OldSize, OldResource);
    }

    // Make anonymous mapping
    VMATracking.TrackVMARange(CTX, OldResource, NewAddress, OldOffset, NewSize, OldFlags, OldProt);
  }
}

void SyscallHandler::TrackShmat(FEXCore::Core::InternalThreadState* Thread, int shmid, uint64_t shmaddr, int shmflg, uint64_t Length) {
  VMATracking::MRID mrid {VMATracking::SpecialDev::SHM, static_cast<uint64_t>(shmid)};

  auto [Iter, IterEnd] = VMATracking.FindResources(mrid);
  if (Iter == IterEnd) {
    Iter = VMATracking.InsertMappedResource(mrid, VMATracking::MappedResource {nullptr, nullptr, Length, {}, {}});
    Iter->second.Iterator = Iter;
  }
  auto Resource = &Iter->second;
  VMATracking.TrackVMARange(CTX, Resource, shmaddr, 0, Length, VMATracking::VMAFlags::fromFlags(MAP_SHARED), VMATracking::VMAProt::fromSHM(shmflg));
}

uint64_t SyscallHandler::TrackShmdt(FEXCore::Core::InternalThreadState* Thread, uint64_t shmaddr) {
  return VMATracking.DeleteSHMRegion(CTX, reinterpret_cast<uintptr_t>(shmaddr));
}

void SyscallHandler::TrackMadvise(FEXCore::Core::InternalThreadState* Thread, uintptr_t Base, uintptr_t Size, int advice) {
  Size = FEXCore::AlignUp(Size, FEXCore::Utils::FEX_PAGE_SIZE);
  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    // TODO
  }
}

} // namespace FEX::HLE
