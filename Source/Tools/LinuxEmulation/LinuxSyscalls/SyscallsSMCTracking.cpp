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

#include "LinuxSyscalls/SMCStoreBackpatch.h"
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
    // Reset REG_CALLRET_SP to the default location to allow for underflows/overflows.
    // ARM64 REG_CALLRET_SP is X25; the register-index literal 25 is ARM-specific and
    // was compiling on every architecture, silently writing an unrelated host GPR on
    // ppc64le (id=25 → gp_regs[28] → pinned r28). Arch-guard the assignment.
#if defined(ARCHITECTURE_arm64)
    ArchHelpers::Context::SetArmReg(ucontext, 25, CallRetStackInfo.DefaultLocation);
#elif defined(ARCHITECTURE_ppc64le)
    // No REG_CALLRET_SP on ppc64le yet; the JIT does not push/pop callret_sp,
    // so the guard-page range is dead today. When the shadow return stack lands
    // and a ppc64le REG_CALLRET_SP is assigned, write it here via gp_regs.
#endif
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
#ifdef ARCHITECTURE_ppc64le
      // FEX_SMCSTOREBACKPATCH: the page is writable again, so an already-
      // backpatched store site targeting it can go back to storing natively.
      FEX::HLE::SMCBackpatch::NotePagesUnprotected(Start, Length);
#endif
    };

#ifdef ARCHITECTURE_ppc64le
    // SMC store-emulation fast path: see block comment above HandleSegfault.
    // v1 restriction: private mappings only — a shared mapping's write is
    // visible through every mirror, so the overlap check would have to cover
    // all mirrored VAs; keep mirrors on the proven path for now.
    //
    // Every way out of this block emits exactly one FEX_SMC_AUDIT line tagged
    // with the reason it declined, plus the faulting address, the decoded
    // effective address/width where known, and the raw host instruction word.
    // The CP2077 histogram showed this fast path firing 0 times with no
    // recorded reason; without per-reason attribution there is no way to tell
    // "the overlap test is too coarse" (fixable, Idea 3) from "the store form
    // isn't decoded" (fixable, widen the decoder) from "these are all shared
    // mappings" (out of scope for v1).
    // SMC Idea 4 (FEX_SMCSEMANTICPATCH) shares this decode and this store
    // emulation, but applies where v1 gives up: when the written bytes DO
    // overlap compiled code and are exactly the rel32 field of a direct branch.
    // It repatches the destination RIP baked into every affected block's
    // translated exit and then lets the store through with the page still
    // protected -- no invalidation, no recompile. Independent flag: either
    // option alone enables its own half of the "emulate the store" outcome.
    // See FEXCore/Source/Interface/Core/SMCSemanticPatch.h.
    if (_SyscallHandler->SMCStoreEmulation() || _SyscallHandler->SMCSemanticPatch()) {
      const uint64_t StorePC = ArchHelpers::Context::GetPc(ucontext);
      const uint32_t RawInsn = *reinterpret_cast<const uint32_t*>(StorePC);
      DecodedStore Store {};

      // Tag, then decoded EA/width (0/0 when we never got that far).
      const auto Fallback = [&](const char* Reason, uint64_t EA, uint32_t Width) {
        SMC_AUDIT("[%d] fault addr=%lx SMC-FALLBACK reason=%s ea=%lx w=%u insn=%08x\n", FHU::Syscalls::gettid(), FaultAddress, Reason, EA,
                  Width, RawInsn);
      };

      // Set when the overlap test says "this is a write into live code" and the
      // semantic patcher then successfully rewrote the translated exits; the
      // store emulation below is then the completion of that patch rather than
      // the false-sharing fast path.
      bool SemanticPatched = false;
      // Which shape it recognised, for per-shape attribution in the trace:
      // "rel32", "movimm" or "mixed".
      const char* SemanticPatchKind = "unknown";

      // Decide the overlap/patch question once, so it can be expressed inside
      // the existing else-if chain without evaluating it twice.
      const auto OverlapDeclines = [&]() -> bool {
        // SMC Idea 3: same substitution as the backpatch helper -- the overlap
        // query is front-ended by the lock-free code-granule bitmap inside
        // LookupCache::RangeOverlapsCompiledCode, which can only answer
        // "provably no code here"; every other answer falls through to the
        // original locked CodePages/BlockList walk unchanged. See
        // FEXCore/Source/Interface/Core/SMCCodeGranules.h.
        if (!Thread->CTX->GuestRangeOverlapsCompiledCode(Thread, Store.EA, Store.Width)) {
          // Pure false sharing: v1's case. Only SMCStoreEmulation may take it.
          if (_SyscallHandler->SMCStoreEmulation()) {
            return false;
          }
          Fallback("storeemulation-off", Store.EA, Store.Width);
          return true;
        }

        if (!_SyscallHandler->SMCSemanticPatch()) {
          Fallback("overlaps-code", Store.EA, Store.Width);
          return true;
        }

        // The bytes this store is about to write, in guest order. Store.Value
        // is the source register; only the low Width bytes are written, and
        // ppc64le is little-endian so they are already in place.
        uint8_t NewBytes[8];
        ::memcpy(NewBytes, &Store.Value, sizeof(NewBytes));

        const char* PatchReason = "unknown";
        if (!_SyscallHandler->TM.SemanticPatchGuestCodeRange(Store.EA, Store.Width, NewBytes, &PatchReason)) {
          SMC_AUDIT("[%d] fault addr=%lx SEMPATCH-DECLINE reason=%s ea=%lx w=%u insn=%08x\n", FHU::Syscalls::gettid(), FaultAddress,
                    PatchReason, Store.EA, Store.Width, RawInsn);
          Fallback("overlaps-code", Store.EA, Store.Width);
          return true;
        }

        SemanticPatched = true;
        SemanticPatchKind = PatchReason;
        return false;
      };

      if (Entry->second.Flags.Shared) {
        Fallback("shared-mapping", 0, 0);
      } else if (!DecodePPCStore(ucontext, StorePC, &Store)) {
        // Not a plain GPR store: VSX/VMX, byte-reversed, store-conditional,
        // dcbz, stq, or an update form with RA==0.
        Fallback("decode-fail", 0, 0);
      } else if (!(FaultAddress >= Store.EA && FaultAddress < Store.EA + Store.Width)) {
        // The decoded target must include the faulting address, or we decoded
        // an instruction whose fault this isn't (paranoia; mismatch => legacy).
        Fallback("fault-outside-store", Store.EA, Store.Width);
      } else if (OverlapDeclines()) {
        // Audit line already emitted by the lambda.
      } else if (SelfMemFD() < 0) {
        Fallback("selfmem-open-fail", Store.EA, Store.Width);
      } else if (::pwrite(SelfMemFD(), &Store.Value, Store.Width, static_cast<off_t>(Store.EA)) != static_cast<ssize_t>(Store.Width)) {
        Fallback("pwrite-fail", Store.EA, Store.Width);
      } else {
        // FEX_SMCSTOREBACKPATCH: this one-shot emulation is correct but costs
        // a full signal round trip (~17us of the ~22us storm cycle, measured
        // on op4k at f01128c0d).  Rewrite the store site so the NEXT execution
        // never traps.  A refusal is not an error: the site simply stays
        // faulting and keeps taking this path, exactly as it does today.
        // Either way the current store is emulated below.
        //
        // Not when this fault was serviced as a semantic patch: that site's
        // writes hit live code on a page that deliberately stays protected, so
        // a stub would just fault again from inside itself on every later
        // patch — strictly worse than faulting here directly. A site that
        // mixes false-sharing and imm-field writes still gets backpatched the
        // first time it faults as false sharing.
        if (!SemanticPatched && _SyscallHandler->SMCStoreBackpatch()) {
          bool QuietRefusal = false;
          const char* Reason = FEX::HLE::SMCBackpatch::TryBackpatchStore(Thread, StorePC, &QuietRefusal);
          if (Reason && !QuietRefusal) {
            SMC_AUDIT("[%d] fault addr=%lx BACKPATCH-REFUSED reason=%s pc=%lx insn=%08x\n", FHU::Syscalls::gettid(), FaultAddress,
                      Reason, StorePC, RawInsn);
          }
        }

        if (Store.UpdateRA != ~0u) {
          ArchHelpers::Context::SetPPCGpReg(ucontext, Store.UpdateRA, Store.EA);
        }
        ArchHelpers::Context::SetPc(ucontext, StorePC + 4);
        if (SemanticPatched) {
          SMC_AUDIT("[%d] fault addr=%lx SEMANTIC-PATCH kind=%s ea=%lx w=%u\n", FHU::Syscalls::gettid(), FaultAddress, SemanticPatchKind,
                    Store.EA, Store.Width);
        } else {
          SMC_AUDIT("[%d] fault addr=%lx EMULATED-STORE ea=%lx w=%u\n", FHU::Syscalls::gettid(), FaultAddress, Store.EA, Store.Width);
        }
        FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSMCCount, 1);
        return true;
      }
    }
#endif // ARCHITECTURE_ppc64le

    // FEX_SMCLAZYINVAL: set when this fault was answered by recording the page
    // instead of invalidating it. Nothing was invalidated, so nothing may
    // pretend a pending invalidation debt has been settled below.
    bool LazyDeferred = false;

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
    } else if (_SyscallHandler->SMCLazyInvalActive()) {
      // FEX_SMCLAZYINVAL: unprotect and record, invalidate NOTHING. The writer
      // returns to native speed immediately; the page's blocks stay live (and
      // therefore possibly stale) in every lookup structure until a drain
      // point soft-invalidates them. This is the deliberately unsound path --
      // see LinuxSyscalls/SMCLazyInvalidate.h for exactly what is being traded.
      //
      // Record BEFORE unprotecting, never after: with the reverse order a
      // concurrent drain could run in between, leaving the page unprotected
      // *and* unrecorded, i.e. permanently writable with live translations on
      // it and nothing left to ever invalidate them. In this order the worst
      // interleaving is a drain that soft-invalidates the page just before we
      // unprotect it, which merely re-arms protection at the next
      // compile/relink through MarkGuestExecutableRange -- sound.
      const bool FirstThisEpoch = _SyscallHandler->MarkSMCLazyDirtyPage(FaultBase);
      UnprotectRegionCallback(FaultBase, FEXCore::Utils::FEX_PAGE_SIZE);
      LazyDeferred = true;

      // FEX_SMCLAZYSCRUB (default on): make the deferral sound for THIS thread.
      // x86 only guarantees SMC coherence to the modifying processor, so it is
      // enough to guarantee that the thread which just dirtied this page cannot
      // reach any cached translation again without draining first. Zeroing its
      // L1 forces its very next dispatch -- inlined block-exit probe or
      // dispatcher probe alike -- into PPC64JITCore::ExitFunctionLink, which
      // drains before it looks at the shared L2/L3. Other threads keep their
      // caches and their speedup, and stay exactly as (un)sound as x86 already
      // allows for cross-modifying code.
      //
      // Deliberately AFTER the record + unprotect: the scrub only has to be in
      // place before this handler returns, and doing it last keeps the ordering
      // argument above (record-before-unprotect) intact and unentangled.
      if (_SyscallHandler->SMCLazyScrubActive()) {
        Thread->CTX->ScrubThreadLookupCacheForLazySMC(Thread);
      }

      if (FirstThisEpoch) {
        SMC_AUDIT("[%d] fault addr=%lx LAZY-UNPROTECT page=%lx\n", FHU::Syscalls::gettid(), FaultAddress, FaultBase);
      }
    } else if (_SyscallHandler->SMCSoftInvalidate()) {
      // SMC v3: delink the page's blocks but keep their code and content
      // hashes, then unprotect exactly as legacy does. The delink completes
      // here, inside the handler, before the faulting store is retried -- that
      // is what makes same-thread patch-then-call safe. See
      // FEXCore/Source/Interface/Core/SMCSoftInvalidate.h.
      // Restricted to private mappings for the same reason as the v1 fast path
      // above: a shared mapping's blocks live under several mirrored VAs and
      // the mirror walk stays on the proven legacy path.
      _SyscallHandler->TM.SoftInvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    } else {
      _SyscallHandler->TM.InvalidateGuestCodeRange(Thread, FaultBase, FEXCore::Utils::FEX_PAGE_SIZE, UnprotectRegionCallback);
    }

    const char* FaultOutcome = "INVALIDATED";
    if (LazyDeferred) {
      FaultOutcome = "LAZY-DEFERRED";
    } else if (!Entry->second.Flags.Shared && _SyscallHandler->SMCSoftInvalidate()) {
      FaultOutcome = "SOFT-INVALIDATED";
    }
    SMC_AUDIT("[%d] fault addr=%lx %s page=%lx shared=%d\n", FHU::Syscalls::gettid(), FaultAddress, FaultOutcome, FaultBase,
              Entry->second.Flags.Shared ? 1 : 0);

    // FEX_SMCMPROTECTDEFER: a deferred-dirty page can still fault here if a
    // block was compiled on it afterwards and MarkGuestExecutableRange
    // re-installed read-only tracking.  The invalidation just above settles the
    // deferred debt, so drop the record instead of paying for it again at the
    // next PROT_EXEC.  (Cheap: the atomic count short-circuits when no page is
    // deferred, which is every fault in a run with the option off.)
    //
    // Not when FEX_SMCLAZYINVAL took the fault: nothing was invalidated, so the
    // W^X deferral is still owed and must survive to its PROT_EXEC.
    if (!LazyDeferred && _SyscallHandler->SMCMprotectDeferActive()) {
      _SyscallHandler->ClearSMCDeferredDirtyRange(FaultBase, FaultBase + FEXCore::Utils::FEX_PAGE_SIZE);
    }

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

// FEX_SMCFILEIMMUTABLE — treat file-backed code as immutable
// ---------------------------------------------------------------------------
// Relaxed correctness for speed.  Opt-in, off by default, and only meaningful
// with SMCChecks=mtrack (Syscalls.cpp logs and ignores it otherwise).
//
// Every page a block was compiled from gets write-protected below so that a
// later guest write faults and invalidates the block.  For a PRIVATE
// FILE-BACKED mapping -- Wine DLLs, libc, the game executable's .text -- that
// protection is nearly pure waste: the mapping is written at load time
// (relocations, CoW) and essentially never again, while data that merely
// shares a page with code keeps faulting forever (the smcstorm "falseshare"
// class).  With this option on, such pages are skipped: no mprotect, no fault,
// no invalidation, no re-protect.
//
// (3) Startup relocations are unaffected in both directions: protection is
// only ever installed HERE, at compile time, and ld.so/Wine write their CoW
// pages before any code is compiled from them.  There is nothing installed for
// their writes to trip over with the option off, and nothing skipped with it
// on.
//
// What still invalidates -- the guest cannot silently retire or repoint a
// skipped page, because these are unconditional (SMCChecks != none):
//   - guest mmap over the range:  GuestMmap     -> InvalidateCodeRangeIfNecessary
//   - guest munmap:               GuestMunmap   -> InvalidateCodeRangeIfNecessary
//   - guest mprotect:             GuestMprotect -> InvalidateCodeRangeIfNecessary
//   - guest mremap:               GuestMremap   -> InvalidateCodeRangeIfNecessaryOnRemap
// (all in this file; InvalidateCodeRangeIfNecessary itself is a no-op only for
// SMCChecks=none, where nothing was tracked to begin with)
// So the only detection actually given up is a genuine in-place SMC write to a
// file-backed page:
//
//   (2a) the mapping is not writable.  This case costs nothing: the guest's own
//        store faults, HandleSegfault above sees !Prot.Writable, returns false,
//        and the signal is forwarded to the guest as SIGSEGV exactly as today.
//        Note that mtrack never installed anything for a non-writable mapping
//        in the first place (the `else` SKIP branch below), so for this class
//        the option changes nothing at all -- its only reachable effect is on
//        WRITABLE private file-backed mappings, which is where Wine's PE images
//        and any RWX file mapping live.
//   (2b) the guest later mprotects the mapping writable and patches it.  This is
//        the case that keeps the option "mostly correct" rather than unsound,
//        and it is handled in GuestMprotect: an mprotect that adds PROT_WRITE to
//        a range we skipped revokes the assumption for the whole MappedResource
//        (sticky) and forces the invalidation, even if FEX_SMCMPROTECTDEFER
//        would otherwise have deferred it.  Chosen over "install the protection
//        at mprotect time" because after revocation the mapping is back on the
//        ordinary mtrack path, so the very next compile on it installs the
//        protection through the normal call below -- same end state, without
//        mprotecting pages whose blocks this same syscall is about to discard,
//        and without having to reason about a protection installed against the
//        protection the guest just asked for.
//
// WATCH LIST -- known breakage class: in-place code patching of file-backed
// .text through a mapping that is ALREADY writable when the patch happens (some
// DRM/packers, some Mono AOT fixups, anything that keeps its own .text RWX and
// rewrites it).  No mprotect is involved, so nothing re-arms and the stale
// translation survives.  That is the price of the option, which is why it is
// opt-in per application.
//
// AUDIT (FEX_SMC_AUDIT): one `mark SKIP-fileimmutable` line per skipped
// protection with the page range, the backing path when it is already known,
// and a running skipped-page total; plus `fileimmutable REARM` from GuestMprotect
// when case 2b fires.
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
#ifdef ARCHITECTURE_ppc64le
              FEX::HLE::SMCBackpatch::NotePagesProtected(MirroredBase - VMAOffsetBase + VMABase, MirroredSize);
#endif
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

          // FEX_SMCFILEIMMUTABLE: see the block comment above this function.
          // File-backed-ness comes straight out of VMA tracking: TrackMmap
          // attaches a MappedResource to every non-MAP_ANONYMOUS mapping and to
          // anonymous MAP_SHARED / SysV shm, and only to those, so within this
          // branch -- which is already the !Flags.Shared side of the split --
          // `Resource != nullptr` is exactly "private file-backed".  Anonymous
          // private memory (JIT arenas, the heap, the class of pages the CP2077
          // histogram is made of) has Resource == nullptr and keeps full mtrack
          // behaviour.  Anything undeterminable therefore fails closed onto the
          // mprotect below.
          if (SMCFileImmutableActive() && Mapping->second.Resource != nullptr && !Mapping->second.Resource->SMCFileImmutableRevoked) {
            const uint64_t Total = MarkSMCImmutableSkippedRange(ProtectBase, ProtectBase + ProtectSize);
            if (SMCAuditFD() >= 0) {
              const auto* MappedFile = Mapping->second.Resource->MappedFile.get();
              SMC_AUDIT("[%d] mark SKIP-fileimmutable base=%lx size=%lx total-pages=%lu path=%s\n", FHU::Syscalls::gettid(), ProtectBase,
                        ProtectSize, Total, MappedFile ? MappedFile->Filename.c_str() : "<unknown>");
            }
            continue;
          }

          int rv = mprotect((void*)ProtectBase, ProtectSize, PROT_READ);
#ifdef ARCHITECTURE_ppc64le
          // FEX_SMCSTOREBACKPATCH: this is where a guest page acquires live
          // compiled code and the mtrack write protection that goes with it.
          FEX::HLE::SMCBackpatch::NotePagesProtected(ProtectBase, ProtectSize);
#endif

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

// FEX_SMCFILEIMMUTABLE case 2b: the guest has contradicted the immutability
// assumption for this range, so every MappedResource it touches drops back to
// ordinary mtrack behaviour permanently.  Resource granularity (rather than
// page or VMA granularity) is deliberate: it is the conservative direction --
// more protection, never less -- and it survives the VMA splitting that a
// partial-range mprotect performs.
void SyscallHandler::RevokeSMCFileImmutabilityLocked(uint64_t Base, uint64_t Top) {
  auto Mapping = VMATracking.VMAs.lower_bound(Top);
  while (Mapping != VMATracking.VMAs.begin()) {
    Mapping--;

    const auto MapBase = Mapping->first;
    const auto MapTop = MapBase + Mapping->second.Length;
    if (MapTop <= Base) {
      break;
    }

    if (Mapping->second.Resource) {
      Mapping->second.Resource->SMCFileImmutableRevoked = true;
    }
  }
}
// ---------------------------------------------------------------------------
// FEX_SMCLAZYINVAL drains.  See LinuxSyscalls/SMCLazyInvalidate.h.
//
// Lock protocol, and it is the whole reason these live here rather than inline:
//   * SMCLazyDirtyMutex is a LEAF.  The batch is swapped/extracted under it and
//     the mutex is dropped before anything else is called.
//   * ThreadManager::SoftInvalidateGuestCodeRange runs outside it and brings
//     its own protocol -- ReleaseAllPendingSharedLocks, ThreadCreationMutex,
//     then the steal-capable exclusive CodeInvalidationMutex.  Because it
//     force-releases pending shared locks, NO caller may hold a shared
//     CodeInvalidationMutex across a drain; every drain point is placed before
//     such a lock is taken (CompileBlock) or where none is held at all
//     (syscall entry, guest signal delivery, guest mprotect).
//   * Nothing here re-protects.  SoftInvalidateRange erases the page from
//     GuestToHostMap::CodePages, so the next relink or compile on that page
//     sees AddBlockExecutableRange return NewPage==true and goes through
//     MarkGuestExecutableRange, which is where mtrack protection is installed.
//     The page is protected again exactly when live code reappears on it.
// ---------------------------------------------------------------------------
namespace {
// Soft-invalidate an ascending, deduplicated page list, coalescing runs of
// contiguous pages so a burst that dirtied one arena costs one lock round trip
// instead of one per page.
void SoftInvalidateLazyPages(FEX::HLE::SyscallHandler* Handler, FEXCore::Core::InternalThreadState* Thread,
                             const fextl::vector<uint64_t>& Pages) {
  // SoftInvalidateGuestCodeRange's after_callback is where legacy re-protects
  // or unprotects; the lazy drain does neither (see the note above), so this is
  // deliberately empty rather than absent.
  const auto NoCallback = [](uint64_t, uint64_t) {};

  size_t Index = 0;
  while (Index < Pages.size()) {
    size_t Run = 1;
    while (Index + Run < Pages.size() && Pages[Index + Run] == Pages[Index + Run - 1] + FEXCore::Utils::FEX_PAGE_SIZE) {
      ++Run;
    }
    Handler->TM.SoftInvalidateGuestCodeRange(Thread, Pages[Index], Run * FEXCore::Utils::FEX_PAGE_SIZE, NoCallback);
    Index += Run;
  }
}
} // anonymous namespace

void SyscallHandler::DrainSMCLazyDirtyPages(FEXCore::Core::InternalThreadState* Thread, FEX::HLE::SMCLazy::DrainPoint Point) {
  // O(1) when there is nothing to do, which is every call in a run with the
  // option off and the overwhelming majority of calls with it on.
  if (SMCLazyDirtyCount.load(std::memory_order_acquire) == 0) {
    return;
  }

  fextl::vector<uint64_t> Batch;
  {
    std::lock_guard lk {SMCLazyDirtyMutex};
    Batch.reserve(SMCLazyDirtyPages.size());
    Batch.insert(Batch.end(), SMCLazyDirtyPages.begin(), SMCLazyDirtyPages.end());
    SMCLazyDirtyPages.clear();
    SMCLazyDirtyCount.store(0, std::memory_order_release);
  }

  if (Batch.empty()) {
    // Raced another drain to the swap; it did the work.
    return;
  }

  SMC_AUDIT("[%d] lazy-drain at=%s pages=%zu first=%lx\n", FHU::Syscalls::gettid(), FEX::HLE::SMCLazy::DrainPointName(Point), Batch.size(),
            Batch.front());

  SoftInvalidateLazyPages(this, Thread, Batch);
}

void SyscallHandler::DrainSMCLazyDirtyRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Base, uint64_t Top,
                                            FEX::HLE::SMCLazy::DrainPoint Point) {
  if (SMCLazyDirtyCount.load(std::memory_order_acquire) == 0) {
    return;
  }

  fextl::vector<uint64_t> Batch;
  {
    std::lock_guard lk {SMCLazyDirtyMutex};
    auto First = SMCLazyDirtyPages.lower_bound(Base);
    auto Last = SMCLazyDirtyPages.lower_bound(Top);
    Batch.insert(Batch.end(), First, Last);
    SMCLazyDirtyPages.erase(First, Last);
    SMCLazyDirtyCount.store(SMCLazyDirtyPages.size(), std::memory_order_release);
  }

  if (Batch.empty()) {
    return;
  }

  SMC_AUDIT("[%d] lazy-drain at=%s pages=%zu first=%lx range=%lx-%lx\n", FHU::Syscalls::gettid(),
            FEX::HLE::SMCLazy::DrainPointName(Point), Batch.size(), Batch.front(), Base, Top);

  SoftInvalidateLazyPages(this, Thread, Batch);
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

// Path of the cache file for one guest file.
//
// `<cache dir>/cache/<basename>-<FileId>-<ConfigId>`: FileId is derived from the
// file's content (CodeCache::ComputeCodeMapId) and ConfigId from the FEX build
// plus every codegen-affecting option (FEXCore::ComputeCodeCacheConfigId). A
// rebuilt library, a rebuilt FEX, or a flipped codegen flag therefore names a
// different file, which simply does not exist yet — a miss, not a mismatched
// load.
static fextl::string CodeCacheFilename(const FEXCore::ExecutableFileInfo& FileInfo, uint64_t CodeCacheConfigId) {
  return fextl::fmt::format("{}cache/{}-{:016x}", FEX::Config::GetCacheDirectory(), FEXCore::CodeMap::GetBaseFilename(FileInfo, false),
                            CodeCacheConfigId);
}

void SyscallHandler::LoadCodeCache(FEXCore::Core::InternalThreadState& Thread, FEXCore::ExecutableFileSectionInfo& Section) {
  // Scope gate. In "rootfs" scope only system libraries participate, so a title
  // shares one cache namespace of immutable libraries with every other title
  // instead of re-caching its own frequently-rebuilt binaries.
  if (!IsPathInCodeCacheScope(Section.FileInfo.Filename)) {
    return;
  }

  auto CacheFilename = CodeCacheFilename(Section.FileInfo, CodeCacheConfigId);
  int CacheFD = open(CacheFilename.c_str(), O_RDONLY);
  if (CacheFD == -1) {
    LogMan::Msg::IFmt("Cache file does not exist: {}", CacheFilename);
    return;
  }

  {
    // Remember that this file's code came from disk: see
    // CodeCacheLoadedFileIds. Recorded before the load attempt on purpose — a
    // partially-applied load leaves relocated blocks registered too.
    std::lock_guard lk {CodeCacheLoadedMutex};
    CodeCacheLoadedFileIds.insert(Section.FileInfo.FileId);
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

bool SyscallHandler::IsPathInCodeCacheScope(std::string_view Path) const {
  switch (CodeCacheScope) {
  case CodeCacheScopeType::Off:
    // The gate is disabled, not the subsystem: this is the legacy
    // FEX_ENABLECODECACHINGWIP behaviour, where any file may be *loaded* from
    // disk. Writing is gated separately (CodeCacheWriteEnabled).
    return true;
  case CodeCacheScopeType::All: return !Path.empty();
  case CodeCacheScopeType::RootFS: {
    // Filenames come from /proc/self/fd, so a rootfs library appears with the
    // RootFS prefix already applied. An empty RootFS means every path would
    // match the empty prefix, which is the opposite of what "rootfs" asks for.
    const auto& Root = RootFSPath();
    if (Root.empty() || Path.empty()) {
      return false;
    }
    if (!Path.starts_with(std::string_view {Root})) {
      return false;
    }
    // Require a path separator at the join so "/rootfs" does not match
    // "/rootfs-backup/lib.so".
    return Root.back() == '/' || Path.size() == Root.size() || Path[Root.size()] == '/';
  }
  }
  return false;
}

void SyscallHandler::SaveCodeCaches(FEXCore::Core::InternalThreadState* Thread, bool Force) {
  if (!CodeCacheWriteEnabled() || !Thread) {
    return;
  }
  if (!CTX->GetCodeCache().WantsSave(Force)) {
    return;
  }

  // Rearm first. A save pass is best-effort: if it partly fails we want the next
  // trigger to come from newly compiled blocks, not to retry immediately in a
  // loop at every mmap.
  CTX->GetCodeCache().NotifyCachesSaved();

  const auto CacheDir = fextl::fmt::format("{}cache/", FEX::Config::GetCacheDirectory());
  std::error_code EC;
  std::filesystem::create_directories(std::string_view {CacheDir}, EC);
  if (EC) {
    LogMan::Msg::EFmt("Code cache: cannot create {}: {}", CacheDir, EC.message());
    return;
  }

  // One entry per file we intend to write.
  struct SaveCandidate {
    const FEXCore::ExecutableFileInfo* FileInfo;
    uint64_t FileStartVA;
    uint64_t BeginVA;
    uint64_t EndVA;
    fextl::vector<FEXCore::GuestAddressRange> GuestRanges;
  };
  fextl::vector<SaveCandidate> Candidates;

  {
    auto lk = FEXCore::GuardSignalDeferringSection<std::shared_lock>(VMATracking.Mutex, Thread);

    for (const auto& ResourcePair : VMATracking.AllResources()) {
      const auto& Resource = ResourcePair.second;
      if (!Resource.MappedFile || !Resource.FirstVMA) {
        continue;
      }
      const auto& FileInfo = *Resource.MappedFile;
      if (!IsPathInCodeCacheScope(FileInfo.Filename)) {
        continue;
      }

      // See ExecutableFileInfo::HasUncacheableRelocations: a file carrying a
      // Skip code relocation cannot be cached at block granularity by a runtime
      // writer, so it is not cached at all.
      if (FileInfo.HasUncacheableRelocations) {
        continue;
      }

      {
        // Never rewrite a file we loaded: those blocks were relocated into this
        // process at load time and shipped no relocation records of their own,
        // so re-serializing them bakes in this run's base address.
        std::lock_guard LoadedLock {CodeCacheLoadedMutex};
        if (CodeCacheLoadedFileIds.contains(FileInfo.FileId)) {
          continue;
        }
      }

      SaveCandidate Candidate {
        .FileInfo = &FileInfo,
        .FileStartVA = static_cast<uint64_t>(Resource.FirstVMA->Base),
        .BeginVA = static_cast<uint64_t>(Resource.FirstVMA->Base),
        .EndVA = static_cast<uint64_t>(Resource.FirstVMA->Base + Resource.FirstVMA->Length),
      };
      for (auto* VMA = Resource.FirstVMA; VMA; VMA = VMA->ResourceNextVMA) {
        Candidate.GuestRanges.emplace_back(VMA->Base, VMA->Base + VMA->Length);
        Candidate.EndVA = std::max<uint64_t>(Candidate.EndVA, VMA->Base + VMA->Length);
      }
      Candidates.push_back(std::move(Candidate));
    }
  }

  for (const auto& Candidate : Candidates) {
    // NOTE: Candidate.FileInfo points into a MappedResource owned by
    // VMATracking, and that lock has already been released. This mirrors the
    // existing delayed-cache-load path in GuestMprotect, which likewise builds
    // section infos under the lock and consumes them after.
    //
    // It is not optional here. SaveData takes CodeBufferWriteMutex, and a thread
    // compiling a block holds CodeBufferWriteMutex while it looks a guest
    // address up in VMATracking. VMATracking's mutex gives writers priority, so
    // holding a shared lock across SaveData deadlocks the moment any thread
    // queues for it exclusively: the compiler waits for the (now blocked)
    // shared lock while we wait for its code buffer lock.
    //
    // The residual hazard — a guest thread unmapping this library between the
    // two — is the pre-existing property of that pattern, not a new one.
    FEXCore::ExecutableFileSectionInfo Section {*Candidate.FileInfo, Candidate.FileStartVA, Candidate.BeginVA, Candidate.EndVA};

    const auto Final = CodeCacheFilename(*Candidate.FileInfo, CodeCacheConfigId);

    // Crash safety: write a fresh temp file in the SAME directory, then
    // rename(2) over the target.
    //
    // rename(2) within a directory is atomic, so a reader either sees the whole
    // old file or the whole new one — never a mixture, and never a truncated
    // file. A process killed at any point before the rename leaves only the
    // temp file behind; the previously saved cache stays intact and loadable,
    // and at most the translations compiled since the last save are lost. The
    // temp name carries the pid so concurrent FEX processes caching the same
    // library cannot collide, and O_EXCL means we never adopt a stale one.
    const auto Temp = fextl::fmt::format("{}.{}.tmp", Final, ::getpid());

    int FD = ::open(Temp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0644);
    if (FD == -1) {
      LogMan::Msg::EFmt("Code cache: cannot create {}: {}", Temp, strerror(errno));
      continue;
    }

    bool Ok = CTX->GetCodeCache().SaveData(*Thread, FD, Section, 0 /* SerializedBaseAddress: LoadData only accepts 0 */,
                                           std::span<const FEXCore::GuestAddressRange> {Candidate.GuestRanges});

    // The data has to be on disk before the directory entry points at it,
    // otherwise a crash between rename and writeback can leave the final name
    // referring to a file with a hole in it.
    if (Ok && ::fsync(FD) != 0) {
      LogMan::Msg::EFmt("Code cache: fsync of {} failed: {}", Temp, strerror(errno));
      Ok = false;
    }
    ::close(FD);

    if (!Ok) {
      ::unlink(Temp.c_str());
      continue;
    }

    if (::rename(Temp.c_str(), Final.c_str()) != 0) {
      LogMan::Msg::EFmt("Code cache: cannot rename {} -> {}: {}", Temp, Final, strerror(errno));
      ::unlink(Temp.c_str());
      continue;
    }

    LogMan::Msg::IFmt("Code cache: wrote {} for {}", Final, Candidate.FileInfo->Filename);
  }
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

  // An mmap over a deferred-dirty range retires whatever was there; the
  // invalidation above is unconditional, so all that is left is to forget the
  // deferral (otherwise the new mapping's first PROT_EXEC would pay for it).
  if (SMCMprotectDeferActive()) {
    ClearSMCDeferredDirtyRange(Result & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::AlignUp(Result + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  }

  // FEX_SMCFILEIMMUTABLE: whatever was mapped here is gone and the invalidation
  // below is unconditional, so the skip records for the range retire with it.
  ClearSMCImmutableSkippedRange(Result & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::AlignUp(Result + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  // FEX_SMCLAZYINVAL: same reasoning. The mmap retired whatever was there and
  // InvalidateCodeRangeIfNecessary below hard-invalidates the range, which is
  // strictly stronger than the soft-invalidate the record was owed, so drop it.
  if (SMCLazyInvalActive()) {
    ClearSMCLazyDirtyRange(Result & FEXCore::Utils::FEX_PAGE_MASK, FEXCore::AlignUp(Result + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  }

  InvalidateCodeRangeIfNecessary(Thread, Result, Size);

  if (LateMetadata) {
    auto CodeInvalidationlk = FEXCore::GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->AddForceTSOInformation(LateMetadata->VolatileValidRanges, std::move(LateMetadata->VolatileInstructions));
  }

  if (EnableCodeCaching && CachedSection) {
    LoadCodeCache(*Thread, *CachedSection);
  }

  // Periodic checkpoint. The memory-management syscalls are the safe points this
  // process reliably passes through: a real (non-signal) syscall context, with
  // every VMATracking and core lock already released.
  MaybeSaveCodeCaches(Thread);

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
#ifdef ARCHITECTURE_ppc64le
    FEX::HLE::SMCBackpatch::NotePagesUnprotected(reinterpret_cast<uint64_t>(addr), length);
#endif
    TrackMunmap(Thread, addr, length);
  }

  // Same as GuestMmap: the range is gone, the invalidation below is
  // unconditional, so just drop the deferred records for it.  This is what
  // keeps a deferred page from leaking stale blocks past its mapping.
  if (SMCMprotectDeferActive()) {
    const auto Base = reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK;
    ClearSMCDeferredDirtyRange(Base, FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  }

  // FEX_SMCFILEIMMUTABLE: same as GuestMmap -- the mapping is gone, so are its
  // skip records.
  ClearSMCImmutableSkippedRange(reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK,
                                FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  // FEX_SMCLAZYINVAL: the memory is gone and the hard invalidation below is
  // unconditional; drop the lazy records so a dirty page can never outlive its
  // mapping (and so a later drain can't soft-invalidate an unmapped range).
  if (SMCLazyInvalActive()) {
    const auto Base = reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK;
    ClearSMCLazyDirtyRange(Base, FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + Size, FEXCore::Utils::FEX_PAGE_SIZE));
  }

  InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), Size);

  if (length) {
    auto CodeInvalidationlk = FEXCore::GuardSignalDeferringSectionWithFallback(CTX->GetCodeInvalidationMutex(), Thread);
    CTX->RemoveForceTSOInformation(reinterpret_cast<uint64_t>(addr), length);
  }

  // Periodic checkpoint; see GuestMmap.
  MaybeSaveCodeCaches(Thread);

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

  if (SMCMprotectDeferActive()) {
    const auto OldBase = reinterpret_cast<uint64_t>(old_address) & FEXCore::Utils::FEX_PAGE_MASK;
    const auto OldTop = FEXCore::AlignUp(reinterpret_cast<uint64_t>(old_address) + old_size, FEXCore::Utils::FEX_PAGE_SIZE);
    const auto NewBase = Result & FEXCore::Utils::FEX_PAGE_MASK;
    const auto NewTop = FEXCore::AlignUp(Result + new_size, FEXCore::Utils::FEX_PAGE_SIZE);

    // The old range is invalidated above (when it moved) and is gone either
    // way, so its records just go.
    ClearSMCDeferredDirtyRange(OldBase, OldTop);

    // The destination is not covered by InvalidateCodeRangeIfNecessaryOnRemap.
    // If anything there was deferred-dirty, the deferral's PROT_EXEC hook can
    // no longer be trusted to cover it (the mapping underneath just changed),
    // so settle the debt now rather than carrying it.
    if (ClearSMCDeferredDirtyRange(NewBase, NewTop)) {
      InvalidateCodeRangeIfNecessary(Thread, NewBase, NewTop - NewBase);
    }
  }

  // FEX_SMCFILEIMMUTABLE: the old range is invalidated above (when it moved) and
  // no longer holds what it held, so drop its skip records.  The destination is
  // not covered by InvalidateCodeRangeIfNecessaryOnRemap, so if it carried
  // records from an earlier mapping, settle them with an invalidation now rather
  // than leave blocks behind an address whose backing just changed.
  // FEX_SMCLAZYINVAL: identical shape. The old range moved/shrank and was
  // invalidated above, so both features' records just go. Anything either
  // feature was tracking at the destination is settled with an invalidation
  // now rather than carried across the mapping change.
  {
    const auto OldBase = reinterpret_cast<uint64_t>(old_address) & FEXCore::Utils::FEX_PAGE_MASK;
    const auto OldTop = FEXCore::AlignUp(reinterpret_cast<uint64_t>(old_address) + old_size, FEXCore::Utils::FEX_PAGE_SIZE);
    const auto NewBase = Result & FEXCore::Utils::FEX_PAGE_MASK;
    const auto NewTop = FEXCore::AlignUp(Result + new_size, FEXCore::Utils::FEX_PAGE_SIZE);

    ClearSMCImmutableSkippedRange(OldBase, OldTop);
    bool SettleNew = ClearSMCImmutableSkippedRange(NewBase, NewTop);
    if (SMCLazyInvalActive()) {
      ClearSMCLazyDirtyRange(OldBase, OldTop);
      SettleNew |= ClearSMCLazyDirtyRange(NewBase, NewTop);
    }
    if (SettleNew) {
      InvalidateCodeRangeIfNecessary(Thread, NewBase, NewTop - NewBase);
    }
  }

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
  bool FileImmutableRearm = false;

  {
    auto lk = FEXCore::GuardSignalDeferringSection(VMATracking.Mutex, Thread);
    Result = ::mprotect(addr, len, prot);
    if (Result == -1) {
      return -errno;
    }

    SMC_AUDIT("[%d] guest-mprotect addr=%lx len=%lx prot=%x\n", FHU::Syscalls::gettid(), reinterpret_cast<uint64_t>(addr), len, prot);
#ifdef ARCHITECTURE_ppc64le
    // The guest's own mprotect replaced whatever mtrack protection we had
    // installed on this range. (MarkGuestExecutableRange re-counts it if code
    // is compiled there again.)
    FEX::HLE::SMCBackpatch::NotePagesUnprotected(reinterpret_cast<uint64_t>(addr), len);
#endif
    TrackMprotect(Thread, addr, len, prot);

    // FEX_SMCFILEIMMUTABLE case 2b: the guest is making a range writable that
    // holds compiled code we deliberately left unprotected.  From here on the
    // mapping cannot be assumed immutable, so revoke it (sticky, resource-wide)
    // and make sure the invalidation below actually runs -- both blocks
    // compiled before this call are dropped, and anything compiled after it is
    // write-protected through the normal MarkGuestExecutableRange path.  Only
    // reached when the option is on: with it off no page is ever recorded and
    // ClearSMCImmutableSkippedRange short-circuits on an atomic load.
    if (prot & PROT_WRITE) {
      const auto Base = reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK;
      const auto Top = FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + len, FEXCore::Utils::FEX_PAGE_SIZE);
      if (ClearSMCImmutableSkippedRange(Base, Top)) {
        RevokeSMCFileImmutabilityLocked(Base, Top);
        FileImmutableRearm = true;
        SMC_AUDIT("[%d] fileimmutable REARM base=%lx top=%lx prot=%x\n", FHU::Syscalls::gettid(), Base, Top, prot);
      }
    }
  }

  // FEX_SMCMPROTECTDEFER: use the guest's own mprotect calls as the SMC
  // validation point for W^X code flips.  See the block comment on
  // SMCDeferredDirtyPages in Syscalls.h for the soundness argument.
  bool DeferInvalidation = false;
  if (SMCMprotectDeferActive()) {
    const auto Base = reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK;
    const auto Top = FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + len, FEXCore::Utils::FEX_PAGE_SIZE);

    if (prot & PROT_EXEC) {
      // The guest is (re-)arming the range for execution.  This is the point
      // the deferral was aiming at: drop the records and fall through to the
      // unconditional invalidation below, which happens before this syscall
      // returns and therefore before the guest can branch into the range.
      //
      // A single W+X request lands here too, which is exactly the legacy
      // behaviour we owe it: with PROT_EXEC granted alongside PROT_WRITE there
      // is no window in which the guest is forbidden from executing, so
      // nothing may be deferred.
      if (ClearSMCDeferredDirtyRange(Base, Top)) {
        SMC_AUDIT("[%d] mprotect-defer REVALIDATE base=%lx top=%lx prot=%x\n", FHU::Syscalls::gettid(), Base, Top, prot);
      }
    } else if ((prot & PROT_WRITE) && (Top - Base) <= SMCMaxDeferredMprotectSize) {
      // Writable but not executable.  The ::mprotect above already replaced
      // whatever read-only tracking protection we had installed, so the
      // guest's writes now run at full speed; record the range so the matching
      // PROT_EXEC transition knows it must invalidate, and skip invalidating
      // (and re-protecting) here.
      MarkSMCDeferredDirtyRange(Base, Top);
      DeferInvalidation = true;
      SMC_AUDIT("[%d] mprotect-defer DEFER base=%lx top=%lx prot=%x\n", FHU::Syscalls::gettid(), Base, Top, prot);
    } else {
      // Either not writable (PROT_READ / PROT_NONE), in which case nothing
      // more can dirty the range, or a range too large to be worth tracking
      // page-by-page.  Let the normal invalidation run and forget any deferral
      // rather than carrying it to some later PROT_EXEC.
      ClearSMCDeferredDirtyRange(Base, Top);
    }
  }

  // FEX_SMCLAZYINVAL: the guest's own mprotect already replaced whatever mtrack
  // protection was installed here, so any lazy record for this range has lost
  // the page state it was describing and must be settled or dropped now.
  if (SMCLazyInvalActive()) {
    const auto Base = reinterpret_cast<uint64_t>(addr) & FEXCore::Utils::FEX_PAGE_MASK;
    const auto Top = FEXCore::AlignUp(reinterpret_cast<uint64_t>(addr) + len, FEXCore::Utils::FEX_PAGE_SIZE);

    if (prot & PROT_EXEC) {
      // The guest is arming the range for execution: it may branch into it the
      // instant this syscall returns, so the debt is settled synchronously
      // here, before the return. (The unconditional invalidation just below
      // would also cover it whenever DeferInvalidation is false -- which
      // PROT_EXEC always is -- but this drain keeps the rule "PROT_EXEC drains
      // the range" true independently of the other options' interactions.)
      DrainSMCLazyDirtyRange(Thread, Base, Top, FEX::HLE::SMCLazy::DrainPoint::MprotectExec);
    } else {
      // Not executable. Either the unconditional invalidation below covers the
      // range, or SMCMprotectDefer took ownership of it (W-not-X) and will
      // invalidate at the matching PROT_EXEC. Either way the lazy record is
      // superseded; carrying it would only risk soft-invalidating a range whose
      // protection state we no longer control.
      ClearSMCLazyDirtyRange(Base, Top);
    }
  }

  // A re-arm outranks the W^X deferral: the deferral's soundness argument is
  // that the intermediate protection lacks PROT_EXEC, but a file-immutable page
  // that was skipped may still be mapped executable right now, so the stale
  // blocks have to go before this syscall returns.
  if (!DeferInvalidation || FileImmutableRearm) {
    InvalidateCodeRangeIfNecessary(Thread, reinterpret_cast<uint64_t>(addr), len);
  }

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
    LoadCodeCache(*Thread, CachedSection);
  }

  // Periodic checkpoint; see GuestMmap.
  MaybeSaveCodeCaches(Thread);

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
          // At runtime, we must drop these relocations: keeping them makes the
          // decoder read the covered displacement as zero (Frontend.cpp), i.e.
          // compile wrong code. Dropping them also drops the frontend's
          // HitBadRelocation signal, so a runtime cache writer can no longer
          // tell which blocks are affected — record the fact at file level and
          // refuse to cache the file at all. See
          // ExecutableFileInfo::HasUncacheableRelocations.
          for (auto it = Resource->MappedFile->Relocations.begin(); it != Resource->MappedFile->Relocations.end();) {
            if (it->second == FEXCore::GuestRelocationType::Skip) {
              Resource->MappedFile->HasUncacheableRelocations = true;
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

  // Destructive advice types replace page contents WITHOUT a page-write fault
  // reaching FEX's SMC tracking, so any translations FEX has for guest code
  // on the affected pages become stale silently. Invalidate to force a
  // recompile on next entry.
  //
  //   MADV_DONTNEED — private anon reverts to zero-fill; shared reverts to
  //                   backing-file contents. Guest arena allocators decommit
  //                   this way; Mono is the workload where this bites us.
  //   MADV_REMOVE   — hole-punches shmem/tmpfs.
  //   MADV_FREE     — kernel MAY reclaim the page lazily under memory
  //                   pressure, MINUTES after the syscall. Invalidating at
  //                   the madvise call is strictly better than nothing but
  //                   is NOT a full fix: the reclaim happens without any
  //                   syscall boundary, so a block compiled between the
  //                   madvise and the lazy reclaim is still exposed. The
  //                   complete closure requires the range being excluded
  //                   from any retention scheme (Nimbus's problem, not this
  //                   commit's). Recording the partial-fix status here so
  //                   the next reader is not misled by the presence of a
  //                   MADV_FREE branch.
  bool NeedsInvalidate = false;
  switch (advice) {
  case MADV_DONTNEED:
  case MADV_REMOVE:
  case MADV_FREE: NeedsInvalidate = true; break;
  default: break;
  }
  if (!NeedsInvalidate) {
    return;
  }

  // Do NOT hold VMATracking.Mutex across InvalidateCodeRangeIfNecessary:
  // it reaches TM::InvalidateGuestCodeRange, which takes ThreadCreationMutex
  // and the EXCLUSIVE CodeInvalidationMutex, and holding VMATracking.Mutex
  // during that would invert the lock order used everywhere else in this
  // file (see GuestMunmap at :550-551 for the required shape: mutex work
  // in a closed scope, then invalidate outside it). The stub used to open
  // a VMATracking.Mutex scope for the empty TODO; there is nothing this
  // handler actually needs to read from VMATracking, so the scope is gone.
  InvalidateCodeRangeIfNecessary(Thread, Base, Size);
}

} // namespace FEX::HLE
