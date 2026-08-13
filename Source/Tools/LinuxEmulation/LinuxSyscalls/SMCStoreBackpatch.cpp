// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: SMC store backpatching (ppc64le)
$end_info$
*/

#include "LinuxSyscalls/SMCStoreBackpatch.h"

#ifdef ARCHITECTURE_ppc64le

// Deliberately does NOT include LinuxSyscalls/Syscalls.h: nothing here needs
// the syscall handler, and staying off it keeps this file's include graph free
// of the ucontext/mcontext machinery.

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/ArchHelpers/PPC64CacheFlush.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <PPC64LE/Emitter.h>
#include <PPC64LE/Registers.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

namespace FEX::HLE {
// Defined in SyscallsSMCTracking.cpp.
int SMCAuditFD();
} // namespace FEX::HLE

namespace FEX::HLE::SMCBackpatch {

#define SMC_AUDIT(...)                \
  do {                                \
    int fd_ = FEX::HLE::SMCAuditFD(); \
    if (fd_ >= 0) {                   \
      dprintf(fd_, __VA_ARGS__);      \
    }                                 \
  } while (0)

using namespace PPC64Emitter;
using namespace PPC64Emitter::GPRegs;

namespace {

  // ---------------------------------------------------------------------------
  // Pinned register duplicated from FEXCore/Source/Interface/Core/ArchHelpers/
  // PPC64Emitter.h, which is not on LinuxEmulation's include path.  The stub
  // passes this to the helper as the CpuStateFrame* argument, so it MUST stay in
  // sync with that header's `constexpr auto STATE`.
  // ---------------------------------------------------------------------------
  constexpr GPR kStateReg = r27;

  std::atomic<bool> gEnabled {false};

  // Opened once from SetEnabled so the helper -- which runs on the JIT's stack
  // with guest state live in registers -- never has to run a function-local
  // static guard or an open() on its hot path.
  std::atomic<int> gSelfMemFD {-1};

  // ===========================================================================
  // Page filter
  // ---------------------------------------------------------------------------
  // A direct-mapped saturating counter table over a hash of the guest page
  // number.  A bucket counts how many currently-mtrack-write-protected pages
  // hash to it.  The stub reads one byte from it with no lock and no barrier.
  //
  // Both error directions are benign, which is the entire point of using a
  // lossy structure here:
  //   over-count  -> the stub calls the helper for a page that is actually
  //                  writable; the helper's pwrite still writes the right bytes.
  //   under-count -> the stub performs a native store on a protected page; it
  //                  faults and HandleSegfault resolves it exactly as it does
  //                  for an unpatched site today.
  // Nothing about the *code-liveness* question is answered here -- that one is
  // asked authoritatively (under the lookup read lock) inside the helper,
  // because a false negative there WOULD be a silent correctness bug.
  // ===========================================================================
  constexpr uint32_t kFilterBits = 20;
  constexpr size_t kFilterSize = size_t {1} << kFilterBits; // 1 MiB
  constexpr uint32_t kFilterShift = 64 - kFilterBits;       // 44
  constexpr uint64_t kHashMul = 0x9E3779B97F4A7C15ull;      // 2^64 / phi

  uint8_t* gFilter {nullptr};

  inline uint32_t BucketOf(uint64_t Page) {
    return static_cast<uint32_t>((Page * kHashMul) >> kFilterShift);
  }

  // Sticky at 255: once a bucket saturates it stops decrementing, so it can
  // never under-report the pages that pushed it there.
  void BumpBucket(uint32_t Bucket, int Delta) {
    uint8_t* Slot = &gFilter[Bucket];
    uint8_t Old = __atomic_load_n(Slot, __ATOMIC_RELAXED);
    for (;;) {
      if (Old == 0xFF) {
        return; // saturated & sticky
      }
      uint8_t New = Delta > 0 ? static_cast<uint8_t>(Old + 1) : (Old ? static_cast<uint8_t>(Old - 1) : 0);
      if (New == Old) {
        return;
      }
      if (__atomic_compare_exchange_n(Slot, &Old, New, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        return;
      }
    }
  }

  void BumpRange(uint64_t Base, uint64_t Size, int Delta) {
    if (!gFilter || !Size) {
      return;
    }
    const uint64_t First = Base >> 12;
    const uint64_t Last = (Base + Size - 1) >> 12;
    // A colossal range (a whole mapping being torn down) is not worth walking
    // page by page; skipping it only leaves the filter hot, which is safe.
    if (Last - First > 4096) {
      return;
    }
    for (uint64_t Page = First; Page <= Last; ++Page) {
      BumpBucket(BucketOf(Page), Delta);
    }
  }

  // ===========================================================================
  // Store form decoding (static: instruction word only, no ucontext)
  //
  // Deliberately the same instruction set SyscallsSMCTracking.cpp's
  // DecodePPCStore accepts, minus the forms listed under "refused" below.
  // ===========================================================================
  struct StoreForm {
    uint32_t RS;
    uint32_t RA;
    uint32_t RB;
    int32_t Disp;
    uint32_t Width; // 1/2/4/8
    bool Indexed;   // X-form (RB) vs D/DS-form (Disp)
    bool Update;    // RA writeback
  };

  bool DecodeStoreForm(uint32_t Insn, StoreForm* Out) {
    const uint32_t Primary = Insn >> 26;
    StoreForm F {};
    F.RS = (Insn >> 21) & 31;
    F.RA = (Insn >> 16) & 31;
    F.RB = (Insn >> 11) & 31;
    const int32_t D = static_cast<int16_t>(Insn & 0xFFFF);
    const int32_t DS = static_cast<int16_t>(Insn & 0xFFFC);

    switch (Primary) {
    case 36:
      F.Width = 4;
      F.Disp = D;
      break; // stw
    case 37:
      F.Width = 4;
      F.Disp = D;
      F.Update = true;
      break; // stwu
    case 38:
      F.Width = 1;
      F.Disp = D;
      break; // stb
    case 39:
      F.Width = 1;
      F.Disp = D;
      F.Update = true;
      break; // stbu
    case 44:
      F.Width = 2;
      F.Disp = D;
      break; // sth
    case 45:
      F.Width = 2;
      F.Disp = D;
      F.Update = true;
      break;   // sthu
    case 62: { // std/stdu (DS-form)
      const uint32_t XO = Insn & 3;
      if (XO == 0) {
        F.Width = 8;
        F.Disp = DS;
      } else if (XO == 1) {
        F.Width = 8;
        F.Disp = DS;
        F.Update = true;
      } else {
        return false; // stq
      }
      break;
    }
    case 31: { // X-forms
      const uint32_t XO = (Insn >> 1) & 0x3FF;
      F.Indexed = true;
      switch (XO) {
      case 215: F.Width = 1; break; // stbx
      case 247:
        F.Width = 1;
        F.Update = true;
        break;                      // stbux
      case 407: F.Width = 2; break; // sthx
      case 439:
        F.Width = 2;
        F.Update = true;
        break;                      // sthux
      case 151: F.Width = 4; break; // stwx
      case 183:
        F.Width = 4;
        F.Update = true;
        break;                      // stwux
      case 149: F.Width = 8; break; // stdx
      case 181:
        F.Width = 8;
        F.Update = true;
        break;               // stdux
      default: return false; // stdcx./byte-reversed/vector/dcbz
      }
      break;
    }
    default: return false;
    }

    if (F.Update && F.RA == 0) {
      return false; // invalid form
    }
    *Out = F;
    return true;
  }

  // ===========================================================================
  // Stub frame layout (offsets from the stub's own r1)
  //
  // The stub allocates a real frame rather than using the ELFv2 red zone: it
  // calls a C++ helper, and a non-leaf may not rely on the red zone.  Bytes
  // 0..95 are the ELFv2 linkage + parameter save area that the helper is
  // entitled to write.
  // ===========================================================================
  constexpr int16_t kFrameSize = 640; // multiple of 16, keeps r1 16B aligned

  // GPRs saved, in slot order: r0, r2, r3..r12.
  // r1 is the stack pointer, r13 is the TLS pointer (never clobbered by us or
  // by the helper), r14-r31 are ELFv2 callee-saved and therefore survive the
  // helper call untouched -- that covers STATE (r27), REG_PF (r28), REG_AF
  // (r29) and the whole RA pool.  r7-r12 are SRA (live guest GPRs) AND
  // ELFv2-volatile, which is exactly why they must be here.
  constexpr int16_t kGPRBase = 96;
  constexpr int GPRSlotIndex(uint32_t Idx) {
    if (Idx == 0) {
      return 0;
    }
    if (Idx >= 2 && Idx <= 12) {
      return static_cast<int>(Idx) - 1;
    }
    return -1;
  }
  constexpr int16_t GPRSlot(uint32_t Idx) {
    return static_cast<int16_t>(kGPRBase + GPRSlotIndex(Idx) * 8);
  }
  constexpr bool IsSavedGPR(uint32_t Idx) {
    return GPRSlotIndex(Idx) >= 0;
  }

  constexpr int16_t kSlotLROrig = 192;
  constexpr int16_t kSlotLRTail = 200;
  constexpr int16_t kSlotCTR = 208;
  constexpr int16_t kSlotXER = 216;
  constexpr int16_t kSlotCR = 224;
  constexpr int16_t kSlotEA = 232;
  constexpr int16_t kVRBase = 240; // v0..v19, 16B aligned, 320 bytes -> 559
  constexpr uint32_t kNumVolatileVRs = 20;
  static_assert(kVRBase + kNumVolatileVRs * 16 <= kFrameSize, "stub frame too small");
  static_assert(kVRBase % 16 == 0, "stvx needs a 16B-aligned displacement");

  constexpr uint32_t kSPR_XER = 1;

  // ===========================================================================
  // Stub pool
  // ---------------------------------------------------------------------------
  // Pools are carved out of the JIT's OWN code buffer via
  // Context::AllocateJITAuxMemory.
  //
  // The obvious implementation -- mmap a pool near the site -- cannot work and
  // measurably did not: all JIT code lives inside one large RWX mapping
  // ([anon:FEXMemJIT], 0x1001980c000-0x1002180b000 on op4k), so every address
  // hint at StorePC+-{8,20,28}MiB lands *inside* that existing mapping. mmap
  // without MAP_FIXED silently ignores such a hint and returns unrelated memory
  // far outside `b` range, the reach check rejects it, and the pool is
  // munmapped again. Every hint failed every time: an audit of a smcstorm
  // falseshare run showed 511,744 BACKPATCH-REFUSED reason=no-stub-in-reach,
  // and because each refused fault re-ran all six mmap/munmap pairs the
  // benchmark fell from 42.3K/s (legacy handling) to 103/s.
  //
  // The code buffer is the only memory that is guaranteed near JIT code, and it
  // is already RWX. Pools are therefore small (64KiB, ~160 stubs each after the
  // shared tail) so a pool that ends up out of reach of later sites wastes very
  // little of the buffer.
  // ===========================================================================
  constexpr size_t kPoolSize = 64 * 1024;
  // `b` reaches +-32MiB. Keep a margin so the pool tail is still reachable from
  // a site at the far end of the window.
  constexpr int64_t kBranchReach = (int64_t {1} << 25) - (int64_t {2} << 20);

  struct StubPool {
    uint8_t* Base;
    size_t Used;
    size_t TailOffset; // offset of the shared save/call/restore trampoline
  };

  struct PatchRecord {
    uint32_t OrigInsn;
    uint32_t BranchInsn;
    uint8_t* Stub;
  };

  std::mutex gMutex;
  std::vector<StubPool> gPools;
  std::map<uint64_t, PatchRecord> gPatched;

  // ---------------------------------------------------------------------------
  // Negative cache
  //
  // A site we could not serve is very likely to fault again immediately -- that
  // is what an SMC storm *is*. Without this, every one of those faults re-runs
  // the whole allocation attempt (and, before pools came from the code buffer,
  // six mmap/munmap pairs). Remember the refusal instead and answer it from the
  // map. Entries are code-buffer-relative host PCs, so they die with the
  // generation exactly like gPools and gPatched.
  //
  // The value counts how many times this site has been audited: audit output is
  // capped per site because a storm hits the same PC hundreds of thousands of
  // times and the audit file is the thing that would explode.
  // ---------------------------------------------------------------------------
  std::map<uint64_t, uint32_t> gRefused;
  constexpr uint32_t kMaxRefusalAudits = 3;
  constexpr size_t kMaxRefusedSites = 64 * 1024;

  // Generation of the code buffer everything above describes. See
  // Context::GetJITCodeBufferGeneration.
  uint64_t gGeneration {0};

  constexpr size_t kMaxPatchedSites = 4096;

  bool InReach(uint64_t From, uint64_t To) {
    const int64_t Delta = static_cast<int64_t>(To) - static_cast<int64_t>(From);
    return Delta >= -kBranchReach && Delta <= kBranchReach;
  }

  // Caller must hold gMutex. A new code buffer means every host address we
  // recorded -- pool bases, patched store PCs, refused store PCs -- belongs to
  // a buffer that may already have been freed and whose range may have been
  // handed back out. None of it may be reused or even dereferenced.
  void DropStaleStateIfNeeded(uint64_t Generation) {
    if (Generation == gGeneration) {
      return;
    }
    gGeneration = Generation;
    gPools.clear();
    gPatched.clear();
    gRefused.clear();
  }

  void EmitSharedTail(Emitter& Em, uint64_t HelperAddr);

  // Find (or create) a pool with `Bytes` free whose allocation AND shared tail
  // are both within branch reach of `NearPC`.
  uint8_t* AllocStub(FEXCore::Core::InternalThreadState* Thread, uint64_t NearPC, size_t Bytes, uint64_t HelperAddr, uint64_t* TailAddrOut) {
    for (auto& Pool : gPools) {
      if (Pool.Used + Bytes > kPoolSize) {
        continue;
      }
      const uint64_t Start = reinterpret_cast<uint64_t>(Pool.Base) + Pool.Used;
      const uint64_t Tail = reinterpret_cast<uint64_t>(Pool.Base) + Pool.TailOffset;
      if (!InReach(NearPC, Start) || !InReach(NearPC, Start + Bytes) || !InReach(Start, Tail)) {
        continue;
      }
      Pool.Used += Bytes;
      *TailAddrOut = Tail;
      return reinterpret_cast<uint8_t*>(Start);
    }

    // Carve a fresh pool out of the code buffer's free tail. This refuses --
    // rather than blocks -- if another thread is compiling, which is required:
    // we are inside a SIGSEGV handler. See the locking comment on
    // CodeBufferManager::TryAllocateAuxMemory.
    //
    // Lock order note: we hold gMutex here and reach for CodeBufferWriteMutex.
    // There is no inversion hazard even though a compiling thread holds
    // CodeBufferWriteMutex and could in principle fault into this code, because
    // the inner acquisition is a try_lock that also refuses outright when the
    // calling thread is the current owner. Nothing here ever waits.
    const auto Aux = Thread->CTX->AllocateJITAuxMemory(Thread, kPoolSize, 16, NearPC, static_cast<uint64_t>(kBranchReach));
    if (!Aux.Ptr) {
      return nullptr;
    }
    if (Aux.Generation != gGeneration) {
      // The buffer rotated between our generation check and this call. The
      // chunk is real but belongs to a buffer whose bookkeeping we have not
      // adopted; drop it (it is 64KiB of a buffer that will be freed anyway)
      // rather than mixing generations in gPools.
      return nullptr;
    }

    StubPool Pool {Aux.Ptr, 0, 0};
    const uint64_t Base = reinterpret_cast<uint64_t>(Aux.Ptr);
    Emitter Em(Pool.Base, kPoolSize);
    EmitSharedTail(Em, HelperAddr);
    Pool.Used = FEXCore::AlignUp(Em.GetOffset(), 16);
    Pool.TailOffset = 0;
    FEXCore::ArchHelpers::PPC64::FlushICacheRange(reinterpret_cast<void*>(Pool.Base), Pool.Used);

    if (Pool.Used + Bytes > kPoolSize) {
      // Cannot happen: the shared tail is a couple hundred bytes. Leak the
      // chunk rather than hand out an overlapping stub.
      return nullptr;
    }
    const uint64_t Start = Base + Pool.Used;
    Pool.Used += Bytes;
    gPools.push_back(Pool);
    *TailAddrOut = Base;
    return reinterpret_cast<uint8_t*>(Start);
  }

} // anonymous namespace

// ===========================================================================
// The helper the stub calls.
//
// Reached only when the page filter says the EA's page is (probably)
// mtrack-write-protected, i.e. the store would fault.
// ===========================================================================
extern "C" void FEXSMCBackpatchStoreHelper(FEXCore::Core::CpuStateFrame* Frame, uint64_t EA, uint64_t Value, uint64_t Width) {
  auto* Thread = Frame->Thread;

  // SMC Idea 3: this query is now front-ended by the lock-free code-granule
  // bitmap inside LookupCache::RangeOverlapsCompiledCode. A "provably clear"
  // bitmap answer returns here in a few loads with no lock taken; anything else
  // still runs the authoritative CodePages/BlockList walk under the read lock,
  // whose verdict is final. Before that, this single call was 55% of all CPU on
  // op4k's smcstorm/falseshare (~400us/call) while the pwrite it gates was 3%.
  // See FEXCore/Source/Interface/Core/SMCCodeGranules.h.
  if (!Thread->CTX->GuestRangeOverlapsCompiledCode(Thread, EA, Width)) {
    // MISS: pure data on a code page (false sharing).  pwrite through
    // /proc/self/mem writes past the read-only protection with FOLL_FORCE and
    // breaks CoW correctly, so the page stays protected and no block dies.
    // This is the case the whole feature exists for.
    const int FD = gSelfMemFD.load(std::memory_order_relaxed);
    if (FD >= 0 && ::pwrite(FD, &Value, Width, static_cast<off_t>(EA)) == static_cast<ssize_t>(Width)) {
      return;
    }
    // Fall through to the direct store on any pwrite failure.
  }

  // HIT (or a failed pwrite): perform the store directly and let it fault.
  //
  // This deliberately does NOT call SoftInvalidateGuestCodeRange from here.
  // Falling into the SIGSEGV handler costs exactly what an unpatched site
  // costs today -- the brief's "a page with live code goes through
  // soft-invalidate exactly as today" -- and it reuses HandleSegfault's shared-
  // mapping mirror walk, its lock-stealing protocol and its
  // ReleaseAllPendingSharedLocks, none of which are safe to re-derive at a
  // point that is neither a signal handler nor a syscall entry.  The handler
  // invalidates, unprotects and returns; the store below then retries and
  // succeeds.  Same ordering guarantee, zero new soundness surface.
  switch (Width) {
  case 1: *reinterpret_cast<volatile uint8_t*>(EA) = static_cast<uint8_t>(Value); break;
  case 2: *reinterpret_cast<volatile uint16_t*>(EA) = static_cast<uint16_t>(Value); break;
  case 4: *reinterpret_cast<volatile uint32_t*>(EA) = static_cast<uint32_t>(Value); break;
  default: *reinterpret_cast<volatile uint64_t*>(EA) = Value; break;
  }
}

namespace {

  // ---------------------------------------------------------------------------
  // Shared per-pool trampoline.
  //
  // Entered by `bl` from a per-site stub that has ALREADY lowered r1 by
  // kFrameSize and saved r0/r2/r3..r12 into the frame.
  //   in:  r3 = EA, r4 = Value, r5 = Width
  //   out: everything it touched restored; returns via blr.
  //
  // It saves the remaining volatile machine state the helper may clobber: LR,
  // CTR, XER, the whole CR (mfcr/mtcr covers CR0-CR7, including the
  // callee-saved CR2-CR4 -- deliberately over-broad), and v0-v19.  v0-v15 are
  // the guest's XMM registers (SRAFPR) and v16-v19 are the first four dynamic
  // vector allocations, all of which are ELFv2-volatile; v20-v31 are
  // callee-saved and need no save.
  // ---------------------------------------------------------------------------
  void EmitSharedTail(Emitter& Em, uint64_t HelperAddr) {
    Em.mflr(r0);
    Em.std(r0, kSlotLRTail, r1);
    Em.mfctr(r0);
    Em.std(r0, kSlotCTR, r1);
    Em.mfspr(r0, kSPR_XER);
    Em.std(r0, kSlotXER, r1);
    Em.mfcr(r0);
    Em.std(r0, kSlotCR, r1);

    for (uint32_t i = 0; i < kNumVolatileVRs; ++i) {
      Em.li(r0, static_cast<int16_t>(kVRBase + i * 16));
      Em.stvx(v(i), r1, r0);
    }

    // (EA, Value, Width) -> (Frame, EA, Value, Width). Shift right-to-left so no
    // argument is overwritten before it is read.
    Em.mr(r6, r5);
    Em.mr(r5, r4);
    Em.mr(r4, r3);
    Em.mr(r3, kStateReg);

    // ELFv2 indirect call: the callee's global entry point address must be in
    // r12 so its `addis r2,r12,..; addi r2,r2,..` prologue can build its TOC.
    // Copied from PPC64Dispatcher.cpp's EmitFuncToR12.  r2 itself is restored by
    // the per-site stub from the frame after we return.
    Em.LoadImm64(r12, HelperAddr);
    Em.mtctr(r12);
    Em.bctrl();

    for (uint32_t i = 0; i < kNumVolatileVRs; ++i) {
      Em.li(r0, static_cast<int16_t>(kVRBase + i * 16));
      Em.lvx(v(i), r1, r0);
    }

    Em.ld(r0, kSlotCR, r1);
    Em.mtcr(r0);
    Em.ld(r0, kSlotXER, r1);
    Em.mtspr(kSPR_XER, r0);
    Em.ld(r0, kSlotCTR, r1);
    Em.mtctr(r0);
    Em.ld(r0, kSlotLRTail, r1);
    Em.mtlr(r0);
    Em.blr();
  }

  // Materialise the ORIGINAL value of host GPR `Src` into `Dest`.
  // Saved registers come from the frame (their live copies may already be
  // clobbered); everything else is still intact in its register.
  void EmitLoadOrigGPR(Emitter& Em, GPR Dest, uint32_t Src) {
    if (IsSavedGPR(Src)) {
      Em.ld(Dest, GPRSlot(Src), r1);
    } else {
      Em.mr(Dest, r(Src));
    }
  }

  size_t EmitPerSiteStub(Emitter& Em, const StoreForm& F, uint64_t ReturnAddr, uint64_t TailAddr, uint64_t StubBase) {
    const auto CurAddr = [&]() {
      return StubBase + Em.GetOffset();
    };

    Em.stdu(r1, -kFrameSize, r1);
    Em.std(r0, GPRSlot(0), r1);
    for (uint32_t Reg = 2; Reg <= 12; ++Reg) {
      Em.std(r(Reg), GPRSlot(Reg), r1);
    }
    Em.mflr(r0);
    Em.std(r0, kSlotLROrig, r1);

    // --- effective address into r3 -------------------------------------------
    if (F.Indexed) {
      if (F.RA == 0) {
        EmitLoadOrigGPR(Em, r3, F.RB);
      } else {
        EmitLoadOrigGPR(Em, r3, F.RA);
        EmitLoadOrigGPR(Em, r5, F.RB);
        Em.add(r3, r3, r5);
      }
    } else {
      if (F.RA == 0) {
        Em.li(r3, static_cast<int16_t>(F.Disp));
      } else {
        EmitLoadOrigGPR(Em, r3, F.RA);
        if (F.Disp) {
          Em.addi(r3, r3, static_cast<int16_t>(F.Disp));
        }
      }
    }
    if (F.Update) {
      Em.std(r3, kSlotEA, r1); // survives the helper call
    }

    // --- stored value into r4 -------------------------------------------------
    EmitLoadOrigGPR(Em, r4, F.RS);

    // --- page filter probe ----------------------------------------------------
    //   bucket = ((EA >> 12) * kHashMul) >> kFilterShift
    Em.srdi(r5, r3, 12);
    Em.LoadImm64(r6, kHashMul);
    Em.mulld(r5, r5, r6);
    Em.srdi(r5, r5, kFilterShift);
    Em.LoadImm64(r6, reinterpret_cast<uint64_t>(gFilter));
    Em.lbzx(r6, r6, r5);
    Em.cmpldi(r6, 0);

    Label NativeStore {};
    Label Epilogue {};
    Em.bc(CC_EQ, &NativeStore);

    // Protected (probably): hand the store to the helper.
    Em.li(r5, static_cast<int16_t>(F.Width));
    Em.bl(static_cast<int32_t>(static_cast<int64_t>(TailAddr) - static_cast<int64_t>(CurAddr())));
    Em.b(&Epilogue);

    // Not protected: this site is writing ordinary memory. Do the real store.
    Em.Bind(&NativeStore);
    switch (F.Width) {
    case 1: Em.stb(r4, 0, r3); break;
    case 2: Em.sth(r4, 0, r3); break;
    case 4: Em.stw(r4, 0, r3); break;
    default: Em.std(r4, 0, r3); break;
    }

    Em.Bind(&Epilogue);

    // --- update-form RA writeback --------------------------------------------
    if (F.Update) {
      Em.ld(r0, kSlotEA, r1);
      if (IsSavedGPR(F.RA)) {
        Em.std(r0, GPRSlot(F.RA), r1); // picked up by the restore below
      } else {
        Em.mr(r(F.RA), r0);
      }
    }

    // --- epilogue -------------------------------------------------------------
    Em.ld(r0, kSlotLROrig, r1);
    Em.mtlr(r0);
    for (uint32_t Reg = 2; Reg <= 12; ++Reg) {
      Em.ld(r(Reg), GPRSlot(Reg), r1);
    }
    Em.ld(r0, GPRSlot(0), r1);
    Em.addi(r1, r1, kFrameSize);
    Em.b(static_cast<int32_t>(static_cast<int64_t>(ReturnAddr) - static_cast<int64_t>(CurAddr())));

    return Em.GetOffset();
  }

  // Upper bound on a per-site stub, used to reserve pool space before emitting.
  constexpr size_t kMaxStubBytes = 96 * 4;

} // anonymous namespace

// ===========================================================================
// Public entry points
// ===========================================================================

void SetEnabled(bool Enabled) {
  if (!Enabled) {
    return;
  }
  if (!gFilter) {
    void* Mem = ::mmap(nullptr, kFilterSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Mem == MAP_FAILED) {
      LogMan::Msg::EFmt("SMCStoreBackpatch: failed to allocate the page filter; feature stays off.");
      return;
    }
    gFilter = static_cast<uint8_t*>(Mem);
  }
  if (gSelfMemFD.load(std::memory_order_relaxed) < 0) {
    const int FD = ::open("/proc/self/mem", O_WRONLY | O_CLOEXEC);
    if (FD < 0) {
      LogMan::Msg::EFmt("SMCStoreBackpatch: cannot open /proc/self/mem; feature stays off.");
      return;
    }
    gSelfMemFD.store(FD, std::memory_order_relaxed);
  }
  gEnabled.store(true, std::memory_order_release);
}

bool IsEnabled() {
  return gEnabled.load(std::memory_order_relaxed);
}

void NotePagesProtected(uint64_t Base, uint64_t Size) {
  if (!IsEnabled()) {
    return;
  }
  BumpRange(Base, Size, +1);
}

void NotePagesUnprotected(uint64_t Base, uint64_t Size) {
  if (!IsEnabled()) {
    return;
  }
  BumpRange(Base, Size, -1);
}

const char* TryBackpatchStore(FEXCore::Core::InternalThreadState* Thread, uint64_t StorePC, bool* SuppressAudit) {
  if (SuppressAudit) {
    *SuppressAudit = false;
  }
  if (!IsEnabled()) {
    return "backpatch-disabled";
  }
  if (StorePC & 3) {
    return "unaligned-pc";
  }
  // Only ever patch inside a JIT CodeBuffer. In particular this is what stops
  // the helper's own fallback store (a plain host store that is allowed to
  // fault) from getting libFEXCore/libc patched underneath it.
  if (!Thread->CTX->IsAddressInCodeBuffer(Thread, StorePC)) {
    return "not-in-codebuffer";
  }

  const uint32_t Insn = *reinterpret_cast<const uint32_t*>(StorePC);
  StoreForm F {};
  if (!DecodeStoreForm(Insn, &F)) {
    return "form-not-patchable";
  }
  // r1 is the host stack pointer, which the stub itself moves; a store based
  // on or of r1 is a JIT spill/frame store that cannot legitimately target a
  // guest page anyway.
  if (F.RA == 1 || F.RS == 1 || (F.Indexed && F.RB == 1)) {
    return "r1-operand";
  }

  const uint64_t Generation = Thread->CTX->GetJITCodeBufferGeneration();

  std::scoped_lock lk {gMutex};

  DropStaleStateIfNeeded(Generation);

  // Negative cache: a site we already failed to place a stub for. Answer from
  // the map instead of re-running the allocator on every fault of a storm.
  auto Refused = gRefused.find(StorePC);
  if (Refused != gRefused.end()) {
    if (Refused->second >= kMaxRefusalAudits && SuppressAudit) {
      *SuppressAudit = true;
    } else {
      ++Refused->second;
    }
    return "no-stub-in-reach-cached";
  }

  auto Existing = gPatched.find(StorePC);
  if (Existing != gPatched.end()) {
    if (Existing->second.BranchInsn == Insn) {
      // Cannot happen -- a patched site does not execute the store -- but if
      // it somehow does, do not patch twice.
      return "already-patched";
    }
    // The CodeBuffer that held the old site was freed and its address reused.
    // The record is stale; drop it and patch afresh. (The stub it named is
    // leaked, bounded by kMaxPatchedSites.)
    gPatched.erase(Existing);
  }

  if (gPatched.size() >= kMaxPatchedSites) {
    return "site-budget-exhausted";
  }

  uint64_t TailAddr {};
  uint8_t* Stub = AllocStub(Thread, StorePC, kMaxStubBytes, reinterpret_cast<uint64_t>(&FEXSMCBackpatchStoreHelper), &TailAddr);
  if (!Stub) {
    // Remember the refusal so the next fault at this PC is a map lookup. The
    // entry is dropped when the code buffer generation changes, which is the
    // only event that can make this site placeable after all.
    if (gRefused.size() < kMaxRefusedSites) {
      gRefused.emplace(StorePC, 1);
    }
    return "no-stub-in-reach";
  }

  const uint64_t StubAddr = reinterpret_cast<uint64_t>(Stub);
  Emitter Em(Stub, kMaxStubBytes);
  const size_t Size = EmitPerSiteStub(Em, F, StorePC + 4, TailAddr, StubAddr);
  LOGMAN_THROW_A_FMT(Size <= kMaxStubBytes, "SMC backpatch stub overflow");

  // Publish the stub's instructions before anything can branch to them.
  FEXCore::ArchHelpers::PPC64::FlushICacheRange(reinterpret_cast<void*>(Stub), Size);

  const int64_t Delta = static_cast<int64_t>(StubAddr) - static_cast<int64_t>(StorePC);
  if (Delta < -(int64_t {1} << 25) || Delta >= (int64_t {1} << 25)) {
    // Unreachable given AllocStub's own reach check, but if it ever happens the
    // stub bytes are already spent -- cache the refusal so a storm cannot leak
    // one stub per fault.
    if (gRefused.size() < kMaxRefusedSites) {
      gRefused.emplace(StorePC, 1);
    }
    return "branch-out-of-range";
  }
  const uint32_t Branch = (18u << 26) | ((static_cast<uint32_t>(static_cast<int32_t>(Delta) >> 2) & 0x00FFFFFFu) << 2);

  // Cross-modifying-code protocol, shared with the dispatcher's publication
  // path: a single naturally-aligned 4-byte store, then dcbst / sync / icbi /
  // sync / isync on that word's cache block. See the header for why a
  // concurrently-executing thread needs no handshake: the pre-patch instruction
  // is a faulting store that HandleSegfault already resolves correctly, so both
  // the old and the new instruction are valid.
  __atomic_store_n(reinterpret_cast<uint32_t*>(StorePC), Branch, __ATOMIC_RELAXED);
  FEXCore::ArchHelpers::PPC64::FlushICacheRange(reinterpret_cast<void*>(StorePC), 4);

  gPatched.emplace(StorePC, PatchRecord {Insn, Branch, Stub});

  SMC_AUDIT("[%d] backpatch OK pc=%lx insn=%08x stub=%lx w=%u upd=%d\n", FHU::Syscalls::gettid(), StorePC, Insn, StubAddr, F.Width,
            F.Update ? 1 : 0);
  return nullptr;
}

} // namespace FEX::HLE::SMCBackpatch

#endif // ARCHITECTURE_ppc64le
