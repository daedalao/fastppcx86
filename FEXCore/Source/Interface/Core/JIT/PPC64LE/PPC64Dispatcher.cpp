// SPDX-License-Identifier: MIT
// PPC64LE JIT dispatcher implementation.
// Generates the native code glue that:
//   - Enters JIT execution from C++ (DispatchPtr)
//   - Implements the block-dispatch loop (read RIP → L1 lookup → branch/link)
//   - Exits JIT back to C++ (ThreadStop, signal stubs)
//   - Re-enters JIT for callbacks (CallbackPtr)
//
// Layout (all generated into a single code buffer):
//   [DispatchPtr]                   entry from C++
//   [DispatcherLoopTop]             dispatch loop
//   [ExitFunctionLinker]            slow-path exit / block linker call
//   [ThreadStopHandler]             unwind to C++
//   [ThreadPauseHandlerSpillSRA]    pause with SRA spill
//   [ThreadPauseHandler]            pause sleep call + illegal instruction trap
//   [GuestSignal_SIGILL]            signal stubs
//   [GuestSignal_SIGTRAP]
//   [GuestSignal_SIGSEGV]
//   [SignalReturnHandler]           stub
//   [CallbackPtr]                   JIT callback re-entry

#include "Interface/Core/JIT/PPC64LE/PPC64Dispatcher.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/LookupCache.h"
#include "Utils/MemberFunctionToPointer.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <cstring>
#include <sys/mman.h>

#include <sched.h>

namespace {
// Called from the pause handler: park the current thread until it is woken.
static void SleepThread(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::CpuStateFrame* Frame) {
  CTX->SyscallHandler->SleepThread(CTX, Frame);
}
// Called from JIT-emitted Yield when guest PAUSE has fired enough times in a
// row that we want to surrender the CPU to another thread on the host. The
// SMT priority hint (or 27,27,27) emitted inline is a per-core nudge only;
// sched_yield() is the only way to give the kernel a chance to schedule a
// different thread (e.g. the lock-holder).
extern "C" void PPC64_PauseSchedYield() {
  sched_yield();
}
} // namespace

// DEBUG: visible to gdb post-mortem. Updated at every dispatcher fast-path
// entry with the guest RIP being dispatched.
extern "C" {
  alignas(64) uint64_t g_last_dispatched_rip = 0;
  alignas(64) uint64_t g_dispatch_count = 0;
  alignas(64) uint64_t g_recent_rips[16] = {};   // ring buffer (count & 15)
  // Push debug: ring buffer of (Src, Dst-after-store, [Dst]) triples.
  alignas(64) uint64_t g_push_count = 0;
  alignas(64) uint64_t g_push_log[8][3] = {};
  // Slow-path SRA-fill debug: capture r14 (= R6 = RSI) at three points.
}

namespace FEXCore::CPU {

static constexpr size_t DISPATCHER_CODE_SIZE = 65536;

fextl::unique_ptr<PPC64Dispatcher>
PPC64Dispatcher::Create(FEXCore::Context::ContextImpl* CTX) {
  return fextl::make_unique<PPC64Dispatcher>(CTX);
}

PPC64Dispatcher::PPC64Dispatcher(FEXCore::Context::ContextImpl* CTX)
  : PPC64EmitterBase(CTX, nullptr, 0), CTX(CTX) {
  // Allocate an executable code buffer for the dispatcher
  void* Mem = mmap(nullptr, DISPATCHER_CODE_SIZE,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  LOGMAN_THROW_A_FMT(Mem != MAP_FAILED, "Failed to allocate dispatcher code buffer");

  SetBuffer(static_cast<uint8_t*>(Mem), DISPATCHER_CODE_SIZE);
  EmitDispatcher();

  // Flush D-cache to memory and invalidate I-cache for the freshly emitted
  // dispatcher. POWER8 has split, non-coherent I/D caches; without this the
  // CPU may execute stale bytes the I-cache happened to fetch on the same
  // physical line. mprotect(PROT_EXEC) typically (but not contractually) does
  // this, so we still issue it explicitly to match ARM64 behaviour.
  __builtin___clear_cache(static_cast<char*>(Mem),
                          static_cast<char*>(Mem) + DISPATCHER_CODE_SIZE);

  // Make the buffer read-only+executable after generation
  mprotect(Mem, DISPATCHER_CODE_SIZE, PROT_READ | PROT_EXEC);
}

void PPC64Dispatcher::InitThreadPointers(FEXCore::Core::InternalThreadState* Thread) {
  auto& Ptrs = Thread->CurrentFrame->Pointers;

  Ptrs.DispatcherLoopTop         = DispatcherLoopTopAddress;
  Ptrs.DispatcherLoopTopFillSRA  = DispatcherLoopTopFillSRAAddress;
  Ptrs.ExitFunctionLinker        = ExitFunctionLinkerAddress;
  Ptrs.ThreadStopHandlerSpillSRA = ThreadStopHandlerAddressSpillSRA;
  Ptrs.ThreadPauseHandlerSpillSRA = ThreadPauseHandlerAddressSpillSRA;
  Ptrs.GuestSignal_SIGILL        = GuestSignal_SIGILL_Address;
  Ptrs.GuestSignal_SIGTRAP       = GuestSignal_SIGTRAP_Address;
  Ptrs.GuestSignal_SIGSEGV       = GuestSignal_SIGSEGV_Address;
  Ptrs.SignalReturnHandler       = SignalHandlerReturnAddress;
  Ptrs.SignalReturnHandlerRT     = SignalHandlerReturnAddress;
  Ptrs.PPC64_PauseSchedYield     = reinterpret_cast<uint64_t>(&PPC64_PauseSchedYield);

  InterpreterOps::FillFallbackIndexPointers(Ptrs.FallbackHandlerPointers, &ABIPointers[0]);
}

// ============================================================
// The generated dispatcher code
// ============================================================
void PPC64Dispatcher::EmitDispatcher() {
  using namespace FEXCore::Core;
  DispatcherBegin = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  // ==============================================================
  // DispatchPtr  (called from C++ with C-ABI: r3=Frame, r4=SingleInst)
  // ==============================================================
  DispatchPtr = reinterpret_cast<AsmDispatch>(GetCursorAddress<uint8_t*>());

  // Establish a standard ELFv2 stack frame for the C ABI.
  PushCalleeSavedRegisters();

  // STATE (r27) = Frame* (r3)
  mr(STATE, r3);

  // Record the host stack pointer as the "returning stack location" so that
  // when a Stop/Pause signal fires outside the JIT (e.g. while the thread is
  // inside a glibc syscall wrapper called from the JIT Syscall op), the signal
  // handler can reset r1 to a valid dispatcher frame and PopCalleeSavedRegisters
  // will correctly restore callee-saved regs and blr back to the C++ caller.
  // Without this, Frame->ReturningStackLocation stays 0 (its default) and
  // SetSp(ucontext, 0) corrupts the stack pointer → cascading crash.
  {
    int32_t rsl_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, ReturningStackLocation));
    std(r1, static_cast<int16_t>(rsl_off), STATE);
  }

  // Fill-SRA entry point: signal-return / pause-resume jump here so SRA is
  // reloaded from Frame->State before falling into the L1 lookup loop.
  //
  // SMC single-instruction recovery: the SMC SIGSEGV handler (SyscallsSMCTracking.cpp
  // HandleSegfault) sets r4=1 in the kernel ucontext when it needs the next JIT
  // entry to recompile as a single-instruction block (so a racing SMC write to
  // the same page is observed before the rest of the original block runs).
  // Mirrors ARM64's ENTRY_FILL_SRA_SINGLE_INST_REG / cbnz pattern
  // (Dispatcher.cpp:89-94). Check BEFORE FillStaticRegs because PPC's
  // FillStaticRegs uses TMP2 (=r4) as scratch in its NZCV unpack stage.
  //
  // The C++ fall-through path (main dispatcher entry from `ExecuteDispatch`)
  // must arrive here with r4 == 0, or the compare-and-branch below will
  // always take the CompileSingleStep exit. `PushCalleeSavedRegisters` at :129
  // clobbers TMP2 (== r4) twice: once via `mfcr(TMP2)` (PPC64Emitter.cpp:279),
  // then finally via `LoadImm32(TMP2, 192)` in the VMX save loop
  // (PPC64Emitter.cpp:298). So on fall-through, r4 is DETERMINISTICALLY 192,
  // and the branch fires on every dispatcher entry — one wasted compile per
  // call, self-corrected by the SingleStep tail's fallback to normal
  // compilation but pure waste. The `li(r4, 0)` below is emitted BEFORE the
  // label, so the fall-through path clears r4 while signal/SMC arrivals jump
  // TO the label and keep whatever the kernel set in the ucontext r4.
  li(r4, 0);
  PPC64Emitter::Label CompileSingleStepLabel{};
  DispatcherLoopTopFillSRAAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  cmpdi(r4, 0);
  bc(CC_NE, &CompileSingleStepLabel);
  FillStaticRegs();

  // Fall through into DispatcherLoopTop

  // ==============================================================
  // DispatcherLoopTop: entered with SRA registers filled, STATE valid.
  // Load RIP, do L1 lookup, branch to JIT block or slow path.
  // ==============================================================
  DispatcherLoopTopAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  {
    // Re-establish the r0=0 zero-index invariant before dispatching into any
    // JIT block.
    //
    // Every guest load/store the backend emits is an X-form indexed access with
    // r0 in the rB slot -- ldx(GDst, EA, r0), stdx(GSrc, EA, r0), and ~50 more
    // in MemoryOps.cpp -- so the effective address is EA + r0. Note that PPC's
    // "r0 reads as zero" rule applies only to the rA operand, NOT to rB: in
    // these instructions r0 is an ordinary register whose contents are added to
    // the address. A nonzero r0 therefore silently offsets EVERY memory access
    // in the block, producing garbage loads whose values are stored into guest
    // state and only fault much later somewhere unrelated.
    //
    // FillStaticRegs deliberately leaves r0 alone (ExitFunctionLinker smuggles
    // the resolved host code pointer through it), and only some entry paths
    // restore it: FillForABICall, the ExitFunctionLinker slow path, and the
    // syscall return. The DispatcherLoopTopFillSRA entry above -- which is where
    // HandleSegfault redirects an SMC fault, and where signal and thread-start
    // paths re-enter -- did not, leaving the invariant dependent on whatever r0
    // happened to hold. Do it here so it holds for every dispatcher-mediated
    // block entry regardless of how we got here. One instruction on a path that
    // already performs several loads.
    li(r(0), 0);

    // Load current RIP from Frame->State.rip
    int32_t rip_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.rip));
    ld(TMP1, rip_off, STATE);  // TMP1 = guest RIP
    // 32-bit guest: mask RIP to 32 bits so the L1 hash and the GuestCode
    // compare both use a canonical 32-bit value. ARM64 dispatcher does the
    // analogous `and_(VirtualMemorySize-1)` (Dispatcher.cpp:188-191).
    MaybeClrUpper32(TMP1);

    // DEBUG: log RIP to globals so gdb post-mortem can see the dispatch trail.
    // Use TMP2 as scratch (reload from STATE below).
    LoadConstant(TMP2, reinterpret_cast<uint64_t>(&g_last_dispatched_rip));
    std(TMP1, 0, TMP2);
    LoadConstant(TMP2, reinterpret_cast<uint64_t>(&g_dispatch_count));
    ld(TMP3, 0, TMP2);
    addi(TMP3, TMP3, 1);
    std(TMP3, 0, TMP2);
    // Ring buffer: g_recent_rips[count & 15] = rip
    LoadConstant(TMP2, reinterpret_cast<uint64_t>(&g_recent_rips[0]));
    rldicl(TMP3, TMP3, 0, 60);   // count & 15
    sldi(TMP3, TMP3, 3);          // *8 for uint64 stride
    add(TMP2, TMP2, TMP3);
    std(TMP1, 0, TMP2);

    // Load L1Pointer and L1Mask from Frame->State.L1Pointer / L1Mask
    // These are adjacent: L1Pointer at offset X, L1Mask at X+8.
    int32_t l1_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.L1Pointer));
    int32_t l1mask_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.L1Mask));

    ld(TMP2, l1_off, STATE);       // TMP2 = L1Pointer
    ld(TMP3, l1mask_off, STATE);   // TMP3 = L1Mask (pre-scaled by sizeof(LookupCacheEntry)=16)

    // Compute byte offset: (RIP << 4) & L1Mask = (RIP & L1PointerMask) * 16.
    // L1Mask is pre-scaled (= L1PointerMask << 4), so shifting RIP left before
    // ANDing gives the correct entry offset. Matches ARM64 dispatcher behavior.
    sldi(TMP4, TMP1, 4);  // LookupCacheEntry = 16 bytes, log2(16) = 4
    and_(TMP4, TMP4, TMP3);

    // Address of L1 entry: L1Pointer + byte_offset
    add(TMP2, TMP2, TMP4);

    // Load L1Entry: {HostCode (8 bytes), GuestCode (8 bytes)}.
    //
    // ORDERING NOTE (paired with LookupCacheEntry::Publish on the writer
    // side): we MUST load GuestCode FIRST, branch on the compare, then load
    // HostCode only on the success path.  The conditional branch establishes
    // a control dependency that the PPC memory model honors as a load-load
    // barrier for free, ensuring we don't observe a torn entry where
    // GuestCode is the new value but HostCode is still stale.
    //
    // Loading HostCode first (the original code) was racy: a concurrent
    // writer mid-Publish could leave us with {stale_HostCode, new_GuestCode},
    // pass the cmpd, and jump into a half-installed / invalidated block --
    // the recurring zero-IR-block spin observed at Steam's PLT-to-malloc
    // stub.  ARM64 sidesteps this entirely by using `stp` (store-pair) for
    // atomic publish; PPC64LE has no equivalent, hence the release-fence /
    // control-dep pattern.
    ld(TMP4, 8, TMP2);   // TMP4 = GuestCode (the "key")

    // Compare GuestCode with current RIP — into CR7, NOT CR0.
    //
    // Why CR7: SpillStaticRegs (called below in ExitFunctionLinker on L1
    // miss) packs CR0 + XER into flags[RFLAG_NZCV_LOC] as the canonical
    // NZCV storage for cross-block transfer. If we used the default CR0
    // here, any L1 miss would overwrite the correct (just-spilled-by-the-
    // JIT-block's-ExitFunction) NZCV with garbage from this lookup compare.
    // Symptom was a phantom SF=1 (and sometimes ZF=1) appearing in PUSHF /
    // LAHF after popfq=0 across ~25 ASM tests (Primary_9C/9D/84/85,
    // ShiftZeroFlagsUpdate, InitialPFFlag, BLSI_flags, etc.). Running cmpd
    // into CR7 leaves CR0 as set by FillStaticRegs.
    // Use cmpw in 32-bit mode: x86 RIP is 32-bit, and FEX zero-extends RIP
    // to 64 bits via MaybeClrUpper32 before the L1 lookup.  The cached
    // GuestCode is published as zero-extended-from-32 too, so cmpd is
    // correct.  But if any publisher were to leave non-zero upper bits in
    // either operand (32-bit IR ops in the future, signal-frame paths,
    // etc.), cmpd would falsely miss and take the slow path.  cmpw is
    // explicitly only-low-32 — it matches what x86 32-bit branch targets
    // logically are.
    if (CTX->Config.Is64BitMode()) {
      cmpd(cr(7), TMP4, TMP1);
    } else {
      cmpw(cr(7), TMP4, TMP1);
    }

    // If mismatch, take slow path through ExitFunctionLinker.
    // BO=12 (branch if true), BI=30 (CR7.EQ at PPC bit 4*7+2 = 30).
    auto match_label = PPC64Emitter::Label{};
    bc({12, 30}, &match_label);

    // Slow path: store RIP, jump to ExitFunctionLinker
    {
      int32_t exit_off = static_cast<int32_t>(
        offsetof(CpuStateFrame, Pointers.ExitFunctionLinker));
      ld(TMP1, exit_off, STATE);
      mtctr(TMP1);
      bctr();
    }

    Bind(&match_label);
    // Fast path: JIT block found.  Load HostCode AFTER the conditional
    // branch — the control dependency on the GuestCode==RIP check provides
    // load-load ordering on PPC, so this load is guaranteed to see the
    // HostCode that was published alongside the matched GuestCode.
    ld(TMP3, 0, TMP2);   // TMP3 = HostCode (loaded under control-dep)
    mtctr(TMP3);
    li(r(0), 0);  // JIT blocks use r0=0 as zero index for ldx/stdx
    bctr();
  }

  // ==============================================================
  // ExitFunctionLinker — slow path when L1 cache misses.
  // Calls the C++ FindBlock / compile path, then re-dispatches.
  //
  // Wrapped in a DeferredSignalRefCount guard (mirror of ARM64's
  // EmitSignalGuardedRegion at Dispatcher.cpp:254-308 and the contract in
  // docs/DeferredSignals.md). Increment marks the dispatcher-resident C++
  // call as uninterruptible so async signals are deferred; decrement +
  // InterruptFaultPage byte-store drains any signal queued during the
  // uninterruptible region.
  //
  // Scratch register choice: TMP1 (r3) — NOT in SRA (PPC64Emitter.h:53 maps
  // r7-r12, r14-r23 to guest GPRs; r3-r6 are non-SRA caller-clobbered
  // scratch). r0 is NOT usable because addi/std with RA=r0 treat RA as
  // literal zero. r12 is NOT usable because it holds guest RBP after
  // FillStaticRegs reloads SRA (this bug caused a SIGSEGV on Steam launch
  // in commit-before-this; symptom was `ldx rX, r5, r0` after `addi r5,
  // r12, -120` crashing — guest RBP was the refcount value).
  // ==============================================================
  ExitFunctionLinkerAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  const int32_t deferred_refcount_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::CpuStateFrame, State.DeferredSignalRefCount));
  const int32_t deferred_fault_off = static_cast<int32_t>(
    offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) -
    offsetof(FEXCore::Core::InternalThreadState, BaseFrameState));
  static_assert(offsetof(FEXCore::Core::InternalThreadState, InterruptFaultPage) >=
                offsetof(FEXCore::Core::InternalThreadState, BaseFrameState),
                "InterruptFaultPage must lie at or after BaseFrameState");

  auto EmitDeferredSignalEnter = [&]() {
    // 3-instr non-atomic thread-local increment per docs/DeferredSignals.md.
    // TMP1 is scratch; SpillStaticRegs(TMP1) below will clobber it again,
    // so we can freely use it here.
    ld(TMP1, deferred_refcount_off, STATE);
    addi(TMP1, TMP1, 1);
    std(TMP1, deferred_refcount_off, STATE);
  };
  auto EmitDeferredSignalExit = [&]() {
    // 4-instr decrement + fault-page byte-store. If a signal was queued
    // while refcount > 0, the page is mprotect'd PROT_NONE and the stb
    // traps SIGSEGV; the host handler picks the queued signal off the
    // per-thread stack and dispatches the guest handler.
    ld(TMP1, deferred_refcount_off, STATE);
    addi(TMP1, TMP1, -1);
    std(TMP1, deferred_refcount_off, STATE);
    stb(TMP1, deferred_fault_off, STATE);
  };

  {
    // Enter uninterruptible region BEFORE SpillStaticRegs so the spill
    // itself runs under the guard. SRA is live; r12 is non-SRA scratch.
    EmitDeferredSignalEnter();

    // Spill SRA before calling C++
    SpillStaticRegs(TMP1);

    // Call PPC64JITCore::ExitFunctionLink(Frame, GuestRIP):
    //   r3 = Frame (CpuStateFrame*)
    //   r4 = current guest RIP
    // Returns r3 = host code address (0 if block can't be compiled).
    // TMP1=r3, TMP2=r4 — must NOT use TMP1/TMP2 to load the function ptr since they
    // hold r3/r4 (the arguments). Load into r12 per ELFv2 indirect-call convention.
    mr(r3, STATE);
    int32_t rip_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.rip));
    ld(r4, rip_off, STATE);
    // 32-bit guest: pass a canonical 32-bit RIP to ExitFunctionLink so the
    // C++ side hashes / lookups match what the JIT block was compiled at.
    MaybeClrUpper32(r4);

    // Load function pointer into r12 (ELFv2 requires r12 == callee address for indirect calls)
    int32_t link_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, Pointers.ExitFunctionLink));
    ld(r(12), link_off, STATE);
    mtctr(r(12));
    // Save/restore r2 (TOC) around indirect call as required by ELFv2
    std(r2, 24, r1);
    bctrl();
    ld(r2, 24, r1);

    // After returning, r3 contains the host code pointer (or 0 if not found).
    // If 0, stop execution (block not compilable).
    cmpdi(r3, 0);
    auto found_label = PPC64Emitter::Label{};
    bc(CC_NE, &found_label);

    // Block not found/compilable: fall through to ThreadStopHandler.
    // Balance the refcount + drain pending deferred signals before leaving
    // the dispatcher region — otherwise the refcount stays elevated and
    // every future signal in this thread silently defers forever.
    {
      EmitDeferredSignalExit();
      int32_t stop_off = static_cast<int32_t>(
        offsetof(CpuStateFrame, Pointers.ThreadStopHandlerSpillSRA));
      ld(TMP1, stop_off, STATE);
      mtctr(TMP1);
      bctr();
    }

    Bind(&found_label);
    // FillStaticRegs uses TMP1=r3 as scratch (unconditionally for XMM fills),
    // which would clobber the host code pointer in r3. Save it in r0 first.
    // r0 is safe: not in SRA, not touched by FillStaticRegs.
    mr(r(0), r3);
    FillStaticRegs();
    mtctr(r(0));
    // CTR now holds the host code pointer; exit the guard region. TMP1
    // (r3) is non-SRA scratch — FillStaticRegs already clobbered it and
    // the next JIT block expects it to be scratch, so reusing it for the
    // refcount decrement / fault store is safe. r0 still holds the host
    // code ptr (only used here to be reset to zero before bctr).
    EmitDeferredSignalExit();
    li(r(0), 0);  // JIT blocks use r0=0 as zero index for ldx/stdx
    bctr();
  }

  // ==============================================================
  // CompileSingleStep — SMC recovery path.
  // Entered from DispatcherLoopTopFillSRA when r4 (= TMP2 =
  // ENTRY_FILL_SRA_SINGLE_INST_REG) was non-zero, set by the SMC fault
  // handler via SetFillSRASingleInst.  SRA is NOT in host regs yet (the
  // FillStaticRegs at the entry was skipped via the branch). r1 still
  // points at the dispatcher's frame so a host C call is safe.
  //
  // Calls uintptr_t ContextImpl::CompileSingleStep(CpuStateFrame*, uint64_t)
  // which compiles JUST the next x86 instruction at State.rip as its own
  // JIT block and returns the host code pointer.  We then FillStaticRegs
  // and jump straight to that block, bypassing the L1 lookup (so a racing
  // stale cache entry can't be hit).
  // ==============================================================
  Bind(&CompileSingleStepLabel);
  {
    // ContextImpl::CompileSingleStep is a non-static member.
    // ELFv2 calling convention: r3 = this (CTX), r4 = Frame, r5 = RIP.
    LoadConstant(r3, reinterpret_cast<uint64_t>(CTX));
    mr(r4, STATE);
    int32_t rip_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.rip));
    ld(r5, rip_off, STATE);
    MaybeClrUpper32(r5);  // 32-bit guest: canonical 32-bit RIP

    // MemberFunctionToPointerCast handles the data-vs-text-vs-thunk wrapping
    // that PPC64LE needs for non-static member function pointers.
    FEXCore::Utils::MemberFunctionToPointerCast PMFCompileSingleStep(
      &FEXCore::Context::ContextImpl::CompileSingleStep);
    LoadConstant(r(12), PMFCompileSingleStep.GetConvertedPointer());
    mtctr(r(12));

    // Save/restore TOC around the indirect C call per ELFv2.
    std(r2, 24, r1);
    bctrl();
    ld(r2, 24, r1);
  }
  // CompileSingleStep returned the host code ptr in r3. Save it past
  // FillStaticRegs (which uses TMP1=r3 as scratch for XMM fills).
  mr(r(0), r3);
  FillStaticRegs();
  mtctr(r(0));
  li(r(0), 0);  // restore r0=0 zero-index invariant
  bctr();

  // ==============================================================
  // ThreadStopHandler — unwind JIT and return to C++ caller
  // ThreadStopHandlerAddressSpillSRA: entered when in JIT (spill first)
  // ThreadStopHandlerAddress:         entered when already spilled
  //
  // SignalDelegator::HandleSignalDeferred picks between the two based on
  // whether the interrupted PC was inside the JIT code buffer
  // (SignalDelegator.cpp:717-728). On the outside-JIT branch — thread
  // interrupted in host C++ — r27 is an ELFv2 non-volatile register
  // OWNED BY THE C++ FRAME and is NOT `STATE`. Running SpillStaticRegs
  // there emits ~34 stores at [r27 + offset], which land at wild
  // addresses (whatever the C++ code had put in r27) and can silently
  // corrupt another thread's CpuStateFrame if the alias falls that way.
  //
  // ThreadPauseHandler above has always split its two entry points
  // correctly (:490 / :493); ThreadStopHandler used to alias both
  // pointers to the same body (see ContextConfig at :1163). Adding
  // the second entry point makes the outside-JIT path skip the spill.
  // ==============================================================
  ThreadStopHandlerAddressSpillSRA = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);

  ThreadStopHandlerAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  PopCalleeSavedRegisters();
  blr();

  // ==============================================================
  // ThreadPauseHandler — park this thread until woken (GDB, explicit pause)
  // ThreadPauseHandlerAddressSpillSRA: entered when in JIT (spill first)
  // ThreadPauseHandlerAddress:         entered when already spilled
  // ==============================================================
  ThreadPauseHandlerAddressSpillSRA = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);

  ThreadPauseHandlerAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  // Call SleepThread(CTX, Frame): r3=CTX, r4=STATE
  LoadConstant(r3, reinterpret_cast<uint64_t>(CTX));
  mr(r4, STATE);
  LoadConstant(TMP1, reinterpret_cast<uint64_t>(SleepThread));
  mr(r(12), TMP1);
  mtctr(TMP1);
  bctrl();

  // PauseReturnInstruction: illegal opcode 0x00000000 → SIGILL.
  // FEX sends SIGILL to this address to wake the paused thread.
  PauseReturnInstruction = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  Emit32(0x00000000u);  // primary opcode 0 — invalid on PPC64LE, generates SIGILL

  // ==============================================================
  // Guest signal stubs — force matching host fault.
  //
  // The Break IR op populates SynchronousFaultData (FaultToTopAndGenerated
  // Exception=1 plus Signal/TrapNo/si_code/err_code) and jumps here.  Each
  // stub then triggers the corresponding host fault so the host signal
  // handler runs through the SignalDelegator → GuestFramesManagement path
  // and delivers the synthesized signal to the guest with proper si_addr
  // and cr2 (now populated from OriginalRIP for synthesized faults — see
  // GuestFramesManagement.cpp:474 (x64) and :742+:819 (i32 RT)).  Without
  // these stubs guest signal handlers never run for JIT-detected faults
  // (NoExec, alignment, etc.) and threads die silently with pthread_join
  // never returning.
  //
  // ExitOnHLTEnabled() keeps the old clean-exit behavior for unit tests
  // that intentionally trigger faults.
  // ==============================================================
  // SIGILL/SIGTRAP stubs — raise the matching host fault.
  //
  // These used to be `SpillStaticRegs; PopCalleeSavedRegisters; blr`, on the
  // stated grounds that FEX "has been silently NOPing" guest UD2/INT3 and that
  // firing a real signal would surprise callers. **That premise was measured
  // and is false.** `blr` here is the dispatcher's *epilogue*: it returns out
  // of ExecuteThread, after which Syscalls/Thread.cpp runs
  // ReleaseAllPendingSharedLocks, UninstallTLSState and DestroyThread. So the
  // old behaviour was not absorption — it silently **destroyed the guest
  // thread**, with any guest-side locks it held left held forever, no handler
  // run and nothing logged. A probe confirmed this at runtime for both INT3
  // and UD2: the thread executed the instruction and never returned, and its
  // peers then blocked indefinitely.
  //
  // Delivering the signal is therefore strictly better than the status quo for
  // every caller the old comment worried about. A guest whose handler catches
  // SIGILL/SIGTRAP now gets to run it; a guest without one dies loudly instead
  // of losing one thread invisibly.
  //
  // Mechanism: spill guest state, then execute a genuinely faulting word so the
  // host kernel raises the signal and SignalDelegator → GuestFramesManagement
  // synthesises delivery with correct si_addr. State reconstruction already
  // works on this path — IsAddressInCodeBuffer is false for the dispatcher
  // mmap, so SpillSRA is skipped and State.rip survives.
  //
  // SIGTRAP additionally required a host thunk, which FEX never installed; see
  // the registration added in LinuxSyscalls/SignalDelegator.cpp.
  //
  // KNOWN LIMITATION: UD2 and UnimplementedOp emit byte-identical
  // BreakDefinitions (OpcodeDispatcher.cpp), so the backend cannot tell a
  // deliberate guest trap from a FEX codegen gap. After this change an
  // unimplemented op surfaces as a guest SIGILL rather than something
  // diagnosable. Separating them needs a new IR field; recorded, not fixed.
  GuestSignal_SIGILL_Address = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);
  // All-zero word: not a valid PowerPC encoding, so the kernel raises SIGILL
  // with si_code ILL_ILLOPC. Same construct SignalHandlerReturnAddress uses
  // below; the two are distinguished by PC, which HandleSIGILL compares.
  Emit32(0x00000000u);

  GuestSignal_SIGTRAP_Address = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);
  // `trap` = tw 31,r0,r0 — unconditional program check, raises SIGTRAP.
  // Same encoding X87Ops.cpp already emits for unsupported fstp conversions.
  tw(31, r0, r0);

  // SIGSEGV stub DELIBERATELY stays silent — do not "fix" it to match the two
  // above without reading this.
  //
  // Guest HLT lowers to BreakOp(SIGSEGV), and HLT is how the ~2200 ASM tests
  // terminate: silent stub → blr out of ExecuteThread → FEXInterpreter runs its
  // normal teardown and returns StatusCode. Making this fault would change how
  // roughly 6672 of the 7011 ctest cases end, which is why the 6/7011 gate has
  // no bearing on the SIGILL/SIGTRAP change above — no ASM test uses UD2 or
  // INT3, verified by search.
  //
  // The same stub also serves NoExec entry-block faults, which guests *should*
  // see, so this is genuinely two behaviours sharing one stub. Separating them
  // needs the Break op to distinguish its callers — the same missing IR field
  // noted above. Until then silence is the safer default here and delivery is
  // the safer default there.
  //
  // (The prior comment claimed a real fault "breaks the worker pool init" for
  // Steam. That claim traces to f78e0613d, which is a pure comment diff whose
  // own message calls it "exploration that got reverted to a clean blr" — no
  // code ever implemented or tested it. Treated as an untested hypothesis, not
  // a finding.)
  GuestSignal_SIGSEGV_Address = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);
  PopCalleeSavedRegisters();
  blr();

  // ==============================================================
  // SignalReturnHandler — sentinel for signal-return state restore.
  // Called from C++ as a function pointer (rt_sigreturn syscall handler);
  // must NOT actually return. Faulting here makes the host kernel raise
  // SIGILL, and SignalDelegator::HandleSIGILL detects PC ==
  // SignalHandlerReturnAddress and runs RestoreThreadState. Same trick
  // PauseReturnInstruction uses above. arm64 emits hlt(0) for this.
  // ==============================================================
  SignalHandlerReturnAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  Emit32(0x00000000u);

  // ==============================================================
  // CallbackPtr — re-entry from JIT callback
  // Called with C-ABI: r3=Frame, r4=target RIP
  // ==============================================================
  CallbackPtr = reinterpret_cast<JITCallback>(GetCursorAddress<uint8_t*>());

  // CRITICAL ORDERING: stash incoming RIP (r4) BEFORE PushCalleeSavedRegisters.
  // PushCalleeSavedRegisters() clobbers TMP2 (== r4) twice in its prologue:
  // first `mfcr(TMP2)` at PPC64Emitter.cpp:279 (which the earlier version of
  // this comment blamed), and then FINALLY `LoadImm32(TMP2, 192)` inside the
  // VMX save loop at :298. That last write is the one that survives — r4
  // holds 192 (= 0xC0, the byte offset of v31's stvx slot in the frame) at
  // every return from PushCalleeSavedRegisters, on every entry. Symptom:
  // State.rip ends up = 0xC0, the dispatcher loads garbage as the next
  // guest PC, and the suspect-RIP bypass fires on every single host->guest
  // callback (libGL XSync, libvulkan X11Manager.*, etc.). The mfcr framing
  // in the earlier comment was arithmetically wrong; the fix was right for
  // the wrong reason.
  //
  // r7 is volatile per ELFv2 ABI -- the C++ caller has either spilled it
  // or doesn't care -- and PushCalleeSavedRegisters only touches r0, r1,
  // r4 (TMP2), and r14-r31. Stashing in r7 is safe across the prologue.
  mr(r(7), r4);

  PushCalleeSavedRegisters();
  mr(STATE, r3);

  // Restore RIP from the stash and persist into State.rip. The original
  // 32-bit clamp is preserved for 32-bit guests.
  {
    int32_t rip_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.rip));
    MaybeClrUpper32(r(7));
    std(r(7), rip_off, STATE);
  }

  // Bump the signal handler ref counter (marks that we're in a JIT callback)
  {
    int32_t ref_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, SignalHandlerRefCounter));
    lwz(TMP1, ref_off, STATE);
    addi(TMP1, TMP1, 1);
    stw(TMP1, ref_off, STATE);
  }

  // Push ThunkCallbackRet onto the guest stack so the guest callback's ret
  // lands on the 0F3E trampoline, which triggers CallbackReturn IR op.
  // Mirrors the ARM64 dispatcher.
  //
  // Invariant: push == retaddr_size + 8, because CallbackReturn's `+8` is
  // unconditional and correct on both backends. So:
  //   x86-64: push 16, guest `ret` pops 8, CallbackReturn adds 8 -> net 0
  //   i386  : push 12, guest `ret` pops 4, CallbackReturn adds 8 -> net 0
  //
  // Was hard-coded to -16 + std(8-byte), which leaked -4 per callback under
  // an i386 guest. Not visible today because GuestStackBumpAllocator
  // (ThunkLibs/include/common/Host.h:674-706, active whenever
  // THUNK_HOST_NOT_X86_64 is defined -- true for every thunk lib on this
  // host, see ThunkLibs/HostLibs/CMakeLists.txt:49-51) snapshots guest RSP
  // before each callback and restores it after, so the leak never
  // accumulates. But it goes live the moment anything reaches CallbackPtr
  // outside that wrapper.
  {
    const bool Is64Bit = CTX->Config.Is64BitMode();
    const int16_t PushBytes = Is64Bit ? -16 : -12;
    int32_t ret_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, Pointers.ThunkCallbackRet));
    int32_t rsp_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, State.gregs[FEXCore::X86State::REG_RSP]));
    ld(TMP1, ret_off, STATE);     // TMP1 = ThunkCallbackRet (guest x86 VA)
    ld(TMP2, rsp_off, STATE);     // TMP2 = guest RSP
    // 32-bit guest: mask the upper 32 bits of RSP defensively. State.gregs is
    // 64-bit storage, and while SpillStaticRegs masks on the way out, host C++
    // code paths (RestoreFrame_ia32, CallCallback, etc.) can write gregs as
    // 64-bit values whose upper bits leak host pointers. Without this mask,
    // "addi -N; store TMP1, 0(TMP2)" stores ThunkCallbackRet to a host stack
    // address — observed in Steam-with-Vulkan-thunk as NoExec crashes when
    // the guest later derefs the corrupted RSP.
    MaybeClrUpper32(TMP2);
    addi(TMP2, TMP2, PushBytes);  // RSP -= 16 (x86-64) / 12 (i386)
    MaybeClrUpper32(TMP2);        // re-mask after addi in case borrow extended high bits
    if (Is64Bit) {
      std(TMP1, 0, TMP2);         // [RSP+0] = ThunkCallbackRet (8B x86-64)
    } else {
      stw(TMP1, 0, TMP2);         // [RSP+0] = ThunkCallbackRet (4B i386)
    }
    std(TMP2, rsp_off, STATE);    // write back new RSP to state
  }

  FillStaticRegs();

  // Jump to dispatcher loop top to run the callback target
  {
    LoadConstant(TMP1, DispatcherLoopTopAddress);
    mtctr(TMP1);
    bctr();
  }

  DispatcherEnd = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  // Generate ABI bridge stubs for all FallbackABI types
  {
    constexpr std::array<FallbackABI, FABI_UNKNOWN> ABIS {{
      FABI_F80_I16_F32_PTR,
      FABI_F80_I16_F64_PTR,
      FABI_F80_I16_I16_PTR,
      FABI_F80_I16_I32_PTR,
      FABI_F32_I16_F80_PTR,
      FABI_F64_I16_F80_PTR,
      FABI_F64_F64_PTR,
      FABI_F64_F64_F64_PTR,
      FABI_I16_I16_F80_PTR,
      FABI_I32_I16_F80_PTR,
      FABI_I64_I16_F80_PTR,
      FABI_I64_I16_F80_F80_PTR,
      FABI_F80_I16_F80_PTR,
      FABI_F80_I16_F80_F80_PTR,
      FABI_F80x2_I16_F80_PTR,
      FABI_F64x2_F64_PTR,
      FABI_I32_I64_I64_V128_V128_I16,
      FABI_I32_V128_V128_I16,
    }};
    for (auto ABI : ABIS) {
      ABIPointers[ABI] = GenerateABICall(ABI);
    }
  }

  // Flush instruction cache for entire generated region
  uint8_t* Start = reinterpret_cast<uint8_t*>(DispatcherBegin);
  uint8_t* End   = GetCursorAddress<uint8_t*>();
  for (uint8_t* p = Start; p < End; p += 32) {
    asm volatile("dcbst 0,%0; sync; icbi 0,%0; isync" :: "r"(p));
  }
}

// ============================================================
// GenerateABICall — emit a PPC64LE ELFv2 bridge stub for one FABI type.
//
// Convention on entry to each stub:
//   VTMP1 (v30) = vector source 1 (for vector/F80 inputs)
//   VTMP2 (v31) = vector source 2 (for binary vector/F80 inputs)
//   TMP2  (r4)  = integer source (sign/zero-extended, for I16/I32 inputs)
//   TMP3  (r5)  = integer source 2 / Control immediate
//   TMP4  (r6)  = Func pointer (the actual C handler to call)
//
// Mini-frame layout (64 bytes, allocated with stdu before SpillForABICall):
//   [r1+ 0]: back chain (old r1)
//   [r1+ 8]: Func pointer save (TMP4, clobbered by SpillStaticRegs NZCV pack)
//   [r1+16]: LR save
//   [r1+24]: integer arg / result save slot
//   [r1+32]: stvx buf1 (16-byte aligned, for float/double <-> VMX conversion)
//   [r1+48]: stvx buf2 (16-byte aligned, for second double)
//
// SpillForABICall lowers r1 by PushDynamicRegs(SaveSize) = 304 bytes for x64
// (32-byte ELFv2 link area + 5 GPRs * 8 = 40 (padded to 48) + 14 VRs * 16 =
// 224, total = 304, 16-aligned).  The 32-byte ELFv2 link area at the bottom
// of the spill frame is mandatory: a typical C++ callee's prologue stores its
// LR via `std r0, 16(r1)` to *its caller's* r1+16, so we must not place a
// register spill there. After the spill, mini-frame slots shift by +304:
//   [r1+312]: Func; [r1+320]: LR; [r1+328]: int save;
//   [r1+336]: buf1; [r1+352]: buf2
//
// ============================================================
uint64_t PPC64Dispatcher::GenerateABICall(FallbackABI ABI) {
  const auto Address = GetCursorAddress<uint64_t>();

  // x64 used literal 304 for kDynRegSaveSize; in x32 mode the spill frame is
  // 496 bytes, so every post-spill mini-frame access must be bitness-aware.
  const bool Is64Bit = CTX->Config.Is64BitMode();
  const int16_t kSpill = static_cast<int16_t>(Is64Bit ? x64::kDynRegSaveSize : x32::kDynRegSaveSize);

  // FCW offset within CPUState (CpuStateFrame::State starts at offset 0)
  const int16_t FCW_off = static_cast<int16_t>(
    offsetof(FEXCore::Core::CPUState, FCW));

  // ----------------------------------------------------------------
  // Helpers emitted inline
  // ----------------------------------------------------------------

  // Allocate mini-frame and save LR. Also stashes TMP4 (=Func pointer) into
  // mini-frame slot [r1+8] because SpillStaticRegs (called inside
  // SpillForABICall) clobbers TMP4 when packing NZCV. Stub bodies must call
  // EmitReloadFunc() after SpillForABICall and before `mtctr(TMP4); bctrl()`.
  auto EmitMiniFrameEnter = [&]() {
    stdu(r1, -64, r1);
    mflr(r(0));
    std(r(0), 16, r1);
    std(TMP4, 8, r1);          // stash Func pointer at mini-frame +8
  };

  // Restore LR, pop mini-frame, return
  auto EmitMiniFrameLeave = [&]() {
    ld(r(0), 16, r1);
    mtlr(r(0));
    addi(r1, r1, 64);
    blr();
  };

  // Reload Func pointer (TMP4) from mini-frame spare slot. After
  // SpillForABICall, r1 has been decremented by 304 (PushDynamicRegs SaveSize
  // for x64) so the original [r1+8] is now at [r1+312].
  // Also copy Func to r12 — PPC64LE ELFv2 mandates the caller passes the
  // callee's global entry point address in r12 so the callee can compute its
  // TOC pointer via the standard `addis r2,r12,...; addi r2,r2,...` prologue.
  auto EmitReloadFunc = [&]() {
    ld(TMP4, static_cast<int16_t>(kSpill + 8), r1);
    mr(r12, TMP4);
  };

  // Extract LE-element-0 float from VTMP1 into f1 (BEFORE SpillForABICall, buf1@[r1+32])
  auto EmitExtractF32FromVTMP1 = [&]() {
    LoadImm32(TMP1, 32);
    stvx(VTMP1, r1, TMP1);   // [r1+32] = VTMP1 (16-byte aligned)
    lfs(f(1), 32, r1);        // f1 = float at LE-element-0 (offset 0 in stvx dump)
  };

  // Extract LE-element-0 double from VTMP1 into f1
  auto EmitExtractF64FromVTMP1 = [&]() {
    LoadImm32(TMP1, 32);
    stvx(VTMP1, r1, TMP1);
    lfd(f(1), 32, r1);
  };

  // Extract LE-element-0 double from VTMP2 into f2
  auto EmitExtractF64FromVTMP2 = [&]() {
    LoadImm32(TMP1, 48);
    stvx(VTMP2, r1, TMP1);
    lfd(f(2), 48, r1);
  };

  // Load FCW into r3 and pass Frame* as second int arg (r4=STATE)
  auto EmitFCW_And_Frame_r4 = [&]() {
    lhz(r3, FCW_off, STATE);
    mr(r4, STATE);
  };

  // Load FCW into r3 and pass Frame* as third int arg (r4 already=src, r5=STATE)
  auto EmitFCW_And_Frame_r5 = [&]() {
    lhz(r3, FCW_off, STATE);
    mr(r5, STATE);
  };

  // PPC64LE ELFv2 parameter-slot accounting for vector args:
  //   * Each non-vector arg consumes one 8-byte slot in the r3-r10 sequence.
  //   * Each FP arg (float/double) consumes one slot AND the next f1-f13 slot.
  //   * Each vector arg consumes 2 slots (16 bytes) AND must be 16-byte aligned
  //     in the parameter area, so it starts at an EVEN slot index. Vector args
  //     also go into v2-v13 in addition to occupying GPR slots.
  // For (uint16 fcw, vec src, Frame*):
  //   slot 0 (r3) = fcw, slot 1 (r4) skipped for vec alignment,
  //   slot 2-3 (r5-r6) consumed by vec (also v2), slot 4 (r7) = Frame.
  auto EmitFCW_VMX1_Frame_r7 = [&]() {
    lhz(r3, FCW_off, STATE);
    vmr(VR{2}, VTMP1);
    mr(r7, STATE);
  };

  // For (uint16 fcw, vec s1, vec s2, Frame*):
  //   r3=fcw, slot 1 skipped, r5-r6=s1 (v2), r7-r8=s2 (v3), r9=Frame.
  auto EmitFCW_VMX2_Frame_r9 = [&]() {
    lhz(r3, FCW_off, STATE);
    vmr(VR{2}, VTMP1);
    vmr(VR{3}, VTMP2);
    mr(r9, STATE);
  };

  // Save VR{2} to VTMP1 then restore all regs (VR{2} is in SRAFPR, clobbered by FillStaticRegs)
  auto FillVec1Result = [&]() {
    vmr(VTMP1, VR{2});
    FillForABICall();
  };

  // Save VR{2}+VR{3} to VTMP1+VTMP2 then restore all regs
  auto FillVec2Result = [&]() {
    vmr(VTMP1, VR{2});
    vmr(VTMP2, VR{3});
    FillForABICall();
  };

  // Save integer result r3 to mini-frame +24 slot (= [r1+328] post-spill),
  // restore regs, load back to TMP1.
  auto FillIntResult = [&]() {
    std(r3, static_cast<int16_t>(kSpill + 24), r1);
    FillForABICall();
    ld(TMP1, 24, r1);
  };

  // f1 result: restore regs, then stfs+lvx to put float in VTMP1
  auto FillF32Result = [&]() {
    FillForABICall();    // r1 = mini_r1; f1 survives (FPR file not touched)
    stfs(f(1), 32, r1);
    addi(TMP1, r1, 32);
    lvx(VTMP1, r(0), TMP1);
  };

  // f1 result: restore regs, then stfd+lvx to put double in VTMP1
  auto FillF64Result = [&]() {
    FillForABICall();
    stfd(f(1), 32, r1);
    addi(TMP1, r1, 32);
    lvx(VTMP1, r(0), TMP1);
  };

  // f1+f2 HFA result: restore regs, put both doubles into VTMP1/VTMP2
  auto FillF64x2Result = [&]() {
    FillForABICall();
    stfd(f(1), 32, r1);
    addi(TMP1, r1, 32);
    lvx(VTMP1, r(0), TMP1);
    stfd(f(2), 48, r1);
    addi(TMP1, r1, 48);
    lvx(VTMP2, r(0), TMP1);
  };

  // ----------------------------------------------------------------
  // Per-FABI stub code
  // ----------------------------------------------------------------
  switch (ABI) {

  case FABI_F80_I16_F32_PTR: {
    // C sig: VectorRegType handle(uint16_t FCW, float src, CpuStateFrame*)
    // PPC64LE ELFv2: arg1 int (FCW)→r3, arg2 float→f1 (and SKIPS r4 in the
    // GPR sequence), arg3 ptr (Frame)→r5.
    EmitMiniFrameEnter();
    EmitExtractF32FromVTMP1();   // f1 = float, before spill
    SpillForABICall(TMP1);
    EmitFCW_And_Frame_r5();      // r3=FCW, r5=Frame*; f1 already set
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec1Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F80_I16_F64_PTR: {
    // C sig: VectorRegType handle(uint16_t FCW, double src, CpuStateFrame*)
    // PPC64LE ELFv2: r3=FCW, f1=src(double), r5=Frame* (r4 skipped).
    EmitMiniFrameEnter();
    EmitExtractF64FromVTMP1();   // f1 = double, before spill
    SpillForABICall(TMP1);
    EmitFCW_And_Frame_r5();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec1Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F80_I16_I16_PTR:
  case FABI_F80_I16_I32_PTR: {
    // C sig: VectorRegType handle(uint16_t FCW, int16/32_t src, CpuStateFrame*)
    // r3=FCW, r4=src(in TMP2=r4, survives spill), r5=Frame*  → ret VR{2}
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);       // TMP2=r4 unchanged; TMP1=r3 clobbered
    EmitFCW_And_Frame_r5();      // r3=FCW, r5=Frame*; r4=src already set by JIT
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec1Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F32_I16_F80_PTR: {
    // C sig: float handle(uint16_t FCW, VectorRegType src, CpuStateFrame*)
    // r3=FCW, v2=src(VTMP1), r4=Frame*  → ret f1
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX1_Frame_r7();     // r3=FCW, v2=VTMP1, r4=Frame*
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillF32Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F64_I16_F80_PTR: {
    // C sig: double handle(uint16_t FCW, VectorRegType src, CpuStateFrame*)
    // r3=FCW, v2=src(VTMP1), r4=Frame*  → ret f1
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX1_Frame_r7();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillF64Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F64_F64_PTR: {
    // C sig: double handle(double src, CpuStateFrame*)
    // PPC64LE ELFv2: each FP arg also consumes one GPR slot.
    // f1=src(from VTMP1), r4=Frame* (r3 skipped by double arg)  → ret f1
    EmitMiniFrameEnter();
    EmitExtractF64FromVTMP1();   // f1 = double, before spill
    SpillForABICall(TMP1);
    mr(r4, STATE);               // r4=Frame*; f1 already set
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillF64Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F64_F64_F64_PTR: {
    // C sig: double handle(double src1, double src2, CpuStateFrame*)
    // f1=src1(VTMP1), f2=src2(VTMP2), r5=Frame* (r3,r4 skipped by 2 doubles)
    EmitMiniFrameEnter();
    EmitExtractF64FromVTMP1();   // f1 = double 1
    EmitExtractF64FromVTMP2();   // f2 = double 2
    SpillForABICall(TMP1);
    mr(r5, STATE);
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillF64Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_I16_I16_F80_PTR:
  case FABI_I32_I16_F80_PTR:
  case FABI_I64_I16_F80_PTR: {
    // C sig: int16/32/64_t handle(uint16_t FCW, VectorRegType src, CpuStateFrame*)
    // r3=FCW, v2=src(VTMP1), r4=Frame*  → ret r3
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX1_Frame_r7();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillIntResult();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_I64_I16_F80_F80_PTR: {
    // C sig: uint64_t handle(uint16_t FCW, VectorRegType s1, VectorRegType s2, CpuStateFrame*)
    // r3=FCW, v2=VTMP1, v3=VTMP2, r4=Frame*  → ret r3
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX2_Frame_r9();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillIntResult();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F80_I16_F80_PTR: {
    // C sig: VectorRegType handle(uint16_t FCW, VectorRegType src, CpuStateFrame*)
    // r3=FCW, v2=VTMP1, r4=Frame*  → ret VR{2}
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX1_Frame_r7();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec1Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F80_I16_F80_F80_PTR: {
    // C sig: VectorRegType handle(uint16_t FCW, VectorRegType s1, VectorRegType s2, CpuStateFrame*)
    // r3=FCW, v2=VTMP1, v3=VTMP2, r4=Frame*  → ret VR{2}
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX2_Frame_r9();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec1Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F80x2_I16_F80_PTR: {
    // C sig: VectorRegPairType handle(uint16_t FCW, VectorRegType src, CpuStateFrame*)
    // r3=FCW, v2=VTMP1, r4=Frame*  → HVA ret: VR{2}+VR{3}
    EmitMiniFrameEnter();
    SpillForABICall(TMP1);
    EmitFCW_VMX1_Frame_r7();
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillVec2Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_F64x2_F64_PTR: {
    // C sig: VectorScalarF64Pair handle(double src, CpuStateFrame*)
    // PPC64LE ELFv2: double src → f1 (consumes slot 0 = r3 in the GPR
    // sequence), Frame* → slot 1 = r4. (Same arg layout as FABI_F64_F64_PTR.)
    EmitMiniFrameEnter();
    EmitExtractF64FromVTMP1();
    SpillForABICall(TMP1);
    mr(r4, STATE);              // r4 = Frame* (r3 skipped by double arg)
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillF64x2Result();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_I32_I64_I64_V128_V128_I16: {
    // C sig: int32_t handle(int64_t RAX, int64_t RDX, VectorRegType LHS,
    //                       VectorRegType RHS, uint16_t Control, CpuStateFrame*)
    // PPC64LE ELFv2 slot accounting (vectors align to even slot indices and
    // consume 2 slots each):
    //   slot 0=RAX→r3, slot 1=RDX→r4, slot 2-3=LHS(v2,r5-r6),
    //   slot 4-5=RHS(v3,r7-r8), slot 6=Control→r9, slot 7=Frame→r10.
    // JIT stages: TMP1(r3)=RAX, TMP2(r4)=RDX, TMP3(r5)=Control(low 16),
    // VTMP1=LHS, VTMP2=RHS, TMP4(r6)=Func.
    EmitMiniFrameEnter();        // stashes TMP4(Func) to mini-frame +8
    std(r3, 24, r1);             // save RAX to [mini_r1+24]
    std(TMP2, 32+8, r1);         // save RDX to mini-frame +40 (overlaps buf1
                                 // upper half; we don't use it before reload)
    std(TMP3, 48+8, r1);         // save Control to mini-frame +56 (overlaps
                                 // buf2 upper half; safe — no buf2 use here)
    SpillForABICall(TMP1);
    EmitReloadFunc();
    ld(r3, static_cast<int16_t>(kSpill + 24), r1);       // RAX
    ld(r4, static_cast<int16_t>(kSpill + 40), r1);       // RDX (mini-frame +40)
    vmr(VR{2}, VTMP1);           // v2 = LHS  (and r5-r6 reserved)
    vmr(VR{3}, VTMP2);           // v3 = RHS  (and r7-r8 reserved)
    ld(r9, static_cast<int16_t>(kSpill + 56), r1);       // Control (mini-frame +56)
    mr(r10, STATE);              // r10 = Frame*
    mtctr(TMP4); bctrl();
    FillIntResult();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_I32_V128_V128_I16: {
    // C sig: int32_t handle(uint16_t Control, VectorRegType LHS, VectorRegType RHS)
    // PPC64LE ELFv2 slots: slot 0=Control→r3, slot 1 skipped (vec align),
    //   slot 2-3=LHS(v2,r5-r6), slot 4-5=RHS(v3,r7-r8). No Frame* arg.
    EmitMiniFrameEnter();        // stashes TMP4(Func) to mini-frame +8
    std(r3, 24, r1);             // save Control to [mini_r1+24]
    SpillForABICall(TMP1);
    vmr(VR{2}, VTMP1);           // v2 = LHS
    vmr(VR{3}, VTMP2);           // v3 = RHS
    ld(r3, static_cast<int16_t>(kSpill + 24), r1);       // Control
    EmitReloadFunc();
    mtctr(TMP4); bctrl();
    FillIntResult();
    EmitMiniFrameLeave();
    break;
  }

  case FABI_UNKNOWN:
  default:
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
    LOGMAN_MSG_A_FMT("Unhandled FABI type: {}", ToUnderlying(ABI));
#endif
    blr();
    break;
  }

  return Address;
}

FEXCore::SignalDelegatorConfig PPC64Dispatcher::MakeSignalDelegatorConfig() const {
  const bool Is64Bit = CTX->Config.Is64BitMode();
  const std::span<const GPR> SRA    = Is64Bit ? std::span<const GPR>(x64::SRA)    : std::span<const GPR>(x32::SRA);
  const std::span<const VR>  SRAFPR = Is64Bit ? std::span<const VR>(x64::SRAFPR) : std::span<const VR>(x32::SRAFPR);

  // PF and AF are the final two entries in the SRA GPR table — exclude them
  // from the count (they're not x86 architectural registers).
  const auto GPRCount = static_cast<uint16_t>(SRA.size() - 2);
  const auto FPRCount = static_cast<uint16_t>(SRAFPR.size());

  SignalDelegatorConfig::SRAIndexMapping GPRMapping {};
  for (size_t i = 0; i < GPRCount; i++) {
    GPRMapping[i] = SRA[i].idx;
  }

  SignalDelegatorConfig::SRAIndexMapping FPRMapping {};
  for (size_t i = 0; i < FPRCount; i++) {
    FPRMapping[i] = SRAFPR[i].idx;
  }

  return FEXCore::SignalDelegatorConfig {
    .DispatcherBegin = DispatcherBegin,
    .DispatcherEnd   = DispatcherEnd,

    .AbsoluteLoopTopAddress        = DispatcherLoopTopAddress,
    .AbsoluteLoopTopAddressFillSRA = DispatcherLoopTopFillSRAAddress,
    .SignalHandlerReturnAddress     = SignalHandlerReturnAddress,
    .SignalHandlerReturnAddressRT   = SignalHandlerReturnAddress,  // same on ppc64le

    .PauseReturnInstruction            = PauseReturnInstruction,
    .ThreadPauseHandlerAddressSpillSRA = ThreadPauseHandlerAddressSpillSRA,
    .ThreadPauseHandlerAddress         = ThreadPauseHandlerAddress,

    .ThreadStopHandlerAddressSpillSRA = ThreadStopHandlerAddressSpillSRA,
    .ThreadStopHandlerAddress         = ThreadStopHandlerAddress,

    .SRAGPRCount = GPRCount,
    .SRAFPRCount = FPRCount,

    .SRAGPRMapping = GPRMapping,
    .SRAFPRMapping = FPRMapping,
  };
}

} // namespace FEXCore::CPU
