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
#include "Interface/Core/Interpreter/InterpreterOps.h"

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/EnumUtils.h>
#include <FEXCore/Utils/LogManager.h>

#include <cstring>
#include <sys/mman.h>

namespace {
// Called from the pause handler: park the current thread until it is woken.
static void SleepThread(FEXCore::Context::ContextImpl* CTX, FEXCore::Core::CpuStateFrame* Frame) {
  CTX->SyscallHandler->SleepThread(CTX, Frame);
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
  Ptrs.ThreadStopHandlerSpillSRA = ThreadStopHandlerAddress;
  Ptrs.ThreadPauseHandlerSpillSRA = ThreadPauseHandlerAddressSpillSRA;
  Ptrs.GuestSignal_SIGILL        = GuestSignal_SIGILL_Address;
  Ptrs.GuestSignal_SIGTRAP       = GuestSignal_SIGTRAP_Address;
  Ptrs.GuestSignal_SIGSEGV       = GuestSignal_SIGSEGV_Address;
  Ptrs.SignalReturnHandler       = SignalHandlerReturnAddress;
  Ptrs.SignalReturnHandlerRT     = SignalHandlerReturnAddress;

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
  DispatcherLoopTopFillSRAAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  FillStaticRegs();

  // Fall through into DispatcherLoopTop

  // ==============================================================
  // DispatcherLoopTop: entered with SRA registers filled, STATE valid.
  // Load RIP, do L1 lookup, branch to JIT block or slow path.
  // ==============================================================
  DispatcherLoopTopAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  {
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

    // Load L1Entry: {HostCode (8 bytes), GuestCode (8 bytes)}
    ld(TMP3, 0, TMP2);   // TMP3 = HostCode
    ld(TMP4, 8, TMP2);   // TMP4 = GuestCode

    // Compare GuestCode with current RIP — into CR7, NOT CR0.
    //
    // Why: SpillStaticRegs (called below in ExitFunctionLinker on L1 miss)
    // packs CR0 + XER into flags[RFLAG_NZCV_LOC] as the canonical NZCV
    // storage for cross-block transfer. If we used the default CR0 here,
    // any L1 miss would overwrite the correct (just-spilled-by-the-JIT-
    // block's-ExitFunction) NZCV with garbage from this lookup compare.
    // Symptom was a phantom SF=1 (and sometimes ZF=1) appearing in PUSHF
    // / LAHF after popfq=0 across ~25 ASM tests (Primary_9C/9D/84/85,
    // ShiftZeroFlagsUpdate, InitialPFFlag, BLSI_flags, etc.). Running
    // cmpd into CR7 leaves CR0 as set by FillStaticRegs.
    cmpd(cr(7), TMP4, TMP1);

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
    // Fast path: JIT block found, jump to it.
    mtctr(TMP3);
    li(r(0), 0);  // JIT blocks use r0=0 as zero index for ldx/stdx
    bctr();
  }

  // ==============================================================
  // ExitFunctionLinker — slow path when L1 cache misses.
  // Calls the C++ FindBlock / compile path, then re-dispatches.
  // ==============================================================
  ExitFunctionLinkerAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  {
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

    // Block not found/compilable: fall through to ThreadStopHandler
    {
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
    li(r(0), 0);  // JIT blocks use r0=0 as zero index for ldx/stdx
    bctr();
  }

  // ==============================================================
  // ThreadStopHandler — unwind JIT and return to C++ caller
  // ==============================================================
  ThreadStopHandlerAddress = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());

  SpillStaticRegs(TMP1);
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
  // Guest signal stubs — store fault data and unwind
  // ==============================================================
  GuestSignal_SIGILL_Address = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);
  PopCalleeSavedRegisters();
  blr();

  GuestSignal_SIGTRAP_Address = reinterpret_cast<uint64_t>(GetCursorAddress<uint8_t*>());
  SpillStaticRegs(TMP1);
  PopCalleeSavedRegisters();
  blr();

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

  PushCalleeSavedRegisters();
  mr(STATE, r3);

  // Save target RIP (r4) early — subsequent operations need r4 as scratch.
  {
    int32_t rip_off = static_cast<int32_t>(offsetof(CpuStateFrame, State.rip));
    // 32-bit guest: clamp the callback target RIP to 32 bits.
    MaybeClrUpper32(r4);
    std(r4, rip_off, STATE);
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
  // Mirrors the ARM64 dispatcher: decrement guest RSP by 16 (maintains
  // x86-64 stack alignment), store ThunkCallbackRet at [new_RSP+0].
  // CallbackReturn subsequently does RSP += 8 to undo the net -8 effect.
  {
    int32_t ret_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, Pointers.ThunkCallbackRet));
    int32_t rsp_off = static_cast<int32_t>(
      offsetof(CpuStateFrame, State.gregs[FEXCore::X86State::REG_RSP]));
    ld(TMP1, ret_off, STATE);     // TMP1 = ThunkCallbackRet (guest x86 VA)
    ld(TMP2, rsp_off, STATE);     // TMP2 = guest RSP
    addi(TMP2, TMP2, -16);        // RSP -= 16 (stack grows down, 16-byte align)
    std(TMP1, 0, TMP2);           // [RSP+0] = ThunkCallbackRet
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

    .ThreadStopHandlerAddressSpillSRA = ThreadStopHandlerAddress,
    .ThreadStopHandlerAddress         = ThreadStopHandlerAddress,

    .SRAGPRCount = GPRCount,
    .SRAFPRCount = FPRCount,

    .SRAGPRMapping = GPRMapping,
    .SRAFPRMapping = FPRMapping,
  };
}

} // namespace FEXCore::CPU
