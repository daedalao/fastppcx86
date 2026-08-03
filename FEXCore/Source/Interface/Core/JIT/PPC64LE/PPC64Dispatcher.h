// SPDX-License-Identifier: MIT
// PPC64LE JIT dispatcher — entry/exit glue between native code and JIT blocks.
#pragma once

#include "Interface/Core/ArchHelpers/PPC64Emitter.h"
#include "Interface/Core/Interpreter/InterpreterOps.h"

#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/fextl/memory.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <unistd.h>

namespace FEXCore::Core {
struct InternalThreadState;
struct CpuStateFrame;
} // namespace FEXCore::Core

namespace FEXCore::Context {
class ContextImpl;
} // namespace FEXCore::Context

namespace FEXCore::CPU {

class PPC64Dispatcher final : public PPC64EmitterBase {
public:
  static fextl::unique_ptr<PPC64Dispatcher>
  Create(FEXCore::Context::ContextImpl* CTX);

  explicit PPC64Dispatcher(FEXCore::Context::ContextImpl* CTX);

  void InitThreadPointers(FEXCore::Core::InternalThreadState* Thread);

  // Build the SignalDelegatorConfig from the generated dispatcher addresses.
  FEXCore::SignalDelegatorConfig MakeSignalDelegatorConfig() const;

  // Called from native code to enter JIT execution.
  void ExecuteDispatch(FEXCore::Core::CpuStateFrame* Frame, bool SingleInst = false) {
    DispatchPtr(Frame, SingleInst);
  }

  // Called for JIT callbacks (signal handler callbacks etc.)
  void ExecuteJITCallback(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP) {
    CallbackPtr(Frame, RIP);
  }

  uint64_t GetExitFunctionLinkerAddress() const {
    return ExitFunctionLinkerAddress;
  }

  // Address of the block-linking dispatcher stub. Read at CompileCode time
  // when the thunk record is emitted and written into PPC64BlockLinkRecord::
  // StubAddr, so the thunk's LinkPath ld reads it off the record instead of
  // through a per-thread CpuStateFrame::Pointers slot (that slot was retired
  // to keep InternalThreadState within its 2-page budget after C4.5/C6/C7
  // consumed the remaining headroom in CpuStateFrame).
  uint64_t GetExitFunctionLinkerWithRecordAddress() const {
    return ExitFunctionLinkerWithRecordAddress;
  }

private:
  FEXCore::Context::ContextImpl* CTX;

  using AsmDispatch = void (*)(FEXCore::Core::CpuStateFrame* Frame, bool SingleInst);
  using JITCallback = void (*)(FEXCore::Core::CpuStateFrame* Frame, uint64_t RIP);

  AsmDispatch DispatchPtr {};
  JITCallback CallbackPtr {};

  // Code range of the dispatcher (for IsAddressInDispatcher)
  uint64_t DispatcherBegin {};
  uint64_t DispatcherEnd   {};

  // Dispatcher loop top: entered with SRA already filled.
  uint64_t DispatcherLoopTopAddress {};
  // Fill-SRA entry: emits FillStaticRegs and falls through to DispatcherLoopTop.
  // Signal-return paths land here so SRA is reloaded from Frame->State.
  uint64_t DispatcherLoopTopFillSRAAddress {};

  // Exit / link path
  uint64_t ExitFunctionLinkerAddress {};
  // Block-linking variant: entered from a link thunk's LinkPath leg with
  // r4 = &PPC64BlockLinkRecord and SRA already spilled by the JIT block.
  uint64_t ExitFunctionLinkerWithRecordAddress {};

  // Thread stop: pop callee-saved regs, blr.
  //   *SpillSRA entry runs SpillStaticRegs first (thread was in JIT);
  //   *Address entry skips the spill (thread was in host C++, SRA already
  //   saved by whatever pushed it onto STATE).
  uint64_t ThreadStopHandlerAddressSpillSRA {};
  uint64_t ThreadStopHandlerAddress {};

  // Thread pause: spill SRA, call SleepThread, then illegal-instruction trap
  uint64_t ThreadPauseHandlerAddressSpillSRA {};
  uint64_t ThreadPauseHandlerAddress {};
  uint64_t PauseReturnInstruction {};

  // Signal return handler addresses. Two distinct sentinel words: the
  // non-RT and RT sigreturn paths call different function pointers so
  // HandleSIGILL can distinguish RestoreType::TYPE_NONREALTIME from
  // TYPE_REALTIME by comparing ucontext PC. Aliasing them caused every
  // signal return to be torn down as REALTIME regardless of which frame
  // was actually built -- a 64-bit-multithreaded-workload crasher
  // (surfaced by Factorio 2026-07-31, LR pointing at
  // HandleSignalHandlerReturn(RT=true) on the SIGILL). Mirrors ARM64
  // Dispatcher.cpp:379,387 which emits two hlt(0) sentinels.
  uint64_t SignalHandlerReturnAddress {};
  uint64_t SignalHandlerReturnAddressRT {};

  // Guest signal stubs
  uint64_t GuestSignal_SIGILL_Address {};
  uint64_t GuestSignal_SIGTRAP_Address {};
  uint64_t GuestSignal_SIGSEGV_Address {};

  void EmitDispatcher();

  // ABI bridge stub addresses (one per FallbackABI type)
  std::array<uint64_t, FallbackABI::FABI_UNKNOWN> ABIPointers {};

  // Generate an ABI bridge stub for the given FallbackABI type.
  // Returns the address of the generated stub.
  uint64_t GenerateABICall(FallbackABI ABI);
};

} // namespace FEXCore::CPU
