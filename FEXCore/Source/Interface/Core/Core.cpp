// SPDX-License-Identifier: MIT
/*
$info$
category: glue ~ Logic that binds various parts together
meta: glue|driver ~ Emulation mainloop related glue logic
tags: glue|driver
desc: Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint
$end_info$
*/

#include <cstdint>
#ifdef ZYDIS_DISASSEMBLER
#include <Zydis/Zydis.h>
#endif
#ifndef ARCHITECTURE_ppc64le
#include "Interface/Core/ArchHelpers/Arm64Emitter.h"
#endif
#include "Interface/Core/LookupCache.h"
#include "Interface/Core/SMCSoftInvalidate.h"
#include "Interface/Core/SMCSemanticPatch.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/CPUID.h"
#include "Interface/Core/Frontend.h"
#include "Interface/Core/OpcodeDispatcher.h"
#ifdef ARCHITECTURE_ppc64le
#include "Interface/Core/JIT/PPC64LE/JITClass.h"
#include "Interface/Core/JIT/PPC64LE/PPC64Dispatcher.h"
#else
#include "Interface/Core/JIT/JITClass.h"
#include "Interface/Core/Dispatcher/Dispatcher.h"
#endif
#include "Interface/Core/X86Tables/X86Tables.h"
#include <Interface/GDBJIT/GDBJIT.h>
#include "Interface/IR/IR.h"
#include "Interface/IR/IREmitter.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"
#include "Interface/IR/Passes.h"
#include "Interface/IR/PassManager.h"
#include "Interface/IR/RegisterAllocationData.h"
#include "Utils/Allocator.h"
#include "Utils/Allocator/HostAllocator.h"
#include <FEXCore/Utils/SpinWaitLock.h>
#include "Utils/variable_length_integer.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/Event.h>
#include <FEXCore/Utils/File.h>
#include <FEXCore/Utils/LogManager.h>
#include "FEXCore/Utils/SignalScopeGuards.h"
#include <FEXCore/Utils/Threads.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <queue>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <xxhash.h>

// FEX_SMC_AUDIT compile-side sibling of the logger in SyscallsSMCTracking.cpp
// (same env var, same file, opened O_APPEND so lines from both interleave).
static int SMCAuditCompileFD() {
  static int fd = [] {
    const char* p = getenv("FEX_SMC_AUDIT");
    if (!p) {
      return -1;
    }
    return ::open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
  }();
  return fd;
}

namespace FEXCore::Context {
// SpinLoopClamp spec: "0x<begin>-0x<end>:<induction>:<bound>", registers by
// x86 name. Any malformed field returns false so a typo disables the hack
// entirely rather than half-applying it. Does not set Out.Active.
static bool ParseSpinLoopClamp(std::string_view Spec, ContextImpl::SpinLoopClampInfo& Out) {
  static constexpr std::array<std::string_view, 16> RegNames = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                                                "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
  auto RegIndex = [&](std::string_view Name) -> int {
    for (size_t i = 0; i < RegNames.size(); ++i) {
      if (Name == RegNames[i]) {
        return static_cast<int>(i);
      }
    }
    return -1;
  };
  auto ParseAddr = [](std::string_view Field, uint64_t& Value) {
    const fextl::string Copy {Field};
    char* End {};
    Value = std::strtoull(Copy.c_str(), &End, 0);
    return !Copy.empty() && *End == '\0';
  };

  const size_t Dash = Spec.find('-');
  const size_t Colon1 = Spec.find(':');
  const size_t Colon2 = Colon1 == Spec.npos ? Spec.npos : Spec.find(':', Colon1 + 1);
  if (Dash == Spec.npos || Colon1 == Spec.npos || Colon2 == Spec.npos || Dash > Colon1) {
    return false;
  }

  uint64_t Begin {}, End {};
  if (!ParseAddr(Spec.substr(0, Dash), Begin) || !ParseAddr(Spec.substr(Dash + 1, Colon1 - Dash - 1), End)) {
    return false;
  }
  const int Induction = RegIndex(Spec.substr(Colon1 + 1, Colon2 - Colon1 - 1));
  const int Bound = RegIndex(Spec.substr(Colon2 + 1));
  if (Induction < 0 || Bound < 0 || Induction == Bound || Begin >= End) {
    return false;
  }

  Out.Begin = Begin;
  Out.End = End;
  Out.InductionReg = static_cast<uint8_t>(Induction);
  Out.BoundReg = static_cast<uint8_t>(Bound);
  return true;
}

ContextImpl::ContextImpl(const FEXCore::HostFeatures& Features)
  : HostFeatures {Features}
  , CPUID {this}
  , CodeCache {*this} {
  if (!Config.Is64BitMode()) {
    // When operating in 32-bit mode, the virtual memory we care about is only the lower 32-bits.
    Config.VirtualMemSize = 1ULL << 32;
  }

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Only initialize symbols file if enabled. Ensures we don't pollute /tmp with empty files.
    Symbols.InitFile();
  }

  uint64_t FrequencyCounter = FEXCore::GetCycleCounterFrequency();
  if (FrequencyCounter && FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM && Config.SmallTSCScale()) {
    // Scale TSC until it is at the minimum required.
    while (FrequencyCounter < FEXCore::Context::TSC_SCALE_MAXIMUM) {
      FrequencyCounter <<= 1;
      ++Config.TSCScale;
    }
  }

  // Track atomic TSO emulation configuration.
  UpdateAtomicTSOEmulationConfig();

  // SMC Idea 3: the code-granule bitmap exists purely to accelerate the SMC
  // store fast paths, so it is gated on exactly the flags that consult it -- no
  // new flag of its own. With all three off nothing is allocated and no reader
  // ever looks at it. This must be decided here, before the first CodeBuffer
  // (and therefore the first GuestToHostMap) is created; see the constructor in
  // Interface/Core/LookupCache.cpp for why it can never be switched on later.
  if (Config.SMCStoreEmulation() || Config.SMCStoreBackpatch() || Config.SMCSemanticPatch()) {
    FEXCore::SMC::CodeGranuleTrackingEnabled.store(true, std::memory_order_release);
  }

  // Spin-loop overshoot clamp; see SpinLoopClampInfo in Context.h.
  if (const fextl::string Spec = Config.SpinLoopClamp(); !Spec.empty()) {
    if (ParseSpinLoopClamp(Spec, SpinLoopClamp)) {
      SpinLoopClamp.Active = true;
      LogMan::Msg::IFmt("SpinLoopClamp active: RIP [0x{:x}, 0x{:x}), induction GPR {}, bound GPR {}", SpinLoopClamp.Begin,
                        SpinLoopClamp.End, SpinLoopClamp.InductionReg, SpinLoopClamp.BoundReg);
    } else {
      LogMan::Msg::EFmt("SpinLoopClamp: failed to parse '{}'; hack disabled", Spec);
    }
  }
}

struct GetFrameBlockInfoResult {
  const CPU::CPUBackend::JITCodeHeader* InlineHeader;
  const CPU::CPUBackend::JITCodeTail* InlineTail;
};
static GetFrameBlockInfoResult GetFrameBlockInfo(FEXCore::Core::CpuStateFrame* Frame) {
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto InlineHeader = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(BlockBegin);

  if (InlineHeader) {
    auto InlineTail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail);
    return {InlineHeader, InlineTail};
  }

  return {InlineHeader, nullptr};
}

bool ContextImpl::IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && (Address + Size > InlineTail->RIP && Address < InlineTail->RIP + InlineTail->GuestSize);
}

bool ContextImpl::IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail && InlineTail->SingleInst;
}

uint64_t ContextImpl::GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) {
  auto [_, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);
  return InlineTail ? InlineTail->RIP : 0;
}

uint64_t ContextImpl::RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) {
  const auto Frame = Thread->CurrentFrame;
  const uint64_t BlockBegin = Frame->State.InlineJITBlockHeader;
  auto [InlineHeader, InlineTail] = GetFrameBlockInfo(Thread->CurrentFrame);

  if (InlineHeader) {
    // Check if the host PC is currently within a code block.
    // If it is then RIP can be reconstructed from the beginning of the code block.
    // This is currently as close as FEX can get RIP reconstructions.
    if (HostPC >= reinterpret_cast<uint64_t>(BlockBegin) && HostPC < reinterpret_cast<uint64_t>(BlockBegin + InlineTail->Size)) {

      // If the block did not emit a per-instruction RIP table, fall through
      // to Frame->State.rip. Without this guard the reconstruction would
      // return the block-entry RIP, which is coarser than the syscall-site
      // RIP that Frame->State.rip already stores today (SeccompEmulator
      // reads .instruction_pointer via this path). Header-only blocks —
      // e.g. blocks with no CanHaveSideEffects IR ops that would emit
      // GuestOpcode markers — hit this branch. (Ppc64le emits entries since
      // P3.1 landed as 244075383; the old comment claiming otherwise was
      // stale, per P5.0 review.)
      if (InlineTail->NumberOfRIPEntries == 0) {
        return Frame->State.rip;
      }

      auto RIPEntry =
        reinterpret_cast<const uint8_t*>(Frame->State.InlineJITBlockHeader + InlineHeader->OffsetToBlockTail + InlineTail->OffsetToRIPEntries);

      // Reconstruct RIP from JIT entries for this block.
      uint64_t StartingHostPC = BlockBegin;
      uint64_t StartingGuestRIP = InlineTail->RIP;

      for (uint32_t i = 0; i < InlineTail->NumberOfRIPEntries; ++i) {
        auto Offset = FEXCore::Utils::vl64pair::Decode(RIPEntry);
        RIPEntry += Offset.Size;
        if (HostPC >= (StartingHostPC + Offset.IntegerARMPC)) {
          // We are beyond this entry, keep going forward.
          StartingHostPC += Offset.IntegerARMPC;
          StartingGuestRIP += Offset.IntegerX86RIP;
        } else {
          // Passed where the Host PC is at. Break now.
          break;
        }
      }
      return StartingGuestRIP;
    }
  }

  // Fallback to what is stored in the RIP currently.
  return Frame->State.rip;
}

uint32_t ContextImpl::ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs,
                                                 uint64_t PSTATE) {
  const auto Frame = Thread->CurrentFrame;
  uint32_t EFLAGS {};

  // Currently these flags just map 1:1 inside of the resulting value.
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_PF_RAW_LOC:
    case X86State::RFLAG_AF_RAW_LOC:
    case X86State::RFLAG_TF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_DF_RAW_LOC:
      // Intentionally do nothing.
      // These contain multiple bits which can corrupt other members when compacted.
      break;
    default: EFLAGS |= uint32_t {Frame->State.flags[i]} << i; break;
    }
  }

  uint32_t Packed_NZCV {};
  if (WasInJIT) {
    // If we were in the JIT then NZCV is in the CPU's PSTATE object.
    // Packed in to the same bit locations as RFLAG_NZCV_LOC.
    Packed_NZCV = PSTATE;

    // If we were in the JIT then PF and AF are in registers.
    // Move them to the CPUState frame now.
    Frame->State.pf_raw = HostGPRs[CPU::REG_PF.Idx()];
    Frame->State.af_raw = HostGPRs[CPU::REG_AF.Idx()];
  } else {
    // If we were not in the JIT then the NZCV state is stored in the CPUState RFLAG_NZCV_LOC.
    // SF/ZF/CF/OF are packed in a 32-bit value in RFLAG_NZCV_LOC.
    memcpy(&Packed_NZCV, &Frame->State.flags[X86State::RFLAG_NZCV_LOC], sizeof(Packed_NZCV));
  }

  uint32_t OF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC)) & 1;
  uint32_t CF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC)) & 1;
  uint32_t ZF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC)) & 1;
  uint32_t SF = (Packed_NZCV >> IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC)) & 1;

  // CF is inverted in our representation, undo the invert here.
  CF ^= 1;

  // Pack in to EFLAGS
  EFLAGS |= OF << X86State::RFLAG_OF_RAW_LOC;
  EFLAGS |= CF << X86State::RFLAG_CF_RAW_LOC;
  EFLAGS |= ZF << X86State::RFLAG_ZF_RAW_LOC;
  EFLAGS |= SF << X86State::RFLAG_SF_RAW_LOC;

  // PF calculation is deferred, calculate it now.
  // Popcount the 8-bit flag and then extract the lower bit.
  uint32_t PFByte = Frame->State.pf_raw & 0xff;
  uint32_t PF = std::popcount(PFByte ^ 1) & 1;
  EFLAGS |= PF << X86State::RFLAG_PF_RAW_LOC;

  // AF calculation is deferred, calculate it now.
  // XOR with PF byte and extract bit 4.
  uint32_t AF = ((Frame->State.af_raw ^ PFByte) & (1 << 4)) ? 1 : 0;
  EFLAGS |= AF << X86State::RFLAG_AF_RAW_LOC;

  uint8_t TFByte = Frame->State.flags[X86State::RFLAG_TF_RAW_LOC];
  EFLAGS |= (TFByte & 1) << X86State::RFLAG_TF_RAW_LOC;

  // DF is pretransformed, undo the transform from 1/-1 back to 0/1
  uint8_t DFByte = Frame->State.flags[X86State::RFLAG_DF_RAW_LOC];
  if (DFByte & 0x80) {
    EFLAGS |= 1 << X86State::RFLAG_DF_RAW_LOC;
  }

  return EFLAGS;
}

void ContextImpl::ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;

  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.avx.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.xmm.avx.data[i][2], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&XMM_Low[i], &Thread->CurrentFrame->State.xmm.sse.data[i][0], sizeof(__uint128_t));
        memcpy(&YMM_High[i], &Thread->CurrentFrame->State.avx_high[i][0], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(XMM_Low, Thread->CurrentFrame->State.xmm.sse.data, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) {
  const size_t MaximumRegisters = Config.Is64BitMode ? FEXCore::Core::CPUState::NUM_XMMS : 8;
  if (YMM_High != nullptr && HostFeatures.SupportsAVX) {
    const bool SupportsConvergedRegisters = HostFeatures.SupportsSVE256;

    if (SupportsConvergedRegisters) {
      ///< Output wants to de-interleave
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][2], &YMM_High[i], sizeof(__uint128_t));
      }
    } else {
      ///< Matches what FEX wants with non-converged registers
      for (size_t i = 0; i < MaximumRegisters; ++i) {
        memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &XMM_Low[i], sizeof(__uint128_t));
        memcpy(&Thread->CurrentFrame->State.avx_high[i][0], &YMM_High[i], sizeof(__uint128_t));
      }
    }
  } else {
    // Only support SSE, no AVX here, even if requested.
    memcpy(Thread->CurrentFrame->State.xmm.sse.data, XMM_Low, MaximumRegisters * sizeof(__uint128_t));
  }
}

void ContextImpl::SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) {
  const auto Frame = Thread->CurrentFrame;
  for (size_t i = 0; i < FEXCore::Core::CPUState::NUM_EFLAG_BITS; ++i) {
    switch (i) {
    case X86State::RFLAG_OF_RAW_LOC:
    case X86State::RFLAG_CF_RAW_LOC:
    case X86State::RFLAG_ZF_RAW_LOC:
    case X86State::RFLAG_SF_RAW_LOC:
      // Intentionally do nothing.
      break;
    case X86State::RFLAG_AF_RAW_LOC:
      // AF stored in bit 4 in our internal representation. It is also
      // XORed with byte 4 of the PF byte, but we write that as zero here so
      // we don't need any special handling for that.
      Frame->State.af_raw = (EFLAGS & (1U << i)) ? (1 << 4) : 0;
      break;
    case X86State::RFLAG_PF_RAW_LOC:
      // PF is inverted in our internal representation.
      Frame->State.pf_raw = (EFLAGS & (1U << i)) ? 0 : 1;
      break;
    case X86State::RFLAG_DF_RAW_LOC:
      // DF is encoded as 1/-1
      Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 0xff : 1;
      break;
    default: Frame->State.flags[i] = (EFLAGS & (1U << i)) ? 1 : 0; break;
    }
  }

  // Calculate packed NZCV. Note CF is inverted.
  uint32_t Packed_NZCV {};
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_OF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_OF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_CF_RAW_LOC)) ? 0 : 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_CF_RAW_LOC);
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_ZF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_ZF_RAW_LOC) : 0;
  Packed_NZCV |= (EFLAGS & (1U << X86State::RFLAG_SF_RAW_LOC)) ? 1U << IR::OpDispatchBuilder::IndexNZCV(X86State::RFLAG_SF_RAW_LOC) : 0;
  memcpy(&Frame->State.flags[X86State::RFLAG_NZCV_LOC], &Packed_NZCV, sizeof(Packed_NZCV));

  // Reserved, Read-As-1, Write-as-1
  Frame->State.flags[X86State::RFLAG_RESERVED_LOC] = 1;
  // Interrupt Flag. Can't be written by CPL-3 userland.
  Frame->State.flags[X86State::RFLAG_IF_LOC] = 1;
}

bool ContextImpl::InitCore() {
  // Initialize the CPU core signal handlers & DispatcherConfig
#ifdef ARCHITECTURE_ppc64le
  Dispatcher = FEXCore::CPU::PPC64Dispatcher::Create(this);
#else
  Dispatcher = FEXCore::CPU::Dispatcher::Create(this);
#endif

  // Set up the SignalDelegator config so it knows our dispatcher's code range,
  // SRA mappings, and handler addresses.
  SignalDelegation->SetConfig(Dispatcher->MakeSignalDelegatorConfig());

#if defined(_WIN32) && !defined(ARCHITECTURE_arm64ec)
  // WOW64 always needs the interrupt fault check to be enabled.
  Config.NeedsPendingInterruptFaultCheck = true;
#endif

  if (Config.GdbServer) {
    // If gdbserver is enabled then this needs to be enabled.
    Config.NeedsPendingInterruptFaultCheck = true;
  }

  return true;
}

void ContextImpl::HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) {
  static_cast<ContextImpl*>(Thread->CTX)->Dispatcher->ExecuteJITCallback(Thread->CurrentFrame, RIP);
}

void ContextImpl::ExecuteThread(FEXCore::Core::InternalThreadState* Thread) {
  // Update the thread pointer for Thunk return to the latest.
  Thread->CurrentFrame->Pointers.ThunkCallbackRet = SignalDelegation->GetThunkCallbackRET();

  Dispatcher->ExecuteDispatch(Thread->CurrentFrame);

  // If it is the parent thread that died then just leave
  // TODO: This doesn't make sense when the parent thread doesn't outlive its children
}

void ContextImpl::InitializeCompiler(FEXCore::Core::InternalThreadState* Thread) {
  Thread->OpDispatcher = fextl::make_unique<FEXCore::IR::OpDispatchBuilder>(this);
  Thread->OpDispatcher->SetMultiblock(Config.Multiblock);
  Thread->LookupCache = fextl::make_unique<FEXCore::LookupCache>(this);
  Thread->FrontendDecoder = fextl::make_unique<FEXCore::Frontend::Decoder>(Thread);
  Thread->PassManager = fextl::make_unique<FEXCore::IR::PassManager>();

  Thread->CurrentFrame->State.L1Pointer = Thread->LookupCache->GetL1Pointer();
  Thread->CurrentFrame->State.L1Mask = Thread->LookupCache->GetScaledL1PointerMask();

  Thread->CurrentFrame->Pointers.L2Pointer = Thread->LookupCache->GetPagePointer();

  Dispatcher->InitThreadPointers(Thread);

  Thread->PassManager->AddDefaultPasses(this);
  Thread->PassManager->AddDefaultValidationPasses();

  Thread->PassManager->RegisterSyscallHandler(SyscallHandler);

  // Create CPU backend
  Thread->PassManager->InsertRegisterAllocationPass(this);
#ifdef ARCHITECTURE_ppc64le
  Thread->CPUBackend = FEXCore::CPU::CreatePPC64JITCore(this, Thread);
#else
  Thread->CPUBackend = FEXCore::CPU::CreateArm64JITCore(this, Thread);
#endif

  Thread->PassManager->Finalize();
}

FEXCore::Core::InternalThreadState*
ContextImpl::CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState) {
  FEXCore::Core::InternalThreadState* Thread = new FEXCore::Core::InternalThreadState {
    .CTX = this,
  };
  FEXCore::Allocator::VirtualName("FEXMem_ThreadState", Thread, sizeof(*Thread));

  Thread->CurrentFrame->State.gregs[X86State::REG_RSP] = StackPointer;
  Thread->CurrentFrame->State.rip = InitialRIP;

  // Copy over the new thread state to the new object
  if (NewThreadState) {
    memcpy(&Thread->CurrentFrame->State, NewThreadState, sizeof(FEXCore::Core::CPUState));
  }

  // Set up the thread manager state
  Thread->CurrentFrame->Thread = Thread;

  InitializeCompiler(Thread);

  Thread->CurrentFrame->State.DeferredSignalRefCount.Store(0);

  if (Config.BlockJITNaming() || Config.GlobalJITNaming() || Config.LibraryJITNaming()) {
    // Allocate a JIT symbol buffer only if enabled.
    Thread->SymbolBuffer = JITSymbols::AllocateBuffer();
  }

  return Thread;
}

void ContextImpl::DestroyThread(FEXCore::Core::InternalThreadState* Thread) {
  FEXCore::Allocator::VirtualProtect(&Thread->InterruptFaultPage, sizeof(Thread->InterruptFaultPage),
                                     Allocator::ProtectOptions::Read | Allocator::ProtectOptions::Write);
  delete Thread;
}

#ifndef _WIN32
void ContextImpl::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  Allocator::UnlockAfterFork(LiveThread, Child);

  Profiler::PostForkAction(Child);
  if (Child) {
    if (CodeMapWriter) {
      CodeMapWriter->ResetAfterFork();
    }

    CodeInvalidationMutex.StealAndDropActiveLocks();
    if (Config.StrictInProcessSplitLocks) {
      StrictSplitLockMutex = 0;
    }
  } else {
    CodeInvalidationMutex.unlock();
    if (Config.StrictInProcessSplitLocks) {
      FEXCore::Utils::SpinWaitLock::unlock(&StrictSplitLockMutex);
    }
    return;
  }
}

void ContextImpl::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  CodeInvalidationMutex.lock();
  Allocator::LockBeforeFork(Thread);
  if (Config.StrictInProcessSplitLocks) {
    FEXCore::Utils::SpinWaitLock::lock(&StrictSplitLockMutex);
  }
}
#endif

void ContextImpl::OnCodeBufferAllocated(const fextl::shared_ptr<CPU::CodeBuffer>& Buffer) {
  if (Config.GlobalJITNaming()) {
    Symbols.RegisterJITSpace(Buffer->Ptr, Buffer->AllocatedSize);
  }

  {
    std::scoped_lock lk {CodeBufferListLock};
    CodeBufferList.emplace_back(Buffer);
  }
}

void ContextImpl::ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer) {
  FEXCORE_PROFILE_INSTANT("ClearCodeCache");

  if (NewCodeBuffer) {
    // Every offset in the relocation sink is relative to the buffer that is
    // about to be abandoned, and every block it describes goes with it. Applying
    // them to the new buffer would patch unrelated code.
    CodeCache.ResetRelocations();
    CodeCache.BlocksSinceSave.store(0, std::memory_order_relaxed);

    // Allocate new CodeBuffer + L3 LookupCache and clear L1+L2 caches
    Thread->CPUBackend->ClearCache();
  } else {
    // Clear L1+L2 cache of this thread, and clear L3 cache across any threads using it.
    //
    // HAZARD: GuestToHostMap::ClearCache (LookupCache.cpp:101-106) drops the
    // BlockLinks map without running any delinker callback. The code buffer,
    // however, stays live in this branch (NewCodeBuffer=false) — its patched
    // callsites still branch to what USED to be linked HostCode entries. Once
    // BlockLinks is gone, those callsites resolve into now-freed slots and any
    // subsequent dispatch through them is undefined.
    //
    // Trip a Release-visible trap here rather than a LOGMAN_* assertion because
    // those compile out in Release (LogManager.h:69-74,130-136) and would let
    // the hazard reach users silently. Today the only caller is
    // ThreadManager::Step (ThreadManager.cpp:535), which is itself stubbed
    // ("not implemented"), so this guard is unreachable in normal execution;
    // if Step gets a real implementation or a new caller appears, they must
    // land a delink walk (or a full code-buffer rotation via NewCodeBuffer=true)
    // before this path becomes correct to take.
    ERROR_AND_DIE_FMT("ClearCodeCache(NewCodeBuffer=false) reached without a delink walk; "
                      "live code buffer still contains patched callsites into cleared BlockLinks");
    auto lk = Thread->LookupCache->AcquireWriteLock();
    Thread->LookupCache->ClearCache(lk);
  }
  Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
}

static void IRDumper(FEXCore::Core::InternalThreadState* Thread, IR::IREmitter* IREmitter, uint64_t GuestRIP) {
  FEXCore::File::File FD = FEXCore::File::File::GetStdERR();
  fextl::stringstream out;
  auto NewIR = IREmitter->ViewIR();
  FEXCore::IR::Dump(&out, &NewIR);
  fextl::fmt::print(FD, "IR-ShouldDump-{} 0x{:x}:\n{}\n@@@@@\n", NewIR.PostRA() ? "post" : "pre", GuestRIP, out.str());
};

bool ContextImpl::CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState& Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  return Thread.FrontendDecoder->CheckIfCacheable(Thread, reinterpret_cast<const uint8_t*>(GuestRIP), GuestRIP, MaxInst);
}

ContextImpl::GenerateIRResult
ContextImpl::GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst) {
  FEXCORE_PROFILE_SCOPED("GenerateIR");

  Thread->OpDispatcher->ResetWorkingList();

  uint64_t TotalInstructions {0};
  uint64_t TotalInstructionsLength {0};

  bool HasCustomIR {};

  // SMC Idea 4 (FEX_SMCSEMANTICPATCH): rel32 fields of the direct branches this
  // decode covers. Filled in the instruction loop below, where the decoded
  // instruction's address and length are both in hand; left empty (and the
  // block therefore ineligible) with the flag off or on a custom-IR block.
  // See Interface/Core/SMCSemanticPatch.h.
  const bool RecordBranchImmSites = Config.SMCSemanticPatch();
  FEXCore::SMC::BranchImmSites BranchImmSites;
  bool BranchImmSitesOverflowed {};
  // ... and the immediate fields of its mov-immediates. Recorded in the same
  // loop; each recognised site additionally tags the IR constant the dispatcher
  // materialises for it, which is what gives the backend provenance for the
  // host window it bakes.
  FEXCore::SMC::MovImmSites MovImmSites;
  bool MovImmSitesOverflowed {};

  if (HasCustomIRHandlers.load(std::memory_order_relaxed)) {
    std::shared_lock lk(CustomIRMutex);
    auto Handler = CustomIRHandlers.find(GuestRIP);
    if (Handler != CustomIRHandlers.end()) {
      TotalInstructions = 1;
      TotalInstructionsLength = 1;
      Handler->second.Handler(GuestRIP, Thread->OpDispatcher.get());
      HasCustomIR = true;
    }
  }

  if (!HasCustomIR) {
    const uint8_t* GuestCode {};
    GuestCode = reinterpret_cast<const uint8_t*>(GuestRIP);

    bool HadDispatchError {false};
    bool HadInvalidInst {false};

    Thread->FrontendDecoder->DecodeInstructionsAtEntry(Thread, GuestCode, GuestRIP, MaxInst);

    // Cheap compile tier (FEX_SMCCHEAPTIER): the decoder decides per block
    // whether the entry page is churning badly enough to compile disposably,
    // and refuses to follow branches when it is. Mirror that decision onto the
    // dispatcher, which otherwise stitches blocks together on its own. This is
    // a per-compilation override of Config.Multiblock; the global config is
    // untouched, and the next block re-derives the flag from scratch.
    Thread->OpDispatcher->SetMultiblock(Config.Multiblock && !Thread->FrontendDecoder->IsCheapTierBlock());

    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    auto CodeBlocks = &BlockInfo->Blocks;

    Thread->OpDispatcher->BeginFunction(GuestRIP, CodeBlocks, BlockInfo->TotalInstructionCount, BlockInfo->Is64BitMode,
                                        AreMonoHacksActive() && MonoBackpatcherBlock.load(std::memory_order_relaxed) == GuestRIP);

    const auto GPRSize = Thread->OpDispatcher->GetGPROpSize();

#ifdef ZYDIS_DISASSEMBLER
    const auto ZydisMachineMode = Config.Is64BitMode ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      const uint64_t DecodedMin = Thread->FrontendDecoder->DecodedMinAddress;
      const uint64_t DecodedMax = Thread->FrontendDecoder->DecodedMaxAddress;
      LogMan::Msg::IFmt("Guest x86 Begin (RIP={:#x}, {:#x}-{:#x})", GuestRIP, DecodedMin, DecodedMax);
    }
#endif

    for (size_t j = 0; j < CodeBlocks->size(); ++j) {
      const FEXCore::Frontend::Decoder::DecodedBlocks& Block = CodeBlocks->at(j);

#ifdef ZYDIS_DISASSEMBLER
      if (FEXCore::Config::Get_X86DISASSEMBLE() && CodeBlocks->size() > 1) {
        LogMan::Msg::IFmt("  Block {} Entry={:#x} NumInsts={}", j, Block.Entry, Block.NumInstructions);
      }
#endif

      bool BlockInForceTSOValidRange = false;
      auto InstForceTSOIt = ForceTSOInstructions.end();
      if (ForceTSOValidRanges.Contains({Block.Entry, Block.Entry + Block.Size})) {
        if (auto It = ForceTSOInstructions.lower_bound(Block.Entry); *It < Block.Entry + Block.Size) {
          InstForceTSOIt = It;
          BlockInForceTSOValidRange = true;
        }
      }

      // Set the block entry point
      Thread->OpDispatcher->SetNewBlockIfChanged(Block.Entry);

      uint64_t BlockInstructionsLength {};

      // Reset any block-specific state
      Thread->OpDispatcher->StartNewBlock();

      uint64_t InstsInBlock = Block.NumInstructions;

      if (InstsInBlock == 0) {
        // Special case for an empty instruction block.
        Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry - GuestRIP));
      }

      for (size_t i = 0; i < InstsInBlock; ++i) {
        uint64_t InstAddress = Block.Entry + BlockInstructionsLength;
        const FEXCore::X86Tables::X86InstInfo* TableInfo {nullptr};
        const FEXCore::X86Tables::DecodedInst* DecodedInfo {nullptr};

        TableInfo = Block.DecodedInstructions[i].TableInfo;
        DecodedInfo = &Block.DecodedInstructions[i];

#ifdef ZYDIS_DISASSEMBLER
        if (FEXCore::Config::Get_X86DISASSEMBLE()) {
          const uint8_t* InstBytes = reinterpret_cast<const uint8_t*>(InstAddress);
          ZydisDisassembledInstruction ZydisInst;
          if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZydisMachineMode, InstAddress, InstBytes, DecodedInfo->InstSize, &ZydisInst))) {
            LogMan::Msg::IFmt("    {:#x}: {}", InstAddress, ZydisInst.text);
          } else {
            LogMan::Msg::IFmt("    {:#x}: (decode failed, {} bytes)", InstAddress, DecodedInfo->InstSize);
          }
        }
#endif

        if (RecordBranchImmSites) {
          if (!BranchImmSitesOverflowed) {
            FEXCore::SMC::BranchImmSite Site {};
            if (FEXCore::SMC::DecodeRel32BranchSite(reinterpret_cast<const uint8_t*>(InstAddress), DecodedInfo->InstSize, InstAddress,
                                                    BlockInfo->Is64BitMode, &Site)) {
              if (BranchImmSites.size() >= FEXCore::SMC::kMaxSitesPerBlock) {
                // Over the cap: drop the whole table rather than describe the
                // block partially. A partial table would let a write to an
                // unrecorded branch look like "not a patch site" and silently take
                // the fallback -- which is correct but unattributable -- while a
                // write to a recorded one would be serviced against a block whose
                // other branches we never checked.
                BranchImmSites.clear();
                BranchImmSitesOverflowed = true;
              } else {
                BranchImmSites.push_back(Site);
              }
            }
          }

          // The mov-immediate half. The tag handed to the dispatcher is only
          // valid for THIS instruction, so it is cleared first and re-set only
          // when the instruction is a recognised site; the dispatcher also
          // re-checks the instruction's PC before acting on it.
          Thread->OpDispatcher->ClearPatchableImmSite();
          if (!MovImmSitesOverflowed) {
            FEXCore::SMC::MovImmSite MovSite {};
            uint64_t MovValue {};
            if (FEXCore::SMC::DecodeMovImmSite(reinterpret_cast<const uint8_t*>(InstAddress), DecodedInfo->InstSize, InstAddress,
                                               BlockInfo->Is64BitMode, &MovSite, &MovValue)) {
              if (MovImmSites.size() >= FEXCore::SMC::kMaxSitesPerBlock) {
                // Same all-or-nothing rule as above. Windows already tagged with
                // now-dangling indices are harmless: CompileBlock drops the whole
                // window table when the site table is empty.
                MovImmSites.clear();
                MovImmSitesOverflowed = true;
              } else {
                MovImmSites.push_back(MovSite);
                Thread->OpDispatcher->SetPatchableImmSite(static_cast<uint32_t>(MovImmSites.size()), InstAddress, MovValue, MovSite.ImmSize);
              }
            }
          }
        }

        bool IsLocked = DecodedInfo->Flags & FEXCore::X86Tables::DecodeFlags::FLAG_LOCK;

        // Do a partial register cache flush before every instruction. This
        // prevents cross-instruction static register caching, while allowing
        // context load/stores to be optimized within a block. Theoretically,
        // this flush is not required for correctness, all mandatory flushes are
        // included in instruction-specific handlers. Instead, this is a blunt
        // heuristic to make the register cache less aggressive, as the current
        // RA generates bad code in common cases with tied registers otherwise.
        //
        // However, it makes our exception handling behaviour more predictable.
        // It is potentially correctness bearing in that sense, but that is a
        // side effect here and (if that behaviour is required) we should handle
        // that more explicitly later.
        Thread->OpDispatcher->FlushRegisterCache(true);

        // Emit a RIP-table marker for EVERY instruction, not just those with
        // side effects. ROOT CAUSE of the Ziggurat finalize spin
        // (docs/ZIGGURAT_FINALIZE_SPIN.md): with sparse markers,
        // RestoreRIPFromHostPC rounds a signal-time host PC DOWN to the last
        // marked instruction, and sigreturn then RE-EXECUTES everything
        // between that marker and the true interrupt point. Re-running a
        // non-idempotent register op — the observed case is `add rbx, 4`
        // replayed after a GC-storm signal landed in the unmarked `cmp`
        // that follows it — double-steps the induction variable past an
        // exact-equality loop exit, which then never fires again.
        // Side-effect-free ops are precisely the ones the old gate skipped
        // AND the ones whose re-execution is unsafe from an earlier marker,
        // so the gate was backwards for signal precision. Per-instruction
        // markers make resume instruction-granular: only the interrupted
        // instruction restarts, from its own start, before its architectural
        // commit is observable. Marker cost is 1-2 vl64pair bytes per
        // instruction in the block tail and no emitted host code
        // (DEF_OP(GuestOpcode) only records the cursor).
        Thread->OpDispatcher->_GuestOpcode(InstAddress - GuestRIP);

        if (Config.SMCChecks == FEXCore::Config::CONFIG_SMC_FULL || Block.ForceFullSMCDetection) {
          // Evidence gate for the accumulator-vs-decoder-PC audit: use
          // DecodedInfo->PC (the address the decoder actually decoded from)
          // as the validated address, not InstAddress (a running total
          // computed before DecodedInfo is even assigned above). If they
          // ever diverge, S4's snapshot would compare the right bytes at
          // the wrong address and validation would pass forever. This trap
          // is Release-visible (ERROR_AND_DIE_FMT — LOGMAN asserts compile
          // out); if it never fires across the regression set, the follow-up
          // commit moves the InstAddress computation on :651 to DecodedInfo
          // ->PC after :655 so the loop has one notion of the current
          // instruction address instead of two.
          if (InstAddress != DecodedInfo->PC) {
            ERROR_AND_DIE_FMT(
              "SMC snapshot: InstAddress accumulator ({:#x}) diverged from decoder PC ({:#x}); "
              "S4 validation would compare decoder bytes at accumulator address (guaranteed miscompile)",
              InstAddress, DecodedInfo->PC);
          }
          auto InstAddressReg = Thread->OpDispatcher->_EntrypointOffset(GPRSize, DecodedInfo->PC - GuestRIP);
          // Snapshot the bytes the decoder actually consumed (DecodedInfo->
          // InstBytes), not a re-read of live guest memory. A guest write
          // landing between decode and this point would otherwise pair IR
          // built from the OLD bytes with a snapshot of the NEW ones, and
          // ValidateCode would then return equal-forever while stale semantics
          // execute. Zero-initialised so any tail past InstSize is defined;
          // static_assert bounds the copy against CodeOriginal.
          std::array<uint8_t, 0x10> CodeOriginal {};
          static_assert(sizeof(DecodedInfo->InstBytes) <= sizeof(CodeOriginal));
          memcpy(CodeOriginal.data(), DecodedInfo->InstBytes.data(), sizeof(DecodedInfo->InstBytes));
          auto CodeChanged = Thread->OpDispatcher->_ValidateCode(CodeOriginal, InstAddressReg, DecodedInfo->InstSize);

          auto InvalidateCodeCond = Thread->OpDispatcher->CondJump(CodeChanged);

          auto CurrentBlock = Thread->OpDispatcher->GetCurrentBlock();
          auto CodeWasChangedBlock = Thread->OpDispatcher->CreateNewCodeBlockAtEnd();
          Thread->OpDispatcher->SetTrueJumpTarget(InvalidateCodeCond, CodeWasChangedBlock);

          Thread->OpDispatcher->SetCurrentCodeBlock(CodeWasChangedBlock);
          Thread->OpDispatcher->_ThreadRemoveCodeEntry();
          Thread->OpDispatcher->ExitFunction(Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, InstAddress - GuestRIP));

          auto NextOpBlock = Thread->OpDispatcher->CreateNewCodeBlockAfter(CurrentBlock);

          Thread->OpDispatcher->SetFalseJumpTarget(InvalidateCodeCond, NextOpBlock);
          Thread->OpDispatcher->SetCurrentCodeBlock(NextOpBlock);
        }

        if (TableInfo && TableInfo->OpcodeDispatcher.OpDispatch) {
          auto Fn = TableInfo->OpcodeDispatcher.OpDispatch;
          Thread->OpDispatcher->ResetHandledLock();
          Thread->OpDispatcher->ResetDecodeFailure();
          IR::ForceTSOMode ForceTSO = IR::ForceTSOMode::NoOverride;
          if (BlockInForceTSOValidRange) {
            if (InstForceTSOIt != ForceTSOInstructions.end() && *InstForceTSOIt == InstAddress) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          } else if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_FORCE_TSO) {
            ForceTSO = IR::ForceTSOMode::ForceEnabled;
          } else if (Config.LockOnlyTSO()) {
            // Opt-in: only x86 instructions carrying FLAG_LOCK (LOCK CMPXCHG,
            // LOCK XADD, implicit-LOCK XCHG-mem-reg, etc.) get TSO acquire/
            // release emission.  Plain `MOV reg,[mem]` falls back to the
            // cheap LoadMem path -- skips the 4-instruction `ldx; cmpd self;
            // bc never; isync` dance that ARM64 sidesteps via single-insn
            // LDAR.  Inert when global TSOEnabled is false (TSO already off).
            //
            // Pitfall: real concurrent guest code that relies on x86's
            // "every load is acquire" contract may race -- particularly
            // glibc futex / PLT lazy resolution.  LOCK CMPXCHG is the
            // primitive backing those, so LOCK-only TSO should keep them
            // correct.  Tune-at-own-risk.
            if (DecodedInfo->Flags & X86Tables::DecodeFlags::FLAG_LOCK) {
              ForceTSO = IR::ForceTSOMode::ForceEnabled;
            } else {
              ForceTSO = IR::ForceTSOMode::ForceDisabled;
            }
          }

          Thread->OpDispatcher->SetForceTSO(ForceTSO);

          // Vector-scan fusion lookahead window (docs/VCMPEQ_FUSION_DESIGN.md).
          // A handler may swallow the instructions that follow it in this block
          // and emit their combined effect itself. Only offer the window when
          // doing so cannot lose anything the surrounding loop is responsible
          // for emitting per instruction:
          //   * CONFIG_SMC_FULL / ForceFullSMCDetection wraps EVERY instruction
          //     in a ValidateCode guard above; a swallowed instruction would
          //     silently lose its guard and run stale semantics after an SMC
          //     write.
          //   * ExtendedDebugInfo asks for a _GuestOpcode marker per
          //     instruction, which swallowed instructions would not get.
          // Both are rare/one-off modes, so refusing to fuse in them costs
          // nothing and removes two whole classes of interaction.
          const bool FusionWindowSafe = !ExtendedDebugInfo && Config.SMCChecks != FEXCore::Config::CONFIG_SMC_FULL && !Block.ForceFullSMCDetection;
          Thread->OpDispatcher->SetDecodeWindow(FusionWindowSafe ? &Block : nullptr, i);

          std::invoke(Fn, Thread->OpDispatcher, DecodedInfo);
          if (Thread->OpDispatcher->HadDecodeFailure()) {
            HadDispatchError = true;
          } else {
            if (Thread->OpDispatcher->HasHandledLock() != IsLocked) {
              HadDispatchError = true;
              LogMan::Msg::EFmt("Missing LOCK HANDLER at 0x{:x}{{'{}'}}", InstAddress, TableInfo->Name ?: "UND");
            }
            BlockInstructionsLength += DecodedInfo->InstSize;
            TotalInstructionsLength += DecodedInfo->InstSize;
            ++TotalInstructions;

            // The handler may have fused the instructions that follow into its
            // own emission (see SetDecodeWindow). Account for them and skip
            // them: they must never be dispatched a second time.
            if (const uint32_t Fused = Thread->OpDispatcher->ConsumeFusedInstructionCount(); Fused) {
              LOGMAN_THROW_A_FMT(i + Fused < InstsInBlock, "Fusion swallowed past the end of the block");
              for (uint32_t f = 1; f <= Fused; ++f) {
                const auto& Swallowed = Block.DecodedInstructions[i + f];
                BlockInstructionsLength += Swallowed.InstSize;
                TotalInstructionsLength += Swallowed.InstSize;
                ++TotalInstructions;
              }
              // DecodedInfo must name the LAST instruction the block consumed,
              // because the loop tail uses it for FinishOp's next-RIP.
              DecodedInfo = &Block.DecodedInstructions[i + Fused];
              i += Fused;
            }

            // Walk InstForceTSOIt forward past the handled instruction
            InstForceTSOIt =
              std::find_if(InstForceTSOIt, ForceTSOInstructions.end(), [&](auto Val) { return Val >= Block.Entry + BlockInstructionsLength; });
          }
        } else {
          // Invalid instruction
          if (!BlockInstructionsLength) {
            // SMC can modify block contents and patch invalid instructions to valid ones inline.
            // End blocks upon encountering them and only emit an invalid opcode exception if there are no prior instructions in the block (that could have modified it to be valid).

            if (TableInfo) {
              LogMan::Msg::EFmt("Invalid or Unknown instruction: {} 0x{:x}", TableInfo->Name ?: "UND", Block.Entry - GuestRIP);
            }

            if (Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::INVALID_INST ||
                Block.BlockStatus == Frontend::Decoder::DecodedBlockStatus::BAD_RELOCATION) {
              Thread->OpDispatcher->InvalidOp(DecodedInfo);
            } else {
              Thread->OpDispatcher->NoExecOp(DecodedInfo);
            }
          }

          HadInvalidInst = true;
        }

        const bool NeedsBlockEnd = (HadDispatchError && TotalInstructions > 0) ||
                                   (Thread->OpDispatcher->NeedsBlockEnder() && i + 1 == InstsInBlock) || HadInvalidInst;

        // If we had a dispatch error then leave early
        if (HadDispatchError && TotalInstructions == 0) {
          // Couldn't handle any instruction in op dispatcher
          Thread->OpDispatcher->DelayedDisownBuffer();
          return {std::nullopt, 0, 0, 0, 0};
        }

        if (NeedsBlockEnd) {
          // We had some instructions. Early exit
          Thread->OpDispatcher->ExitFunction(
            Thread->OpDispatcher->_InlineEntrypointOffset(GPRSize, Block.Entry + BlockInstructionsLength - GuestRIP));
          break;
        }


        if (Thread->OpDispatcher->FinishOp(DecodedInfo->PC + DecodedInfo->InstSize, i + 1 == InstsInBlock)) {
          break;
        }
      }
    }

#ifdef ZYDIS_DISASSEMBLER
    if (FEXCore::Config::Get_X86DISASSEMBLE()) {
      LogMan::Msg::IFmt("Guest x86 End");
    }
#endif

    Thread->OpDispatcher->Finalize();

    Thread->FrontendDecoder->DelayedDisownBuffer();
  }

  IR::IREmitter* IREmitter = Thread->OpDispatcher.get();

  auto ShouldDump = Thread->OpDispatcher->ShouldDumpIR();
  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  // Run the passmanager over the IR from the dispatcher
  Thread->PassManager->Run(IREmitter);

  // Debug
  if (ShouldDump) {
    IRDumper(Thread, IREmitter, GuestRIP);
  }

  return {
    .IRView = IREmitter->ViewIR(),
    .TotalInstructions = TotalInstructions,
    .TotalInstructionsLength = TotalInstructionsLength,
    .StartAddr = Thread->FrontendDecoder->DecodedMinAddress,
    .Length = Thread->FrontendDecoder->DecodedMaxAddress - Thread->FrontendDecoder->DecodedMinAddress,
    .NeedsAddGuestCodeRanges = !HasCustomIR,
    .BranchImmSites = std::move(BranchImmSites),
    .MovImmSites = std::move(MovImmSites),
  };
}

ContextImpl::CompileCodeResult ContextImpl::CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) {
  if (SourcecodeResolver && Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      MappedSection->FileInfo.SourcecodeMap =
        SourcecodeResolver->GenerateMap(MappedSection->FileInfo.Filename, CodeMap::GetBaseFilename(MappedSection->FileInfo, false));
    }
  }

  // Generate IR + Meta Info
  auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, NeedsAddGuestCodeRanges, BranchImmSites, MovImmSites] =
    GenerateIR(Thread, GuestRIP, Config.GDBSymbols(), MaxInst);
  if (!IRView) {
    // OpDispatcher IR already released in this case.
    return {{}, nullptr, 0, 0, false, {}, {}};
  }

  // Attempt to get the CPU backend to compile this code
  // Re-check if another thread raced us in compiling this block.
  // We could lock CodeBufferWriteMutex earlier to prevent this from happening,
  // but this would increase lock contention. Redundant frontend runs aren't
  // as expensive and are easily reverted.
  if (MaxInst != 1) {
    if (auto Block = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
      // Raced to compile, release the OpDispatcher IR.
      Thread->OpDispatcher->DelayedDisownBuffer();
      return {.CompiledCode = {.BlockBegin = reinterpret_cast<uint8_t*>(Block), .EntryPoints = {{GuestRIP, reinterpret_cast<uint8_t*>(Block)}}},
              .DebugData = nullptr,
              .StartAddr = 0,
              .Length = 0,
              .NeedsAddGuestCodeRanges = false,
              .BranchImmSites = {},
              .MovImmSites = {}};
    }
  }

  auto DebugData = fextl::make_unique<FEXCore::Core::DebugData>();

  // If the trap flag is set we generate single instruction blocks that each check to generate a single step exception.
  bool TFSet = Thread->CurrentFrame->State.flags[X86State::RFLAG_TF_RAW_LOC];

  auto CompiledCode = Thread->CPUBackend->CompileCode(GuestRIP, Length, TotalInstructions == 1, &*IRView, DebugData.get(), TFSet);

  // Release the IR
  Thread->OpDispatcher->DelayedDisownBuffer();

  return {
    .CompiledCode = std::move(CompiledCode),
    .DebugData = std::move(DebugData),
    .StartAddr = StartAddr,
    .Length = Length,
    .NeedsAddGuestCodeRanges = NeedsAddGuestCodeRanges,
    .BranchImmSites = std::move(BranchImmSites),
    .MovImmSites = std::move(MovImmSites),
  };
}

uintptr_t ContextImpl::CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst) {
  auto Thread = Frame->Thread;
  FEXCORE_PROFILE_SCOPED("CompileBlock");
  FEXCORE_PROFILE_ACCUMULATION(Thread, AccumulatedJITTime);

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // FEX_SMCLAZYINVAL drain point (a). This thread is about to run code it does
  // not already have in its L1, so settle any deferred SMC invalidations first:
  // pages dirtied since the last drain get soft-invalidated now, so the lookup
  // below either misses (and recompiles) or relinks against a validated hash,
  // instead of publishing a translation of bytes that have been overwritten.
  //
  // MUST stay above the shared CodeInvalidationMutex guard: the drain takes the
  // exclusive side of that same mutex and calls ReleaseAllPendingSharedLocks to
  // get there, which would yank a lock this function relies on for its whole
  // body (the v2 hazard, see SMCSoftInvalidate.h note (d)). Null pointer =>
  // option off => one predictable load and a not-taken branch.
  if (auto* LazyCount = SyscallHandler->LazySMCDirtyCount; LazyCount) {
    // FEX_SMCLAZYSCRUB: this thread's scrub debt (if any) is settled by the
    // unconditional drain below, so consume it here too. CompileBlock is
    // normally reached *through* the lookup slow path, which already took it;
    // this covers the direct callers (CompileRIP, HandleCallback, AOT).
    Thread->LookupCache->TakeLazySMCDrainPending();
    if (LazyCount->load(std::memory_order_acquire) != 0) {
      SyscallHandler->DrainLazySMCInvalidations(Thread);
    }
  }

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  // Is the code in the cache?
  // The backends only check L1 and L2, not L3
  if (auto HostCode = Thread->LookupCache->FindBlock(Thread, GuestRIP)) {
    return HostCode;
  }

  // SMC v3: the lookup miss may be a soft-invalidated block whose guest bytes
  // never actually changed. Revalidating by hash costs microseconds where a
  // recompile costs tens. See Interface/Core/SMCSoftInvalidate.h.
  // Runs under this function's shared CodeInvalidationMutex, which is what
  // makes it mutually exclusive with any concurrent (soft-)invalidation.
  if (Config.SMCSoftInvalidate()) {
    if (auto HostCode = TryRelinkSoftInvalidatedBlock(Thread, GuestRIP)) {
      return HostCode;
    }
  }

  // Accumulate a JIT count now, as even if another thread raced us, it should count as a compile.
  FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedJITCount, 1);

  auto [CompiledCode, DebugData, StartAddr, Length, NeedsAddGuestCodeRanges, BranchImmSites, MovImmSites] =
    CompileCode(Thread, GuestRIP, MaxInst);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    return 0;
  } else if (!DebugData) {
    // DebugData wasn't populated, indicating another thread raced us for compiling this block
    return reinterpret_cast<uintptr_t>(CodePtr);
  }

  // The core managed to compile the code.
  if (Config.BlockJITNaming()) {
    auto FragmentBasePtr = CompiledCode.BlockBegin;

    auto GuestRIPLookup = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);

    if (DebugData->Subblocks.size()) {
      for (auto& Subblock : DebugData->Subblocks) {
        auto BlockBasePtr = FragmentBasePtr + Subblock.HostCodeOffset;
        if (GuestRIPLookup) {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                           GuestRIP - GuestRIPLookup->FileStartVA);
        } else {
          Symbols.Register(Thread->SymbolBuffer.get(), BlockBasePtr, GuestRIP, Subblock.HostCodeSize);
        }
      }
    } else {
      if (GuestRIPLookup) {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, CompiledCode.Size, GuestRIPLookup->FileInfo.Filename,
                         GuestRIP - GuestRIPLookup->FileStartVA);
      } else {
        Symbols.Register(Thread->SymbolBuffer.get(), FragmentBasePtr, GuestRIP, CompiledCode.Size);
      }
    }
  }

  if (Config.LibraryJITNaming() || Config.GDBSymbols()) {
    auto MappedSection = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (MappedSection) {
      if (Config.LibraryJITNaming()) {
        Symbols.RegisterNamedRegion(Thread->SymbolBuffer.get(), CodePtr, DebugData->HostCodeSize, MappedSection->FileInfo.Filename);
      }

      if (Config.GDBSymbols()) {
        GDBJITRegister(MappedSection->FileInfo, MappedSection->FileStartVA, GuestRIP, (uintptr_t)CodePtr, *DebugData);
      }
    }
  }

  // Clear any relocations that might have been generated
  if (!CodeCache.IsGeneratingCache) {
    Thread->CPUBackend->ClearRelocations();
  } else {
    // Cache generation: hand them to the context-wide sink instead of leaving
    // them to pile up in this thread's backend. See CodeCache::AbsorbRelocations
    // — a runtime cache writer saves from whichever thread reaches a safe point
    // first, and per-thread relocation lists would make it save a cache missing
    // every relocation another thread produced.
    CodeCache.AbsorbRelocations(*Thread);
    CodeCache.BlocksSinceSave.fetch_add(1, std::memory_order_relaxed);
  }

  fextl::vector<uint64_t> CodePages;

  if (NeedsAddGuestCodeRanges) {
    // Track in the guest to host map all entrypoints for all pages the compiled block touches, if any page didn't previously
    // contain code, inform the frontend so it can setup SMC detection.
    auto BlockInfo = Thread->FrontendDecoder->GetDecodedBlockInfo();
    CodePages.reserve(BlockInfo->CodePages.size());
    CodePages.insert(CodePages.end(), BlockInfo->CodePages.begin(), BlockInfo->CodePages.end());
    for (auto CodePage : BlockInfo->CodePages) {
      // SMC Idea 3: [StartAddr, StartAddr+Length) is the frontend's decoded
      // guest span; passing it gives the granule bitmap 64-byte precision for
      // this block instead of a whole-page mark. It MUST be recorded here,
      // before MarkGuestExecutableRange below arms the page's write protection
      // -- see the ordering argument in Interface/Core/SMCCodeGranules.h.
      const bool NewPage =
        Thread->LookupCache->AddBlockExecutableRange(Thread, BlockInfo->EntryPoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE, StartAddr, Length);
      if (NewPage) {
        SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
      if (SMCAuditCompileFD() >= 0) {
        dprintf(SMCAuditCompileFD(), "compile rip=%lx page=%lx newpage=%d nentry=%zu\n", GuestRIP, CodePage, NewPage ? 1 : 0,
                BlockInfo->EntryPoints.size());
      }
    }
    if (SMCAuditCompileFD() >= 0 && BlockInfo->CodePages.empty()) {
      dprintf(SMCAuditCompileFD(), "compile rip=%lx NO-PAGES\n", GuestRIP);
    }
  }

  // SMC v3: record a content hash of the block's guest source bytes so a later
  // soft-invalidation of this block can be undone by revalidation instead of a
  // recompile. [StartAddr, StartAddr+Length) is the frontend's decoded span;
  // HashGuestBlock only hashes the parts of it that lie in CodePages.
  uint64_t GuestHash = 0;
  uint64_t HashedRangeLength = 0;
  if (Config.SMCSoftInvalidate() && FEXCore::SMC::IsHashableBlock(Length, CodePages.size())) {
    HashedRangeLength = Length;
    GuestHash = FEXCore::SMC::HashGuestBlock(CodePages, StartAddr, Length);
  }

  // Insert to lookup cache

  // BlockBegin is shared across all EntryPoints of a single CompiledCode
  // (each block has one begin, potentially multiple entry points).
  const uint64_t BlockBegin = reinterpret_cast<uintptr_t>(CompiledCode.BlockBegin);
  // SMC Idea 4: the block is eligible for semantic patching only if BOTH halves
  // of the metadata survived (a decoded rel32 field to match the guest write
  // against, and a constant exit window to repatch). Either table empty leaves
  // both empty, so the fault handler's "block claims the write but has no exit
  // sites" decline can only mean a genuine multiblock-folded branch.
  if (BranchImmSites.empty() || CompiledCode.ExitRIPSites.empty()) {
    BranchImmSites.clear();
    CompiledCode.ExitRIPSites.clear();
  }
  // The mov-immediate half is independent: a block can be eligible for one
  // shape and not the other. Same all-or-nothing rule per half -- a site table
  // without windows (or windows whose site indices were invalidated by an
  // overflowing site table) must not be consulted at fault time.
  if (MovImmSites.empty() || CompiledCode.MovImmWindows.empty()) {
    MovImmSites.clear();
    CompiledCode.MovImmWindows.clear();
  }

  for (auto [GuestAddr, HostAddr] : CompiledCode.EntryPoints) {
    Thread->LookupCache->AddBlockMapping(Thread, GuestAddr, BlockBegin, CodePages, HostAddr, StartAddr, HashedRangeLength, GuestHash,
                                         BranchImmSites, CompiledCode.ExitRIPSites, MovImmSites, CompiledCode.MovImmWindows);
  }

  if (CodeMapWriter) {
    auto Region = SyscallHandler->LookupExecutableFileSection(Thread, GuestRIP);
    if (Region && Region->FileStartVA != 0) {
      CodeMapWriter->AppendBlock(*Region, GuestRIP);
    }
  }

  return (uintptr_t)CodePtr;
}

uintptr_t ContextImpl::CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  FEXCORE_PROFILE_SCOPED("CompileSingleStep");
  auto Thread = Frame->Thread;

  if (SMCAuditCompileFD() >= 0) {
    dprintf(SMCAuditCompileFD(), "single-step rip=%lx tid=%d\n", GuestRIP, FHU::Syscalls::gettid());
  }

  static_cast<ContextImpl*>(Thread->CTX)->SyscallHandler->PreCompile();

  // Invalidate might take a unique lock on this, to guarantee that during invalidation no code gets compiled
  auto lk = GuardSignalDeferringSection<std::shared_lock>(CodeInvalidationMutex, Thread);

  auto [CompiledCode, DebugData, StartAddr, Length, _, __, ___] = CompileCode(Thread, GuestRIP, 1);
  auto CodePtr = CompiledCode.EntryPoints[GuestRIP];
  if (CodePtr == nullptr) {
    if (SMCAuditCompileFD() >= 0) {
      dprintf(SMCAuditCompileFD(), "single-step rip=%lx FAILED (nullptr)\n", GuestRIP);
    }
    return 0;
  }

  // Clear any relocations that might have been generated
  Thread->CPUBackend->ClearRelocations();

  return (uintptr_t)CodePtr;
}

void ContextImpl::InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) {
  FEXCORE_PROFILE_SCOPED("InvalidateCodeBuffersCodeRange");

  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  // Every invalidation funnels through here, so this is the one place that
  // sees the per-page churn the cheap compile tier keys off. No-op unless
  // FEX_SMCCHEAPTIER is set.
  RecordCodeRangeInvalidation(Start, Length);

  std::scoped_lock lk {CodeBufferListLock};
  auto it = CodeBufferList.begin();
  while (it != CodeBufferList.end()) {
    if (auto Strong = it->lock()) {
      Strong->LookupCache->InvalidateRange(Start, Length);
      it++;
    } else {
      it = CodeBufferList.erase(it);
    }
  }
}

uintptr_t ContextImpl::TryRelinkSoftInvalidatedBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) {
  // Called from CompileBlock, which holds CodeInvalidationMutex shared. That is
  // load-bearing: it excludes every (soft-)invalidation for the duration, so a
  // retained entry taken here cannot be concurrently purged by a munmap.
  auto Retained = Thread->LookupCache->TakeRetainedBlock(GuestRIP);
  if (!Retained) {
    return 0;
  }

  const uint64_t CurrentHash = FEXCore::SMC::HashGuestBlock(Retained->CodePages, Retained->GuestRangeStart, Retained->GuestRangeLength);
  if (CurrentHash != Retained->GuestHash) {
    // Genuinely modified: drop the metadata (the host code stays in the
    // CodeBuffer for any thread still executing it, exactly as legacy
    // invalidation leaves it) and let the caller compile a fresh block.
    //
    // The soft-invalidation path bypasses InvalidateCodeBuffersCodeRange, so
    // the cheap-tier churn counter (FEX_SMCCHEAPTIER) would never see these
    // pages. Count the churn here instead — a hash mismatch is a stronger
    // "this page's code really changed" signal than a raw invalidation, and it
    // deliberately excludes relinks (false sharing / identical rewrites), which
    // are not churn worth demoting a page's compile tier over.
    RecordCodeRangeInvalidation(Retained->GuestRangeStart, Retained->GuestRangeLength);
    if (SMCAuditCompileFD() >= 0) {
      dprintf(SMCAuditCompileFD(), "relink-miss rip=%lx\n", GuestRIP);
    }
    return 0;
  }

  // Unchanged: re-publish. Registering the code pages again re-arms mtrack's
  // write protection through the same path a fresh compile uses, so the page
  // becomes protected exactly when live code reappears on it.
  fextl::set<uint64_t> Entrypoints {GuestRIP};
  for (auto CodePage : Retained->CodePages) {
    // SMC Idea 3: re-set the granule bits the soft-invalidation cleared. The
    // retained entry always carries a non-zero extent (SoftEraseBlock refuses
    // to retain a block without one), so this is granule-precise, and it lands
    // before MarkGuestExecutableRange re-arms the protection.
    const bool NewPage = Thread->LookupCache->AddBlockExecutableRange(
      Thread, Entrypoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE, Retained->GuestRangeStart, Retained->GuestRangeLength);
    if (NewPage) {
      SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
    }
  }

  // SMC Idea 4: carry the semantic-patch metadata across the relink. A relink
  // only happens when the guest bytes hashed identical, and the host code is
  // the same code that was compiled from them -- so every recorded guest field
  // and every recorded host window is still exactly as valid as it was before
  // the soft-invalidation. Dropping it here would silently make every
  // soft-invalidated block ineligible for patching from then on.
  Thread->LookupCache->AddBlockMapping(Thread, GuestRIP, Retained->BlockBegin, Retained->CodePages,
                                       reinterpret_cast<void*>(Retained->HostCode), Retained->GuestRangeStart, Retained->GuestRangeLength,
                                       Retained->GuestHash, Retained->BranchImmSites, Retained->ExitRIPSites, Retained->MovImmSites,
                                       Retained->MovImmWindows);

  if (SMCAuditCompileFD() >= 0) {
    dprintf(SMCAuditCompileFD(), "relink rip=%lx host=%lx pages=%zu\n", GuestRIP, Retained->HostCode, Retained->CodePages.size());
  }

  return Retained->HostCode;
}

void ContextImpl::SoftInvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) {
  FEXCORE_PROFILE_SCOPED("SoftInvalidateCodeBuffersCodeRange");

  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  std::scoped_lock lk {CodeBufferListLock};
  auto it = CodeBufferList.begin();
  while (it != CodeBufferList.end()) {
    if (auto Strong = it->lock()) {
      Strong->LookupCache->SoftInvalidateRange(Start, Length);
      it++;
    } else {
      it = CodeBufferList.erase(it);
    }
  }
}

void ContextImpl::InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {
  LOGMAN_THROW_A_FMT(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  // Ensures now-modified mappings aren't cached as being in their previous non-executable state.
  // Accessing FrontendDecoder is safe as the thread's code invalidation mutex must be locked here.
  Thread->FrontendDecoder->ResetExecutableRangeCache();

  if (Thread->LookupCache->InvalidateCacheRange(Start, Length)) {
    FEXCORE_PROFILE_SCOPED("InvalidateCallRet");

    // This may cause access violations in the thread on Windows as zeroing is not atomic, this is handled by the frontend
    Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
  }
}

void ContextImpl::ScrubThreadLookupCacheForLazySMC(FEXCore::Core::InternalThreadState* Thread) {
  // FEX_SMCLAZYSCRUB. Signal-handler context, faulting thread, own cache.
  // Deliberately does NOT touch L2/L3, CachedCodePages, the frontend's
  // executable-range cache, or the CallRet stack: all of those need a lock this
  // handler must not take, and none of them is reachable without first going
  // through the lookup slow path, which drains. The PPC64LE backend does not
  // use the CallRet predictor stack at all (see JIT/PPC64LE/JIT.cpp).
  Thread->LookupCache->ScrubForLazySMC();
}

void ContextImpl::ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP) {
  static_cast<ContextImpl*>(Frame->Thread->CTX)->SyscallHandler->InvalidateGuestCodeRange(Frame->Thread, GuestRIP, 1);
}

std::optional<CustomIRResult>
ContextImpl::AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator, void* Data) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::unique_lock lk(CustomIRMutex);

  auto InsertedIterator = CustomIRHandlers.emplace(Entrypoint, CustomIRHandlerEntry {Handler, Creator, Data});
  HasCustomIRHandlers = true;

  if (!InsertedIterator.second) {
    const auto& [fn, Creator, Data] = InsertedIterator.first->second;
    return CustomIRResult(Creator, Data);
  }

  return std::nullopt;
}

void ContextImpl::AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) {
  LOGMAN_THROW_A_FMT(Entrypoint, "Tried to link null pointer address to guest function");
  LOGMAN_THROW_A_FMT(GuestThunkEntrypoint, "Tried to link address to null pointer guest function");
  if (!Config.Is64BitMode) {
    LOGMAN_THROW_A_FMT((Entrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
    LOGMAN_THROW_A_FMT((GuestThunkEntrypoint >> 32) == 0, "Tried to link 64-bit address in 32-bit mode");
  }

  LogMan::Msg::DFmt("Thunks: Adding guest trampoline from address {:#x} to guest function {:#x}", Entrypoint, GuestThunkEntrypoint);

  auto Result = AddCustomIREntrypoint(
    Entrypoint,
    [this, GuestThunkEntrypoint](uintptr_t Entrypoint, FEXCore::IR::IREmitter* emit) {
      auto IRHeader = emit->_IRHeader(emit->Invalid(), Entrypoint, 0, 0, 0, 0);
      auto Block = emit->CreateCodeNode(true, 0);
      IRHeader.first->Blocks = emit->WrapNode(Block);
      emit->SetCurrentCodeBlock(Block);

      const auto GPRSize = this->Config.Is64BitMode ? IR::OpSize::i64Bit : IR::OpSize::i32Bit;

      // Thunk entry-points don't get cached, don't need to be padded.
      if (GPRSize == IR::OpSize::i64Bit) {
        IR::Ref R = emit->_StoreRegister(emit->Constant(Entrypoint), GPRSize);
        R->Reg = IR::PhysicalRegister(IR::RegClass::GPRFixed, X86State::REG_R11).Raw;
      } else {
        emit->_StoreContextFPR(GPRSize, emit->_VCastFromGPR(IR::OpSize::i64Bit, IR::OpSize::i64Bit, emit->Constant(Entrypoint)),
                               offsetof(Core::CPUState, mm[0][0]));
      }
      emit->_ExitFunction(IR::OpSize::i64Bit, emit->Constant(GuestThunkEntrypoint), IR::BranchHint::None, emit->Invalid(), emit->Invalid());
    },
    ThunkHandler, (void*)GuestThunkEntrypoint);

  if (Result.has_value()) {
    if (Result->Creator != ThunkHandler) {
      ERROR_AND_DIE_FMT("Input address for AddThunkTrampoline is already linked by another module");
    }
    if (Result->Data != (void*)GuestThunkEntrypoint) {
      // NOTE: This may happen in Vulkan thunks if the Vulkan driver resolves two different symbols
      //       to the same function (e.g. vkGetPhysicalDeviceFeatures2/vkGetPhysicalDeviceFeatures2KHR)
      LogMan::Msg::EFmt("Input address for AddThunkTrampoline is already linked elsewhere");
    }
  }
}

void ContextImpl::AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");
  ForceTSOValidRanges.Insert(ValidRanges);
  ForceTSOInstructions.merge(std::move(Instructions));
}

void ContextImpl::RemoveForceTSOInformation(uint64_t Address, uint64_t Size) {
  LogMan::Throw::AFmt(CodeInvalidationMutex.try_lock() == false, "CodeInvalidationMutex needs to be unique_locked here");

  ForceTSOValidRanges.Remove({Address, Address + Size});
  ForceTSOInstructions.erase(ForceTSOInstructions.lower_bound(Address), ForceTSOInstructions.upper_bound(Address + Size));
}

void ContextImpl::MarkMonoBackpatcherBlock(uint64_t BlockEntry) {
  MonoBackpatcherBlock.store(BlockEntry, std::memory_order_relaxed);
}

void ContextImpl::RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint) {
  LOGMAN_THROW_A_FMT(Config.Is64BitMode || !(Entrypoint >> 32), "64-bit Entrypoint in 32-bit mode {:x}", Entrypoint);

  std::scoped_lock lk(CustomIRMutex);

  CustomIRHandlers.erase(Entrypoint);
  HasCustomIRHandlers = !CustomIRHandlers.empty();
  SyscallHandler->InvalidateGuestCodeRange(Thread, Entrypoint, 1);
}

void ContextImpl::MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value) {
  auto Thread = Frame->Thread;
  auto CTX = static_cast<ContextImpl*>(Thread->CTX);
  {
    auto lk = GuardSignalDeferringSection(CTX->CodeInvalidationMutex, Thread);

    if (Size == 8) {
      *reinterpret_cast<uint64_t*>(Address) = Value;
    } else if (Size == 4) {
      *reinterpret_cast<uint32_t*>(Address) = Value;
    } else {
      ERROR_AND_DIE_FMT("Unexpected write size for backpatcher: {}", Size);
    }
  }

  CTX->SyscallHandler->InvalidateGuestCodeRange(Thread, Address, Size);
}

void ContextImpl::ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) {
  Thread->FrontendDecoder->SetExternalBranches(ExternalBranches);
}
} // namespace FEXCore::Context
