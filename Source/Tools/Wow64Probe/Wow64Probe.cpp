// SPDX-License-Identifier: MIT
/*
$info$
tags: Bin|Wow64Probe
desc: Frontend-free FEXCore embedding probe.

  Answers, by execution rather than by argument, whether FEXCore can serve as
  the emulation backend that a *native ppc64le* host (Wine) calls into — the
  role dlls/wow64cpu plays for x86-64-on-ARM64.

  This links FEXCore_Base + CommonTools and deliberately does NOT link
  LinuxEmulation. Everything here is what a CPU-DLL-shaped embedder has to do
  for itself.

  It exercises the four capabilities the CPU-DLL contract needs:
    T1  entry into guest code + return to host           (BTCpuSimulate)
    T2  return to host on a guest syscall trap           (BTCpuGetBopCode path)
    T3  guest register state <-> a flat AMD64 CONTEXT    (BTCpuGet/SetContext)
    T4  adopting a host thread FEX did not create        (BTCpuThreadInit)
    T5  host fault inside JIT -> guest RIP recovery      (BTCpuResetToConsistentState)
$end_info$
*/

#include "DummyHandlers.h"
#include "Common/HostFeatures.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/vector.h>

#include <atomic>
#include <mutex>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>

namespace {

// ---------------------------------------------------------------------------
// Result accounting
// ---------------------------------------------------------------------------
int Failures {};
int Checks {};

void Check(bool Cond, const char* What) {
  ++Checks;
  if (!Cond) {
    ++Failures;
    fprintf(stderr, "  FAIL: %s\n", What);
  } else {
    fprintf(stderr, "  ok:   %s\n", What);
  }
}

template<typename T>
void CheckEq(T Got, T Want, const char* What) {
  ++Checks;
  if (Got != Want) {
    ++Failures;
    fprintf(stderr, "  FAIL: %s (got 0x%llx want 0x%llx)\n", What, (unsigned long long)Got, (unsigned long long)Want);
  } else {
    fprintf(stderr, "  ok:   %s = 0x%llx\n", What, (unsigned long long)Got);
  }
}

void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  fprintf(stderr, "[%s] %s\n", LogMan::DebugLevelStr(Level), Message);
}

void AssertHandler(const char* Message) {
  fprintf(stderr, "[ASSERT] %s\n", Message);
  fflush(nullptr);
}

// ---------------------------------------------------------------------------
// The embedder's syscall handler. This is the whole of what a CPU DLL needs
// on the FEXCore::HLE::SyscallHandler interface when there is no Linux guest:
// a trap sink, plus the two decoder-facing queries.
// ---------------------------------------------------------------------------
struct ProbeSyscallHandler final : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
  // Everything the trap observed, for the test to inspect afterwards.
  std::atomic<uint64_t> TrapCount {};
  uint64_t SeenRIP {};
  uint64_t SeenRAX {};
  uint64_t SeenRDI {};
  uint64_t SeenRSI {};

  // If set, the handler writes this into guest RAX before resuming, which is
  // how a real CPU DLL returns an NTSTATUS to the guest.
  bool InjectRAX {};
  uint64_t InjectRAXValue {};

  // If set, the handler overwrites every guest GPR in the frame with
  // WriteAllBase + regnum, and (optionally) rewrites RIP. This measures which
  // frame writes the ppc64le backend actually propagates back to guest code.
  bool WriteAllGPRs {};
  uint64_t WriteAllBase {};
  uint64_t ReturnValue {};

  // Bop mode: behave like a real CPU DLL. Two trap instructions at two known
  // guest addresses; dispatch on State.rip; pop the guest return address off
  // the guest stack and resume the guest there with a result in RAX.
  bool BopMode {};
  uint64_t BopSyscall {};
  uint64_t BopUnixCall {};
  uint64_t BopSyscallHits {};
  uint64_t BopUnixCallHits {};

  ProbeSyscallHandler() {
    // OS_GENERIC: "No JIT-side argument handling, spill/fill all regs."
    // This is what both of FEX's Windows modules selected.
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }

  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override {
    TrapCount.fetch_add(1, std::memory_order_relaxed);
    // With OS_GENERIC the JIT has spilled the full register file into the
    // frame before calling us, so CPUState is authoritative here. That is the
    // property BTCpuSimulate's syscall break-out depends on.
    SeenRIP = Frame->State.rip;
    SeenRAX = Frame->State.gregs[FEXCore::X86State::REG_RAX];
    SeenRDI = Frame->State.gregs[FEXCore::X86State::REG_RDI];
    SeenRSI = Frame->State.gregs[FEXCore::X86State::REG_RSI];

    if (InjectRAX) {
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = InjectRAXValue;
    }
    if (BopMode) {
      // This is Source/Windows/WOW64/Module.cpp:431-464 with the widths
      // changed from 32-bit to 64-bit and Wow64SystemServiceEx replaced by a
      // stub. Nothing else about it is different.
      const uint64_t GuestRSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      const uint64_t ReturnRIP = *reinterpret_cast<uint64_t*>(GuestRSP); // pushed by the guest's CALL
      uint64_t ReturnRAX = 0;
      if (Frame->State.rip == BopSyscall) {
        ++BopSyscallHits;
        ReturnRAX = 0x1111 + Frame->State.gregs[FEXCore::X86State::REG_RAX];
      } else if (Frame->State.rip == BopUnixCall) {
        ++BopUnixCallHits;
        ReturnRAX = 0x2222;
      } else {
        return 0; // not one of ours
      }
      Frame->State.gregs[FEXCore::X86State::REG_RAX] = ReturnRAX;
      Frame->State.gregs[FEXCore::X86State::REG_RSP] = GuestRSP + 8;
      Frame->State.rip = ReturnRIP;
      return 0;
    }

    // The handler OWNS RIP. FEXCore stores the address *of* the trapping
    // instruction (not the one after it) so that a CPU DLL can tell which bop
    // it was — the recovered WOW64 module compares Frame->State.rip against
    // BridgeInstrs::Syscall / ::UnixCall for exactly this. Under OS_GENERIC the
    // block ends after the syscall and re-dispatches from State.rip, so a
    // handler that does not advance RIP re-executes the trap forever.
    Frame->State.rip = SeenRIP + 2; // sizeof(0F 05)

    if (WriteAllGPRs) {
      for (size_t i = 0; i < 16; ++i) {
        if (i == FEXCore::X86State::REG_RSP) {
          continue; // leave the guest stack alone, the probe stores through it
        }
        Frame->State.gregs[i] = WriteAllBase + i;
      }
    }
    return ReturnValue;
  }

  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t) override {
    return std::nullopt;
  }

  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, uint64_t) override {
    // A CPU DLL answers this out of its ImageTracker/InvalidationTracker. The
    // probe maps everything itself, so: one flat writable range.
    return {0, UINT64_MAX, true};
  }
};

// ---------------------------------------------------------------------------
// The embedder's signal delegator. FEXCore has no pure virtuals here; all that
// is needed is a place to stash the config and a thread<->state association.
// A real CPU DLL uses a TEB slot; on Linux, thread_local is the analogue.
// ---------------------------------------------------------------------------
thread_local FEXCore::Core::InternalThreadState* TLSThread {};

struct ProbeSignalDelegator final : public FEXCore::SignalDelegator, public FEXCore::Allocator::FEXAllocOperators {
  void Register(FEXCore::Core::InternalThreadState* Thread) {
    TLSThread = Thread;
  }
};

FEXCore::Context::Context* CTX {};
ProbeSyscallHandler* SyscallHandler {};
ProbeSignalDelegator* SigDelegator {};

// ---------------------------------------------------------------------------
// Guest thread creation — the BTCpuThreadInit body, minus Windows.
//
// This is the "one real obligation that transfers with the frontend": FEXCore
// allocates the InternalThreadState but two CPUState fields are only ever
// initialised by frontend code, and the JIT reads garbage without them:
//   - segment_arrays[] (emulated GDT/LDT)
//   - callret_sp       (call-return shadow stack pointer)
// ---------------------------------------------------------------------------
constexpr size_t CALLRET_ALLOC = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE;

FEXCore::Core::InternalThreadState* ProbeThreadInit(uint64_t RIP, uint64_t RSP) {
  auto* Thread = CTX->CreateThread(RIP, RSP);
  auto* Frame = Thread->CurrentFrame;

  // --- GDT. CPUState carries private_gdt[32] inline now, so unlike the
  // recovered Windows module we do not need to new[] one.
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &Frame->State.private_gdt[0];
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &Frame->State.private_gdt[0];

  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  auto* GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
  FEXCore::Core::CPUState::SetGDTBase(GDT, 0);
  FEXCore::Core::CPUState::SetGDTLimit(GDT, 0xF'FFFFU);
  GDT->L = 1; // 64-bit guest
  GDT->D = 0;
  Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*GDT);

  // --- Call-ret shadow stack, guard pages both sides.
  auto AllocBase = reinterpret_cast<uint64_t>(::mmap(nullptr, CALLRET_ALLOC, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  LOGMAN_THROW_A_FMT(AllocBase != (uint64_t)MAP_FAILED, "callret stack mmap failed");
  Thread->CallRetStackBase = reinterpret_cast<void*>(AllocBase + FEXCore::Utils::FEX_PAGE_SIZE);
  ::mprotect(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
  Frame->State.callret_sp = AllocBase + FEXCore::Utils::FEX_PAGE_SIZE + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4;

  SigDelegator->Register(Thread);
  return Thread;
}

void ProbeThreadTerm(FEXCore::Core::InternalThreadState* Thread) {
  auto Base = reinterpret_cast<uint64_t>(Thread->CallRetStackBase) - FEXCore::Utils::FEX_PAGE_SIZE;
  CTX->DestroyThread(Thread);
  ::munmap(reinterpret_cast<void*>(Base), CALLRET_ALLOC);
}

// ---------------------------------------------------------------------------
// Guest memory
// ---------------------------------------------------------------------------
// Code publication. Note the lock: Context::InvalidateCodeBuffersCodeRange
// asserts that the caller already holds GetCodeInvalidationMutex() exclusively
// (see FEX::Windows::InvalidationTracker, which does the same). This is part of
// the CPU-DLL contract and is not stated in the public header.
void PublishGuestCode(uint64_t Start, uint64_t Length) {
  std::scoped_lock Lk {CTX->GetCodeInvalidationMutex()};
  CTX->InvalidateCodeBuffersCodeRange(Start, Length);
}

struct GuestBlob {
  uint8_t* Code {};
  uint64_t CodeAddr {};
  uint8_t* Stack {};
  uint64_t StackTop {};
};

GuestBlob MakeGuest(std::initializer_list<uint8_t> Bytes) {
  GuestBlob B {};
  B.Code = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  B.Stack = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(B.Code, 0xCC, 0x10000);
  size_t i = 0;
  for (auto Byte : Bytes) {
    B.Code[i++] = Byte;
  }
  B.CodeAddr = reinterpret_cast<uint64_t>(B.Code);
  B.StackTop = reinterpret_cast<uint64_t>(B.Stack) + 0x8000;
  // Native host code just wrote guest instructions. This is exactly what
  // Wine's PE loader does, and it is the embedder's job to publish it.
  PublishGuestCode(B.CodeAddr, 0x10000);
  return B;
}

// ---------------------------------------------------------------------------
// T3 support: a flat AMD64 CONTEXT, hand-declared (no Windows headers).
// Field order/offsets copied from winnt.h so that the marshaller written here
// is the one a CPU DLL would ship.
// ---------------------------------------------------------------------------
struct alignas(16) M128A {
  uint64_t Low;
  int64_t High;
};

struct alignas(16) XSAVE_FORMAT64 {
  uint16_t ControlWord;
  uint16_t StatusWord;
  uint8_t TagWord;
  uint8_t Reserved1;
  uint16_t ErrorOpcode;
  uint32_t ErrorOffset;
  uint16_t ErrorSelector;
  uint16_t Reserved2;
  uint32_t DataOffset;
  uint16_t DataSelector;
  uint16_t Reserved3;
  uint32_t MxCsr;
  uint32_t MxCsr_Mask;
  M128A FloatRegisters[8];
  M128A XmmRegisters[16];
  uint8_t Reserved4[96];
};

struct alignas(16) AMD64_CONTEXT {
  uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
  uint32_t ContextFlags;
  uint32_t MxCsr;
  uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
  uint32_t EFlags;
  uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
  uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
  uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
  uint64_t Rip;
  XSAVE_FORMAT64 FltSave;
  M128A VectorRegister[26];
  uint64_t VectorControl;
  uint64_t DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
};

static_assert(sizeof(AMD64_CONTEXT) == 1232, "AMD64 CONTEXT must be 1232 bytes");
static_assert(offsetof(AMD64_CONTEXT, Rax) == 0x78, "CONTEXT.Rax offset");
static_assert(offsetof(AMD64_CONTEXT, Rip) == 0xF8, "CONTEXT.Rip offset");
static_assert(offsetof(AMD64_CONTEXT, FltSave) == 0x100, "CONTEXT.FltSave offset");

constexpr uint32_t CONTEXT_AMD64 = 0x00100000;
constexpr uint32_t CTX_CONTROL = CONTEXT_AMD64 | 0x1;
constexpr uint32_t CTX_INTEGER = CONTEXT_AMD64 | 0x2;
constexpr uint32_t CTX_SEGMENTS = CONTEXT_AMD64 | 0x4;
constexpr uint32_t CTX_FLOATING_POINT = CONTEXT_AMD64 | 0x8;
constexpr uint32_t CTX_FULL = CTX_CONTROL | CTX_INTEGER | CTX_FLOATING_POINT;

// BTCpuGetContext half. This is the piece the embeddability survey called
// "genuinely net-new for ppc64le": ARM64EC packs into ARM64 registers, the
// 32-bit WoW64 module produces a flat I386_CONTEXT. This is the flat AMD64
// analogue of StoreWowContextFromState.
void StoreStateToAmd64Context(FEXCore::Core::InternalThreadState* Thread, AMD64_CONTEXT* Context) {
  const auto& State = Thread->CurrentFrame->State;

  if (Context->ContextFlags & CTX_CONTROL & ~CONTEXT_AMD64) {
    Context->Rip = State.rip;
    Context->Rsp = State.gregs[FEXCore::X86State::REG_RSP];
    Context->SegCs = State.cs_idx;
    Context->SegSs = State.ss_idx;
    // WasInJIT = false: state is already spilled into the frame by the time an
    // embedder reads it (guaranteed on the syscall and HLT paths; on a fault
    // path the embedder must spill SRA first — see T5).
    Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  }

  if (Context->ContextFlags & CTX_INTEGER & ~CONTEXT_AMD64) {
    Context->Rax = State.gregs[FEXCore::X86State::REG_RAX];
    Context->Rcx = State.gregs[FEXCore::X86State::REG_RCX];
    Context->Rdx = State.gregs[FEXCore::X86State::REG_RDX];
    Context->Rbx = State.gregs[FEXCore::X86State::REG_RBX];
    Context->Rbp = State.gregs[FEXCore::X86State::REG_RBP];
    Context->Rsi = State.gregs[FEXCore::X86State::REG_RSI];
    Context->Rdi = State.gregs[FEXCore::X86State::REG_RDI];
    Context->R8 = State.gregs[FEXCore::X86State::REG_R8];
    Context->R9 = State.gregs[FEXCore::X86State::REG_R9];
    Context->R10 = State.gregs[FEXCore::X86State::REG_R10];
    Context->R11 = State.gregs[FEXCore::X86State::REG_R11];
    Context->R12 = State.gregs[FEXCore::X86State::REG_R12];
    Context->R13 = State.gregs[FEXCore::X86State::REG_R13];
    Context->R14 = State.gregs[FEXCore::X86State::REG_R14];
    Context->R15 = State.gregs[FEXCore::X86State::REG_R15];
  }

  if (Context->ContextFlags & CTX_SEGMENTS & ~CONTEXT_AMD64) {
    Context->SegDs = State.ds_idx;
    Context->SegEs = State.es_idx;
    Context->SegFs = State.fs_idx;
    Context->SegGs = State.gs_idx;
  }

  if (Context->ContextFlags & CTX_FLOATING_POINT & ~CONTEXT_AMD64) {
    // XMM: never read State.xmm directly — the physical layout is
    // split-vs-converged depending on host features and on ppc64le the split
    // layout is live.
    __uint128_t XMM[16];
    __uint128_t YMM[16];
    CTX->ReconstructXMMRegisters(Thread, XMM, YMM);
    memcpy(Context->FltSave.XmmRegisters, XMM, sizeof(XMM));

    Context->MxCsr = State.mxcsr;
    Context->FltSave.MxCsr = State.mxcsr;
    Context->FltSave.ControlWord = State.FCW;
    Context->FltSave.TagWord = State.AbridgedFTW;

    // x87: mm[] is stored ROTATED by top-of-stack; TOP lives in a flags byte.
    // Undo the rotation so the CONTEXT holds architectural ST(0)..ST(7).
    const uint32_t Top = State.flags[FEXCore::X86State::X87FLAG_TOP_LOC];
    for (size_t i = 0; i < 8; ++i) {
      const size_t Phys = (Top + i) % 8;
      memcpy(&Context->FltSave.FloatRegisters[i], &State.mm[Phys][0], 16);
    }
    // FSW: rebuild the status word from the discrete flag bytes + TOP.
    uint16_t FSW = 0;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] != 0) << 8;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] != 0) << 9;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] != 0) << 10;
    FSW |= (Top & 0b111) << 11;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] != 0) << 14;
    Context->FltSave.StatusWord = FSW;
  }

  // FEX has no source for these; a CPU DLL must synthesise them as zero.
  Context->Dr0 = Context->Dr1 = Context->Dr2 = Context->Dr3 = Context->Dr6 = Context->Dr7 = 0;
  Context->FltSave.ErrorOffset = Context->FltSave.DataOffset = 0;
  Context->FltSave.ErrorOpcode = 0;
}

// BTCpuSetContext half. Structurally identical to LoadStateFromECContext,
// which is already host-neutral in the recovered ARM64EC module.
void LoadStateFromAmd64Context(FEXCore::Core::InternalThreadState* Thread, const AMD64_CONTEXT* Context) {
  auto& State = Thread->CurrentFrame->State;

  if (Context->ContextFlags & CTX_CONTROL & ~CONTEXT_AMD64) {
    State.rip = Context->Rip;
    State.gregs[FEXCore::X86State::REG_RSP] = Context->Rsp;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);
  }

  if (Context->ContextFlags & CTX_INTEGER & ~CONTEXT_AMD64) {
    State.gregs[FEXCore::X86State::REG_RAX] = Context->Rax;
    State.gregs[FEXCore::X86State::REG_RCX] = Context->Rcx;
    State.gregs[FEXCore::X86State::REG_RDX] = Context->Rdx;
    State.gregs[FEXCore::X86State::REG_RBX] = Context->Rbx;
    State.gregs[FEXCore::X86State::REG_RBP] = Context->Rbp;
    State.gregs[FEXCore::X86State::REG_RSI] = Context->Rsi;
    State.gregs[FEXCore::X86State::REG_RDI] = Context->Rdi;
    State.gregs[FEXCore::X86State::REG_R8] = Context->R8;
    State.gregs[FEXCore::X86State::REG_R9] = Context->R9;
    State.gregs[FEXCore::X86State::REG_R10] = Context->R10;
    State.gregs[FEXCore::X86State::REG_R11] = Context->R11;
    State.gregs[FEXCore::X86State::REG_R12] = Context->R12;
    State.gregs[FEXCore::X86State::REG_R13] = Context->R13;
    State.gregs[FEXCore::X86State::REG_R14] = Context->R14;
    State.gregs[FEXCore::X86State::REG_R15] = Context->R15;
  }

  if (Context->ContextFlags & CTX_FLOATING_POINT & ~CONTEXT_AMD64) {
    __uint128_t XMM[16];
    __uint128_t YMM[16] {};
    memcpy(XMM, Context->FltSave.XmmRegisters, sizeof(XMM));
    CTX->SetXMMRegistersFromState(Thread, XMM, YMM);

    State.mxcsr = Context->FltSave.MxCsr;
    State.FCW = Context->FltSave.ControlWord;
    State.AbridgedFTW = Context->FltSave.TagWord;

    const uint16_t FSW = Context->FltSave.StatusWord;
    const uint32_t Top = (FSW >> 11) & 0b111;
    State.flags[FEXCore::X86State::X87FLAG_TOP_LOC] = Top;
    State.flags[FEXCore::X86State::X87FLAG_C0_LOC] = (FSW >> 8) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C1_LOC] = (FSW >> 9) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C2_LOC] = (FSW >> 10) & 1;
    State.flags[FEXCore::X86State::X87FLAG_C3_LOC] = (FSW >> 14) & 1;
    for (size_t i = 0; i < 8; ++i) {
      const size_t Phys = (Top + i) % 8;
      memcpy(&State.mm[Phys][0], &Context->FltSave.FloatRegisters[i], 16);
    }
  }
}

// ===========================================================================
// T1 — entry into guest code, return to host, register state readable.
// ===========================================================================
void T1_EnterAndReturn() {
  fprintf(stderr, "\n== T1: enter guest x86-64 code, run, return to host ==\n");

  // mov rax, 0x1122334455667788
  // mov rbx, 0x10
  // add rax, rbx
  // mov rcx, rax
  // shl rcx, 1
  // hlt
  auto Blob = MakeGuest({
    0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // movabs rax, imm64
    0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x00,                   // mov rbx, 0x10
    0x48, 0x01, 0xD8,                                           // add rax, rbx
    0x48, 0x89, 0xC1,                                           // mov rcx, rax
    0x48, 0xD1, 0xE1,                                           // shl rcx, 1
    0xF4,                                                       // hlt
  });

  auto* Thread = ProbeThreadInit(Blob.CodeAddr, Blob.StackTop);
  CTX->ExecuteThread(Thread);

  const auto& S = Thread->CurrentFrame->State;
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RAX], 0x1122334455667798ULL, "RAX after add");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RBX], 0x10ULL, "RBX");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RCX], 0x22446688AACCEF30ULL, "RCX after shl");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RSP], Blob.StackTop, "RSP unchanged");

  ProbeThreadTerm(Thread);
}

// ===========================================================================
// T2 — guest hits a trap instruction, host regains control with guest state
//      readable AND writable, guest resumes.
//
// This is the BTCpuGetBopCode mechanism minus the choice of opcode. On a
// _WIN32 build FEXCore decodes INT 0x2E as the syscall; on this Linux build
// the syscall opcode is 0F 05 / INT 0x80. Both lower to the same IR::Syscall
// op and the same SyscallHandler::HandleSyscall call, so this exercises the
// exact break-out path a CPU DLL uses.
// ===========================================================================
void T2_SyscallBreakout() {
  fprintf(stderr, "\n== T2: guest trap -> host, mutate guest state, resume ==\n");

  // mov rax, 0x1234        ; "syscall number"
  // mov rdi, 0xAAAA
  // mov rsi, 0xBBBB
  // syscall
  // mov rdx, rax           ; observe what the host injected
  // syscall                ; second trap, to prove re-entry works
  // hlt
  auto Blob = MakeGuest({
    0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
    0x48, 0xC7, 0xC7, 0xAA, 0xAA, 0x00, 0x00, // mov rdi, 0xAAAA
    0x48, 0xC7, 0xC6, 0xBB, 0xBB, 0x00, 0x00, // mov rsi, 0xBBBB
    0x0F, 0x05,                               // syscall
    0x48, 0x89, 0xC2,                         // mov rdx, rax
    0x0F, 0x05,                               // syscall
    0xF4,                                     // hlt
  });

  const uint64_t FirstSyscallRIP = Blob.CodeAddr + 21;

  SyscallHandler->TrapCount = 0;
  SyscallHandler->InjectRAX = true;
  SyscallHandler->InjectRAXValue = 0xC0000005ULL; // an NTSTATUS, for flavour

  auto* Thread = ProbeThreadInit(Blob.CodeAddr, Blob.StackTop);
  CTX->ExecuteThread(Thread);

  CheckEq<uint64_t>(SyscallHandler->TrapCount.load(), 2ULL, "trap taken twice");
  // Note the handler recorded the *second* trap's values; check RIP is the
  // address of a syscall instruction, and that the first trap saw the right
  // arguments is proven by RDX below.
  const auto& S = Thread->CurrentFrame->State;
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RDX], 0xC0000005ULL, "host-injected RAX visible to guest");
  Check(SyscallHandler->SeenRIP == Blob.CodeAddr + 26, "RIP at trap == address of the trapping instruction");
  fprintf(stderr, "  (first syscall at 0x%llx, handler saw last RIP 0x%llx)\n", (unsigned long long)FirstSyscallRIP,
          (unsigned long long)SyscallHandler->SeenRIP);

  SyscallHandler->InjectRAX = false;
  ProbeThreadTerm(Thread);
}

// A separate run that checks the *first* trap's argument visibility.
void T2b_SyscallArgs() {
  fprintf(stderr, "\n== T2b: guest register file readable at the trap ==\n");
  auto Blob = MakeGuest({
    0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
    0x48, 0xC7, 0xC7, 0xAA, 0xAA, 0x00, 0x00, // mov rdi, 0xAAAA
    0x48, 0xC7, 0xC6, 0xBB, 0xBB, 0x00, 0x00, // mov rsi, 0xBBBB
    0x0F, 0x05,                               // syscall
    0xF4,                                     // hlt
  });
  SyscallHandler->TrapCount = 0;
  auto* Thread = ProbeThreadInit(Blob.CodeAddr, Blob.StackTop);
  CTX->ExecuteThread(Thread);
  CheckEq<uint64_t>(SyscallHandler->TrapCount.load(), 1ULL, "trap taken once");
  CheckEq<uint64_t>(SyscallHandler->SeenRAX, 0x1234ULL, "RAX visible at trap");
  CheckEq<uint64_t>(SyscallHandler->SeenRDI, 0xAAAAULL, "RDI visible at trap");
  CheckEq<uint64_t>(SyscallHandler->SeenRSI, 0xBBBBULL, "RSI visible at trap");
  CheckEq<uint64_t>(SyscallHandler->SeenRIP, Blob.CodeAddr + 21, "RIP == trapping instruction address");
  ProbeThreadTerm(Thread);
}

// ===========================================================================
// T2c — WHICH guest registers can a host handler write from inside the trap?
//
// This is the question a CPU DLL lives or dies on: BTCpuGetContext /
// BTCpuSetContext, NtContinue, exception dispatch and APC delivery all mean
// "the host rewrites the guest register file while the guest is stopped at the
// bop, then the guest resumes with the new file". The recovered WOW64 module
// does exactly that (Module.cpp:459-462 writes gregs[RAX], gregs[RSP] and rip
// in the frame and returns 0).
//
// The guest stores every GPR to its own stack right after the trap, so we read
// back what the *guest* saw, not what the frame says.
// ===========================================================================
void EmitStoreRegToStack(fextl::vector<uint8_t>& Out, uint8_t Reg, int8_t Disp) {
  // REX.W [+ REX.R] ; 89 /r ; modrm mod=01 reg=Reg rm=100(SIB) ; SIB=0x24 (base=rsp) ; disp8
  Out.push_back(0x48 | ((Reg >= 8) ? 0x04 : 0x00));
  Out.push_back(0x89);
  Out.push_back(0x44 | ((Reg & 7) << 3));
  Out.push_back(0x24);
  Out.push_back((uint8_t)Disp);
}

void T2c_WhichRegistersPropagate() {
  fprintf(stderr, "\n== T2c: which handler-written guest registers reach the guest ==\n");

  fextl::vector<uint8_t> Code;
  // syscall
  Code.push_back(0x0F);
  Code.push_back(0x05);
  // mov [rsp+8*i], reg   for i = 0..15  (RSP itself stored too, harmless)
  for (uint8_t i = 0; i < 16; ++i) {
    EmitStoreRegToStack(Code, i, (int8_t)(i * 8));
  }
  Code.push_back(0xF4); // hlt

  auto* CodePage = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  auto* StackPage = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(CodePage, 0xCC, 0x10000);
  memcpy(CodePage, Code.data(), Code.size());
  PublishGuestCode(reinterpret_cast<uint64_t>(CodePage), 0x10000);
  const uint64_t StackTop = reinterpret_cast<uint64_t>(StackPage) + 0x4000;

  constexpr uint64_t Base = 0x7700000000ULL;
  SyscallHandler->TrapCount = 0;
  SyscallHandler->WriteAllGPRs = true;
  SyscallHandler->WriteAllBase = Base;
  SyscallHandler->ReturnValue = 0xDEAD0000ULL;

  auto* Thread = ProbeThreadInit(reinterpret_cast<uint64_t>(CodePage), StackTop);
  CTX->ExecuteThread(Thread);

  SyscallHandler->WriteAllGPRs = false;
  SyscallHandler->ReturnValue = 0;

  static const char* Names[16] = {"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
                                  "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15"};
  auto* Slots = reinterpret_cast<uint64_t*>(StackTop);
  int Propagated = 0;
  fprintf(stderr, "  guest-observed values after the trap (want 0x%llx+regnum):\n", (unsigned long long)Base);
  for (int i = 0; i < 16; ++i) {
    if (i == FEXCore::X86State::REG_RSP) {
      continue;
    }
    const bool Ok = Slots[i] == (Base + i);
    Propagated += Ok;
    fprintf(stderr, "    %-4s = 0x%016llx %s\n", Names[i], (unsigned long long)Slots[i], Ok ? "<- propagated" : "<- LOST");
  }
  fprintf(stderr, "  handler return value 0x%llx landed in guest RAX: %s\n", 0xDEAD0000ULL,
          Slots[FEXCore::X86State::REG_RAX] == 0xDEAD0000ULL ? "yes" : "no");
  fprintf(stderr, "  %d of 15 handler-written GPRs reached the guest\n", Propagated);

  Check(Propagated == 15, "all handler-written GPRs propagate to the guest");
  ProbeThreadTerm(Thread);
}

// ===========================================================================
// T2d — the BTCpuGetBopCode protocol, end to end.
//
// A real CPU DLL allocates a small page of GUEST code containing its chosen
// trap opcode, hands the address back from BTCpuGetBopCode(), and Wine patches
// guest ntdll's syscall/unix-call dispatchers to jump there. The emulator then
// distinguishes the two entry points by State.rip, reads the caller's return
// address off the guest stack, runs native code, and resumes the guest at that
// return address with a result in RAX.
//
// Everything above is host-architecture-neutral. The only thing this probe
// changes versus Source/Windows/WOW64/Module.cpp is the opcode (0F 05 rather
// than INT 0x2E, since a native ELF build does not get _WIN32 and therefore
// does not decode INT 0x2E as a syscall) and the pointer width.
// ===========================================================================
void T2d_BopProtocol() {
  fprintf(stderr, "\n== T2d: BTCpuGetBopCode protocol (two bops, dispatch by RIP, return to caller) ==\n");

  // The bop page: two trap instructions at two distinct guest addresses.
  auto* BopPage = (uint8_t*)::mmap(nullptr, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(BopPage, 0xCC, 0x1000);
  BopPage[0] = 0x0F;
  BopPage[1] = 0x05; // "syscall" bop
  BopPage[2] = 0x0F;
  BopPage[3] = 0x05; // "unix call" bop
  PublishGuestCode(reinterpret_cast<uint64_t>(BopPage), 0x1000);

  const uint64_t BopSyscall = reinterpret_cast<uint64_t>(BopPage);
  const uint64_t BopUnixCall = BopSyscall + 2;

  auto EmitMovR10Imm64 = [](fextl::vector<uint8_t>& Out, uint64_t Imm) {
    Out.push_back(0x49);
    Out.push_back(0xBA); // movabs r10, imm64
    for (int i = 0; i < 8; ++i) {
      Out.push_back((uint8_t)(Imm >> (8 * i)));
    }
    Out.push_back(0x41);
    Out.push_back(0xFF);
    Out.push_back(0xD2); // call r10
  };

  fextl::vector<uint8_t> Code;
  // mov rax, 0x42
  for (uint8_t B : {0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00}) {
    Code.push_back(B);
  }
  EmitMovR10Imm64(Code, BopSyscall);
  // mov r15, rax
  for (uint8_t B : {0x49, 0x89, 0xC7}) {
    Code.push_back(B);
  }
  EmitMovR10Imm64(Code, BopUnixCall);
  // mov r14, rax
  for (uint8_t B : {0x49, 0x89, 0xC6}) {
    Code.push_back(B);
  }
  Code.push_back(0xF4); // hlt

  auto* CodePage = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  auto* StackPage = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(CodePage, 0xCC, 0x10000);
  memcpy(CodePage, Code.data(), Code.size());
  PublishGuestCode(reinterpret_cast<uint64_t>(CodePage), 0x10000);

  SyscallHandler->BopMode = true;
  SyscallHandler->BopSyscall = BopSyscall;
  SyscallHandler->BopUnixCall = BopUnixCall;
  SyscallHandler->BopSyscallHits = 0;
  SyscallHandler->BopUnixCallHits = 0;

  const uint64_t StackTop = reinterpret_cast<uint64_t>(StackPage) + 0x8000;
  auto* Thread = ProbeThreadInit(reinterpret_cast<uint64_t>(CodePage), StackTop);
  CTX->ExecuteThread(Thread);
  SyscallHandler->BopMode = false;

  const auto& S = Thread->CurrentFrame->State;
  CheckEq<uint64_t>(SyscallHandler->BopSyscallHits, 1ULL, "bop #1 (syscall) dispatched by RIP");
  CheckEq<uint64_t>(SyscallHandler->BopUnixCallHits, 1ULL, "bop #2 (unix call) dispatched by RIP");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_R15], 0x1111ULL + 0x42, "guest resumed at CALL return with result of bop #1");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_R14], 0x2222ULL, "guest resumed at CALL return with result of bop #2");
  CheckEq<uint64_t>(S.gregs[FEXCore::X86State::REG_RSP], StackTop, "guest stack balanced after two bop calls");

  ProbeThreadTerm(Thread);
}

// ===========================================================================
// T3 — CPUState <-> flat AMD64_CONTEXT round trip.
// ===========================================================================
void T3_ContextRoundTrip() {
  fprintf(stderr, "\n== T3: CPUState <-> AMD64_CONTEXT round trip ==\n");

  // Run something that dirties GPRs, flags, XMM and x87, then HLT.
  //   mov rax, -1 ; add rax, 1   -> ZF=1 CF=1 PF=1
  //   movdqa-ish: use pcmpeqd xmm0,xmm0 (all ones), and movq xmm1, rax
  //   fld1 ; fldz  -> x87 TOP moves
  auto Blob = MakeGuest({
    0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, -1
    0x48, 0x83, 0xC0, 0x01,                   // add rax, 1   (ZF, CF)
    0x48, 0xC7, 0xC6, 0x77, 0x00, 0x00, 0x00, // mov rsi, 0x77
    0x66, 0x0F, 0x76, 0xC0,                   // pcmpeqd xmm0, xmm0
    0x66, 0x48, 0x0F, 0x6E, 0xCE,             // movq xmm1, rsi
    0xD9, 0xE8,                               // fld1
    0xD9, 0xEE,                               // fldz
    0xF4,                                     // hlt
  });

  auto* Thread = ProbeThreadInit(Blob.CodeAddr, Blob.StackTop);
  CTX->ExecuteThread(Thread);

  AMD64_CONTEXT C1 {};
  C1.ContextFlags = CTX_FULL | CTX_SEGMENTS;
  StoreStateToAmd64Context(Thread, &C1);

  fprintf(stderr, "  CONTEXT: Rip=0x%llx Rax=0x%llx Rsi=0x%llx EFlags=0x%08x MxCsr=0x%x FCW=0x%x FSW=0x%x\n", (unsigned long long)C1.Rip,
          (unsigned long long)C1.Rax, (unsigned long long)C1.Rsi, C1.EFlags, C1.MxCsr, C1.FltSave.ControlWord, C1.FltSave.StatusWord);
  fprintf(stderr, "  xmm0=%016llx%016llx xmm1=%016llx%016llx\n", (unsigned long long)C1.FltSave.XmmRegisters[0].High,
          (unsigned long long)C1.FltSave.XmmRegisters[0].Low, (unsigned long long)C1.FltSave.XmmRegisters[1].High,
          (unsigned long long)C1.FltSave.XmmRegisters[1].Low);

  CheckEq<uint64_t>(C1.Rax, 0ULL, "CONTEXT.Rax");
  CheckEq<uint64_t>(C1.Rsi, 0x77ULL, "CONTEXT.Rsi");
  Check((C1.EFlags & 0x40) != 0, "CONTEXT.EFlags ZF set");
  Check((C1.EFlags & 0x01) != 0, "CONTEXT.EFlags CF set");
  Check((C1.EFlags & 0x02) != 0, "CONTEXT.EFlags reserved bit1 set");
  CheckEq<uint64_t>(C1.FltSave.XmmRegisters[0].Low, ~0ULL, "CONTEXT xmm0 low all-ones");
  CheckEq<uint64_t>((uint64_t)C1.FltSave.XmmRegisters[0].High, ~0ULL, "CONTEXT xmm0 high all-ones");
  CheckEq<uint64_t>(C1.FltSave.XmmRegisters[1].Low, 0x77ULL, "CONTEXT xmm1 low == rsi");
  CheckEq<uint64_t>((uint64_t)C1.FltSave.XmmRegisters[1].High, 0ULL, "CONTEXT xmm1 high zero");
  // fld1 then fldz -> ST(0)=0.0, ST(1)=1.0 architecturally
  CheckEq<uint64_t>(C1.FltSave.FloatRegisters[1].Low, 0x8000000000000000ULL, "ST(1) mantissa == 1.0");
  CheckEq<uint64_t>((uint64_t)(C1.FltSave.FloatRegisters[1].High & 0xFFFF), 0x3FFFULL, "ST(1) exponent == 1.0");

  // Now push it back and read it out again; must be identical.
  LoadStateFromAmd64Context(Thread, &C1);
  AMD64_CONTEXT C2 {};
  C2.ContextFlags = CTX_FULL | CTX_SEGMENTS;
  StoreStateToAmd64Context(Thread, &C2);

  Check(C1.Rip == C2.Rip && C1.Rsp == C2.Rsp, "round trip: control");
  Check(memcmp(&C1.Rax, &C2.Rax, 16 * sizeof(uint64_t)) == 0, "round trip: 16 GPRs");
  CheckEq<uint32_t>(C2.EFlags, C1.EFlags, "round trip: EFlags");
  Check(memcmp(C1.FltSave.XmmRegisters, C2.FltSave.XmmRegisters, sizeof(C1.FltSave.XmmRegisters)) == 0, "round trip: XMM0-15");
  Check(memcmp(C1.FltSave.FloatRegisters, C2.FltSave.FloatRegisters, sizeof(C1.FltSave.FloatRegisters)) == 0, "round trip: ST0-7");
  CheckEq<uint16_t>(C2.FltSave.StatusWord, C1.FltSave.StatusWord, "round trip: FSW (incl. TOP)");
  CheckEq<uint16_t>(C2.FltSave.ControlWord, C1.FltSave.ControlWord, "round trip: FCW");
  CheckEq<uint32_t>(C2.MxCsr, C1.MxCsr, "round trip: MXCSR");

  // And prove SetContext actually steers execution: rewrite RIP/RAX and re-run.
  auto Blob2 = MakeGuest({
    0x48, 0x83, 0xC0, 0x05, // add rax, 5
    0xF4,                   // hlt
  });
  AMD64_CONTEXT C3 {};
  C3.ContextFlags = CTX_CONTROL | CTX_INTEGER;
  C3.Rip = Blob2.CodeAddr;
  C3.Rsp = Blob2.StackTop;
  C3.Rax = 0x1000;
  C3.EFlags = 0x202;
  LoadStateFromAmd64Context(Thread, &C3);
  CTX->ExecuteThread(Thread);
  CheckEq<uint64_t>(Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX], 0x1005ULL, "SetContext steered execution");

  ProbeThreadTerm(Thread);
}

// ===========================================================================
// T4 — adopt a host thread FEX did not create, and run guest code on it.
//      This is what BTCpuThreadInit does: Windows creates the thread and hands
//      it to the emulator.
// ===========================================================================
struct AdoptArgs {
  GuestBlob Blob;
  uint64_t ResultRAX;
  uint64_t ResultRBX;
};

void* AdoptedThreadMain(void* Arg) {
  auto* A = static_cast<AdoptArgs*>(Arg);
  // Nothing about this pthread was created by FEXCore.
  auto* Thread = ProbeThreadInit(A->Blob.CodeAddr, A->Blob.StackTop);
  CTX->ExecuteThread(Thread);
  A->ResultRAX = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RAX];
  A->ResultRBX = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RBX];
  ProbeThreadTerm(Thread);
  return nullptr;
}

void T4_ThreadAdoption() {
  fprintf(stderr, "\n== T4: adopt a bare pthread, run guest code on it ==\n");

  AdoptArgs A {};
  A.Blob = MakeGuest({
    0x48, 0xC7, 0xC0, 0xEF, 0xBE, 0x00, 0x00, // mov rax, 0xBEEF
    0x48, 0xC7, 0xC3, 0x0D, 0xF0, 0x00, 0x00, // mov rbx, 0xF00D
    0xF4,                                     // hlt
  });

  pthread_t T;
  Check(pthread_create(&T, nullptr, AdoptedThreadMain, &A) == 0, "pthread_create");
  pthread_join(T, nullptr);
  CheckEq<uint64_t>(A.ResultRAX, 0xBEEFULL, "RAX from adopted thread");
  CheckEq<uint64_t>(A.ResultRBX, 0xF00DULL, "RBX from adopted thread");

  // Two adopted threads at once, to prove per-thread state is independent.
  AdoptArgs A1 {}, A2 {};
  A1.Blob = MakeGuest({0x48, 0xC7, 0xC0, 0x11, 0x11, 0x00, 0x00, 0x48, 0xC7, 0xC3, 0x11, 0x00, 0x00, 0x00, 0xF4});
  A2.Blob = MakeGuest({0x48, 0xC7, 0xC0, 0x22, 0x22, 0x00, 0x00, 0x48, 0xC7, 0xC3, 0x22, 0x00, 0x00, 0x00, 0xF4});
  pthread_t T1, T2;
  pthread_create(&T1, nullptr, AdoptedThreadMain, &A1);
  pthread_create(&T2, nullptr, AdoptedThreadMain, &A2);
  pthread_join(T1, nullptr);
  pthread_join(T2, nullptr);
  CheckEq<uint64_t>(A1.ResultRAX, 0x1111ULL, "thread 1 RAX");
  CheckEq<uint64_t>(A2.ResultRAX, 0x2222ULL, "thread 2 RAX");
}

// ===========================================================================
// T5 — a host fault inside JIT code, and recovery of the guest RIP.
//      This is the BTCpuResetToConsistentState core question, with a POSIX
//      signal handler standing in for the Windows exception dispatcher.
// ===========================================================================
sigjmp_buf FaultJump;
volatile bool FaultTaken {};
uint64_t FaultHostPC {};
uint64_t FaultGuestRIP {};
bool FaultWasInJIT {};
AMD64_CONTEXT FaultContext {};

// ppc64le pt_regs indices into mcontext_t.gp_regs[].
constexpr uint32_t PPC_PT_NIP = 32;
constexpr uint32_t PPC_PT_XER = 37;
constexpr uint32_t PPC_PT_CCR = 38;

// The ppc64le equivalent of FEX::Windows::Context::ReconstructThreadState
// (WOW64/Module.cpp:296-316 @99284a16c), which the embeddability survey listed
// as ~21 lines of net-new work. It is: pull the host register file out of the
// fault context and write it back into CPUState through the SRA map that
// FEXCore publishes in SignalDelegatorConfig. Nothing here is Linux-specific
// except the shape of the container the host registers arrive in.
void SpillSRAFromHostContext(FEXCore::Core::InternalThreadState* Thread, ucontext_t* UC) {
  const auto& Cfg = SigDelegator->GetConfig();
  auto& State = Thread->CurrentFrame->State;
  const uint64_t* HostGPRs = reinterpret_cast<const uint64_t*>(&UC->uc_mcontext.gp_regs[0]);

  State.rip = CTX->RestoreRIPFromHostPC(Thread, UC->uc_mcontext.gp_regs[PPC_PT_NIP]);
  for (size_t i = 0; i < Cfg.SRAGPRCount && i < 16; ++i) {
    State.gregs[i] = HostGPRs[Cfg.SRAGPRMapping[i]];
  }
  for (size_t i = 0; i < Cfg.SRAFPRCount && i < 16; ++i) {
    // ppc64le is never "converged": guest XMM low-128 lives in the sse view.
    memcpy(&State.xmm.sse.data[i][0], &UC->uc_mcontext.v_regs->vrregs[Cfg.SRAFPRMapping[i]], sizeof(__uint128_t));
  }
}

// Repack ppc64le CR0+XER into the ARM PSTATE word ReconstructCompactedEFLAGS
// wants when WasInJIT is true. Guest NZCV is split across two host registers
// by the JIT: CR0 carries N/Z, XER carries C/V.
uint64_t HostPStateFromContext(ucontext_t* UC) {
  const uint64_t ccr = UC->uc_mcontext.gp_regs[PPC_PT_CCR];
  const uint64_t xer = UC->uc_mcontext.gp_regs[PPC_PT_XER];
  return (ccr & (1ULL << 31)) | ((ccr & (1ULL << 29)) << 1) | (xer & (1ULL << 29)) | ((xer & (1ULL << 30)) >> 2);
}

void FaultHandler(int Sig, siginfo_t* Info, void* UContext) {
  auto* UC = static_cast<ucontext_t*>(UContext);
  FaultHostPC = UC->uc_mcontext.gp_regs[PPC_PT_NIP];
  auto* Thread = TLSThread;
  if (Thread) {
    FaultWasInJIT = CTX->IsAddressInCodeBuffer(Thread, FaultHostPC);
    FaultGuestRIP = CTX->RestoreRIPFromHostPC(Thread, FaultHostPC);
    if (FaultWasInJIT) {
      // BTCpuResetToConsistentState's core: republish the guest register file
      // from the host fault context, then read it out as an AMD64 CONTEXT
      // exactly as BTCpuGetContext would.
      SpillSRAFromHostContext(Thread, UC);
      FaultContext = AMD64_CONTEXT {};
      FaultContext.ContextFlags = CTX_FULL;
      StoreStateToAmd64Context(Thread, &FaultContext);
      // EFLAGS specifically must be reconstructed with WasInJIT=true, because
      // NZCV/PF/AF are in host condition registers at this instant, not in
      // CPUState.
      const uint64_t* HostGPRs = reinterpret_cast<const uint64_t*>(&UC->uc_mcontext.gp_regs[0]);
      FaultContext.EFlags = CTX->ReconstructCompactedEFLAGS(Thread, true, HostGPRs, HostPStateFromContext(UC));
    }
  }
  FaultTaken = true;
  siglongjmp(FaultJump, 1);
}

void T5_FaultRecovery() {
  fprintf(stderr, "\n== T5: host fault inside JIT -> guest RIP recovery ==\n");

  // A PROT_NONE page for the guest to touch.
  auto* Bad = ::mmap(nullptr, 0x1000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  const uint64_t BadAddr = reinterpret_cast<uint64_t>(Bad);

  // mov rax, 0x5A5A ; mov r15, 0x1234 ; pcmpeqd xmm3,xmm3 ; add rax,1 (flags)
  // mov rbx, <bad>
  // mov [rbx], rax      <- faults
  // hlt
  uint8_t B[64];
  size_t n = 0;
  const uint8_t Pre[] = {
    0x48, 0xC7, 0xC0, 0x5A, 0x5A, 0x00, 0x00, // mov rax, 0x5A5A
    0x49, 0xC7, 0xC7, 0x34, 0x12, 0x00, 0x00, // mov r15, 0x1234
    0x66, 0x0F, 0x76, 0xDB,                   // pcmpeqd xmm3, xmm3
  };
  memcpy(B, Pre, sizeof(Pre));
  n = sizeof(Pre);
  B[n++] = 0x48;
  B[n++] = 0xBB; // movabs rbx, imm64
  memcpy(B + n, &BadAddr, 8);
  n += 8;
  const uint64_t StoreOffset = n;
  B[n++] = 0x48;
  B[n++] = 0x89;
  B[n++] = 0x03; // mov [rbx], rax
  B[n++] = 0xF4; // hlt

  auto* Code = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  auto* Stack = (uint8_t*)::mmap(nullptr, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(Code, 0xCC, 0x10000);
  memcpy(Code, B, n);
  const uint64_t CodeAddr = reinterpret_cast<uint64_t>(Code);
  PublishGuestCode(CodeAddr, 0x10000);

  struct sigaction SA {}, Old {};
  SA.sa_sigaction = FaultHandler;
  SA.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&SA.sa_mask);
  sigaction(SIGSEGV, &SA, &Old);

  auto* Thread = ProbeThreadInit(CodeAddr, reinterpret_cast<uint64_t>(Stack) + 0x8000);
  FaultTaken = false;
  if (sigsetjmp(FaultJump, 1) == 0) {
    CTX->ExecuteThread(Thread);
  }
  sigaction(SIGSEGV, &Old, nullptr);

  Check(FaultTaken, "host SIGSEGV taken from guest store");
  Check(FaultWasInJIT, "IsAddressInCodeBuffer(hostPC) == true");
  fprintf(stderr, "  hostPC=0x%llx -> guest RIP 0x%llx (expected 0x%llx)\n", (unsigned long long)FaultHostPC,
          (unsigned long long)FaultGuestRIP, (unsigned long long)(CodeAddr + StoreOffset));
  CheckEq<uint64_t>(FaultGuestRIP, CodeAddr + StoreOffset, "RestoreRIPFromHostPC recovered the faulting guest RIP");

  // Full guest register file, reconstructed from the host fault context.
  fprintf(stderr, "  reconstructed CONTEXT: Rip=0x%llx Rax=0x%llx Rbx=0x%llx R15=0x%llx EFlags=0x%08x xmm3=%016llx%016llx\n",
          (unsigned long long)FaultContext.Rip, (unsigned long long)FaultContext.Rax, (unsigned long long)FaultContext.Rbx,
          (unsigned long long)FaultContext.R15, FaultContext.EFlags, (unsigned long long)FaultContext.FltSave.XmmRegisters[3].High,
          (unsigned long long)FaultContext.FltSave.XmmRegisters[3].Low);
  CheckEq<uint64_t>(FaultContext.Rip, CodeAddr + StoreOffset, "fault CONTEXT.Rip");
  CheckEq<uint64_t>(FaultContext.Rax, 0x5A5AULL, "fault CONTEXT.Rax (SRA slot 0, host r7)");
  CheckEq<uint64_t>(FaultContext.Rbx, BadAddr, "fault CONTEXT.Rbx (SRA slot 3, host r10)");
  CheckEq<uint64_t>(FaultContext.R15, 0x1234ULL, "fault CONTEXT.R15 (SRA slot 15, host r23)");
  CheckEq<uint64_t>(FaultContext.Rsp, reinterpret_cast<uint64_t>(Stack) + 0x8000, "fault CONTEXT.Rsp");
  CheckEq<uint64_t>(FaultContext.FltSave.XmmRegisters[3].Low, ~0ULL, "fault CONTEXT xmm3 low");
  CheckEq<uint64_t>((uint64_t)FaultContext.FltSave.XmmRegisters[3].High, ~0ULL, "fault CONTEXT xmm3 high");
  Check((FaultContext.EFlags & 0x02) != 0, "fault CONTEXT.EFlags reserved bit1 (reconstructed WasInJIT=true)");

  // Deliberately do not tear the thread down: it was abandoned mid-JIT.
}

} // namespace

int main(int argc, char** argv) {
  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  FEXCore::Config::Initialize();
  // NOTE the order: ReloadMetaLayer() calls MetaLayer::Load(), which rebuilds
  // the top layer from the layers below and therefore DISCARDS anything Set()
  // put there. Setting before reloading silently loses the value; the symptom
  // is a 64-bit guest being decoded in 32-bit mode (CS.L == 0) and the decoder
  // reading a truncated guest RIP.
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, "1");
  // No frontend => no mprotect-based SMC tracking host. A CPU DLL feeds
  // invalidation from BTCpuNotifyMemory*; here we call
  // InvalidateCodeBuffersCodeRange explicitly after writing guest code.
  FEXCore::Config::Set(FEXCore::Config::CONFIG_SMCCHECKS, "0");

  auto HostFeatures = FEX::FetchHostFeatures();
  auto CTXPtr = FEXCore::Context::Context::CreateNewContext(HostFeatures);

  auto SyscallHandlerPtr = fextl::make_unique<ProbeSyscallHandler>();
  auto SigDelegatorPtr = fextl::make_unique<ProbeSignalDelegator>();
  SyscallHandler = SyscallHandlerPtr.get();
  SigDelegator = SigDelegatorPtr.get();

  CTX = CTXPtr.get();
  CTX->SetSignalDelegator(SigDelegatorPtr.get());
  CTX->SetSyscallHandler(SyscallHandlerPtr.get());
  if (!CTX->InitCore()) {
    fprintf(stderr, "InitCore failed\n");
    return 1;
  }
  fprintf(stderr, "FEXCore initialised, frontend-free.\n");

  T1_EnterAndReturn();
  T2_SyscallBreakout();
  T2b_SyscallArgs();
  T2c_WhichRegistersPropagate();
  T2d_BopProtocol();
  T3_ContextRoundTrip();
  T4_ThreadAdoption();
  T5_FaultRecovery();

  fprintf(stderr, "\n===== %d checks, %d failures =====\n", Checks, Failures);
  return Failures ? 1 : 0;
}
