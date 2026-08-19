// SPDX-License-Identifier: MIT
/*
$info$
tags: Lib|FexBridge
desc: C-ABI embedding library around frontend-free FEXCore (the Wow64Probe
      findings, packaged for a native ppc64le caller such as Wine's ntdll).

  Links FEXCore + Common + CommonTools and deliberately NOT LinuxEmulation.
  Only the fexbridge_* symbols are exported (fexbridge.map); everything else,
  including the statically linked FEXCore and its allocator, stays local so
  nothing interposes on the host process.

  The four FEXCore fixes this depends on live in the same working tree
  (wow64-probe branch) and are compiled into this library:
    - WritePriorityMutex::is_write_owned() replacing side-effecting
      try_lock() asserts (Context.cpp/Core.cpp call sites)
    - DEF_OP(Syscall): no RAX store-back under OS_GENERIC
    - DEF_OP(Syscall): no syscall fill elision under OS_GENERIC
    - SyscallOp: block-end after syscall under OS_GENERIC (handler owns RIP)
$end_info$
*/

#include "fexbridge.h"

#include "Common/Config.h"
#include "Common/HostFeatures.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/fextl/memory.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <setjmp.h>
#include <signal.h>
#include <cerrno>
#include <cinttypes>
#include <sys/mman.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

namespace {

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
std::atomic<fexbridge_log_fn> LogCb {nullptr};

void EmitLog(int Level, const char* Message) {
  if (auto Cb = LogCb.load(std::memory_order_acquire)) {
    Cb(Level, Message);
  } else {
    fprintf(stderr, "fexbridge[%d]: %s\n", Level, Message);
  }
}

void MsgHandler(LogMan::DebugLevels Level, const char* Message) {
  EmitLog(static_cast<int>(Level), Message);
}

void AssertHandler(const char* Message) {
  EmitLog(0, Message);
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
struct RunFrame {
  RunFrame* Prev {};
  sigjmp_buf JB;
  bool ExitRequested {};
  uint64_t ExitRIP {};
};

struct BridgeThread {
  FEXCore::Core::InternalThreadState* Thread {};
  uint64_t CallRetAllocBase {};
  RunFrame* RunTop {}; // innermost active fexbridge_run on this host thread
};

FEXCore::Context::Context* CTX {};
std::atomic<fexbridge_trap_fn> TrapCb {nullptr};
std::atomic<void*> TrapUser {nullptr};
uint64_t HltPageAddr {}; // one guest-visible HLT, used to end a run cooperatively
bool Initialized {};
bool GuestIs64 {true};   // fixed by whichever process_init variant ran first

thread_local BridgeThread* TLSThread {};

constexpr size_t CALLRET_ALLOC = FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE + 2 * FEXCore::Utils::FEX_PAGE_SIZE;

// ---------------------------------------------------------------------------
// Embedder SyscallHandler: OS_GENERIC trap sink -> caller's trap callback.
// ---------------------------------------------------------------------------
struct BridgeSyscallHandler final : public FEXCore::HLE::SyscallHandler, public FEXCore::Allocator::FEXAllocOperators {
  BridgeSyscallHandler() {
    OSABI = FEXCore::HLE::SyscallOSABI::OS_GENERIC;
  }
  uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) override;
  std::optional<FEXCore::ExecutableFileSectionInfo> LookupExecutableFileSection(FEXCore::Core::InternalThreadState*, uint64_t) override {
    return std::nullopt;
  }
  FEXCore::HLE::ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState*, uint64_t Address) override {
    // The caller owns the address space, so mapped-and-readable is the only
    // honest definition of "fetchable" available here.  The old
    // {0, UINT64_MAX} answer made the frontend decoder blind-read any guest
    // jump target and take a REAL host SIGSEGV inside CompileCode -- with
    // the shared CodeInvalidationMutex held, where no signal handler can
    // safely unwind (this is how a Wine guest calling a wild pointer died
    // illegibly).  A page-granular readability probe routes an unfetchable
    // target through the frontend's own machinery instead:
    // CheckRangeExecutable sees Size == 0, CompileCode emits NoExecOp, and
    // fexbridge_run classifies that exit as FEXBRIDGE_RUN_FAULT with rip at
    // the bad address.
    //
    // process_vm_readv respects page protections (mincore/msync would call
    // a PROT_NONE guard page readable), and one syscall per compiled block
    // page is noise against the compile itself.  NX stays unenforced:
    // readable data is still "executable", exactly as before.
    const uint64_t PageSize = FEXCore::Utils::FEX_PAGE_SIZE;
    const uint64_t Page = Address & ~(PageSize - 1);
    uint8_t Probe;
    struct iovec Local {&Probe, 1};
    struct iovec Remote {reinterpret_cast<void*>(Page), 1};
    // Only EFAULT asserts anything about the page's protection.  Every other
    // failure (ENOMEM when the kernel cannot pin, EINTR) is about the
    // syscall, not the page -- and answering "unfetchable" for one of those
    // is not a transient wrong answer, it is a STICKY one: CompileCode
    // caches a NoExecOp block for the rip and every later call lands on the
    // cached refusal even after nothing was ever wrong (measured: Cyberpunk
    // 2077's crash handler at Cyberpunk2077.exe+29d07bc, readable at every
    // fault report, permanently NoExec).  So: retry the transient class,
    // and if it will not clear, say so loudly and answer fetchable -- the
    // worst case of that answer is the pre-probe behaviour (a real host
    // fault under the compile mutex), where the worst case of the other
    // answer is a wrong NoExec cached forever.
    for (int Attempt = 0;; ++Attempt) {
      if (process_vm_readv(getpid(), &Local, 1, &Remote, 1, 0) == 1) {
        break;
      }
      if (errno == EFAULT) {
        return {0, 0, true};
      }
      if (Attempt >= 3) {
        fprintf(stderr,
                "fexbridge[2]: executable probe of %#" PRIx64 " failed with "
                "errno %d; answering fetchable rather than caching NoExec\n",
                Page, errno);
        break;
      }
    }
    return {Page, PageSize, true};
  }
};

// FEXCore requires a SignalDelegator instance but has no pure virtuals; the
// bridge installs no signal handlers — the embedding process owns signals.
struct BridgeSignalDelegator final : public FEXCore::SignalDelegator, public FEXCore::Allocator::FEXAllocOperators {};

BridgeSyscallHandler* SyscallHandler {};
BridgeSignalDelegator* SigDelegator {};

// ---------------------------------------------------------------------------
// PROT_SAO hardware TSO (FEX_HWTSO).  The frontend's machinery lives in
// FEX::HLE (SetupTSOEmulation's probe, HardwareTSO::OnRangeRefusedSAO's
// refusal policy, SyscallHandler::RevokeHardwareTSO's closure) and none of it
// links here — the bridge deliberately excludes LinuxEmulation.  This is the
// same semantics re-hosted on the bridge's primitives, with one structural
// difference: the frontend owns the guest's mmap/mprotect choke points and
// applies the bit itself, while here the EMBEDDER owns the address space, so
// the bit crosses the C ABI (fexbridge_hwtso_prot) and refusals cross back
// (fexbridge_hwtso_refused).  Litmus/semantics provenance: SetupTSOEmulation
// in FEXInterpreter.cpp — MP violations 0/16.3M on SAO pages, and acceptance
// is meaningful because powerpc's arch_validate_prot rejects PROT_SAO
// whenever the CPU/MMU cannot honor it.
// ---------------------------------------------------------------------------
namespace HwTso {
constexpr int PROT_SAO_BIT = 0x10;
std::atomic<bool> Live {false};
bool Strict = false;

void ProbeAndEnable() {
  FEX_CONFIG_OPT(HWTSOEnabled, HWTSO);
  FEX_CONFIG_OPT(TSOEnabledOpt, TSOENABLED);
  if (!HWTSOEnabled() || !TSOEnabledOpt()) {
    return;
  }
  void* Probe = ::mmap(nullptr, FEXCore::Utils::FEX_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_SAO_BIT, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (Probe == MAP_FAILED) {
    fprintf(stderr,
            "fexbridge: FEX_HWTSO requested but this kernel/CPU rejected PROT_SAO (errno=%d). "
            "Falling back to atomic/barrier TSO emulation.\n",
            errno);
    return;
  }
  // Touch it so an accept-then-fault setup dies here, at init, not in-guest.
  *static_cast<volatile uint32_t*>(Probe) = 1;
  ::munmap(Probe, FEXCore::Utils::FEX_PAGE_SIZE);
  const char* StrictEnv = getenv("FEX_HWTSO_STRICT");
  Strict = StrictEnv && StrictEnv[0] == '1';
  Live.store(true, std::memory_order_release);
  CTX->SetHardwareTSOSupport(true);
  fprintf(stderr, "fexbridge: FEX_HWTSO live: PROT_SAO carries ordering, no TSO barriers emitted%s\n",
          Strict ? " (STRICT: a refused range aborts)" : "");
}
} // namespace HwTso

// ---------------------------------------------------------------------------
// CPUState <-> flat AMD64 CONTEXT marshalling (probe T3, verbatim semantics).
// YMM is carried through the internal trap round-trip so the flat CONTEXT
// (which has no YMM home) does not truncate AVX state across a trap.
// ---------------------------------------------------------------------------
void StoreStateToContext(FEXCore::Core::InternalThreadState* Thread, FEXBRIDGE_AMD64_CONTEXT* Context, __uint128_t* YMMOut) {
  const auto& State = Thread->CurrentFrame->State;
  const uint32_t Flags = Context->ContextFlags;

  if (Flags & FEXBRIDGE_CTX_CONTROL & ~FEXBRIDGE_CTX_AMD64) {
    Context->Rip = State.rip;
    Context->Rsp = State.gregs[FEXCore::X86State::REG_RSP];
    Context->SegCs = State.cs_idx;
    Context->SegSs = State.ss_idx;
    // State is spilled into the frame on every path this is called from
    // (syscall trap and HLT both spill; the fault path spills SRA first).
    Context->EFlags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);
  }

  if (Flags & FEXBRIDGE_CTX_INTEGER & ~FEXBRIDGE_CTX_AMD64) {
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

  if (Flags & FEXBRIDGE_CTX_SEGMENTS & ~FEXBRIDGE_CTX_AMD64) {
    Context->SegDs = State.ds_idx;
    Context->SegEs = State.es_idx;
    Context->SegFs = State.fs_idx;
    Context->SegGs = State.gs_idx;
  }

  if (Flags & FEXBRIDGE_CTX_FLOATING_POINT & ~FEXBRIDGE_CTX_AMD64) {
    // Never read State.xmm directly: physical layout is split-vs-converged
    // by host feature; on ppc64le the split layout is live.
    __uint128_t XMM[16];
    __uint128_t YMMLocal[16];
    __uint128_t* YMM = YMMOut ? YMMOut : YMMLocal;
    CTX->ReconstructXMMRegisters(Thread, XMM, YMM);
    memcpy(Context->FltSave.XmmRegisters, XMM, sizeof(XMM));

    Context->MxCsr = State.mxcsr;
    Context->FltSave.MxCsr = State.mxcsr;
    Context->FltSave.ControlWord = State.FCW;
    Context->FltSave.TagWord = State.AbridgedFTW;

    // x87 mm[] is stored rotated by TOP; the CONTEXT holds architectural
    // ST(0)..ST(7).
    const uint32_t Top = State.flags[FEXCore::X86State::X87FLAG_TOP_LOC];
    for (size_t i = 0; i < 8; ++i) {
      const size_t Phys = (Top + i) % 8;
      memcpy(&Context->FltSave.FloatRegisters[i], &State.mm[Phys][0], 16);
    }
    uint16_t FSW = 0;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C0_LOC] != 0) << 8;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C1_LOC] != 0) << 9;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C2_LOC] != 0) << 10;
    FSW |= (Top & 0b111) << 11;
    FSW |= (State.flags[FEXCore::X86State::X87FLAG_C3_LOC] != 0) << 14;
    Context->FltSave.StatusWord = FSW;

    // No FEX source for these; synthesise zero like a CPU DLL must.
    Context->FltSave.ErrorOffset = Context->FltSave.DataOffset = 0;
    Context->FltSave.ErrorOpcode = 0;
  }

  Context->Dr0 = Context->Dr1 = Context->Dr2 = Context->Dr3 = Context->Dr6 = Context->Dr7 = 0;
}

void LoadStateFromContext(FEXCore::Core::InternalThreadState* Thread, const FEXBRIDGE_AMD64_CONTEXT* Context, const __uint128_t* YMMIn) {
  auto& State = Thread->CurrentFrame->State;
  const uint32_t Flags = Context->ContextFlags;

  if (Flags & FEXBRIDGE_CTX_CONTROL & ~FEXBRIDGE_CTX_AMD64) {
    State.rip = Context->Rip;
    State.gregs[FEXCore::X86State::REG_RSP] = Context->Rsp;
    CTX->SetFlagsFromCompactedEFLAGS(Thread, Context->EFlags);
  }

  if (Flags & FEXBRIDGE_CTX_INTEGER & ~FEXBRIDGE_CTX_AMD64) {
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

  // FEXBRIDGE_CTX_SEGMENTS deliberately not loaded: the bridge owns the
  // emulated GDT (flat 64-bit CS), matching the probe and the WOW64 module.

  if (Flags & FEXBRIDGE_CTX_FLOATING_POINT & ~FEXBRIDGE_CTX_AMD64) {
    __uint128_t XMM[16];
    __uint128_t YMMZero[16] {};
    memcpy(XMM, Context->FltSave.XmmRegisters, sizeof(XMM));
    CTX->SetXMMRegistersFromState(Thread, XMM, YMMIn ? YMMIn : YMMZero);

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

// ---------------------------------------------------------------------------
// Trap sink. Marshals the full guest file to the caller, applies whatever the
// caller wrote, and either resumes or steers the run to a cooperative HLT.
// ---------------------------------------------------------------------------
uint64_t BridgeSyscallHandler::HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments*) {
  BridgeThread* BT = TLSThread;
  auto* Thread = Frame->Thread;

  alignas(16) FEXBRIDGE_AMD64_CONTEXT C {};
  alignas(16) __uint128_t YMM[16];
  C.ContextFlags = FEXBRIDGE_CTX_FULL | FEXBRIDGE_CTX_SEGMENTS;
  StoreStateToContext(Thread, &C, YMM);

  auto Cb = TrapCb.load(std::memory_order_acquire);
  int Result = FEXBRIDGE_TRAP_EXIT; // no handler: end the run, Rip at the trap
  if (Cb) {
    Result = Cb(BT, &C, TrapUser.load(std::memory_order_acquire));
    LoadStateFromContext(Thread, &C, YMM);
  }

  if (Result != FEXBRIDGE_TRAP_CONTINUE && BT && BT->RunTop) {
    // Cooperative exit: park the continuation RIP, route the guest through a
    // bridge-owned HLT so the JIT unwinds itself (no longjmp over JIT frames,
    // nothing abandoned), then restore the continuation in fexbridge_run.
    BT->RunTop->ExitRequested = true;
    BT->RunTop->ExitRIP = Frame->State.rip;
    Frame->State.rip = HltPageAddr;
  }
  // OS_GENERIC: return value is meaningless; the frame owns everything
  // (BranchOps.cpp fix). RIP is whatever the callback set — un-advanced RIP
  // loops on the trap by design, exactly like the WOW64 module.
  return 0;
}

// ---------------------------------------------------------------------------
// ppc64le fault-context helpers (probe T5, verbatim).
// ---------------------------------------------------------------------------
constexpr uint32_t PPC_PT_NIP = 32;
constexpr uint32_t PPC_PT_XER = 37;
constexpr uint32_t PPC_PT_CCR = 38;

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

// Repack ppc64le CR0+XER into the PSTATE word ReconstructCompactedEFLAGS
// expects when WasInJIT: CR0 carries N/Z, XER carries C/V.
uint64_t HostPStateFromContext(const ucontext_t* UC) {
  const uint64_t ccr = UC->uc_mcontext.gp_regs[PPC_PT_CCR];
  const uint64_t xer = UC->uc_mcontext.gp_regs[PPC_PT_XER];
  return (ccr & (1ULL << 31)) | ((ccr & (1ULL << 29)) << 1) | (xer & (1ULL << 29)) | ((xer & (1ULL << 30)) >> 2);
}

} // namespace

// ===========================================================================
// Exported C surface
// ===========================================================================
extern "C" {

uint32_t fexbridge_abi_version(void) {
  return FEXBRIDGE_ABI_VERSION;
}

void fexbridge_set_log_handler(fexbridge_log_fn cb) {
  LogCb.store(cb, std::memory_order_release);
}

static int process_init_common(bool Is64, uint64_t ExitPage) {
  if (Initialized) {
    if (GuestIs64 != Is64) {
      EmitLog(0, Is64 ? "fexbridge: process already initialized 32-bit; 64-bit init refused" :
                        "fexbridge: process already initialized 64-bit; 32-bit init refused");
      return -5;
    }
    return 0;
  }

  // 32-bit mode: the cooperative-exit trampoline the guest executes through
  // must live in the guest's own (4 GiB) address space, and only the caller's
  // memory manager can place a low page without racing whatever else owns
  // that range -- so the caller provides it, already filled with hlt and
  // executable.  Checked before any FEX state exists so a refusal is clean.
  if (!Is64 && (!ExitPage || (ExitPage >> 32) || ((ExitPage + FEXCore::Utils::FEX_PAGE_SIZE - 1) >> 32))) {
    EmitLog(0, "fexbridge: 32-bit init needs a caller-provided exit page below 4 GiB");
    return -4;
  }

  LogMan::Throw::InstallHandler(AssertHandler);
  LogMan::Msg::InstallHandler(MsgHandler);

  FEXCore::Config::Initialize();
  // The FEX_* environment, which until 2026-08-19 the bridge never read: no
  // frontend meant no config layers at all, so every knob the emulated lane
  // tunes through the environment (FEX_X87REDUCEDPRECISION being the
  // measured one -- fex-scripts/fex defaults it to 1 for every emulated
  // title) was silently inert for a native-lane guest.  The environment
  // layer is the ONLY layer added, deliberately: config files and AppConfig
  // stay out, because a bridge guest is launched by a tool (wine-ppc64le's
  // steamtool) whose appconfig/<appid>.env is already the per-title
  // mechanism, and two per-title mechanisms with different keys is how a
  // setting gets lost.
  //
  // What this does NOT change, by construction: the two Set() calls below
  // run AFTER ReloadMetaLayer(), so IS64BIT_MODE and SMCCHECKS still beat
  // anything the environment says -- FEX_SMCCHECKS=1 cannot turn
  // mprotect-based SMC tracking back on in a process with no frontend to
  // host it.  And FEX_HWTSO stays inert here for a different reason:
  // SetupTSOEmulation (the PROT_SAO probe) is FEXInterpreter's, the bridge
  // never runs it, so EffectiveHardwareTSO stays false and TSO barriers
  // keep being emitted -- safe, and named here so nobody reads a benchmark
  // delta into a knob that does not reach this JIT path.
  FEXCore::Config::AddLayer(FEX::Config::CreateEnvironmentLayer(environ));
  // Load() before ReloadMetaLayer(), because the meta merge reads each
  // layer's ALREADY-LOADED option map -- an added-but-unloaded layer merges
  // as empty, which is exactly the silent no-op the first cut of this
  // change shipped ([MEASURED] the x87 discriminator probe still answered
  // FULL-F80 under FEX_X87REDUCEDPRECISION=1 until this line existed).
  FEXCore::Config::Load();
  // Order matters (measured): ReloadMetaLayer() rebuilds the top layer and
  // DISCARDS anything Set() placed there earlier. Set after reload or the
  // 64-bit guest decodes with CS.L == 0.
  FEXCore::Config::ReloadMetaLayer();
  FEXCore::Config::Set(FEXCore::Config::CONFIG_IS64BIT_MODE, Is64 ? "1" : "0");
  // No frontend => no mprotect-based SMC tracking host. The caller reports
  // code writes through fexbridge_invalidate_code_range.
  FEXCore::Config::Set(FEXCore::Config::CONFIG_SMCCHECKS, "0");

  auto HostFeatures = FEX::FetchHostFeatures();
  auto CTXPtr = FEXCore::Context::Context::CreateNewContext(HostFeatures);
  if (!CTXPtr) {
    EmitLog(0, "fexbridge: CreateNewContext failed");
    return -1;
  }

  SyscallHandler = new BridgeSyscallHandler();
  SigDelegator = new BridgeSignalDelegator();

  CTX = CTXPtr.release(); // process-lifetime; FEX teardown is not re-entered
  CTX->SetSignalDelegator(SigDelegator);
  CTX->SetSyscallHandler(SyscallHandler);
  // Same ordering rule as the frontend's SetupTSOEmulation: hardware TSO must
  // be decided before the first block is compiled, so before InitCore.  The
  // embedder reads the verdict through fexbridge_hwtso_prot() after this
  // returns and retro-applies the bit to whatever it mapped before init.
  HwTso::ProbeAndEnable();
  if (!CTX->InitCore()) {
    EmitLog(0, "fexbridge: InitCore failed");
    return -2;
  }

  if (Is64) {
    // One guest-visible HLT used to end runs cooperatively.
    auto* Page = ::mmap(nullptr, FEXCore::Utils::FEX_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (Page == MAP_FAILED) {
      EmitLog(0, "fexbridge: HLT page mmap failed");
      return -3;
    }
    memset(Page, 0xF4 /* hlt */, FEXCore::Utils::FEX_PAGE_SIZE);
    HltPageAddr = reinterpret_cast<uint64_t>(Page);
  } else {
    HltPageAddr = ExitPage;
  }
  fexbridge_invalidate_code_range(HltPageAddr, FEXCore::Utils::FEX_PAGE_SIZE);

  GuestIs64 = Is64;
  Initialized = true;
  return 0;
}

int fexbridge_process_init(void) {
  return process_init_common(true, 0);
}

int fexbridge_process_init32(uint64_t exit_page) {
  return process_init_common(false, exit_page);
}

void fexbridge_set_trap_handler(fexbridge_trap_fn cb, void* user) {
  TrapUser.store(user, std::memory_order_release);
  TrapCb.store(cb, std::memory_order_release);
}

int fexbridge_thread_init(void** thread_out) {
  if (!Initialized || !thread_out) {
    return -1;
  }
  if (TLSThread) {
    return -2; // one guest thread per host thread
  }

  auto* Thread = CTX->CreateThread(0, 0);
  if (!Thread) {
    return -3;
  }
  auto* Frame = Thread->CurrentFrame;

  // GDT: CPUState carries private_gdt[32] inline; flat code segment.
  // These two CPUState fields are only ever initialised by frontend code —
  // the JIT reads garbage without them (probe finding).
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &Frame->State.private_gdt[0];
  Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &Frame->State.private_gdt[0];

  if (GuestIs64) {
    Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
    auto* GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Frame->State.cs_idx);
    FEXCore::Core::CPUState::SetGDTBase(GDT, 0);
    FEXCore::Core::CPUState::SetGDTLimit(GDT, 0xF'FFFFU);
    GDT->L = 1; // 64-bit guest
    GDT->D = 0;
    Frame->State.cs_cached = FEXCore::Core::CPUState::CalculateGDTBase(*GDT);
  } else {
    // 32-bit guest: the Windows flat model with Windows' own selector values,
    // because they are architecturally visible (mov %cs,%ax; a CONTEXT's
    // SegCs) and 32-bit code does look at them.  CS=0x23 (GDT index 4, RPL 3)
    // flat code with D=1; SS/DS/ES/GS=0x2B (index 5) flat data; FS=0x53
    // (index 10) is the TIB selector whose base fexbridge_set_fs_base
    // installs -- into the DESCRIPTOR as well as the cached copy, because a
    // segment reload recomputes the cached base from the descriptor
    // (OpDispatchBuilder::UpdatePrefixFromSegment reads the GDT qword).
    // Ordinary flat accesses never consult any of this: GetSegment's 32-bit
    // arm adds nothing for unprefixed DS/ES/SS and reads fs_cached for fs:.
    auto InitSeg = [&](uint32_t Selector, bool Code) {
      auto* GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(Frame->State, Selector);
      FEXCore::Core::CPUState::SetGDTBase(GDT, 0);
      FEXCore::Core::CPUState::SetGDTLimit(GDT, 0xF'FFFFU);
      GDT->Type = Code ? 0xB : 0x3; // accessed code RX / accessed data RW
      GDT->S = 1;
      GDT->DPL = 3;
      GDT->P = 1;
      GDT->L = 0;
      GDT->D = 1;
      GDT->G = 1;
    };
    InitSeg(0x23, true);
    InitSeg(0x2b, false);
    InitSeg(0x53, false); // base written by fexbridge_set_fs_base
    Frame->State.cs_idx = 0x23;
    Frame->State.ss_idx = Frame->State.ds_idx = Frame->State.es_idx = 0x2b;
    Frame->State.gs_idx = 0x2b;
    Frame->State.fs_idx = 0x53;
    Frame->State.cs_cached = Frame->State.ss_cached = 0;
    Frame->State.ds_cached = Frame->State.es_cached = 0;
    Frame->State.gs_cached = Frame->State.fs_cached = 0;
  }

  // Call-ret shadow stack, guard pages both sides.
  auto AllocBase = reinterpret_cast<uint64_t>(::mmap(nullptr, CALLRET_ALLOC, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (AllocBase == reinterpret_cast<uint64_t>(MAP_FAILED)) {
    CTX->DestroyThread(Thread);
    return -4;
  }
  Thread->CallRetStackBase = reinterpret_cast<void*>(AllocBase + FEXCore::Utils::FEX_PAGE_SIZE);
  ::mprotect(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
  Frame->State.callret_sp = AllocBase + FEXCore::Utils::FEX_PAGE_SIZE + FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE / 4;

  auto* BT = new BridgeThread();
  BT->Thread = Thread;
  BT->CallRetAllocBase = AllocBase;
  TLSThread = BT;
  *thread_out = BT;
  return 0;
}

void fexbridge_thread_term(void* thread) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || BT->RunTop) {
    return; // active run: refuse
  }
  if (TLSThread == BT) {
    TLSThread = nullptr;
  }
  CTX->DestroyThread(BT->Thread);
  ::munmap(reinterpret_cast<void*>(BT->CallRetAllocBase), CALLRET_ALLOC);
  delete BT;
}

int fexbridge_run(void* thread, void* ctx) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || BT != TLSThread) {
    return FEXBRIDGE_RUN_ERROR; // must run on the owning host thread
  }
  auto* Ctx = static_cast<FEXBRIDGE_AMD64_CONTEXT*>(ctx);
  if (Ctx) {
    LoadStateFromContext(BT->Thread, Ctx, nullptr);
  }

  RunFrame F {};
  F.Prev = BT->RunTop;
  BT->RunTop = &F;

  int Reason;
  if (sigsetjmp(F.JB, 1) == 0) {
    CTX->ExecuteThread(BT->Thread);
    if (F.ExitRequested) {
      // The run ended through the bridge HLT; put the callback's continuation
      // RIP back so the reported state is the state the guest will resume at.
      // The HLT executed on the way out populated SynchronousFaultData; clear
      // it as the other arm does, or a later run could classify against a
      // stale record.  Harmless today only because both non-exit sources
      // repopulate it; load-bearing for a caller (the 32-bit lane) that takes
      // this path on every single trap.
      BT->Thread->CurrentFrame->State.rip = F.ExitRIP;
      BT->Thread->CurrentFrame->SynchronousFaultData.FaultToTopAndGeneratedException = false;
      Reason = FEXBRIDGE_RUN_EXITED;
    } else {
      // Both a guest HLT and a NoExec entry block (a jump to unfetchable
      // memory, surfaced by QueryGuestExecutableRange above) leave through
      // the dispatcher's silent SIGSEGV stub, but their Break definitions
      // differ: HLT is TRAPNO_GP/si_code 0x80, NoExec is TRAPNO_PF/
      // SEGV_ACCERR (OpcodeDispatcher.cpp).  Classify by the
      // SynchronousFaultData the Break op populated; State.rip already
      // points at the unfetchable address for the fault case.
      auto& SFD = BT->Thread->CurrentFrame->SynchronousFaultData;
      if (SFD.FaultToTopAndGeneratedException && SFD.Signal == FEXCore::Core::FAULT_SIGSEGV &&
          SFD.TrapNo == FEXCore::X86State::X86_TRAPNO_PF) {
        Reason = FEXBRIDGE_RUN_FAULT;
      } else {
        Reason = FEXBRIDGE_RUN_HLT;
      }
      SFD.FaultToTopAndGeneratedException = false;
    }
  } else {
    // fexbridge_fault_unwind landed here; guest state was reconstructed from
    // the host fault context before the jump.
    Reason = FEXBRIDGE_RUN_FAULT;
  }
  BT->RunTop = F.Prev;

  if (Ctx) {
    Ctx->ContextFlags = FEXBRIDGE_CTX_FULL | FEXBRIDGE_CTX_SEGMENTS;
    StoreStateToContext(BT->Thread, Ctx, nullptr);
  }
  return Reason;
}

int fexbridge_get_context(void* thread, void* ctx) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || !ctx) {
    return -1;
  }
  StoreStateToContext(BT->Thread, static_cast<FEXBRIDGE_AMD64_CONTEXT*>(ctx), nullptr);
  return 0;
}

int fexbridge_set_context(void* thread, const void* ctx) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || !ctx) {
    return -1;
  }
  LoadStateFromContext(BT->Thread, static_cast<const FEXBRIDGE_AMD64_CONTEXT*>(ctx), nullptr);
  return 0;
}

// 64-bit FS/GS bases. CPUState holds these as plain per-thread uint64_t fields
// (gs_cached/fs_cached) which the JIT loads on every FS/GS-prefixed access
// (OpDispatchBuilder::GetSegment, Is64BitMode path) — there is no GDT
// involvement in 64-bit mode, a descriptor base being only 32 bits wide. So
// this is the same one-word store LinuxEmulation's arch_prctl(ARCH_SET_GS)
// performs, exposed for an embedder that has no Linux syscall layer.
int fexbridge_set_gs_base(void* thread, uint64_t base) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT) {
    return -1;
  }
  BT->Thread->CurrentFrame->State.gs_cached = base;
  return 0;
}

int fexbridge_get_gs_base(void* thread, uint64_t* base_out) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || !base_out) {
    return -1;
  }
  *base_out = BT->Thread->CurrentFrame->State.gs_cached;
  return 0;
}

int fexbridge_set_fs_base(void* thread, uint64_t base) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT) {
    return -1;
  }
  auto& State = BT->Thread->CurrentFrame->State;
  if (!GuestIs64) {
    // A 32-bit base has a second home: the FS descriptor.  A guest segment
    // reload (pop %fs) recomputes fs_cached from the descriptor, so a base
    // living only in the cache would silently revert to 0 the first time a
    // guest saves and restores FS around a call.  The descriptor base field
    // is 32 bits wide, which is also the honest limit for a 32-bit guest.
    if (base >> 32) {
      return -2;
    }
    auto* GDT = FEXCore::Core::CPUState::GetSegmentFromIndex(State, State.fs_idx);
    FEXCore::Core::CPUState::SetGDTBase(GDT, static_cast<uint32_t>(base));
  }
  State.fs_cached = base;
  return 0;
}

int fexbridge_get_fs_base(void* thread, uint64_t* base_out) {
  auto* BT = static_cast<BridgeThread*>(thread);
  if (!BT || !base_out) {
    return -1;
  }
  *base_out = BT->Thread->CurrentFrame->State.fs_cached;
  return 0;
}

void fexbridge_invalidate_code_range(uint64_t start, uint64_t length) {
  // Before any process init there is no context and nothing cached to
  // invalidate, and the embedder can not know our init state: wine's memory
  // syscalls forward every mapping change here from process start, while a
  // 32-bit-only process does not initialise the bridge until wow64cpu's
  // BTCpuProcessInit — dereferencing CTX here was a c0000005 inside that
  // very init (measured: check-wow64-smoke, the 32-bit lane started 0 times).
  if (!CTX) {
    return;
  }
  // InvalidateCodeBuffersCodeRange requires the caller to hold the code
  // invalidation mutex exclusively — unstated in the public header, enforced
  // by (previously side-effecting) assertions. Part of the CPU-DLL contract.
  std::scoped_lock Lk {CTX->GetCodeInvalidationMutex()};
  CTX->InvalidateCodeBuffersCodeRange(start, length);
}

uint32_t fexbridge_hwtso_prot(void) {
  return HwTso::Live.load(std::memory_order_acquire) ? HwTso::PROT_SAO_BIT : 0;
}

uint32_t fexbridge_hwtso_refused(uint64_t start, uint64_t length) {
  if (!HwTso::Live.load(std::memory_order_acquire)) {
    return 0;
  }
  fprintf(stderr,
          "fexbridge: HWTSO: kernel refused PROT_SAO for %#" PRIx64 "+%#" PRIx64 " on ordinary memory — "
          "this range would run with neither hardware ordering nor emitted barriers\n",
          start, length);
  if (HwTso::Strict) {
    fprintf(stderr, "fexbridge: FEX_HWTSO_STRICT: aborting so the refusing range can be identified.\n");
    abort();
  }
  // The frontend's RevokeHardwareTSO closure, on the bridge's primitives: the
  // flag flips and every translation is dropped inside the same exclusive
  // critical section, so everything compiled from here on reads
  // SupportsHardwareTSO == false and the first re-entry anywhere recompiles
  // with barriers.  A thread already inside a block finishes it barrier-free,
  // which is sound for the same reason as in the frontend: the refused range
  // does not exist from the guest's point of view until the embedder's
  // operation returns, and every range that already exists is still SAO.
  // Re-checked under the mutex so two refusals produce exactly one downgrade.
  if (CTX) {
    std::scoped_lock Lk {CTX->GetCodeInvalidationMutex()};
    if (HwTso::Live.load(std::memory_order_relaxed)) {
      CTX->InvalidateCodeBuffersCodeRange(0, ~0ULL);
      HwTso::Live.store(false, std::memory_order_release);
      CTX->SetHardwareTSOSupport(false);
      fprintf(stderr, "fexbridge: HWTSO revoked; TSO barriers are being emitted again.\n");
    }
  }
  return 0;
}

int fexbridge_fault_is_jit(const void* host_ucontext) {
  auto* BT = TLSThread;
  if (!BT || !host_ucontext) {
    return 0;
  }
  const auto* UC = static_cast<const ucontext_t*>(host_ucontext);
  return CTX->IsAddressInCodeBuffer(BT->Thread, UC->uc_mcontext.gp_regs[PPC_PT_NIP]) ? 1 : 0;
}

int fexbridge_fault_unwind(void* host_ucontext) {
  auto* BT = TLSThread;
  if (!BT || !BT->RunTop || !host_ucontext) {
    return 0;
  }
  auto* UC = static_cast<ucontext_t*>(host_ucontext);
  const uint64_t HostPC = UC->uc_mcontext.gp_regs[PPC_PT_NIP];
  if (!CTX->IsAddressInCodeBuffer(BT->Thread, HostPC)) {
    return 0;
  }

  // Reconstruct the guest register file from the host fault context (probe
  // T5): GPR/XMM through the published SRA maps, RIP through the JIT's
  // reverse map, EFLAGS from live host CR0/XER since NZCV/PF/AF are in host
  // condition registers at this instant, not in CPUState.
  SpillSRAFromHostContext(BT->Thread, UC);
  const uint64_t* HostGPRs = reinterpret_cast<const uint64_t*>(&UC->uc_mcontext.gp_regs[0]);
  const uint32_t EFlags = CTX->ReconstructCompactedEFLAGS(BT->Thread, true, HostGPRs, HostPStateFromContext(UC));
  CTX->SetFlagsFromCompactedEFLAGS(BT->Thread, EFlags);

  siglongjmp(BT->RunTop->JB, 1);
}

void* fexbridge_current_thread(void) {
  return TLSThread;
}

int fexbridge_run_entry(void* entry, void* arg, unsigned long long* rax_out, char* err, unsigned int errlen) {
  auto Fail = [&](const char* Fmt, uint64_t A = 0, uint64_t B = 0) {
    if (err && errlen) {
      snprintf(err, errlen, Fmt, (unsigned long long)A, (unsigned long long)B);
    }
    return 1;
  };

  if (!entry || !rax_out) {
    return Fail("fexbridge_run_entry: NULL entry or rax_out");
  }
  if (Initialized && !GuestIs64) {
    // The frame built below is MS-x64: 32-byte shadow space, RCX argument,
    // 64-bit return-address slot.  None of that exists for an i386 guest.
    return Fail("fexbridge_run_entry: process is in 32-bit guest mode; use fexbridge_run");
  }
  if (fexbridge_process_init() != 0) {
    return Fail("fexbridge_run_entry: process init failed");
  }

  // Adopt the caller's guest thread if this host thread already has one;
  // otherwise create a transient one.
  bool OwnThread = false;
  void* Thread = TLSThread;
  if (!Thread) {
    if (fexbridge_thread_init(&Thread) != 0) {
      return Fail("fexbridge_run_entry: thread init failed");
    }
    OwnThread = true;
  }

  // Guest stack: 8 MiB with a guard page below.
  constexpr size_t StackSize = 8ULL * 1024 * 1024;
  auto* StackBase = ::mmap(nullptr, StackSize + FEXCore::Utils::FEX_PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (StackBase == MAP_FAILED) {
    if (OwnThread) {
      fexbridge_thread_term(Thread);
    }
    return Fail("fexbridge_run_entry: stack mmap failed");
  }
  ::mprotect(reinterpret_cast<uint8_t*>(StackBase) + FEXCore::Utils::FEX_PAGE_SIZE, StackSize, PROT_READ | PROT_WRITE);
  const uint64_t StackTop = (reinterpret_cast<uint64_t>(StackBase) + FEXCore::Utils::FEX_PAGE_SIZE + StackSize) & ~0xFULL;

  // MS-x64 call frame: caller reserves 32 bytes of shadow space, CALL pushes
  // the return address, so at entry RSP % 16 == 8 and [RSP] is the return
  // address — preloaded to the bridge HLT trampoline.
  const uint64_t RSP = StackTop - 0x28;
  *reinterpret_cast<uint64_t*>(RSP) = HltPageAddr;

  FEXBRIDGE_AMD64_CONTEXT Ctx {};
  Ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  Ctx.Rip = reinterpret_cast<uint64_t>(entry);
  Ctx.Rsp = RSP;
  Ctx.Rcx = reinterpret_cast<uint64_t>(arg); // MS-x64 first argument
  Ctx.EFlags = 0x202;

  const int R = fexbridge_run(Thread, &Ctx);

  int Ret;
  if (R == FEXBRIDGE_RUN_HLT) {
    *rax_out = Ctx.Rax;
    Ret = 0;
  } else if (R == FEXBRIDGE_RUN_EXITED) {
    Ret = Fail("fexbridge_run_entry: guest trap (0F 05) at rip=0x%llx with no consuming handler", Ctx.Rip);
  } else if (R == FEXBRIDGE_RUN_FAULT) {
    Ret = Fail("fexbridge_run_entry: guest fault at rip=0x%llx", Ctx.Rip);
  } else {
    Ret = Fail("fexbridge_run_entry: run error %llu", (uint64_t)(int64_t)R);
  }

  ::munmap(StackBase, StackSize + FEXCore::Utils::FEX_PAGE_SIZE);
  if (OwnThread) {
    fexbridge_thread_term(Thread);
  }
  return Ret;
}

} // extern "C"
