// SPDX-License-Identifier: MIT
/*
$info$
tags: LinuxSyscalls|common
desc: Handles host -> host and host -> guest signal routing, emulates procmask & co
$end_info$
*/

#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/Syscalls.h"

#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/FPState.h>
#include <FEXCore/Utils/Profiler.h>
#include <FEXCore/Utils/ArchHelpers/Arm64.h>
#ifdef ARCHITECTURE_ppc64le
#include <FEXCore/Utils/ArchHelpers/PPC64.h>
#endif
#include <FEXHeaderUtils/Syscalls.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <linux/futex.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/uio.h>
#include <unistd.h>
#include <utility>

// For older build environments
#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif

namespace FEX::HLE {
#ifdef ARCHITECTURE_x86_64
__attribute__((naked)) static void sigrestore() {
  __asm volatile("syscall;" ::"a"(0xF) : "memory");
}
#endif

constexpr static uint32_t X86_MINSIGSTKSZ = 2048;

// FEX_SIGTRACE=1: raw write() tracing of the signal delivery/defer/drain/
// sigreturn flow. Diagnostic-only; snprintf in signal context matches the
// existing FEX_ABORT_TRIPWIRE precedent.
static bool SigTraceEnabled() {
  static const bool on = getenv("FEX_SIGTRACE") != nullptr;
  return on;
}
#define SIGTRACE(fmt, ...) \
  do { \
    if (SigTraceEnabled()) { \
      char _stbuf[256]; \
      int _stn = snprintf(_stbuf, sizeof(_stbuf), "[ST %d] " fmt "\n", FHU::Syscalls::gettid(), ##__VA_ARGS__); \
      [[maybe_unused]] auto _stw = write(2, _stbuf, _stn); \
    } \
  } while (0)

static FEX::HLE::ThreadStateObject* GetThreadFromAltStack(const stack_t& alt_stack) {
  // The thread object lives just before the alt-stack begin. If the alt-stack
  // is disabled or has no base (signal arrived during thread teardown after
  // sigaltstack(SS_DISABLE) in UninstallTLSState), there is no valid thread
  // pointer to read. Return nullptr so the caller can chain the default
  // handler -- the original fault is then preserved in a clean coredump
  // instead of being clobbered by a recovery-path double-fault.
  if ((alt_stack.ss_flags & SS_DISABLE) || alt_stack.ss_sp == nullptr) {
    return nullptr;
  }
  FEX::HLE::ThreadStateObject* ThreadObject {};
  memcpy(&ThreadObject, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(alt_stack.ss_sp) - 8), sizeof(void*));
  return ThreadObject;
}

// 2026-05-14 diagnostic: capture host PC + si_addr for every sync fault
// (SIGSEGV/SIGBUS/SIGILL/SIGFPE) BEFORE FEX hands it to the guest.  Steam
// installs breakpad which re-raises via tgkill, destroying the original
// si_code and clobbering host registers -- so the coredump shows post-
// breakpad state instead of the actual fault site.  Logging via raw
// write() to /tmp/fex_signal_trace.log is async-signal-safe.  Set
// FEX_TRACE_SIGNALS=1 to enable.  No-op otherwise; one atomic-load fast path.
// On the first fatal-signal hit, copy /proc/self/maps to /tmp/fex_maps.log so
// any LR / nip we log can be matched to a loaded library after the fact.
[[gnu::cold]]
static void DumpMapsOnce() {
  static int done = 0;
  if (done) return;
  done = 1;
  int in = ::open("/proc/self/maps", O_RDONLY);
  if (in < 0) return;
  int out = ::open("/tmp/fex_maps.log",
                    O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (out < 0) { ::close(in); return; }
  char buf[4096];
  ssize_t n;
  while ((n = ::read(in, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = ::write(out, buf + off, n - off);
      if (w <= 0) break;
      off += w;
    }
  }
  ::close(in);
  ::close(out);
}

[[gnu::cold]]
static void TraceSyncSignal(int Signal, siginfo_t* Info, ucontext_t* _context) {
  static int trace_fd = -2;
  if (trace_fd == -2) {
    if (getenv("FEX_TRACE_SIGNALS")) {
      trace_fd = ::open("/tmp/fex_signal_trace.log",
                        O_WRONLY | O_CREAT | O_APPEND, 0644);
      DumpMapsOnce();
    } else {
      trace_fd = -1;
    }
  }
  if (trace_fd < 0) return;
  // Build line manually (no fprintf -- not async-signal-safe).
  // Worst case with every field present is ~300 bytes (11 hex fields at up to
  // 18 chars each plus labels); 512 leaves headroom.
  char buf[512];
  auto write_hex = [](char* dst, uint64_t v) -> int {
    int n = 0;
    char tmp[18];
    if (v == 0) { tmp[n++] = '0'; }
    while (v) { int d = v & 0xf; tmp[n++] = (d < 10 ? '0'+d : 'a'+d-10); v >>= 4; }
    int len = 0;
    dst[len++] = '0'; dst[len++] = 'x';
    while (n > 0) dst[len++] = tmp[--n];
    return len;
  };
  int len = 0;
  const char* prefix = "FEX-SIG tid=";
  for (const char* p = prefix; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)::syscall(SYS_gettid));
  const char* sig = " sig="; for (const char* p = sig; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)Signal);
  const char* code = " code="; for (const char* p = code; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)Info->si_code);
  const char* addr = " addr="; for (const char* p = addr; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)Info->si_addr);
  const char* nip = " nip="; for (const char* p = nip; *p; p++) buf[len++] = *p;
#ifdef ARCHITECTURE_ppc64le
  len += write_hex(buf + len, (uint64_t)_context->uc_mcontext.regs->nip);
  const char* r27 = " r27="; for (const char* p = r27; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)_context->uc_mcontext.regs->gpr[27]);
  const char* r3 = " r3="; for (const char* p = r3; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)_context->uc_mcontext.regs->gpr[3]);
  const char* lr = " lr="; for (const char* p = lr; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)_context->uc_mcontext.regs->link);
  // Also r11 (guest RSP per FEX SRA mapping on PPC64LE).
  const char* r11 = " r11="; for (const char* p = r11; *p; p++) buf[len++] = *p;
  len += write_hex(buf + len, (uint64_t)_context->uc_mcontext.regs->gpr[11]);
#endif
  // Reconstructed GUEST RIP.  `nip=` above is the HOST program counter -- on a
  // fault taken inside JIT code it points into a code buffer that was mmap'd
  // after DumpMapsOnce() ran, so it resolves against nothing in
  // /tmp/fex_maps.log and it is NOT the guest instruction that faulted.  That
  // trap is documented in docs/POWER9_PORT_PLAN.md.  RestoreRIPFromHostPC()
  // maps the host PC back to the guest RIP via the block's inline RIP table.
  //
  // IMPORTANT: RestoreRIPFromHostPC() has no failure return.  When the host PC
  // is not inside the current JIT block it silently returns Frame->State.rip
  // (FEXCore/Source/Interface/Core/Core.cpp), which is a stale block-boundary
  // value, not the fault site -- and printing that unqualified would be
  // actively misleading here, since a stale zero would read as a null guest
  // RIP in exactly the null-deref bug being chased.  So the call is gated on
  // IsAddressInCodeBuffer(), the same guard SyscallHandler::
  // DetectMonoBackpatcherBlock (SyscallsSMCTracking.cpp) puts in front of this
  // exact call, and the field is printed as <none> when the guard fails.
  //
  // blk_rip= is the guest RIP of the current block's ENTRY (GetGuestBlockEntry,
  // read straight out of the JITCodeTail).  Coarser than guest_rip=, but it
  // does not depend on the per-instruction vl64pair table, so trust it if the
  // two disagree.  state_rip= is the raw Frame->State.rip and must ALWAYS be
  // read as "possibly stale" -- it is the value guest_rip= would have silently
  // degraded to on the fallback path.
  //
  // InJITCode is hoisted out of the block below because the GUEST GPR dump
  // (second trace line, PPC64LE only) is gated on the exact same condition:
  // the static register allocation only holds guest state while host execution
  // is inside a JIT code buffer.
  [[maybe_unused]] bool InJITCode = false;
#if defined(ARCHITECTURE_arm64) || defined(ARCHITECTURE_ppc64le)
  {
    // Re-entrancy guard.  Everything below dereferences JIT-owned memory
    // reached through CpuStateFrame::State.InlineJITBlockHeader.  If that
    // pointer is stale the deref faults *inside* this handler, re-enters
    // SignalHandlerThunk, and loops until the alt stack overflows -- which
    // would destroy the very trace we came here for.  A nested entry skips
    // reconstruction and prints <none>.
    static volatile sig_atomic_t InReconstruct = 0;
    uint64_t GuestRIP = 0, BlockRIP = 0, StateRIP = 0;
    bool HaveGuestRIP = false, HaveBlockRIP = false, HaveStateRIP = false;

    auto* ThreadObject = GetThreadFromAltStack(_context->uc_stack);
    if (ThreadObject && !InReconstruct) {
      // Same zombie-ThreadStateObject guard SignalHandlerThunk applies below:
      // after ThreadManager::DestroyThread sets ThreadInfo.IsZombie, the
      // slab is leaked and ->Thread must not be dereferenced.
      const uint32_t TraceHostTid = FHU::Syscalls::gettid();
      const bool ObjIsZombie = ThreadObject->ThreadInfo.IsZombie.load(std::memory_order_acquire);
      const uint32_t ObjTid = ThreadObject->ThreadInfo.TID.load(std::memory_order_relaxed);
      auto* Thread = ThreadObject->Thread;
      if (Thread && !ObjIsZombie && ObjTid == TraceHostTid) {
        InReconstruct = 1;
        const uint64_t HostPC = ArchHelpers::Context::GetPc(_context);
        StateRIP = Thread->CurrentFrame->State.rip;
        HaveStateRIP = true;
        if (Thread->CTX->IsAddressInCodeBuffer(Thread, HostPC)) {
          InJITCode = true;
          GuestRIP = Thread->CTX->RestoreRIPFromHostPC(Thread, HostPC);
          HaveGuestRIP = true;
          BlockRIP = Thread->CTX->GetGuestBlockEntry(Thread);
          HaveBlockRIP = BlockRIP != 0;
        }
        InReconstruct = 0;
      }
    }

    auto write_field = [&](const char* Name, bool Have, uint64_t Value) {
      for (const char* p = Name; *p; p++) {
        buf[len++] = *p;
      }
      if (Have) {
        len += write_hex(buf + len, Value);
      } else {
        for (const char* p = "<none>"; *p; p++) {
          buf[len++] = *p;
        }
      }
    };
    write_field(" guest_rip=", HaveGuestRIP, GuestRIP);
    write_field(" blk_rip=", HaveBlockRIP, BlockRIP);
    write_field(" state_rip=", HaveStateRIP, StateRIP);
  }
#endif
  buf[len++] = '\n';
  ::write(trace_fd, buf, len);

#ifdef ARCHITECTURE_ppc64le
  // ---------------------------------------------------------------------
  // Second trace line: the GUEST general-purpose register file.
  //
  // A second line rather than more fields on the first: 16 labelled 64-bit
  // hex fields is ~380 bytes on its own, and buf[512] above already carries
  // ~300 bytes worst case.  Separate buffer, separate write(), so neither
  // line can be truncated by the other.
  //
  // Emitted ONLY when the fault was taken inside a JIT code buffer.  The
  // guest register file lives in host registers under FEX's static register
  // allocation (SRA) while JIT code is executing; anywhere else those host
  // registers hold whatever FEXCore's own C++ left in them, and printing
  // that would look exactly like a plausible guest state.  Same
  // IsAddressInCodeBuffer() gate as guest_rip= above.  When the gate fails
  // an explicit marker is printed so "no register line" is never confused
  // with "this build does not have the patch".
  //
  // MAPPING SOURCE (duplicated by necessity, see below):
  //   FEXCore/Source/Interface/Core/ArchHelpers/PPC64Emitter.h
  //     x64::SRA -- std::array<GPR, 18>  (16 guest GPRs, then PF, AF)
  //     x32::SRA -- std::array<GPR, 10>  ( 8 guest GPRs, then PF, AF)
  //   Both arrays are indexed by the FEXCore::X86State::X86Reg enum
  //   (FEXCore/include/FEXCore/Core/X86Enums.h: RAX=0, RCX=1, RDX=2, RBX=3,
  //   RSP=4, RBP=5, RSI=6, RDI=7, R8..R15=8..15), because SRA[i] is the host
  //   register dedicated to CpuStateFrame::State.gregs[i] -- see
  //   PPC64EmitterBase::SpillStaticRegs/FillStaticRegs in PPC64Emitter.cpp.
  //
  //   *** The prose comment sitting above x64::SRA in that header claims the
  //   order is "RAX, RDX, RCX, ..." -- that comment is WRONG, RCX and RDX are
  //   transposed in it.  Index by the enum, not by that comment. ***
  //
  //   Resulting guest -> host GPR mapping (note host r13 is skipped; it is
  //   the ELFv2 thread pointer and is not in any FEX pool):
  //     rax->r7  rcx->r8  rdx->r9  rbx->r10 rsp->r11 rbp->r12 rsi->r14 rdi->r15
  //     r8 ->r16 r9 ->r17 r10->r18 r11->r19 r12->r20 r13->r21 r14->r22 r15->r23
  //   Corroborated by the existing host r11= field on the first line, whose
  //   observed value (0x3ffffffab78) is a plausible guest stack pointer.
  //
  // WHY DUPLICATED RATHER THAN DERIVED: PPC64Emitter.h is under
  // FEXCore/Source/, and it pulls in <PPC64LE/Emitter.h> / <PPC64LE/Registers.h>
  // from the external emitter.  Neither is on LinuxEmulation's include path
  // (target_include_directories in Source/Tools/LinuxEmulation/CMakeLists.txt
  // lists only ${CMAKE_BINARY_DIR}/generated, this directory, and the drm
  // headers), so x64::SRA / x32::SRA are unreachable from this TU.  If those
  // arrays ever change, this table must change with them.
  //
  // Names are printed with a leading '%' (%rax=, %r11=) to make it
  // unmistakable that these are GUEST x86 registers and not the HOST PPC64
  // registers printed on the first line -- which also carries an r11=.
  {
    struct GuestGPRMap {
      const char* Name;
      uint8_t HostGPR;
    };
    static constexpr GuestGPRMap Map64[] = {
      {" %rax=", 7},  {" %rcx=", 8},  {" %rdx=", 9},  {" %rbx=", 10},
      {" %rsp=", 11}, {" %rbp=", 12}, {" %rsi=", 14}, {" %rdi=", 15},
      {" %r8=", 16},  {" %r9=", 17},  {" %r10=", 18}, {" %r11=", 19},
      {" %r12=", 20}, {" %r13=", 21}, {" %r14=", 22}, {" %r15=", 23},
    };
    // x32::SRA's first 8 entries are the same host registers as x64::SRA's.
    static constexpr GuestGPRMap Map32[] = {
      {" %eax=", 7},  {" %ecx=", 8},  {" %edx=", 9},  {" %ebx=", 10},
      {" %esp=", 11}, {" %ebp=", 12}, {" %esi=", 14}, {" %edi=", 15},
    };

    // 16 fields * (6 label + 18 hex) = 384, plus a ~40 byte prefix. 512 is
    // enough; 640 leaves the same kind of headroom buf[512] has above.
    char gbuf[640];
    int glen = 0;
    auto put = [&](const char* s) {
      for (const char* p = s; *p; p++) {
        gbuf[glen++] = *p;
      }
    };
    put("FEX-SIG-GUEST tid=");
    glen += write_hex(gbuf + glen, (uint64_t)::syscall(SYS_gettid));

    // Guest bitness. _SyscallHandler is a process-global set during startup;
    // Is64BitMode() is a cached config read (plain member load, no lock, no
    // allocation), so it is safe here. If it is somehow null we must not
    // guess -- printing x64 names for a 32-bit guest is exactly the kind of
    // mislabelling this line exists to prevent.
    if (!InJITCode) {
      put(" <not-in-jit-code:sra-does-not-hold-guest-state>");
    } else if (FEX::HLE::_SyscallHandler == nullptr) {
      put(" <unknown-guest-bitness>");
    } else {
      const bool Is64Bit = FEX::HLE::_SyscallHandler->Is64BitMode();
      const GuestGPRMap* Map = Is64Bit ? Map64 : Map32;
      const size_t Count = Is64Bit ? 16u : 8u;
      for (size_t i = 0; i < Count; ++i) {
        put(Map[i].Name);
        uint64_t Value = (uint64_t)_context->uc_mcontext.regs->gpr[Map[i].HostGPR];
        if (!Is64Bit) {
          // Only the low 32 bits are architecturally defined for an i686
          // guest; FillStaticRegs zero-extends on entry but in-block results
          // can leave junk in the upper half. Mask so it reads as x86 state.
          Value &= 0xFFFF'FFFFULL;
        }
        glen += write_hex(gbuf + glen, Value);
      }
    }
    gbuf[glen++] = '\n';
    ::write(trace_fd, gbuf, glen);
  }
#endif
}

static void SignalHandlerThunk(int Signal, siginfo_t* Info, void* UContext) {
  ucontext_t* _context = (ucontext_t*)UContext;
  // Diagnostic: log the raw kernel-delivered context before any FEX/guest
  // handler runs.  Steam's breakpad clobbers this in the post-mortem
  // coredump via SIGSEGV re-raise (tgkill SI_TKILL).
  if (Signal == SIGSEGV || Signal == SIGBUS || Signal == SIGILL || Signal == SIGFPE) {
    TraceSyncSignal(Signal, Info, _context);
  }
  auto ThreadObject = GetThreadFromAltStack(_context->uc_stack);
  if (!ThreadObject) {
    // No valid alt-stack: cannot dispatch this signal through FEX. Restore
    // the default disposition and return -- the kernel will re-deliver on
    // resume, preserving the original fault NIP/siginfo in the coredump.
    struct sigaction sa {};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(Signal, &sa, nullptr);
    return;
  }
  // UAF guard (Steam SteamRT3 teardown race, 2026-05-15): the kernel can
  // deliver an in-flight signal AFTER ThreadManager::DestroyThread has run
  // (which sets ThreadInfo.IsZombie before leaking the slab). If the
  // object is marked zombie or the TID does not match the current kernel
  // TID, the ThreadObject is dead-mail and dereferencing ->Thread /
  // ->SignalInfo crashes. Fall through to default disposition; coredump
  // preserves original siginfo.
  const uint32_t HostTid = FHU::Syscalls::gettid();
  const bool ObjIsZombie = ThreadObject->ThreadInfo.IsZombie.load(std::memory_order_acquire);
  const uint32_t ObjTid = ThreadObject->ThreadInfo.TID.load(std::memory_order_relaxed);
  if (ObjIsZombie || ObjTid != HostTid) {
    struct sigaction sa {};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(Signal, &sa, nullptr);
    return;
  }
  FEXCORE_PROFILE_ACCUMULATION(ThreadObject->Thread, AccumulatedSignalTime);
  ThreadObject->SignalInfo.Delegator->HandleSignal(ThreadObject, Signal, Info, UContext);
}

uint64_t SigIsMember(GuestSAMask* Set, int Signal) {
  // Signal 0 isn't real, so everything is offset by one inside the set
  Signal -= 1;
  return (Set->Val >> Signal) & 1;
}

uint64_t SetSignal(GuestSAMask* Set, int Signal) {
  // Signal 0 isn't real, so everything is offset by one inside the set
  Signal -= 1;
  return Set->Val | (1ULL << Signal);
}

/**
 * @name Signal frame setup
 * @{ */

void SignalDelegator::HandleSignal(FEX::HLE::ThreadStateObject* Thread, int Signal, void* Info, void* UContext) {
  // Let the host take first stab at handling the signal
  if (!Thread) {
    LogMan::Msg::AFmt("Thread {} has received a signal and hasn't registered itself with the delegate! Programming error!",
                      FHU::Syscalls::gettid());
  } else {
    // FEX_SIGFAULTWATCH=1 logs every fault signal on entry, with the guest RIP
    // and faulting address, BEFORE any handler runs.
    //
    // It has to be here rather than further down: FEX's own handlers (SMC
    // tracking) and the frontend handler both return early when they claim a
    // signal, and the frontend is what delivers a fault to the guest — so
    // anything logged after them misses precisely the deliveries of interest.
    //
    // FEX_SIGRIPWATCH cannot answer this either: it lives in SpillSRA, so it
    // only sees signals arriving while the guest is in JIT code with static
    // registers live. A fault taken inside a thunk, or entering/leaving one,
    // never reaches it. Both were silent on a 32-bit Unity title (Dex) that
    // demonstrably takes a SIGSEGV.
    if (Signal == SIGSEGV || Signal == SIGBUS || Signal == SIGILL || Signal == SIGFPE) {
      static const bool FaultWatch = getenv("FEX_SIGFAULTWATCH") != nullptr;
      if (FaultWatch) {
        const auto* SigInfo = static_cast<const siginfo_t*>(Info);
        const auto& G = Thread->Thread->CurrentFrame->State.gregs;
        LogMan::Msg::IFmt("SigFaultWatch: tid {} sig {} code {} fault_addr 0x{:x} guest rip 0x{:x} rsp 0x{:x} "
                          "rax 0x{:x} rbx 0x{:x} rcx 0x{:x} rdx 0x{:x} rsi 0x{:x} rdi 0x{:x} rbp 0x{:x}",
                          FHU::Syscalls::gettid(), Signal, SigInfo->si_code, reinterpret_cast<uint64_t>(SigInfo->si_addr),
                          Thread->Thread->CurrentFrame->State.rip, G[FEXCore::X86State::REG_RSP], G[FEXCore::X86State::REG_RAX],
                          G[FEXCore::X86State::REG_RBX], G[FEXCore::X86State::REG_RCX], G[FEXCore::X86State::REG_RDX],
                          G[FEXCore::X86State::REG_RSI], G[FEXCore::X86State::REG_RDI], G[FEXCore::X86State::REG_RBP]);
      }
    }

    SignalHandler& Handler = HostHandlers[Signal];
    for (auto& HandlerFunc : Handler.Handlers) {
      if (HandlerFunc(Thread->Thread, Signal, Info, UContext)) {
        // If the host handler handled the fault then we can continue now
        return;
      }
    }

    if (Handler.FrontendHandler && Handler.FrontendHandler(Thread->Thread, Signal, Info, UContext)) {
      return;
    }

    // Now let the frontend handle the signal
    // It's clearly a guest signal and this ends up being an OS specific issue
    HandleGuestSignal(Thread, Signal, Info, UContext);
  }
}

void SignalDelegator::RegisterHostSignalHandler(int Signal, HostSignalDelegatorFunction Func, bool Required) {
  SetHostSignalHandler(Signal, std::move(Func), Required);
  FrontendRegisterHostSignalHandler(Signal, Required);
}

void SignalDelegator::SpillSRA(FEXCore::Core::InternalThreadState* Thread, void* ucontext, uint32_t IgnoreMask) {
#if defined(ARCHITECTURE_arm64) || defined(ARCHITECTURE_ppc64le)
  Thread->CurrentFrame->State.rip = CTX->RestoreRIPFromHostPC(Thread, ArchHelpers::Context::GetPc(ucontext));

  for (size_t i = 0; i < Config.SRAGPRCount; i++) {
    const uint8_t SRAIdxMap = Config.SRAGPRMapping[i];
    if (IgnoreMask & (1U << SRAIdxMap)) {
      // Skip this one, it's already spilled
      continue;
    }
    // NOTE: read the ucontext slot DIRECTLY, not via GetArmReg().
    // GetArmReg() applies a cross-arch ARM-X-name -> PPC-r-reg `+3` shift
    // (ARM X0 -> PPC r3 = TMP1, etc.) for callers like
    // SyscallHandler::HandleSegfault that name registers in ARM terms.
    // SRAGPRMapping[i] is the *host-native* register index (ARM xN on
    // arm64, PPC rN on ppc64le); passing it through GetArmReg on ppc64le
    // silently rotated every gregs[i] read by 3 slots, producing the
    // recurring "bogus-RSP / RAX==RSP / ".com"-fragment" cascade seen
    // during signal-during-JIT delivery (see project_spillsra_offset_bug).
    // GetArmGPRs() returns the raw gp_regs[0] pointer on both arches,
    // matching SRAGPRMapping's native-index semantics.
    Thread->CurrentFrame->State.gregs[i] = ArchHelpers::Context::GetArmGPRs(ucontext)[SRAIdxMap];
  }

  // Spill the SRA-mapped host FPRs (guest XMM low-128) back into guest State.
  //
  // The destination view depends on whether the host keeps XMM/YMM in CONVERGED
  // 256-bit registers (arm64 SVE256): converged hosts interleave low+high in the
  // 32-byte-stride xmm.avx.data slots (low at [i][0], high at [i][2]); every
  // other host keeps the low 128 in the 16-byte-stride xmm.sse.data view (high
  // 128 lives separately in State.avx_high). This must match the JIT's own SRA
  // fill/spill (PPC64Emitter/ARM emitter) or the values scatter — see the same
  // branch in ContextImpl::SetXMMRegistersFromState.
  //
  // PPC64LE advertises AVX (guest CPUID) but has NO converged registers, and its
  // JIT stores SRA XMMs in sse.data. Gating only on SupportsAVX — which on arm64
  // implies SVE256 — silently selected the 32-byte avx.data stride here, writing
  // xmm[k] into sse.data[2k] and zeroing the odd slots (the movss/movsd store in
  // fpr_store_pattern.asm faults on its own code page under SMC mtrack, and this
  // spill then corrupted the live XMM file). On ppc64le the low 128 must land in
  // sse.data, exactly as the non-AVX path does.
#ifdef ARCHITECTURE_ppc64le
  constexpr bool UseConvergedAVXStorage = false;
#else
  const bool UseConvergedAVXStorage = SupportsAVX;
#endif
  if (UseConvergedAVXStorage) {
    // TODO: This doesn't save the upper 128-bits of the 256-bit registers.
    // This needs to be implemented still.
    for (size_t i = 0; i < Config.SRAFPRCount; i++) {
      auto FPR = ArchHelpers::Context::GetArmFPR(ucontext, Config.SRAFPRMapping[i]);
      memcpy(&Thread->CurrentFrame->State.xmm.avx.data[i][0], &FPR, sizeof(__uint128_t));
    }
  } else {
    for (size_t i = 0; i < Config.SRAFPRCount; i++) {
      auto FPR = ArchHelpers::Context::GetArmFPR(ucontext, Config.SRAFPRMapping[i]);
      memcpy(&Thread->CurrentFrame->State.xmm.sse.data[i][0], &FPR, sizeof(__uint128_t));
    }
  }

#ifdef ARCHITECTURE_ppc64le
  // AVX-high VSX bank: guest YMM_hi[i] lives in host vs(First+i) while the
  // thread runs JIT code (Count is zero unless AVX is advertised). Capture
  // into State.avx_high so the guest sigframe XSTATE and any State readers
  // see current high halves. Register layout is the VR convention: dw1 =
  // guest LOW qword -> avx_high[i][0], dw0 = guest HIGH -> [i][1]. The bank
  // is ELFv2 callee-saved, so the frame values are valid even when the
  // signal landed inside a host helper call.
  for (size_t i = 0; i < Config.SRAAVXHighBankCount; i++) {
    const uint32_t Reg = Config.SRAAVXHighBankFirst + i;
    Thread->CurrentFrame->State.avx_high[i][0] = ArchHelpers::Context::GetPPCVSXLowBankDW1(ucontext, Reg);
    Thread->CurrentFrame->State.avx_high[i][1] = ArchHelpers::Context::GetPPCVSXLowBankDW0(ucontext, Reg);
  }
#endif

  uint32_t EFlags =
    CTX->ReconstructCompactedEFLAGS(Thread, true, ArchHelpers::Context::GetArmGPRs(ucontext), ArchHelpers::Context::GetArmPState(ucontext));
  CTX->SetFlagsFromCompactedEFLAGS(Thread, EFlags);

  // Root-cause tripwire for the Ziggurat finalize spin (docs/
  // ZIGGURAT_FINALIZE_SPIN.md): FEX_SIGRIPWATCH=0xBEGIN-0xEND logs every
  // in-JIT signal delivery whose RECONSTRUCTED guest RIP lands in the range,
  // with the host PC and the loop's registers. The suspicion is a resume
  // landing on the wrong instruction boundary so the induction-register init
  // is skipped — this catches the reconstruction in the act, with the
  // register values needed to judge whether they are consistent with the
  // claimed RIP.
  static const auto SigRIPWatch = []() -> std::pair<uint64_t, uint64_t> {
    const char* Env = getenv("FEX_SIGRIPWATCH");
    if (!Env) {
      return {0, 0};
    }
    char* End {};
    const uint64_t Begin = std::strtoull(Env, &End, 0);
    if (*End != '-') {
      return {0, 0};
    }
    return {Begin, std::strtoull(End + 1, nullptr, 0)};
  }();
  if (SigRIPWatch.second) {
    const uint64_t RIP = Thread->CurrentFrame->State.rip;
    if (RIP >= SigRIPWatch.first && RIP < SigRIPWatch.second) {
      const auto& G = Thread->CurrentFrame->State.gregs;
      LogMan::Msg::IFmt("SigRIPWatch: tid {} host pc 0x{:x} -> guest rip 0x{:x} RBX=0x{:x} R12=0x{:x} R14=0x{:x} R15=0x{:x}",
                        FHU::Syscalls::gettid(), reinterpret_cast<uint64_t>(ArchHelpers::Context::GetPc(ucontext)), RIP,
                        G[FEXCore::X86State::REG_RBX], G[FEXCore::X86State::REG_R12], G[FEXCore::X86State::REG_R14],
                        G[FEXCore::X86State::REG_R15]);
    }
  }
#endif
}

ArchHelpers::Context::ContextBackup* SignalDelegator::StoreThreadState(FEXCore::Core::InternalThreadState* Thread, int Signal, void* ucontext) {
  // We can end up getting a signal at any point in our host state
  // Jump to a handler that saves all state so we can safely return
  uint64_t OldSP = ArchHelpers::Context::GetSp(ucontext);
  uintptr_t NewSP = OldSP;

  size_t StackOffset = sizeof(ArchHelpers::Context::ContextBackup);

  // We need to back up behind the host's red zone
  // We do this on the guest side as well
  // (does nothing on arm hosts)
  NewSP -= ArchHelpers::Context::ContextBackup::RedZoneSize;

  NewSP -= StackOffset;
  NewSP = FEXCore::AlignDown(NewSP, 16);

  auto Context = reinterpret_cast<ArchHelpers::Context::ContextBackup*>(NewSP);
  ArchHelpers::Context::BackupContext(ucontext, Context);

  // Retain the action pointer so we can see it when we return
  Context->Signal = Signal;

  // Save guest state
  // We can't guarantee if registers are in context or host GPRs
  // So we need to save everything
  memcpy(&Context->GuestState, &Thread->CurrentFrame->State, sizeof(FEXCore::Core::CPUState));

  // Set the new SP
  ArchHelpers::Context::SetSp(ucontext, NewSP);

  Context->Flags = 0;
  Context->FPStateLocation = 0;
  Context->UContextLocation = 0;
  Context->SigInfoLocation = 0;
  Context->InSyscallInfo = 0;

  // Store fault to top status and then reset it
  Context->FaultToTopAndGeneratedException = Thread->CurrentFrame->SynchronousFaultData.FaultToTopAndGeneratedException;
  Thread->CurrentFrame->SynchronousFaultData.FaultToTopAndGeneratedException = false;

  return Context;
}

void SignalDelegator::RestoreThreadState(FEXCore::Core::InternalThreadState* Thread, void* ucontext, RestoreType Type) {
  uint64_t OldSP {};
  if (Type == RestoreType::TYPE_PAUSE) [[unlikely]] {
    OldSP = ArchHelpers::Context::GetSp(ucontext);
  } else {
    // Some fun introspection here.
    // We store a pointer to our host-stack on the guest stack.
    // We need to inspect the guest state coming in, so we can get our host stack back.
    uint64_t GuestSP = Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];

    if (Is64BitMode) {
      // Signal frame layout on stack needs to be as follows
      // void* ReturnPointer
      // ucontext_t
      // siginfo_t
      // FP state
      // Host stack location

      GuestSP += sizeof(FEXCore::x86_64::ucontext_t);
      GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::ucontext_t));

      GuestSP += sizeof(siginfo_t);
      GuestSP = FEXCore::AlignUp(GuestSP, alignof(siginfo_t));

      if (SupportsAVX) {
        GuestSP += sizeof(FEXCore::x86_64::xstate);
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::xstate));
      } else {
        GuestSP += sizeof(FEXCore::x86_64::_libc_fpstate);
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86_64::_libc_fpstate));
      }
    } else {
      if (Type == RestoreType::TYPE_NONREALTIME) {
        // Signal frame layout on stack needs to be as follows
        // SigFrame_i32
        // FPState
        // Host stack location

        // Remove the 4-byte pretcode /AND/ a legacy argument that is ignored.
        GuestSP += sizeof(SigFrame_i32) - 8;
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(SigFrame_i32));

        if (SupportsAVX) {
          GuestSP += sizeof(FEXCore::x86::xstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::xstate));
        } else {
          GuestSP += sizeof(FEXCore::x86::_libc_fpstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::_libc_fpstate));
        }
      } else {
        // Signal frame layout on stack needs to be as follows
        // RTSigFrame_i32
        // FPState
        // Host stack location

        // Remove the 4-byte pretcode.
        GuestSP += sizeof(RTSigFrame_i32) - 4;
        GuestSP = FEXCore::AlignUp(GuestSP, alignof(RTSigFrame_i32));

        if (SupportsAVX) {
          GuestSP += sizeof(FEXCore::x86::xstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::xstate));
        } else {
          GuestSP += sizeof(FEXCore::x86::_libc_fpstate);
          GuestSP = FEXCore::AlignUp(GuestSP, alignof(FEXCore::x86::_libc_fpstate));
        }
      }
    }

    OldSP = *reinterpret_cast<uint64_t*>(GuestSP);
  }

  uintptr_t NewSP = OldSP;
  auto Context = reinterpret_cast<ArchHelpers::Context::ContextBackup*>(NewSP);

#ifdef ARCHITECTURE_ppc64le
  // r10 is included because it is the SRA home of guest RBX: an INJIT resume
  // that reinstates a stale r10 is the current prime suspect for the
  // finalize-spin corruption (docs/ZIGGURAT_FINALIZE_SPIN.md), and this line
  // is the only place that value is visible.
  SIGTRACE("RESTORE type=%d guest_rsp=0x%lx backup=0x%lx nip=0x%lx lr=0x%lx r10=0x%lx flags=0x%x isi=0x%x sig=%d",
           (int)Type, (unsigned long)Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP], (unsigned long)NewSP,
           (unsigned long)Context->GPRs[32], (unsigned long)Context->GPRs[36], (unsigned long)Context->GPRs[10], Context->Flags,
           (unsigned)Context->InSyscallInfo, Context->Signal);
#endif

  // Restore host state
  ArchHelpers::Context::RestoreContext(ucontext, Context);

  // Reset the guest state
  memcpy(&Thread->CurrentFrame->State, &Context->GuestState, sizeof(FEXCore::Core::CPUState));

  if (Context->UContextLocation) {
    auto Frame = Thread->CurrentFrame;

    if (Context->Flags & ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT) {
      // 2026-05-15: PPC64LE used to route INJIT signal returns through the
      // dispatcher's FillSRA entry because BackupContext didn't save VMX
      // (V0..V31).  That workaround broke signal-driven inter-thread wakeups
      // (Steam manifest deadlock, Mono/.NET GC busy loops) by forcing every
      // signal return to re-enter the JIT block from its head with state
      // memcpy'd back from memory.  With BackupContext/RestoreContext now
      // saving and restoring VMX state (MContext_ppc64le.h), PPC64LE can
      // resume at the original NIP like ARM64 -- the kernel's RestoreContext
      // path runs, RestoreContext puts V0..V31 back, and execution continues
      // mid-block with the live pre-signal register file.
      Frame->InSyscallInfo = Context->InSyscallInfo;
    } else {
      // Outside-JIT deliveries stash InSyscallInfo too (a thread blocked in a
      // guest syscall like sigsuspend has 0xFFFF set while sitting in host C).
      // Reinstate it with the resumed context so the interrupted syscall op's
      // tail sees the state it left behind; while the handler ran it was 0.
      Frame->InSyscallInfo = Context->InSyscallInfo;
    }

    if (Is64BitMode) {
      RestoreFrame_x64(Thread, Context, Frame, ucontext);
    } else {
      if (Type == RestoreType::TYPE_NONREALTIME) {
        RestoreFrame_ia32(Thread, Context, Frame, ucontext);
      } else {
        RestoreRTFrame_ia32(Thread, Context, Frame, ucontext);
      }
    }
  }
}

bool SignalDelegator::HandleDispatcherGuestSignal(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext,
                                                  GuestSigAction* GuestAction, stack_t* GuestStack) {
  auto ContextBackup = StoreThreadState(Thread, Signal, ucontext);

  auto Frame = Thread->CurrentFrame;

  // Ref count our faults
  // We use this to track if it is safe to clear cache
  ++Thread->CurrentFrame->SignalHandlerRefCounter;

  uint64_t OldPC = ArchHelpers::Context::GetPc(ucontext);
  const bool WasInJIT = CTX->IsAddressInCodeBuffer(Thread, OldPC);

  // Spill the SRA regardless of signal handler type
  // We are going to be returning to the top of the dispatcher which will fill again
  // Otherwise we might load garbage
  if (WasInJIT) {
    uint32_t IgnoreMask {};
#if defined(ARCHITECTURE_arm64) || defined(ARCHITECTURE_ppc64le)
    if (Frame->InSyscallInfo != 0) {
      // We are in a syscall, this means we are in a weird register state
      // We need to spill SRA but only some of it, since some values have already been spilled
      // Lower 16 bits tells us which registers are already spilled to the context
      // So we ignore spilling those ones
      IgnoreMask = Frame->InSyscallInfo & 0xFFFF;
    } else {
      // We must spill everything
      IgnoreMask = 0;
    }
#endif

    // We are in jit, SRA must be spilled
    SpillSRA(Thread, ucontext, IgnoreMask);

#if defined(ARCHITECTURE_ppc64le)
    // StoreThreadState captured GuestState BEFORE SpillSRA ran. SpillSRA has
    // now committed the correct x86 state (gregs, rip, xmm) from the actual
    // signal-arrival register file into Thread->CurrentFrame->State. Re-capture
    // so that RestoreThreadState's memcpy(State, GuestState) restores the
    // authoritative pre-signal values rather than a stale one-block-behind copy.
    memcpy(&ContextBackup->GuestState, &Thread->CurrentFrame->State,
           sizeof(FEXCore::Core::CPUState));
#endif

    ContextBackup->Flags |= ArchHelpers::Context::ContextFlags::CONTEXT_FLAG_INJIT;

    // We are leaving the syscall information behind. Make sure to store the previous state.
    ContextBackup->InSyscallInfo = Thread->CurrentFrame->InSyscallInfo;
    Thread->CurrentFrame->InSyscallInfo = 0;
    SIGTRACE("DELIVER sig=%d injit pc=0x%lx rip=0x%lx rsp=0x%lx backup=0x%lx isi=0x%x", Signal, OldPC,
             (unsigned long)Frame->State.rip, (unsigned long)Frame->State.gregs[FEXCore::X86State::REG_RSP],
             (unsigned long)(uintptr_t)ContextBackup, (unsigned)ContextBackup->InSyscallInfo);
  } else {
    // The interrupted context can still be mid-syscall even though the host
    // PC is outside the JIT: DEF_OP(Syscall) sets Frame->InSyscallInfo=0xFFFF
    // before bctrl'ing into C, so a thread blocked in e.g. sigsuspend carries
    // the in-syscall spill mask while it waits. The guest handler we are about
    // to dispatch runs fresh JIT blocks; if the stale mask is left set, any
    // nested mid-JIT delivery (deferred-signal drain at a poke, another GC
    // suspend) takes SpillSRA's partial-spill path at a boundary that is NOT
    // the syscall window and freezes guest RAX..RDI at stale memory values.
    // That was the Ziggurat "SRA corruption" wedge: Boehm GC's SIGPWR/SIGXCPU
    // storm nests exactly this way (stop handler parked in sigsuspend).
    // Scope it like the InJIT branch does: stash in the backup, clear for the
    // handler, and RestoreThreadState reinstates it with the resumed context.
    ContextBackup->InSyscallInfo = Thread->CurrentFrame->InSyscallInfo;
    Thread->CurrentFrame->InSyscallInfo = 0;
    SIGTRACE("DELIVER sig=%d outside pc=0x%lx indisp=%d rip=0x%lx rsp=0x%lx backup=0x%lx isi=0x%x", Signal, OldPC,
             IsAddressInDispatcher(OldPC) ? 1 : 0, (unsigned long)Frame->State.rip,
             (unsigned long)Frame->State.gregs[FEXCore::X86State::REG_RSP], (unsigned long)(uintptr_t)ContextBackup,
             (unsigned)ContextBackup->InSyscallInfo);
    if (!IsAddressInDispatcher(OldPC)) {
      // This is likely to cause issues but in some cases it isn't fatal
      // This can also happen if we have put a signal on hold, then we just reenabled the signal
      // So we are in the syscall handler
      // Only throw a log message in this case
      if constexpr (false) {
        // XXX: Messages in the signal handler can cause us to crash
        LogMan::Msg::EFmt("Signals in dispatcher have unsynchronized context");
      }
    }
  }

  uint64_t OldGuestSP = Frame->State.gregs[FEXCore::X86State::REG_RSP];

  // Defensive: refuse to lay out a signal frame on a guest SP that is
  // clearly unusable. Threads created via clone() with unsupported flags
  // (FEX has been logging "clone: Unsupported flags w/o CLONE_THREAD"
  // for pressure-vessel's CLONE_PIDFD calls) can end up with a near-NULL
  // RSP. SetupFrame_x64 then decrements NewGuestSP by ucontext_t size and
  // writes to (RSP - sizeof(...))  which wraps to ~0xFFFFFFFFFFFFFE48 and
  // SIGSEGVs. Better to bail out and let the default disposition run.
  // Valid x86_64 user-space addresses are 0x10000..0x7FFFFFFFFFFF; i386
  // is 0x1000..0xFFFFFFFF. The lower bound catches both.
  if (OldGuestSP < 0x10000ULL || OldGuestSP > 0x00007FFFFFFFFFFFULL) {
    // Diagnostic dump: capture as much state as possible to root-cause the
    // bogus-RSP. Print TID, signal info, guest RIP/RBP/segment selectors,
    // and full guest GPR snapshot. Helps distinguish "freshly-cloned thread
    // with uninitialized state" vs "syscall-return-window race" vs other.
    auto& S = Thread->CurrentFrame->State;
    siginfo_t* si = reinterpret_cast<siginfo_t*>(info);
    LogMan::Msg::EFmt("HandleDispatcherGuestSignal: refusing to deliver "
                      "signal {} to guest with bogus RSP {:#x}",
                      Signal, OldGuestSP);
    LogMan::Msg::EFmt("  tid={} si_code={} si_addr={:#x} si_pid={}",
                      FHU::Syscalls::gettid(),
                      si->si_code, reinterpret_cast<uint64_t>(si->si_addr), si->si_pid);
    LogMan::Msg::EFmt("  guest RIP={:#x} RBP={:#x} CS={:x} SS={:x}",
                      S.rip, S.gregs[FEXCore::X86State::REG_RBP],
                      S.cs_idx, S.ss_idx);
    LogMan::Msg::EFmt("  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
                      S.gregs[0], S.gregs[3], S.gregs[1], S.gregs[2]);
    LogMan::Msg::EFmt("  RSI={:#x} RDI={:#x} R8={:#x} R9={:#x}",
                      S.gregs[6], S.gregs[7], S.gregs[8], S.gregs[9]);
    LogMan::Msg::EFmt("  R10={:#x} R11={:#x} R12={:#x} R13={:#x}",
                      S.gregs[10], S.gregs[11], S.gregs[12], S.gregs[13]);
    LogMan::Msg::EFmt("  R14={:#x} R15={:#x}",
                      S.gregs[14], S.gregs[15]);

    // Guest code dump around RIP (16 bytes before, 32 after). Lets us
    // decode the x86 instruction that was about to execute -- the trailing
    // instruction is almost certainly the one that tried to use the bogus
    // stack. Probe with msync to avoid a double-fault if RIP is unmapped.
    auto dump_guest = [](uint64_t addr, size_t len, const char* label) {
      if (addr < 0x1000ULL || addr > 0x00007FFFFFFFFFFFULL) {
        LogMan::Msg::EFmt("  {} {:#x}: <out of range>", label, addr);
        return;
      }
      uint64_t page = addr & ~0xFFFULL;
      if (msync(reinterpret_cast<void*>(page), 0x1000, MS_ASYNC) != 0) {
        LogMan::Msg::EFmt("  {} {:#x}: <unmapped>", label, addr);
        return;
      }
      const uint8_t* mem = reinterpret_cast<const uint8_t*>(addr);
      char buf[3 * 32 + 1];
      size_t off = 0;
      for (size_t i = 0; i < len && off + 3 < sizeof(buf); ++i) {
        off += std::snprintf(buf + off, sizeof(buf) - off, "%02x ", mem[i]);
      }
      buf[sizeof(buf) - 1] = 0;
      LogMan::Msg::EFmt("  {} {:#x}: {}", label, addr, buf);
    };
    if (S.rip >= 16) {
      dump_guest(S.rip - 16, 16, "code[RIP-16]");
    }
    dump_guest(S.rip, 32, "code[RIP]   ");
    // Stack walk via RBP -- the guest RBP often survives RSP corruption.
    uint64_t rbp = S.gregs[FEXCore::X86State::REG_RBP];
    if (rbp >= 0x1000ULL && rbp <= 0x00007FFFFFFFFFFFULL) {
      uint64_t page = rbp & ~0xFFFULL;
      if (msync(reinterpret_cast<void*>(page), 0x1000, MS_ASYNC) == 0) {
        const uint64_t* fp = reinterpret_cast<const uint64_t*>(rbp);
        LogMan::Msg::EFmt("  RBP frame: saved_RBP={:#x} return_RIP={:#x}",
                          fp[0], fp[1]);
      }
    }
    return false;
  }

  uint64_t NewGuestSP = OldGuestSP;

  // altstack is only used if the signal handler was setup with SA_ONSTACK
  if (GuestAction->sa_flags & SA_ONSTACK) {
    // Additionally the altstack is only used if the enabled (SS_DISABLE flag is not set)
    if (!(GuestStack->ss_flags & SS_DISABLE)) {
      // If our guest is already inside of the alternative stack
      // Then that means we are hitting recursive signals and we need to walk back the stack correctly
      uint64_t AltStackBase = reinterpret_cast<uint64_t>(GuestStack->ss_sp);
      uint64_t AltStackEnd = AltStackBase + GuestStack->ss_size;
      if (OldGuestSP >= AltStackBase && OldGuestSP <= AltStackEnd) {
        // We are already in the alt stack, the rest of the code will handle adjusting this
      } else {
        NewGuestSP = AltStackEnd;
      }
    }
  }

  // siginfo_t
  siginfo_t* HostSigInfo = reinterpret_cast<siginfo_t*>(info);

  ContextBackup->OriginalRIP = Thread->CurrentFrame->State.rip;
  uint32_t eflags = CTX->ReconstructCompactedEFLAGS(Thread, false, nullptr, 0);

  if (Is64BitMode) {
    NewGuestSP = SetupFrame_x64(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
  } else {
    const bool SigInfoFrame = (GuestAction->sa_flags & SA_SIGINFO) == SA_SIGINFO;
    if (SigInfoFrame) {
      NewGuestSP = SetupRTFrame_ia32(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
    } else {
      NewGuestSP = SetupFrame_ia32(Thread, ContextBackup, Frame, Signal, HostSigInfo, ucontext, GuestAction, GuestStack, NewGuestSP, eflags);
    }
  }

  Frame->State.rip = reinterpret_cast<uint64_t>(GuestAction->sigaction_handler.sigaction);
  Frame->State.gregs[FEXCore::X86State::REG_RSP] = NewGuestSP;

  // Linux clears DF, RF, and TF flags on signal.
  Frame->State.flags[FEXCore::X86State::RFLAG_DF_RAW_LOC] = 1;
  Frame->State.flags[FEXCore::X86State::RFLAG_RF_LOC] = 0;
  Frame->State.flags[FEXCore::X86State::RFLAG_TF_RAW_LOC] = 0;

  // Linux resets the CS and SS registers on signal handler.
  // This way signal handlers always go back to their original operating mode.
  // Doesn't matter for 32-bit processes as they can only be 32-bit, but does
  // matter for 64-bit processes as they could have potentially installed a 32-bit code segment.
  Frame->State.cs_idx = FEXCore::Core::CPUState::DEFAULT_USER_CS << 3;
  Frame->State.ss_idx = 0;
  Frame->State.cs_cached = Frame->State.CalculateGDTBase(*Frame->State.GetSegmentFromIndex(Frame->State, Frame->State.cs_idx));
  Frame->State.ss_cached = Frame->State.CalculateGDTBase(*Frame->State.GetSegmentFromIndex(Frame->State, Frame->State.ss_idx));

  // The guest starts its signal frame with a zero initialized FPU
  // Set that up now. Little bit costly but it's a requirement
  // This state will be restored on rt_sigreturn
  memset(Frame->State.xmm.avx.data, 0, sizeof(Frame->State.xmm));
  memset(Frame->State.mm, 0, sizeof(Frame->State.mm));
  Frame->State.FCW = 0x37F;
  Frame->State.AbridgedFTW = 0;

  // Set the new PC
  ArchHelpers::Context::SetPc(ucontext, Config.AbsoluteLoopTopAddressFillSRA);
  ArchHelpers::Context::SetFillSRASingleInst(ucontext, false);
  // Set our state register to point to our guest thread data
  ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

  return true;
}

bool SignalDelegator::HandleSIGILL(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  SIGTRACE("SIGILL pc=0x%lx sentinel=%d pause=%d", ArchHelpers::Context::GetPc(ucontext),
           (ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddress ||
            ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddressRT) ? 1 : 0,
           ArchHelpers::Context::GetPc(ucontext) == Config.PauseReturnInstruction ? 1 : 0);
  if (ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddress ||
      ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddressRT) {
    auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
    RestoreThreadState(Thread, ucontext,
                       ArchHelpers::Context::GetPc(ucontext) == Config.SignalHandlerReturnAddressRT ? RestoreType::TYPE_REALTIME :
                                                                                                      RestoreType::TYPE_NONREALTIME);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;

    if (ThreadObject->SignalInfo.DeferredSignalFrames.size() != 0) {
      // If we have more deferred frames to process then mprotect back to PROT_NONE.
      // It will have been RW coming in to this sigreturn and now we need to remove permissions
      // to ensure FEX trampolines back to the SIGSEGV deferred handler.
      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_NONE);
    }
    return true;
  }

  if (ArchHelpers::Context::GetPc(ucontext) == Config.PauseReturnInstruction) {
    RestoreThreadState(Thread, ucontext, RestoreType::TYPE_PAUSE);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;
    return true;
  }

  return false;
}

bool SignalDelegator::HandleSignalPause(FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) {
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  SignalEvent SignalReason = ThreadObject->SignalReason.load();
  auto Frame = Thread->CurrentFrame;

  if (SignalReason == SignalEvent::Pause) {
    // Store our thread state so we can come back to this
    StoreThreadState(Thread, Signal, ucontext);

    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext))) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadPauseHandlerAddressSpillSRA);
    } else {
      // We are in non-jit, SRA is already spilled
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_THROW_A_FMT(!IsAddressInDispatcher(ArchHelpers::Context::GetPc(ucontext)), "Signals in dispatcher have unsynchronized "
                                                                                        "context");
#endif
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadPauseHandlerAddress);
    }

    // Set our state register to point to our guest thread data
    ArchHelpers::Context::SetState(ucontext, reinterpret_cast<uint64_t>(Frame));

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    ++Thread->CurrentFrame->SignalHandlerRefCounter;

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == SignalEvent::Stop) {
    // Our thread is stopping
    // We don't care about anything at this point
    // Set the stack to our starting location when we entered the core and get out safely
    ArchHelpers::Context::SetSp(ucontext, Frame->ReturningStackLocation);

    // Our ref counting doesn't matter anymore
    Thread->CurrentFrame->SignalHandlerRefCounter = 0;

    // Set the new PC
    if (CTX->IsAddressInCodeBuffer(Thread, ArchHelpers::Context::GetPc(ucontext))) {
      // We are in jit, SRA must be spilled
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadStopHandlerAddressSpillSRA);
    } else {
      // We are in non-jit, SRA is already spilled
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED
      LOGMAN_THROW_A_FMT(!IsAddressInDispatcher(ArchHelpers::Context::GetPc(ucontext)), "Signals in dispatcher have unsynchronized "
                                                                                        "context");
#endif
      ArchHelpers::Context::SetPc(ucontext, Config.ThreadStopHandlerAddress);
    }

    // We need to be a little bit careful here
    // If we were already paused (due to GDB) and we are immediately stopping (due to gdb kill)
    // Then we need to ensure we don't double decrement our idle thread counter
    if (ThreadObject->ThreadSleeping) {
      // If the thread was sleeping then its idle counter was decremented
      // Reincrement it here to not break logic
      FEX::HLE::_SyscallHandler->TM.IncrementIdleRefCount();
    }

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }

  if (SignalReason == SignalEvent::Return || SignalReason == SignalEvent::ReturnRT) {
    RestoreThreadState(Thread, ucontext, SignalReason == SignalEvent::ReturnRT ? RestoreType::TYPE_REALTIME : RestoreType::TYPE_NONREALTIME);

    // Ref count our faults
    // We use this to track if it is safe to clear cache
    --Thread->CurrentFrame->SignalHandlerRefCounter;

    ThreadObject->SignalReason.store(SignalEvent::Nothing);
    return true;
  }
  return false;
}

void SignalDelegator::SignalThread(FEXCore::Core::InternalThreadState* Thread, SignalEvent Event) {
  auto ThreadObject = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread);
  ThreadObject->SignalReason.store(Event);
  FHU::Syscalls::tgkill(ThreadObject->ThreadInfo.PID, ThreadObject->ThreadInfo.TID, SignalDelegator::SIGNAL_FOR_PAUSE);
}

/**  @} */

static bool IsAsyncSignal(const siginfo_t* Info, int Signal) {
  if (Info->si_code <= SI_USER) {
    // If the signal is not from the kernel then it is always async.
    // This is because synchronous signals can be sent through tgkill,sigqueue and other methods.
    // SI_USER == 0 and all negative si_code values come from the user.
    return true;
  } else {
    // If the signal is from the kernel then it is async only if it isn't an explicit synchronous signal.
    switch (Signal) {
    // These are all synchronous signals.
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
    case SIGSEGV:
    case SIGTRAP: return false;
    default: break;
    }
  }

  // Everything else is async and can be deferred.
  return true;
}

bool SignalDelegator::ThreadHasDeliverableGuestSignal(FEX::HLE::ThreadStateObject* ThreadObject) {
  // Mirrors the drain-time filtering in HandleGuestSignal: a frame that is
  // guest-masked gets parked in PendingSignals instead of delivered, and a
  // SIG_IGN / default-ignore disposition gets dropped. Only what survives
  // those filters can interrupt a sleep on a real kernel.
  //
  // Runs on the owning thread from the syscall path. The thread's own signal
  // handler can append a frame concurrently, but DeferredSignalFrames never
  // reallocates (capacity is pre-reserved, enforced at the emplace site), so
  // indexed iteration over a snapshotted size is safe; a frame appended after
  // the snapshot is caught by the caller's next check.
  const uint64_t GuestMask = ThreadObject->SignalInfo.CurrentSignalMask.Val;
  const auto Deliverable = [&](int Signal) {
    if (Signal < 1 || Signal > MAX_SIGNALS) {
      return false;
    }
    if (GuestMask & (1ULL << (Signal - 1))) {
      return false;
    }
    const SignalHandler& Handler = HostHandlers[Signal];
    const auto GuestHandler = Handler.GuestAction.sigaction_handler.handler;
    if (GuestHandler == SIG_IGN) {
      return false;
    }
    if (GuestHandler == SIG_DFL && Handler.DefaultBehaviour == DEFAULT_IGNORE) {
      return false;
    }
    // Real handler, or default-terminate: both reach the guest on drain.
    return true;
  };

  const auto& Frames = ThreadObject->SignalInfo.DeferredSignalFrames;
  const size_t Count = Frames.size();
  for (size_t i = 0; i < Count; ++i) {
    if (Deliverable(Frames[i].Signal)) {
      return true;
    }
  }

  uint64_t Pending = ThreadObject->SignalInfo.PendingSignals & ~GuestMask;
  while (Pending) {
    const int Signal = __builtin_ctzll(Pending) + 1;
    Pending &= Pending - 1;
    if (Deliverable(Signal)) {
      return true;
    }
  }
  return false;
}

uint64_t SignalDelegator::GetNewSigMask(int Signal) const {
  const SignalHandler& Handler = HostHandlers[Signal];
  // Set up a new mask based on this signals signal mask
  uint64_t NewMask = Handler.GuestAction.sa_mask.Val;

  // If NODEFER then the new signal mask includes this signal
  if (!(Handler.GuestAction.sa_flags & SA_NODEFER)) {
    NewMask |= (1ULL << (Signal - 1));
  }

  // Walk our required signals and stop masking them if requested
  for (size_t i = 0; i < MAX_SIGNALS; ++i) {
    if (HostHandlers[i + 1].Required.load(std::memory_order_relaxed)) {
      // Never mask our required signals
      NewMask &= ~(1ULL << i);
    }
  }

  return NewMask;
}

bool SignalDelegator::HandleFrontendSIGSEGV(FEXCore::Core::InternalThreadState* Thread, int Signal, void* Info, void* UContext) {
  auto SigInfo = *static_cast<siginfo_t*>(Info);

  if (FaultSafeUserMemAccess::TryHandleSafeFault(Signal, SigInfo, UContext)) {
    ERROR_AND_DIE_FMT("Received invalid data to syscall. Crashing now!");
  }

#ifdef ARCHITECTURE_arm64
  if (Signal == SIGSEGV && SigInfo.si_code == SEGV_ACCERR && SigInfo.si_addr >= reinterpret_cast<void*>(Thread->JITGuardPage) &&
      SigInfo.si_addr < reinterpret_cast<void*>(Thread->JITGuardPage + FEXCore::Utils::FEX_PAGE_SIZE)) {
    FEXCore::UncheckedLongJump::ManuallyLoadJumpBuf(Thread->RestartJump, Thread->JITGuardOverflowArgument,
                                                    ArchHelpers::Context::GetArmGPRs(UContext), ArchHelpers::Context::GetArmFPRs(UContext),
                                                    ArchHelpers::Context::GetArmPc(UContext));
    return true;
  }
#endif

  return false;
}

void SignalDelegator::HandleGuestSignal(FEX::HLE::ThreadStateObject* ThreadObject, int Signal, void* Info, void* UContext) {
  auto Thread = ThreadObject->Thread;
  ucontext_t* _context = (ucontext_t*)UContext;
  auto SigInfo = *static_cast<siginfo_t*>(Info);

  auto MustDeferSignal = (Thread->CurrentFrame->State.DeferredSignalRefCount.Load() != 0);

#if defined(ARCHITECTURE_ppc64le)
  // PPC64LE: also defer async signals whose host PC lies inside the JIT code
  // buffer. SpillSRA blindly copies the ucontext SRA regs into State.gregs
  // assuming they hold the coherent x86 register file at the snapped x86
  // boundary returned by RestoreRIPFromHostPC. That assumption only holds at
  // IR-op boundaries. The host kernel can interrupt a block mid-IR-op (for
  // example between an `and__` writing a 64-bit AND result into SRA[rax] and
  // the follow-up `rldicl` that zero-extends to 32 bits) — at which point
  // SRA[rax] holds the un-zero-extended scratch value and *not* the post-x86
  // RAX. Eager processing of such a signal corrupts State.gregs and the
  // INJIT-routed FillSRA on return re-dispatches with garbage gregs (typical
  // crash: SEGV_MAPERR at NULL+8 ~2 KB later, when a now-NULL gregs-derived
  // pointer is dereferenced).
  //
  // Treat the entire JIT code buffer as a deferral region for async signals;
  // the EmitSuspendInterruptCheck poke at every block entry / backward branch
  // drains the queued signal at a guaranteed-coherent boundary. Synchronous
  // signals (SIGSEGV/SIGBUS/SIGILL/SIGFPE — IsAsyncSignal is false) still go
  // through their normal handlers, so a real guest fault is not affected.
  // Defer inside the dispatcher too, not just JIT blocks. Blocks exit to the
  // dispatcher loop-top/L1-probe with the SRA registers live and dirty (no
  // spill on the block->dispatcher edge -- that is the SRA design), but the
  // host PC is no longer in the code buffer, so an eager delivery there goes
  // through HandleDispatcherGuestSignal's outside-JIT branch: no SpillSRA,
  // guest frame built from STALE State.gregs, and the handler's sigreturn
  // restores those stale values into the resumed context. Observed live on
  // Ziggurat dungeon generation (compilation storm + Boehm GC signal storm):
  // guest rbx came back holding an old heap pointer and the 0x934d00 scan
  // loop wedged with rbx billions past its r15=4 limit -- the same corrupted
  // register signature as the InSyscallInfo leak, via a different door.
  // Every dispatcher path reaches a block-entry fault-page poke (L1 hit ->
  // block entry; miss -> linker/compile, which is already refcount-deferred,
  // then block entry), so a deferred signal always drains at a boundary
  // where the register state is coherent.
  const uint64_t DeferPc = ArchHelpers::Context::GetPc(UContext);
  const bool InJIT_ForDefer = CTX->IsAddressInCodeBuffer(Thread, DeferPc) || IsAddressInDispatcher(DeferPc);
  const bool MustDeferAsync = MustDeferSignal || InJIT_ForDefer;
  SIGTRACE("GUEST sig=%d code=%d pc=0x%lx rip=0x%lx defer=%d injit=%d q=%zu", Signal, SigInfo.si_code,
           ArchHelpers::Context::GetPc(UContext), (unsigned long)Thread->CurrentFrame->State.rip, MustDeferSignal ? 1 : 0,
           InJIT_ForDefer ? 1 : 0, ThreadObject->SignalInfo.DeferredSignalFrames.size());
#else
  const bool MustDeferAsync = MustDeferSignal;
#endif

  if (Signal == SIGSEGV && SigInfo.si_code == SEGV_ACCERR && SigInfo.si_addr == reinterpret_cast<void*>(&Thread->InterruptFaultPage)) {
    if (!MustDeferSignal) {
      // We just reached the end of the outermost signal-deferring section and faulted to check for pending signals.
      // Pull a signal frame off the stack.

      mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_READ | PROT_WRITE);

      // FEX_SMCLAZYLINK: the SMC fault handler arms this page after a lazy
      // deferral, because with block linking live the fault-page poke at block
      // entry is the only trap a linked chain cannot skip. Settle the drain
      // debt BEFORE any resume path below — including the "no signals queued"
      // return — or the thread could re-enter a linked chain and reach a stale
      // translation of code it wrote itself. Unprotect-first ordering above is
      // load-bearing: the drain compiles/relinks nothing, but the thread's
      // next entry poke must not re-fault into a loop. No-op (one relaxed
      // load) unless the lazy-link mode armed it.
      if (FEX::HLE::_SyscallHandler && FEX::HLE::_SyscallHandler->SMCLazyLinkActive()) {
        Thread->CTX->SettleLazySMCDrainIfPending(Thread);
      }

      if (ThreadObject->SignalInfo.DeferredSignalFrames.empty()) {
        // No signals to defer. Just set the fault page back to RW and continue execution.
        // This occurs as a minor race condition between the refcount decrement and the access to the fault page.
        return;
      }

      const auto& Top = ThreadObject->SignalInfo.DeferredSignalFrames.back();
      Signal = Top.Signal;
      SigInfo = Top.Info;
      // sig mask has been updated at the defer time, recover the original mask
      memcpy(&_context->uc_sigmask, &Top.SigMask, sizeof(uint64_t));
      ThreadObject->SignalInfo.DeferredSignalFrames.pop_back();
      SIGTRACE("DRAIN sig=%d mask=0x%lx qleft=%zu", Signal, Top.SigMask, ThreadObject->SignalInfo.DeferredSignalFrames.size());

      // Until we re-protect the page to PROT_NONE, FEX will now *permanently* defer signals and /not/ check them.
      //
      // In order to return /back/ to a sane state, we wait for the rt_sigreturn to happen.
      // rt_sigreturn will check if there are any more deferred signals to handle
      // - If there are deferred signals
      //   - mprotect back to PROT_NONE
      //   - sigreturn will trampoline out to the previous fault address check, SIGSEGV and restart
      // - If there are *no* deferred signals
      //  - No need to mprotect, it is already RW
    } else {
#if defined(ARCHITECTURE_arm64) || defined(ARCHITECTURE_ppc64le)
      // If RefCount != 0 then that means we hit an access with nested signal-deferring sections.
      // Increment the PC past the unconditional refcount-store (`str zr, [x1]` on Arm64,
      // `std rN, 0(rM)` on PPC64LE — both 4-byte fixed-size stores) so execution continues
      // until we reach the outermost section.
      ArchHelpers::Context::SetPc(UContext, ArchHelpers::Context::GetPc(UContext) + 4);
      return;
#else
      // X86 should always be doing a refcount compare and branch since we can't guarantee instruction size.
      // ARM64 / PPC64LE just always do the access to reduce branching overhead.
      ERROR_AND_DIE_FMT("X86 shouldn't hit this InterruptFaultPage");
#endif
    }
  } else if (IsAsyncSignal(&SigInfo, Signal) && MustDeferAsync) {
    // If the signal is asynchronous (as determined by si_code) and FEX is in a state of needing
    // to defer the signal, then add the signal to the thread's signal queue.
    LOGMAN_THROW_A_FMT(ThreadObject->SignalInfo.DeferredSignalFrames.size() != ThreadObject->SignalInfo.DeferredSignalFrames.capacity(),
                       "Deferred signals vector hit "
                       "capacity size. This will "
                       "likely crash! Asserting now!");

    ThreadObject->SignalInfo.DeferredSignalFrames.emplace_back(ThreadStateObject::DeferredSignalState {
      .Info = SigInfo,
      .Signal = Signal,
      .SigMask = _context->uc_sigmask.__val[0],
    });

    uint64_t NewMask = GetNewSigMask(Signal);

    // Update our host signal mask so we don't hit race conditions with signals
    // This allows us to maintain the expected signal mask through the guest signal handling and then all the way back again
    memcpy(&_context->uc_sigmask, &NewMask, sizeof(uint64_t));

    // Now update the faulting page permissions so it will fault on write.
    mprotect(reinterpret_cast<void*>(&Thread->InterruptFaultPage), sizeof(Thread->InterruptFaultPage), PROT_NONE);
    SIGTRACE("DEFER sig=%d pc=0x%lx newmask=0x%lx q=%zu", Signal, ArchHelpers::Context::GetPc(UContext), NewMask,
             ThreadObject->SignalInfo.DeferredSignalFrames.size());

    // Postpone the remainder of signal handling logic until we process the SIGSEGV triggered by writing to InterruptFaultPage.
    return;
  }

  // Diagnostic (FEX_ABORT_TRIPWIRE=1): log every guest-delivered fatal-class
  // sync signal with its si_addr/si_code and the guest RIP. Paired with the
  // tgkill(SIGABRT) tripwire in Passthrough.cpp -- together they show what
  // fault preceded a guest abort(). Unity redirects guest stderr to
  // Player.log, so that is where these lines land.
  if ((Signal == SIGSEGV || Signal == SIGBUS || Signal == SIGILL || Signal == SIGFPE) && !IsAsyncSignal(&SigInfo, Signal)) {
    static const bool trip = (getenv("FEX_ABORT_TRIPWIRE") != nullptr);
    if (trip) {
      char buf[2048];
      int n = snprintf(buf, sizeof(buf), "[GSIG] tid=%d sig=%d si_code=%d si_addr=0x%lx guest_rip=0x%lx\n",
                       FHU::Syscalls::gettid(), Signal, SigInfo.si_code, reinterpret_cast<unsigned long>(SigInfo.si_addr),
                       (unsigned long)Thread->CurrentFrame->State.rip);
      const auto& St = Thread->CurrentFrame->State;
      n += snprintf(buf + n, sizeof(buf) - n, "[GSIG]  rax=%lx rcx=%lx rdx=%lx rbx=%lx rsp=%lx rbp=%lx rsi=%lx rdi=%lx\n",
                    St.gregs[0], St.gregs[1], St.gregs[2], St.gregs[3], St.gregs[4], St.gregs[5], St.gregs[6], St.gregs[7]);

      // FEX_TRIPWIRE_PROBE="<reg>:<off>[,<off>...]" — dump guest memory at
      // fixed offsets from one register, e.g. "rdi:0x0,0x28,0x490". The dumped
      // GPRs are SRA-reconstructed block-entry state, so probing memory they
      // point at is how a suspect object is inspected post-mortem (RimWorld's
      // UnityPlayer+0x1aa3ba0 NULL-field crash is the motivating case).
      // Reads go through process_vm_readv: the register value is untrusted and
      // a raw dereference here would turn a bad reconstruction into a
      // recursive SIGSEGV inside the signal handler, losing the whole dump.
      static const char* ProbeSpec = getenv("FEX_TRIPWIRE_PROBE");
      if (ProbeSpec) {
        static constexpr std::pair<const char*, int> RegNames[] = {
          {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3}, {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
          {"r8", 8},  {"r9", 9},  {"r10", 10}, {"r11", 11}, {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15},
        };
        const char* Colon = strchr(ProbeSpec, ':');
        int RegIdx = -1;
        if (Colon) {
          for (auto& [Name, Idx] : RegNames) {
            if (strlen(Name) == static_cast<size_t>(Colon - ProbeSpec) && !memcmp(ProbeSpec, Name, Colon - ProbeSpec)) {
              RegIdx = Idx;
              break;
            }
          }
        }
        if (RegIdx >= 0) {
          const uint64_t Base = St.gregs[RegIdx];
          const char* p = Colon + 1;
          for (int i = 0; i < 16 && *p; ++i) {
            char* End = nullptr;
            const uint64_t Off = strtoul(p, &End, 0);
            if (End == p) {
              break;
            }
            uint64_t Val = 0;
            struct iovec Local {&Val, sizeof(Val)};
            struct iovec Remote {reinterpret_cast<void*>(Base + Off), sizeof(Val)};
            if (process_vm_readv(::getpid(), &Local, 1, &Remote, 1, 0) == sizeof(Val)) {
              n += snprintf(buf + n, sizeof(buf) - n, "[GSIG]  probe [%.*s+0x%lx] = 0x%lx\n", static_cast<int>(Colon - ProbeSpec),
                            ProbeSpec, Off, Val);
            } else {
              n += snprintf(buf + n, sizeof(buf) - n, "[GSIG]  probe [%.*s+0x%lx] = <unreadable>\n",
                            static_cast<int>(Colon - ProbeSpec), ProbeSpec, Off);
            }
            p = (*End == ',') ? End + 1 : End;
          }
        }
      }
      // 32-bit guests keep a walkable EBP chain: ebp -> {saved ebp, ret}.
      // Reads are within our own address space; bound them to the low 4GB and
      // require monotonically increasing frame pointers to stay fault-free.
      uint64_t bp = St.gregs[5];
      for (int i = 0; i < 8 && bp >= 0x1000 && bp < 0xFFFFF000ULL && (bp & 3) == 0; ++i) {
        uint32_t SavedBP = 0;
        uint32_t RetAddr = 0;
        memcpy(&SavedBP, reinterpret_cast<void*>(bp), 4);
        memcpy(&RetAddr, reinterpret_cast<void*>(bp + 4), 4);
        n += snprintf(buf + n, sizeof(buf) - n, "[GSIG]  frame[%d] ebp=%lx ret=0x%x\n", i, bp, RetAddr);
        if (SavedBP <= bp) {
          break;
        }
        bp = SavedBP;
      }
      [[maybe_unused]] auto _ = write(2, buf, n);
    }
  }

  // Check for masked signals
  if (ThreadObject->SignalInfo.CurrentSignalMask.Val & (1ULL << (Signal - 1)) && IsAsyncSignal(&SigInfo, Signal)) {
    // This signal is masked, must defer until the guest updates the signal mask.
    // Add it to the pending signal list
    ThreadObject->SignalInfo.PendingSignals |= 1ULL << (Signal - 1);
    return;
  }

  // Let the host take first stab at handling the signal
  SignalHandler& Handler = HostHandlers[Signal];

  // Remove the pending signal
  ThreadObject->SignalInfo.PendingSignals &= ~(1ULL << (Signal - 1));

  // We have an emulation thread pointer, we can now modify its state
  if (Handler.GuestAction.sigaction_handler.handler == SIG_DFL) {
    if (Handler.DefaultBehaviour == DEFAULT_TERM || Handler.DefaultBehaviour == DEFAULT_COREDUMP) {
      // Let the signal fall through to the unhandled path
      // This way the parent process can know it died correctly
    }
  } else if (Handler.GuestAction.sigaction_handler.handler == SIG_IGN) {
    return;
  } else {
    // FEX_SMCLAZYINVAL drain point (c): guest signal delivery.
    //
    // The guest handler is about to run, on a control-flow edge the guest did
    // not write and cannot have prepared for. It is also a serializing event in
    // x86 terms, so it is a place a guest is entitled to assume its own earlier
    // code writes have become visible. Settle the deferred invalidations before
    // the frame is built and the handler dispatched.
    //
    // Lock protocol: this runs in a host signal handler, so the drain's
    // ReleaseAllPendingSharedLocks is load-bearing rather than decorative --
    // it is the same recovery HandleSegfault performs before it soft-invalidates
    // from signal context. Reaching here means the signal was NOT deferred:
    // async signals with DeferredSignalRefCount != 0 (which covers every host
    // syscall body, hence every place FEX holds VMATracking/ThreadCreation
    // locks) and async signals raised inside the JIT or dispatcher have already
    // returned above, queued. What is left is a synchronous guest fault from
    // JIT code, or an async signal at a drained-to boundary; in neither case is
    // this thread inside a FEX lock scope that the drain's exclusive
    // CodeInvalidationMutex could deadlock against.
    if (_SyscallHandler->SMCLazyInvalActive()) {
      _SyscallHandler->DrainSMCLazyDirtyPages(Thread, FEX::HLE::SMCLazy::DrainPoint::GuestSignal);
    }

    if (Handler.GuestHandler &&
        Handler.GuestHandler(Thread, Signal, &SigInfo, UContext, &Handler.GuestAction, &ThreadObject->SignalInfo.GuestAltStack)) {
      // Guest SA_RESTART bookkeeping. A guest handler is now committed to run on
      // this thread; record whether the guest asked for interrupted syscalls to
      // be restarted around it. HandleSyscall's restart loop reads these once
      // its DeferredSignalRefCountGuard has destructed -- which, for a thread
      // interrupted inside a host syscall, is exactly the point this delivery
      // happens from (fault-page poke -> drain -> handler -> sigreturn -> back
      // into the destructor). See ThreadManager.h for the field comments.
      ++ThreadObject->SignalInfo.DeliveredGuestSignals;
      if (!(Handler.GuestAction.sa_flags & SA_RESTART)) {
        ++ThreadObject->SignalInfo.DeliveredGuestSignalsWithoutRestart;
      }

      uint64_t NewMask = GetNewSigMask(Signal);

      // Update our host signal mask so we don't hit race conditions with signals
      // This allows us to maintain the expected signal mask through the guest signal handling and then all the way back again
      memcpy(&_context->uc_sigmask, &NewMask, sizeof(uint64_t));

      // We handled this signal, continue running
      return;
    }
    // GuestHandler returned false: we tried to deliver the signal but the
    // dispatcher refused (e.g., bogus guest RSP per the HandleDispatcherGuestSignal
    // SP guard, or pressure-vessel sandbox half-init state). Aborting the whole
    // emulator with "Unhandled guest exception" is too aggressive -- the thread
    // is in a bad state but the rest of the process is fine. Fall through to
    // the default-disposition path below so SIGSEGV terminates THAT THREAD
    // (or process, per kernel default for SIGSEGV) instead of crashing FEX.
    LogMan::Msg::EFmt("HandleGuestSignal: GuestHandler refused signal {}; falling to default disposition", Signal);
  }

  // Unhandled crash
  // Call back in to the previous handler
  if (Handler.OldAction.sa_flags & SA_SIGINFO) {
    Handler.OldAction.sigaction(Signal, &SigInfo, UContext);
  } else if (Handler.OldAction.handler == SIG_IGN || (Handler.OldAction.handler == SIG_DFL && Handler.DefaultBehaviour == DEFAULT_IGNORE)) {
    // Do nothing
  } else if (Handler.OldAction.handler == SIG_DFL && (Handler.DefaultBehaviour == DEFAULT_COREDUMP || Handler.DefaultBehaviour == DEFAULT_TERM)) {
    CTX->FlushAndCloseCodeMap();

#ifndef FEX_DISABLE_TELEMETRY
    // In the case of signals that cause coredump or terminate, save telemetry early.
    // FEX is hard crashing at this point and won't hit regular shutdown routines.
    // Add the signal to the crash mask.
    FEXCORE_TELEMETRY_OR(TYPE_CRASH_MASK, (1ULL << Signal));
    if (Signal == SIGSEGV && reinterpret_cast<uint64_t>(SigInfo.si_addr) >= SyscallHandler::TASK_MAX_64BIT) {
      // Tried accessing invalid non-canonical x86-64 address.
      FEXCORE_TELEMETRY_SET(TYPE_UNHANDLED_NONCANONICAL_ADDRESS, 1);
    }
    SaveTelemetry();
#endif

    FEX::HLE::_SyscallHandler->TM.CleanupForExit();

    // Reassign back to DFL and crash
    signal(Signal, SIG_DFL);
    if (SigInfo.si_code != SI_KERNEL) {
      // If the signal wasn't sent by the kernel then we need to reraise it.
      // This is necessary since returning from this signal handler now might just continue executing.
      // eg: If sent from tgkill then the signal gets dropped and returns.
      FHU::Syscalls::tgkill(::getpid(), FHU::Syscalls::gettid(), Signal);
    }
  } else {
    Handler.OldAction.handler(Signal);
  }
}

void SignalDelegator::SaveTelemetry() {
#ifndef FEX_DISABLE_TELEMETRY
  if (!ApplicationName.empty()) {
    FEXCore::Telemetry::Shutdown(ApplicationName);
  }
#endif
}

bool SignalDelegator::InstallHostThunk(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];
  // If the host thunk is already installed for this, just return
  if (SignalHandler.Installed) {
    return false;
  }

  // Default flags for us
  SignalHandler.HostAction.sa_flags = SA_SIGINFO | SA_ONSTACK;

  bool Result = UpdateHostThunk(Signal);

  SignalHandler.Installed = Result;
  return Result;
}

bool SignalDelegator::UpdateHostThunk(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];

  // Now install the thunk handler
  SignalHandler.HostAction.sigaction = SignalHandlerThunk;

  auto CheckAndAddFlags = [](uint64_t HostFlags, uint64_t GuestFlags, uint64_t Flags) {
    // If any of the flags don't match then update to the newest set
    if ((HostFlags ^ GuestFlags) & Flags) {
      // Remove all the flags from the host that we are testing for
      HostFlags &= ~Flags;
      // Copy over the guest flags being set
      HostFlags |= GuestFlags & Flags;
    }

    return HostFlags;
  };

  // Don't allow the guest to override flags for
  // SA_SIGINFO : Host always needs SA_SIGINFO
  // SA_ONSTACK : Host always needs the altstack
  // SA_RESETHAND : We don't support one shot handlers
  // SA_RESTORER : We always need our host side restorer on x86-64, Couldn't use guest restorer anyway
  SignalHandler.HostAction.sa_flags = CheckAndAddFlags(SignalHandler.HostAction.sa_flags, SignalHandler.GuestAction.sa_flags,
                                                       SA_NOCLDSTOP | SA_NOCLDWAIT | SA_NODEFER | SA_RESTART);

#if defined(ARCHITECTURE_ppc64le)
  // PPC64LE defers async signals for the whole of HandleSyscall (9560b3c8e), which
  // only works because the interrupted host ::syscall returns -EINTR: that return is
  // what unwinds to the guard's destructor, which is what drains the deferred queue.
  //
  // SA_RESTART on the *host* action defeats that. The kernel runs our thunk, we queue
  // the signal, and then the kernel silently restarts the syscall instead of returning
  // -EINTR -- so HandleSyscall never returns, the guard never destructs, and the queued
  // guest signal is never delivered. A guest thread blocked in futex() when it gets a
  // suspend signal is then unwakeable. Observed on Ziggurat: mono's GC stop-the-world
  // handshake wedges permanently at assembly load, one thread holding a PROT_NONE
  // InterruptFaultPage with nothing left to deliver it.
  //
  // Keep the guest's SA_RESTART recorded in GuestAction (it still drives guest-visible
  // behaviour); just never let the host thunk carry it.
  SignalHandler.HostAction.sa_flags &= ~SA_RESTART;
#endif

#ifdef ARCHITECTURE_x86_64
#define SA_RESTORER 0x04000000
  SignalHandler.HostAction.sa_flags |= SA_RESTORER;
  SignalHandler.HostAction.restorer = sigrestore;
#endif

  // Walk the signals we have that are required and make sure to remove it from the mask
  // This'll likely be SIGILL, SIGBUS, SIG63

  // If the guest has masked some signals then we need to also mask those signals
  for (size_t i = 1; i < HostHandlers.size(); ++i) {
    if (HostHandlers[i].Required.load(std::memory_order_relaxed)) {
      SignalHandler.HostAction.sa_mask &= ~(1ULL << (i - 1));
    } else if (SigIsMember(&SignalHandler.GuestAction.sa_mask, i)) {
      SignalHandler.HostAction.sa_mask |= (1ULL << (i - 1));
    }
  }

  // Check for SIG_IGN
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_IGN && HostHandlers[Signal].Required.load(std::memory_order_relaxed) == false) {
    // We are ignoring this signal on the guest
    // Which means we need to ignore it on the host as well
    SignalHandler.HostAction.handler = SIG_IGN;
  }

  // Check for SIG_DFL
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_DFL && HostHandlers[Signal].Required.load(std::memory_order_relaxed) == false) {
    // Default handler on guest and default handler on host
    // With coredump and terminate then expect fireworks, but that is what the guest wants
    SignalHandler.HostAction.handler = SIG_DFL;
  }

  // Only update the old action if we haven't ever been installed
  const int Result =
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.HostAction, SignalHandler.Installed ? nullptr : &SignalHandler.OldAction, 8);
  if (Result < 0) {
    // Signal 32 and 33 are consumed by glibc. We don't handle this atm
    LogMan::Msg::AFmt("Failed to install host signal thunk for signal {}: {}", Signal, strerror(errno));
    return false;
  }

  return true;
}

void SignalDelegator::UninstallHostHandler(int Signal) {
  SignalHandler& SignalHandler = HostHandlers[Signal];

  ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.OldAction, nullptr, 8);
}

void SignalDelegator::QueueSignal(pid_t tgid, pid_t tid, int Signal, siginfo_t* info, bool IgnoreMask) {
  bool WasIgnored {};
  bool WasMasked {};
  SignalHandler& SignalHandler = HostHandlers[Signal];
  if (SignalHandler.GuestAction.sigaction_handler.handler == SIG_IGN && IgnoreMask) {
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.OldAction, nullptr, 8);
    WasIgnored = true;
  }

  // Get the current host signal mask
  uint64_t ThreadSignalMask {};
  const uint64_t SignalMask = 1ULL << (Signal - 1);
  ::syscall(SYS_rt_sigprocmask, 0, nullptr, &ThreadSignalMask, 8);
  if (ThreadSignalMask & SignalMask) {
    WasMasked = true;

    // Signal currently masked, unmask
    ThreadSignalMask &= ~SignalMask;
    ::syscall(SYS_rt_sigprocmask, 0, &ThreadSignalMask, &ThreadSignalMask, 8);
  }

  ::syscall(SYSCALL_DEF(rt_tgsigqueueinfo), tgid, tid, Signal, info);

  if (WasMasked) {
    // Mask again
    ::syscall(SYS_rt_sigprocmask, 0, &ThreadSignalMask, nullptr, 8);
  }

  if (WasIgnored) {
    // Ignore again
    ::syscall(SYS_rt_sigaction, Signal, &SignalHandler.HostAction, nullptr, 8);
  }
}

SignalDelegator::SignalDelegator(FEXCore::Context::Context* _CTX, const std::string_view ApplicationName, bool SupportsAVX)
  : CTX {_CTX}
  , ApplicationName {ApplicationName}
  , SupportsAVX {SupportsAVX} {
  // Signal zero isn't real
  HostHandlers[0].Installed = true;

  // We can't capture SIGKILL or SIGSTOP
  HostHandlers[SIGKILL].Installed = true;
  HostHandlers[SIGSTOP].Installed = true;

  if (HalfBarrierTSOEnabled()) {
    UnalignedHandlerType = FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::HalfBarrier;
  } else {
    UnalignedHandlerType = FEXCore::ArchHelpers::Arm64::UnalignedHandlerType::NonAtomic;
  }

  // Most signals default to termination
  // These ones are slightly different
  static constexpr std::array<std::pair<int, SignalDelegator::DefaultBehaviourType>, 14> SignalDefaultBehaviours = {{
    {SIGQUIT, DEFAULT_COREDUMP},
    {SIGILL, DEFAULT_COREDUMP},
    {SIGTRAP, DEFAULT_COREDUMP},
    {SIGABRT, DEFAULT_COREDUMP},
    {SIGBUS, DEFAULT_COREDUMP},
    {SIGFPE, DEFAULT_COREDUMP},
    {SIGSEGV, DEFAULT_COREDUMP},
    {SIGCHLD, DEFAULT_IGNORE},
    {SIGCONT, DEFAULT_IGNORE},
    {SIGURG, DEFAULT_IGNORE},
    {SIGXCPU, DEFAULT_COREDUMP},
    {SIGXFSZ, DEFAULT_COREDUMP},
    {SIGSYS, DEFAULT_COREDUMP},
    {SIGWINCH, DEFAULT_IGNORE},
  }};

  for (const auto& [Signal, Behaviour] : SignalDefaultBehaviours) {
    HostHandlers[Signal].DefaultBehaviour = Behaviour;
  }

  // Register frontend SIGILL handler for forced assertion.
  RegisterFrontendHostSignalHandler(
    SIGILL,
    [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
      ucontext_t* _context = (ucontext_t*)ucontext;
      auto& mcontext = _context->uc_mcontext;
      uint64_t PC {};
#ifdef ARCHITECTURE_arm64
      PC = mcontext.pc;
#elif defined(ARCHITECTURE_ppc64le)
      PC = mcontext.gp_regs[32]; // PPC_PT_NIP
#else
      PC = mcontext.gregs[REG_RIP];
#endif
      if (PC == reinterpret_cast<uint64_t>(&FEXCore::Assert::ForcedAssert)) {
        // This is a host side assert. Don't deliver this to the guest
        // We want to actually break here
        FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->UninstallHostHandler(Signal);
        return true;
      }
      return false;
    },
    true);

  const auto PauseHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleSignalPause(Thread, Signal, info, ucontext);
  };

  const auto GuestSignalHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext,
                                     GuestSigAction* GuestAction, stack_t* GuestStack) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleDispatcherGuestSignal(
      Thread, Signal, info, ucontext, GuestAction, GuestStack);
  };

  const auto SigillHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleSIGILL(Thread, Signal, info, ucontext);
  };

  const auto SigsegvHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleFrontendSIGSEGV(Thread, Signal,
                                                                                                                         info, ucontext);
  };

  // Register SIGILL signal handler.
  RegisterHostSignalHandler(SIGILL, SigillHandler, true);
  RegisterHostSignalHandler(SIGSEGV, SigsegvHandler, true);

  // SIGTRAP needs a host thunk for the same reason SIGILL does, and until now
  // it never had one. Host thunks were installed only for SIGILL, SIGSEGV,
  // SIGBUS and the pause signal; the all-signals loop below calls
  // RegisterHostSignalHandlerForGuest, which assigns a GuestHandler but never
  // calls InstallHostThunk. So a SIGTRAP-producing instruction reached FEX only
  // if the guest itself had called sigaction(SIGTRAP, ...) — otherwise the
  // process died on the host default disposition with FEX bypassed entirely:
  // no CleanupForExit, no telemetry, and a NIP inside the dispatcher mmap.
  //
  // This is already a live defect independent of any Break-op work. X87Ops.cpp
  // emits `trap` (0x7FE00008) for unsupported fstp conversion paths, with a
  // comment promising "a clear SIGILL". Without a thunk that path core-dumps
  // instead of failing loudly, and it is reachable by any guest doing
  // `fstp dword`/`fstp qword` from a non-80-bit stack value.
  //
  // Required=true matters: it blocks both downgrades in UpdateHostThunk, so a
  // guest setting SIG_DFL or SIG_IGN cannot strip our thunk and leave the
  // sentinel or a Break-generated trap unhandled.
  const auto SigtrapHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* info, void* ucontext) -> bool {
    return FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator->HandleSIGILL(Thread, Signal, info, ucontext);
  };
  RegisterHostSignalHandler(SIGTRAP, SigtrapHandler, true);

#ifdef ARCHITECTURE_arm64
  // Register SIGBUS signal handler.
  const auto SigbusHandler = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* _info, void* ucontext) -> bool {
    const auto PC = ArchHelpers::Context::GetPc(ucontext);
    if (!Thread->CTX->IsAddressInCodeBuffer(Thread, PC)) {
      // Wasn't a sigbus in JIT code
      return false;
    }
    siginfo_t* info = reinterpret_cast<siginfo_t*>(_info);

    if (info->si_code != BUS_ADRALN) {
      // This only handles alignment problems
      return false;
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
    const auto Delegator = FEX::HLE::ThreadManager::GetStateObjectFromFEXCoreThread(Thread)->SignalInfo.Delegator;
    const auto Result = FEXCore::ArchHelpers::Arm64::HandleUnalignedAccess(Thread, Delegator->GetUnalignedHandlerType(), PC,
                                                                           ArchHelpers::Context::GetArmGPRs(ucontext));
    ArchHelpers::Context::SetPc(ucontext, PC + Result.value_or(0));
    return Result.has_value();
  };

  RegisterHostSignalHandler(SIGBUS, SigbusHandler, true);
#endif

#ifdef ARCHITECTURE_ppc64le
  // PPC64LE SIGBUS handler -- split-lock safety net.
  //
  // POWER8's ldarx/lwarx/lharx/lbarx require natural alignment; an x86
  // LOCK RMW on a misaligned EA would otherwise SIGBUS with si_code=
  // BUS_ADRALN. The PPC64LE JIT emits an inline alignment check on
  // every atomic and routes misaligned EAs through
  // PPC64_SplitLockEmulate (process-wide mutex), so SIGBUS from an
  // atomic LL is not expected in normal codegen. This handler is the
  // safety net for any LL that slips through the inline check
  // (codegen regressions, future opt passes that elide the gate,
  // hardware oddities). On a recognized LL it decodes the LL+body+SC
  // pattern, dispatches to PPC64_SplitLockEmulate, writes the
  // pre-RMW value to the LL's RT register, and advances PC past the
  // bc.NE back-edge so the thread doesn't loop on a faulting
  // reservation.
  const auto SigbusHandlerPPC64 = [](FEXCore::Core::InternalThreadState* Thread, int Signal, void* _info, void* ucontext) -> bool {
    const auto PC = ArchHelpers::Context::GetPc(ucontext);
    if (!Thread->CTX->IsAddressInCodeBuffer(Thread, PC)) {
      // SIGBUS outside JIT code -- let default handling (or a guest
      // handler) take it.
      return false;
    }
    siginfo_t* info = reinterpret_cast<siginfo_t*>(_info);
    if (info->si_code != BUS_ADRALN) {
      // We only own alignment SIGBUS. Other si_codes (BUS_ADRERR,
      // BUS_OBJERR, BUS_MCEERR_*) are real faults.
      return false;
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedSIGBUSCount, 1);
    const auto Result = FEXCore::ArchHelpers::PPC64::HandleUnalignedAtomicSIGBUS(
      Thread, PC, ArchHelpers::Context::GetArmGPRs(ucontext));
    if (Result.has_value()) {
      ArchHelpers::Context::SetPc(ucontext, PC + Result.value());
      return true;
    }
    // HandleUnalignedAtomicSIGBUS only returns an advance on a
    // recognized LL/SC pattern. If we don't recognize the LL (CAS,
    // an unfamiliar emit pattern, a SIGBUS from non-atomic JIT
    // code), let the fault escape -- a faulting non-atomic LD/ST
    // should crash the thread rather than silently advance past it.
    return false;
  };

  RegisterHostSignalHandler(SIGBUS, SigbusHandlerPPC64, true);
#endif
  // Register pause signal handler.
  RegisterHostSignalHandler(SignalDelegator::SIGNAL_FOR_PAUSE, PauseHandler, true);

  // Guest signal handlers.
  for (uint32_t Signal = 0; Signal <= SignalDelegator::MAX_SIGNALS; ++Signal) {
    RegisterHostSignalHandlerForGuest(Signal, GuestSignalHandler);
  }
}

SignalDelegator::~SignalDelegator() {
  for (int i = 0; i < MAX_SIGNALS; ++i) {
    if (i == 0 || i == SIGKILL || i == SIGSTOP || !HostHandlers[i].Installed) {
      continue;
    }
    ::syscall(SYS_rt_sigaction, i, &HostHandlers[i].OldAction, nullptr, 8);
    HostHandlers[i].Installed = false;
  }
}

void SignalDelegator::RegisterTLSState(FEX::HLE::ThreadStateObject* Thread) {
  FEXCore::Allocator::RegisterTLSData(Thread->Thread);

  Thread->SignalInfo.Delegator = this;

  // Set up our signal alternative stack
  // This is per thread rather than per signal
  Thread->SignalInfo.AltStackPtr = FEXCore::Allocator::mmap(nullptr, SIGSTKSZ * 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  FEXCore::Allocator::VirtualName("FEXMem_Misc", reinterpret_cast<void*>(Thread->SignalInfo.AltStackPtr), SIGSTKSZ * 16);
  stack_t altstack {};
  altstack.ss_sp = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(Thread->SignalInfo.AltStackPtr) + 8);
  altstack.ss_size = SIGSTKSZ * 16 - 8;
  altstack.ss_flags = 0;
  LOGMAN_THROW_A_FMT(!!altstack.ss_sp, "Couldn't allocate stack pointer");

  // Copy the thread object to the start of the alt-stack
  memcpy(Thread->SignalInfo.AltStackPtr, &Thread, sizeof(void*));

  // Protect the first page of the alt-stack for overflow protection.
  mprotect(Thread->SignalInfo.AltStackPtr, FEXCore::Utils::FEX_PAGE_SIZE, PROT_READ);

  // Register the alt stack
  const int Result = sigaltstack(&altstack, nullptr);
  if (Result == -1) {
    LogMan::Msg::EFmt("Failed to install alternative signal stack {}", strerror(errno));
  }

  // Get the current host signal mask
  ::syscall(SYS_rt_sigprocmask, 0, nullptr, &Thread->SignalInfo.CurrentSignalMask.Val, 8);

  if (Thread->Thread) {
    // Reserve a small amount of deferred signal frames. Usually the stack won't be utilized beyond
    // 1 or 2 signals but add a few more just in case.
    Thread->SignalInfo.DeferredSignalFrames.reserve(8);
  }
}

void SignalDelegator::UninstallTLSState(FEX::HLE::ThreadStateObject* Thread) {
  FEXCore::Allocator::munmap(Thread->SignalInfo.AltStackPtr, SIGSTKSZ * 16);

  Thread->SignalInfo.AltStackPtr = nullptr;

  stack_t altstack {};
  altstack.ss_flags = SS_DISABLE;

  // Uninstall the alt stack
  const int Result = sigaltstack(&altstack, nullptr);
  if (Result == -1) {
    LogMan::Msg::EFmt("Failed to uninstall alternative signal stack {}", strerror(errno));
  }

  FEXCore::Allocator::UninstallTLSData(Thread->Thread);
}

void SignalDelegator::FrontendRegisterHostSignalHandler(int Signal, bool Required) {
  // Linux signal handlers are per-process rather than per thread
  // Multiple threads could be calling in to this
  std::lock_guard lk(HostDelegatorMutex);
  HostHandlers[Signal].Required = Required;
  InstallHostThunk(Signal);
}

void SignalDelegator::FrontendRegisterFrontendHostSignalHandler(int Signal, bool Required) {
  // Linux signal handlers are per-process rather than per thread
  // Multiple threads could be calling in to this
  std::lock_guard lk(HostDelegatorMutex);
  HostHandlers[Signal].Required = Required;
  InstallHostThunk(Signal);
}

void SignalDelegator::RegisterHostSignalHandlerForGuest(int Signal, FEX::HLE::HostSignalDelegatorFunctionForGuest Func) {
  std::lock_guard lk(HostDelegatorMutex);
  HostHandlers[Signal].GuestHandler = std::move(Func);
}

void SignalDelegator::RegisterFrontendHostSignalHandler(int Signal, HostSignalDelegatorFunction Func, bool Required) {
  SetFrontendHostSignalHandler(Signal, std::move(Func), Required);
  FrontendRegisterFrontendHostSignalHandler(Signal, Required);
}

uint64_t SignalDelegator::RegisterGuestSignalHandler(int Signal, const GuestSigAction* Action, GuestSigAction* OldAction) {
  std::lock_guard lk(GuestDelegatorMutex);

  // Invalid signal specified
  if (Signal > MAX_SIGNALS) {
    return -EINVAL;
  }

  // If we have an old signal set then give it back
  if (OldAction) {
    *OldAction = HostHandlers[Signal].GuestAction;
  }

  // Now assign the new action
  if (Action) {
    // These signal dispositions can't be changed on Linux
    if (Signal == SIGKILL || Signal == SIGSTOP) {
      return -EINVAL;
    }

    HostHandlers[Signal].GuestAction = *Action;
    // Only attempt to install a new thunk handler if we were installing a new guest action
    if (!InstallHostThunk(Signal)) {
      UpdateHostThunk(Signal);
    }
  }

  return 0;
}

void SignalDelegator::CheckXIDHandler() {
  std::lock_guard lk(GuestDelegatorMutex);
  std::lock_guard lk2(HostDelegatorMutex);

  constexpr size_t SIGNAL_SETXID = 33;

  kernel_sigaction CurrentAction {};

  // Only update the old action if we haven't ever been installed
  const int Result = ::syscall(SYS_rt_sigaction, SIGNAL_SETXID, nullptr, &CurrentAction, 8);
  if (Result < 0) {
    LogMan::Msg::AFmt("Failed to get status of XID signal");
    return;
  }

  SignalHandler& HostHandler = HostHandlers[SIGNAL_SETXID];
  if (CurrentAction.handler != HostHandler.HostAction.handler) {
    // GLIBC overwrote our XID handler, reinstate our handler
    const int Result = ::syscall(SYS_rt_sigaction, SIGNAL_SETXID, &HostHandler.HostAction, nullptr, 8);
    if (Result < 0) {
      LogMan::Msg::AFmt("Failed to reinstate our XID signal handler {}", strerror(errno));
    }
  }
}

uint64_t SignalDelegator::RegisterGuestSigAltStack(FEX::HLE::ThreadStateObject* Thread, const stack_t* ss, stack_t* old_ss) {
  bool UsingAltStack {};
  uint64_t AltStackBase = reinterpret_cast<uint64_t>(Thread->SignalInfo.GuestAltStack.ss_sp);
  uint64_t AltStackEnd = AltStackBase + Thread->SignalInfo.GuestAltStack.ss_size;
  uint64_t GuestSP = Thread->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP];

  if (!(Thread->SignalInfo.GuestAltStack.ss_flags & SS_DISABLE) && GuestSP >= AltStackBase && GuestSP <= AltStackEnd) {
    UsingAltStack = true;
  }

  // If we have an old signal set then give it back
  if (old_ss) {
    *old_ss = Thread->SignalInfo.GuestAltStack;

    if (UsingAltStack) {
      // We are currently operating on the alt stack
      // Let the guest know
      old_ss->ss_flags |= SS_ONSTACK;
    } else {
      old_ss->ss_flags |= SS_DISABLE;
    }
  }

  // Now assign the new action
  if (ss) {
    // If we tried setting the alt stack while we are using it then throw an error
    if (UsingAltStack) {
      return -EPERM;
    }

    // We need to check for invalid flags
    // The only flag that can be passed is SS_AUTODISARM and SS_DISABLE
    if ((ss->ss_flags & ~SS_ONSTACK) & // SS_ONSTACK is ignored
        ~(SS_AUTODISARM | SS_DISABLE)) {
      // A flag remained that isn't one of the supported ones?
      return -EINVAL;
    }

    if (ss->ss_flags & SS_DISABLE) {
      // If SS_DISABLE Is specified then the rest of the details are ignored
      Thread->SignalInfo.GuestAltStack = *ss;
      return 0;
    }

    // stack size needs to be at least X86_MINSIGSTKSZ
    if (ss->ss_size < X86_MINSIGSTKSZ) {
      return -ENOMEM;
    }

    Thread->SignalInfo.GuestAltStack = *ss;
  }

  return 0;
}

static void CheckForPendingSignals(const FEX::HLE::ThreadStateObject* Thread) {
  // Do we have any pending signals that became unmasked?
  uint64_t PendingSignals = ~Thread->SignalInfo.CurrentSignalMask.Val & Thread->SignalInfo.PendingSignals;
  if (PendingSignals != 0) {
    for (int i = 0; i < 64; ++i) {
      if (PendingSignals & (1ULL << i)) {
        FHU::Syscalls::tgkill(Thread->ThreadInfo.PID, Thread->ThreadInfo.TID, i + 1);
        // We might not even return here which is spooky
      }
    }
  }
}

uint64_t SignalDelegator::GuestSigProcMask(FEX::HLE::ThreadStateObject* Thread, int how, const uint64_t* set, uint64_t* oldset) {
  // The order in which we handle signal mask setting is important here
  // old and new can point to the same location in memory.
  // Even if the pointers are to same memory location, we must store the original signal mask
  // coming in to the syscall.
  // 1) Store old mask
  // 2) Set mask to new mask if exists
  // 3) Give old mask back
  auto OldSet = Thread->SignalInfo.CurrentSignalMask.Val;

  if (!!set) {
    uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));
    if (how == SIG_BLOCK) {
      Thread->SignalInfo.CurrentSignalMask.Val |= *set & IgnoredSignalsMask;
    } else if (how == SIG_UNBLOCK) {
      Thread->SignalInfo.CurrentSignalMask.Val &= ~(*set & IgnoredSignalsMask);
    } else if (how == SIG_SETMASK) {
      Thread->SignalInfo.CurrentSignalMask.Val = *set & IgnoredSignalsMask;
    } else {
      return -EINVAL;
    }

    uint64_t HostMask = Thread->SignalInfo.CurrentSignalMask.Val;
    // Now actually set the host mask
    // This will hide from the guest that we are not actually setting all of the masks it wants
    for (size_t i = 0; i < MAX_SIGNALS; ++i) {
      if (HostHandlers[i + 1].Required.load(std::memory_order_relaxed)) {
        // If it is a required host signal then we can't mask it
        HostMask &= ~(1ULL << i);
      }
    }

    ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &HostMask, nullptr, 8);
  }

  if (!!oldset) {
    *oldset = OldSet;
  }

  CheckForPendingSignals(Thread);

  return 0;
}

uint64_t SignalDelegator::GuestSigPending(FEX::HLE::ThreadStateObject* Thread, uint64_t* set, size_t sigsetsize) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  *set = Thread->SignalInfo.PendingSignals;

  sigset_t HostSet {};
  if (sigpending(&HostSet) == 0) {
    uint64_t HostSignals {};
    for (size_t i = 0; i < MAX_SIGNALS; ++i) {
      if (sigismember(&HostSet, i + 1)) {
        HostSignals |= (1ULL << i);
      }
    }

    // Merge the real pending signal mask as well
    *set |= HostSignals;
  }
  return 0;
}

uint64_t SignalDelegator::GuestSigSuspend(FEX::HLE::ThreadStateObject* Thread, uint64_t* set, size_t sigsetsize) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  uint64_t IgnoredSignalsMask = ~((1ULL << (SIGKILL - 1)) | (1ULL << (SIGSTOP - 1)));

  // Backup the mask
  Thread->SignalInfo.PreviousSuspendMask = Thread->SignalInfo.CurrentSignalMask;
  // Set the new mask
  Thread->SignalInfo.CurrentSignalMask.Val = *set & IgnoredSignalsMask;
  sigset_t HostSet {};

  sigemptyset(&HostSet);

  for (int32_t i = 0; i < MAX_SIGNALS; ++i) {
    if (*set & (1ULL << i)) {
      sigaddset(&HostSet, i + 1);
    }
  }

  // Additionally we must always listen to SIGNAL_FOR_PAUSE
  // This technically forces us in to a race but should be fine
  // SIGBUS and SIGILL can't happen so we don't need to listen for them
  // sigaddset(&HostSet, SIGNAL_FOR_PAUSE);

  // Spin this in a loop until we aren't sigsuspended
  // This can happen in the case that the guest has sent signal that we can't block
  uint64_t Result = sigsuspend(&HostSet);

  // Restore Previous signal mask we are emulating
  // XXX: Might be unsafe if the signal handler adjusted the thread's signal mask
  // But since we don't support the guest adjusting the mask through the context object
  // then this is safe-ish
  Thread->SignalInfo.CurrentSignalMask = Thread->SignalInfo.PreviousSuspendMask;

  CheckForPendingSignals(Thread);

  return Result == -1 ? -errno : Result;
}

uint64_t SignalDelegator::GuestSigTimedWait(uint64_t* set, siginfo_t* info, const struct timespec* timeout, size_t sigsetsize) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  uint64_t Result = ::syscall(SYS_rt_sigtimedwait, set, info, timeout);

  return Result == -1 ? -errno : Result;
}

uint64_t SignalDelegator::GuestSignalFD(int fd, const uint64_t* set, size_t sigsetsize, int flags) {
  if (sigsetsize > sizeof(uint64_t)) {
    return -EINVAL;
  }

  sigset_t HostSet {};
  sigemptyset(&HostSet);

  for (size_t i = 0; i < MAX_SIGNALS; ++i) {
    if (HostHandlers[i + 1].Required.load(std::memory_order_relaxed)) {
      // For now skip our internal signals
      continue;
    }

    if (*set & (1ULL << i)) {
      sigaddset(&HostSet, i + 1);
    }
  }

  // XXX: This is a barebones implementation just to get applications that listen for SIGCHLD to work
  // In the future we need our own listern thread that forwards the result
  // Thread is necessary to prevent deadlocks for a thread that has signaled on the same thread listening to the FD and blocking is enabled
  uint64_t Result = signalfd(fd, &HostSet, flags);

  return Result == -1 ? -errno : Result;
}

fextl::unique_ptr<FEX::HLE::SignalDelegator>
CreateSignalDelegator(FEXCore::Context::Context* CTX, const std::string_view ApplicationName, bool SupportsAVX) {
  return fextl::make_unique<FEX::HLE::SignalDelegator>(CTX, ApplicationName, SupportsAVX);
}
} // namespace FEX::HLE
