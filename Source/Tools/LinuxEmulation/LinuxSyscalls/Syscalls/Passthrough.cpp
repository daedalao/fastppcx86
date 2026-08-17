// SPDX-License-Identifier: MIT
/*
$info$
meta: LinuxSyscalls|syscalls-shared ~ Syscall implementations shared between x86 and x86-64
tags: LinuxSyscalls|syscalls-shared
$end_info$
*/

#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/ThreadManager.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/SyscallObserver.h"
#include "LinuxSyscalls/ThreadCensus.h"
#include "VDSO_Emulation.h"

#ifdef ARCHITECTURE_ppc64le
#include "LinuxSyscalls/PPC64LE/TermiosTranslation.h"
#endif

#include <FEXCore/IR/IR.h>

#include <errno.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <termios.h>  // PPC TCGETS family expands to use sizeof(struct termios)

namespace FEX::HLE {
#if defined(ARCHITECTURE_ppc64le)
// PPC64LE Linux syscall ABI:
//   r0    = syscall number
//   r3..r8 = args 1..6  (r9, r10 for arg 7 if needed)
//   sc    instruction
//   r3    = result; CR0.SO set on error (r3 holds positive errno on error)
// Use inline asm to avoid glibc syscall() wrapper overhead (extra branch,
// TLS errno write, validation), and to keep the syscall path heap- and
// TLS-quiet for cases where that matters (vfork window).
//
// Errno handling: we mimic glibc semantics — return -errno on error,
// raw result on success.  The "isel" via mfocrf+rldicl-style check would
// be tighter, but we use a simple "neg r3 ; mfcr ; isel" idiom that the
// compiler can fold.  Easier: just test SO bit and conditionally negate.

// The `sc` and the CR0 read MUST live in the same asm block.
//
// This used to be two statements: `__asm volatile("sc" ...)` followed by a
// separate `__asm volatile("mfcr %0" ...)`. Two problems with that:
//
//  1. Correctness. Nothing tied the two blocks together. The compiler is free
//     to schedule any CR0-writing instruction between them -- a compare from
//     surrounding code, a dot-suffixed op the instruction selector picked,
//     anything -- at which point the SO bit read back belongs to that
//     instruction rather than to the kernel. The `sc` block clobbers "cr0",
//     which tells the compiler CR0 is *dead* after the syscall: precisely the
//     licence it needs to overwrite CR0 before the mfcr runs. A latent
//     miscompile that would surface as syscalls randomly reporting bogus
//     errors (or, worse, negating a valid positive result).
//
//  2. Cost. `mfcr` reads all eight CR fields and on POWER8 is cracked into
//     multiple internal ops, serialising against the whole condition register.
//     `mfocrf RT, 0x80` reads only CR0 and stays a single non-cracked op.
//     FXM=0x80 leaves CR0's bits in their architectural position (bits 32..35
//     of the GPR, i.e. mask 0xF000'0000; the rest are undefined), so the SO
//     test below is bit-for-bit the same test as before.
//
// This is glibc's ppc64 INTERNAL_SYSCALL shape -- sc, then mfocrf of CR0 in the
// same asm, then test the SO bit. See sysdeps/unix/sysv/linux/powerpc/
// powerpc64/sysdep.h.
#define PPC64_SYSCALL_SC_MFOCRF "sc\n\tmfocrf %[_cr0], 0x80"

#define PPC64_SYSCALL_RESULT(r3_out, cr0_in)                                                                      \
  /* If SO bit (bit 0 of cr0) set, kernel returned positive errno; negate to match Linux's -errno convention. */  \
  ({                                                                                                              \
    long _r = (long)(r3_out);                                                                                     \
    if ((cr0_in) & 0x10000000u) _r = -_r; /* SO bit lives at bit 28 of cr in CR0 position */                       \
    (uint64_t)_r;                                                                                                 \
  })

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough0(FEXCore::Core::CpuStateFrame* Frame) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3");
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "=r"(r3), "+r"(r0)
                 : : "memory", "r4","r5","r6","r7","r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough1(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0)
                 : : "memory", "r4","r5","r6","r7","r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough2(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4)
                 : : "memory", "r5","r6","r7","r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough3(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  register long r5 asm("r5") = (long)arg3;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4), "+r"(r5)
                 : : "memory", "r6","r7","r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough4(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  register long r5 asm("r5") = (long)arg3;
  register long r6 asm("r6") = (long)arg4;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4), "+r"(r5), "+r"(r6)
                 : : "memory", "r7","r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough5(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  register long r5 asm("r5") = (long)arg3;
  register long r6 asm("r6") = (long)arg4;
  register long r7 asm("r7") = (long)arg5;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7)
                 : : "memory", "r8","r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough6(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  register long r5 asm("r5") = (long)arg3;
  register long r6 asm("r6") = (long)arg4;
  register long r7 asm("r7") = (long)arg5;
  register long r8 asm("r8") = (long)arg6;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8)
                 : : "memory", "r9","r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough7(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6, uint64_t arg7) {
  register long r0 asm("r0") = syscall_num;
  register long r3 asm("r3") = (long)arg1;
  register long r4 asm("r4") = (long)arg2;
  register long r5 asm("r5") = (long)arg3;
  register long r6 asm("r6") = (long)arg4;
  register long r7 asm("r7") = (long)arg5;
  register long r8 asm("r8") = (long)arg6;
  register long r9 asm("r9") = (long)arg7;
  uint64_t _cr0;
  __asm volatile(PPC64_SYSCALL_SC_MFOCRF
                 : [_cr0] "=&r"(_cr0), "+r"(r3), "+r"(r0), "+r"(r4), "+r"(r5), "+r"(r6), "+r"(r7), "+r"(r8), "+r"(r9)
                 : : "memory", "r10","r11","r12","cr0","ctr");
  return PPC64_SYSCALL_RESULT(r3, _cr0);
}
#elif defined(ARCHITECTURE_arm64)
template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough0(FEXCore::Core::CpuStateFrame* Frame) {
  register uint64_t x0 asm("x0");
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough1(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1) {
  register uint64_t x0 asm("x0") = arg1;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough2(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough3(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough4(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough5(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough6(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register uint64_t x5 asm("x5") = arg6;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory");
  return x0;
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough7(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6, uint64_t arg7) {
  register uint64_t x0 asm("x0") = arg1;
  register uint64_t x1 asm("x1") = arg2;
  register uint64_t x2 asm("x2") = arg3;
  register uint64_t x3 asm("x3") = arg4;
  register uint64_t x4 asm("x4") = arg5;
  register uint64_t x5 asm("x5") = arg6;
  register uint64_t x6 asm("x6") = arg7;
  register int x8 asm("x8") = syscall_num;
  __asm volatile(R"(
    svc #0;
  )"
                 : "=r"(x0)
                 : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x6)
                 : "memory");
  return x0;
}
#else
template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough0(FEXCore::Core::CpuStateFrame* Frame) {
  uint64_t Result = ::syscall(syscall_num);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough1(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1) {
  uint64_t Result = ::syscall(syscall_num, arg1);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough2(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough3(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough4(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough5(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough6(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
  SYSCALL_ERRNO();
}

template<int syscall_num>
requires (syscall_num != -1)
uint64_t SyscallPassthrough7(FEXCore::Core::CpuStateFrame* Frame, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5,
                             uint64_t arg6, uint64_t arg7) {
  uint64_t Result = ::syscall(syscall_num, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
  SYSCALL_ERRNO();
}
#endif

// Phase B of SyscallObserver: tgkill wrapper. Pure logging side-effect;
// delegates the actual syscall to the bare SyscallPassthrough3 template
// so the guest sees byte-identical kernel ABI regardless of observer state.
// When FEX_SYSCALLOBSERVE is unset, OnTgkillCall is a single bool-load
// short-circuit -- essentially free.
static uint64_t WrappedTgkillObserved(FEXCore::Core::CpuStateFrame* Frame,
                                     uint64_t tgid, uint64_t tid, uint64_t sig) {
  // Diagnostic tripwire: a guest raising SIGABRT at itself is abort(). The
  // abort reason is frequently silent (mono/FMOD/Unity route their logs away
  // from stderr), so dump the guest RIP/RSP and a raw stack window here --
  // return addresses in the dump can be symbolized offline against the guest
  // libraries. Gated on FEX_ABORT_TRIPWIRE=1.
  if (sig == SIGABRT) {
    static const bool trip = (getenv("FEX_ABORT_TRIPWIRE") != nullptr);
    if (trip) {
      char buf[256];
      const uint64_t rip = Frame->State.rip;
      const uint64_t rsp = Frame->State.gregs[FEXCore::X86State::REG_RSP];
      int n = snprintf(buf, sizeof(buf), "[ABRT] tid=%d tgkill(%lu,%lu,SIGABRT) guest rip=0x%lx rsp=0x%lx stack:\n",
                       static_cast<int>(::syscall(SYS_gettid)), (unsigned long)tgid, (unsigned long)tid,
                       (unsigned long)rip, (unsigned long)rsp);
      [[maybe_unused]] auto _ = write(2, buf, n);
      if (rsp >= 0x10000ULL && rsp <= 0x00007FFFFFFFFFFFULL) {
        const uint64_t* sp = reinterpret_cast<const uint64_t*>(rsp);
        for (int i = 0; i < 96; i += 4) {
          n = snprintf(buf, sizeof(buf), "[ABRT] +%03x: %016lx %016lx %016lx %016lx\n", i * 8,
                       (unsigned long)sp[i], (unsigned long)sp[i + 1], (unsigned long)sp[i + 2], (unsigned long)sp[i + 3]);
          [[maybe_unused]] auto _2 = write(2, buf, n);
        }
      }
    }
  }
  FEX::HLE::SyscallObserver::OnTgkillCall(tgid, tid, sig);
  return SyscallPassthrough3<SYSCALL_DEF(tgkill)>(Frame, tgid, tid, sig);
}

// True when this thread has a signal that will ACTUALLY reach guest code on
// the next drain. Filtering matters in both directions this predicate is
// used: a deferred frame whose signal is guest-masked, SIG_IGN, or
// default-ignore (a Wine process's SIGCHLD, typically) is parked or dropped
// at drain time, never delivered — synthesizing an EINTR for it would
// fabricate an interruption no real kernel produces, and suppressing a
// restart for it would leak the same. See
// SignalDelegator::ThreadHasDeliverableGuestSignal for the filter.
static bool HasGuestDeliverableSignal(FEXCore::Core::CpuStateFrame* Frame) {
  auto* TSO = FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame);
  return FEX::HLE::_SyscallHandler->GetSignalDelegator()->ThreadHasDeliverableGuestSignal(TSO);
}

// Non-static: also the terminal stage of the x32 classic futex(240) handler
// (x32/Thread.cpp), which converts its timespec32 and forwards here so both
// bitnesses share the deferred-signal guard, restart logic and diagnostics.
uint64_t ObservedFutexSyscall(FEXCore::Core::CpuStateFrame* Frame,
                              uint64_t uaddr, uint64_t futex_op, uint64_t val,
                              uint64_t timeout, uint64_t uaddr2, uint64_t val3) {
  // PPC64LE strips SA_RESTART from every host sigaction (SignalDelegator.cpp:
  // the deferred-signal queue drains on the -EINTR unwind of HandleSyscall).
  // Two consequences meet here, pulling in opposite directions:
  //
  //  1. FEX-INTERNAL async signals — thread-suspend pokes, code-invalidation
  //     IPIs — interrupt guest futex waits and leak a spurious EINTR the
  //     guest never asked for. Native x86 apps see EINTR only for signals
  //     they actually receive; Unity's semaphore wrapper logs "Failed to
  //     wait on a semaphore (Interrupted system call)" and its render thread
  //     parks forever (Ziggurat wedges at init with a black window). So
  //     internal-only interruptions must be restarted, not surfaced.
  //
  //  2. A GUEST signal consumed while the thread was still in JIT code (or
  //     early in the syscall body) sits in DeferredSignalFrames until the
  //     drain sentinel fires at the next JIT dispatch. If the thread's next
  //     act is an UNTIMED futex wait, the sentinel is never touched: the
  //     thread sleeps forever holding the very signal whose handler would
  //     have woken it. A real kernel delivers a pending unblocked signal
  //     before or during the wait — never after an eternal sleep. Proven
  //     deterministically by notes/tools/futex_stress.c 'sig' mode (native
  //     clean, FEX 32- and 64-bit both wedge in seconds). So untimed waits
  //     must never block with a deferred frame queued, and must recheck
  //     periodically because a frame can be queued between any check and
  //     the trap. The same black hole exists, UNADDRESSED, for every other
  //     signal-wakeable untimed sleep: epoll_wait, ppoll, nanosleep, and
  //     futex_waitv (plain passthrough below — Wine fsync waits ride it, so
  //     any Proton config still on fsync rather than ntsync is exposed).
  //
  // Resolution, two tiers:
  //
  // ALWAYS (the entry check): never enter a signal-wakeable untimed wait
  // with a deferred frame already queued — return -EINTR, whose unwind
  // delivers the signal. This closes the proven black hole for the common
  // case (the frame is queued while the thread is still in JIT). A residual
  // race remains: a frame queued between this check and the trap still
  // parks (window is a few hundred instructions vs. the entire preceding
  // JIT block chain before the fix). 32-bit caveat: the guest-SA_RESTART
  // restart loop is 64-bit-only (Syscalls.cpp), so a 32-bit raw-futex user
  // whose handler has SA_RESTART sees an EINTR here that a native kernel
  // would hide behind an automatic restart. glibc loops on EINTR and is
  // unaffected. KNOWN-OPEN: extend guest SA_RESTART to 32-bit.
  //
  // DEFAULT-ON, FEX_FUTEX_RESCUE=0 disables (exact string "0" only):
  // additionally wait in 100ms slices, rechecking the deferred queue at
  // every boundary (closes the residual race), and after ~5s of no progress
  // return a spurious wake (0) so the guest rechecks its predicate.
  // FUTEX_WAIT is documented to wake spuriously and correct waiters
  // tolerate it — but be honest about the converse: a waiter that treats
  // wake-as-event without a predicate (reliable in practice on real Linux)
  // will see the rescue as a FALSE EVENT every ~5s parked. Steady-state
  // cost, also honest: each parked untimed waiter takes an hrtimer expiry +
  // syscall re-issue per 100ms slice — ten kernel wakeups per second per
  // parked thread, forever — plus the one guest-visible spurious wake per
  // 5s. A 100-thread parked pool is ~1000 idle wakeups/s process-wide.
  //
  // WHY THIS TIER IS DEFAULT-ON (measured, 2026-08-13): with only the entry
  // check, futex_stress 'sig' mode still wedges ~half its runs — the
  // check-to-trap window is readily hit under signal storms, so
  // entry-check-only leaves a reachable PERMANENT hang in the default
  // config. The slicing trade-off cuts the other way and is bounded:
  // between slice re-issues the thread is briefly not queued on the futex.
  // Protocols that mutate the word before waking (all of glibc) are safe —
  // the re-issue converts the missed wake to EAGAIN via the kernel's
  // *uaddr==val re-compare. A pure FUTEX_WAKE nudge with NO word change
  // landing in that microsecond gap is lost until the 5s spurious wake
  // recovers it — bounded latency, vs. the unbounded hang the black hole
  // causes. Bounded beats unbounded, so the default is ON; slicing and
  // rescue are one inseparable knob (slicing without the rescue would turn
  // that lost nudge into a permanent hang), FEX_FUTEX_RESCUE=0 disables
  // both.
  //
  // PI waits (LOCK_PI, WAIT_REQUEUE_PI, LOCK_PI2) are excluded from both
  // tiers' wait paths: the kernel auto-restarts them across signals
  // (ERESTARTNOINTR), glibc treats an EINTR from them as fatal, and
  // WAIT_REQUEUE_PI must not be re-issued after the requeue has happened.
  // Their wake comes from FUTEX_UNLOCK_PI, not a signal, so the black hole
  // needs the owner to be wedged too — KNOWN-OPEN, revisit if a PI-mutex
  // guest wedges.
  //
  // Escape hatch: FEX_FUTEX_EINTR_PASSTHRU=1 restores always-surface EINTR.
  constexpr uint64_t FUTEX_CMD_MASK_LOCAL = ~uint64_t(128 | 256); // ~(PRIVATE_FLAG|CLOCK_REALTIME)
  const uint64_t cmd = futex_op & FUTEX_CMD_MASK_LOCAL;
  const bool PlainWait = cmd == 0;   // FUTEX_WAIT: relative timeout or none
  const bool BitsetWait = cmd == 9;  // FUTEX_WAIT_BITSET: absolute timeout or none
  static const bool Passthru = (getenv("FEX_FUTEX_EINTR_PASSTHRU") != nullptr);
  static const bool Rescue = [] {
    const char* Env = getenv("FEX_FUTEX_RESCUE");
    return !(Env && Env[0] == '0' && Env[1] == '\0');
  }();

  uint64_t result;
  if ((PlainWait || BitsetWait) && HasGuestDeliverableSignal(Frame)) {
    // Never enter a signal-wakeable sleep with a parked guest signal.
    result = static_cast<uint64_t>(-EINTR);
  } else if ((PlainWait || BitsetWait) && timeout == 0 && Rescue) {
    int SlicesParked = 0;
    for (;;) {
      struct timespec Slice;
      if (BitsetWait) {
        // WAIT_BITSET takes an ABSOLUTE deadline on the op's clock.
        clock_gettime((futex_op & 256) ? CLOCK_REALTIME : CLOCK_MONOTONIC, &Slice);
        Slice.tv_nsec += 100000000;
        if (Slice.tv_nsec >= 1000000000) {
          Slice.tv_nsec -= 1000000000;
          Slice.tv_sec += 1;
        }
      } else {
        Slice.tv_sec = 0;
        Slice.tv_nsec = 100000000;
      }
      result = SyscallPassthrough6<SYSCALL_DEF(futex)>(Frame, uaddr, futex_op, val,
                                                       reinterpret_cast<uint64_t>(&Slice), uaddr2, val3);
      const int64_t sr = static_cast<int64_t>(result);
      if (sr == -ETIMEDOUT) {
        // Slice deadline is synthesized; the guest asked for no timeout and
        // must never see ETIMEDOUT. The kernel re-compares *uaddr==val on
        // re-issue, so a wake that raced the boundary converts to EAGAIN.
        if (HasGuestDeliverableSignal(Frame)) {
          result = static_cast<uint64_t>(-EINTR);
          break;
        }
        if (++SlicesParked >= 50) {
          result = 0; // spurious wake: guest rechecks its predicate
          break;
        }
        continue;
      }
      if (sr == -EINTR && !Passthru && !HasGuestDeliverableSignal(Frame)) {
        continue; // FEX-internal interruption, invisible to the guest
      }
      break;
    }
  } else {
    result = SyscallPassthrough6<SYSCALL_DEF(futex)>(Frame, uaddr, futex_op, val, timeout, uaddr2, val3);
    // FUTEX_WAIT with a relative timeout is restarted by re-issuing the FULL
    // timeout. That over-waits by up to one interval per internal
    // interruption — acceptable imprecision, and strictly better than a
    // spurious EINTR: Unity's sem_timedwait-based render-thread sync treats
    // the EINTR as failure and parks the renderer permanently.
    if (!Passthru && (PlainWait || BitsetWait)) {
      while (static_cast<int64_t>(result) == -EINTR && !HasGuestDeliverableSignal(Frame)) {
        result = SyscallPassthrough6<SYSCALL_DEF(futex)>(Frame, uaddr, futex_op, val, timeout, uaddr2, val3);
      }
    }
  }

  // Diagnostic: catch any futex syscall whose errno is something glibc
  // pthread treats as fatal — that's what produces "The futex facility
  // returned an unexpected error code" panics. glibc accepts 0, EAGAIN,
  // EINTR, ETIMEDOUT, EWOULDBLOCK; anything else aborts the process.
  // Enable with FEX_LOG_UNEXPECTED_FUTEX=1.
  const int64_t signed_result = static_cast<int64_t>(result);
  if (signed_result < 0) {
    static const bool log_futex = (getenv("FEX_LOG_UNEXPECTED_FUTEX") != nullptr);
    if (log_futex) {
      const int err = static_cast<int>(-signed_result);
      const bool is_expected = (err == EAGAIN || err == EINTR || err == ETIMEDOUT || err == EWOULDBLOCK);
      if (!is_expected) {
        char buf[256];
        int n = snprintf(buf, sizeof(buf),
                         "[FEX-futex-bad] op=0x%lx uaddr=0x%lx val=0x%lx timeout=0x%lx uaddr2=0x%lx val3=0x%lx -> errno=%d\n",
                         (unsigned long)futex_op, (unsigned long)uaddr, (unsigned long)val,
                         (unsigned long)timeout, (unsigned long)uaddr2, (unsigned long)val3, err);
        [[maybe_unused]] auto _ = write(2, buf, n);
      }
    }
  }

  // Diagnostic: full futex traffic trace, for chasing lost-wakeup livelocks.
  // Two-stage arming so it costs one bool load until wanted and can be turned
  // on mid-run once a wedge is established: run with FEX_FUTEX_TRACE=1, then
  // `touch /tmp/ftx_on` to start logging (rm to stop). Logs every futex call:
  // tid, op, uaddr, val, kernel result, and the futex word's live value after
  // return -- enough to see a WAIT that never blocks and whether any WAKE
  // targets the same uaddr.
  {
    static const bool trace_futex = (getenv("FEX_FUTEX_TRACE") != nullptr);
    if (trace_futex && access("/tmp/ftx_on", F_OK) == 0) {
      // Own file, not stderr: guests (steamcmd) redirect or replace fd 2
      // early, which silently ate the trace from exactly the process under
      // investigation. Benign race on first use: a double open leaks one fd
      // once per process.
      // O_NOFOLLOW: predictable name in world-writable /tmp, refuse a
      // planted symlink. A fork-without-exec child inherits this fd and
      // keeps logging into the PARENT's pid-named file — separation holds
      // only across exec.
      static int trace_fd = -1;
      if (trace_fd == -1) {
        char path[64];
        snprintf(path, sizeof(path), "/tmp/ftx.%d.log", static_cast<int>(::getpid()));
        trace_fd = ::open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0644);
        if (trace_fd == -1) {
          trace_fd = -2; // failed once: never retry, never write
        }
      }
      if (trace_fd >= 0) {
      static thread_local pid_t tls_tid = 0;
      if (tls_tid == 0) {
        tls_tid = static_cast<pid_t>(::syscall(SYS_gettid));
      }
      // process_vm_readv, not a raw memcpy: a WAKE can succeed against a
      // uaddr the guest has since unmapped, and a raw read of it would
      // SIGSEGV the emulator from inside its own diagnostic.
      uint32_t cur = 0xdeadbeef;
      if (uaddr && signed_result != -EFAULT) {
        struct iovec local {&cur, sizeof(cur)};
        struct iovec remote {reinterpret_cast<void*>(uaddr), sizeof(cur)};
        if (::process_vm_readv(::getpid(), &local, 1, &remote, 1, 0) != sizeof(cur)) {
          cur = 0xdeadbeef;
        }
      }
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      char buf[192];
      int n = snprintf(buf, sizeof(buf), "[FTX %ld.%03ld] t=%d op=0x%lx u=0x%lx val=0x%lx to=0x%lx r=%ld cur=0x%x\n",
                       (long)now.tv_sec, now.tv_nsec / 1000000, static_cast<int>(tls_tid), (unsigned long)futex_op,
                       (unsigned long)uaddr, (unsigned long)val, (unsigned long)timeout, (long)signed_result, cur);
      [[maybe_unused]] auto _ = write(trace_fd, buf, n);
      }
    }
  }

  const auto action =
    FEX::HLE::SyscallObserver::OnFutexReturn(uaddr, futex_op, val, static_cast<int64_t>(result));
  if (action == FEX::HLE::SyscallObserver::FutexAction::ThenYield) {
    ::sched_yield();
  }
  return result;
}

// ---------------------------------------------------------------------------
// ThreadCensus / SchedPassthrough wrappers for the sched_set* family.
//
// FEX's pre-existing behaviour for every one of these is a *bare passthrough*:
// the guest's request goes straight to the host kernel with the same arguments
// (guest TIDs are host TIDs in FEX's 1:1 threading model), and the guest sees
// whatever the kernel said. Nothing is faked and nothing is filtered. These
// wrappers preserve that exactly -- they call the same SyscallPassthrough<N>
// template and return its result unmodified. All they add are side effects:
// census lines, and (only after the host has already refused with EPERM) the
// SchedPassthrough ladder's extra host-side scheduling calls.
//
// Reading the guest's argument structs: these pointers were just handed to the
// kernel, so they are only dereferenced when the kernel's own return value
// proves it read them successfully. Every one of these syscalls copies its
// user struct in before any other validation, so anything other than -EFAULT
// means the buffer was readable. That keeps a bogus guest pointer returning
// EFAULT instead of faulting inside FEX.
static bool GuestStructReadable(uint64_t Pointer, uint64_t Result) {
  return Pointer != 0 && static_cast<int64_t>(Result) != -EFAULT;
}

// struct sched_param is a single int on every ABI FEX emulates (x86-32,
// x86-64) as well as on the PPC64LE host, so no layout translation is needed.
static int ReadSchedPriority(uint64_t Param, uint64_t Result) {
  if (!GuestStructReadable(Param, Result)) {
    return -1;
  }
  return *reinterpret_cast<const int32_t*>(Param);
}

// Prefix of the kernel's struct sched_attr. Identical layout for 32-bit and
// 64-bit guests (fixed-width fields, naturally aligned, no pointers).
struct CensusSchedAttr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
};

static uint64_t WrappedSchedSetparam(FEXCore::Core::CpuStateFrame* Frame, uint64_t pid, uint64_t param) {
  const uint64_t Result = SyscallPassthrough2<SYSCALL_DEF(sched_setparam)>(Frame, pid, param);
  if (FEX::HLE::ThreadCensus::Enabled()) {
    FEX::HLE::ThreadCensus::OnSchedSet("sched_setparam", static_cast<int64_t>(pid), -1, ReadSchedPriority(param, Result),
                                       static_cast<int64_t>(Result));
  }
  return Result;
}

static uint64_t WrappedSchedSetscheduler(FEXCore::Core::CpuStateFrame* Frame, uint64_t pid, uint64_t policy, uint64_t param) {
  const uint64_t Result = SyscallPassthrough3<SYSCALL_DEF(sched_setscheduler)>(Frame, pid, policy, param);

  const int Priority = ReadSchedPriority(param, Result);
  if (FEX::HLE::ThreadCensus::Enabled()) {
    FEX::HLE::ThreadCensus::OnSchedSet("sched_setscheduler", static_cast<int64_t>(pid), static_cast<int>(policy), Priority,
                                       static_cast<int64_t>(Result));
  }
  if (static_cast<int64_t>(Result) < 0) {
    FEX::HLE::SchedPassthrough::OnSchedRequestRefused(static_cast<int64_t>(pid), static_cast<int>(policy), Priority,
                                                      static_cast<int64_t>(Result));
  }
  return Result;
}

static uint64_t WrappedSchedSetattr(FEXCore::Core::CpuStateFrame* Frame, uint64_t pid, uint64_t attr, uint64_t flags) {
  const uint64_t Result = SyscallPassthrough3<SYSCALL_DEF(sched_setattr)>(Frame, pid, attr, flags);

  int Policy = -1;
  int Priority = -1;
  if (GuestStructReadable(attr, Result)) {
    const auto* GuestAttr = reinterpret_cast<const CensusSchedAttr*>(attr);
    if (GuestAttr->size >= sizeof(CensusSchedAttr)) {
      Policy = static_cast<int>(GuestAttr->sched_policy);
      Priority = static_cast<int>(GuestAttr->sched_priority);
    }
  }

  if (FEX::HLE::ThreadCensus::Enabled()) {
    FEX::HLE::ThreadCensus::OnSchedSet("sched_setattr", static_cast<int64_t>(pid), Policy, Priority, static_cast<int64_t>(Result));
  }
  if (static_cast<int64_t>(Result) < 0 && Policy >= 0) {
    FEX::HLE::SchedPassthrough::OnSchedRequestRefused(static_cast<int64_t>(pid), Policy, Priority, static_cast<int64_t>(Result));
  }
  return Result;
}

static uint64_t WrappedSchedSetaffinity(FEXCore::Core::CpuStateFrame* Frame, uint64_t pid, uint64_t cpusetsize, uint64_t mask) {
  const uint64_t Result = SyscallPassthrough3<SYSCALL_DEF(sched_setaffinity)>(Frame, pid, cpusetsize, mask);
  if (FEX::HLE::ThreadCensus::Enabled()) {
    const bool Readable = GuestStructReadable(mask, Result);
    FEX::HLE::ThreadCensus::OnSetAffinity(static_cast<int64_t>(pid), Readable ? reinterpret_cast<const uint8_t*>(mask) : nullptr,
                                          Readable ? cpusetsize : 0, static_cast<int64_t>(Result));
  }
  return Result;
}

// -----------------------------------------------------------------------------
// Clock reads via the host vDSO
// -----------------------------------------------------------------------------
// A guest that goes through its own vDSO never reaches these handlers -- the
// guest-vDSO thunks in VDSO_Emulation.cpp already call the host vDSO directly.
// But plenty of guest code issues the raw syscall regardless: Mono's
// mono_100ns_ticks, static binaries with no vDSO wired up, and anything calling
// syscall(2) by hand. Those paid a full kernel entry for a clock read that the
// host can serve entirely in userspace, on a path hot enough that Mono profiles
// it as a top-of-list syscall.
//
// Route them through the same pointers the guest-vDSO path uses, falling back
// to the raw `sc` when the host kernel exposes no vDSO (or no such symbol), in
// which case the pointer stays null forever.
//
// The pointers are resolved once by LoadHostVDSO(), from LoadVDSOThunks() on
// the main thread, before any guest instruction runs -- so a guest syscall can
// never observe them half-initialised, and every read here is of immutable
// data. Re-read the accessor per call rather than caching: the cost is a load
// from a static, and caching would only add a second copy to keep coherent.
//
// Return convention: these pointers carry the negative-errno convention (on
// ppc64le they are ppc_kernel_vdso's sign-flipping shims, see VDSO_Emulation.h),
// which is exactly what a passthrough handler must return, so the result is
// sign-extended straight through with no SYSCALL_ERRNO() dance.
static uint64_t VDSOClockGetTime(FEXCore::Core::CpuStateFrame* Frame, uint64_t clk_id, uint64_t tp) {
  const auto Fn = FEX::VDSO::GetHostVDSOClocks().ClockGetTime;
  if (Fn) {
    return static_cast<uint64_t>(static_cast<int64_t>(Fn(static_cast<clockid_t>(clk_id), reinterpret_cast<struct timespec*>(tp))));
  }
  return SyscallPassthrough2<SYSCALL_DEF(clock_gettime)>(Frame, clk_id, tp);
}

static uint64_t VDSOClockGetRes(FEXCore::Core::CpuStateFrame* Frame, uint64_t clk_id, uint64_t tp) {
  const auto Fn = FEX::VDSO::GetHostVDSOClocks().ClockGetRes;
  if (Fn) {
    return static_cast<uint64_t>(static_cast<int64_t>(Fn(static_cast<clockid_t>(clk_id), reinterpret_cast<struct timespec*>(tp))));
  }
  return SyscallPassthrough2<SYSCALL_DEF(clock_getres)>(Frame, clk_id, tp);
}

static uint64_t VDSOGetTimeOfDay(FEXCore::Core::CpuStateFrame* Frame, uint64_t tv, uint64_t tz) {
  const auto Fn = FEX::VDSO::GetHostVDSOClocks().GetTimeOfDay;
  if (Fn) {
    return static_cast<uint64_t>(
      static_cast<int64_t>(Fn(reinterpret_cast<struct timeval*>(tv), reinterpret_cast<struct timezone*>(tz))));
  }
  return SyscallPassthrough2<SYSCALL_DEF(gettimeofday)>(Frame, tv, tz);
}

void RegisterCommon(FEX::HLE::SyscallHandler* Handler) {
  using namespace FEXCore::IR;
  REGISTER_SYSCALL_IMPL(read, SyscallPassthrough3<SYSCALL_DEF(read)>);
  REGISTER_SYSCALL_IMPL(write, SyscallPassthrough3<SYSCALL_DEF(write)>);
  REGISTER_SYSCALL_IMPL(lseek, SyscallPassthrough3<SYSCALL_DEF(lseek)>);
  REGISTER_SYSCALL_IMPL(sched_yield, SyscallPassthrough0<SYSCALL_DEF(sched_yield)>);
  REGISTER_SYSCALL_IMPL(msync, SyscallPassthrough3<SYSCALL_DEF(msync)>);
  REGISTER_SYSCALL_IMPL(mincore, SyscallPassthrough3<SYSCALL_DEF(mincore)>);
  REGISTER_SYSCALL_IMPL(shmget, SyscallPassthrough3<SYSCALL_DEF(shmget)>);
  // shmctl needs struct translation (powerpc64 shmid64_ds field order differs
  // from x86); registered in x64/x32 Semaphore.cpp.
  REGISTER_SYSCALL_IMPL(getpid, SyscallPassthrough0<SYSCALL_DEF(getpid)>);
  REGISTER_SYSCALL_IMPL(socket, SyscallPassthrough3<SYSCALL_DEF(socket)>);
  REGISTER_SYSCALL_IMPL(connect, SyscallPassthrough3<SYSCALL_DEF(connect)>);
  REGISTER_SYSCALL_IMPL(sendto, SyscallPassthrough6<SYSCALL_DEF(sendto)>);
  REGISTER_SYSCALL_IMPL(recvfrom, SyscallPassthrough6<SYSCALL_DEF(recvfrom)>);
  REGISTER_SYSCALL_IMPL(shutdown, SyscallPassthrough2<SYSCALL_DEF(shutdown)>);
  REGISTER_SYSCALL_IMPL(bind, SyscallPassthrough3<SYSCALL_DEF(bind)>);
  REGISTER_SYSCALL_IMPL(listen, SyscallPassthrough2<SYSCALL_DEF(listen)>);
  REGISTER_SYSCALL_IMPL(getsockname, SyscallPassthrough3<SYSCALL_DEF(getsockname)>);
  REGISTER_SYSCALL_IMPL(getpeername, SyscallPassthrough3<SYSCALL_DEF(getpeername)>);
  REGISTER_SYSCALL_IMPL(socketpair, SyscallPassthrough4<SYSCALL_DEF(socketpair)>);
  REGISTER_SYSCALL_IMPL(kill, SyscallPassthrough2<SYSCALL_DEF(kill)>);
  REGISTER_SYSCALL_IMPL(semget, SyscallPassthrough3<SYSCALL_DEF(semget)>);
  REGISTER_SYSCALL_IMPL(msgget, SyscallPassthrough2<SYSCALL_DEF(msgget)>);
  REGISTER_SYSCALL_IMPL(msgsnd, SyscallPassthrough4<SYSCALL_DEF(msgsnd)>);
  REGISTER_SYSCALL_IMPL(msgrcv, SyscallPassthrough5<SYSCALL_DEF(msgrcv)>);
  // msqid64_ds layout matches the host for 64-bit guests only; the 32-bit
  // direct msgctl is registered in x32/Semaphore.cpp.
  REGISTER_SYSCALL_IMPL_X64(msgctl, SyscallPassthrough3<SYSCALL_DEF(msgctl)>);
  REGISTER_SYSCALL_IMPL(flock, SyscallPassthrough2<SYSCALL_DEF(flock)>);
  REGISTER_SYSCALL_IMPL(fsync, SyscallPassthrough1<SYSCALL_DEF(fsync)>);
  REGISTER_SYSCALL_IMPL(fdatasync, SyscallPassthrough1<SYSCALL_DEF(fdatasync)>);
  REGISTER_SYSCALL_IMPL(getcwd, SyscallPassthrough2<SYSCALL_DEF(getcwd)>);
  // chdir goes through FileManager for path translation — the raw passthrough
  // that used to live here missed the rootfs remap and broke dpkg -i, which
  // creates its workdir via mkdirat(rootfs_dirfd, "var/lib/dpkg/tmp.ci", ...)
  // and then chdir("/var/lib/dpkg/tmp.ci"). fchdir takes a bare fd and needs
  // no translation, so it stays a raw passthrough.
  REGISTER_SYSCALL_IMPL(fchdir, SyscallPassthrough1<SYSCALL_DEF(fchdir)>);
  REGISTER_SYSCALL_IMPL(fchmod, SyscallPassthrough2<SYSCALL_DEF(fchmod)>);
  REGISTER_SYSCALL_IMPL(fchown, SyscallPassthrough3<SYSCALL_DEF(fchown)>);
  REGISTER_SYSCALL_IMPL(umask, SyscallPassthrough1<SYSCALL_DEF(umask)>);
  REGISTER_SYSCALL_IMPL(getuid, SyscallPassthrough0<SYSCALL_DEF(getuid)>);
  REGISTER_SYSCALL_IMPL(syslog, SyscallPassthrough3<SYSCALL_DEF(syslog)>);
  REGISTER_SYSCALL_IMPL(getgid, SyscallPassthrough0<SYSCALL_DEF(getgid)>);
  REGISTER_SYSCALL_IMPL(setuid, SyscallPassthrough1<SYSCALL_DEF(setuid)>);
  REGISTER_SYSCALL_IMPL(setgid, SyscallPassthrough1<SYSCALL_DEF(setgid)>);
  REGISTER_SYSCALL_IMPL(geteuid, SyscallPassthrough0<SYSCALL_DEF(geteuid)>);
  REGISTER_SYSCALL_IMPL(getegid, SyscallPassthrough0<SYSCALL_DEF(getegid)>);
  REGISTER_SYSCALL_IMPL(setpgid, SyscallPassthrough2<SYSCALL_DEF(setpgid)>);
  REGISTER_SYSCALL_IMPL(getppid, SyscallPassthrough0<SYSCALL_DEF(getppid)>);
  REGISTER_SYSCALL_IMPL(setsid, SyscallPassthrough0<SYSCALL_DEF(setsid)>);
  REGISTER_SYSCALL_IMPL(setreuid, SyscallPassthrough2<SYSCALL_DEF(setreuid)>);
  REGISTER_SYSCALL_IMPL(setregid, SyscallPassthrough2<SYSCALL_DEF(setregid)>);
  REGISTER_SYSCALL_IMPL(getgroups, SyscallPassthrough2<SYSCALL_DEF(getgroups)>);
  REGISTER_SYSCALL_IMPL(setgroups, SyscallPassthrough2<SYSCALL_DEF(setgroups)>);
  REGISTER_SYSCALL_IMPL(setresuid, SyscallPassthrough3<SYSCALL_DEF(setresuid)>);
  REGISTER_SYSCALL_IMPL(getresuid, SyscallPassthrough3<SYSCALL_DEF(getresuid)>);
  REGISTER_SYSCALL_IMPL(setresgid, SyscallPassthrough3<SYSCALL_DEF(setresgid)>);
  REGISTER_SYSCALL_IMPL(getresgid, SyscallPassthrough3<SYSCALL_DEF(getresgid)>);
  REGISTER_SYSCALL_IMPL(getpgid, SyscallPassthrough1<SYSCALL_DEF(getpgid)>);
  REGISTER_SYSCALL_IMPL(setfsuid, SyscallPassthrough1<SYSCALL_DEF(setfsuid)>);
  REGISTER_SYSCALL_IMPL(setfsgid, SyscallPassthrough1<SYSCALL_DEF(setfsgid)>);
  REGISTER_SYSCALL_IMPL(getsid, SyscallPassthrough1<SYSCALL_DEF(getsid)>);
  REGISTER_SYSCALL_IMPL(capget, SyscallPassthrough2<SYSCALL_DEF(capget)>);
  REGISTER_SYSCALL_IMPL(capset, SyscallPassthrough2<SYSCALL_DEF(capset)>);
  REGISTER_SYSCALL_IMPL(getpriority, SyscallPassthrough2<SYSCALL_DEF(getpriority)>);
  REGISTER_SYSCALL_IMPL(setpriority, SyscallPassthrough3<SYSCALL_DEF(setpriority)>);
  REGISTER_SYSCALL_IMPL(sched_setparam, WrappedSchedSetparam);
  REGISTER_SYSCALL_IMPL(sched_getparam, SyscallPassthrough2<SYSCALL_DEF(sched_getparam)>);
  REGISTER_SYSCALL_IMPL(sched_setscheduler, WrappedSchedSetscheduler);
  REGISTER_SYSCALL_IMPL(sched_getscheduler, SyscallPassthrough1<SYSCALL_DEF(sched_getscheduler)>);
  REGISTER_SYSCALL_IMPL(sched_get_priority_max, SyscallPassthrough1<SYSCALL_DEF(sched_get_priority_max)>);
  REGISTER_SYSCALL_IMPL(sched_get_priority_min, SyscallPassthrough1<SYSCALL_DEF(sched_get_priority_min)>);
  REGISTER_SYSCALL_IMPL(mlock, SyscallPassthrough2<SYSCALL_DEF(mlock)>);
  REGISTER_SYSCALL_IMPL(munlock, SyscallPassthrough2<SYSCALL_DEF(munlock)>);
  REGISTER_SYSCALL_IMPL(pivot_root, SyscallPassthrough2<SYSCALL_DEF(pivot_root)>);
  REGISTER_SYSCALL_IMPL(chroot, SyscallPassthrough1<SYSCALL_DEF(chroot)>);
  REGISTER_SYSCALL_IMPL(sync, SyscallPassthrough0<SYSCALL_DEF(sync)>);
  REGISTER_SYSCALL_IMPL(acct, SyscallPassthrough1<SYSCALL_DEF(acct)>);
  REGISTER_SYSCALL_IMPL(mount, SyscallPassthrough5<SYSCALL_DEF(mount)>);
  REGISTER_SYSCALL_IMPL(umount2, SyscallPassthrough2<SYSCALL_DEF(umount2)>);
  REGISTER_SYSCALL_IMPL(swapon, SyscallPassthrough2<SYSCALL_DEF(swapon)>);
  REGISTER_SYSCALL_IMPL(swapoff, SyscallPassthrough1<SYSCALL_DEF(swapoff)>);
  REGISTER_SYSCALL_IMPL(gettid, SyscallPassthrough0<SYSCALL_DEF(gettid)>);
  REGISTER_SYSCALL_IMPL(fsetxattr, SyscallPassthrough5<SYSCALL_DEF(fsetxattr)>);
  REGISTER_SYSCALL_IMPL(fgetxattr, SyscallPassthrough4<SYSCALL_DEF(fgetxattr)>);
  REGISTER_SYSCALL_IMPL(flistxattr, SyscallPassthrough3<SYSCALL_DEF(flistxattr)>);
  REGISTER_SYSCALL_IMPL(fremovexattr, SyscallPassthrough2<SYSCALL_DEF(fremovexattr)>);
  REGISTER_SYSCALL_IMPL(tkill, SyscallPassthrough2<SYSCALL_DEF(tkill)>);
  REGISTER_SYSCALL_IMPL(sched_setaffinity, WrappedSchedSetaffinity);
  REGISTER_SYSCALL_IMPL(sched_getaffinity, SyscallPassthrough3<SYSCALL_DEF(sched_getaffinity)>);
  REGISTER_SYSCALL_IMPL(io_setup, SyscallPassthrough2<SYSCALL_DEF(io_setup)>);
  REGISTER_SYSCALL_IMPL(io_destroy, SyscallPassthrough1<SYSCALL_DEF(io_destroy)>);
  REGISTER_SYSCALL_IMPL(io_submit, SyscallPassthrough3<SYSCALL_DEF(io_submit)>);
  REGISTER_SYSCALL_IMPL(io_cancel, SyscallPassthrough3<SYSCALL_DEF(io_cancel)>);
  REGISTER_SYSCALL_IMPL(remap_file_pages, SyscallPassthrough5<SYSCALL_DEF(remap_file_pages)>);
  REGISTER_SYSCALL_IMPL(timer_getoverrun, SyscallPassthrough1<SYSCALL_DEF(timer_getoverrun)>);
  REGISTER_SYSCALL_IMPL(timer_delete, SyscallPassthrough1<SYSCALL_DEF(timer_delete)>);
  REGISTER_SYSCALL_IMPL(tgkill, WrappedTgkillObserved);
  REGISTER_SYSCALL_IMPL(mbind, SyscallPassthrough6<SYSCALL_DEF(mbind)>);
  REGISTER_SYSCALL_IMPL(set_mempolicy, SyscallPassthrough3<SYSCALL_DEF(set_mempolicy)>);
  REGISTER_SYSCALL_IMPL(get_mempolicy, SyscallPassthrough5<SYSCALL_DEF(get_mempolicy)>);
  REGISTER_SYSCALL_IMPL(mq_unlink, SyscallPassthrough1<SYSCALL_DEF(mq_unlink)>);
  REGISTER_SYSCALL_IMPL(add_key, SyscallPassthrough5<SYSCALL_DEF(add_key)>);
  REGISTER_SYSCALL_IMPL(request_key, SyscallPassthrough4<SYSCALL_DEF(request_key)>);
  REGISTER_SYSCALL_IMPL(keyctl, SyscallPassthrough5<SYSCALL_DEF(keyctl)>);
  REGISTER_SYSCALL_IMPL(ioprio_set, SyscallPassthrough2<SYSCALL_DEF(ioprio_set)>);
  REGISTER_SYSCALL_IMPL(ioprio_get, SyscallPassthrough3<SYSCALL_DEF(ioprio_get)>);
  REGISTER_SYSCALL_IMPL(inotify_add_watch, SyscallPassthrough3<SYSCALL_DEF(inotify_add_watch)>);
  REGISTER_SYSCALL_IMPL(inotify_rm_watch, SyscallPassthrough2<SYSCALL_DEF(inotify_rm_watch)>);
  REGISTER_SYSCALL_IMPL(migrate_pages, SyscallPassthrough4<SYSCALL_DEF(migrate_pages)>);
  REGISTER_SYSCALL_IMPL(mknodat, SyscallPassthrough4<SYSCALL_DEF(mknodat)>);
  REGISTER_SYSCALL_IMPL(unshare, SyscallPassthrough1<SYSCALL_DEF(unshare)>);
  REGISTER_SYSCALL_IMPL(splice, SyscallPassthrough6<SYSCALL_DEF(splice)>);
  REGISTER_SYSCALL_IMPL(tee, SyscallPassthrough4<SYSCALL_DEF(tee)>);
  REGISTER_SYSCALL_IMPL(move_pages, SyscallPassthrough6<SYSCALL_DEF(move_pages)>);
  REGISTER_SYSCALL_IMPL(timerfd_create, SyscallPassthrough2<SYSCALL_DEF(timerfd_create)>);
  REGISTER_SYSCALL_IMPL(accept4, SyscallPassthrough4<SYSCALL_DEF(accept4)>);
  REGISTER_SYSCALL_IMPL(eventfd2, SyscallPassthrough2<SYSCALL_DEF(eventfd2)>);
  REGISTER_SYSCALL_IMPL(epoll_create1, SyscallPassthrough1<SYSCALL_DEF(epoll_create1)>);
  REGISTER_SYSCALL_IMPL(inotify_init1, SyscallPassthrough1<SYSCALL_DEF(inotify_init1)>);
  REGISTER_SYSCALL_IMPL(fanotify_init, SyscallPassthrough2<SYSCALL_DEF(fanotify_init)>);
  REGISTER_SYSCALL_IMPL(fanotify_mark, SyscallPassthrough5<SYSCALL_DEF(fanotify_mark)>);
  REGISTER_SYSCALL_IMPL(prlimit_64, SyscallPassthrough4<SYSCALL_DEF(prlimit_64)>);
  REGISTER_SYSCALL_IMPL(name_to_handle_at, SyscallPassthrough5<SYSCALL_DEF(name_to_handle_at)>);
  REGISTER_SYSCALL_IMPL(open_by_handle_at, SyscallPassthrough3<SYSCALL_DEF(open_by_handle_at)>);
  REGISTER_SYSCALL_IMPL(syncfs, SyscallPassthrough1<SYSCALL_DEF(syncfs)>);
  REGISTER_SYSCALL_IMPL(setns, SyscallPassthrough2<SYSCALL_DEF(setns)>);
  REGISTER_SYSCALL_IMPL(getcpu, SyscallPassthrough3<SYSCALL_DEF(getcpu)>);
  REGISTER_SYSCALL_IMPL(kcmp, SyscallPassthrough5<SYSCALL_DEF(kcmp)>);
  REGISTER_SYSCALL_IMPL(sched_setattr, WrappedSchedSetattr);
  REGISTER_SYSCALL_IMPL(sched_getattr, SyscallPassthrough4<SYSCALL_DEF(sched_getattr)>);
  REGISTER_SYSCALL_IMPL(getrandom, SyscallPassthrough3<SYSCALL_DEF(getrandom)>);
  REGISTER_SYSCALL_IMPL(memfd_create, SyscallPassthrough2<SYSCALL_DEF(memfd_create)>);
  REGISTER_SYSCALL_IMPL(membarrier, SyscallPassthrough2<SYSCALL_DEF(membarrier)>);
  REGISTER_SYSCALL_IMPL(mlock2, SyscallPassthrough3<SYSCALL_DEF(mlock2)>);
  REGISTER_SYSCALL_IMPL(copy_file_range, SyscallPassthrough6<SYSCALL_DEF(copy_file_range)>);
  // Memory protection keys must not pass through to the host. The host kernel
  // (POWER) can hand out a real pkey, which makes the guest believe x86 PKU is
  // usable and start executing RDPKRU/WRPKRU — instructions the JIT does not
  // implement (Chromium's zygote dies this way). Report "no keys available"
  // so guests take their no-PKU fallback paths.
  REGISTER_SYSCALL_IMPL(pkey_mprotect,
                        [](FEXCore::Core::CpuStateFrame* Frame, void* addr, size_t len, int prot, int pkey) -> uint64_t {
                          // pkey == -1 is defined to behave exactly like mprotect(2); it also must
                          // go through GuestMprotect so SMC tracking sees the permission change.
                          if (pkey == -1) {
                            return FEX::HLE::_SyscallHandler->GuestMprotect(Frame->Thread, addr, len, prot);
                          }
                          return -EINVAL;
                        });
  REGISTER_SYSCALL_IMPL(pkey_alloc, [](FEXCore::Core::CpuStateFrame* Frame, unsigned int flags, unsigned int access_rights) -> uint64_t {
    // flags is reserved and access_rights only has two defined bits.
    if (flags != 0 || (access_rights & ~3U) != 0) {
      return -EINVAL;
    }
    return -ENOSPC;
  });
  REGISTER_SYSCALL_IMPL(pkey_free, [](FEXCore::Core::CpuStateFrame* Frame, int pkey) -> uint64_t { return -EINVAL; });
  // io_uring can't be emulated as it can pass `epoll_event` objects around.
  // These are 12-byte packed structs on x86/x86-64, but on other architectures are 16-byte.
  // This means the `data` member is at offset 4 on x86, but offset 8 on other architectures, corrupting the data.
  // The queue data is entirely user-controlled, so we can't rewrite data in any sane fashion.
  // This is visible with `node.js` as a hang.
  REGISTER_SYSCALL_IMPL(io_uring_setup, UnimplementedSyscallSafe);
  REGISTER_SYSCALL_IMPL(io_uring_enter, UnimplementedSyscallSafe);
  REGISTER_SYSCALL_IMPL(io_uring_register, UnimplementedSyscallSafe);
  REGISTER_SYSCALL_IMPL(open_tree, SyscallPassthrough3<SYSCALL_DEF(open_tree)>);
  REGISTER_SYSCALL_IMPL(move_mount, SyscallPassthrough5<SYSCALL_DEF(move_mount)>);
  REGISTER_SYSCALL_IMPL(fsopen, SyscallPassthrough3<SYSCALL_DEF(fsopen)>);
  REGISTER_SYSCALL_IMPL(fsconfig, SyscallPassthrough5<SYSCALL_DEF(fsconfig)>);
  REGISTER_SYSCALL_IMPL(fsmount, SyscallPassthrough3<SYSCALL_DEF(fsmount)>);
  REGISTER_SYSCALL_IMPL(fspick, SyscallPassthrough3<SYSCALL_DEF(fspick)>);
  REGISTER_SYSCALL_IMPL(pidfd_open, SyscallPassthrough2<SYSCALL_DEF(pidfd_open)>);
  REGISTER_SYSCALL_IMPL(pidfd_getfd, SyscallPassthrough3<SYSCALL_DEF(pidfd_getfd)>);
  REGISTER_SYSCALL_IMPL(mount_setattr, SyscallPassthrough5<SYSCALL_DEF(mount_setattr)>);
  REGISTER_SYSCALL_IMPL(quotactl_fd, SyscallPassthrough4<SYSCALL_DEF(quotactl_fd)>);
  REGISTER_SYSCALL_IMPL(landlock_create_ruleset, SyscallPassthrough3<SYSCALL_DEF(landlock_create_ruleset)>);
  REGISTER_SYSCALL_IMPL(landlock_add_rule, SyscallPassthrough4<SYSCALL_DEF(landlock_add_rule)>);
  REGISTER_SYSCALL_IMPL(landlock_restrict_self, SyscallPassthrough2<SYSCALL_DEF(landlock_restrict_self)>);
#ifdef ARCHITECTURE_ppc64le
  REGISTER_SYSCALL_IMPL(memfd_secret, UnimplementedSyscallSafe);
#else
  REGISTER_SYSCALL_IMPL(memfd_secret, SyscallPassthrough1<SYSCALL_DEF(memfd_secret)>);
#endif
  REGISTER_SYSCALL_IMPL(process_mrelease, SyscallPassthrough2<SYSCALL_DEF(process_mrelease)>);
  if (Handler->IsHostKernelVersionAtLeast(5, 16, 0)) {
    REGISTER_SYSCALL_IMPL(futex_waitv, SyscallPassthrough5<SYSCALL_DEF(futex_waitv)>);
  } else {
    REGISTER_SYSCALL_IMPL(futex_waitv, UnimplementedSyscallSafe);
  }
  if (Handler->IsHostKernelVersionAtLeast(5, 17, 0)) {
    REGISTER_SYSCALL_IMPL(set_mempolicy_home_node, SyscallPassthrough4<SYSCALL_DEF(set_mempolicy_home_node)>);
  } else {
    REGISTER_SYSCALL_IMPL(set_mempolicy_home_node, UnimplementedSyscallSafe);
  }

  if (Handler->IsHostKernelVersionAtLeast(6, 8, 0)) {
    REGISTER_SYSCALL_IMPL(futex_wake, SyscallPassthrough4<SYSCALL_DEF(futex_wake)>);
    REGISTER_SYSCALL_IMPL(futex_wait, SyscallPassthrough6<SYSCALL_DEF(futex_wait)>);
    REGISTER_SYSCALL_IMPL(futex_requeue, SyscallPassthrough4<SYSCALL_DEF(futex_requeue)>);
    REGISTER_SYSCALL_IMPL(statmount, SyscallPassthrough4<SYSCALL_DEF(statmount)>);
    REGISTER_SYSCALL_IMPL(listmount, SyscallPassthrough4<SYSCALL_DEF(listmount)>);
    REGISTER_SYSCALL_IMPL(lsm_get_self_attr, SyscallPassthrough4<SYSCALL_DEF(lsm_get_self_attr)>);
    REGISTER_SYSCALL_IMPL(lsm_set_self_attr, SyscallPassthrough4<SYSCALL_DEF(lsm_set_self_attr)>);
    REGISTER_SYSCALL_IMPL(lsm_list_modules, SyscallPassthrough3<SYSCALL_DEF(lsm_list_modules)>);
  } else {
    REGISTER_SYSCALL_IMPL(futex_wake, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(futex_wait, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(futex_requeue, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(statmount, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(listmount, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_get_self_attr, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_set_self_attr, UnimplementedSyscallSafe);
    REGISTER_SYSCALL_IMPL(lsm_list_modules, UnimplementedSyscallSafe);
  }
  if (Handler->IsHostKernelVersionAtLeast(6, 10, 0)) {
    REGISTER_SYSCALL_IMPL(mseal, SyscallPassthrough3<SYSCALL_DEF(mseal)>);
  } else {
    REGISTER_SYSCALL_IMPL(mseal, UnimplementedSyscallSafe);
  }
}

namespace x64 {
  void RegisterPassthrough(FEX::HLE::SyscallHandler* Handler) {
    using namespace FEXCore::IR;
    RegisterCommon(Handler);
    REGISTER_SYSCALL_IMPL_X64(ftruncate, SyscallPassthrough2<SYSCALL_DEF(ftruncate)>);
#ifdef ARCHITECTURE_ppc64le
    // PowerPC uses different ioctl encoding than x86: 3 dir bits at [29:31]
    // (NONE=1/READ=2/WRITE=4/RW=6) vs x86's 2 dir bits at [30:31]
    // (NONE=0/WRITE=1/READ=2/RW=3), and a 13-bit size field instead of 14.
    // A blanket encoding remap risks breaking working ioctls whose values
    // happen to match between archs; we narrow the fix to DRM type ('d')
    // ioctls which the rootfs DRM stack issues during GL initialization
    // (amdgpu_query_info returns EINVAL without this -- see
    // project_grimrock_amdgpu_ioctl.md).
    //
    // PPC-FIO* family (commit 828352361) is a separate quirk handled first.
    static constexpr auto RemapIoctlForPPC = [](uint32_t cmd) -> uint32_t {
      switch (cmd) {
      // FIO* family (file ioctls).
      case 0x5421u: return FIONBIO;
      case 0x541Bu: return FIONREAD;  // also TIOCINQ on x86 (== FIONREAD)
      case 0x5450u: return FIONCLEX;
      case 0x5451u: return FIOCLEX;
      case 0x5452u: return FIOASYNC;

      // TTY / pty / terminal-control / job-control. On x86 these are
      // legacy hard-coded 0x54xx values; on PPC asm/ioctls.h overrides
      // them with _IOR/_IOW-encoded numbers via the 3-bit-direction PPC
      // convention. The right-hand constants resolve at compile-time to
      // PPC values because <sys/ioctl.h> pulls in asm/ioctls.h on this
      // host. Fixes the gvisor socket_unix_*_test TIOCOUTQ failures and
      // any guest x86 binary that calls TTY ioctls on sockets/files.
      // NOTE: this run was previously off by one — it began at 0x5400, which is
      // not a defined x86 ioctl, so every entry through 0x540F named the wrong
      // command. The critical case was 0x5401: x86's TCGETS was being
      // translated to the host's TCSETS, turning "read the terminal settings"
      // into "WRITE the terminal settings" from whatever the caller's buffer
      // happened to hold. That silently reconfigured the user's terminal on any
      // interactive program — observed as all output turning UPPERCASE (a
      // garbage c_oflag with PPC's OLCUC bit set) and apt's progress redraw
      // breaking (ONLCR cleared), persisting after exit because the tty really
      // had been reprogrammed. Piped output was unaffected, which is why every
      // automated test missed it: they all redirect.
      case 0x5401u: return TCGETS;
      case 0x5402u: return TCSETS;
      case 0x5403u: return TCSETSW;
      case 0x5404u: return TCSETSF;
      case 0x5405u: return TCGETA;
      case 0x5406u: return TCSETA;
      case 0x5407u: return TCSETAW;
      case 0x5408u: return TCSETAF;
      case 0x5409u: return TCSBRK;
      case 0x540Au: return TCXONC;
      case 0x540Bu: return TCFLSH;
      case 0x540Cu: return TIOCEXCL;
      case 0x540Du: return TIOCNXCL;
      case 0x540Eu: return TIOCSCTTY;
      case 0x540Fu: return TIOCGPGRP;
      case 0x5410u: return TIOCSPGRP;
      case 0x5411u: return TIOCOUTQ;
      case 0x5412u: return TIOCSTI;
      case 0x5413u: return TIOCGWINSZ;
      case 0x5414u: return TIOCSWINSZ;
      case 0x5415u: return TIOCMGET;
      case 0x5416u: return TIOCMBIS;
      case 0x5417u: return TIOCMBIC;
      case 0x5418u: return TIOCMSET;
      case 0x5419u: return TIOCGSOFTCAR;
      case 0x541Au: return TIOCSSOFTCAR;
      case 0x541Cu: return TIOCLINUX;
      case 0x541Du: return TIOCCONS;
      case 0x541Eu: return TIOCGSERIAL;
      case 0x541Fu: return TIOCSSERIAL;
      case 0x5420u: return TIOCPKT;
      case 0x5422u: return TIOCNOTTY;
      case 0x5423u: return TIOCSETD;
      case 0x5424u: return TIOCGETD;
      case 0x5425u: return TCSBRKP;
      case 0x5429u: return TIOCGSID;
      case 0x5430u: return TIOCGPTN;
      case 0x5431u: return TIOCSPTLCK;
      case 0x5432u: return TIOCGDEV;
      case 0x5437u: return TIOCSIG;
      case 0x5438u: return TIOCVHANGUP;

      default: break;
      }

      // DRM type 'd' (0x64), udmabuf type 'u' (0x75) and ntsync type 'N'
      // (0x4E) ioctls rely on _IOC encoding; translate their direction bits
      // from x86's 2-bit layout to PPC's 3-bit layout.  Anything else passes
      // through.  ntsync payloads are fixed-width __u32/__u64 structs, so the
      // command number is the only thing that needs translating.
      const uint32_t type = (cmd >> 8) & 0xFFu;
      if (type != 0x64u && type != 0x75u && type != 0x4Eu) {
        return cmd;
      }

      const uint32_t nr      = cmd & 0xFFu;
      const uint32_t size    = (cmd >> 16) & 0x3FFFu;
      const uint32_t dir_x86 = (cmd >> 30) & 0x3u;

      static constexpr uint32_t DirX86ToPPC[4] = {1u, 4u, 2u, 6u};
      const uint32_t dir_ppc = DirX86ToPPC[dir_x86];
      const uint32_t size_ppc = size & 0x1FFFu;
      return (dir_ppc << 29) | (size_ppc << 16) | (type << 8) | nr;
    };

    REGISTER_SYSCALL_IMPL_X64(ioctl, [](FEXCore::Core::CpuStateFrame* Frame, int fd, uint32_t cmd, uint64_t arg) -> uint64_t {
      // termios needs its payload marshalled, not just its command number
      // remapped. Guest x86 struct is 36 bytes; the buffer we hand `::ioctl`
      // on PowerPC must be glibc's own 60-byte `struct termios`, because the
      // glibc ioctl wrapper writes 60 bytes into it regardless of the caller's
      // declared size — the "*** stack smashing detected ***" on stty/apt.
      // Field order and every flag-bit value differ as well; see
      // PPC64LE/TermiosTranslation.h.
      switch (cmd) {
      case 0x5401u: { // x86 TCGETS
        struct termios HostT {};
        uint64_t Result = ::ioctl(fd, TCGETS, &HostT);
        if (Result == 0) {
          FEX::HLE::PPC64::HostToGuest(HostT, *reinterpret_cast<FEX::HLE::PPC64::GuestTermios*>(arg));
        }
        SYSCALL_ERRNO();
      }
      case 0x5402u:   // x86 TCSETS
      case 0x5403u:   // x86 TCSETSW
      case 0x5404u: { // x86 TCSETSF
        // Array literal cannot live inline here — the C preprocessor's
        // comma-splitting sees {a, b, c} as extra macro arguments to
        // REGISTER_SYSCALL_IMPL_X64. Pick via switch instead.
        uint32_t host_cmd;
        switch (cmd) {
          case 0x5402u: host_cmd = TCSETS;  break;
          case 0x5403u: host_cmd = TCSETSW; break;
          default:      host_cmd = TCSETSF; break;
        }
        struct termios HostT {};
        FEX::HLE::PPC64::GuestToHost(*reinterpret_cast<const FEX::HLE::PPC64::GuestTermios*>(arg), HostT);
        uint64_t Result = ::ioctl(fd, host_cmd, &HostT);
        SYSCALL_ERRNO();
      }
      default: break;
      }

      cmd = RemapIoctlForPPC(cmd);

      // ntsync WAIT_ANY/WAIT_ALL (type 'N' = 0x4E, nr 0x82/0x83) are
      // signal-wakeable sleeps that wine parks worker threads in
      // indefinitely — the same shape futex(2) grew an entry check for, on a
      // path that never had one. A thread could park here holding the very
      // signal whose handler would have woken it, which is the black hole
      // described at the futex handler above; that comment lists the known
      // uncovered sleeps (epoll_wait, ppoll, nanosleep, futex_waitv) and
      // ntsync is not even on it, because ntsync arrived later.
      //
      // Observed as a DETERMINISTIC menu wedge in FreeInfantry under Proton:
      // 21 threads parked as 14 futex / 5 ntsync / 2 nanosleep, one condvar
      // polled 63 times in 71s and never signalled, and no runnable thread.
      // PROTON_NO_NTSYNC=1 avoids it entirely, which is what localises it
      // here rather than to the futex side.
      //
      // Retry on a FEX-internal EINTR mirrors the futex path, and is simpler
      // here: ntsync's deadline is ABSOLUTE on CLOCK_MONOTONIC, so re-issuing
      // cannot over-wait the way re-issuing a relative FUTEX_WAIT does.
      // Slicing (the futex rescue tier) is NOT done: the deadline lives
      // inside the guest's ntsync_wait_args, so shortening it means writing
      // guest memory, and the entry check is what closes the proven case.
      const uint32_t IoctlType = (cmd >> 8) & 0xFFu;
      const uint32_t IoctlNr = cmd & 0xFFu;
      const bool NtsyncWait = IoctlType == 0x4Eu && (IoctlNr == 0x82u || IoctlNr == 0x83u);
      if (NtsyncWait && HasGuestDeliverableSignal(Frame)) {
        return static_cast<uint64_t>(-EINTR);
      }

      uint64_t Result = ::ioctl(fd, cmd, arg);
      if (NtsyncWait) {
        while (Result == static_cast<uint64_t>(-1) && errno == EINTR && !HasGuestDeliverableSignal(Frame)) {
          Result = ::ioctl(fd, cmd, arg);
        }
      }

      // Diagnostic: ntsync ioctl traffic, for chasing wedges where waiters
      // park forever and nothing ever signals them. The futex trace cannot
      // see this path at all — ntsync waits are ioctls, not futexes — which
      // left a whole synchronisation backend uninstrumented while a
      // FreeInfantry menu wedge was being blamed on deferred signals. What
      // this answers that nothing else does: whether the SIGNALLING ioctls
      // (event set, sem release, mutex unlock) are succeeding. A setter
      // quietly failing with ENOTTY/EINVAL — a mistranslated command number,
      // say — produces exactly the observed symptom, waiters waiting on a
      // wake that was never actually issued.
      //
      // Same two-stage arming and own-file discipline as FEX_FUTEX_TRACE:
      // FEX_NTSYNC_TRACE=1 then `touch /tmp/nts_on`, logging to
      // /tmp/nts.<pid>.log because guests replace fd 2 early and ate the
      // futex trace from exactly the process under investigation.
      if (IoctlType == 0x4Eu) {
        static const bool trace_ntsync = (getenv("FEX_NTSYNC_TRACE") != nullptr);
        if (trace_ntsync && access("/tmp/nts_on", F_OK) == 0) {
          static int nts_fd = -1;
          if (nts_fd == -1) {
            char path[64];
            snprintf(path, sizeof(path), "/tmp/nts.%d.log", static_cast<int>(::getpid()));
            nts_fd = ::open(path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0644);
            if (nts_fd == -1) {
              nts_fd = -2;
            }
          }
          if (nts_fd >= 0) {
            static thread_local pid_t nts_tid = 0;
            if (nts_tid == 0) {
              nts_tid = static_cast<pid_t>(::syscall(SYS_gettid));
            }
            struct timespec ts {};
            clock_gettime(CLOCK_MONOTONIC, &ts);
            const int64_t sr = static_cast<int64_t>(Result);
            char line[192];
            const int n = snprintf(line, sizeof(line), "[NTS %ld.%03ld] t=%d fd=%d nr=0x%x cmd=0x%x arg=0x%lx r=%ld errno=%d\n",
                                   static_cast<long>(ts.tv_sec), static_cast<long>(ts.tv_nsec / 1000000), static_cast<int>(nts_tid), fd,
                                   IoctlNr, cmd, arg, static_cast<long>(sr), sr == -1 ? errno : 0);
            if (n > 0) {
              [[maybe_unused]] auto _ = ::write(nts_fd, line, static_cast<size_t>(n));
            }
          }
        }
      }
      SYSCALL_ERRNO();
    });
#else
    REGISTER_SYSCALL_IMPL_X64(ioctl, SyscallPassthrough3<SYSCALL_DEF(ioctl)>);
#endif
    REGISTER_SYSCALL_IMPL_X64(pread_64, SyscallPassthrough4<SYSCALL_DEF(pread_64)>);
    REGISTER_SYSCALL_IMPL_X64(pwrite_64, SyscallPassthrough4<SYSCALL_DEF(pwrite_64)>);
    REGISTER_SYSCALL_IMPL_X64(readv, SyscallPassthrough3<SYSCALL_DEF(readv)>);
    REGISTER_SYSCALL_IMPL_X64(writev, SyscallPassthrough3<SYSCALL_DEF(writev)>);
    REGISTER_SYSCALL_IMPL_X64(dup, SyscallPassthrough1<SYSCALL_DEF(dup)>);
    REGISTER_SYSCALL_IMPL_X64(nanosleep, SyscallPassthrough2<SYSCALL_DEF(nanosleep)>);
    REGISTER_SYSCALL_IMPL_X64(getitimer, SyscallPassthrough2<SYSCALL_DEF(getitimer)>);
    REGISTER_SYSCALL_IMPL_X64(setitimer, SyscallPassthrough3<SYSCALL_DEF(setitimer)>);
    REGISTER_SYSCALL_IMPL_X64(sendfile, SyscallPassthrough4<SYSCALL_DEF(sendfile)>);
    REGISTER_SYSCALL_IMPL_X64(accept, SyscallPassthrough3<SYSCALL_DEF(accept)>);
    REGISTER_SYSCALL_IMPL_X64(sendmsg, SyscallPassthrough3<SYSCALL_DEF(sendmsg)>);
    REGISTER_SYSCALL_IMPL_X64(recvmsg, SyscallPassthrough3<SYSCALL_DEF(recvmsg)>);
    // Not passthrough: powerpc hosts use legacy SOL_SOCKET option numbers for
    // six options; the guest's x86 numbering must be translated (see
    // TranslateGuestSockOptName). Everything else is unchanged passthrough.
    REGISTER_SYSCALL_IMPL_X64(setsockopt,
                              [](FEXCore::Core::CpuStateFrame* Frame, int sockfd, int level, int optname, const void* optval,
                                 socklen_t optlen) -> uint64_t {
                                uint64_t Result = ::syscall(SYSCALL_DEF(setsockopt), sockfd, level,
                                                            FEX::HLE::TranslateGuestSockOptName(level, optname), optval, optlen);
                                SYSCALL_ERRNO();
                              });
    REGISTER_SYSCALL_IMPL_X64(getsockopt,
                              [](FEXCore::Core::CpuStateFrame* Frame, int sockfd, int level, int optname, void* optval,
                                 socklen_t* optlen) -> uint64_t {
                                uint64_t Result = ::syscall(SYSCALL_DEF(getsockopt), sockfd, level,
                                                            FEX::HLE::TranslateGuestSockOptName(level, optname), optval, optlen);
                                SYSCALL_ERRNO();
                              });
    REGISTER_SYSCALL_IMPL_X64(wait4, SyscallPassthrough4<SYSCALL_DEF(wait4)>);
#ifdef ARCHITECTURE_ppc64le
    REGISTER_SYSCALL_IMPL_X64(semop, UnimplementedSyscallSafe);
#else
    REGISTER_SYSCALL_IMPL_X64(semop, SyscallPassthrough3<SYSCALL_DEF(semop)>);
#endif
    REGISTER_SYSCALL_IMPL_X64(gettimeofday, VDSOGetTimeOfDay);
    REGISTER_SYSCALL_IMPL_X64(getrlimit, SyscallPassthrough2<SYSCALL_DEF(getrlimit)>);
    REGISTER_SYSCALL_IMPL_X64(getrusage, SyscallPassthrough2<SYSCALL_DEF(getrusage)>);
    REGISTER_SYSCALL_IMPL_X64(sysinfo, SyscallPassthrough1<SYSCALL_DEF(sysinfo)>);
    REGISTER_SYSCALL_IMPL_X64(times, SyscallPassthrough1<SYSCALL_DEF(times)>);
    REGISTER_SYSCALL_IMPL_X64(rt_sigqueueinfo, SyscallPassthrough3<SYSCALL_DEF(rt_sigqueueinfo)>);
    REGISTER_SYSCALL_IMPL_X64(fstatfs, SyscallPassthrough2<SYSCALL_DEF(fstatfs)>);
    REGISTER_SYSCALL_IMPL_X64(sched_rr_get_interval, SyscallPassthrough2<SYSCALL_DEF(sched_rr_get_interval)>);
    REGISTER_SYSCALL_IMPL_X64(mlockall, SyscallPassthrough1<SYSCALL_DEF(mlockall)>);
    REGISTER_SYSCALL_IMPL_X64(munlockall, SyscallPassthrough0<SYSCALL_DEF(munlockall)>);
    REGISTER_SYSCALL_IMPL_X64(adjtimex, SyscallPassthrough1<SYSCALL_DEF(adjtimex)>);
    REGISTER_SYSCALL_IMPL_X64(setrlimit, SyscallPassthrough2<SYSCALL_DEF(setrlimit)>);
    REGISTER_SYSCALL_IMPL_X64(settimeofday, SyscallPassthrough2<SYSCALL_DEF(settimeofday)>);
    REGISTER_SYSCALL_IMPL_X64(readahead, SyscallPassthrough3<SYSCALL_DEF(readahead)>);
    REGISTER_SYSCALL_IMPL_X64(futex, ObservedFutexSyscall);
    REGISTER_SYSCALL_IMPL_X64(io_getevents, SyscallPassthrough5<SYSCALL_DEF(io_getevents)>);
    REGISTER_SYSCALL_IMPL_X64(semtimedop, SyscallPassthrough4<SYSCALL_DEF(semtimedop)>);
    REGISTER_SYSCALL_IMPL_X64(timer_create, SyscallPassthrough3<SYSCALL_DEF(timer_create)>);
    REGISTER_SYSCALL_IMPL_X64(timer_settime, SyscallPassthrough4<SYSCALL_DEF(timer_settime)>);
    REGISTER_SYSCALL_IMPL_X64(timer_gettime, SyscallPassthrough2<SYSCALL_DEF(timer_gettime)>);
    REGISTER_SYSCALL_IMPL_X64(clock_settime, SyscallPassthrough2<SYSCALL_DEF(clock_settime)>);
    REGISTER_SYSCALL_IMPL_X64(clock_gettime, VDSOClockGetTime);
    REGISTER_SYSCALL_IMPL_X64(clock_getres, VDSOClockGetRes);
    REGISTER_SYSCALL_IMPL_X64(clock_nanosleep, SyscallPassthrough4<SYSCALL_DEF(clock_nanosleep)>);
    REGISTER_SYSCALL_IMPL_X64(mq_open, SyscallPassthrough4<SYSCALL_DEF(mq_open)>);
    REGISTER_SYSCALL_IMPL_X64(mq_timedsend, SyscallPassthrough5<SYSCALL_DEF(mq_timedsend)>);
    REGISTER_SYSCALL_IMPL_X64(mq_timedreceive, SyscallPassthrough5<SYSCALL_DEF(mq_timedreceive)>);
    REGISTER_SYSCALL_IMPL_X64(mq_notify, SyscallPassthrough2<SYSCALL_DEF(mq_notify)>);
    REGISTER_SYSCALL_IMPL_X64(mq_getsetattr, SyscallPassthrough3<SYSCALL_DEF(mq_getsetattr)>);
    REGISTER_SYSCALL_IMPL_X64(waitid, SyscallPassthrough5<SYSCALL_DEF(waitid)>);
    REGISTER_SYSCALL_IMPL_X64(pselect6, SyscallPassthrough6<SYSCALL_DEF(pselect6)>);
    REGISTER_SYSCALL_IMPL_X64(ppoll, SyscallPassthrough5<SYSCALL_DEF(ppoll)>);
    REGISTER_SYSCALL_IMPL_X64(set_robust_list, SyscallPassthrough2<SYSCALL_DEF(set_robust_list)>);
    REGISTER_SYSCALL_IMPL_X64(get_robust_list, SyscallPassthrough3<SYSCALL_DEF(get_robust_list)>);
    REGISTER_SYSCALL_IMPL_X64(sync_file_range, SyscallPassthrough4<SYSCALL_DEF(sync_file_range)>);
    REGISTER_SYSCALL_IMPL_X64(vmsplice, SyscallPassthrough4<SYSCALL_DEF(vmsplice)>);
    // utimensat is NOT a passthrough: it takes a path and needs RootFS translation.
    // Handled by FileManager::Utimensat, registered in Syscalls/FS.cpp.
    REGISTER_SYSCALL_IMPL_X64(fallocate, SyscallPassthrough4<SYSCALL_DEF(fallocate)>);
    REGISTER_SYSCALL_IMPL_X64(timerfd_settime, SyscallPassthrough4<SYSCALL_DEF(timerfd_settime)>);
    REGISTER_SYSCALL_IMPL_X64(timerfd_gettime, SyscallPassthrough2<SYSCALL_DEF(timerfd_gettime)>);
    REGISTER_SYSCALL_IMPL_X64(preadv, SyscallPassthrough5<SYSCALL_DEF(preadv)>);
    REGISTER_SYSCALL_IMPL_X64(pwritev, SyscallPassthrough5<SYSCALL_DEF(pwritev)>);
    REGISTER_SYSCALL_IMPL_X64(rt_tgsigqueueinfo, SyscallPassthrough4<SYSCALL_DEF(rt_tgsigqueueinfo)>);
    REGISTER_SYSCALL_IMPL_X64(recvmmsg, SyscallPassthrough5<SYSCALL_DEF(recvmmsg)>);
    REGISTER_SYSCALL_IMPL_X64(clock_adjtime, SyscallPassthrough2<SYSCALL_DEF(clock_adjtime)>);
    REGISTER_SYSCALL_IMPL_X64(sendmmsg, SyscallPassthrough4<SYSCALL_DEF(sendmmsg)>);
    REGISTER_SYSCALL_IMPL_X64(process_vm_readv, SyscallPassthrough6<SYSCALL_DEF(process_vm_readv)>);
    REGISTER_SYSCALL_IMPL_X64(process_vm_writev, SyscallPassthrough6<SYSCALL_DEF(process_vm_writev)>);
    REGISTER_SYSCALL_IMPL_X64(preadv2, SyscallPassthrough6<SYSCALL_DEF(preadv2)>);
    REGISTER_SYSCALL_IMPL_X64(pwritev2, SyscallPassthrough6<SYSCALL_DEF(pwritev2)>);
    REGISTER_SYSCALL_IMPL_X64(io_pgetevents, SyscallPassthrough6<SYSCALL_DEF(io_pgetevents)>);
    REGISTER_SYSCALL_IMPL_X64(pidfd_send_signal, SyscallPassthrough4<SYSCALL_DEF(pidfd_send_signal)>);
    REGISTER_SYSCALL_IMPL_X64(process_madvise, SyscallPassthrough5<SYSCALL_DEF(process_madvise)>);
    REGISTER_SYSCALL_IMPL_X64(fadvise64, SyscallPassthrough4<SYSCALL_DEF(fadvise64)>);
    if (Handler->IsHostKernelVersionAtLeast(6, 5, 0)) {
      REGISTER_SYSCALL_IMPL_X64(cachestat, SyscallPassthrough4<SYSCALL_DEF(cachestat)>);
    } else {
      REGISTER_SYSCALL_IMPL_X64(cachestat, UnimplementedSyscallSafe);
    }
    if (Handler->IsHostKernelVersionAtLeast(6, 6, 0)) {
    } else {
      REGISTER_SYSCALL_IMPL_X64(fchmodat2, UnimplementedSyscallSafe);
    }
  }
} // namespace x64

namespace x32 {
  void RegisterPassthrough(FEX::HLE::SyscallHandler* Handler) {
    using namespace FEXCore::IR;
    RegisterCommon(Handler);
    REGISTER_SYSCALL_IMPL_X32(getuid32, SyscallPassthrough0<SYSCALL_DEF(getuid)>);
    REGISTER_SYSCALL_IMPL_X32(getgid32, SyscallPassthrough0<SYSCALL_DEF(getgid)>);
    REGISTER_SYSCALL_IMPL_X32(geteuid32, SyscallPassthrough0<SYSCALL_DEF(geteuid)>);
    REGISTER_SYSCALL_IMPL_X32(getegid32, SyscallPassthrough0<SYSCALL_DEF(getegid)>);
    REGISTER_SYSCALL_IMPL_X32(setreuid32, SyscallPassthrough2<SYSCALL_DEF(setreuid)>);
    REGISTER_SYSCALL_IMPL_X32(setregid32, SyscallPassthrough2<SYSCALL_DEF(setregid)>);
    REGISTER_SYSCALL_IMPL_X32(getgroups32, SyscallPassthrough2<SYSCALL_DEF(getgroups)>);
    REGISTER_SYSCALL_IMPL_X32(setgroups32, SyscallPassthrough2<SYSCALL_DEF(setgroups)>);
    REGISTER_SYSCALL_IMPL_X32(fchown32, SyscallPassthrough3<SYSCALL_DEF(fchown)>);
    REGISTER_SYSCALL_IMPL_X32(setresuid32, SyscallPassthrough3<SYSCALL_DEF(setresuid)>);
    REGISTER_SYSCALL_IMPL_X32(getresuid32, SyscallPassthrough3<SYSCALL_DEF(getresuid)>);
    REGISTER_SYSCALL_IMPL_X32(setresgid32, SyscallPassthrough3<SYSCALL_DEF(setresgid)>);
    REGISTER_SYSCALL_IMPL_X32(getresgid32, SyscallPassthrough3<SYSCALL_DEF(getresgid)>);
    REGISTER_SYSCALL_IMPL_X32(setuid32, SyscallPassthrough1<SYSCALL_DEF(setuid)>);
    REGISTER_SYSCALL_IMPL_X32(setgid32, SyscallPassthrough1<SYSCALL_DEF(setgid)>);
    REGISTER_SYSCALL_IMPL_X32(setfsuid32, SyscallPassthrough1<SYSCALL_DEF(setfsuid)>);
    REGISTER_SYSCALL_IMPL_X32(setfsgid32, SyscallPassthrough1<SYSCALL_DEF(setfsgid)>);
    REGISTER_SYSCALL_IMPL_X32(sendfile64, SyscallPassthrough4<SYSCALL_DEF(sendfile)>);
    REGISTER_SYSCALL_IMPL_X32(clock_gettime64, VDSOClockGetTime);
    REGISTER_SYSCALL_IMPL_X32(clock_settime64, SyscallPassthrough2<SYSCALL_DEF(clock_settime)>);
    REGISTER_SYSCALL_IMPL_X32(clock_adjtime64, SyscallPassthrough2<SYSCALL_DEF(clock_adjtime)>);
    REGISTER_SYSCALL_IMPL_X32(clock_getres_time64, VDSOClockGetRes);
    REGISTER_SYSCALL_IMPL_X32(clock_nanosleep_time64, SyscallPassthrough4<SYSCALL_DEF(clock_nanosleep)>);
    REGISTER_SYSCALL_IMPL_X32(timer_gettime64, SyscallPassthrough2<SYSCALL_DEF(timer_gettime)>);
    REGISTER_SYSCALL_IMPL_X32(timer_settime64, SyscallPassthrough4<SYSCALL_DEF(timer_settime)>);
    REGISTER_SYSCALL_IMPL_X32(timerfd_gettime64, SyscallPassthrough2<SYSCALL_DEF(timerfd_gettime)>);
    REGISTER_SYSCALL_IMPL_X32(timerfd_settime64, SyscallPassthrough4<SYSCALL_DEF(timerfd_settime)>);
    REGISTER_SYSCALL_IMPL_X32(utimensat_time64, SyscallPassthrough4<SYSCALL_DEF(utimensat)>);
    REGISTER_SYSCALL_IMPL_X32(ppoll_time64, SyscallPassthrough5<SYSCALL_DEF(ppoll)>);
    REGISTER_SYSCALL_IMPL_X32(io_pgetevents_time64, SyscallPassthrough6<SYSCALL_DEF(io_pgetevents)>);
    REGISTER_SYSCALL_IMPL_X32(mq_timedsend_time64, SyscallPassthrough5<SYSCALL_DEF(mq_timedsend)>);
    REGISTER_SYSCALL_IMPL_X32(mq_timedreceive_time64, SyscallPassthrough5<SYSCALL_DEF(mq_timedreceive)>);
    REGISTER_SYSCALL_IMPL_X32(semtimedop_time64, SyscallPassthrough4<SYSCALL_DEF(semtimedop)>);
    REGISTER_SYSCALL_IMPL_X32(futex_time64, ObservedFutexSyscall);
    REGISTER_SYSCALL_IMPL_X32(sched_rr_get_interval_time64, SyscallPassthrough2<SYSCALL_DEF(sched_rr_get_interval)>);
  }
} // namespace x32
} // namespace FEX::HLE
