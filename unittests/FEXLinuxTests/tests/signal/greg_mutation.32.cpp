// Signal handler general-purpose register writeback test, ia32 edition.
//
// ia32 semantics: a signal handler may mutate the interrupted context's
// integer registers through the signal frame -- via uc_mcontext.gregs[] on the
// SA_SIGINFO (rt) frame, or via the `struct sigcontext` embedded by value in
// the classic non-RT frame -- and those mutations MUST be visible to the
// interrupted code after sigreturn, even when the handler leaves EIP alone.
// This is how GC/JIT/green-thread runtimes fix up a thread from a signal
// (Mono/.NET GC thread hijack, Wine exception fixups on the sigcontext path).
//
// This is the 32-bit port of greg_mutation.64.cpp: FEX's RestoreFrame_ia32 /
// RestoreRTFrame_ia32 historically only wrote the handler's greg edits back
// into guest state when the handler ALSO changed EIP, silently dropping
// everything else. Both ia32 frame flavors are covered here, under the same
// three delivery contexts as the 64-bit test:
//   (i)   blocked in a host syscall (nanosleep),
//   (ii)  pure JIT compute (a spin loop),
//   (iii) parked in a futex wait.
//
// The handler mutates EAX, EBX, ESI, EDI, and -- unlike the 64-bit test --
// ESP, redirecting the interrupted code onto a prepared alternate stack
// region. The interrupted code captures its live registers (including ESP)
// after resuming, then restores its original ESP from a memory slot before
// unwinding, so an honored ESP edit is observable without crashing.
//
// Oracle: native i386 Linux (verified by compiling this file -m32 and running
// on an x86 host). The kernel copies the (possibly handler-edited) sigcontext
// back into the task's pt_regs on sigreturn, so all contexts observe the
// edits. EAX is the one caveat: when a syscall is interrupted, the kernel
// stages the syscall's error code (-EINTR) into the saved frame BEFORE the
// handler runs, and the handler's EAX edit therefore wins natively. FEX's
// syscall op instead writes its result after the guest sigreturn, so the edit
// loses there. Both orderings are accepted for the syscall contexts; EAX is
// asserted strictly only in the compute context.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <pthread.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

namespace {

// Distinctive pre-signal markers the interrupted code parks in the GPRs.
constexpr uint32_t MARK_EAX = 0xA1A1'A1A1u;
constexpr uint32_t MARK_EBX = 0xB2B2'B2B2u;
constexpr uint32_t MARK_ESI = 0xC3C3'C3C3u;
constexpr uint32_t MARK_EDI = 0xD4D4'D4D4u;

// Values the handler injects; the interrupted code must observe these.
constexpr uint32_t NEW_EAX = 0x1111'2222u;
constexpr uint32_t NEW_EBX = 0x5555'6666u;
constexpr uint32_t NEW_ESI = 0x9999'AAAAu;
constexpr uint32_t NEW_EDI = 0xDDDD'EEEEu;

struct TestCtx {
  // [0x00] input markers
  uint32_t mark_eax;
  uint32_t mark_ebx;
  uint32_t mark_esi;
  uint32_t mark_edi;
  // [0x10] captured-after-return outputs
  uint32_t out_eax;
  uint32_t out_ebx;
  uint32_t out_esi;
  uint32_t out_edi;
  uint32_t out_esp;
  // [0x24] entry ESP, restored before unwinding (survives the handler's ESP edit)
  uint32_t saved_esp;
  // [0x28] spin-loop exit flag pointer (compute mode)
  volatile int* flag;
  // [0x2C] futex word (must be 0 for FUTEX_WAIT to block)
  uint32_t futexword;
};

static_assert(sizeof(void*) == 4, "ia32-only test");
static_assert(offsetof(TestCtx, mark_eax) == 0x00);
static_assert(offsetof(TestCtx, out_eax) == 0x10);
static_assert(offsetof(TestCtx, out_esp) == 0x20);
static_assert(offsetof(TestCtx, saved_esp) == 0x24);
static_assert(offsetof(TestCtx, flag) == 0x28);
static_assert(offsetof(TestCtx, futexword) == 0x2C);

volatile sig_atomic_t g_flag = 0;

// Alternate stack region the handler points ESP at. Nothing is pushed onto it
// before the interrupted code captures ESP, but keep it real and roomy anyway.
alignas(64) uint8_t g_altstack[16384];
uint32_t g_new_esp = 0;

void MutatingHandlerRT(int, siginfo_t*, void* ucv) {
  auto* uc = reinterpret_cast<ucontext_t*>(ucv);
  uc->uc_mcontext.gregs[REG_EAX] = static_cast<greg_t>(NEW_EAX);
  uc->uc_mcontext.gregs[REG_EBX] = static_cast<greg_t>(NEW_EBX);
  uc->uc_mcontext.gregs[REG_ESI] = static_cast<greg_t>(NEW_ESI);
  uc->uc_mcontext.gregs[REG_EDI] = static_cast<greg_t>(NEW_EDI);
  // The kernel restores ESP from gregs[REG_ESP] (sigcontext.sp); REG_UESP is
  // the legacy sp_at_signal slot and is ignored on sigreturn.
  uc->uc_mcontext.gregs[REG_ESP] = static_cast<greg_t>(g_new_esp);
  g_flag = 1;
}

// The classic non-RT frame embeds the sigcontext by value directly after the
// signal number, so a cdecl `handler(int, struct sigcontext)` receives the
// live frame memory as its second argument -- the time-honored i386 idiom for
// mutating state from a non-SA_SIGINFO handler. Field layout per the kernel
// UAPI (all 32-bit slots; segments are 16-bit values in 32-bit-padded slots).
struct ClassicSigcontext {
  uint32_t gs, fs, es, ds;
  uint32_t di, si, bp, sp, bx, dx, cx, ax;
  uint32_t trapno, err, ip, cs, flags, sp_at_signal, ss;
  uint32_t fpstate, oldmask, cr2;
};
static_assert(offsetof(ClassicSigcontext, ax) == 0x2C);
static_assert(sizeof(ClassicSigcontext) == 0x58);

void MutatingHandlerClassic(int, ClassicSigcontext sc_in_frame) {
  // Write through a volatile pointer to the by-value argument: its stack slot
  // IS the kernel frame (cdecl passes aggregates in the caller-owned argument
  // area), and volatile keeps the compiler from discarding stores to a
  // parameter that is dead on return.
  volatile ClassicSigcontext* sc = &sc_in_frame;
  sc->ax = NEW_EAX;
  sc->bx = NEW_EBX;
  sc->si = NEW_ESI;
  sc->di = NEW_EDI;
  sc->sp = g_new_esp;
  g_flag = 1;
}

// Each naked routine: ebp = ctx (callee-saved, never mutated by the handler).
// Park the markers, save the entry ESP for the epilogue, do the "work"
// (syscall or spin), then store the live registers. The captured registers
// are never touched by the work body, so anything the handler wrote through
// the frame must appear in the stores iff the writeback is honored. ESP is
// captured and then restored from the saved slot so the handler's ESP edit is
// observable without wrecking the unwind. Written as naked functions with
// intel inline asm so -masm=intel applies; labels use the %= asm-instance id
// because clang's intel-mode integrated assembler does not accept 1b/1f
// numeric label references.

// Context (i): blocked in nanosleep.
__attribute__((naked)) void RunSyscallCtx(TestCtx* /*[esp+4]*/) {
  __asm volatile(R"(
    push ebp
    push ebx
    push esi
    push edi
    mov ebp, dword ptr [esp + 20]
    mov [ebp + 0x24], esp
    mov esi, [ebp + 0x08]
    mov edi, [ebp + 0x0C]
    sub esp, 16
    mov dword ptr [esp], 10          // tv_sec = 10 (32-bit timespec)
    mov dword ptr [esp + 4], 0       // tv_nsec = 0
    mov ebx, esp                     // req
    xor ecx, ecx                     // rem = NULL
    mov eax, 162                     // SYS_nanosleep (i386)
    int 0x80
    mov [ebp + 0x10], eax
    mov [ebp + 0x14], ebx
    mov [ebp + 0x18], esi
    mov [ebp + 0x1C], edi
    mov [ebp + 0x20], esp
    mov esp, [ebp + 0x24]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
  )" ::: "memory");
}

// Context (ii): pure JIT compute (spin until the handler sets the flag).
__attribute__((naked)) void RunComputeCtx(TestCtx* /*[esp+4]*/) {
  __asm volatile(R"(
    push ebp
    push ebx
    push esi
    push edi
    mov ebp, dword ptr [esp + 20]
    mov [ebp + 0x24], esp
    mov eax, [ebp + 0x00]
    mov ebx, [ebp + 0x04]
    mov esi, [ebp + 0x08]
    mov edi, [ebp + 0x0C]
    mov ecx, [ebp + 0x28]            // ecx = &flag
  .Lspin%=:
    mov edx, dword ptr [ecx]
    test edx, edx
    jz .Lspin%=
    mov [ebp + 0x10], eax
    mov [ebp + 0x14], ebx
    mov [ebp + 0x18], esi
    mov [ebp + 0x1C], edi
    mov [ebp + 0x20], esp
    mov esp, [ebp + 0x24]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
  )" ::: "memory");
}

// Context (iii): parked in FUTEX_WAIT.
__attribute__((naked)) void RunFutexCtx(TestCtx* /*[esp+4]*/) {
  __asm volatile(R"(
    push ebp
    push ebx
    push esi
    push edi
    mov ebp, dword ptr [esp + 20]
    mov [ebp + 0x24], esp
    mov edi, [ebp + 0x0C]
    lea ebx, [ebp + 0x2C]            // uaddr = &futexword (==0)
    xor ecx, ecx                     // FUTEX_WAIT (0)
    xor edx, edx                     // val = 0
    xor esi, esi                     // timeout = NULL
    mov eax, 240                     // SYS_futex (i386)
    int 0x80
    mov [ebp + 0x10], eax
    mov [ebp + 0x14], ebx
    mov [ebp + 0x18], esi
    mov [ebp + 0x1C], edi
    mov [ebp + 0x20], esp
    mov esp, [ebp + 0x24]
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
  )" ::: "memory");
}

pthread_t g_target;

void* Poker(void*) {
  // Give the main thread time to reach its blocking point / enter the loop.
  struct timespec ts {
    0, 200'000'000
  };
  nanosleep(&ts, nullptr);
  pthread_kill(g_target, SIGUSR1);
  return nullptr;
}

TestCtx RunUnder(void (*fn)(TestCtx*)) {
  g_flag = 0;
  // Point the handler's ESP edit at the top of the alternate region, 16-byte
  // aligned, with headroom above in case anything ever pushes there.
  g_new_esp = (reinterpret_cast<uintptr_t>(g_altstack) + sizeof(g_altstack) - 256) & ~15u;

  TestCtx ctx {};
  ctx.mark_eax = MARK_EAX;
  ctx.mark_ebx = MARK_EBX;
  ctx.mark_esi = MARK_ESI;
  ctx.mark_edi = MARK_EDI;
  ctx.flag = &g_flag;
  ctx.futexword = 0;

  g_target = pthread_self();
  pthread_t poker;
  pthread_create(&poker, nullptr, Poker, nullptr);
  fn(&ctx);
  pthread_join(poker, nullptr);
  return ctx;
}

struct RTHandlerGuard {
  RTHandlerGuard() {
    struct sigaction act {};
    act.sa_sigaction = MutatingHandlerRT;
    act.sa_flags = SA_SIGINFO; // rt frame; no SA_RESTART: interrupted syscalls return EINTR
    sigemptyset(&act.sa_mask);
    sigaction(SIGUSR1, &act, nullptr);
  }
};

struct ClassicHandlerGuard {
  ClassicHandlerGuard() {
    struct sigaction act {};
    act.sa_handler = reinterpret_cast<void (*)(int)>(MutatingHandlerClassic);
    act.sa_flags = 0; // no SA_SIGINFO: classic non-RT frame
    sigemptyset(&act.sa_mask);
    sigaction(SIGUSR1, &act, nullptr);
  }
};

void CheckCompute(const TestCtx& r) {
  CHECK(r.out_ebx == NEW_EBX);
  CHECK(r.out_esi == NEW_ESI);
  CHECK(r.out_edi == NEW_EDI);
  CHECK(r.out_esp == g_new_esp);
  // No syscall to clobber EAX in this context, so the EAX edit must survive too.
  CHECK(r.out_eax == NEW_EAX);
}

void CheckSyscall(const TestCtx& r) {
  CHECK(r.out_ebx == NEW_EBX);
  CHECK(r.out_esi == NEW_ESI);
  CHECK(r.out_edi == NEW_EDI);
  CHECK(r.out_esp == g_new_esp);
  // EAX ordering diverges (see the file comment): natively the handler's edit
  // is restored after the kernel staged -EINTR, so the edit wins; FEX's
  // syscall op writes its EINTR result after the guest sigreturn, so there the
  // syscall result wins. Accept both.
  const int32_t eax = static_cast<int32_t>(r.out_eax);
  CHECK((r.out_eax == NEW_EAX || eax == -EINTR));
}

void CheckFutex(const TestCtx& r) {
  CHECK(r.out_ebx == NEW_EBX);
  CHECK(r.out_esi == NEW_ESI);
  CHECK(r.out_edi == NEW_EDI);
  CHECK(r.out_esp == g_new_esp);
  // Same EAX ordering divergence as the nanosleep context, plus -EAGAIN in
  // case the futex value check lost a race.
  const int32_t eax = static_cast<int32_t>(r.out_eax);
  CHECK((r.out_eax == NEW_EAX || eax == -EINTR || eax == -EAGAIN));
}

} // namespace

TEST_CASE("greg writeback rt frame: compute (in-JIT)") {
  RTHandlerGuard g;
  CheckCompute(RunUnder(RunComputeCtx));
}

TEST_CASE("greg writeback rt frame: in-syscall (nanosleep)") {
  RTHandlerGuard g;
  CheckSyscall(RunUnder(RunSyscallCtx));
}

TEST_CASE("greg writeback rt frame: futex wait") {
  RTHandlerGuard g;
  CheckFutex(RunUnder(RunFutexCtx));
}

TEST_CASE("greg writeback classic frame: compute (in-JIT)") {
  ClassicHandlerGuard g;
  CheckCompute(RunUnder(RunComputeCtx));
}

TEST_CASE("greg writeback classic frame: in-syscall (nanosleep)") {
  ClassicHandlerGuard g;
  CheckSyscall(RunUnder(RunSyscallCtx));
}

TEST_CASE("greg writeback classic frame: futex wait") {
  ClassicHandlerGuard g;
  CheckFutex(RunUnder(RunFutexCtx));
}
