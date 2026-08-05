// Signal handler general-purpose register writeback test.
//
// x86-64 semantics: a signal handler installed with SA_SIGINFO may mutate the
// interrupted context's integer registers through uc_mcontext.gregs[]. When the
// handler returns (rt_sigreturn), those mutations MUST be visible to the
// interrupted code -- this is how GC/JIT/green-thread runtimes redirect or fix
// up a thread from a signal.
//
// FEX historically only wrote the handler's greg edits back into guest state
// when the handler ALSO changed RIP (RestoreFrame_x64 gated the whole COPY_REG
// block on OriginalRIP != NewRIP). A handler that touched only RAX/RBX/R12/R15
// had its writes silently dropped on resume, because:
//   * in-JIT deliveries resumed mid-block straight from the restored host
//     register file (the pre-signal SRA), and
//   * in-syscall deliveries resumed the interrupted host syscall and then let
//     the JIT syscall-op tail FillStaticRegs reload the *unmodified* frame.
//
// This test parks distinctive markers in RAX/RBX/R12/R15, has the handler
// overwrite them via ucontext, and checks that the interrupted code observes
// the new values -- under three delivery contexts:
//   (i)   blocked in a host syscall (nanosleep),
//   (ii)  pure JIT compute (a spin loop),
//   (iii) parked in a futex wait.
//
// Oracle: native x86-64 Linux. Kernel copies the (possibly handler-edited)
// sigcontext gregs back into the task's pt_regs on rt_sigreturn, so all three
// contexts observe the edits. RAX is the one caveat: for the two contexts that
// resume through a real syscall, the syscall's own return value lands in RAX
// after the handler runs, so RAX is asserted only in the compute context.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
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
constexpr uint64_t MARK_RAX = 0xA1A1'A1A1'A1A1'A1A1ULL;
constexpr uint64_t MARK_RBX = 0xB2B2'B2B2'B2B2'B2B2ULL;
constexpr uint64_t MARK_R12 = 0xC3C3'C3C3'C3C3'C3C3ULL;
constexpr uint64_t MARK_R15 = 0xD4D4'D4D4'D4D4'D4D4ULL;

// Values the handler injects; the interrupted code must observe these.
constexpr uint64_t NEW_RAX = 0x1111'2222'3333'4444ULL;
constexpr uint64_t NEW_RBX = 0x5555'6666'7777'8888ULL;
constexpr uint64_t NEW_R12 = 0x9999'AAAA'BBBB'CCCCULL;
constexpr uint64_t NEW_R15 = 0xDDDD'EEEE'FFFF'0000ULL;

struct TestCtx {
  // [0x00] input markers
  uint64_t mark_rax;
  uint64_t mark_rbx;
  uint64_t mark_r12;
  uint64_t mark_r15;
  // [0x20] captured-after-return outputs
  uint64_t out_rax;
  uint64_t out_rbx;
  uint64_t out_r12;
  uint64_t out_r15;
  // [0x40] spin-loop exit flag pointer (compute mode)
  volatile int* flag;
  // [0x48] futex word (must be 0 for FUTEX_WAIT to block)
  uint32_t futexword;
  uint32_t _pad;
};

static_assert(offsetof(TestCtx, mark_rax) == 0x00);
static_assert(offsetof(TestCtx, out_rax) == 0x20);
static_assert(offsetof(TestCtx, flag) == 0x40);
static_assert(offsetof(TestCtx, futexword) == 0x48);

volatile sig_atomic_t g_flag = 0;

void MutatingHandler(int, siginfo_t*, void* ucv) {
  auto* uc = reinterpret_cast<ucontext_t*>(ucv);
  uc->uc_mcontext.gregs[REG_RAX] = static_cast<greg_t>(NEW_RAX);
  uc->uc_mcontext.gregs[REG_RBX] = static_cast<greg_t>(NEW_RBX);
  uc->uc_mcontext.gregs[REG_R12] = static_cast<greg_t>(NEW_R12);
  uc->uc_mcontext.gregs[REG_R15] = static_cast<greg_t>(NEW_R15);
  g_flag = 1;
}

// Each naked routine: r13 = ctx (callee-saved, survives the syscall). Park the
// four markers, do the "work" (syscall or spin), then store the live registers.
// RAX/RBX/R12/R15 are never touched by the work body, so anything the handler
// wrote through ucontext must appear in the stores iff the writeback is honored.
// Written as naked functions with intel inline asm so -masm=intel applies (a
// top-level __asm__ block would be assembled in AT&T mode instead).

// Context (i): blocked in nanosleep.
__attribute__((naked)) void RunSyscallCtx(TestCtx* /*rdi*/) {
  __asm volatile(R"(
    push rbx
    push r12
    push r13
    push r15
    mov r13, rdi
    mov rax, [r13 + 0x00]
    mov rbx, [r13 + 0x08]
    mov r12, [r13 + 0x10]
    mov r15, [r13 + 0x18]
    sub rsp, 16
    mov qword ptr [rsp], 10          // tv_sec = 10
    mov qword ptr [rsp + 8], 0       // tv_nsec = 0
    mov eax, 35                      // SYS_nanosleep
    lea rdi, [rsp]                   // req
    xor esi, esi                     // rem = NULL
    syscall
    add rsp, 16
    mov [r13 + 0x20], rax            // syscall return (EINTR) -- not the handler RAX
    mov [r13 + 0x28], rbx
    mov [r13 + 0x30], r12
    mov [r13 + 0x38], r15
    pop r15
    pop r13
    pop r12
    pop rbx
    ret
  )" ::: "memory");
}

// Context (ii): pure JIT compute (spin until the handler sets the flag).
__attribute__((naked)) void RunComputeCtx(TestCtx* /*rdi*/) {
  __asm volatile(R"(
    push rbx
    push r12
    push r13
    push r15
    mov r13, rdi
    mov rax, [r13 + 0x00]
    mov rbx, [r13 + 0x08]
    mov r12, [r13 + 0x10]
    mov r15, [r13 + 0x18]
    mov r10, [r13 + 0x40]            // r10 = &flag
  1:
    mov ecx, dword ptr [r10]
    test ecx, ecx
    jz 1b
    mov [r13 + 0x20], rax
    mov [r13 + 0x28], rbx
    mov [r13 + 0x30], r12
    mov [r13 + 0x38], r15
    pop r15
    pop r13
    pop r12
    pop rbx
    ret
  )" ::: "memory");
}

// Context (iii): parked in FUTEX_WAIT.
__attribute__((naked)) void RunFutexCtx(TestCtx* /*rdi*/) {
  __asm volatile(R"(
    push rbx
    push r12
    push r13
    push r15
    mov r13, rdi
    mov rax, [r13 + 0x00]
    mov rbx, [r13 + 0x08]
    mov r12, [r13 + 0x10]
    mov r15, [r13 + 0x18]
    lea rdi, [r13 + 0x48]            // uaddr = &futexword (==0)
    xor esi, esi                     // FUTEX_WAIT (0)
    xor edx, edx                     // val = 0
    xor r10d, r10d                   // timeout = NULL
    mov eax, 202                     // SYS_futex
    syscall
    mov [r13 + 0x20], rax
    mov [r13 + 0x28], rbx
    mov [r13 + 0x30], r12
    mov [r13 + 0x38], r15
    pop r15
    pop r13
    pop r12
    pop rbx
    ret
  )" ::: "memory");
}

pthread_t g_target;

void* Poker(void*) {
  // Give the main thread time to reach its blocking point / enter the loop.
  struct timespec ts { 0, 200'000'000 };
  nanosleep(&ts, nullptr);
  pthread_kill(g_target, SIGUSR1);
  return nullptr;
}

TestCtx RunUnder(void (*fn)(TestCtx*)) {
  g_flag = 0;
  TestCtx ctx {};
  ctx.mark_rax = MARK_RAX;
  ctx.mark_rbx = MARK_RBX;
  ctx.mark_r12 = MARK_R12;
  ctx.mark_r15 = MARK_R15;
  ctx.flag = &g_flag;
  ctx.futexword = 0;

  g_target = pthread_self();
  pthread_t poker;
  pthread_create(&poker, nullptr, Poker, nullptr);
  fn(&ctx);
  pthread_join(poker, nullptr);
  return ctx;
}

struct HandlerGuard {
  HandlerGuard() {
    struct sigaction act {};
    act.sa_sigaction = MutatingHandler;
    act.sa_flags = SA_SIGINFO; // no SA_RESTART: interrupted syscalls return EINTR
    sigemptyset(&act.sa_mask);
    sigaction(SIGUSR1, &act, nullptr);
  }
};

} // namespace

TEST_CASE("greg writeback: compute (in-JIT)") {
  HandlerGuard g;
  TestCtx r = RunUnder(RunComputeCtx);
  CHECK(r.out_rbx == NEW_RBX);
  CHECK(r.out_r12 == NEW_R12);
  CHECK(r.out_r15 == NEW_R15);
  // No syscall to clobber RAX in this context, so the RAX edit must survive too.
  CHECK(r.out_rax == NEW_RAX);
}

TEST_CASE("greg writeback: in-syscall (nanosleep)") {
  HandlerGuard g;
  TestCtx r = RunUnder(RunSyscallCtx);
  CHECK(r.out_rbx == NEW_RBX);
  CHECK(r.out_r12 == NEW_R12);
  CHECK(r.out_r15 == NEW_R15);
  // RAX carries the syscall's own return (EINTR), matching x86: the syscall
  // result is written after the handler runs.
  CHECK(static_cast<int64_t>(r.out_rax) == -EINTR);
}

TEST_CASE("greg writeback: futex wait") {
  HandlerGuard g;
  TestCtx r = RunUnder(RunFutexCtx);
  CHECK(r.out_rbx == NEW_RBX);
  CHECK(r.out_r12 == NEW_R12);
  CHECK(r.out_r15 == NEW_R15);
  // FUTEX_WAIT returns -EINTR (or -EAGAIN if the value check lost a race).
  const int64_t rax = static_cast<int64_t>(r.out_rax);
  CHECK((rax == -EINTR || rax == -EAGAIN));
}
