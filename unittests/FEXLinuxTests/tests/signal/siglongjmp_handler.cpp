// Leaving a signal handler with siglongjmp must not consume host stack.
//
// FEX keeps a copy of the interrupted HOST context (the ContextBackup) on the
// host stack under the interrupted SP for the duration of a guest handler and
// only the handler's rt_sigreturn releases it. A handler the guest exits with
// siglongjmp never sigreturns, so every such handler used to sink the host SP
// by one backup (several KB) for the life of the thread: interpreters, test
// harnesses and crash handlers that longjmp out of handlers crashed after
// ~2,500 deliveries on an 8 MB host stack. The fix (SignalDelegator.cpp,
// "Abandoned-frame reclaim") recognises abandoned backups through the guest
// frame and reuses their space.
//
// Every storm below runs far more deliveries than an unfixed host stack can
// hold (Iterations x ~5 KB = ~100 MB against an 8 MB stack), so a leak is a
// crash long before the loop ends, and each storm is followed by a normal
// delivery to check the thread's signal state is still coherent. The storms
// cover the delivery shapes the reclaim distinguishes:
//   - raise(): the signal lands while the thread is inside a host syscall
//     (helper-level interrupt, the backup sits under host C frames);
//   - a synchronous fault and an interval timer: the signal lands inside a
//     JIT block (JIT-level interrupt);
//   - the alternate stack: the frame is rebuilt at the same guest address
//     every time (the overwrite test), vs deep recursion: the frame moves
//     (the cookie test);
//   - nested handlers where the inner one longjmps out of both, and where it
//     longjmps back into the outer one which then returns normally (the
//     sigreturn path has to drop the abandoned inner backup);
//   - a secondary thread (its own host stack).
//
// Oracle: native x86 Linux passes every case (the kernel keeps nothing on the
// kernel side across a handler); any FEX failure is an emulation defect.

#include <catch2/catch_test_macros.hpp>

#include <csetjmp>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

namespace {
constexpr int Iterations = 20000;

sigjmp_buf Jump;
volatile sig_atomic_t Handled;
volatile sig_atomic_t Returned;

void LongjmpHandler(int) {
  ++Handled;
  siglongjmp(Jump, 1);
}

void LongjmpHandlerSigInfo(int, siginfo_t*, void*) {
  ++Handled;
  siglongjmp(Jump, 1);
}

void ReturningHandler(int) {
  ++Returned;
}

void Install(int Signal, void (*Handler)(int), int Flags) {
  struct sigaction sa {};
  sa.sa_handler = Handler;
  sa.sa_flags = Flags;
  sigemptyset(&sa.sa_mask);
  REQUIRE(sigaction(Signal, &sa, nullptr) == 0);
}

void InstallSigInfo(int Signal, void (*Handler)(int, siginfo_t*, void*), int Flags) {
  struct sigaction sa {};
  sa.sa_sigaction = Handler;
  sa.sa_flags = Flags | SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  REQUIRE(sigaction(Signal, &sa, nullptr) == 0);
}

// raise() delivers before it returns, so the handler's siglongjmp is the only
// way past it: reaching FAIL means the handler did not run.
void RaiseStorm(int Signal, int Count) {
  Handled = 0;
  for (int i = 0; i < Count; ++i) {
    if (sigsetjmp(Jump, 1) == 0) {
      raise(Signal);
      FAIL("handler did not run");
    }
  }
  REQUIRE(Handled == Count);
}

// A handler that returns normally must still work after a storm.
void CheckNormalDelivery() {
  Install(SIGUSR2, ReturningHandler, 0);
  Returned = 0;
  raise(SIGUSR2);
  REQUIRE(Returned == 1);
}
} // namespace

TEST_CASE("siglongjmp out of a non-siginfo handler") {
  Install(SIGUSR1, LongjmpHandler, 0);
  RaiseStorm(SIGUSR1, Iterations);
  CheckNormalDelivery();
}

TEST_CASE("siglongjmp out of a SA_SIGINFO handler") {
  InstallSigInfo(SIGUSR1, LongjmpHandlerSigInfo, 0);
  RaiseStorm(SIGUSR1, Iterations);
  CheckNormalDelivery();
}

TEST_CASE("siglongjmp out of a handler on the alternate stack") {
  const size_t Size = 64 * 1024;
  void* Stack = mmap(nullptr, Size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(Stack != MAP_FAILED);
  stack_t ss {};
  ss.ss_sp = Stack;
  ss.ss_size = Size;
  ss.ss_flags = 0;
  REQUIRE(sigaltstack(&ss, nullptr) == 0);

  InstallSigInfo(SIGUSR1, LongjmpHandlerSigInfo, SA_ONSTACK);
  RaiseStorm(SIGUSR1, Iterations);
  CheckNormalDelivery();

  ss.ss_flags = SS_DISABLE;
  REQUIRE(sigaltstack(&ss, nullptr) == 0);
  munmap(Stack, Size);
}

TEST_CASE("siglongjmp out of a synchronous fault handler") {
  // The fault is raised by guest code itself, so the signal lands inside a
  // JIT block rather than inside a host syscall.
  InstallSigInfo(SIGSEGV, LongjmpHandlerSigInfo, 0);
  Handled = 0;
  volatile int* Bad = nullptr;
  for (int i = 0; i < Iterations; ++i) {
    if (sigsetjmp(Jump, 1) == 0) {
      *Bad = 0;
      FAIL("fault did not raise SIGSEGV");
    }
  }
  REQUIRE(Handled == Iterations);
  signal(SIGSEGV, SIG_DFL);
  CheckNormalDelivery();
}

TEST_CASE("siglongjmp out of an interval-timer handler landing in compute") {
  // Asynchronous delivery inside JIT'd code. Fewer iterations: they are paced
  // by the timer, not by raise().
  constexpr int TimerIterations = 400;
  Install(SIGALRM, LongjmpHandler, 0);
  Handled = 0;

  struct itimerval Timer {};
  Timer.it_interval.tv_usec = 1000;
  Timer.it_value.tv_usec = 1000;
  REQUIRE(setitimer(ITIMER_REAL, &Timer, nullptr) == 0);

  volatile uint64_t Sink = 0;
  while (Handled < TimerIterations) {
    if (sigsetjmp(Jump, 1) == 0) {
      // Compute until the next tick lands.
      for (uint64_t k = 0; k < 1'000'000'000ULL && Handled < TimerIterations; ++k) {
        Sink += k;
      }
    }
  }

  struct itimerval Off {};
  REQUIRE(setitimer(ITIMER_REAL, &Off, nullptr) == 0);
  signal(SIGALRM, SIG_IGN);
  REQUIRE(Handled >= TimerIterations);
  CheckNormalDelivery();
}

namespace {
volatile sig_atomic_t OuterEntered;
volatile sig_atomic_t OuterReturned;
sigjmp_buf OuterJump;

// Outer handler: raises the inner signal, whose handler longjmps to the
// top-level Jump -- out of BOTH handlers.
void OuterRaisesInner(int) {
  ++OuterEntered;
  raise(SIGUSR1);
  // Not reached: the inner handler longjmps past us.
  OuterReturned = -1;
}

// Outer handler: the inner handler longjmps back INTO the outer one, which
// then returns normally, sigreturning over the abandoned inner backup.
void OuterCatchesInner(int) {
  ++OuterEntered;
  if (sigsetjmp(OuterJump, 1) == 0) {
    raise(SIGUSR1);
    FAIL("inner handler did not run");
  }
  ++OuterReturned;
}

void InnerToOuter(int) {
  ++Handled;
  siglongjmp(OuterJump, 1);
}
} // namespace

TEST_CASE("nested: the inner handler longjmps out of both") {
  constexpr int Nested = 5000;
  Install(SIGUSR1, LongjmpHandler, 0);
  Install(SIGUSR2, OuterRaisesInner, 0);
  Handled = 0;
  OuterEntered = 0;
  OuterReturned = 0;
  for (int i = 0; i < Nested; ++i) {
    if (sigsetjmp(Jump, 1) == 0) {
      raise(SIGUSR2);
      FAIL("handlers did not run");
    }
  }
  REQUIRE(Handled == Nested);
  REQUIRE(OuterEntered == Nested);
  REQUIRE(OuterReturned == 0);
  CheckNormalDelivery();
}

TEST_CASE("nested: the inner handler longjmps into the outer, which returns") {
  constexpr int Nested = 5000;
  Install(SIGUSR1, InnerToOuter, 0);
  Install(SIGUSR2, OuterCatchesInner, 0);
  Handled = 0;
  OuterEntered = 0;
  OuterReturned = 0;
  for (int i = 0; i < Nested; ++i) {
    raise(SIGUSR2);
  }
  REQUIRE(Handled == Nested);
  REQUIRE(OuterEntered == Nested);
  REQUIRE(OuterReturned == Nested);
  CheckNormalDelivery();
}

namespace {
// Recurse so the handler frame lands somewhere different from the previous
// iteration's (which the next recursion then overwrites): this exercises the
// cookie test rather than the same-address overwrite test.
int Recurse(int Depth) {
  volatile char Pad[64];
  Pad[0] = static_cast<char>(Depth);
  if (Depth == 0) {
    raise(SIGUSR1);
    return -1;
  }
  return Recurse(Depth - 1) + Pad[0];
}
} // namespace

TEST_CASE("siglongjmp out of a handler raised deep in recursion") {
  constexpr int Deep = 2000;
  Install(SIGUSR1, LongjmpHandler, 0);
  Handled = 0;
  for (int i = 0; i < Deep; ++i) {
    if (sigsetjmp(Jump, 1) == 0) {
      // Vary the depth so consecutive frames do not coincide.
      Recurse(200 + (i % 7) * 50);
      FAIL("handler did not run");
    }
  }
  REQUIRE(Handled == Deep);
  CheckNormalDelivery();
}

namespace {
void* ThreadStorm(void*) {
  // Per-thread jump buffer: the file-scope one belongs to the main thread.
  static sigjmp_buf ThreadJump;
  static volatile sig_atomic_t ThreadHandled;
  struct sigaction sa {};
  sa.sa_handler = [](int) {
    ++ThreadHandled;
    siglongjmp(ThreadJump, 1);
  };
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, nullptr) != 0) {
    return reinterpret_cast<void*>(1);
  }
  for (int i = 0; i < Iterations; ++i) {
    if (sigsetjmp(ThreadJump, 1) == 0) {
      pthread_kill(pthread_self(), SIGUSR1);
      return reinterpret_cast<void*>(2);
    }
  }
  return reinterpret_cast<void*>(ThreadHandled == Iterations ? 0 : 3);
}
} // namespace

TEST_CASE("siglongjmp storm on a secondary thread") {
  pthread_t Thread;
  REQUIRE(pthread_create(&Thread, nullptr, ThreadStorm, nullptr) == 0);
  void* Result = nullptr;
  REQUIRE(pthread_join(Thread, &Result) == 0);
  REQUIRE(Result == nullptr);
  CheckNormalDelivery();
}
