// Host-fault gate (SignalDelegator::HandleGuestSignal): a synchronous fault
// raised inside FEX's own host code must not be delivered to the guest as a
// signal. The ctest row sets FEX_HOSTFAULT_INJECT=<getppid nr> (110 on x86-64,
// 64 on i386), which makes FEX execute a `trap` inside its syscall body, in a
// deferred-signal section, whenever the guest calls getppid.
//
// The child installs a SIGTRAP/SIGSEGV handler that exits 0. With the old
// delivery the handler ran on top of FEX's host frame and the child exited
// normally; with the gate the child is killed by the fault's default
// disposition. Without the injection variable there is nothing to test, so
// the test passes vacuously (the test binary also runs natively).
#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void GuestHandler(int) {
  _exit(0);
}

TEST_CASE("Signals: a fault in FEX host code is not delivered to the guest") {
  if (!getenv("FEX_HOSTFAULT_INJECT")) {
    SUCCEED("FEX_HOSTFAULT_INJECT not set; nothing to inject");
    return;
  }

  const pid_t Pid = fork();
  REQUIRE(Pid >= 0);
  if (Pid == 0) {
    struct sigaction act {};
    act.sa_handler = GuestHandler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGTRAP, &act, nullptr);
    sigaction(SIGSEGV, &act, nullptr);
    syscall(SYS_getppid);
    // The syscall returned: the injection did not fire.
    _exit(2);
  }

  int Status = 0;
  REQUIRE(waitpid(Pid, &Status, 0) == Pid);
  INFO("child status 0x" << std::hex << Status);
  // exit 0 = the guest handler ran (delivered); exit 2 = nothing injected.
  CHECK(WIFSIGNALED(Status));
  if (WIFSIGNALED(Status)) {
    CHECK((WTERMSIG(Status) == SIGTRAP || WTERMSIG(Status) == SIGSEGV));
  }
}
