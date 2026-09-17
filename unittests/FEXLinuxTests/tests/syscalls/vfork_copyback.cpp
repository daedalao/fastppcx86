// vfork/CLONE_VM copy-back (ForkGuest, single-threaded guests).
//
// FEX cannot give a vfork child the parent's address space (the JIT state is
// per process), so the child runs in a copy and its writes are copied back to
// the parent when it exits or execs. These cases check the semantics a real
// vfork gives a single-threaded program:
//   - a global the child writes is visible to the parent afterwards;
//   - a grandchild (the vfork child fork()s) is a separate copy: its writes
//     never reach the grandparent, and its exit must not end the vfork wait
//     early or hand the grandparent the wrong image;
//   - posix_spawn of a missing program reports the child's execve errno.
// The vfork children below use only async-signal-safe calls.
//
// Oracle: native x86 Linux passes all cases.

#include <catch2/catch_test_macros.hpp>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace {
volatile int ChildWrote;
volatile int GrandchildWrote;
volatile int ChildSawGrandchildExit;
} // namespace

TEST_CASE("vfork child's write is visible to the parent") {
  ChildWrote = 0;
  pid_t Child = vfork();
  REQUIRE(Child >= 0);
  if (Child == 0) {
    ChildWrote = 42;
    _exit(7);
  }
  int Status = 0;
  REQUIRE(waitpid(Child, &Status, 0) == Child);
  REQUIRE(WIFEXITED(Status));
  REQUIRE(WEXITSTATUS(Status) == 7);
  REQUIRE(ChildWrote == 42);
}

TEST_CASE("a grandchild of a vfork child is a separate copy") {
  ChildWrote = 0;
  GrandchildWrote = 0;
  ChildSawGrandchildExit = 0;
  pid_t Child = vfork();
  REQUIRE(Child >= 0);
  if (Child == 0) {
    ChildWrote = 1;
    pid_t Grandchild = fork();
    if (Grandchild == 0) {
      GrandchildWrote = 1;
      _exit(3);
    }
    if (Grandchild > 0) {
      int S = 0;
      while (waitpid(Grandchild, &S, 0) == -1 && errno == EINTR) {
      }
      if (WIFEXITED(S) && WEXITSTATUS(S) == 3) {
        ChildSawGrandchildExit = 1;
      }
    }
    _exit(5);
  }
  int Status = 0;
  REQUIRE(waitpid(Child, &Status, 0) == Child);
  REQUIRE(WIFEXITED(Status));
  REQUIRE(WEXITSTATUS(Status) == 5);
  REQUIRE(ChildWrote == 1);
  REQUIRE(ChildSawGrandchildExit == 1);
  REQUIRE(GrandchildWrote == 0);
}

TEST_CASE("vfork child that execs leaves the parent intact") {
  ChildWrote = 0;
  pid_t Child = vfork();
  REQUIRE(Child >= 0);
  if (Child == 0) {
    ChildWrote = 9;
    char* const Argv[] = {const_cast<char*>("/bin/true"), nullptr};
    execve("/bin/true", Argv, environ);
    _exit(127);
  }
  int Status = 0;
  REQUIRE(waitpid(Child, &Status, 0) == Child);
  REQUIRE(WIFEXITED(Status));
  REQUIRE(WEXITSTATUS(Status) == 0);
  REQUIRE(ChildWrote == 9);
}

TEST_CASE("posix_spawn reports the child's exec error") {
  pid_t Pid = -1;
  char* const Argv[] = {const_cast<char*>("/nonexistent/program"), nullptr};
  const int Err = posix_spawn(&Pid, "/nonexistent/program", nullptr, nullptr, Argv, environ);
  REQUIRE(Err == ENOENT);

  char* const Argv2[] = {const_cast<char*>("/bin/true"), nullptr};
  REQUIRE(posix_spawn(&Pid, "/bin/true", nullptr, nullptr, Argv2, environ) == 0);
  int Status = 0;
  REQUIRE(waitpid(Pid, &Status, 0) == Pid);
  REQUIRE(WIFEXITED(Status));
  REQUIRE(WEXITSTATUS(Status) == 0);
}

TEST_CASE("many vforks in a row do not accumulate") {
  for (int i = 0; i < 300; ++i) {
    ChildWrote = 0;
    pid_t Child = vfork();
    REQUIRE(Child >= 0);
    if (Child == 0) {
      ChildWrote = i + 1;
      _exit(0);
    }
    int Status = 0;
    REQUIRE(waitpid(Child, &Status, 0) == Child);
    REQUIRE(ChildWrote == i + 1);
  }
}
