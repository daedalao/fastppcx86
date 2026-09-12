/*
  fork() racing SMC write faults on other threads.

  Regression test for the VMATracking.Mutex / CodeInvalidationMutex lock
  inversion in SyscallHandler::HandleSegfault (2026-09-08): the SIGSEGV
  handler used to hold VMATracking (shared) while taking the exclusive
  CodeInvalidationMutex, and LockBeforeFork takes those two in the opposite
  order. One thread forking while another thread's store faults on a
  write-protected code page deadlocked, and
  TakeCodeInvalidationWriteLockOrSteal turned that into a SIGTRAP after 4s.

  Each writer thread owns its own RWX page holding `mov eax, imm32; ret`,
  rewrites the immediate and calls the function, so every store faults once
  the page holds compiled code and the returned value checks the SMC handling
  itself. The main thread forks in a loop the whole time. Under the old
  handler this dies within a few seconds; it must complete and every call
  must return the value just stored.
*/
#include <atomic>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

namespace {
std::atomic<bool> stop {false};
std::atomic<int> mismatches {0};
std::atomic<int> stores {0};

void* writer(void*) {
  auto code = (unsigned char*)mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
  const unsigned char stub[] = {0xB8, 0, 0, 0, 0, 0xC3};
  memcpy(code, stub, sizeof(stub));
  auto fn = (int (*)())code;

  for (unsigned i = 1; !stop; i++) {
    code[1] = i & 0xff;
    const int r = fn();
    if ((r & 0xff) != (int)(i & 0xff)) {
      mismatches++;
    }
    stores++;
  }
  return nullptr;
}
} // namespace

TEST_CASE("SMC: fork() while other threads take SMC write faults") {
  constexpr int NumWriters = 8;
  constexpr int NumForks = 300;

  pthread_t tid[NumWriters];
  for (auto& t : tid) {
    REQUIRE(pthread_create(&t, nullptr, &writer, nullptr) == 0);
  }

  for (int i = 0; i < NumForks; i++) {
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
      _exit(0);
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 0);
  }

  stop = true;
  for (auto& t : tid) {
    pthread_join(t, nullptr);
  }

  printf("forks=%d stores=%d mismatches=%d\n", NumForks, stores.load(), mismatches.load());
  CHECK(stores.load() > 0);
  CHECK(mismatches.load() == 0);
}
