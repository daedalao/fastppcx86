// SMC test for MADV_DONTNEED code-invalidation (S3 / TrackMadvise).
//
// Gate test for the S3 fix: it must FAIL on a tree where TrackMadvise is the
// pre-fix empty stub (guest sees stale JIT-cached translation of a page whose
// contents were destroyed via madvise), and must PASS once TrackMadvise
// invalidates on the destructive advice codes.
//
// Sequence:
//   1. mmap 4 KiB RWX private-anon.
//   2. Write `mov eax, 0x1234ABCD; ret` at page[0]; call it — JIT translates.
//   3. madvise(page, 4096, MADV_DONTNEED) — kernel silently drops the page.
//      No guest write, so FEX's write-fault SMC path does not fire; only
//      TrackMadvise can force invalidation.
//   4. Fork; child calls the page again. With TrackMadvise wired, the JIT
//      re-decodes from the zero-filled page; execution steps into
//      `add [rax], al` etc. and terminates on signal or FEX-internal abort.
//      Without the fix, the parent's stale JIT is reachable to the child
//      and fn() returns 0x1234ABCD cleanly.
//   5. Parent asserts the child was terminated abnormally (any signal, or
//      child exited with rc=3 signalling non-stale non-zero return). Only a
//      clean rc=1 with `child returned 0x1234ABCD` is FAIL.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("SMC: MADV_DONTNEED invalidates cached translations") {
  void* page = mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(page != MAP_FAILED);

  uint8_t* code = static_cast<uint8_t*>(page);
  // mov eax, 0x1234ABCD; ret
  code[0] = 0xB8;
  code[1] = 0xCD;
  code[2] = 0xAB;
  code[3] = 0x34;
  code[4] = 0x12;
  code[5] = 0xC3;

  using fn_t = uint32_t (*)();
  auto fn = reinterpret_cast<fn_t>(code);

  const uint32_t r1 = fn();
  REQUIRE(r1 == 0x1234ABCDu);

  REQUIRE(madvise(page, 4096, MADV_DONTNEED) == 0);

  const pid_t pid = fork();
  REQUIRE(pid >= 0);
  if (pid == 0) {
    // Child. If TrackMadvise did not invalidate, the parent's cached
    // translation is what the guest observes and fn() returns the stale
    // 0x1234ABCD. If it did invalidate, the JIT re-decodes from the
    // destroyed page's zero bytes and execution enters `add [rax], al`
    // territory — signals or FEX-internal abort.
    volatile uint32_t r2 = fn();
    _exit(r2 == 0x1234ABCDu ? 1 : 3);
  }

  int status = 0;
  REQUIRE(waitpid(pid, &status, 0) == pid);

  const bool signalled = WIFSIGNALED(status);
  const bool exited_nonstale = WIFEXITED(status) && WEXITSTATUS(status) == 3;
  const bool exited_stale = WIFEXITED(status) && WEXITSTATUS(status) == 1;

  INFO("child status = 0x" << std::hex << status);
  CHECK((signalled || exited_nonstale));
  CHECK_FALSE(exited_stale);

  munmap(page, 4096);
}
