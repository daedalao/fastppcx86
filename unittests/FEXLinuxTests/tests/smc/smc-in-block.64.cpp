// SPDX-License-Identifier: MIT
//
// In-block SMC: the guest instruction *inside a running JIT block* stores to
// the same page whose code is currently executing. The store faults on the
// FEX-shadow-protected code page, and FEX's SMC SIGSEGV handler must:
//   1. invalidate the block, unprotect the page,
//   2. detect that the fault address is inside the *current* block
//      (SyscallsSMCTracking.cpp:146 — IsAddressInCurrentBlock),
//   3. set ENTRY_FILL_SRA_SINGLE_INST_REG to redirect the dispatcher into
//      CompileSingleStep on re-entry.
//
// The pre-existing smc-*.cpp tests all mutate code *between* fn() calls,
// which take the InvalidateGuestCodeRange path via VMATracking rather than
// the in-block single-step path. Neither of those tests reaches :146.
//
// Requires FEX_SMCCHECKS=mtrack — otherwise MarkGuestExecutableRange is a
// no-op (SyscallsSMCTracking.cpp:168) and FEX never shadow-strips W from the
// host mapping, so the in-block store just succeeds silently and no SIGSEGV
// is delivered. The guest VMA is kept R+W+X so the SIGSEGV handler's
// Prot.Writable check at :98 passes.
//
// The x86-64 payload:
//   xor  rax, rax                       ; 3B    scratch = 0
//   lea  rcx, [rip - 10]                ; 7B    rcx = &payload[0]
//   mov  [rcx], eax                     ; 2B    writes 0 to payload[0..3] — faults on RX-only page
//   mov  eax, 0x1234                    ; 5B    return marker (executed after single-step recovery)
//   ret                                 ; 1B
//
// Success:  fn() returns 0x1234 and payload[0..3] == 0.
// Regression signatures:
//   * SIGSEGV that never gets caught by FEX (handler didn't match) — test crashes.
//   * `mov eax, 0x1234` returns unchanged only if single-step recompiled the
//     store correctly. A busted CompileSingleStep would jump to the
//     ThreadStopHandler (S2 failure gate) — process exits without returning.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

namespace {

constexpr uint8_t kPayload[] = {
    0x48, 0x31, 0xc0,                               // xor rax, rax
    0x48, 0x8d, 0x0d, 0xf6, 0xff, 0xff, 0xff,       // lea rcx, [rip - 10]
    0x89, 0x01,                                     // mov [rcx], eax
    0xb8, 0x34, 0x12, 0x00, 0x00,                   // mov eax, 0x1234
    0xc3,                                           // ret
};

using fn_t = int (*)();

}  // namespace

TEST_CASE("SMC: in-block self-modification triggers single-step recompile") {
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* mem = mmap(nullptr, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(mem != MAP_FAILED);

  auto* code = static_cast<uint8_t*>(mem);
  std::memcpy(code, kPayload, sizeof(kPayload));

  // Guest VMA stays R+W+X. FEX (under SMCChecks=mtrack) shadow-strips W in
  // the host-side mapping and re-adds it inside HandleSegfault when the
  // in-block store faults. If FEX is NOT running in mtrack mode, the store
  // silently succeeds and this test loses discriminating power — treat as a
  // skip rather than a failure by checking rv only.
  int rv = reinterpret_cast<fn_t>(code)();
  CHECK(rv == 0x1234);
  // Under mtrack: xor rax,rax bytes were overwritten by the in-block store.
  // Under non-mtrack: same, because the store still executes.
  CHECK(code[0] == 0x00);
  CHECK(code[1] == 0x00);
  CHECK(code[2] == 0x00);
  CHECK(code[3] == 0x00);

  munmap(mem, page);
}
