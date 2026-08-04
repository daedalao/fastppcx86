// SMC test for mremap-with-MREMAP_FIXED destination invalidation (§J.1).
//
// Gate: fails on the pre-fix tree (only source was invalidated on
// OldAddress != NewAddress), passes on the fix that also invalidates the
// destination range.
//
// Sequence:
//   1. mmap two 4 KiB RWX private-anon pages A and B.
//   2. Write `mov eax, 0xAAAAAAAA; ret` at A; call — JIT translates A.
//   3. Write `mov eax, 0xBBBBBBBB; ret` at B; call — JIT translates B.
//   4. mremap(B, 4096, 4096, MREMAP_MAYMOVE|MREMAP_FIXED, A). B's bytes now
//      live at A. A's original bytes are gone (its mapping was overwritten).
//   5. Call at A. With the fix, FEX invalidated A's cached translation and
//      re-decodes from the mapping now covering A (which was B's bytes) —
//      returns 0xBBBBBBBB. Pre-fix, FEX still holds A's original
//      translation and returns the stale 0xAAAAAAAA.

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

// mremap(MREMAP_MAYMOVE|MREMAP_FIXED) needs an explicit destination.
static void write_ret_imm32(uint8_t* code, uint32_t value) {
  code[0] = 0xB8;                        // mov eax, imm32
  code[1] = value & 0xff;
  code[2] = (value >> 8) & 0xff;
  code[3] = (value >> 16) & 0xff;
  code[4] = (value >> 24) & 0xff;
  code[5] = 0xC3;                        // ret
}

TEST_CASE("SMC: mremap MREMAP_FIXED invalidates destination cached translations") {
  // Reserve a 16 KiB window so we can pick fixed addresses inside it.
  void* window = mmap(nullptr, 16 * 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(window != MAP_FAILED);
  auto base = reinterpret_cast<uintptr_t>(window);
  void* A = mmap(reinterpret_cast<void*>(base + 4 * 4096), 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  void* B = mmap(reinterpret_cast<void*>(base + 8 * 4096), 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  REQUIRE(A != MAP_FAILED);
  REQUIRE(B != MAP_FAILED);

  auto codeA = static_cast<uint8_t*>(A);
  auto codeB = static_cast<uint8_t*>(B);
  write_ret_imm32(codeA, 0xAAAAAAAAu);
  write_ret_imm32(codeB, 0xBBBBBBBBu);

  using fn_t = uint32_t (*)();
  auto fnA = reinterpret_cast<fn_t>(A);
  auto fnB = reinterpret_cast<fn_t>(B);
  REQUIRE(fnA() == 0xAAAAAAAAu);
  REQUIRE(fnB() == 0xBBBBBBBBu);

  // Move B onto A. A's original mapping is replaced by B's page; the guest
  // now sees B's bytes at address A. No guest write happens against A, so
  // FEX's write-fault SMC path does not fire; only the mremap-destination
  // invalidation from InvalidateCodeRangeIfNecessaryOnRemap can force the
  // JIT to re-decode.
  void* moved = mremap(B, 4096, 4096, MREMAP_MAYMOVE | MREMAP_FIXED, A);
  REQUIRE(moved == A);

  const uint32_t result = fnA();
  INFO("post-mremap call at A returned 0x" << std::hex << result);
  CHECK(result == 0xBBBBBBBBu);
  CHECK_FALSE(result == 0xAAAAAAAAu);  // stale — would indicate pre-fix behaviour

  munmap(A, 4096);
  // B was consumed by the mremap.
  munmap(window, 16 * 4096);
}
