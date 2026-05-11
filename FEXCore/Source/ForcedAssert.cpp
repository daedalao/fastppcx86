// SPDX-License-Identifier: MIT
namespace FEXCore::Assert {
// This function can not be inlined
[[noreturn]]
__attribute__((noinline, naked)) void ForcedAssert() {
#if defined(ARCHITECTURE_x86_64)
  asm volatile("ud2");
#elif defined(ARCHITECTURE_ppc64le)
  asm volatile("trap");
#else
  asm volatile("hlt #1");
#endif
}
} // namespace FEXCore::Assert
