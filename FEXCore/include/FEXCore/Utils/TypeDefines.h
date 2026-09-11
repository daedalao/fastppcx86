// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>
#include <cstdint>
#include <unistd.h>

namespace FEXCore::Utils {
// The page granularity that the *x86 guest* observes.
//
// This is the x86 ABI: the guest is handed AT_PAGESZ=4096 and computes
// MAP_FIXED addresses, ELF segment offsets and mprotect ranges from it. It is a
// compile-time constant and does not change with the host kernel's page size.
//
// If the quantity you are describing ends up in a real mmap/mprotect/munmap/
// mremap/madvise argument, it is NOT this: use FEXCore::HostPage below.
constexpr size_t FEX_GUEST_PAGE_SIZE = 4096;
constexpr size_t FEX_GUEST_PAGE_SHIFT = 12;
constexpr size_t FEX_GUEST_PAGE_MASK = ~(FEX_GUEST_PAGE_SIZE - 1);
} // namespace FEXCore::Utils

namespace FEXCore::HostPage {
// The granularity the *host kernel* demands. Runtime quantity: 4096 on a 4K
// kernel, 65536 on a 64K ppc64le kernel. Initialize() is called first thing in
// every tool's main (before any mapping is made); every accessor additionally
// self-initialises so that a missed call can never observe zero.
namespace Detail {
// Inline variables: one copy per process, shared across every translation unit.
inline size_t PageSize {};
inline size_t PageShift {};
inline size_t PageMask {};

inline size_t SlowInitialize();
} // namespace Detail

// Initialise from sysconf(_SC_PAGESIZE). Idempotent, and safe to call from
// several threads (every caller computes the same value).
inline size_t Initialize() {
  const long Result = ::sysconf(_SC_PAGESIZE);
  const size_t Size = (Result > 0) ? static_cast<size_t>(Result) : FEXCore::Utils::FEX_GUEST_PAGE_SIZE;
  Detail::PageShift = static_cast<size_t>(__builtin_ctzl(Size));
  Detail::PageMask = ~(Size - 1);
  // Publish the size last: it is the flag the lazy accessors test.
  Detail::PageSize = Size;
  return Size;
}

namespace Detail {
inline size_t SlowInitialize() {
  return FEXCore::HostPage::Initialize();
}
} // namespace Detail

[[nodiscard]]
inline size_t Size() {
  if (__builtin_expect(Detail::PageSize == 0, 0)) {
    return Detail::SlowInitialize();
  }
  return Detail::PageSize;
}

[[nodiscard]]
inline size_t Shift() {
  if (__builtin_expect(Detail::PageSize == 0, 0)) {
    Detail::SlowInitialize();
  }
  return Detail::PageShift;
}

// ~(Size() - 1)
[[nodiscard]]
inline size_t Mask() {
  if (__builtin_expect(Detail::PageSize == 0, 0)) {
    Detail::SlowInitialize();
  }
  return Detail::PageMask;
}

[[nodiscard]]
inline uint64_t AlignUp(uint64_t Value) {
  const uint64_t PageSize = Size();
  return (Value + PageSize - 1) & Mask();
}

[[nodiscard]]
inline uint64_t AlignDown(uint64_t Value) {
  return Value & Mask();
}

template<typename T>
[[nodiscard]]
inline T* AlignUpPtr(T* Value) {
  return reinterpret_cast<T*>(AlignUp(reinterpret_cast<uint64_t>(Value)));
}

template<typename T>
[[nodiscard]]
inline T* AlignDownPtr(T* Value) {
  return reinterpret_cast<T*>(AlignDown(reinterpret_cast<uint64_t>(Value)));
}

[[nodiscard]]
inline bool IsAligned(uint64_t Value) {
  return (Value & ~Mask()) == 0;
}

// True when the host page size is the same as the guest's, i.e. every legacy
// 4K assumption in the tree happens to still hold.
[[nodiscard]]
inline bool MatchesGuest() {
  return Size() == FEXCore::Utils::FEX_GUEST_PAGE_SIZE;
}
} // namespace FEXCore::HostPage
