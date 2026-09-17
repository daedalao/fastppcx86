// SPDX-License-Identifier: MIT
#include "LinuxSyscalls/Syscalls.h"

#include <algorithm>
#include <cstring>

namespace FEX::HLE::FaultSafeUserMemAccess {
#ifdef ARCHITECTURE_arm64
__attribute__((naked)) size_t CopyFromUser(void* Dest, const void* Src, size_t Size) {
  __asm volatile(R"(
  // Early exit if a memcpy of size zero.
  cbz x2, 2f;

  1:
  .globl CopyFromUser_FaultInst
  CopyFromUser_FaultInst:
    ldrb w3, [x1], 1; // <- This line can fault.
    strb w3, [x0], 1;
    sub x2, x2, 1;
    cbnz x2, 1b;
2:
    mov x0, 0;
    ret;
  )" ::
                   : "memory");
}

__attribute__((naked)) size_t CopyToUser(void* Dest, const void* Src, size_t Size) {
  __asm volatile(R"(
  // Early exit if a memcpy of size zero.
  cbz x2, 2f;

  1:
    ldrb w3, [x1], 1;
  .globl CopyToUser_FaultInst
  CopyToUser_FaultInst:
    strb w3, [x0], 1; // <- This line can fault.
    sub x2, x2, 1;
    cbnz x2, 1b;
2:
    mov x0, 0;
    ret;
  )" ::
                   : "memory");
}

extern "C" uint64_t CopyFromUser_FaultInst;
void* const CopyFromUser_FaultLocation = &CopyFromUser_FaultInst;

extern "C" uint64_t CopyToUser_FaultInst;
void* const CopyToUser_FaultLocation = &CopyToUser_FaultInst;

#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED && defined(ARCHITECTURE_arm64)
__attribute__((naked)) bool VerifyIsReadableImpl(const void* Src, size_t Size) {
  __asm volatile(R"(
  // Early exit if size is zero.
  cbz x1, 2f;

  1:
  .globl UserReadable_FaultInst
  UserReadable_FaultInst:
  ldrb wzr, [x0], 1; // <- This line can fault.
  sub x1, x1, 1;
  cbnz x1, 1b;

  2:
  mov x0, 1;
  ret;
  )" ::
                   : "memory");
}

__attribute__((naked)) bool VerifyIsOnlyWritable(void* Src, size_t Size) {
  __asm volatile(R"(
  // Early exit if size is zero.
  cbz x1, 2f;

  1:
  ldrb w2, [x0];
  .globl UserWritable_FaultInst
  UserWritable_FaultInst:
  strb w2, [x0], 1; // <- This line can fault.

  sub x1, x1, 1;
  cbnz x1, 1b;

  2:
  mov x0, 1;
  ret;
  )" ::
                   : "memory");
}

__attribute__((naked)) bool VerifyIsStringReadableMaxSizeImpl(const char* Src, size_t MaxSize) {
  __asm volatile(R"(
  1:
  cbz x1, 2f;

  .globl UserStringReadable_FaultInst
  UserStringReadable_FaultInst:
  ldrb w2, [x0], 1; //< This line can fault.
  sub x1, x1, 1;
  cbnz x2, 1b;

  2:
  mov x0, 1;
  ret;
  )" ::
                   : "memory");
}

void VerifyIsReadable(const void* Src, size_t Size) {
  LOGMAN_THROW_A_FMT(VerifyIsReadableImpl(Src, Size), "EFAULT needs readable!");
}

void VerifyIsStringReadable(const char* Src) {
  LOGMAN_THROW_A_FMT(VerifyIsStringReadableMaxSizeImpl(Src, ~0ULL), "EFAULT needs string readable!");
}

void VerifyIsStringReadableMaxSize(const char* Src, size_t MaxSize) {
  LOGMAN_THROW_A_FMT(VerifyIsStringReadableMaxSizeImpl(Src, MaxSize), "EFAULT needs string readable!");
}

void VerifyIsReadableOrNull(const void* Src, size_t Size) {
  if (Src == nullptr) {
    return;
  }

  LOGMAN_THROW_A_FMT(VerifyIsReadableImpl(Src, Size), "EFAULT needs readable!");
}

void VerifyIsWritable(void* Src, size_t Size) {
  ///< Checking if writable needs to check if readable first.
  VerifyIsReadable(Src, Size);

  LOGMAN_THROW_A_FMT(VerifyIsOnlyWritable(Src, Size), "EFAULT needs writable!");
}

void VerifyIsWritableOrNull(void* Src, size_t Size) {
  if (Src == nullptr) {
    return;
  }

  ///< Checking if writable needs to check if readable first.
  VerifyIsReadable(Src, Size);
  LOGMAN_THROW_A_FMT(VerifyIsOnlyWritable(Src, Size), "EFAULT needs writable!");
}

extern "C" uint64_t UserReadable_FaultInst;
void* const UserReadable_FaultLocation = &UserReadable_FaultInst;

extern "C" uint64_t UserWritable_FaultInst;
void* const UserWritable_FaultLocation = &UserWritable_FaultInst;

extern "C" uint64_t UserStringReadable_FaultInst;
void* const UserStringReadable_FaultLocation = &UserStringReadable_FaultInst;
#endif

bool IsFaultLocation(uint64_t PC) {
  bool IsMemcpyFault = false;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == CopyToUser_FaultLocation;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == CopyFromUser_FaultLocation;
#if defined(ASSERTIONS_ENABLED) && ASSERTIONS_ENABLED && defined(ARCHITECTURE_arm64)
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == UserReadable_FaultLocation;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == UserWritable_FaultLocation;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == UserStringReadable_FaultLocation;
#endif
  return IsMemcpyFault;
}

#elif defined(ARCHITECTURE_ppc64le)
// PPC64LE parity with the ARM64 naked-asm implementations above. Each function
// has one labelled instruction where a guest-pointer dereference can SIGSEGV;
// `TryHandleSafeFault` (Syscalls.h) compares the faulting PC against these
// labels and, on match, sets r3=EFAULT and PC=LR to return to the caller.
//
// Calling convention (PPC64LE ELFv2): r3=Dest, r4=Src, r5=Size; return in r3.
// We use r6 as the loop temp (caller-clobbered scratch under ELFv2).
__attribute__((naked)) size_t CopyFromUser(void* Dest, const void* Src, size_t Size) {
  __asm volatile(R"(
    cmpdi   3, 5, 0
    beq     3, 2f
  1:
    .globl CopyFromUser_FaultInst
    CopyFromUser_FaultInst:
    lbz     6, 0(4)          # <- This line can fault on a bad guest Src.
    stb     6, 0(3)
    addi    3, 3, 1
    addi    4, 4, 1
    addic.  5, 5, -1
    bne     0, 1b
  2:
    li      3, 0
    blr
  )" ::
                   : "memory");
}

__attribute__((naked)) size_t CopyToUser(void* Dest, const void* Src, size_t Size) {
  __asm volatile(R"(
    cmpdi   3, 5, 0
    beq     3, 2f
  1:
    lbz     6, 0(4)
    .globl CopyToUser_FaultInst
    CopyToUser_FaultInst:
    stb     6, 0(3)          # <- This line can fault on a bad guest Dest.
    addi    3, 3, 1
    addi    4, 4, 1
    addic.  5, 5, -1
    bne     0, 1b
  2:
    li      3, 0
    blr
  )" ::
                   : "memory");
}

extern "C" uint64_t CopyFromUser_FaultInst;
void* const CopyFromUser_FaultLocation = &CopyFromUser_FaultInst;

extern "C" uint64_t CopyToUser_FaultInst;
void* const CopyToUser_FaultLocation = &CopyToUser_FaultInst;

// strncpy_from_user for path arguments (GuestPath): copies the guest string
// at Src into Dest up to its NUL or Size bytes. Returns the string's length,
// -1 when there is no NUL in the first Size bytes, or -EFAULT (set by
// TryHandleSafeFault) when a byte before the NUL is unreadable.
//
// Bytes one at a time until Src is 8-aligned, then 8 at a time: an aligned
// 8-byte load never crosses a page boundary, so it faults only when the page
// holding the next string byte is unreadable, exactly where the kernel's
// strncpy_from_user fails. The NUL test is the (w - 0x01..) & ~w & 0x80..
// trick; its lowest set bit marks the first zero byte (little-endian).
// r3=Dest r4=Src r5=Size; r7 keeps Dest; r8/r9 hold the constants.
__attribute__((naked, used)) int64_t CopyStringFromUserFast(char* Dest, const char* Src, size_t Size) {
  __asm volatile(R"(
    mr      7, 3
    cmpldi  5, 0
    beq     9f
  1:
    andi.   0, 4, 7
    beq     3f
    .globl CopyStringFromUser_FaultByte
    CopyStringFromUser_FaultByte:
    lbz     6, 0(4)          # <- can fault on a bad guest Src.
    stb     6, 0(3)
    cmpdi   6, 0
    beq     8f
    addi    3, 3, 1
    addi    4, 4, 1
    addic.  5, 5, -1
    bne     1b
    b       9f
  3:
    lis     8, 0x0101
    ori     8, 8, 0x0101
    sldi    9, 8, 32
    or      8, 8, 9
    sldi    9, 8, 7
  4:
    cmpldi  5, 8
    blt     6f
    .globl CopyStringFromUser_FaultWord
    CopyStringFromUser_FaultWord:
    ld      6, 0(4)          # <- can fault on a bad guest Src.
    std     6, 0(3)
    subf    10, 8, 6
    andc    10, 10, 6
    and.    10, 10, 9
    bne     5f
    addi    3, 3, 8
    addi    4, 4, 8
    addi    5, 5, -8
    b       4b
  5:
    neg     11, 10
    and     11, 10, 11
    addi    11, 11, -1
    popcntd 11, 11
    srdi    11, 11, 3
    add     3, 3, 11
    b       8f
  6:
    cmpldi  5, 0
    beq     9f
    .globl CopyStringFromUser_FaultTail
    CopyStringFromUser_FaultTail:
    lbz     6, 0(4)          # <- can fault on a bad guest Src.
    stb     6, 0(3)
    cmpdi   6, 0
    beq     8f
    addi    3, 3, 1
    addi    4, 4, 1
    addi    5, 5, -1
    b       6b
  8:
    subf    3, 7, 3
    blr
  9:
    li      3, -1
    blr
  )" ::
                   : "memory");
}

extern "C" uint64_t CopyStringFromUser_FaultByte;
extern "C" uint64_t CopyStringFromUser_FaultWord;
extern "C" uint64_t CopyStringFromUser_FaultTail;

bool IsStringFaultLocation(uint64_t PC) {
  const auto* P = reinterpret_cast<void*>(PC);
  return P == &CopyStringFromUser_FaultByte || P == &CopyStringFromUser_FaultWord || P == &CopyStringFromUser_FaultTail;
}

ssize_t CopyStringFromUser(char* Dest, const char* Src, size_t DestSize) {
  const int64_t Len = CopyStringFromUserFast(Dest, Src, DestSize);
  return Len == -1 ? -ENAMETOOLONG : Len;
}

// NOTE: ARM64 also implements VerifyIsReadable/Writable/StringReadable as
// naked-asm probes for assertion-only builds, with matching fault locations
// in IsFaultLocation. On PPC64LE the corresponding wrappers in
// `Syscalls.h:559-580` are `inline` stubs (the ASSERTIONS+ARM64 combined
// gate is false), so defining real impls here would double-define them.
// The CopyFromUser/CopyToUser path is the only correctness-critical surface
// for guest user-pointer fault recovery; the Verify* probes are debug-only
// and can be added later if the inline-stub conflict is resolved.

bool IsFaultLocation(uint64_t PC) {
  bool IsMemcpyFault = false;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == CopyToUser_FaultLocation;
  IsMemcpyFault |= reinterpret_cast<void*>(PC) == CopyFromUser_FaultLocation;
  return IsMemcpyFault;
}

#else
size_t CopyFromUser(void* Dest, const void* Src, size_t Size) {
  memcpy(Dest, Src, Size);
  return Size;
}

size_t CopyToUser(void* Dest, const void* Src, size_t Size) {
  memcpy(Dest, Src, Size);
  return Size;
}

bool IsFaultLocation(uint64_t PC) {
  return false;
}
#endif
#ifndef ARCHITECTURE_ppc64le
ssize_t CopyStringFromUser(char* Dest, const char* Src, size_t DestSize) {
  // Copy up to each 4K boundary at a time: a string that ends just before an
  // unmapped page is still valid, so nothing past a found NUL may be touched.
  size_t Copied = 0;
  while (Copied < DestSize) {
    const uintptr_t Addr = reinterpret_cast<uintptr_t>(Src) + Copied;
    const size_t ToBoundary = 4096 - (Addr & 4095);
    const size_t Chunk = std::min(DestSize - Copied, ToBoundary);
    if (CopyFromUser(Dest + Copied, reinterpret_cast<const void*>(Addr), Chunk) != 0) {
      return -EFAULT;
    }
    if (const auto* Nul = static_cast<const char*>(memchr(Dest + Copied, 0, Chunk))) {
      return Nul - Dest;
    }
    Copied += Chunk;
  }
  return -ENAMETOOLONG;
}

bool IsStringFaultLocation(uint64_t PC) {
  return false;
}
#endif
} // namespace FEX::HLE::FaultSafeUserMemAccess
