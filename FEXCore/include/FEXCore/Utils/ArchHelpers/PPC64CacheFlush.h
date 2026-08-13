// SPDX-License-Identifier: MIT
#pragma once

// ---------------------------------------------------------------------------
// Instruction-cache publication for freshly written host code, on ppc64le.
//
// WHY THIS EXISTS AT ALL — read before "simplifying" it back to a builtin.
//
// This file replaces `__builtin___clear_cache()`, which on this platform
// performs NO cache maintenance whatsoever. Measured on the AC922, 2026-08-13:
//
//   * gcc 16.1.1  `-O2`: the builtin expands to nothing. A function whose only
//     statement is the builtin compiles to a single `blr`.
//   * clang 22.1.8 `-O2` (this tree's compiler): the builtin lowers to
//     `bl __clear_cache`, which binds to `__clear_cache@GCC_3.0` in
//     /usr/lib/libgcc_s.so.1. That symbol is 0x24 bytes of prologue and
//     epilogue ending in `blr` — no dcbst, no sync, no icbi, no isync.
//
// POWER's instruction cache is NOT coherent with the data cache. Instructions
// written through the store path (the JIT emitter, a memcpy out of the code
// cache, a relocation patch) sit in the D-cache; the fetch unit reads the
// I-cache. Without explicit maintenance a branch into that memory can execute
// whatever the I-cache last held for the same physical line. Everything
// appeared to work anyway, because the window requires the line to have been
// fetched as *different* code beforehand — which is exactly what a JIT with a
// recycled code buffer eventually does.
//
// The sequence below is the one from Power ISA Book II, "Synchronization
// Requirements for Instruction Storage": for each block, `dcbst` to push the
// stored bytes out to coherent storage; one `sync` to order every dcbst ahead
// of the invalidations; for each block, `icbi` to invalidate the instruction
// cache (broadcast to all processors on this implementation); one `sync` to
// ensure the icbis have been performed; `isync` to discard anything already
// prefetched into this thread's pipeline.
//
// Residual, unchanged and inherent: a thread ALREADY executing inside the
// modified range does not itself execute the `isync`, so it may retire the old
// instruction. x86 says the same thing about cross-modifying code without a
// serialising instruction on the executing processor. Callers that patch live
// code (the block linker/delinker, SMC backpatch) are written so that both the
// old and the new word are a correct-behaviour path.
// ---------------------------------------------------------------------------

#include <atomic>
#include <cstddef>
#include <cstdint>

#ifdef __powerpc64__
#include <sys/auxv.h>
#endif

namespace FEXCore::ArchHelpers::PPC64 {

#ifdef __powerpc64__

/**
 * @brief Cache block size in bytes to stride the dcbst/icbi loops by.
 *
 * Queried from the auxiliary vector rather than assumed: `dcbst` and `icbi`
 * each operate on one block of their respective cache, and the two sizes are
 * not architecturally required to match. Striding by the SMALLER of the two is
 * the only value that is guaranteed to touch every block of both caches.
 *
 * POWER8/POWER9 report 128 for both. A stride smaller than the true block size
 * is merely redundant work (the extra dcbst/icbi hit blocks already covered),
 * never incorrect, so a missing or nonsensical auxv value falls back to 32 —
 * the smallest block size any PowerPC implementation has used.
 *
 * SIGNAL SAFETY — why this is not a `static const size_t X = f();`.
 * FlushICacheRange is reachable from inside a SIGSEGV handler: the SMC store
 * backpatcher rewrites a faulting store instruction from HandleSegfault
 * (LinuxSyscalls/SyscallsSMCTracking.cpp). A function-local static with a
 * dynamic initialiser emits a __cxa_guard_acquire/release pair, and a signal
 * taken on the same thread while that guard is held re-enters it — recursive
 * initialisation, which aborts or deadlocks. A constant-initialised
 * std::atomic emits no guard at all; the worst case is two threads both
 * computing the same value and storing it, which is harmless.
 *
 * The `getauxval` calls themselves are not on that path in practice — the
 * first flush in any process is PPC64Dispatcher's constructor, from
 * ContextImpl::InitCore, before any guest code runs and therefore before any
 * SMC fault can be taken. Even if one did land there, glibc's getauxval for a
 * non-HWCAP tag is a walk of the auxv array saved at startup: no lock, no
 * allocation, nothing that a signal can interrupt unsafely.
 */
inline size_t CacheBlockSize() {
  static std::atomic<size_t> Cached {0}; // constant-initialised: no guard variable
  size_t Size = Cached.load(std::memory_order_relaxed);
  if (Size != 0) [[likely]] {
    return Size;
  }

  const unsigned long DBlock = ::getauxval(AT_DCACHEBSIZE);
  const unsigned long IBlock = ::getauxval(AT_ICACHEBSIZE);

  unsigned long Chosen = 0;
  if (DBlock && IBlock) {
    Chosen = DBlock < IBlock ? DBlock : IBlock;
  } else {
    Chosen = DBlock ? DBlock : IBlock;
  }

  // Reject 0 and non-power-of-two; the align-down below depends on the mask.
  if (Chosen == 0 || (Chosen & (Chosen - 1)) != 0) {
    Chosen = 32;
  }

  Size = static_cast<size_t>(Chosen);
  Cached.store(Size, std::memory_order_relaxed);
  return Size;
}

/**
 * @brief Publish freshly written instructions in [Start, Start+Length) to the
 *        fetch stream.
 *
 * Must be called AFTER the last store to the range and BEFORE anything can
 * branch into it. The "memory" clobbers keep the compiler from sinking those
 * stores past the maintenance.
 *
 * @param Start  First byte of the modified range. Need not be block-aligned;
 *               the loops align down so a partially-covered first block is
 *               still invalidated.
 * @param Length Byte length of the modified range. Zero is a no-op.
 */
inline void FlushICacheRange(const void* Start, size_t Length) {
  if (Length == 0) {
    return;
  }

  const size_t BlockSize = CacheBlockSize();
  const uintptr_t Base = reinterpret_cast<uintptr_t>(Start);
  const uintptr_t End = Base + Length;
  const uintptr_t Begin = Base & ~static_cast<uintptr_t>(BlockSize - 1);

  for (uintptr_t P = Begin; P < End; P += BlockSize) {
    asm volatile("dcbst 0,%0" ::"r"(P) : "memory");
  }
  // Orders every dcbst above ahead of every icbi below.
  asm volatile("sync" ::: "memory");

  for (uintptr_t P = Begin; P < End; P += BlockSize) {
    asm volatile("icbi 0,%0" ::"r"(P) : "memory");
  }
  // sync: the icbis have been performed. isync: this thread refetches.
  asm volatile("sync; isync" ::: "memory");
}

#else

/**
 * @brief Non-ppc64 fallback. Retained only so shared headers (CodeEmitter,
 *        ThunkLibs) still compile off-target; this port has no other backend.
 */
inline void FlushICacheRange(const void* Start, size_t Length) {
  __builtin___clear_cache(reinterpret_cast<char*>(const_cast<void*>(Start)),
                          reinterpret_cast<char*>(const_cast<void*>(Start)) + Length);
}

#endif

} // namespace FEXCore::ArchHelpers::PPC64
