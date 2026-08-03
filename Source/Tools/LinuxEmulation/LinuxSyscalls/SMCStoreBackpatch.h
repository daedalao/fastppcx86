// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC store backpatching (FEX_SMCSTOREBACKPATCH=1, ppc64le only)
//   "Idea 1/2" from notes/SMC_IDEAS.md -- kill the fault, not the recompile.
// ===========================================================================
//
// PROBLEM
// -------
// v1 (SMCStoreEmulation) emulates the faulting store in the SIGSEGV handler
// and v3 (SMCSoftInvalidate) makes the invalidation cheap, but BOTH still pay
// one signal round trip per storm cycle.  Measured on op4k (POWER8, branch
// f01128c0d) the fault itself is ~17us of the ~22us cycle: falseshare goes
// 42.3K/s -> 57.1K/s under v3 and no further, because the remaining cost is
// the trap, not the compiler.  Removing the recompile cannot get past the
// trap; only removing the trap can.
//
// DESIGN
// ------
// When an SMC write fault arrives and the faulting *host* instruction is a
// plain GPR store we recognise, do not merely emulate that one store:
// BACKPATCH the store site so it never faults again.
//
//   1. Emit a per-site stub into a stub pool placed within +-32MiB of the
//      faulting instruction (PowerISA `b` has a 26-bit signed byte
//      displacement).
//   2. Replace the 4-byte store with a single aligned 4-byte `b <stub>`.
//   3. The stub recomputes the store's effective address from the same
//      register fields the decoder read, consults a lock-free page filter,
//      and either
//        - performs the store natively (page is not mtrack-protected: this is
//          the same site later writing ordinary memory), or
//        - calls a C++ helper that does the correct, locked thing: if the
//          written bytes overlap compiled code, soft-invalidate first (v3
//          semantics, synchronously), then perform the store through
//          pwrite(/proc/self/mem) so the read-only protection survives.
//      Then it returns to the instruction after the original store.
//
// A pwrite is ~1us against the ~17us signal round trip it replaces, and the
// native-store path is ~50 cycles.
//
// WHY THE PATCH NEEDS NO CROSS-MODIFYING-CODE HANDSHAKE
// ------------------------------------------------------
// Power's cross-modifying-code sequence normally requires every *other*
// processor executing the patched line to issue its own isync.  We do not
// need that here, because BOTH the pre-patch and the post-patch instruction
// are correct:
//   - a thread that still sees the old store instruction executes it, faults,
//     and is handled by HandleSegfault exactly as it is today;
//   - a thread that sees the new branch runs the stub.
// The patch is therefore a pure optimisation hint with no correctness-
// critical visibility deadline.  We still issue the tree's standard
// dcbst/sync/icbi/isync (copied verbatim from PPC64Dispatcher.cpp:941) on the
// patched word so the patching thread and, in practice, its neighbours pick
// it up promptly.
//
// SOUNDNESS OF THE STORE ITSELF
// -----------------------------
// The HIT path runs ThreadManager::SoftInvalidateGuestCodeRange (or the
// legacy hard invalidate when SMCSoftInvalidate is off) to completion BEFORE
// performing the store, which is the same ordering the SIGSEGV handler uses:
// the delink happens before the store's effects can be observed, so a
// same-thread patch-then-call cannot reach stale host code.  The MISS path
// re-runs the authoritative GuestRangeOverlapsCompiledCode query under the
// lookup read lock -- the page filter is only a cheap pre-screen and is never
// trusted for the code-liveness answer, because a false negative there would
// be a silent correctness bug rather than a slowdown.
//
// INHERITED CAVEAT (same as v1): pwrite's kernel-side copy is not guaranteed
// single-copy-atomic the way a host `std` is.  Accepted for the same reason.
//
// Flag off => nothing below is allocated, nothing is patched, no filter
// counter is touched; behaviour is byte-identical to the flag-off tree.
// ===========================================================================

#include <cstddef>
#include <cstdint>

namespace FEXCore::Core {
struct CpuStateFrame;
struct InternalThreadState;
} // namespace FEXCore::Core

namespace FEX::HLE::SMCBackpatch {

#ifdef ARCHITECTURE_ppc64le

/// One-time arm/disarm from SyscallHandler construction. Off => every entry
/// point below is a predictable-false branch on a relaxed atomic bool.
void SetEnabled(bool Enabled);
bool IsEnabled();

/// Page filter maintenance. `Base`/`Size` are host-page granular guest
/// addresses. Protected() is called where mtrack installs PROT_READ
/// (MarkGuestExecutableRange), Unprotected() where that protection is
/// dropped (the fault handler's unprotect callback, guest munmap/mprotect).
///
/// Accuracy requirements are deliberately one-sided: an over-count sends the
/// stub to the (correct, slower) helper, an under-count sends it to a native
/// store that simply faults and is handled by HandleSegfault as today.
/// Neither direction can produce a wrong result.
void NotePagesProtected(uint64_t Base, uint64_t Size);
void NotePagesUnprotected(uint64_t Base, uint64_t Size);

/// Attempt to backpatch the store at host address StorePC.
/// Returns nullptr on success, or a short reason tag for SMC_AUDIT on refusal.
const char* TryBackpatchStore(FEXCore::Core::InternalThreadState* Thread, uint64_t StorePC);

#endif // ARCHITECTURE_ppc64le

} // namespace FEX::HLE::SMCBackpatch
