// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC lazy invalidation   (FEX_SMCLAZYINVAL=1)
//
//   As originally written this option traded correctness for speed.  It no
//   longer does by default: FEX_SMCLAZYSCRUB (default 1) closes the
//   same-thread hole -- see "SAME-THREAD SOUNDNESS: THE SCRUB" at the bottom,
//   which supersedes the "ACCEPTED UNSOUNDNESS" section above it.
//   FEX_SMCLAZYSCRUB=0 restores the original unsound-but-faster behaviour and
//   is kept only for A/B measurement.
//
// ===========================================================================
//
// PROBLEM
// -------
// Even with v3 (soft-invalidate + validate-relink, see
// FEXCore/Source/Interface/Core/SMCSoftInvalidate.h) an SMC write fault still
// performs work *inside the signal handler*, on the writer's critical path:
// SoftInvalidateGuestCodeRange takes ThreadCreationMutex plus the exclusive
// CodeInvalidationMutex, walks every CodeBuffer's LookupCache, severs block
// links and moves entries to the retained table.  Measured on POWER8 the whole
// storm cycle is ~22us and the fault + delink + relink portion is ~17us of it;
// removing only the recompile bought +35% on smcstorm/falseshare.  The writer
// wants to get back to storing, and the invalidation it is being charged for
// is not needed until *something* is about to execute.
//
// DESIGN
// ------
//  1. SMC write fault on a PRIVATE tracked code page: record the page in a
//     global dirty-page set, unprotect it (exactly the mprotect legacy does),
//     and invalidate NOTHING.  Return.  The store retries and succeeds, and
//     the writer then runs at native speed -- no further faults on that page
//     until a drain re-arms protection.
//  2. Drain: for each dirty page, ThreadManager::SoftInvalidateGuestCodeRange.
//     That is v3's delink; the retained entries are hash-validated and
//     relinked-or-recompiled lazily at their next dispatch.
//  3. Drain does NOT re-protect.  It does not have to: SoftInvalidateRange
//     erases the page from GuestToHostMap::CodePages, so the next relink
//     (ContextImpl::TryRelinkSoftInvalidatedBlock) or fresh compile
//     (ContextImpl::CompileBlock) sees AddBlockExecutableRange return
//     NewPage==true and calls SyscallHandler::MarkGuestExecutableRange, which
//     is the one and only place mtrack write protection is installed.  So the
//     page becomes protected again exactly when live code reappears on it --
//     the same invariant v3 already relies on.
//  4. Drain points (all gated on an atomic count so an empty set costs one
//     relaxed load and a not-taken branch):
//       a. ContextImpl::CompileBlock, *before* it takes CodeInvalidationMutex
//          shared -- i.e. before any lookup or relink.  Any thread about to
//          run code it has not got in its L1 drains first.
//       b. FEX::HLE::SyscallHandler::HandleSyscall, at entry.
//       c. FEX::HLE::SignalDelegator::HandleGuestSignal, immediately before
//          the guest signal handler frame is built.
//  5. A hard invalidation of a dirty page (guest munmap/mmap-over/mremap/
//     mprotect) drops its record, exactly where FEX_SMCMPROTECTDEFER drops
//     its own: the unconditional InvalidateCodeRangeIfNecessary on those paths
//     is strictly stronger than the drain would have been.  A guest mprotect
//     that grants PROT_EXEC drains the range synchronously before the syscall
//     returns.
//
// Requires FEX_SMCSOFTINVALIDATE=1 and FEX_SMCCHECKS=mtrack; with anything
// else the option logs once and stays off.  Off => not one line of this runs
// and behaviour is byte-identical to whatever the other SMC options select.
//
// ACCEPTED UNSOUNDNESS  (FEX_SMCLAZYSCRUB=0 only -- see the scrub section
// below, which is the default and removes the same-thread part of this)
// ------------------------------------------------------------
// v3 is sound because the delink completes inside the SIGSEGV handler, before
// the faulting store is even retired: from the instant the store lands, no
// path reaches the old host code without going through CompileBlock, which
// re-hashes.  This option deletes exactly that guarantee.
//
//   *** A thread can execute a STALE translation of guest code between the ***
//   *** write that modified it and the next drain point.                   ***
//
// What bounds the exposure:
//
//   - This backend has NO block linking in the sense that matters here.  Every
//     block exit re-probes the L1 lookup table (PPC64LE
//     JIT/BranchOps.cpp DEF_OP(ExitFunction) -- verified), so removing a block
//     from lookup is a complete visibility barrier for anything that is not
//     *already running*.  A lazy scheme therefore only exposes blocks whose
//     translation is currently on-stack or hot-looping at the moment of the
//     write, plus L1 hits taken before the next drain.
//   - Cross-thread SMC is unaffected in contract terms: x86 requires the
//     executing processor to serialize (a branch is not enough) before running
//     cross-modified code, and every mechanism a guest uses to do that --
//     syscall, signal, or dispatching code it has not run before -- is a drain
//     point here.
//   - Same-thread SMC is where we knowingly stretch the contract.  x86 says a
//     same-thread patch is visible at the next branch; we say it is visible at
//     the next drain point.  Patch -> call is safe whenever the call misses L1
//     (the target was never compiled, or was invalidated by an earlier drain),
//     because the miss lands in CompileBlock and CompileBlock drains first.
//
//   *** THE KNOWN EXPOSURE: same-thread patch-then-call that HITS L1 on an ***
//   *** already-compiled, not-yet-drained block runs the STALE code.       ***
//
//     That is precisely smcstorm's `patchloop` shape (patch an immediate in a
//     tiny stub, then call the stub, in a tight loop with no intervening
//     syscall).  **With FEX_SMCLAZYSCRUB=0, smcstorm/patchloop's checksum may
//     legitimately FAIL.  That is the accepted, expected outcome of turning
//     the scrub off and NOT a bug.**  Any guest doing runtime codegen in that
//     shape (Mono/.NET tiering-up, JS JIT patch points, game scripting VMs)
//     can miscompute or crash in that configuration.
//
//     With the default FEX_SMCLAZYSCRUB=1 this exposure is closed; see
//     "SAME-THREAD SOUNDNESS: THE SCRUB" below.
//
// Nothing here can corrupt FEX itself: soft-invalidation never frees host
// code, so a stale block is stale-but-valid machine code operating on the
// guest's own state, exactly as a legacy in-flight block is.  The damage is
// confined to guest semantics.
//
//
// SAME-THREAD SOUNDNESS: THE SCRUB   (FEX_SMCLAZYSCRUB=1, the default)
// --------------------------------------------------------------------
// x86 only ever promised SMC coherence to the *modifying* processor.  Code
// modified by one logical processor and executed by another is
// "cross-modifying code" and the architecture requires the executing processor
// to perform a serializing operation before running it; a plain branch is not
// enough, on real hardware either.  So lazy invalidation does not have to
// invalidate globally at fault time.  It only has to guarantee:
//
//   *** after a store fault on thread T dirties page P, thread T's NEXT   ***
//   *** dispatch into any block drains the deferred set first.            ***
//
// Other threads may lawfully keep running stale translations until one of
// their own drain points, and every mechanism a guest has for the serializing
// event x86 demands -- a syscall, a signal, or dispatching code it has not run
// before -- IS one of those drain points.
//
// The guarantee is implemented in two halves:
//
//   1. FAULT SIDE.  SyscallsSMCTracking.cpp, in the lazy branch of
//      HandleSegfault, calls Context::ScrubThreadLookupCacheForLazySMC on the
//      faulting thread.  That zeroes THIS thread's entire L1 lookup table
//      (LookupCache::ScrubForLazySMC -- one madvise(MADV_DONTNEED) on the L1
//      mapping, no lock, no allocation, signal-safe) and sets a per-thread
//      "owes a drain" flag inside the same per-thread LookupCache object.
//      A full flush rather than a per-page one: the fault already costs
//      microseconds, and the page->block direction is not indexable from L1
//      without the write lock this handler must not take.
//
//   2. LOOKUP SIDE.  With L1 empty, the thread cannot resolve ANY guest RIP
//      inline: the dispatcher's probe (PPC64Dispatcher.cpp) and every block's
//      inlined exit probe (BranchOps.cpp DEF_OP(ExitFunction)) both miss and
//      branch to PPC64JITCore::ExitFunctionLink.  That function now, BEFORE it
//      takes CodeInvalidationMutex and consults the shared L2/L3, consumes the
//      flag and runs the drain.  Only then does it look anything up -- so the
//      lookup it performs is against a set from which the dirtied page's
//      blocks have already been soft-invalidated, and a patched block
//      re-hashes and recompiles instead of being republished into L1.
//
// Why the L1 flush alone is not enough, and the ordering in (2) is the whole
// point: L2/L3 are shared and were never scrubbed, so an L1 miss that went
// straight to L2 would simply re-publish the stale translation.  The flush
// buys nothing except the guaranteed trip through (2); (2) is where the
// correctness is.
//
// Why this is complete on PPC64LE and not on Arm64: this backend has no block
// linking.  There is no jump thunk, no ExitFunctionLinkData, no return-address
// predictor stack (BranchOps.cpp's DEF_OP(ExitFunction) header says so; the
// backend's non-use of the CallRet stack is noted in JIT/PPC64LE/JIT.cpp).
// Every single block-to-block transfer re-probes L1.  Therefore "L1 is empty"
// really does mean "the next transfer of control leaves translated code".
// Arm64 patches callsites to branch directly between blocks, so the same
// scrub would leave a thread inside a linked chain running stale code; the
// hook exists there for parity but the soundness claim is PPC64LE-only.
//
// What the scrub still does NOT cover, by design:
//   - The block the faulting thread is CURRENTLY executing runs to its next
//     exit before the scrub can matter.  Identical to legacy invalidation,
//     which also cannot recall an in-flight block, and handled by the
//     pre-existing single-instruction-block re-execution path at the tail of
//     HandleSegfault for the case where the store hits the current block.
//   - Cross-thread modification with no serializing event on the reader.  Not
//     a regression: x86 does not guarantee that either.
//   - A store that FEX never sees as a fault at all (a page unprotected by an
//     earlier lazy fault and not yet drained can be written repeatedly with no
//     further faults).  That is the amortization the whole option is built on;
//     it is safe because the FIRST such store on that page already scrubbed
//     this thread and left the drain owed, and the debt is only cleared by a
//     drain that soft-invalidates every recorded page.
//
// Cost model: the scrub is paid once per fault, on the writer, and it is a
// single syscall.  The drain is paid at the writer's next dispatch, and only
// then.  A writer that stores into a page and never re-dispatches (smcstorm's
// falseshare and crossthread shapes) pays the syscall and nothing else, which
// is why lazy's speedup is expected to survive there while patchloop -- which
// re-dispatches into the page it just wrote, every iteration, and is exactly
// the case that requires the drain -- becomes correct.
//
// POWER8: no codegen is involved.  Pure C++ runtime code.
// ===========================================================================

namespace FEX::HLE::SMCLazy {

// Tag for the FEX_SMC_AUDIT batch lines, so a trace shows which drain point
// paid for which pages.
enum class DrainPoint {
  CompileBlock,
  Syscall,
  GuestSignal,
  MprotectExec,
};

inline const char* DrainPointName(DrainPoint Point) {
  switch (Point) {
  case DrainPoint::CompileBlock: return "compile";
  case DrainPoint::Syscall: return "syscall";
  case DrainPoint::GuestSignal: return "gsignal";
  case DrainPoint::MprotectExec: return "mprotect-exec";
  }
  return "unknown";
}

} // namespace FEX::HLE::SMCLazy
