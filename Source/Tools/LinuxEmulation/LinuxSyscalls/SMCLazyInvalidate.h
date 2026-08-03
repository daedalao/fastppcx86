// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC lazy invalidation   (FEX_SMCLAZYINVAL=1)
//
//   *** THIS OPTION DELIBERATELY RELAXES CORRECTNESS FOR SPEED. ***
//   Read "ACCEPTED UNSOUNDNESS" below before enabling it anywhere.
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
// ACCEPTED UNSOUNDNESS  (this is the whole point of the option)
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
//     syscall).  **smcstorm/patchloop's checksum may legitimately FAIL under
//     FEX_SMCLAZYINVAL=1.  That is an accepted, expected outcome of this
//     option and NOT a bug in it.**  Any guest doing runtime codegen in that
//     shape (Mono/.NET tiering-up, JS JIT patch points, game scripting VMs)
//     can miscompute or crash with this option on.
//
// Nothing here can corrupt FEX itself: soft-invalidation never frees host
// code, so a stale block is stale-but-valid machine code operating on the
// guest's own state, exactly as a legacy in-flight block is.  The damage is
// confined to guest semantics.
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
