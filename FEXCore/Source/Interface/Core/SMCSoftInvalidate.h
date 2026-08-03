// SPDX-License-Identifier: MIT
#pragma once

// ===========================================================================
// SMC v3: soft-invalidate + validate-relink   (FEX_SMCSOFTINVALIDATE=1)
// ===========================================================================
//
// PROBLEM
// -------
// mtrack SMC handling write-protects every guest page that holds translated
// code.  A guest store to such a page faults; the legacy handler invalidates
// every block on the page, unprotects the page, and lets the store retry.  The
// unprotect amortizes a burst of stores to a single fault, but the price is an
// unconditional full recompile of everything on the page -- even when the
// burst never touched a single compiled byte (data and code sharing a page),
// and even when the "modification" rewrote the same bytes.  Measured on POWER8
// the storm cycle is ~22us; smcstorm/falseshare runs 376x slower than native
// and CP2077's runtime-codegen arena burns ~55K invalidations.
//
// DESIGN
// ------
//  1. At compile time, hash the block's guest source bytes (xxhash XXH3) and
//     store the hash + the guest extent alongside the block's lookup metadata
//     (GuestToHostMap::BlockEntry).
//  2. On an SMC write fault, SOFT-invalidate the page: sever inbound direct
//     block links, remove each block from the L1/L2/L3 lookup structures, and
//     move its BlockEntry (host code pointer, code page list, hash) into a
//     retained side table.  The compiled host code is NOT freed.  Then
//     unprotect the page exactly as legacy does, so the rest of the burst runs
//     fault-free.
//  3. The next time an affected guest RIP is dispatched, every fast path
//     misses and the slow path (ContextImpl::CompileBlock) runs.  It takes the
//     retained entry, re-hashes the current guest bytes, and:
//       - hash matches  -> re-publish the retained host code into the lookup
//         caches (microseconds, no compiler involved), or
//       - hash differs  -> discard the retained metadata and compile normally.
//  4. Relinking/recompiling re-registers the block's guest code pages, which
//     re-arms mtrack write protection on them through the ordinary
//     MarkGuestExecutableRange path.  Code on the page is live again exactly
//     when it is protected again.
//
// Flag off => not one of the above runs; behavior is byte-identical to legacy.
//
// SOUNDNESS
// ---------
// (a) Same-thread patch-then-call must observe the new code.
//     Visibility of a translated block is gated entirely on lookup: the JIT
//     dispatcher probes L1, then (under the lookup lock) L2 and L3/BlockList,
//     then calls CompileBlock.  Soft-invalidation removes the block from all
//     three, severs direct block links, and zeroes the CallRet return-address
//     predictor stack (via the unmodified InvalidateThreadCachedCodeRange),
//     and it does all of that inside the SIGSEGV handler, before the handler
//     returns and the faulting store is retried.  So from the instant the
//     store retires, no path reaches the old host code without going through
//     CompileBlock, and CompileBlock re-hashes.  A patched block therefore
//     always mismatches and recompiles before it can execute.  This is the
//     same visibility point legacy uses; the only change is that a matching
//     hash short-circuits the compiler.
//
// (b) Cross-thread: another thread may be executing a soft-invalidated block.
//     Soft-invalidation never frees host code.  Neither does legacy: FEX has
//     no per-block code deallocator at all -- GuestToHostMap::Erase drops
//     metadata only, and host code memory is reclaimed solely when an entire
//     CodeBuffer is retired (ClearCodeCache), which is the tree's existing
//     safe-deletion path and is unchanged here.  A hash mismatch takes exactly
//     that legacy route: drop the metadata, compile a fresh block into the
//     current CodeBuffer.  An in-flight thread therefore keeps running valid
//     (if stale) host code to its next block exit, where it re-dispatches --
//     identical to what legacy invalidation does to an in-flight thread.
//     GuestToHostMap::ClearCache clears the retained table, so a CodeBuffer
//     swap can never leave a retained entry pointing into freed code.
//
// (c) Linked-block jumps.  Blocks branch directly to each other via
//     ExitFunctionLink, bypassing dispatch.  Legacy severs those links in
//     GuestToHostMap::Erase by running each registered BlockDelinkerFunc for
//     the destination.  Soft-invalidation calls the identical
//     SeverBlockLinks() helper (factored out of Erase) before retaining the
//     entry, so no inbound direct branch survives.  Links are re-established
//     lazily by ExitFunctionLink after the block is relinked/recompiled.
//
// (d) Locking.  Everything here runs under the tree's existing two locks and
//     adds no new ones.  The order relied on is:
//
//         VMATracking.Mutex  ->  ThreadCreationMutex  ->  CodeInvalidationMutex
//                            ->  GuestToHostMap::Lock (LookupCache token)
//
//     Soft-invalidation runs from ThreadManager::SoftInvalidateGuestCodeRange,
//     a byte-for-byte copy of the legacy InvalidateGuestCodeRange path
//     (ReleaseAllPendingSharedLocks, ThreadCreationMutex, then the
//     steal-capable exclusive CodeInvalidationMutex), so it holds the same
//     locks in the same order legacy already does from the same call site.
//     Relink runs inside CompileBlock, which already holds
//     CodeInvalidationMutex *shared*; it then takes the lookup write lock and
//     calls MarkGuestExecutableRange (which takes VMATracking.Mutex shared) --
//     the same sequence, in the same order, a fresh compile performs today.
//     Because CompileBlock holds the shared side of CodeInvalidationMutex for
//     its whole body and every (soft-)invalidation takes the exclusive side,
//     relink and invalidation are mutually exclusive: a retained entry cannot
//     be relinked while a concurrent munmap/mprotect is purging it.
//
//     The v2 hazard is explicitly avoided: nothing is drained or invalidated
//     from inside MarkGuestExecutableRange, whose callers hold a *live,
//     continuing* shared CodeInvalidationMutex that InvalidateGuestCodeRange
//     would forcibly drop out from under them via ReleaseAllPendingSharedLocks.
//
// (e) Stale-metadata purge.  A retained entry names guest bytes that must
//     still be readable and still mean the same thing.  GuestToHostMap::
//     InvalidateRange -- the funnel for every hard invalidation, i.e. munmap,
//     mremap, mprotect, shmdt, custom-IR removal -- drops retained entries
//     covering the range as well, keyed off a page index that mirrors
//     CodePages.  So a retained block whose memory is unmapped is gone before
//     anything can hash it.
//
// (f) What is hashed.  [DecodedMinAddress, DecodedMaxAddress) is the exact
//     span of guest bytes the frontend decoded (multiblock included), but with
//     multiblock the span can jump over unrelated (possibly unmapped) memory,
//     so the hash covers only the parts of that span that fall inside the
//     block's own registered code pages -- precisely the pages mtrack
//     protects and the pages the purge above tracks.  Blocks with no tracked
//     code pages, or with an implausibly large span, are simply not eligible
//     for retention and take the legacy hard-invalidate path.
//
// RESIDUAL RISK (identical to legacy, called out for review)
//   Between hashing the guest bytes at compile/relink time and re-arming the
//   page's write protection, a concurrent guest store on another thread is
//   invisible.  Legacy has exactly the same window (it decodes, compiles, then
//   protects) and x86 requires a serializing event for cross-modifying code,
//   so this is unchanged, not newly introduced.
//
// POWER8: no codegen is involved.  This is pure C++ runtime code.
// ===========================================================================

#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/vector.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <xxhash.h>

namespace FEXCore::SMC {

// Guest blocks whose decoded span exceeds this are not eligible for retention.
// Multiblock can produce a min..max span far larger than the code it actually
// decoded (a far forward branch inside the block), and hashing that span would
// be both slow and needlessly fragile.  64KiB comfortably covers a MaxInst
// block of real code.
constexpr uint64_t kMaxHashableGuestSpan = 64 * 1024;

// True if a block with this decoded span and code-page set can be hashed, and
// therefore soft-invalidated instead of hard-invalidated.
inline bool IsHashableBlock(uint64_t GuestSpan, size_t NumCodePages) {
  return GuestSpan != 0 && NumCodePages != 0 && GuestSpan <= kMaxHashableGuestSpan;
}

/**
 * @brief Content hash of a compiled block's guest source bytes.
 *
 * Hashes the intersection of [Start, Start+Length) with each of the block's
 * registered guest code pages, in ascending page order, folding the running
 * result and the page address into the seed so that neither reordering nor a
 * change of chunk boundaries can alias.
 *
 * CodePages must be the block's own page list (BlockEntry::CodePages, which
 * originates from the frontend's DecodedBlockInfo::CodePages -- an ordered
 * set, so ascending here).  All of those pages are mapped whenever this runs:
 * unmapping any of them purges the block first (see the design note above).
 */
inline uint64_t HashGuestBlock(const fextl::vector<uint64_t>& CodePages, uint64_t Start, uint64_t Length) {
  const uint64_t End = Start + Length;
  uint64_t Hash = Length;

  for (uint64_t Page : CodePages) {
    const uint64_t PageEnd = Page + FEXCore::Utils::FEX_PAGE_SIZE;
    const uint64_t ChunkStart = std::max(Page, Start);
    const uint64_t ChunkEnd = std::min(PageEnd, End);
    if (ChunkStart >= ChunkEnd) {
      // Page holds no decoded bytes of this block (possible when the block's
      // span was clamped); skip it, but keep it in the seed so that the set of
      // pages is itself covered.
      Hash = XXH3_64bits_withSeed(&Page, sizeof(Page), Hash);
      continue;
    }

    Hash = XXH3_64bits_withSeed(&ChunkStart, sizeof(ChunkStart), Hash);
    Hash = XXH3_64bits_withSeed(reinterpret_cast<const void*>(ChunkStart), ChunkEnd - ChunkStart, Hash);
  }

  return Hash;
}

} // namespace FEXCore::SMC
