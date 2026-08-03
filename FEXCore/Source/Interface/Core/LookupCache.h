// SPDX-License-Identifier: MIT
#pragma once
#include "Interface/Context/Context.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/SMCCodeGranules.h"
#include <atomic>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/SHMStats.h>
#include <FEXCore/Utils/WritePriorityMutex.h>

#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory_resource.h>
#include <FEXCore/fextl/robin_map.h>
#include <FEXCore/fextl/robin_set.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/memory_resource.h>

#include <cstdint>
#include <cstring>
#include <stddef.h>
#include <optional>
#include <utility>
#include <mutex>
#include <sys/mman.h>

namespace FEXCore {
struct LookupCacheBaseLockToken {
protected:
  // Protected constructor - only derived classes can construct
  LookupCacheBaseLockToken() = default;
};

struct LookupCacheWriteLockToken : public LookupCacheBaseLockToken {
private:
  // Only constructible by GuestToHostMap
  friend struct GuestToHostMap;
  LookupCacheWriteLockToken(FEXCore::Utils::WritePriorityMutex::Mutex& Mutex)
    : Lock {Mutex} {}
  std::lock_guard<FEXCore::Utils::WritePriorityMutex::Mutex> Lock;
};

struct LookupCacheReadLockToken : public LookupCacheBaseLockToken {
private:
  // Only constructible by GuestToHostMap
  friend struct GuestToHostMap;
  LookupCacheReadLockToken(FEXCore::Utils::WritePriorityMutex::Mutex& Mutex)
    : Lock {Mutex} {}
  std::shared_lock<FEXCore::Utils::WritePriorityMutex::Mutex> Lock;
};

struct GuestToHostMap {
  FEXCore::Utils::WritePriorityMutex::Mutex Lock {};

  [[nodiscard]]
  LookupCacheWriteLockToken AcquireWriteLock() {
    return LookupCacheWriteLockToken {Lock};
  }

  [[nodiscard]]
  LookupCacheReadLockToken AcquireReadLock() {
    return LookupCacheReadLockToken {Lock};
  }

  struct BlockLinkTag {
    uint64_t GuestDestination;
    FEXCore::Context::ExitFunctionLinkData* HostLink;

    bool operator<(const BlockLinkTag& other) const {
      if (GuestDestination < other.GuestDestination) {
        return true;
      } else if (GuestDestination == other.GuestDestination) {
        return HostLink < other.HostLink;
      } else {
        return false;
      }
    }
  };

  // Use a monotonic buffer resource to allocate both the std::pmr::map and its members.
  // This allows us to quickly clear the block link map by clearing the monotonic allocator.
  // If we had allocated the block link map without the MBR, then clearing the map would require slowly
  // walking each block member and destructing objects.
  //
  // This makes `BlockLinks` look like a raw pointer that could memory leak, but since it is backed by the MBR, it won't.
  fextl::pmr::named_monotonic_page_buffer_resource BlockLinks_mbr;
  using BlockLinksMapType = std::pmr::map<BlockLinkTag, FEXCore::Context::BlockDelinkerFunc>;
  fextl::unique_ptr<std::pmr::polymorphic_allocator<std::byte>> BlockLinks_pma;
  BlockLinksMapType* BlockLinks;

  struct BlockEntry {
    uint64_t HostCode;
    // Absolute pointer to the start of the JIT block (containing the
    // JITCodeHeader). Symmetric with HostCode above — buffer-relative
    // conversion happens only when the cache is serialized. Needed by
    // CodeCache::Validate to locate the header on ppc64le, where
    // BlockBegin != HostCode - sizeof(JITCodeHeader) (there is a
    // FillStaticRegs / EmitEntryPoint sequence between them, ~200-270
    // bytes). On ARM64 the two are exactly 4 bytes apart, but we store
    // it explicitly rather than assuming.
    uint64_t BlockBegin;
    fextl::vector<uint64_t> CodePages;

    // SMC v3 (FEX_SMCSOFTINVALIDATE): content hash of the block's guest source
    // bytes plus the guest extent it was taken over. GuestRangeLength == 0
    // means "no hash recorded" (code-cache-loaded blocks, custom IR, blocks
    // with no tracked code pages, flag off) and makes the block ineligible for
    // soft-invalidation -- it takes the legacy hard-invalidate path instead.
    // See Interface/Core/SMCSoftInvalidate.h for the full design note.
    uint64_t GuestRangeStart = 0;
    uint64_t GuestRangeLength = 0;
    uint64_t GuestHash = 0;

    // SMC Idea 4 (FEX_SMCSEMANTICPATCH): the block's direct rel32 branch
    // immediates (guest side) and the host windows its ExitFunctions baked
    // constant destination RIPs into. Both empty => block ineligible for
    // semantic patching, which is the default for cache-loaded blocks, custom
    // IR, and every block compiled with the flag off.
    // See Interface/Core/SMCSemanticPatch.h.
    FEXCore::SMC::BranchImmSites BranchImmSites;
    FEXCore::SMC::ExitRIPSites ExitRIPSites;

    // SMC Idea 4, mov-immediate half: the block's guest mov-immediate fields
    // and the host windows their tagged constants were materialised into.
    // MovImmWindow::SiteIndex indexes MovImmSites, so the claim is resolved by
    // identity rather than by value. Both empty => ineligible, same rules.
    FEXCore::SMC::MovImmSites MovImmSites;
    FEXCore::SMC::MovImmWindows MovImmWindows;
  };

  fextl::robin_map<uint64_t, BlockEntry> BlockList;

  fextl::map<uint64_t, fextl::vector<uint64_t>> CodePages;

  // SMC v3: blocks that have been soft-invalidated. Their host code is still
  // live in the CodeBuffer and their metadata is intact, but they are absent
  // from BlockList/L1/L2 so every dispatch of them misses into CompileBlock,
  // which re-hashes and either relinks or recompiles them.
  // RetainedCodePages mirrors CodePages for these entries so that a later hard
  // invalidation (munmap/mprotect/...) can purge them by address range.
  fextl::map<uint64_t, BlockEntry> RetainedBlocks;
  fextl::map<uint64_t, fextl::robin_set<uint64_t>> RetainedCodePages;

  // SMC Idea 3: lock-free "does this guest range hold code?" accelerator for the
  // SMC store fast paths. Mirrors (conservatively) the CodePages/BlockList
  // content maintained above; consulted only as a fast negative gate, with
  // RangeOverlapsCompiledCode below as the authoritative fallback.
  // See Interface/Core/SMCCodeGranules.h.
  FEXCore::SMC::CodeGranuleBitmap CodeGranules;

  GuestToHostMap();

  // Adds to Guest -> Host code mapping
  const BlockEntry& AddBlockMapping(uint64_t Address, uint64_t BlockBegin, const fextl::vector<uint64_t>& CodePages, void* HostCode,
                                    const LookupCacheWriteLockToken&, uint64_t GuestRangeStart = 0, uint64_t GuestRangeLength = 0,
                                    uint64_t GuestHash = 0, const FEXCore::SMC::BranchImmSites& BranchImmSites = {},
                                    const FEXCore::SMC::ExitRIPSites& ExitRIPSites = {}, const FEXCore::SMC::MovImmSites& MovImmSites = {},
                                    const FEXCore::SMC::MovImmWindows& MovImmWindows = {}) {
    // This may replace an existing mapping
    // NOTE: Generally no previous entry should exist, however there is one exception:
    //       If the backend updates the active thread's CodeBuffer, the new associated LookupCache
    //       may already contain the block address. Since is comparatively rare, we'll just leak
    //       one of the two blocks in this case.
    return BlockList
      .insert_or_assign(Address, BlockEntry {(uintptr_t)HostCode, BlockBegin, CodePages, GuestRangeStart, GuestRangeLength, GuestHash,
                                             BranchImmSites, ExitRIPSites, MovImmSites, MovImmWindows})
      .first->second;
  }

  // Token widened to the base type: reading BlockList needs at least the
  // shared lock, and the write token grants a strict superset of that.
  // PPC64LE's block linker re-validates GuestRIP -> HostCode under the final
  // WRITE lock immediately before backpatching (patching against a stale
  // mapping would permanently link a branch to a translation of guest code
  // that has since been rewritten), which requires calling this with a
  // LookupCacheWriteLockToken.
  const BlockEntry* FindBlock(uint64_t Address, const LookupCacheBaseLockToken&) {
    auto HostCode = BlockList.find(Address);
    if (HostCode == BlockList.end()) {
      return nullptr;
    }
    return &HostCode->second;
  }

  // Runs the delinker for every direct (dispatch-bypassing) block link that
  // targets this guest address, so no other block can branch straight into its
  // host code anymore. Factored out of Erase so soft-invalidation can reuse the
  // exact same severing behaviour.
  void SeverBlockLinks(uint64_t Address) {
    auto lower = BlockLinks->lower_bound({Address, nullptr});
    auto upper = BlockLinks->upper_bound({Address, reinterpret_cast<FEXCore::Context::ExitFunctionLinkData*>(UINTPTR_MAX)});
    for (auto it = lower; it != upper; it = BlockLinks->erase(it)) {
      it->second(it->first.HostLink);
    }
  }

  bool Erase(uint64_t Address, const LookupCacheWriteLockToken&) {
    // Sever any links to this block
    SeverBlockLinks(Address);

    // Remove from BlockList
    return BlockList.erase(Address) != 0;
  }

  // --- SMC v3 soft-invalidate -----------------------------------------------
  // All of these require the write lock to be held (token parameter enforces on
  // the public entry points; the *Locked helpers are called from them).

  void DropRetainedBlockLocked(uint64_t Address) {
    auto it = RetainedBlocks.find(Address);
    if (it == RetainedBlocks.end()) {
      return;
    }

    for (uint64_t Page : it->second.CodePages) {
      auto PageIt = RetainedCodePages.find(Page >> 12);
      if (PageIt != RetainedCodePages.end()) {
        PageIt->second.erase(Address);
        if (PageIt->second.empty()) {
          RetainedCodePages.erase(PageIt);
        }
      }
    }

    RetainedBlocks.erase(it);
  }

  // Removes a block from the lookup structures without discarding its compiled
  // code: severs inbound links, moves the entry into the retained table, and
  // erases it from BlockList so every dispatch misses into CompileBlock.
  // Blocks that carry no content hash cannot be revalidated and are simply
  // erased, exactly like legacy invalidation.
  void SoftEraseBlock(uint64_t Address, const LookupCacheWriteLockToken&) {
    auto BlockIt = BlockList.find(Address);
    if (BlockIt == BlockList.end()) {
      return;
    }

    SeverBlockLinks(Address);

    if (BlockIt->second.GuestRangeLength == 0 || BlockIt->second.CodePages.empty()) {
      BlockList.erase(Address);
      return;
    }

    // Drop any older retained copy first so the page index stays consistent.
    DropRetainedBlockLocked(Address);

    for (uint64_t Page : BlockIt->second.CodePages) {
      RetainedCodePages[Page >> 12].insert(Address);
    }
    RetainedBlocks.insert_or_assign(Address, std::move(BlockIt->second));
    BlockList.erase(Address);
  }

  // Removes retained entries whose guest code pages intersect the range. Called
  // from every hard invalidation so that unmapped/remapped/reprotected guest
  // memory can never be revalidated against a stale hash.
  void DropRetainedRange(uint64_t Start, uint64_t Length, const LookupCacheWriteLockToken&) {
    if (RetainedCodePages.empty()) {
      return;
    }

    auto lower = RetainedCodePages.lower_bound(Start >> 12);
    auto upper = RetainedCodePages.upper_bound((Start + Length - 1) >> 12);

    fextl::vector<uint64_t> Doomed;
    for (auto it = lower; it != upper; ++it) {
      Doomed.insert(Doomed.end(), it->second.begin(), it->second.end());
    }

    // DropRetainedBlockLocked mutates RetainedCodePages, hence the two passes.
    for (uint64_t Address : Doomed) {
      DropRetainedBlockLocked(Address);
    }
  }

  // Hands the retained entry for this address (if any) to the caller and
  // removes it from the retained table. The caller (ContextImpl::CompileBlock)
  // either re-publishes it after a successful hash check, or drops it on the
  // floor and compiles a fresh block.
  std::optional<BlockEntry> TakeRetainedBlock(uint64_t Address, const LookupCacheWriteLockToken&) {
    auto it = RetainedBlocks.find(Address);
    if (it == RetainedBlocks.end()) {
      return std::nullopt;
    }

    BlockEntry Out = std::move(it->second);
    RetainedBlocks.erase(it);

    for (uint64_t Page : Out.CodePages) {
      auto PageIt = RetainedCodePages.find(Page >> 12);
      if (PageIt != RetainedCodePages.end()) {
        PageIt->second.erase(Address);
        if (PageIt->second.empty()) {
          RetainedCodePages.erase(PageIt);
        }
      }
    }

    return Out;
  }

  // Soft-invalidate every block registered on the pages covering the range.
  // Mirrors InvalidateRange, but retains instead of erasing.
  void SoftInvalidateRange(uint64_t Start, uint64_t Length) {
    auto lk = AcquireWriteLock();

    auto lower = CodePages.lower_bound(Start >> 12);
    auto upper = CodePages.upper_bound((Start + Length - 1) >> 12);

    for (auto it = lower; it != upper; it++) {
      for (const auto& Entry : it->second) {
        SoftEraseBlock(Entry, lk);
      }
      // SMC Idea 3 CLEAR POINT (soft): the page's blocks just left BlockList,
      // so no granule on it is backed by a live block anymore. A relink
      // (Core.cpp TryRelinkSoftInvalidatedBlock) re-registers the page through
      // AddBlockExecutableRange and re-sets the bits.
      if (CodeGranules.Enabled()) {
        CodeGranules.ClearPage(it->first << 12);
      }
    }
    CodePages.erase(lower, upper);
  }

  // Returns true if any *compiled block's guest bytes* intersect
  // [Start, Start+Length). Used by the SMC store-emulation fast path to
  // distinguish a write into code (must invalidate, take the slow path) from a
  // write that merely lands on the same page as code (false sharing — safe to
  // emulate and keep every block).
  //
  // Guest extent is recovered per block via
  // BlockBegin -> JITCodeHeader::OffsetToBlockTail -> JITCodeTail{RIP, GuestSize},
  // the same walk CodeCache::Validate does. A block whose tail cannot be
  // trusted is treated as overlapping (conservative: false positives cost a
  // page invalidation, false negatives would execute stale code).
  //
  // Must be called with at least the read lock held (token parameter enforces).
  bool RangeOverlapsCompiledCode(uint64_t Start, uint64_t Length, const LookupCacheBaseLockToken&) const {
    const uint64_t End = Start + Length;
    auto lower = CodePages.lower_bound(Start >> 12);
    auto upper = CodePages.upper_bound((End - 1) >> 12);

    for (auto it = lower; it != upper; it++) {
      for (const auto& EntryAddr : it->second) {
        auto Block = BlockList.find(EntryAddr);
        if (Block == BlockList.end()) {
          // Stale page-vector entry (block already erased via another page).
          continue;
        }
        const auto* Header = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeHeader*>(Block->second.BlockBegin);
        const auto* Tail =
          reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeTail*>(Block->second.BlockBegin + Header->OffsetToBlockTail);
        if (Tail->GuestSize == 0) {
          return true; // Unknown extent — be conservative.
        }
        if (Tail->RIP < End && (Tail->RIP + Tail->GuestSize) > Start) {
          return true;
        }
      }
    }
    return false;
  }

#ifdef ARCHITECTURE_ppc64le
  // --- SMC Idea 4 semantic patching ----------------------------------------
  // Outcome of planning a semantic patch over one lookup cache. Ordering
  // matters: the caller keeps the worst outcome seen across all code buffers.
  enum class SemanticPatchPlan {
    NoCandidate, // no compiled block on these pages claims the write
    Planned,     // every claiming block yielded an unambiguous single-word edit
    Decline,     // a claiming block could not be patched -- abandon entirely
  };

  /**
   * @brief Plan (but do not apply) the host-code edits for a semantic patch.
   *
   * For every compiled block registered on the written page, check whether the
   * guest range [Start, Start+Length) is exactly one of its recorded patchable
   * immediate fields -- the rel32 of a direct branch, or the immediate of a
   * mov-immediate. If it is, that block MUST be patchable or the whole attempt
   * is abandoned: leaving one copy stale would let a thread using that code
   * buffer keep using the old value.
   *
   * NewBytes holds the Length bytes the guest store is about to write; the old
   * and new values are derived from the claiming site's current guest bytes
   * overlaid with them. Guest memory is NOT touched here -- the caller performs
   * the store only after every buffer has planned successfully.
   *
   * *Reason receives a static audit tag whenever Decline is returned, and
   * *Kind the shape ("rel32"/"movimm"/"mixed") whenever anything was Planned.
   *
   * Requires the read lock; the caller additionally holds the exclusive
   * CodeInvalidationMutex, which is what keeps the host code buffers alive.
   */
  SemanticPatchPlan PlanSemanticPatch(uint64_t Start, uint64_t Length, const uint8_t* NewBytes,
                                      fextl::vector<FEXCore::SMC::WordPatch>& Out, const char** Reason, const char** Kind,
                                      const LookupCacheBaseLockToken&) const {
    const uint64_t End = Start + Length;
    auto lower = CodePages.lower_bound(Start >> 12);
    auto upper = CodePages.upper_bound((End - 1) >> 12);

    auto Result = SemanticPatchPlan::NoCandidate;

    // Claims of both shapes can land in one planning pass (two code buffers,
    // or two blocks covering the same bytes); the audit line reports "mixed"
    // rather than silently attributing the fault to one of them.
    const auto NoteKind = [Kind](const char* K) {
      if (*Kind == nullptr || ::strcmp(*Kind, K) == 0) {
        *Kind = K;
      } else {
        *Kind = "mixed";
      }
    };

    for (auto it = lower; it != upper; it++) {
      for (const auto& EntryAddr : it->second) {
        auto Block = BlockList.find(EntryAddr);
        if (Block == BlockList.end()) {
          // Stale page-vector entry (block already erased via another page).
          continue;
        }
        const auto& Entry = Block->second;

        // Does this block claim the write as one of its rel32 fields?
        const FEXCore::SMC::BranchImmSite* Claimed {};
        for (const auto& Site : Entry.BranchImmSites) {
          if (Start >= Site.ImmStart && End <= Site.ImmStart + 4) {
            Claimed = &Site;
            break;
          }
        }
        if (!Claimed) {
          // ... or as one of its mov-immediate fields?
          switch (PlanMovImmPatch(Entry, Start, End, NewBytes, Out, Reason)) {
          case SemanticPatchPlan::NoCandidate: break; // fall through to the unclaimed-cover check
          case SemanticPatchPlan::Decline:     return SemanticPatchPlan::Decline;
          case SemanticPatchPlan::Planned:
            NoteKind("movimm");
            Result = SemanticPatchPlan::Planned;
            continue;
          }

          // Nothing in this block claims the write, but the block may still have
          // TRANSLATED these guest bytes -- it can carry no metadata at all (a
          // code-cache-loaded block, a block whose site table overflowed) or
          // have decoded them at different instruction boundaries. Patching the
          // other blocks while leaving this one live would make two translations
          // of the same guest bytes disagree, with this one stuck on the old
          // value forever, since the page deliberately stays protected. That is
          // exactly what soundness note (b) forbids, so decline the whole
          // attempt and let the normal invalidation path deal with it.
          if (BlockTranslatedRange(Entry, Start, End)) {
            *Reason = "unclaimed-cover";
            return SemanticPatchPlan::Decline;
          }
          continue;
        }

        // Old target from the bytes still in guest memory; new target from the
        // same four bytes with the pending store overlaid.
        uint32_t OldRel {};
        ::memcpy(&OldRel, reinterpret_cast<const void*>(Claimed->ImmStart), sizeof(OldRel));
        uint32_t NewRel = OldRel;
        ::memcpy(reinterpret_cast<uint8_t*>(&NewRel) + (Start - Claimed->ImmStart), NewBytes, Length);

        const uint64_t OldTarget = FEXCore::SMC::Rel32Target(Claimed->InstEnd, OldRel);
        const uint64_t NewTarget = FEXCore::SMC::Rel32Target(Claimed->InstEnd, NewRel);

        if (Entry.ExitRIPSites.empty()) {
          // Compiled without the metadata (flag off at compile time, cap
          // exceeded, cache-loaded), so its baked constant cannot be located.
          *Reason = "no-exit-sites";
          return SemanticPatchPlan::Decline;
        }

        // Exactly one exit window may currently materialise OldTarget.
        FEXCore::SMC::WordPatch Patch {};
        bool NeedsWrite = false;
        size_t Matches = 0;
        for (const auto& Site : Entry.ExitRIPSites) {
          FEXCore::SMC::WordPatch Candidate {};
          bool CandidateNeedsWrite = false;
          switch (FEXCore::SMC::ClassifyRIPSite(Site.HostAddr, OldTarget, NewTarget, &Candidate, &CandidateNeedsWrite)) {
          case FEXCore::SMC::SiteMatch::NoMatch: continue;
          case FEXCore::SMC::SiteMatch::MultiWord:
            // The new RIP would need two or more of the five window words
            // rewritten, which cannot be published atomically to a thread
            // executing the block.
            *Reason = "multiword";
            return SemanticPatchPlan::Decline;
          case FEXCore::SMC::SiteMatch::Patchable:
            ++Matches;
            Patch = Candidate;
            NeedsWrite = CandidateNeedsWrite;
            break;
          }
        }

        if (Matches != 1) {
          // 0: the branch did not become a constant-destination exit (the
          //    target was folded into this compilation unit by multiblock, or
          //    the destination is register-computed).
          // >1: two exits bake the same RIP; patching either would be a guess.
          *Reason = Matches == 0 ? "no-matching-exit" : "ambiguous-exit";
          return SemanticPatchPlan::Decline;
        }

        if (NeedsWrite) {
          Out.push_back(Patch);
        }
        NoteKind("rel32");
        Result = SemanticPatchPlan::Planned;
      }
    }

    return Result;
  }

private:
  /**
   * @brief Does this block's translated guest extent overlap [Start, End)?
   *
   * Same JITCodeTail read RangeOverlapsCompiledCode uses, and equally
   * conservative: an unknown extent answers yes.
   */
  bool BlockTranslatedRange(const BlockEntry& Entry, uint64_t Start, uint64_t End) const {
    const auto* Header = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeHeader*>(Entry.BlockBegin);
    const auto* Tail = reinterpret_cast<const FEXCore::CPU::CPUBackend::JITCodeTail*>(Entry.BlockBegin + Header->OffsetToBlockTail);
    if (Tail->GuestSize == 0) {
      return true;
    }
    return Tail->RIP < End && (Tail->RIP + Tail->GuestSize) > Start;
  }

  /**
   * @brief The mov-immediate half of PlanSemanticPatch, for one block.
   *
   * Returns NoCandidate when this block does not claim the write, Planned when
   * it does and yielded an unambiguous edit (appended to Out unless the value
   * is unchanged), Decline when it claims it but cannot be patched.
   *
   * The claim is by containment, in either direction:
   *   * the store lies wholly inside the immediate field -- a partial patch,
   *     combined with the bytes already there (the rel32 rule); or
   *   * the store covers the whole field, and every byte it writes OUTSIDE the
   *     field is byte-identical to what is already there. This is the shape a
   *     real patcher uses when it publishes `b8 <imm32> c3` with one 8-byte
   *     store. A store that changes a byte outside the field is changing
   *     instructions, not immediates: it is not claimed, and the caller falls
   *     back to invalidation, which is what such a write deserves.
   *
   * Unlike the rel32 half, the host window is found by IDENTITY (the site index
   * the frontend tagged the IR constant with), not by value; the value check is
   * then a verification of the invariant rather than the lookup key. See the
   * mov-immediate section of Interface/Core/SMCSemanticPatch.h for why value
   * lookup would be unsound here.
   */
  SemanticPatchPlan PlanMovImmPatch(const BlockEntry& Entry, uint64_t Start, uint64_t End, const uint8_t* NewBytes,
                                    fextl::vector<FEXCore::SMC::WordPatch>& Out, const char** Reason) const {
    // Every site is examined, not just the first hit: a block whose decode
    // visited the same guest instruction twice (a jump into the middle of an
    // already-decoded run) holds two sites over the same bytes and two windows,
    // and patching one of them would leave the other stale.
    size_t ClaimedIndex = Entry.MovImmSites.size();
    size_t Claims = 0;
    for (size_t i = 0; i < Entry.MovImmSites.size(); ++i) {
      const auto& Site = Entry.MovImmSites[i];
      const uint64_t ImmEnd = Site.ImmStart + Site.ImmSize;

      if (Start >= Site.ImmStart && End <= ImmEnd) {
        ClaimedIndex = i;
        ++Claims;
        continue;
      }

      if (Start <= Site.ImmStart && End >= ImmEnd) {
        bool OutsideUnchanged = true;
        for (uint64_t Addr = Start; Addr < End; ++Addr) {
          if (Addr >= Site.ImmStart && Addr < ImmEnd) {
            continue;
          }
          if (*reinterpret_cast<const uint8_t*>(Addr) != NewBytes[Addr - Start]) {
            OutsideUnchanged = false;
            break;
          }
        }
        if (!OutsideUnchanged) {
          // The write reaches past this immediate and genuinely changes those
          // bytes. Stop looking: no site may claim a write that rewrites
          // instruction bytes.
          return SemanticPatchPlan::NoCandidate;
        }
        ClaimedIndex = i;
        ++Claims;
        continue;
      }
    }

    if (Claims == 0) {
      return SemanticPatchPlan::NoCandidate;
    }
    if (Claims > 1) {
      *Reason = "movimm-duplicate-site";
      return SemanticPatchPlan::Decline;
    }

    const auto& Site = Entry.MovImmSites[ClaimedIndex];
    const uint64_t ImmEnd = Site.ImmStart + Site.ImmSize;

    // Old value from the bytes still in guest memory; new value from those same
    // bytes with the part of the pending store that lands inside the field
    // overlaid. Both zero-extended, matching DecodeMovImmSite.
    const uint64_t OldValue = FEXCore::SMC::MovImmSiteValue(Site);
    uint64_t NewValue = OldValue;
    {
      const uint64_t OverlapStart = Start > Site.ImmStart ? Start : Site.ImmStart;
      const uint64_t OverlapEnd = End < ImmEnd ? End : ImmEnd;
      ::memcpy(reinterpret_cast<uint8_t*>(&NewValue) + (OverlapStart - Site.ImmStart), NewBytes + (OverlapStart - Start),
               OverlapEnd - OverlapStart);
    }

    // Exactly one window may belong to this site. Zero means the constant was
    // never materialised as tagged (folded, rematerialised away, deleted as
    // dead, or the dispatcher transformed the immediate); more than one means
    // it was rematerialised into several windows, and patching one of them
    // would leave the others stale.
    const FEXCore::SMC::MovImmWindow* Window {};
    size_t Windows = 0;
    for (const auto& W : Entry.MovImmWindows) {
      if (W.SiteIndex == ClaimedIndex) {
        Window = &W;
        ++Windows;
      }
    }
    if (Windows != 1) {
      *Reason = Windows == 0 ? "movimm-no-window" : "movimm-multi-window";
      return SemanticPatchPlan::Decline;
    }

    FEXCore::SMC::WordPatch Patch {};
    bool NeedsWrite = false;
    switch (FEXCore::SMC::ClassifyRIPSite(Window->HostAddr, OldValue, NewValue, &Patch, &NeedsWrite)) {
    case FEXCore::SMC::SiteMatch::NoMatch:
      // The window does not currently hold the value the guest bytes say it
      // should. The invariant is broken (a code buffer rotated under us, the
      // constant was transformed on the way to the backend, ...), so nothing
      // here is trustworthy.
      *Reason = "movimm-stale-window";
      return SemanticPatchPlan::Decline;
    case FEXCore::SMC::SiteMatch::MultiWord:
      // The new immediate would need two or more of the five window words
      // rewritten, which cannot be published atomically to a thread executing
      // the block. Typically a change in both 16-bit halves at once.
      *Reason = "movimm-multiword";
      return SemanticPatchPlan::Decline;
    case FEXCore::SMC::SiteMatch::Patchable: break;
    }

    if (NeedsWrite) {
      Out.push_back(Patch);
    }
    return SemanticPatchPlan::Planned;
  }

public:
#endif // ARCHITECTURE_ppc64le

  void InvalidateRange(uint64_t Start, uint64_t Length) {
    auto lk = AcquireWriteLock();

    auto lower = CodePages.lower_bound(Start >> 12);
    auto upper = CodePages.upper_bound((Start + Length - 1) >> 12);

    for (auto it = lower; it != upper; it++) {
      for (const auto& Entry : it->second) {
        Erase(Entry, lk);
      }
      // SMC Idea 3 CLEAR POINT (hard). Page-granular, matching the CodePages
      // erase below. Never per-block: several blocks share a 64-byte granule.
      if (CodeGranules.Enabled()) {
        CodeGranules.ClearPage(it->first << 12);
      }
    }
    CodePages.erase(lower, upper);

    // A hard invalidation supersedes any pending soft-invalidation of the same
    // guest memory: the bytes may be about to be unmapped or reused, so their
    // retained metadata (and the hash that would revalidate it) must go too.
    DropRetainedRange(Start, Length, lk);
  }

  void AddBlockLink(uint64_t GuestDestination, FEXCore::Context::ExitFunctionLinkData* HostLink,
                    const FEXCore::Context::BlockDelinkerFunc& delinker, const LookupCacheWriteLockToken&) {
    BlockLinks->insert({{GuestDestination, HostLink}, delinker});
  }

  // SMC Idea 3 SET POINT. This is the single choke point through which a guest
  // page becomes a tracked code page, so it is also where the granule bits go
  // in. GuestRangeStart/GuestRangeLength describe the block's decoded guest
  // extent; a zero length means "extent unknown" (cache-loaded blocks, custom
  // IR, callers with no hash) and sets every granule of the page. Callers must
  // invoke this BEFORE SyscallHandler::MarkGuestExecutableRange arms the page's
  // write protection -- see the ordering argument in SMCCodeGranules.h.
  bool AddBlockExecutableRange(const std::ranges::input_range auto& Addresses, uint64_t Start, uint64_t Length,
                               const LookupCacheWriteLockToken&, uint64_t GuestRangeStart = 0, uint64_t GuestRangeLength = 0) {
    bool rv = false;

    for (auto CurrentPage = Start >> 12, EndPage = (Start + Length - 1) >> 12; CurrentPage <= EndPage; CurrentPage++) {
      auto& CodePage = CodePages[CurrentPage];
      rv |= CodePage.empty();
      CodePage.insert(CodePage.end(), Addresses.begin(), Addresses.end());

      if (CodeGranules.Enabled()) {
        CodeGranules.SetPageRange(CurrentPage << 12, GuestRangeStart, GuestRangeLength);
      }
    }

    return rv;
  }

  void ClearCache(const LookupCacheWriteLockToken&);
};

class LookupCache {
public:
  struct LookupCacheEntry {
    uintptr_t HostCode;
    uintptr_t GuestCode;

    // Publish a new mapping with release ordering so that any reader that
    // observes the new GuestCode (the "key") is guaranteed to also observe
    // the new HostCode (the "data").  Mirrors ARM64's atomic-pair `stp`
    // semantics on architectures (PPC64LE, riscv64) that don't have a
    // store-pair instruction.
    //
    // Readers must use either:
    //   (a) load GuestCode, then load HostCode through an address or data
    //       dependency carried from the GuestCode value (e.g. add a
    //       provably-zero `GuestCode ^ GuestCode` into the HostCode load's
    //       base register), OR
    //   (b) load GuestCode with acquire ordering, then load HostCode.
    //
    // NOT sufficient: "load GuestCode, conditional branch on the compare,
    // then load HostCode on the success path".  This comment used to claim
    // that was control-dependency-ordered and free on PPC.  It is not.
    // Power orders load->load only on address/data dependencies; a control
    // dependency orders load->store only, and the second load may be issued
    // speculatively before the branch resolves.  Every ppc64le L1 probe
    // therefore uses form (a); FindBlock below uses form (b).
    void Publish(uintptr_t NewHostCode, uintptr_t NewGuestCode) {
      HostCode = NewHostCode;
      std::atomic_thread_fence(std::memory_order_release);
      GuestCode = NewGuestCode;
    }
  };

  LookupCache(FEXCore::Context::ContextImpl* CTX);
  ~LookupCache();

  // Swaps out the underlying GuestToHostMap and clears all associated caches.
  // This interface requires the previous CodeBuffer to be provided despite not using it. This ensures the shared write lock is still valid.
  void ChangeGuestToHostMapping([[maybe_unused]] CPU::CodeBuffer& Prev, GuestToHostMap& NewMap, const LookupCacheWriteLockToken& lk) {
    ClearThreadLocalCaches(lk);
    Shared = &NewMap;
  }

  uintptr_t FindBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) {
    // Try L1, no lock needed.  Acquire fence pairs with the writer's release
    // in LookupCacheEntry::Publish so that observing the new GuestCode also
    // observes the new HostCode (no torn read of a half-installed entry).
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[Address & L1PointerMask];
    if (L1Entry.GuestCode == Address) {
      std::atomic_thread_fence(std::memory_order_acquire);
      return L1Entry.HostCode;
    }

    // L2 and L3 need to be locked
    uintptr_t HostPtr {};
    {
      std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
        Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheReadLockTime : nullptr);
      auto lk = Shared->AcquireReadLock();
      LockTime.reset();

      if (!DisableL2Cache()) {
        // Try L2
        const auto PageIndex = (Address & (VirtualMemSize - 1)) >> 12;
        const auto PageOffset = Address & (0x0FFF);

        const auto Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
        auto LocalPagePointer = Pointers[PageIndex];

        // Do we a page pointer for this address?
        if (LocalPagePointer) {
          // Find there pointer for the address in the blocks
          auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);

          if (BlockPointers[PageOffset].GuestCode == Address) {
            // Publish atomically: HostCode first, release fence, then
            // GuestCode (the key the dispatcher / fast-path reader checks).
            L1Entry.Publish(BlockPointers[PageOffset].HostCode, Address);
            HostPtr = L1Entry.HostCode;
          }
        }
      }

      if (!HostPtr) {
        // Try L3
        auto Entry = Shared->FindBlock(Address, lk);
        if (Entry) {
          CacheBlockMapping(Address, *Entry, false, lk);
          HostPtr = Entry->HostCode;
        }
      }
    }

    if (HostPtr && DynamicL1Cache()) {
      UpdateDynamicL1Stats(Thread);
    }

    FEXCORE_PROFILE_INSTANT_INCREMENT(Thread, AccumulatedCacheMissCount, 1);

    return HostPtr;
  }

  void UpdateDynamicL1Stats(FEXCore::Core::InternalThreadState* Thread) {
    // If host pointer was found in L2 or L3, then add it to the counter.
    // Keeping track not L1 misses, but specifically L2/L3 hits.
    ++L2L3CacheHits;

    const auto CurrentTime = std::chrono::system_clock::now();
    const auto Period = CurrentTime - LastPeriod;
    if (Period >= SamplePeriod) {
      // If larger than the sample period then check if we need to increase L1 cache size.
      const double AveragePerSecond = static_cast<double>(L2L3CacheHits) /
                                      static_cast<double>(std::chrono::duration_cast<std::chrono::milliseconds>(Period).count()) * 1000.0;

      if (AveragePerSecond >= DynamicL1CacheIncreaseCountHeuristic()) {
        if (CurrentL1Entries < MAX_L1_ENTRIES) {
          CurrentL1Entries <<= 1;
          L1PointerMask = CurrentL1Entries - 1;

          // Update the thread's L1 pointer mask to increase how much cache it uses.
          // Since we're in C-code, this is safe to update here.
          Thread->CurrentFrame->State.L1Mask = GetScaledL1PointerMask();
        }
      } else if (AveragePerSecond < DynamicL1CacheDecreaseCountHeuristic()) {
        if (CurrentL1Entries > MIN_L1_ENTRIES) {
          CurrentL1Entries >>= 1;
          L1PointerMask = CurrentL1Entries - 1;

          // Madvise the entries that we are dropping. Gives the memory back to the OS.
          LookupCacheEntry* FirstZeroL1Entry = &reinterpret_cast<LookupCacheEntry*>(L1Pointer)[CurrentL1Entries];
          size_t ZeroMemorySize = (MAX_L1_ENTRIES - CurrentL1Entries) * sizeof(LookupCacheEntry);
          FEXCore::Allocator::VirtualDontNeed(FirstZeroL1Entry, ZeroMemorySize, false);

          // Update the thread's L1 pointer mask to increase how much cache it uses.
          // Since we're in C-code, this is safe to update here.
          Thread->CurrentFrame->State.L1Mask = GetScaledL1PointerMask();
        }
      }

      // Update Last period to start again.
      LastPeriod = CurrentTime;
      L2L3CacheHits = 0;
    }
  }

  GuestToHostMap* Shared = nullptr;

  // Appends a list of Block {Address} to CodePages [Start, Start + Length)
  // Returns true if new pages are marked as containing code
  // GuestRangeStart/GuestRangeLength: SMC Idea 3, the block's decoded guest
  // extent. Zero length => the granule bitmap conservatively marks the whole
  // page. See GuestToHostMap::AddBlockExecutableRange.
  bool AddBlockExecutableRange(FEXCore::Core::InternalThreadState* Thread, const fextl::set<uint64_t>& Addresses, uint64_t Start,
                               uint64_t Length, uint64_t GuestRangeStart = 0, uint64_t GuestRangeLength = 0) {
    std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
      Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheWriteLockTime : nullptr);
    auto lk = Shared->AcquireWriteLock();
    LockTime.reset();

    return Shared->AddBlockExecutableRange(Addresses, Start, Length, lk, GuestRangeStart, GuestRangeLength);
  }

  // SMC store-emulation support: does [Start, Start+Length) intersect any
  // compiled block's guest bytes? See GuestToHostMap::RangeOverlapsCompiledCode
  // for the authoritative semantics.
  //
  // SMC Idea 3 READER. Both consumers of this query --
  // FEXSMCBackpatchStoreHelper (SMCStoreBackpatch.cpp) and HandleSegfault's v1
  // fast path (SyscallsSMCTracking.cpp) -- reach it through
  // ContextImpl::GuestRangeOverlapsCompiledCode, so the substitution is made
  // once, here, rather than duplicated at both call sites where the two copies
  // could drift apart. The bitmap is consulted WITHOUT taking the read lock; it
  // may report false positives but never false negatives, so a "provably clear"
  // answer is final and anything else falls through to the original locked map
  // walk unchanged. Reading `Shared` unlocked is exactly what this function
  // already did before touching the lock. See Interface/Core/SMCCodeGranules.h
  // for the memory-ordering argument.
  bool RangeOverlapsCompiledCode(uint64_t Start, uint64_t Length) {
    if (Shared->CodeGranules.ProvablyClear(Start, Length)) {
      return false;
    }

    auto lk = Shared->AcquireReadLock();
    return Shared->RangeOverlapsCompiledCode(Start, Length, lk);
  }

  // SMC v3: take the retained (soft-invalidated) entry for this guest address,
  // if one exists. See Interface/Core/SMCSoftInvalidate.h.
  std::optional<GuestToHostMap::BlockEntry> TakeRetainedBlock(uint64_t Address) {
    auto lk = Shared->AcquireWriteLock();
    return Shared->TakeRetainedBlock(Address, lk);
  }

  // Adds to Guest -> Host code mapping
  void AddBlockMapping(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t BlockBegin, const fextl::vector<uint64_t>& CodePages,
                       void* HostCode, uint64_t GuestRangeStart = 0, uint64_t GuestRangeLength = 0, uint64_t GuestHash = 0,
                       const FEXCore::SMC::BranchImmSites& BranchImmSites = {}, const FEXCore::SMC::ExitRIPSites& ExitRIPSites = {},
                       const FEXCore::SMC::MovImmSites& MovImmSites = {}, const FEXCore::SMC::MovImmWindows& MovImmWindows = {}) {
    std::optional<FEXCore::SHMStats::AccumulationBlock<uint64_t>> LockTime(
      Thread->ThreadStats ? &Thread->ThreadStats->AccumulatedCacheWriteLockTime : nullptr);
    auto lk = Shared->AcquireWriteLock();
    LockTime.reset();

    const auto& Entry = Shared->AddBlockMapping(Address, BlockBegin, CodePages, HostCode, lk, GuestRangeStart, GuestRangeLength, GuestHash,
                                                BranchImmSites, ExitRIPSites, MovImmSites, MovImmWindows);

    // There is no need to update L1 or L2, they will get updated on first lookup
    // However, adding to L1 here increases performance
    CacheBlockMapping(Address, Entry, true, lk);
  }

  // Invalidates L1/L2 for a given guest block
  void InvalidateCache(uint64_t Address, const LookupCacheWriteLockToken& lk) {
    // Do L1
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[Address & L1PointerMask];
    if (L1Entry.GuestCode == Address) {
      L1Entry.GuestCode = 0;
      // Leave L1Entry.HostCode as is, so that concurrent lookups won't read a null pointer
      // This is a soft guarantee for cross thread invalidation, as atomics are not used
      // and it hasn't been thoroughly tested
    }

    if (!DisableL2Cache()) {
      // Do full map
      Address = Address & (VirtualMemSize - 1);
      uint64_t PageOffset = Address & (0x0FFF);
      Address >>= 12;

      uintptr_t* Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
      uint64_t LocalPagePointer = Pointers[Address];
      if (!LocalPagePointer) {
        // Page for this code didn't even exist, nothing to do
        return;
      }

      // Page exists, just set the offset to zero
      auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);
      BlockPointers[PageOffset].GuestCode = 0;
      BlockPointers[PageOffset].HostCode = 0;
    }
  }

  // Invalidates all L1/L2 entries for all guest block that intersect the given range
  bool InvalidateCacheRange(uint64_t Start, uint64_t Length) {
    auto lk = Shared->AcquireWriteLock();

    auto lower = CachedCodePages.lower_bound(Start >> 12);
    auto upper = CachedCodePages.upper_bound((Start + Length - 1) >> 12);

    for (auto it = lower; it != upper; it++) {
      for (const auto& Entry : it->second) {
        InvalidateCache(Entry, lk);
      }
    }
    bool ret = upper != lower;
    CachedCodePages.erase(lower, upper);
    return ret;
  }

  void AddBlockLink(uint64_t GuestDestination, FEXCore::Context::ExitFunctionLinkData* HostLink,
                    const FEXCore::Context::BlockDelinkerFunc& delinker, const LookupCacheWriteLockToken& lk) {
    Shared->AddBlockLink(GuestDestination, HostLink, delinker, lk);
  }

  void ClearCache(const LookupCacheWriteLockToken&);
  void ClearL2Cache(const LookupCacheBaseLockToken&);
  void ClearThreadLocalCaches(const LookupCacheWriteLockToken&);

  // ---------------------------------------------------------------------
  // FEX_SMCLAZYSCRUB (see Source/Tools/LinuxEmulation/LinuxSyscalls/
  // SMCLazyInvalidate.h, section "SAME-THREAD SOUNDNESS").
  //
  // Called from the SMC SIGSEGV handler, on the faulting thread, for its OWN
  // LookupCache, when the lazy route defers invalidation.  It does two things:
  //
  //   * zeroes this thread's entire L1 table, so the thread's next dispatch --
  //     from the dispatcher's inlined probe or from a block's inlined
  //     ExitFunction probe -- cannot hit any translation at all and must call
  //     into the C++ lookup slow path (PPC64JITCore::ExitFunctionLink); and
  //   * records that this thread owes a lazy drain, which that slow path
  //     settles before it consults the shared L2/L3 caches.
  //
  // Together those close the same-thread patch-then-call hole: the thread that
  // wrote the code cannot reach ANY cached translation again without first
  // draining the dirty set.  Other threads are untouched and may lawfully keep
  // running stale code until one of their own drain points, which is exactly
  // what x86 permits for cross-modifying code.
  //
  // SIGNAL SAFETY.  Takes no lock.  The only writer of this thread's L1 is
  // this thread (which is stopped inside this handler); the only foreign
  // writes are LookupCache::InvalidateCache from a cross-thread Erase, which
  // stores a zero into GuestCode -- so a race can at worst lose a store that
  // zeroing is performing anyway.  Nothing anywhere reads another thread's L1.
  // The zeroing itself is a single madvise(MADV_DONTNEED) on the L1 mapping
  // (a private anonymous mapping, so it reads back as zero), which is one
  // syscall rather than a multi-megabyte memset and is safe to issue from a
  // signal handler.
  //
  // Zeroing HostCode as well as GuestCode is deliberate and matches
  // ClearThreadLocalCaches; the "leave HostCode alone" rule in InvalidateCache
  // exists so a concurrent *lock-free reader of a single entry* cannot observe
  // {matching GuestCode, null HostCode}, and here GuestCode goes to zero at
  // the same time or earlier, so no entry can ever be observed half-cleared in
  // that direction.  A guest RIP of 0 is the sole address that "matches" a
  // zeroed entry; that is already true of a freshly allocated L1 and is
  // filtered as a suspect RIP by the lookup slow path.
  void ScrubForLazySMC() {
    LazySMCDrainPending.store(true, std::memory_order_relaxed);
    // A failed madvise (EAGAIN under memory pressure) would silently leave the
    // stale L1 entries in place and reopen the same-thread hole this exists to
    // close, so the result must be checked; fall back to zeroing by hand.
    // Both paths are async-signal-safe.
    if (::madvise(reinterpret_cast<void*>(L1Pointer), MAX_L1_SIZE, MADV_DONTNEED) != 0) {
      std::memset(reinterpret_cast<void*>(L1Pointer), 0, MAX_L1_SIZE);
    }
  }

  // Consume this thread's lazy-drain debt.  Cleared BEFORE the drain runs so
  // that a fault re-arming it while the drain is in flight is not lost.
  bool TakeLazySMCDrainPending() {
    if (!LazySMCDrainPending.load(std::memory_order_relaxed)) {
      return false;
    }
    LazySMCDrainPending.store(false, std::memory_order_relaxed);
    return true;
  }

  uintptr_t GetL1Pointer() const {
    return L1Pointer;
  }
  uintptr_t GetScaledL1PointerMask() const {
    return L1PointerMask << FEXCore::ilog2(sizeof(LookupCache::LookupCacheEntry));
  }
  uintptr_t GetPagePointer() const {
    return PagePointer;
  }
  uintptr_t GetVirtualMemorySize() const {
    return VirtualMemSize;
  }

  // This needs to be taken before reads or writes to L2, L3, CodePages,
  // and before writes to L1. Concurrent access from a thread that this LookupCache doesn't belong to
  // may only happen during cross thread invalidation (::Erase).
  // All other operations must be done from the owning thread.
  // Some care is taken so that L1 lookups can be done without locks, and even tearing is unlikely to lead to a crash.
  // This approach has not been fully vetted yet.
  // Also note that L1 lookups might be inlined in the JIT Dispatcher and/or block ends.
  auto AcquireWriteLock() {
    return Shared->AcquireWriteLock();
  }

private:
  void CacheBlockMapping(uint64_t Address, const GuestToHostMap::BlockEntry& Entry, bool L1Only, const LookupCacheBaseLockToken& lk) {
    for (const auto& CodePage : Entry.CodePages) {
      CachedCodePages[CodePage >> 12].insert(Address);
    }

    // Do L1.  Atomic publish: see LookupCacheEntry::Publish for why ordering
    // matters on weakly-ordered hosts (PPC64LE).
    auto& L1Entry = reinterpret_cast<LookupCacheEntry*>(L1Pointer)[Address & L1PointerMask];
    L1Entry.Publish(Entry.HostCode, Address);

    if (!DisableL2Cache() && !L1Only) {
      // Do ful map
      auto FullAddress = Address;
      Address = Address & (VirtualMemSize - 1);

      uint64_t PageOffset = Address & (0x0FFF);
      Address >>= 12;

      uintptr_t* Pointers = reinterpret_cast<uintptr_t*>(PagePointer);
      uint64_t LocalPagePointer = Pointers[Address];
      if (!LocalPagePointer) {
        // We don't have a page pointer for this address
        // Allocate one now if we can
        uintptr_t NewPageBacking = AllocateBackingForPage();
        if (!NewPageBacking) {
          // Couldn't allocate, clear L2 and retry
          ClearL2Cache(lk);
          CacheBlockMapping(FullAddress, Entry, false, lk);
          return;
        }
        Pointers[Address] = NewPageBacking;
        LocalPagePointer = NewPageBacking;
      }

      // Add the new pointer to the page block
      auto BlockPointers = reinterpret_cast<LookupCacheEntry*>(LocalPagePointer);

      // This silently replaces existing mappings.
      // Same release-publish discipline as L1 above: HostCode first, release
      // fence, then GuestCode as the visibility key.  See
      // LookupCacheEntry::Publish.  Every reader of L2 currently holds the
      // shared read lock, so this is not load-bearing today, but the previous
      // unordered store pair is the exact inverse of the required order and
      // would hand a lock-free reader a valid GuestCode paired with a stale or
      // uninitialised HostCode on a weakly-ordered host.
      BlockPointers[PageOffset].Publish(Entry.HostCode, FullAddress);
    }
  }

  uintptr_t AllocateBackingForPage() {
    uintptr_t NewBase = AllocateOffset;
    uintptr_t NewEnd = AllocateOffset + SIZE_PER_PAGE;

    if (NewEnd >= CODE_SIZE) {
      // We ran out of block backing space. Need to clear the block cache and tell the JIT cores to clear their caches as well
      // Tell whatever is calling this that it needs to do it.
      return 0;
    }

    AllocateOffset = NewEnd;
    return PageMemory + NewBase;
  }

  // Maps from a page index to all blocks in the page that have at some point been fetched into L1/L2
  fextl::map<uint64_t, fextl::robin_set<uint64_t>> CachedCodePages;

  uintptr_t PagePointer;
  uintptr_t PageMemory;
  uintptr_t L1Pointer;
  uintptr_t L1PointerMask;

  size_t TotalCacheSize;

  // Start with 8k entries in L1 to give 128KB of L1 cache to each thread.
  // Max out at 1 million entries to give each thread 16MB of L1 cache maximum.
  constexpr static size_t MIN_L1_ENTRIES = 8 * 1024;        // Must be a power of 2
  constexpr static size_t MAX_L1_ENTRIES = 1 * 1024 * 1024; // Must be a power of 2

  constexpr static size_t CODE_SIZE = 128 * 1024 * 1024;
  constexpr static size_t SIZE_PER_PAGE = FEXCore::Utils::FEX_PAGE_SIZE * sizeof(LookupCacheEntry);
  constexpr static size_t MAX_L1_SIZE = MAX_L1_ENTRIES * sizeof(LookupCacheEntry);

  size_t AllocateOffset {};

  // FEX_SMCLAZYSCRUB.  Per-thread (this object is per-thread), set by the SMC
  // fault handler on the faulting thread and consumed by that same thread in
  // the lookup slow path.  Atomic only so the compiler cannot sink or fold the
  // signal-handler store; no cross-thread ordering is required or implied.
  std::atomic<bool> LazySMCDrainPending {false};

  FEXCore::Context::ContextImpl* ctx;
  uint64_t VirtualMemSize {};

  size_t CurrentL1Entries = MIN_L1_ENTRIES;
  uint64_t L2L3CacheHits {};
  std::chrono::time_point<std::chrono::system_clock> LastPeriod {};
  constexpr static std::chrono::seconds SamplePeriod {1};
  FEX_CONFIG_OPT(DynamicL1CacheIncreaseCountHeuristic, DYNAMICL1CACHEINCREASECOUNTHEURISTIC);
  FEX_CONFIG_OPT(DynamicL1CacheDecreaseCountHeuristic, DYNAMICL1CACHEDECREASECOUNTHEURISTIC);

  FEX_CONFIG_OPT(DynamicL1Cache, DYNAMICL1CACHE);
  FEX_CONFIG_OPT(DisableL2Cache, DISABLEL2CACHE);
};
} // namespace FEXCore
