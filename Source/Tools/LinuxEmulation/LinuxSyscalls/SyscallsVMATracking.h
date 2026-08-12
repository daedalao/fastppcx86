// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <tuple>

#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/TypeDefines.h>

#include <elf.h>

namespace FEX::HLE::VMATracking {
///// VMA (Virtual Memory Area) tracking /////

namespace SpecialDev {
  static constexpr uint64_t Anon = 0x1'0000'0000; // Anonymous shared mapping, id is incrementing allocation number
  static constexpr uint64_t SHM = 0x2'0000'0000;  // sys-v shm, id is shmid
}; // namespace SpecialDev

// Memory Resource ID
// An id that can be used to identify when shared mappings actually have the same backing storage
// when dev != SpecialDev::Anon, this is unique system wide
struct MRID {
  uint64_t dev; // kernel dev_t is actually 32-bits, we use the extra bits to track SpecialDevs
  uint64_t id;

  bool operator<(const MRID& other) const {
    return std::tie(dev, id) < std::tie(other.dev, other.id);
  }
};

struct VMAEntry;

/**
 * Meta data associated to one system resource.
 *
 * Typically there is one instance of this type per ELF/PE file or special device.
 * However if an ELF/PE file is mapped multiple times at different base addresses,
 * there will be one separate MappedResource for each base address. The MRID
 * is the same in this case.
 */
struct MappedResource {
  using ContainerType = fextl::multimap<MRID, MappedResource>;

  fextl::unique_ptr<FEXCore::ExecutableFileInfo> MappedFile;
  // Pointer to lowest memory range this file is mapped to
  VMAEntry* FirstVMA;
  uint64_t Length; // 0 if not fixed size
  ContainerType::iterator Iterator;

  bool RequiresDelayedCacheLoad = false;

  // FEX_SMCFILEIMMUTABLE: set once the guest mprotects any part of this
  // resource writable *after* FEX skipped installing SMC write-protection on
  // it, i.e. once the "file-backed code is immutable" assumption has been
  // observably contradicted. Sticky and resource-wide (fail closed): from then
  // on every VMA of this mapping goes back to plain mtrack behaviour.
  // Written only under a unique lock on VMATracking::Mutex (GuestMprotect),
  // read under the shared lock in MarkGuestExecutableRange.
  bool SMCFileImmutableRevoked = false;

  fextl::vector<Elf64_Phdr> ProgramHeaders;
};

union VMAProt {
  struct {
    bool Readable   : 1;
    bool Writable   : 1;
    bool Executable : 1;
  };
  uint8_t All : 3;

  static VMAProt fromProt(int Prot);
  static VMAProt fromSHM(int SHMFlg);
};

struct VMAFlags {
  bool Shared : 1;

  static VMAFlags fromFlags(int Flags);
};

struct VMAEntry {
  MappedResource* Resource;

  // these are for intrusive linked list tracking, starting from Resource->FirstVMA and ordered by address
  VMAEntry* ResourcePrevVMA;
  VMAEntry* ResourceNextVMA;

  uint64_t Base;
  uint64_t Offset;
  uint64_t Length;

  VMAFlags Flags;
  VMAProt Prot;
};

struct VMATracking {
  // Held while reading/writing this struct
  FEXCore::ForkableSharedMutex Mutex;

  // Memory ranges indexed by page aligned starting address
  fextl::map<uint64_t, VMAEntry> VMAs;

  using VMACIterator = decltype(VMAs)::const_iterator;

  // Find a VMA entry associated with the memory address.
  // Used by `mremap` and SIGSEGV handler to find previously mapped ranges, and CodeCache to find cache entries.
  // - Mutex must be at least shared_locked before calling
  VMACIterator FindVMAEntry(uint64_t GuestAddr) const;

  // Adds a new VMA Range to be tracked, along with a `MappedResource` associated with that VMA range.
  // Primarily matches `mmap` semantics, but also used by `mremap`, and `shmat`, as they all can add new VMA ranges to be tracked.
  // - Mutex must be unique_locked before calling
  void TrackVMARange(FEXCore::Context::Context* Ctx, MappedResource* MappedResource, uintptr_t Base, uintptr_t Offset, uintptr_t Length,
                     VMAFlags Flags, VMAProt Prot);

  // Deletes a VMA range provided from tracking.
  // Matches `munmap` semantics, and `mremap` with `MREMAP_DONTUNMAP` flag set.
  // Deletes internal `MappedResource` that correlates with the range **unless** it matches `PreservedMappedResource`
  // - Mutex must be unique_locked before calling
  void DeleteVMARange(FEXCore::Context::Context* Ctx, uintptr_t Base, uintptr_t Length, MappedResource* PreservedMappedResource = nullptr);

  // Changes the protections tracking for the VMA range provided.
  // Matches `mprotect` semantics.
  // - Mutex must be unique_locked before calling
  void ChangeProtectionFlags(uintptr_t Base, uintptr_t Length, VMAProt Prot);

  // Deletes the SHM region mapped at Base from tracking.
  // Matches `shmdt` semantics.
  // - Mutex must be unique_locked before calling
  // Returns the Size of the Shm or 0 if not found
  uintptr_t DeleteSHMRegion(FEXCore::Context::Context* Ctx, uintptr_t Base);

  ///// "Nothing to do here" memo for MarkGuestExecutableRange /////
  //
  // MarkGuestExecutableRange runs on the compile path: every time a compiled
  // block touches a page that isn't already known to hold code, Core.cpp asks
  // us to write-protect that page.  For the overwhelming majority of pages the
  // answer is "nothing to do" -- the page lives in a private, non-writable
  // mapping, so there is nothing to mprotect and no state to change (a 16.5
  // minute Witcher 3 audit saw 120K calls, 114K of which were that pure no-op).
  // Each of those still paid a signal-deferring section, a shared_lock on
  // Mutex, a lower_bound and the mapping walk, all on the hot compile path
  // while other threads want the same mutex.
  //
  // The memo below lets the second and later calls for such a page answer
  // lock-free.  It is a small direct-mapped table of page numbers, each entry
  // stamped with the generation of the VMA map it was computed against.
  //
  // Invariant we must not break: if a page's mapping is (or becomes) shared,
  // writable-private, or in any other way actionable, the mark must reach the
  // slow path.  Two rules give us that:
  //
  //  1) Generation is bumped by *every* mutation of the VMA map.  All of them
  //     funnel through TrackVMARange / DeleteVMARange / ChangeProtectionFlags /
  //     DeleteSHMRegion (mmap, munmap, mprotect, mremap, shmat, shmdt all call
  //     one of those), so the bump lives at the top of those four functions
  //     rather than at their call sites -- a new caller cannot forget it.  An
  //     entry only matches while its stamp equals the live generation, so any
  //     mutation retires the whole table at once.
  //
  //  2) A reader samples Generation *before* it inspects the map, and stamps
  //     the entry it publishes with that sample.  This is what makes the
  //     publish safe against a writer running in between: if anything mutated
  //     the map after the sample, the published stamp is already stale and no
  //     later lookup can match it, however long the publishing thread was
  //     descheduled before its store landed.  Conversely a mutation that
  //     completed before the sample is visible in the map the reader then reads
  //     under the shared lock.  So a hit is always equivalent to the slow path
  //     having run at the instant of the sample -- which is exactly the race
  //     the locked version has with a concurrent mmap/mprotect anyway.
  //
  // Memory ordering: the fast path performs no action, so nothing is published
  // through these loads; acquire/release is used purely so the stamp and the
  // store that retires an entry are never reordered against each other on
  // POWER's weak model.  Slot reads/writes are single 64-bit atomics, so a
  // torn (tag, generation) pair is impossible by construction.
  //
  // Entry encoding: (PageNumber >> MarkNoOpIndexBits) << MarkNoOpGenBits | Gen.
  // The low index bits of the page number are implied by the slot, and a zero
  // word means "empty" -- which is unambiguous because the generation field is
  // never zero (BumpGeneration skips it, see below).
  constexpr static size_t MarkNoOpIndexBits = 9;
  constexpr static size_t MarkNoOpEntries = 1 << MarkNoOpIndexBits;
  constexpr static uint64_t MarkNoOpGenBits = 32;
  constexpr static uint64_t MarkNoOpGenMask = (1ULL << MarkNoOpGenBits) - 1;

  // Version of VMAs, bumped by every mutation. Its low MarkNoOpGenBits bits
  // are never zero, because zero encodes an empty table slot (see above).
  std::atomic<uint64_t> Generation {1};

  uint64_t LoadGeneration() const {
    return Generation.load(std::memory_order_acquire);
  }

  // Retires every memo entry. Called from the four mutating operations; also
  // safe to call from anything else that could change the answer.
  void BumpGeneration() {
    const uint64_t New = Generation.fetch_add(1, std::memory_order_release) + 1;
    if ((New & MarkNoOpGenMask) == 0) [[unlikely]] {
      // The generation field wrapped. Step over zero (reserved for "empty")
      // and drop the whole table: without this, an entry stamped exactly
      // 2^MarkNoOpGenBits mutations ago would start matching again.
      Generation.fetch_add(1, std::memory_order_release);
      for (auto& Slot : MarkNoOpCache) {
        Slot.store(0, std::memory_order_relaxed);
      }
    }
  }

  // Returns true if PageBase was recorded as needing no work at generation Gen.
  // Lock-free; Gen must have been sampled by the caller before it looked at the
  // map (see rule 2 above).
  bool IsMarkNoOp(uint64_t PageBase, uint64_t Gen) const {
    uint64_t Entry;
    if (!EncodeMarkNoOp(PageBase, Gen, Entry)) {
      return false;
    }
    return MarkNoOpCache[MarkNoOpIndex(PageBase)].load(std::memory_order_acquire) == Entry;
  }

  void RecordMarkNoOp(uint64_t PageBase, uint64_t Gen) {
    uint64_t Entry;
    if (!EncodeMarkNoOp(PageBase, Gen, Entry)) {
      return;
    }
    MarkNoOpCache[MarkNoOpIndex(PageBase)].store(Entry, std::memory_order_release);
  }

  // Adds a new `MappedResource` to track.
  inline auto InsertMappedResource(const MRID& mrid, MappedResource Resource) {
    return MappedResources.emplace(mrid, std::move(Resource));
  }

  // Returns an iterator pair spanning the range of all MappedResources matching the given MRID.
  // Typically there is only one associated resource, however sometimes the same file gets mapped
  // multiple times at different base addresses. In that case, each MappedResource will cover an
  // exclusive set of VMAEntries that refer to a consistent base mapping address.
  inline auto FindResources(const MRID& mrid) {
    return MappedResources.equal_range(mrid);
  }

  // All tracked resources, for whole-process passes (the code cache writer walks
  // this to find every mapped file with compiled code).
  // - Mutex must be at least shared_locked before calling, and for as long as
  //   the returned range is used.
  inline const MappedResource::ContainerType& AllResources() const {
    return MappedResources;
  }

private:
  static size_t MarkNoOpIndex(uint64_t PageBase) {
    return (PageBase >> FEXCore::Utils::FEX_PAGE_SHIFT) & (MarkNoOpEntries - 1);
  }

  // Builds the table word for (PageBase, Gen). Fails (returns false, meaning
  // "don't use the memo for this address") if the tag doesn't fit, which can
  // only happen for guest addresses far beyond TASK_MAX_64BIT. Bailing out is
  // always safe: it just forces the locked slow path.
  static bool EncodeMarkNoOp(uint64_t PageBase, uint64_t Gen, uint64_t& Entry) {
    const uint64_t Tag = (PageBase >> FEXCore::Utils::FEX_PAGE_SHIFT) >> MarkNoOpIndexBits;
    if (Tag >> (64 - MarkNoOpGenBits)) [[unlikely]] {
      return false;
    }
    Entry = (Tag << MarkNoOpGenBits) | (Gen & MarkNoOpGenMask);
    // A zero word is the empty slot, so never hand one out. The generation
    // field is never zero, so this can only be reached with a zero tag *and* a
    // zero generation field, which BumpGeneration already excludes; keep the
    // check anyway so the encoding stays self-contained.
    return Entry != 0;
  }

  std::array<std::atomic<uint64_t>, MarkNoOpEntries> MarkNoOpCache {};

  MappedResource::ContainerType MappedResources;
};


} // namespace FEX::HLE::VMATracking
