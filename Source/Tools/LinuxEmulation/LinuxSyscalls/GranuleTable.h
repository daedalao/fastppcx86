// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/fextl/map.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <sys/mman.h>

namespace FEX::HLE::VMATracking {

/**
 * @brief The granule table (docs/PAGE_SIZE_64K_PLAN.md Part 2 §2).
 *
 * FEX hands the guest AT_PAGESZ=4096 unconditionally, so the guest places
 * MAP_FIXED mappings, arms guard pages and unmaps ranges on 4096-byte
 * boundaries. A host kernel whose page is larger cannot represent that: on
 * ppc64le/64K, one host page -- a "granule" -- covers 16 guest pages and the
 * kernel carries exactly one protection for all of them.
 *
 * This table is the fiction that bridges the two. It records
 *
 *   - per guest 4K page, whether it is live and the protection the guest
 *     INTENDED for it, and
 *   - per host granule, the protection FEX actually MATERIALISED with the
 *     kernel.
 *
 * INVARIANT (AssertInvariant(), and checked at every materialisation):
 *
 *     HostProt(granule) == Union(IntendedProt(p) : p in granule, p live)
 *                          & ~(PROT_WRITE if SMC tracking has the granule armed)
 *
 * The armed state is read from the SMC granule table (SMCHostGranule.h); for a
 * granule SMC tracking has ever armed, HostProt is treated as a hint only,
 * because mtrack's own mprotects move the kernel's protection behind it.
 *
 * "Union" is the most permissive combination: nothing the guest believes
 * writable may ever fault for granularity reasons. The consequence -- a
 * protection STRICTER than the granule union is tracked but not enforced -- is
 * the permissive tier, whose correctness envelope is PAGE_SIZE_64K_PLAN §6.
 * Guard pages the guest arms PROT_NONE inside a live granule therefore appear
 * in this table, and in the synthesised /proc/self/maps, but do not fault.
 *
 * ON A 4K HOST THIS TABLE IS NEVER POPULATED. Every entry point that could
 * reach it is guarded by FEXCore::HostPage::MatchesGuest(), so a 4K build
 * executes byte-identically to the pre-port tree. Active() is the single
 * predicate; the emulation layer tests it once per syscall.
 *
 * LOCKING: the table lives inside VMATracking and is covered by
 * VMATracking::Mutex. Mutating calls require the unique (write) hold; const
 * queries require at least the shared hold. It takes no lock of its own -- a
 * second lock here would invert against the CodeInvalidationMutex ordering the
 * SMC layer depends on.
 */
struct GranuleTable {
  // True when the host page is larger than the guest's, i.e. when any of this
  // machinery does anything at all.
  [[nodiscard]] static bool Active() {
    return !FEXCore::HostPage::MatchesGuest();
  }

  // Guest 4K pages covered by one host granule. 1 on a 4K host, 16 on 64K.
  [[nodiscard]] static uint64_t PagesPerGranule() {
    return FEXCore::HostPage::Size() >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  }

  // The largest host page this encoding supports: one nibble per guest page in
  // a single uint64_t. ppc64le offers 4K and 64K and nothing between, so 16
  // guest pages per granule is the real ceiling; the check exists so that a
  // hypothetical 2M-page host fails loudly here instead of corrupting the
  // table.
  static constexpr uint64_t MaxPagesPerGranule = 16;
  static constexpr uint64_t MaxHostPageSize = MaxPagesPerGranule * FEXCore::Utils::FEX_GUEST_PAGE_SIZE;

  [[nodiscard]] static bool HostPageRepresentable() {
    return FEXCore::HostPage::Size() <= MaxHostPageSize;
  }

  [[nodiscard]] static uint64_t GranuleOf(uint64_t Addr) {
    return FEXCore::HostPage::AlignDown(Addr);
  }

  [[nodiscard]] static uint64_t IndexOf(uint64_t Addr) {
    return (Addr - GranuleOf(Addr)) >> FEXCore::Utils::FEX_GUEST_PAGE_SHIFT;
  }

  // Nibble layout, 4 bits per guest page.
  enum : uint64_t {
    PageLive = 1,
    PageRead = 2,
    PageWrite = 4,
    PageExec = 8,
    PageNibbleMask = 0xF,
  };

  [[nodiscard]] static uint64_t NibbleFromProt(int Prot) {
    uint64_t Nibble = PageLive;
    if (Prot & PROT_READ) {
      Nibble |= PageRead;
    }
    if (Prot & PROT_WRITE) {
      Nibble |= PageWrite;
    }
    if (Prot & PROT_EXEC) {
      Nibble |= PageExec;
    }
    return Nibble;
  }

  [[nodiscard]] static int ProtFromNibble(uint64_t Nibble) {
    int Prot = PROT_NONE;
    if (Nibble & PageRead) {
      Prot |= PROT_READ;
    }
    if (Nibble & PageWrite) {
      Prot |= PROT_WRITE;
    }
    if (Nibble & PageExec) {
      Prot |= PROT_EXEC;
    }
    return Prot;
  }

  struct GranuleEntry {
    // 4 bits per guest page: Live | R | W | X, page i at bits [4i, 4i+4).
    uint64_t Nibbles {0};
    // The protection last handed to the kernel for this granule. Kept so the
    // invariant can be checked without a /proc read, and so a rematerialisation
    // that would be a no-op can be skipped (mprotect is not free at 64K: it
    // walks the HPT).
    uint8_t HostProt {PROT_NONE};
    // True once FEX has replaced this granule's backing with a private
    // anonymous mapping of its own, which is what makes sub-granule MAP_FIXED
    // and sub-granule file content possible. Once set, FEX may freely
    // mprotect/pwrite the granule; before it is set, the granule's backing is
    // whatever the guest's own (host-aligned) mapping put there.
    bool FEXBacked {false};
    // Set by the shared-file passthrough (GranuleMemory.cpp, Granule::Mmap):
    // the whole granule is one MAP_SHARED mapping of SharedFd at SharedOffset
    // and FEX keeps a dup of the fd, so that a later private sub-granule
    // request in the same granule can be represented by re-mapping the
    // granule MAP_PRIVATE from the same file (wine's KUSER_SHARED_DATA page at
    // 0x7ffe0000 next to its private syscall-dispatcher page at 0x7ffe1000).
    // Closed by Forget().
    int SharedFd {-1};
    uint64_t SharedOffset {0};

    [[nodiscard]] uint64_t NibbleAt(uint64_t Index) const {
      return (Nibbles >> (Index * 4)) & PageNibbleMask;
    }
    void SetNibbleAt(uint64_t Index, uint64_t Nibble) {
      const uint64_t Shift = Index * 4;
      Nibbles = (Nibbles & ~(PageNibbleMask << Shift)) | ((Nibble & PageNibbleMask) << Shift);
    }
    [[nodiscard]] bool Empty() const {
      return Nibbles == 0;
    }
  };

  using ContainerType = fextl::map<uint64_t, GranuleEntry>;

  /// The union of the intended protections of every live page in Entry.
  /// PROT_NONE when nothing in the granule is live. Not what gets
  /// materialised: see WantedProt.
  [[nodiscard]] static int UnionProtOf(const GranuleEntry& Entry) {
    uint64_t Union = 0;
    uint64_t Nibbles = Entry.Nibbles;
    const uint64_t Count = PagesPerGranule();
    for (uint64_t i = 0; i < Count; ++i, Nibbles >>= 4) {
      const uint64_t Nibble = Nibbles & PageNibbleMask;
      if (Nibble & PageLive) {
        Union |= Nibble;
      }
    }
    return ProtFromNibble(Union);
  }

  /// The protection to materialise for a granule: the union of its live
  /// pages, minus PROT_WRITE while SMC tracking (mtrack) has the granule
  /// armed. mtrack's arm and fault paths issue their own granule-wide
  /// mprotects without the VMATracking lock, so this table cannot be told
  /// about them; it asks the SMC granule table instead (SMCHostGranule.h,
  /// "how they stay in step"). Identity with UnionProtOf on a 4K host.
  [[nodiscard]] static int WantedProt(uint64_t GranuleBase, const GranuleEntry& Entry);

  /// Mark [Base, Base+Length) (guest-4K quantities) live with intended
  /// protection Prot. Creates granule entries as needed. Does NOT materialise;
  /// the caller decides when to call Rematerialise, because a single guest
  /// syscall usually wants one host mprotect per granule at the end rather than
  /// one per page.
  /// - VMATracking::Mutex must be unique_locked.
  void SetIntended(uint64_t Base, uint64_t Length, int Prot);

  /// Mark [Base, Base+Length) not live. Granules that empty out entirely are
  /// appended to Emptied (may be nullptr) and left in the table; the caller
  /// unmaps them and then calls Forget(). Granules that keep a live sibling
  /// stay mapped: that is the sub-granule munmap rule.
  /// - VMATracking::Mutex must be unique_locked.
  void ClearIntended(uint64_t Base, uint64_t Length, fextl::vector<uint64_t>* Emptied);

  /// Intended protection of one guest page. Returns false when the page is not
  /// tracked (either not live, or this granule was never emulated).
  /// - VMATracking::Mutex must be at least shared_locked.
  [[nodiscard]] bool LookupPage(uint64_t GuestPage, int* Prot) const;

  /// True when this granule has an entry, i.e. FEX has emulated something in
  /// it. A granule the guest mapped host-aligned and never subdivided has no
  /// entry, and every path must behave as if the kernel is the authority for
  /// it.
  /// - VMATracking::Mutex must be at least shared_locked.
  [[nodiscard]] const GranuleEntry* Find(uint64_t GranuleBase) const;
  [[nodiscard]] GranuleEntry* FindMutable(uint64_t GranuleBase);
  GranuleEntry& FindOrCreate(uint64_t GranuleBase);

  /// Drop a granule from the table. Call after the granule has actually been
  /// unmapped.
  /// - VMATracking::Mutex must be unique_locked.
  void Forget(uint64_t GranuleBase);

  ///// SMC / mtrack /////
  //
  // mtrack write-protects guest code pages. At 64K the quantum is the whole
  // granule, and mtrack's arm/unprotect mprotects run without this table's
  // lock (SyscallsSMCTracking.cpp), so there is no hook for it to call here.
  // RematerialiseIfNeeded keeps the invariant instead by consulting the SMC
  // granule table (WantedProt above): PROT_WRITE stays held back while the
  // granule is armed, and the cached HostProt is never trusted to skip the
  // syscall for a granule mtrack has touched. The soundness rule from
  // PAGE_SIZE_64K_PLAN section 5 binds mtrack: whatever range it unprotects,
  // it invalidates or re-arms every tracked guest page inside it. This table
  // deliberately never invalidates anything -- it has no access to the code
  // cache and taking one here would invert the VMATracking/CodeInvalidation
  // lock order.

  /// Bring the kernel's protection for this granule in line with the invariant.
  /// No-op (and no syscall) when the granule is already correct, unless SMC
  /// tracking has ever armed the granule (its raw mprotects move the kernel's
  /// protection behind HostProt's back, so the syscall is always issued). Returns true on
  /// success; on failure the entry's HostProt is left describing what the kernel
  /// actually has, so the invariant check reports the divergence rather than
  /// hiding it.
  /// - VMATracking::Mutex must be unique_locked.
  bool RematerialiseIfNeeded(uint64_t GranuleBase);

  /// Record a protection the caller materialised itself (a pass-through mmap or
  /// mprotect of a whole, host-aligned range). Keeps HostProt honest without a
  /// second syscall.
  /// - VMATracking::Mutex must be unique_locked.
  void NoteHostProt(uint64_t GranuleBase, int Prot);

  /// Debug-only full sweep of the invariant. Compiled out in release builds via
  /// LOGMAN_THROW_A_FMT, which is exactly where the assertion belongs: the
  /// sweep is O(granules) and this table can hold tens of thousands of them.
  void AssertInvariant() const;

  [[nodiscard]] const ContainerType& All() const {
    return Granules;
  }
  [[nodiscard]] bool Empty() const {
    return Granules.empty();
  }

private:
  ContainerType Granules;
};

} // namespace FEX::HLE::VMATracking
