// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: The 64K-host granule table (docs/PAGE_SIZE_64K_PLAN.md Part 2 §2)
$end_info$
*/

#include "LinuxSyscalls/GranuleTable.h"

#include <FEXCore/Utils/LogManager.h>

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

namespace FEX::HLE::VMATracking {

void GranuleTable::SetIntended(uint64_t Base, uint64_t Length, int Prot) {
  if (!Length) {
    return;
  }
  LOGMAN_THROW_A_FMT(Active(), "granule table touched on a 4K host");

  const uint64_t Nibble = NibbleFromProt(Prot);
  const uint64_t End = Base + Length;
  for (uint64_t Page = Base; Page < End; Page += FEXCore::Utils::FEX_GUEST_PAGE_SIZE) {
    auto& Entry = FindOrCreate(GranuleOf(Page));
    Entry.SetNibbleAt(IndexOf(Page), Nibble);
  }
}

void GranuleTable::ClearIntended(uint64_t Base, uint64_t Length, fextl::vector<uint64_t>* Emptied) {
  if (!Length) {
    return;
  }
  LOGMAN_THROW_A_FMT(Active(), "granule table touched on a 4K host");

  const uint64_t End = Base + Length;
  for (uint64_t Page = Base; Page < End; Page += FEXCore::Utils::FEX_GUEST_PAGE_SIZE) {
    auto* Entry = FindMutable(GranuleOf(Page));
    if (!Entry) {
      continue;
    }
    Entry->SetNibbleAt(IndexOf(Page), 0);
  }

  if (!Emptied) {
    return;
  }
  const uint64_t GranuleEnd = FEXCore::HostPage::AlignUp(End);
  for (uint64_t Granule = GranuleOf(Base); Granule < GranuleEnd; Granule += FEXCore::HostPage::Size()) {
    const auto* Entry = Find(Granule);
    if (Entry && Entry->Empty()) {
      Emptied->emplace_back(Granule);
    }
  }
}

bool GranuleTable::LookupPage(uint64_t GuestPage, int* Prot) const {
  const auto* Entry = Find(GranuleOf(GuestPage));
  if (!Entry) {
    return false;
  }
  const uint64_t Nibble = Entry->NibbleAt(IndexOf(GuestPage));
  if (!(Nibble & PageLive)) {
    return false;
  }
  if (Prot) {
    *Prot = ProtFromNibble(Nibble);
  }
  return true;
}

const GranuleTable::GranuleEntry* GranuleTable::Find(uint64_t GranuleBase) const {
  auto it = Granules.find(GranuleBase);
  return it == Granules.end() ? nullptr : &it->second;
}

GranuleTable::GranuleEntry* GranuleTable::FindMutable(uint64_t GranuleBase) {
  auto it = Granules.find(GranuleBase);
  return it == Granules.end() ? nullptr : &it->second;
}

GranuleTable::GranuleEntry& GranuleTable::FindOrCreate(uint64_t GranuleBase) {
  LOGMAN_THROW_A_FMT(HostPageRepresentable(), "host page {} exceeds the granule table's {} byte encoding limit",
                     FEXCore::HostPage::Size(), MaxHostPageSize);
  return Granules[GranuleBase];
}

void GranuleTable::Forget(uint64_t GranuleBase) {
  Granules.erase(GranuleBase);
}

int GranuleTable::SetSMCOverlay(uint64_t GranuleBase, int RemovedProt) {
  auto& Entry = FindOrCreate(GranuleBase);
  Entry.SMCOverlay = static_cast<uint8_t>(RemovedProt & (PROT_READ | PROT_WRITE | PROT_EXEC));
  return UnionProtOf(Entry);
}

bool GranuleTable::RematerialiseIfNeeded(uint64_t GranuleBase) {
  auto* Entry = FindMutable(GranuleBase);
  if (!Entry) {
    return true;
  }

  const int Want = UnionProtOf(*Entry);
  if (Want == static_cast<int>(Entry->HostProt)) {
    // Already what the kernel has. Skipping the syscall is not just an
    // optimisation: at 64K, mprotect walks and re-inserts hash-table entries,
    // and the guest pthread-guard path (PAGE_SIZE_64K_PLAN finding 8) would
    // otherwise pay for it at every pthread_create.
    return true;
  }

  if (::mprotect(reinterpret_cast<void*>(GranuleBase), FEXCore::HostPage::Size(), Want) != 0) {
    // Leave HostProt describing what the kernel still has, so AssertInvariant
    // reports the divergence instead of the table lying about it.
    LogMan::Msg::EFmt("granule table: mprotect(0x{:x}, {}, {}) failed: {}", GranuleBase, FEXCore::HostPage::Size(), Want, ::strerror(errno));
    return false;
  }
  Entry->HostProt = static_cast<uint8_t>(Want);
  return true;
}

void GranuleTable::NoteHostProt(uint64_t GranuleBase, int Prot) {
  auto* Entry = FindMutable(GranuleBase);
  if (!Entry) {
    return;
  }
  Entry->HostProt = static_cast<uint8_t>(Prot & (PROT_READ | PROT_WRITE | PROT_EXEC));
}

void GranuleTable::AssertInvariant() const {
  for (const auto& [Base, Entry] : Granules) {
    [[maybe_unused]] const int Want = UnionProtOf(Entry);
    LOGMAN_THROW_A_FMT(Want == static_cast<int>(Entry.HostProt),
                       "granule table invariant violated at 0x{:x}: union|overlay says {} but the kernel has {}", Base, Want, Entry.HostProt);
  }
}

} // namespace FEX::HLE::VMATracking
