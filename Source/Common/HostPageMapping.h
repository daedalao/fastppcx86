// SPDX-License-Identifier: MIT
#pragma once

// ---------------------------------------------------------------------------
// File mappings whose alignment the host kernel cannot represent (64K port, S4)
// ---------------------------------------------------------------------------
// x86 toolchains emit p_align = 0x1000 and the x86 mmap2 ABI counts file
// offsets in 4096-byte units, so a guest file mapping is only ever guaranteed
// to be 4K-congruent. A host mmap requires `offset % hostpage == 0` (and, for
// MAP_FIXED, `addr % hostpage == 0`). On a host whose page is larger than the
// guest's, the request has to be emulated: establish the containing host pages
// as private anonymous memory, pread the file bytes into place, then apply the
// requested protection at host granularity.
//
// The cost is that such a mapping is no longer shared with the page cache.
// That is an RSS cost, not a semantics cost (design Part 2 section 3), and it
// only applies on a host whose page size differs from the guest's -- every
// predicate here short-circuits to "no fallback" when they match, so the 4K
// build never reaches any of this.
// ---------------------------------------------------------------------------

#include <FEXCore/Utils/TypeDefines.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace FEX::HostPageMapping {

/**
 * @brief Can this mapping request be handed to the host kernel verbatim?
 *
 * Anything anonymous can: the kernel rounds the length up itself and the
 * guest-visible address it returns is host-aligned, which is also 4K-aligned,
 * which is all the guest ABI promises. Only file offsets and MAP_FIXED
 * addresses carry a congruence the host cannot satisfy.
 */
[[nodiscard]]
inline bool RequiresFallback(uint64_t Addr, uint64_t Offset, int Flags, int FD) {
  if (FEXCore::HostPage::MatchesGuest()) {
    // The overwhelmingly common case, and the shipping 4K build's only case.
    return false;
  }

  if ((Flags & MAP_ANONYMOUS) || FD == -1) {
    return false;
  }

  if (!FEXCore::HostPage::IsAligned(Offset)) {
    return true;
  }

  // A non-fixed mapping lets the kernel pick a host-aligned address, so only a
  // caller-dictated address can be unrepresentable.
  if ((Flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) && !FEXCore::HostPage::IsAligned(Addr)) {
    return true;
  }

  return false;
}

/**
 * @brief pread a whole range, retrying short reads and EINTR.
 *
 * A short read at EOF is not an error: mmap past the end of a file gives zero
 * bytes, and the destination here is freshly anonymous (or has been explicitly
 * zeroed by the caller), so stopping early reproduces that. Returns false only
 * on a real I/O error.
 */
inline bool ReadFully(int FD, void* Dest, size_t Size, uint64_t Offset) {
  auto* Out = static_cast<uint8_t*>(Dest);
  while (Size) {
    const ssize_t Read = ::pread(FD, Out, Size, static_cast<off_t>(Offset));
    if (Read < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (Read == 0) {
      // EOF; the remainder stays zero, matching mmap-past-EOF.
      return true;
    }
    Out += Read;
    Offset += Read;
    Size -= static_cast<size_t>(Read);
  }
  return true;
}

/**
 * @brief Emulate one unrepresentable file mapping.
 *
 * MmapFn:     void*(void* Addr, size_t Length, int Prot, int Flags, int FD, off_t Offset)
 * MprotectFn: uint64_t(void* Addr, size_t Length, int Prot)
 *
 * Both are supplied by the caller so the mapping is made through whatever layer
 * owns the address space (the guest syscall handler, the 32-bit allocator, ...)
 * rather than behind its back.
 *
 * Only valid for MAP_PRIVATE. MAP_SHARED at an unrepresentable alignment cannot
 * be emulated by copying -- the caller must reject it (design Part 2 section 2).
 *
 * Returns the guest-visible address, or a negative errno encoded as a pointer
 * (the convention FEX::HLE::HasSyscallError() decodes).
 */
template<typename MmapFn, typename MprotectFn>
inline void* MapFilePrivate(MmapFn&& Mmap, MprotectFn&& Mprotect, void* Addr, size_t Length, int Prot, int Flags, int FD, uint64_t Offset) {
  const uint64_t Guest = reinterpret_cast<uint64_t>(Addr);
  const bool Fixed = (Flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0;

  // Reserve the host pages that back the request. Without a fixed address the
  // kernel picks, and the result is host-aligned by construction, so the guest
  // address is simply the reservation base.
  const uint64_t HostStart = Fixed ? FEXCore::HostPage::AlignDown(Guest) : 0;
  const uint64_t HostLength = Fixed ? FEXCore::HostPage::AlignUp(Guest + Length) - HostStart : FEXCore::HostPage::AlignUp(Length);

  const int AnonFlags = (Flags & ~(MAP_SHARED | MAP_SHARED_VALIDATE | MAP_DENYWRITE)) | MAP_PRIVATE | MAP_ANONYMOUS;

  // Write permission is needed for the pread regardless of what the caller
  // asked for; the requested protection is applied afterwards.
  void* Base = Mmap(reinterpret_cast<void*>(HostStart), HostLength, PROT_READ | PROT_WRITE, AnonFlags, -1, 0);
  if (reinterpret_cast<uint64_t>(Base) >= -4095ULL) {
    return Base;
  }

  const uint64_t Result = Fixed ? Guest : reinterpret_cast<uint64_t>(Base);
  if (!ReadFully(FD, reinterpret_cast<void*>(Result), Length, Offset)) {
    return reinterpret_cast<void*>(static_cast<int64_t>(-errno));
  }

  if (Prot != (PROT_READ | PROT_WRITE)) {
    // Host granularity: a protection finer than the host page cannot be
    // installed, so the whole reservation takes the requested one. The
    // reservation is private to this mapping, so nothing else is affected.
    Mprotect(reinterpret_cast<void*>(FEXCore::HostPage::AlignDown(Result)), HostLength, Prot);
  }

  return reinterpret_cast<void*>(Result);
}

} // namespace FEX::HostPageMapping
