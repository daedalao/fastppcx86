// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/string.h>

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace FEXCore::Core {
struct InternalThreadState;
}

/**
 * @brief Guest memory-syscall emulation for a host page larger than the guest's
 *        (docs/PAGE_SIZE_64K_PLAN.md Part 2 §2 and §7).
 *
 * Every entry point here returns false without doing anything when the host page
 * equals the guest page, which is every path the shipping 4K build takes: the
 * registration sites fall through to the untouched GuestMmap/GuestMunmap/
 * GuestMprotect/GuestMremap, so the 4K build is byte-identical to the pre-port
 * tree.
 *
 * When the host page is larger, each entry point either
 *   - returns false, meaning "this request is host-representable, take the normal
 *     path", which is the common case (anonymous mmap(NULL), host-aligned
 *     MAP_FIXED, whole-granule munmap/mprotect), or
 *   - returns true with *Result set, having done the work itself.
 *
 * The requests that need work are the ones the guest builds out of its
 * AT_PAGESZ=4096 view: MAP_FIXED at a 4K-but-not-granule-aligned address, a
 * munmap that frees part of a granule, and -- the hot one, see
 * PAGE_SIZE_64K_PLAN finding 8 -- the 4K PROT_NONE guard glibc mprotects at the
 * low end of every pthread stack.
 */
namespace FEX::HLE::Granule {

/// True when any of this does anything, i.e. the host page is larger than 4096.
bool Active();

bool Mmap(FEXCore::Core::InternalThreadState* Thread, bool Is64Bit, void* addr, size_t length, int prot, int flags, int fd, off_t offset,
          uint64_t* Result);
bool Munmap(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, uint64_t* Result);
bool Mprotect(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int prot, uint64_t* Result);
bool Mremap(FEXCore::Core::InternalThreadState* Thread, bool Is64Bit, void* old_address, size_t old_size, size_t new_size, int flags,
            void* new_address, uint64_t* Result);

///// Guest-visible reporting (§7) /////

/// mincore's vector is one byte per GUEST page; a raw passthrough both sizes it
/// by the host page and EINVALs on a 4K-aligned address. Answers from the
/// granule table plus the host's own answer for the containing granule.
bool Mincore(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, uint8_t* vec, uint64_t* Result);
bool Msync(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int flags, uint64_t* Result);
bool Madvise(FEXCore::Core::InternalThreadState* Thread, void* addr, size_t length, int advice, uint64_t* Result);

/// /proc/self/maps (Smaps == false) and /proc/self/smaps, synthesised from
/// VMATracking and the granule table. Returns an empty string when there is
/// nothing to report (no tracking yet), which the caller treats as "fall back
/// to the host file".
fextl::string GenerateMaps(bool Smaps);

} // namespace FEX::HLE::Granule
