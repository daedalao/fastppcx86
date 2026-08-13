// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/vector.h>

#include <cstddef>
#include <cstdint>

namespace FEX::HLE {

// Spelled out rather than relying on the host's headers, exactly as
// LinuxAllocator.cpp does: the value is architecture-independent in Linux and
// must be parsed whether or not the build host's <sys/mman.h> knows it.
constexpr int FEX_MAP_FIXED_NOREPLACE = 0x100000;

/**
 * @brief The host address ranges a 64-bit guest must never be allowed to
 *        replace, unmap or reprotect.
 *
 * WHY THIS EXISTS (ppc64le-specific, measured):
 *
 * FEX and the guest share one address space. For a 64-bit guest,
 * SyscallHandler::GuestMmap forwards the guest's mmap straight to the host
 * kernel with the guest's flags intact, so a guest `mmap(MAP_FIXED)` destroys
 * whatever was at that address -- including FEX's own text.
 *
 * On ppc64le, `ELF_ET_DYN_BASE` is 0x1'0000'0000 (arch/powerpc/include/asm/
 * elf.h), so the kernel places FEX's PIE image at 4 GiB + up to 1 GiB of
 * randomisation, i.e. somewhere in [0x1'0000'0000, 0x1'4000'0000). The top of
 * that window is 0x1'4000'0000 -- which is the default `ImageBase` of every
 * 64-bit Windows PE, and the address Wine's `wine64-preloader` reserves with an
 * unconditional
 *
 *     mmap(0x140000000, SizeOfImage, PROT_NONE,
 *          MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
 *
 * for every PE process it starts. When FEX's ~7.3 MiB image lands in the top
 * 7.3 MiB of the ASLR window (p ~ 0.68% per exec), that reservation lands on
 * FEX's own code or .bss and the emulator dies at the next call into the
 * clobbered range -- typically with a SIGSEGV somewhere deep in FEXCore that
 * looks like a use-after-free but is an instruction fetch from a PROT_NONE
 * page.
 *
 * On arm64 and x86-64 hosts `ELF_ET_DYN_BASE` is ~0x5555'5555'4000 /
 * 2*TASK_SIZE/3, nowhere near a PE image base, which is why upstream FEX has
 * never needed this.
 *
 * WHAT IT DOES
 *
 * SnapshotSelf() is called once, after FEX's own allocator is up and *before*
 * any guest memory is mapped, and records every mapping that exists at that
 * moment: FEX's image (text, rodata, data, bss), the sbrk guard page, the host
 * libraries, the host stack, the vdso, and FEX's stolen allocator regions.
 * Everything recorded is host-private by construction -- the guest did not
 * exist yet -- so refusing a guest request that would destroy one of them can
 * never refuse something the guest legitimately owns.
 *
 * The guest is told "no" the same way the kernel would tell it "no", and the
 * failure is one Wine already handles: `preloader: Warning: failed to reserve
 * range ...`, after which ntdll relocates the image.
 *
 * SCOPE / KNOWN GAPS (deliberate, see docs/fex-teardown-crash.md):
 *  - Only mappings that exist at snapshot time are protected. Host allocations
 *    made later (JIT CodeBuffers, per-thread LookupCache tables, rpmalloc
 *    arenas) are not, unless registered through Add(). They land in the host
 *    mmap arena at 0x3fff'xxxx'xxxx, which no Wine PE base targets.
 *  - Only MAP_FIXED-class requests are checked. Without MAP_FIXED the kernel
 *    never places a mapping over an existing one, so there is nothing to guard.
 */
class HostOwnedRanges final {
public:
  /// Record every currently-existing mapping as host-owned. Idempotent; the
  /// second and later calls are ignored so an execve-style re-entry cannot
  /// swallow guest mappings.
  static void SnapshotSelf();

  /// Register an additional host-owned range (page-aligned internally).
  static void Add(uint64_t Base, uint64_t Size);

  /// If [Base, Base+Size) intersects a host-owned range, returns that range;
  /// otherwise returns {0, 0}. Lets the refusal diagnostic name the mapping it
  /// just saved, which is what distinguishes a genuine PIE-base collision from
  /// a table that has grown a false entry.
  struct Range;
  static Range FindOverlap(uint64_t Base, uint64_t Size);

  /// True if [Base, Base+Size) intersects any host-owned range.
  /// Always false before SnapshotSelf() has run, so tools that never call it
  /// (TestHarnessRunner, CodeSizeValidation, unit tests) are unaffected.
  static bool Overlaps(uint64_t Base, uint64_t Size);

  /// Emit one diagnostic line for a refused guest request. Rate-limited so a
  /// guest that retries in a loop cannot flood the log.
  static void ReportRefusal(const char* Op, uint64_t Base, uint64_t Size);

  struct Range {
    uint64_t Base;
    uint64_t End; // exclusive
    // False only for mappings the kernel itself refuses to ever make writable
    // ([vvar]: VM_MAYWRITE is clear). A refused mprotect(PROT_WRITE) over one
    // of these must fail with the kernel's own EACCES rather than ENOMEM --
    // the mapping is visible in the guest's /proc/self/maps, and gvisor's
    // VvarTest.WriteVvar checks for exactly that errno.
    bool MayWrite = true;
  };

  /// Test/diagnostic accessor.
  static const fextl::vector<Range>& GetRanges();
};

} // namespace FEX::HLE
