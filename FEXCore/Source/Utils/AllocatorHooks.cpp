// SPDX-License-Identifier: MIT
#ifdef ENABLE_FEX_ALLOCATOR
#include <rpmalloc/rpmalloc.h>
#ifndef _WIN32
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#else
#define NTDDI_VERSION 0x0A000005
#include <memoryapi.h>
#endif
#endif

#include <cstdint>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atomic>

namespace FEXCore::Allocator {

// Placement hint for FEX's *own* anonymous reservations.
//
// Everything FEX allocates for itself -- the rpmalloc arenas ("FEXAllocator"),
// the per-thread LookupCache ("FEXMem_Lookup", 272 MiB each with the default
// VirtualMemSize), JIT code buffers, dispatcher stacks, the fextl pools --
// used to be mapped with addr=nullptr, letting the kernel place it wherever.
// In practice that means interleaved with the guest's own mappings, since both
// come out of the same top-down mmap region.
//
// That interleaving breaks guests. Measured running Ziggurat (Unity 4.7) on an
// 80-core POWER8: FEX held ~69 GiB of reservations against the guest's ~6 GiB,
// sprayed between the guest's thread stacks, which pushed the guest's heaps
// across 20 different (address >> 32) 4 GiB regions. Unity indexes its allocator
// metadata by address>>32 in a fixed 5-entry table, so it overflowed, took its
// not-found path, and crashed. A guest is entitled to assume its own allocations
// stay reasonably clustered; the emulator should not be salting its address space.
//
// Bump a hint through a window well clear of both the guest's executable/brk and
// 32-bit region (below) and the kernel's top-down mmap area (above). This is only
// a hint -- never MAP_FIXED -- so if anything already occupies the address the
// kernel simply places the mapping elsewhere and we are no worse off.
namespace {
// 1 TiB base, 31 TiB of hint space -- still an order of magnitude below the
// ~64 TiB top-down region the kernel hands out for ordinary mmaps.
constexpr uintptr_t INTERNAL_ARENA_BASE = 0x0000010000000000ULL;
constexpr uintptr_t INTERNAL_ARENA_SIZE = 0x00001F0000000000ULL;
std::atomic<uintptr_t> InternalArenaOffset {0};
} // namespace

void* GetInternalPlacementHint(size_t Size) {
#ifdef _WIN32
  return nullptr;
#else
  // Page-align and leave a page of slack so an oversized mapping doesn't force
  // the kernel to ignore the hint entirely.
  constexpr size_t PageSize = 4096;
  const size_t Reserve = ((Size + PageSize - 1) & ~(PageSize - 1)) + PageSize;
  if (Reserve >= INTERNAL_ARENA_SIZE) {
    // Absurdly large; let the kernel choose.
    return nullptr;
  }
  // Wrap rather than give up once the window is walked. The bump is cumulative,
  // not live-set: rpmalloc maps and unmaps continuously, so a monotonic pointer
  // walks off the end long before FEX's actual footprint would. On wrap the hint
  // may land on something already mapped, in which case the kernel just picks a
  // nearby free address -- which is still inside this window, so the clustering
  // holds either way.
  const uintptr_t Offset = InternalArenaOffset.fetch_add(Reserve, std::memory_order_relaxed) % (INTERNAL_ARENA_SIZE - Reserve);
  return reinterpret_cast<void*>(INTERNAL_ARENA_BASE + (Offset & ~(uintptr_t)(PageSize - 1)));
#endif
}

using mmap_hook_type = void* (*)(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
using munmap_hook_type = int (*)(void* addr, size_t length);

#ifdef ENABLE_FEX_ALLOCATOR
typedef void* (*rp_mmap_hook_type)(size_t size, size_t alignment, size_t* offset, size_t* mapped_size);
typedef void (*rp_munmap_hook_type)(void* address, size_t offset, size_t mapped_size);
extern "C" rp_mmap_hook_type rp_mmap_hook;
extern "C" rp_munmap_hook_type rp_munmap_hook;

#ifndef _WIN32
// Default mapper for FEX's own allocations. Applies the placement hint so the
// clustering holds regardless of whether SetupHooks/InitializeAllocator ever
// ran -- they only run for 32-bit guests, so a 64-bit guest would otherwise
// keep scattering rpmalloc's arenas through the guest's address space.
static void* FEX_default_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  if (addr == nullptr && (flags & MAP_ANONYMOUS) && !(flags & MAP_FIXED)) {
    addr = GetInternalPlacementHint(length);
  }
  return ::mmap(addr, length, prot, flags, fd, offset);
}

mmap_hook_type fex_mmap_hook = FEX_default_mmap;
munmap_hook_type fex_munmap_hook = ::munmap;
#endif

// Assume a 64KB page size until told otherwise.
static rpmalloc_config_t global_config {
  .page_size = 64 * 1024,
  // THP causes crashes for some reason.
  .enable_huge_pages = 0,
  .disable_decommit = 0,
  .page_name = "FEXAllocator",
  .huge_page_name = "FEXAllocator",
  .unmap_on_finalize = 0,
};

void* malloc(size_t size) {
  return ::rpmalloc(size);
}
void* calloc(size_t n, size_t size) {
  return ::rpcalloc(n, size);
}
void* memalign(size_t align, size_t s) {
  return ::rpmemalign(align, s);
}
void* valloc(size_t size) {
  return ::rpaligned_alloc(global_config.page_size, size);
}
int posix_memalign(void** r, size_t a, size_t s) {
  void* ptr;
  auto res = ::rpposix_memalign(&ptr, a, s);
  *r = ptr;
  return res;
}
void* realloc(void* ptr, size_t size) {
  return ::rprealloc(ptr, size);
}
void free(void* ptr) {
  return ::rpfree(ptr);
}
size_t malloc_usable_size(void* ptr) {
  return ::rpmalloc_usable_size(ptr);
}
void* aligned_alloc(size_t a, size_t s) {
  return ::rpaligned_alloc(a, s);
}
void aligned_free(void* ptr) {
  return ::rpfree(ptr);
}

void InitializeThread() {
  rpmalloc_thread_initialize();
}

#ifndef _WIN32
[[nodiscard]]
constexpr uint64_t AlignUp(uint64_t value, uint64_t size) {
  return value + (size - value % size) % size;
}

static void* FEX_rp_mmap(size_t size, size_t alignment, size_t* offset, size_t* mapped_size) {
#define pointer_offset(ptr, ofs) (void*)((char*)(ptr) + (ptrdiff_t)(ofs))
  // If the alignment is less than the operating page size then alignment is guaranteed. Just remove it.
  if (alignment < global_config.page_size) {
    alignment = 0;
  }

  size_t map_size = AlignUp(size + alignment, global_config.page_size);
  auto ptr = fex_mmap_hook(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (ptr == MAP_FAILED) {
    ptr = nullptr;
  } else {
#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif

#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, map_size, global_config.page_name);

    // Disable HUGEPAGE on allocation from rpmalloc.
    madvise(ptr, map_size, MADV_NOHUGEPAGE);
  }

  if (ptr == nullptr) {
    fprintf(stderr, "Failed to map VMA region.");
    return nullptr;
  }

  if (alignment) {
    size_t padding = ((uintptr_t)ptr & (uintptr_t)(alignment - 1));
    if (padding) {
      padding = alignment - padding;
    }
    ptr = pointer_offset(ptr, padding);
    *offset = padding;
  }
  *mapped_size = map_size;
  return ptr;
}

static void FEX_rp_memory_commit(void* address, size_t size) {
  // NOP-implementation.
}

static void FEX_rp_memory_decommit(void* address, size_t size) {
  if (global_config.disable_decommit) {
    return;
  }

  if (madvise(address, size, MADV_DONTNEED)) {
    fprintf(stderr, "Failed to decommit VMA region.");
  }
}

static void FEX_rp_memory_unmap(void* address, size_t offset, size_t mapped_size) {
  address = pointer_offset(address, -(int32_t)offset);
  int Result = fex_munmap_hook(address, mapped_size);
  if (Result == -1) {
    fprintf(stderr, "Failed to unmap VMA region.");
  }
#undef pointer_offset
}

void SetupAllocatorHooks(mmap_hook_type MMapHook, munmap_hook_type MunmapHook) {
  fex_mmap_hook = MMapHook;
  fex_munmap_hook = MunmapHook;
}

static rpmalloc_interface_t global_interface {
  .memory_map = FEX_rp_mmap,
  .memory_commit = FEX_rp_memory_commit,
  .memory_decommit = FEX_rp_memory_decommit,
  .memory_unmap = FEX_rp_memory_unmap,
  .map_fail_callback = nullptr,
  .error_callback = nullptr,
};

void InitializeAllocator(size_t PageSize) {
  global_config.page_size = PageSize;
  rpmalloc_initialize_config(&global_interface, &global_config);
  rp_mmap_hook = FEX_rp_mmap;
  rp_munmap_hook = FEX_rp_memory_unmap;
}
#endif

#elif defined(_WIN32)
#error "Tried building _WIN32 without jemalloc"

#else
void InitializeThread() {}

void* malloc(size_t size) {
  return ::malloc(size);
}
void* calloc(size_t n, size_t size) {
  return ::calloc(n, size);
}
void* memalign(size_t align, size_t s) {
  return ::memalign(align, s);
}
void* valloc(size_t size) {
  return ::valloc(size);
}
int posix_memalign(void** r, size_t a, size_t s) {
  return ::posix_memalign(r, a, s);
}
void* realloc(void* ptr, size_t size) {
  return ::realloc(ptr, size);
}
void free(void* ptr) {
  return ::free(ptr);
}
size_t malloc_usable_size(void* ptr) {
  return ::malloc_usable_size(ptr);
}
void* aligned_alloc(size_t a, size_t s) {
  return ::aligned_alloc(a, s);
}
void aligned_free(void* ptr) {
  return ::free(ptr);
}

void SetupAllocatorHooks(mmap_hook_type MMapHook, munmap_hook_type MunmapHook) {}

void InitializeAllocator(size_t PageSize) {}

#endif
} // namespace FEXCore::Allocator
