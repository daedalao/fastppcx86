// pageprobe -- host page-size facts FEX needs before it maps anything.
//
// Build (native, on the host under test):
//   cc -O2 -o pageprobe Scripts/64k/pageprobe.c
//
// Prints, in order:
//   AT_PAGESZ from the aux vector, sysconf(_SC_PAGESIZE), getpagesize(),
//   sbrk(0) and its alignment, MAP_FIXED_NOREPLACE hint results for
//   2^44..2^52 (does FEX's 48-bit steal allocator engage on this kernel?),
//   and whether a 4K-aligned MAP_FIXED and a 4K-granular mprotect succeed.
//
// Everything here is observation only; nothing is left mapped.

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static const char* yesno(int v) {
  return v ? "yes" : "no";
}

int main(void) {
  unsigned long at_pagesz = getauxval(AT_PAGESZ);
  long sc_pagesz = sysconf(_SC_PAGESIZE);
  int gp = getpagesize();

  printf("== page size ==\n");
  printf("AT_PAGESZ            = %lu\n", at_pagesz);
  printf("sysconf(_SC_PAGESIZE)= %ld\n", sc_pagesz);
  printf("getpagesize()        = %d\n", gp);
  printf("agree                = %s\n", yesno((unsigned long)sc_pagesz == at_pagesz && gp == sc_pagesz));

  size_t page = (size_t)(sc_pagesz > 0 ? sc_pagesz : 4096);

  printf("\n== brk ==\n");
  void* brk0 = sbrk(0);
  printf("sbrk(0)              = %p\n", brk0);
  printf("host-page aligned    = %s\n", yesno(((uintptr_t)brk0 & (page - 1)) == 0));
  printf("64K aligned          = %s\n", yesno(((uintptr_t)brk0 & 0xFFFFu) == 0));

  // Does the 48-bit steal allocator (OSAllocator_64Bit) have room to engage?
  printf("\n== MAP_FIXED_NOREPLACE hints (len = one host page) ==\n");
  for (int shift = 44; shift <= 52; ++shift) {
    void* hint = (void*)(uintptr_t)(1ULL << shift);
    void* got = mmap(hint, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    if (got == MAP_FAILED) {
      printf("2^%-2d %-18p FAILED  errno=%d (%s)\n", shift, hint, errno, strerror(errno));
    } else {
      printf("2^%-2d %-18p ok      got=%p%s\n", shift, hint, got, got == hint ? "" : " (MOVED)");
      munmap(got, page);
    }
  }

  // Sub-host-page granularity: the two things FEX's guest memory emulation
  // wants and the kernel refuses when the host page is larger than 4K.
  printf("\n== 4K granularity ==\n");
  void* base = mmap(NULL, page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (base == MAP_FAILED) {
    printf("scratch mmap FAILED errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }
  printf("scratch base         = %p (len %zu)\n", base, page * 4);

  // 4K-aligned, non-host-page-aligned MAP_FIXED into the middle of it.
  void* mid = (void*)((uintptr_t)base + 4096);
  void* fixed = mmap(mid, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (fixed == MAP_FAILED) {
    printf("4K MAP_FIXED @%p   FAILED  errno=%d (%s)\n", mid, errno, strerror(errno));
  } else {
    printf("4K MAP_FIXED @%p   ok (got %p)\n", mid, fixed);
  }

  // 4K-granular mprotect of a sub-page range.
  if (mprotect(mid, 4096, PROT_READ) == 0) {
    printf("4K mprotect  @%p   ok\n", mid);
    mprotect(mid, 4096, PROT_READ | PROT_WRITE);
  } else {
    printf("4K mprotect  @%p   FAILED  errno=%d (%s)\n", mid, errno, strerror(errno));
  }

  // And the host-page-granular versions, as the control.
  void* second = (void*)((uintptr_t)base + page);
  printf("host mprotect@%p   %s\n", second, mprotect(second, page, PROT_READ) == 0 ? "ok" : strerror(errno));
  mprotect(second, page, PROT_READ | PROT_WRITE);

  // Partial munmap at 4K granularity: does the kernel round, or refuse?
  if (munmap(mid, 4096) == 0) {
    printf("4K munmap    @%p   ok (kernel rounded the range)\n", mid);
  } else {
    printf("4K munmap    @%p   FAILED  errno=%d (%s)\n", mid, errno, strerror(errno));
  }

  munmap(base, page * 4);
  return 0;
}
