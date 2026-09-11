// SPDX-License-Identifier: MIT
/*
 * Guest-4K memory semantics, from the guest's side of the fiction.
 *
 * The guest is handed AT_PAGESZ=4096 unconditionally, so every expectation in
 * this file is a plain 4096-byte expectation and none of it is conditional on
 * the host page size. That is the point: on a 4K host this is an ordinary
 * regression test, and on a 64K host it is the acceptance test for the granule
 * table (docs/PAGE_SIZE_64K_PLAN.md Part 2 §2 and §7) -- every case here is one
 * the host kernel cannot express and FEX has to emulate.
 *
 * Deliberately NOT tested: that a PROT_NONE guard page inside a live granule
 * faults. At the permissive tier it does not, by design (§6), and a test that
 * demanded it would be asserting the tier we have not built yet.
 *
 * Written to compile both as C++ (it joins FEXLinuxTests) and as C with
 * `x86_64-pc-linux-gnu-gcc -static -x c`, because until the stage-S4a loader
 * work lands nothing dynamic loads on a 64K host and the only way to run this
 * there is a static binary.
 *
 * Building it standalone for a 64K host, until the stage-S4a loader work
 * lands: the ELF loader still maps PT_LOAD segments at their 4K-congruent file
 * offsets, so even a static binary has to be linked with every LOAD segment,
 * and the bss ends, on 64K boundaries. Scripts/granule_page_64k.sh does that;
 * the short version is a copy of ld's default script with
 *   . = ALIGN(0x10000);                             before the data segment,
 *   .fexfilepad : { BYTE(0); . = ALIGN(0x10000); }  before __bss_start,
 *   . = ALIGN(0x10000);                             at the end of .bss,
 * plus -static -z max-page-size=0x10000 -z norelro --build-id=none.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GUEST_PAGE 4096u

static int Failures = 0;
static int Checks = 0;

#define CHECK(cond, ...)                                  \
  do {                                                    \
    ++Checks;                                             \
    if (!(cond)) {                                        \
      ++Failures;                                         \
      printf("FAIL %s:%d: " #cond "\n", __func__, __LINE__); \
      printf("     ");                                    \
      printf(__VA_ARGS__);                                \
      printf("\n");                                       \
    }                                                     \
  } while (0)

static void FillPattern(unsigned char* Base, unsigned long Length, unsigned char Seed) {
  unsigned long i;
  for (i = 0; i < Length; ++i) {
    Base[i] = (unsigned char)(Seed + (i & 0x7F));
  }
}

static int CheckPattern(const unsigned char* Base, unsigned long Length, unsigned char Seed) {
  unsigned long i;
  for (i = 0; i < Length; ++i) {
    if (Base[i] != (unsigned char)(Seed + (i & 0x7F))) {
      return 0;
    }
  }
  return 1;
}

static int CheckZero(const unsigned char* Base, unsigned long Length) {
  unsigned long i;
  for (i = 0; i < Length; ++i) {
    if (Base[i] != 0) {
      return 0;
    }
  }
  return 1;
}

///// /proc/self/maps /////

struct MapLine {
  unsigned long Base;
  unsigned long End;
  char Perms[8];
};

#define MAX_MAP_LINES 4096
static struct MapLine Maps[MAX_MAP_LINES];
static int MapCount;

// Reads and parses /proc/self/maps in one go. Returns the number of lines, or
// -1. A read(2) loop, not fopen: the file must be consumed in as few syscalls
// as possible or the address space it describes changes underneath it.
static int ReadMaps(void) {
  static char Buffer[1 << 20];
  int FD;
  ssize_t Got;
  size_t Used = 0;
  char* Cursor;

  MapCount = 0;
  FD = open("/proc/self/maps", O_RDONLY);
  if (FD < 0) {
    return -1;
  }
  for (;;) {
    Got = read(FD, Buffer + Used, sizeof(Buffer) - 1 - Used);
    if (Got < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(FD);
      return -1;
    }
    if (Got == 0) {
      break;
    }
    Used += (size_t)Got;
    if (Used + 1 >= sizeof(Buffer)) {
      break;
    }
  }
  close(FD);
  Buffer[Used] = '\0';

  Cursor = Buffer;
  while (*Cursor && MapCount < MAX_MAP_LINES) {
    unsigned long Base = 0, End = 0;
    char Perms[8];
    char* LineEnd = strchr(Cursor, '\n');
    if (LineEnd) {
      *LineEnd = '\0';
    }
    Perms[0] = '\0';
    if (sscanf(Cursor, "%lx-%lx %7s", &Base, &End, Perms) == 3) {
      Maps[MapCount].Base = Base;
      Maps[MapCount].End = End;
      strncpy(Maps[MapCount].Perms, Perms, sizeof(Maps[MapCount].Perms) - 1);
      Maps[MapCount].Perms[sizeof(Maps[MapCount].Perms) - 1] = '\0';
      ++MapCount;
    }
    if (!LineEnd) {
      break;
    }
    Cursor = LineEnd + 1;
  }
  return MapCount;
}

// Perms of the mapping covering Addr, or NULL when Addr is in a hole.
static const char* PermsAt(unsigned long Addr) {
  int i;
  for (i = 0; i < MapCount; ++i) {
    if (Addr >= Maps[i].Base && Addr < Maps[i].End) {
      return Maps[i].Perms;
    }
  }
  return NULL;
}

///// Tests /////

// MAP_FIXED at 4K-but-not-granule offsets, inside a reservation. Every fixed
// mapping here starts at an address a 64K kernel cannot take, and the sibling
// pages around it must survive untouched.
static void TestFixedAt4KOffsets(void) {
  const unsigned long Length = 16 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned char* First;
  unsigned char* Second;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  FillPattern(Base, Length, 0x11);

  // One guest page at +4K. On a 64K host this lands inside a granule with 15
  // live siblings.
  First = (unsigned char*)mmap(Base + GUEST_PAGE, GUEST_PAGE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  CHECK(First == Base + GUEST_PAGE, "MAP_FIXED at +4K returned %p want %p (%s)", (void*)First, (void*)(Base + GUEST_PAGE), strerror(errno));
  CHECK(CheckZero(Base + GUEST_PAGE, GUEST_PAGE), "a fresh anonymous MAP_FIXED must read as zero");
  CHECK(CheckPattern(Base, GUEST_PAGE, 0x11), "the page below the fixed mapping was clobbered");
  CHECK(CheckPattern(Base + 2 * GUEST_PAGE, GUEST_PAGE, (unsigned char)(0x11 + ((2 * GUEST_PAGE) & 0x7F))) ||
          Base[2 * GUEST_PAGE] == (unsigned char)(0x11 + ((2 * GUEST_PAGE) & 0x7F)),
        "the page above the fixed mapping was clobbered");

  // A second one at +3 pages, three pages long, crossing what would be a
  // granule boundary on a 64K host if Base happened to be granule-aligned.
  Second = (unsigned char*)mmap(Base + 3 * GUEST_PAGE, 3 * GUEST_PAGE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  CHECK(Second == Base + 3 * GUEST_PAGE, "MAP_FIXED at +12K returned %p (%s)", (void*)Second, strerror(errno));
  CHECK(CheckZero(Base + 3 * GUEST_PAGE, 3 * GUEST_PAGE), "the second fixed mapping must read as zero");

  // And they must be independently writable afterwards.
  FillPattern(Base + GUEST_PAGE, GUEST_PAGE, 0x22);
  FillPattern(Base + 3 * GUEST_PAGE, 3 * GUEST_PAGE, 0x33);
  CHECK(CheckPattern(Base + GUEST_PAGE, GUEST_PAGE, 0x22), "first fixed mapping is not writable");
  CHECK(CheckPattern(Base + 3 * GUEST_PAGE, 3 * GUEST_PAGE, 0x33), "second fixed mapping is not writable");

  munmap(Base, Length);
}

// A file mapping at a 4K file offset that is not a host page offset. On a 64K
// host this is the pread path.
static void TestFixedFileAt4KOffset(void) {
  char Template[] = "/tmp/fex-granule-XXXXXX";
  int FD;
  unsigned long Length = 8 * GUEST_PAGE;
  unsigned char* Scratch;
  unsigned char* Mapped;
  unsigned long i;

  // The guest's /tmp, not the host's: this runs under FEX's RootFS.
  FD = mkstemp(Template);
  if (FD < 0) {
    printf("SKIP %s: no writable temp file (%s)\n", __func__, strerror(errno));
    return;
  }
  unlink(Template);

  Scratch = (unsigned char*)malloc(Length);
  CHECK(Scratch != NULL, "malloc");
  if (!Scratch) {
    close(FD);
    return;
  }
  for (i = 0; i < Length; ++i) {
    Scratch[i] = (unsigned char)(i * 7 + 3);
  }
  CHECK(write(FD, Scratch, Length) == (ssize_t)Length, "write: %s", strerror(errno));

  // offset 4096: legal for the guest, unrepresentable for a 64K kernel.
  Mapped = (unsigned char*)mmap(NULL, 3 * GUEST_PAGE, PROT_READ, MAP_PRIVATE, FD, GUEST_PAGE);
  CHECK(Mapped != MAP_FAILED, "mmap(file, offset=4096): %s", strerror(errno));
  if (Mapped != MAP_FAILED) {
    CHECK(memcmp(Mapped, Scratch + GUEST_PAGE, 3 * GUEST_PAGE) == 0, "file content at a 4K offset is wrong");
    munmap(Mapped, 3 * GUEST_PAGE);
  }

  free(Scratch);
  close(FD);
}

// Unmapping one guest page out of a larger mapping. The siblings must survive
// with their contents, and the hole must be visible in /proc/self/maps -- which
// on a 64K host it can only be because the granule table records it, the
// granule itself still being mapped for the siblings' sake.
static void TestPartialMunmap(void) {
  const unsigned long Length = 16 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned long Hole;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  FillPattern(Base, Length, 0x44);
  Hole = (unsigned long)Base + 5 * GUEST_PAGE;

  CHECK(munmap((void*)Hole, GUEST_PAGE) == 0, "partial munmap: %s", strerror(errno));

  CHECK(CheckPattern(Base, 5 * GUEST_PAGE, 0x44), "pages below the hole lost their contents");
  CHECK(Base[6 * GUEST_PAGE] == (unsigned char)(0x44 + ((6 * GUEST_PAGE) & 0x7F)), "the page above the hole lost its contents");

  // Still writable on both sides.
  Base[4 * GUEST_PAGE] = 0xA5;
  Base[6 * GUEST_PAGE] = 0x5A;
  CHECK(Base[4 * GUEST_PAGE] == 0xA5 && Base[6 * GUEST_PAGE] == 0x5A, "siblings of a partial munmap are not writable");

  CHECK(ReadMaps() > 0, "could not read /proc/self/maps");
  CHECK(PermsAt(Hole) == NULL, "the partially unmapped page is still listed in /proc/self/maps");
  CHECK(PermsAt(Hole - GUEST_PAGE) != NULL, "the page below the hole vanished from /proc/self/maps");
  CHECK(PermsAt(Hole + GUEST_PAGE) != NULL, "the page above the hole vanished from /proc/self/maps");

  // Unmapping the rest must work and must not leave anything behind.
  CHECK(munmap(Base, 5 * GUEST_PAGE) == 0, "munmap head: %s", strerror(errno));
  CHECK(munmap(Base + 6 * GUEST_PAGE, Length - 6 * GUEST_PAGE) == 0, "munmap tail: %s", strerror(errno));
  CHECK(ReadMaps() > 0, "could not re-read /proc/self/maps");
  CHECK(PermsAt((unsigned long)Base) == NULL, "the whole region should be gone");
}

// A protection ladder across what is one host page on a 64K kernel. Every rung
// is a separate 4K mprotect of a different protection.
static void TestProtLadder(void) {
  const unsigned long Length = 16 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  const int Ladder[4] = {PROT_NONE, PROT_READ, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC};
  const char* Expect[4] = {"---p", "r--p", "rw-p", "r-xp"};
  int i;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  FillPattern(Base, Length, 0x66);

  for (i = 0; i < 4; ++i) {
    CHECK(mprotect(Base + (unsigned long)i * GUEST_PAGE, GUEST_PAGE, Ladder[i]) == 0, "mprotect rung %d: %s", i, strerror(errno));
  }

  // The rung the guest left writable must still be writable. On a 64K host this
  // is the union-permissive materialisation doing its job: the granule carries
  // the most permissive protection of its 16 pages.
  Base[2 * GUEST_PAGE] = 0xC3;
  CHECK(Base[2 * GUEST_PAGE] == 0xC3, "the PROT_READ|PROT_WRITE rung is not writable");

  // And the readable rungs must still read their old contents.
  CHECK(Base[GUEST_PAGE] == (unsigned char)(0x66 + (GUEST_PAGE & 0x7F)), "the PROT_READ rung lost its contents");
  CHECK(Base[3 * GUEST_PAGE] == (unsigned char)(0x66 + ((3 * GUEST_PAGE) & 0x7F)), "the PROT_READ|PROT_EXEC rung lost its contents");

  // /proc must report what the guest ASKED for, not what the host materialised.
  CHECK(ReadMaps() > 0, "could not read /proc/self/maps");
  for (i = 0; i < 4; ++i) {
    const char* Got = PermsAt((unsigned long)Base + (unsigned long)i * GUEST_PAGE);
    CHECK(Got != NULL && strcmp(Got, Expect[i]) == 0, "rung %d reports %s, want %s", i, Got ? Got : "(hole)", Expect[i]);
  }

  // Put it all back and check the contents survived the round trip.
  CHECK(mprotect(Base, 4 * GUEST_PAGE, PROT_READ | PROT_WRITE) == 0, "mprotect back: %s", strerror(errno));
  CHECK(Base[GUEST_PAGE] == (unsigned char)(0x66 + (GUEST_PAGE & 0x7F)), "contents lost across the protection round trip");

  munmap(Base, Length);
}

// mincore's vector is one byte per GUEST page. A host that sized it by its own
// page would overflow this buffer's guard, and a raw passthrough EINVALs on a
// 4K-aligned address.
static void TestMincoreVector(void) {
  const unsigned long Pages = 9;
  const unsigned long Length = 16 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned char Vec[16];
  unsigned long i;
  int Result;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  FillPattern(Base, Length, 0x77);
  memset(Vec, 0xEE, sizeof(Vec));

  // Start at +4K so the address is 4K- but (on a 64K host) not granule-aligned.
  Result = mincore(Base + GUEST_PAGE, Pages * GUEST_PAGE, Vec);
  CHECK(Result == 0, "mincore returned %d (%s)", Result, strerror(errno));
  if (Result == 0) {
    for (i = 0; i < Pages; ++i) {
      CHECK((Vec[i] & 1) != 0, "page %lu should be resident, vec[%lu]=0x%02x", i, i, Vec[i]);
    }
    for (i = Pages; i < sizeof(Vec); ++i) {
      CHECK(Vec[i] == 0xEE, "mincore wrote past the end of the guest's vector at byte %lu (0x%02x)", i, Vec[i]);
    }
  }

  // A hole anywhere in the range is ENOMEM.
  CHECK(munmap(Base + 3 * GUEST_PAGE, GUEST_PAGE) == 0, "munmap for the hole: %s", strerror(errno));
  memset(Vec, 0xEE, sizeof(Vec));
  Result = mincore(Base + GUEST_PAGE, Pages * GUEST_PAGE, Vec);
  CHECK(Result == -1 && errno == ENOMEM, "mincore over a sub-page hole returned %d errno %d, want -1/ENOMEM", Result, errno);

  munmap(Base, 3 * GUEST_PAGE);
  munmap(Base + 4 * GUEST_PAGE, Length - 4 * GUEST_PAGE);
}

// MADV_DONTNEED on one guest page must zero exactly that page.
static void TestMadviseSubPage(void) {
  const unsigned long Length = 16 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  FillPattern(Base, Length, 0x88);
  CHECK(madvise(Base + 7 * GUEST_PAGE, GUEST_PAGE, MADV_DONTNEED) == 0, "madvise: %s", strerror(errno));
  CHECK(CheckZero(Base + 7 * GUEST_PAGE, GUEST_PAGE), "MADV_DONTNEED did not zero the page");
  CHECK(Base[6 * GUEST_PAGE] == (unsigned char)(0x88 + ((6 * GUEST_PAGE) & 0x7F)), "MADV_DONTNEED zeroed the page below it");
  CHECK(Base[8 * GUEST_PAGE] == (unsigned char)(0x88 + ((8 * GUEST_PAGE) & 0x7F)), "MADV_DONTNEED zeroed the page above it");

  munmap(Base, Length);
}

// Plain grow / shrink / move, at sizes that are not host-page multiples.
static void TestMremap(void) {
  const unsigned long Small = 3 * GUEST_PAGE;
  const unsigned long Large = 5 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Small, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  unsigned char* Grown;
  unsigned char* Shrunk;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }
  FillPattern(Base, Small, 0x99);

  Grown = (unsigned char*)mremap(Base, Small, Large, MREMAP_MAYMOVE);
  CHECK(Grown != MAP_FAILED, "mremap grow: %s", strerror(errno));
  if (Grown == MAP_FAILED) {
    munmap(Base, Small);
    return;
  }
  CHECK(CheckPattern(Grown, Small, 0x99), "mremap grow lost the contents");
  CHECK(((unsigned long)Grown & (GUEST_PAGE - 1)) == 0, "mremap returned a misaligned address");
  Grown[Large - 1] = 0x5C;
  CHECK(Grown[Large - 1] == 0x5C, "the grown tail is not writable");

  Shrunk = (unsigned char*)mremap(Grown, Large, Small, MREMAP_MAYMOVE);
  CHECK(Shrunk != MAP_FAILED, "mremap shrink: %s", strerror(errno));
  if (Shrunk != MAP_FAILED) {
    CHECK(CheckPattern(Shrunk, Small, 0x99), "mremap shrink lost the contents");
    munmap(Shrunk, Small);
  }
}

// The maps file has to be parseable at all -- glibc and wine's loader both
// sscanf it at start-up, and a synthesised file that they cannot read is worse
// than no file.
static void TestMapsParse(void) {
  const unsigned long Length = 4 * GUEST_PAGE;
  unsigned char* Base = (unsigned char*)mmap(NULL, Length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  const char* Perms;
  int i;
  int Sane = 1;
  CHECK(Base != MAP_FAILED, "mmap: %s", strerror(errno));
  if (Base == MAP_FAILED) {
    return;
  }

  CHECK(ReadMaps() > 0, "no parseable lines in /proc/self/maps");
  Perms = PermsAt((unsigned long)Base);
  CHECK(Perms != NULL && strcmp(Perms, "rw-p") == 0, "a fresh rw anonymous mapping reports %s", Perms ? Perms : "(hole)");

  for (i = 0; i < MapCount; ++i) {
    if (Maps[i].End <= Maps[i].Base) {
      Sane = 0;
    }
    if ((Maps[i].Base & (GUEST_PAGE - 1)) || (Maps[i].End & (GUEST_PAGE - 1))) {
      Sane = 0;
    }
    if (strlen(Maps[i].Perms) != 4) {
      Sane = 0;
    }
  }
  CHECK(Sane, "a /proc/self/maps line is malformed or not 4K-aligned (%d lines)", MapCount);

  munmap(Base, Length);
}

int main(void) {
  TestFixedAt4KOffsets();
  TestFixedFileAt4KOffset();
  TestPartialMunmap();
  TestProtLadder();
  TestMincoreVector();
  TestMadviseSubPage();
  TestMremap();
  TestMapsParse();

  printf("%s: %d checks, %d failures\n", Failures ? "FAILED" : "PASSED", Checks, Failures);
  return Failures ? 1 : 0;
}
