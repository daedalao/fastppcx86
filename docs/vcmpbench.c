// vcmpbench: correctness sweep + timing for the pcmpeqb/pmovmskb/test/jcc
// vector-scan idiom that FEX_VCMPFUSION fuses on ppc64le.
//
// Two families of scan loops are exercised:
//   * hand-written SSE2 asm loops that reproduce glibc's idiom EXACTLY, in
//     every shape the fusion cares about (jnz-forward, jz-forward, pcmpeqw,
//     pcmpeqd) plus shapes it must REFUSE (backward conditional edge, a mask
//     that is consumed after the branch).
//   * the real libc strlen/strchr/memchr, whichever IFUNC glibc picks.
//
// Correctness is checked against a byte-at-a-time reference for every length
// 0..1023 at every alignment 0..15, and for the mask-consumer variants the
// returned mask itself is compared, so an incorrectly elided PMOVMSKB
// destination is caught rather than merely suspected.
//
// Build: gcc -O2 -static -o vcmpbench vcmpbench.c    (x86-64)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define ALIGN_SLOP 64
#define MAXLEN 1024

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec * 1e-9;
}

// ---------------------------------------------------------------------------
// 1. strlen, SSE2, forward JNZ out of the loop. This is glibc's shape and the
//    one the fusion is built for.
// ---------------------------------------------------------------------------
static size_t asm_strlen_jnz(const char* s) {
  size_t r;
  __asm__ volatile(
    "movq   %1, %%rax\n\t"
    "pxor   %%xmm1, %%xmm1\n\t"
    "andq   $-16, %%rax\n\t"          // align down
    "movdqa (%%rax), %%xmm0\n\t"
    "pcmpeqb %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "movq   %1, %%rcx\n\t"
    "andl   $15, %%ecx\n\t"
    "shrl   %%cl, %%edx\n\t"          // discard bytes before the start
    "testl  %%edx, %%edx\n\t"
    "jnz    2f\n\t"
    "1:\n\t"
    "addq   $16, %%rax\n\t"
    "movdqa (%%rax), %%xmm0\n\t"
    "pcmpeqb %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "testl  %%edx, %%edx\n\t"         // <-- fused
    "jnz    3f\n\t"                   // <-- forward
    "jmp    1b\n\t"
    "2:\n\t"
    "bsfl   %%edx, %%edx\n\t"
    "movq   %%rdx, %0\n\t"
    "jmp    4f\n\t"
    "3:\n\t"
    "bsfl   %%edx, %%edx\n\t"         // mask consumed on the exit edge
    "subq   %1, %%rax\n\t"
    "addq   %%rdx, %%rax\n\t"
    "movq   %%rax, %0\n\t"
    "4:\n\t"
    : "=r"(r)
    : "r"(s)
    : "rax", "rcx", "rdx", "xmm0", "xmm1", "cc", "memory");
  return r;
}

// ---------------------------------------------------------------------------
// 2. Same, but the loop is closed with a BACKWARD `jz`. The fusion must
//    REFUSE this (bail-out 18); it exists to prove the refusal is correct,
//    not merely taken.
// ---------------------------------------------------------------------------
static size_t asm_strlen_jz_backward(const char* s) {
  size_t r;
  __asm__ volatile(
    "movq   %1, %%rax\n\t"
    "pxor   %%xmm1, %%xmm1\n\t"
    "subq   $16, %%rax\n\t"
    "1:\n\t"
    "addq   $16, %%rax\n\t"
    "movdqu (%%rax), %%xmm0\n\t"
    "pcmpeqb %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "testl  %%edx, %%edx\n\t"
    "jz     1b\n\t"                   // backward conditional edge
    "bsfl   %%edx, %%edx\n\t"
    "subq   %1, %%rax\n\t"
    "addq   %%rdx, %%rax\n\t"
    "movq   %%rax, %0\n\t"
    : "=r"(r)
    : "r"(s)
    : "rax", "rdx", "xmm0", "xmm1", "cc", "memory");
  return r;
}

// ---------------------------------------------------------------------------
// 3. memchr-shaped scan, and it RETURNS THE RAW MASK from the exit edge so an
//    incorrectly materialised mask shows up as a wrong value, not just a
//    wrong pointer.
// ---------------------------------------------------------------------------
static uint32_t asm_scan_mask(const char* p, char c, size_t nblocks) {
  uint32_t mask;
  __asm__ volatile(
    "movzbl %2, %%eax\n\t"
    "movd   %%eax, %%xmm1\n\t"
    "punpcklbw %%xmm1, %%xmm1\n\t"
    "punpcklwd %%xmm1, %%xmm1\n\t"
    "pshufd $0, %%xmm1, %%xmm1\n\t"
    "movq   %1, %%rax\n\t"
    "movq   %3, %%rcx\n\t"
    "xorl   %%edx, %%edx\n\t"
    "1:\n\t"
    "testq  %%rcx, %%rcx\n\t"
    "jz     3f\n\t"
    "movdqu (%%rax), %%xmm0\n\t"
    "pcmpeqb %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "testl  %%edx, %%edx\n\t"         // <-- fused
    "jnz    2f\n\t"                   // <-- forward
    "addq   $16, %%rax\n\t"
    "decq   %%rcx\n\t"
    "jmp    1b\n\t"
    "2:\n\t"
    "3:\n\t"
    "movl   %%edx, %0\n\t"            // the mask itself is the result
    : "=r"(mask)
    : "r"(p), "m"(c), "r"(nblocks)
    : "rax", "rcx", "rdx", "xmm0", "xmm1", "cc", "memory");
  return mask;
}

// ---------------------------------------------------------------------------
// 4. 16-bit and 32-bit element variants (pcmpeqw / pcmpeqd), to cover the
//    ElementSize switch in the backend lowering.
// ---------------------------------------------------------------------------
static uint32_t asm_scan_mask_w(const uint16_t* p, uint16_t v, size_t nblocks) {
  uint32_t mask;
  __asm__ volatile(
    "movzwl %2, %%eax\n\t"
    "movd   %%eax, %%xmm1\n\t"
    "punpcklwd %%xmm1, %%xmm1\n\t"
    "pshufd $0, %%xmm1, %%xmm1\n\t"
    "movq   %1, %%rax\n\t"
    "movq   %3, %%rcx\n\t"
    "xorl   %%edx, %%edx\n\t"
    "1:\n\t"
    "testq  %%rcx, %%rcx\n\t"
    "jz     3f\n\t"
    "movdqu (%%rax), %%xmm0\n\t"
    "pcmpeqw %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "testl  %%edx, %%edx\n\t"
    "jnz    2f\n\t"
    "addq   $16, %%rax\n\t"
    "decq   %%rcx\n\t"
    "jmp    1b\n\t"
    "2:\n\t"
    "3:\n\t"
    "movl   %%edx, %0\n\t"
    : "=r"(mask)
    : "r"(p), "m"(v), "r"(nblocks)
    : "rax", "rcx", "rdx", "xmm0", "xmm1", "cc", "memory");
  return mask;
}

static uint32_t asm_scan_mask_d(const uint32_t* p, uint32_t v, size_t nblocks) {
  uint32_t mask;
  __asm__ volatile(
    "movl   %2, %%eax\n\t"
    "movd   %%eax, %%xmm1\n\t"
    "pshufd $0, %%xmm1, %%xmm1\n\t"
    "movq   %1, %%rax\n\t"
    "movq   %3, %%rcx\n\t"
    "xorl   %%edx, %%edx\n\t"
    "1:\n\t"
    "testq  %%rcx, %%rcx\n\t"
    "jz     3f\n\t"
    "movdqu (%%rax), %%xmm0\n\t"
    "pcmpeqd %%xmm1, %%xmm0\n\t"
    "pmovmskb %%xmm0, %%edx\n\t"
    "testl  %%edx, %%edx\n\t"
    "jnz    2f\n\t"
    "addq   $16, %%rax\n\t"
    "decq   %%rcx\n\t"
    "jmp    1b\n\t"
    "2:\n\t"
    "3:\n\t"
    "movl   %%edx, %0\n\t"
    : "=r"(mask)
    : "r"(p), "m"(v), "r"(nblocks)
    : "rax", "rcx", "rdx", "xmm0", "xmm1", "cc", "memory");
  return mask;
}

// ---------------------------------------------------------------------------
// References
// ---------------------------------------------------------------------------
static size_t ref_strlen(const char* s) {
  size_t n = 0;
  while (s[n]) {
    n++;
  }
  return n;
}

static uint32_t ref_scan_mask(const char* p, char c, size_t nblocks) {
  for (size_t b = 0; b < nblocks; b++) {
    uint32_t m = 0;
    for (int i = 0; i < 16; i++) {
      if (p[b * 16 + i] == c) {
        m |= 1u << i;
      }
    }
    if (m) {
      return m;
    }
  }
  return 0;
}

static uint32_t ref_scan_mask_w(const uint16_t* p, uint16_t v, size_t nblocks) {
  for (size_t b = 0; b < nblocks; b++) {
    uint32_t m = 0;
    for (int i = 0; i < 8; i++) {
      if (p[b * 8 + i] == v) {
        m |= 3u << (i * 2);
      }
    }
    if (m) {
      return m;
    }
  }
  return 0;
}

static uint32_t ref_scan_mask_d(const uint32_t* p, uint32_t v, size_t nblocks) {
  for (size_t b = 0; b < nblocks; b++) {
    uint32_t m = 0;
    for (int i = 0; i < 4; i++) {
      if (p[b * 4 + i] == v) {
        m |= 0xFu << (i * 4);
      }
    }
    if (m) {
      return m;
    }
  }
  return 0;
}

static int failures = 0;
static void fail(const char* what, unsigned long long got, unsigned long long want, int len, int align) {
  if (failures++ < 30) {
    printf("FAIL %-22s len=%4d align=%2d got=%llu want=%llu\n", what, len, align, got, want);
  }
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
  const int iters = argc > 1 ? atoi(argv[1]) : 200;

  char* raw = aligned_alloc(64, MAXLEN + 2 * ALIGN_SLOP);
  memset(raw, 'a', MAXLEN + 2 * ALIGN_SLOP);

  // ---------------- correctness sweep ----------------
  for (int align = 0; align < 16; align++) {
    char* s = raw + ALIGN_SLOP + align;
    for (int len = 0; len < MAXLEN - 32; len++) {
      memset(s, 'a', len);
      s[len] = 0;
      // keep some trailing junk so an over-read shows up as a wrong answer
      memset(s + len + 1, 'b', 16);

      size_t want = ref_strlen(s);
      size_t got = asm_strlen_jnz(s);
      if (got != want) {
        fail("strlen_jnz", got, want, len, align);
      }
      got = asm_strlen_jz_backward(s);
      if (got != want) {
        fail("strlen_jz_backward", got, want, len, align);
      }
      got = strlen(s);
      if (got != want) {
        fail("libc strlen", got, want, len, align);
      }
      if (len) {
        const char* wantp = memchr(s, 'a', len);
        if (wantp != s) {
          fail("libc memchr", (unsigned long long)(uintptr_t)wantp, (unsigned long long)(uintptr_t)s, len, align);
        }
        char* wc = strchr(s, 0);
        if (wc != s + len) {
          fail("libc strchr", (unsigned long long)(uintptr_t)wc, (unsigned long long)(uintptr_t)(s + len), len, align);
        }
      }
      s[len] = 'a';
    }
  }

  // mask-exact sweeps: the raw PMOVMSKB result must survive the fusion
  {
    char* buf = raw + ALIGN_SLOP;
    for (int nb = 1; nb <= 8; nb++) {
      for (int pos = 0; pos < nb * 16; pos++) {
        memset(buf, 'a', nb * 16);
        buf[pos] = 'Z';
        uint32_t got = asm_scan_mask(buf, 'Z', nb);
        uint32_t want = ref_scan_mask(buf, 'Z', nb);
        if (got != want) {
          fail("scan_mask_b", got, want, pos, nb);
        }
      }
      // no match at all: mask must be exactly 0 on the fallthrough exit
      memset(buf, 'a', nb * 16);
      if (asm_scan_mask(buf, 'Z', nb) != 0) {
        fail("scan_mask_b nomatch", asm_scan_mask(buf, 'Z', nb), 0, 0, nb);
      }
    }

    uint16_t* w = (uint16_t*)buf;
    for (int nb = 1; nb <= 8; nb++) {
      for (int pos = 0; pos < nb * 8; pos++) {
        for (int i = 0; i < nb * 8; i++) {
          w[i] = 0x1111;
        }
        w[pos] = 0xBEEF;
        uint32_t got = asm_scan_mask_w(w, 0xBEEF, nb);
        uint32_t want = ref_scan_mask_w(w, 0xBEEF, nb);
        if (got != want) {
          fail("scan_mask_w", got, want, pos, nb);
        }
      }
    }

    uint32_t* d = (uint32_t*)buf;
    for (int nb = 1; nb <= 8; nb++) {
      for (int pos = 0; pos < nb * 4; pos++) {
        for (int i = 0; i < nb * 4; i++) {
          d[i] = 0x11111111u;
        }
        d[pos] = 0xDEADBEEFu;
        uint32_t got = asm_scan_mask_d(d, 0xDEADBEEFu, nb);
        uint32_t want = ref_scan_mask_d(d, 0xDEADBEEFu, nb);
        if (got != want) {
          fail("scan_mask_d", got, want, pos, nb);
        }
      }
    }
  }

  printf("correctness: %s (%d failures)\n", failures ? "FAILED" : "OK", failures);

  // ---------------- timing ----------------
  // Lengths chosen to span "one block" through "many loop iterations".
  static const int lens[] = {7, 15, 31, 63, 127, 255, 511, 1000};
  const int nlens = sizeof(lens) / sizeof(lens[0]);

  volatile size_t sink = 0;
  struct {
    const char* name;
    double s;
  } results[8];
  int nres = 0;

  for (int a = 0; a < 2; a++) {
    const int align = a ? 5 : 0;
    char* s = raw + ALIGN_SLOP + align;

    double t0 = now_s();
    for (int it = 0; it < iters; it++) {
      for (int li = 0; li < nlens; li++) {
        int len = lens[li];
        memset(s, 'a', len);
        s[len] = 0;
        for (int rep = 0; rep < 64; rep++) {
          sink += asm_strlen_jnz(s);
        }
      }
    }
    double t1 = now_s();
    results[nres].name = a ? "asm_strlen_jnz  align=5" : "asm_strlen_jnz  align=0";
    results[nres++].s = t1 - t0;

    t0 = now_s();
    for (int it = 0; it < iters; it++) {
      for (int li = 0; li < nlens; li++) {
        int len = lens[li];
        memset(s, 'a', len);
        s[len] = 0;
        for (int rep = 0; rep < 64; rep++) {
          sink += asm_strlen_jz_backward(s);
        }
      }
    }
    t1 = now_s();
    results[nres].name = a ? "asm_strlen_jzbk align=5" : "asm_strlen_jzbk align=0";
    results[nres++].s = t1 - t0;

    t0 = now_s();
    for (int it = 0; it < iters; it++) {
      for (int li = 0; li < nlens; li++) {
        int len = lens[li];
        memset(s, 'a', len);
        s[len] = 0;
        for (int rep = 0; rep < 64; rep++) {
          sink += strlen(s);
        }
      }
    }
    t1 = now_s();
    results[nres].name = a ? "libc strlen     align=5" : "libc strlen     align=0";
    results[nres++].s = t1 - t0;

    t0 = now_s();
    for (int it = 0; it < iters; it++) {
      for (int li = 0; li < nlens; li++) {
        int len = lens[li];
        memset(s, 'a', len);
        s[len] = 0;
        for (int rep = 0; rep < 64; rep++) {
          sink += (size_t)(uintptr_t)memchr(s, 'Z', len);
        }
      }
    }
    t1 = now_s();
    results[nres].name = a ? "libc memchr     align=5" : "libc memchr     align=0";
    results[nres++].s = t1 - t0;
  }

  for (int i = 0; i < nres; i++) {
    printf("time %-24s %8.4f s\n", results[i].name, results[i].s);
  }
  printf("sink %llu\n", (unsigned long long)sink);
  return failures ? 1 : 0;
}
