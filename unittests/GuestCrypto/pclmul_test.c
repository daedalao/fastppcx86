// PCLMULQDQ conformance: all four operand selectors against a bitwise
// carryless-multiply reference, a randomized sweep, edge bit patterns
// (all-ones, single bit at 0 and 63, alternating), aliasing shapes, and a
// GHASH-shaped reduction chain (the shape real GCM code emits).
#include <immintrin.h>
#include "crypto_common.h"

static void st128(u8* p, __m128i v) { _mm_storeu_si128((__m128i*)p, v); }
static __m128i ld128(const u8* p) { return _mm_loadu_si128((const __m128i*)p); }

static __m128i clmul_sel(__m128i a, __m128i b, int sel) {
  switch (sel) {
  case 0x00: return _mm_clmulepi64_si128(a, b, 0x00);
  case 0x01: return _mm_clmulepi64_si128(a, b, 0x01);
  case 0x10: return _mm_clmulepi64_si128(a, b, 0x10);
  default: return _mm_clmulepi64_si128(a, b, 0x11);
  }
}

static void test_random(void) {
  rng_t r;
  rng_seed(&r, 0xc10ec001u);
  static const int sels[4] = {0x00, 0x01, 0x10, 0x11};
  int fails[4] = {0, 0, 0, 0};
  u8 a[16], b[16], got[16], want[16];
  for (int i = 0; i < 2048; ++i) {
    rng_fill(&r, a, 16);
    rng_fill(&r, b, 16);
    __m128i va = ld128(a), vb = ld128(b);
    for (int s = 0; s < 4; ++s) {
      st128(got, clmul_sel(va, vb, sels[s]));
      ref_pclmul(want, a, b, sels[s]);
      if (!same_mem(got, want, 16)) ++fails[s];
    }
  }
  report("pclmul.random.sel00", fails[0] == 0);
  report("pclmul.random.sel01", fails[1] == 0);
  report("pclmul.random.sel10", fails[2] == 0);
  report("pclmul.random.sel11", fails[3] == 0);
}

static void test_edges(void) {
  static const u64 pats[8] = {
      0x0000000000000000ull, 0xffffffffffffffffull, 0x0000000000000001ull, 0x8000000000000000ull,
      0xaaaaaaaaaaaaaaaaull, 0x5555555555555555ull, 0x0000000100000001ull, 0x8000000000000001ull,
  };
  static const int sels[4] = {0x00, 0x01, 0x10, 0x11};
  int fails = 0;
  u8 a[16], b[16], got[16], want[16];
  for (int i = 0; i < 8; ++i)
    for (int j = 0; j < 8; ++j) {
      /* both halves loaded so every selector sees an interesting pattern */
      st64(a, pats[i]);
      st64(a + 8, pats[(i + 3) & 7]);
      st64(b, pats[j]);
      st64(b + 8, pats[(j + 5) & 7]);
      __m128i va = ld128(a), vb = ld128(b);
      for (int s = 0; s < 4; ++s) {
        st128(got, clmul_sel(va, vb, sels[s]));
        ref_pclmul(want, a, b, sels[s]);
        if (!same_mem(got, want, 16)) ++fails;
      }
    }
  report("pclmul.edge_patterns", fails == 0);

  /* every single-bit position x every single-bit position, selector 0x00 */
  int sb = 0;
  for (int i = 0; i < 64; ++i)
    for (int j = 0; j < 64; ++j) {
      st64(a, 1ull << i);
      st64(a + 8, 0);
      st64(b, 1ull << j);
      st64(b + 8, 0);
      st128(got, _mm_clmulepi64_si128(ld128(a), ld128(b), 0x00));
      u64 lo = 0, hi = 0;
      if (i + j < 64)
        lo = 1ull << (i + j);
      else
        hi = 1ull << (i + j - 64);
      st64(want, lo);
      st64(want + 8, hi);
      if (!same_mem(got, want, 16)) ++sb;
    }
  report("pclmul.single_bit_matrix", sb == 0);
}

__attribute__((aligned(16))) static __m128i g_a, g_b, g_out;

static void test_alias(void) {
  rng_t r;
  rng_seed(&r, 0x5a5a1234u);
  u8 a[16], got[16], want[16];
  int fails = 0;
  for (int i = 0; i < 256; ++i) {
    rng_fill(&r, a, 16);
    _mm_store_si128(&g_a, ld128(a));
    /* dst == src1 == src2, all four selectors */
    __asm__ volatile("movdqa %1, %%xmm3\n\t"
                     "pclmulqdq $0x00, %%xmm3, %%xmm3\n\t"
                     "movdqa %%xmm3, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm3");
    st128(got, _mm_load_si128(&g_out));
    ref_pclmul(want, a, a, 0x00);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm6\n\t"
                     "pclmulqdq $0x11, %%xmm6, %%xmm6\n\t"
                     "movdqa %%xmm6, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm6");
    st128(got, _mm_load_si128(&g_out));
    ref_pclmul(want, a, a, 0x11);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm0\n\t"
                     "pclmulqdq $0x10, %%xmm0, %%xmm0\n\t"
                     "movdqa %%xmm0, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm0");
    st128(got, _mm_load_si128(&g_out));
    ref_pclmul(want, a, a, 0x10);
    if (!same_mem(got, want, 16)) ++fails;

    /* memory-operand form */
    __asm__ volatile("movdqa %1, %%xmm4\n\t"
                     "pclmulqdq $0x01, %1, %%xmm4\n\t"
                     "movdqa %%xmm4, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm4");
    st128(got, _mm_load_si128(&g_out));
    ref_pclmul(want, a, a, 0x01);
    if (!same_mem(got, want, 16)) ++fails;
  }
  report("pclmul.alias.self_operand", fails == 0);
}

/* GHASH-shaped: karatsuba-free schoolbook multiply + Montgomery-style fold,
   both sides computed by the same reference arithmetic. */
static void gf128_mul_ref(const u8* x, const u8* y, u8* out) {
  /* carryless 128x128 via four 64x64 references, then reduce mod
     x^128 + x^7 + x^2 + x + 1 in the GHASH bit order used below. */
  u64 x0 = ld64(x), x1 = ld64(x + 8), y0 = ld64(y), y1 = ld64(y + 8);
  u64 lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3;
  ref_clmul(x0, y0, &lo0, &hi0);
  ref_clmul(x1, y1, &lo3, &hi3);
  ref_clmul(x0, y1, &lo1, &hi1);
  ref_clmul(x1, y0, &lo2, &hi2);
  u64 mlo = lo1 ^ lo2, mhi = hi1 ^ hi2;
  u64 r0 = lo0;
  u64 r1 = hi0 ^ mlo;
  u64 r2 = lo3 ^ mhi;
  u64 r3 = hi3;
  st64(out, r0);
  st64(out + 8, r1);
  st64(out + 16, r2);
  st64(out + 24, r3);
}

static void test_ghash_shape(void) {
  rng_t r;
  rng_seed(&r, 0x600d1234u);
  int fails = 0;
  u8 x[16], y[16], want[32], got[32];
  for (int i = 0; i < 512; ++i) {
    rng_fill(&r, x, 16);
    rng_fill(&r, y, 16);
    __m128i vx = ld128(x), vy = ld128(y);
    __m128i t0 = _mm_clmulepi64_si128(vx, vy, 0x00);
    __m128i t3 = _mm_clmulepi64_si128(vx, vy, 0x11);
    __m128i t1 = _mm_clmulepi64_si128(vx, vy, 0x10); /* x0 * y1 */
    __m128i t2 = _mm_clmulepi64_si128(vx, vy, 0x01); /* x1 * y0 */
    __m128i mid = _mm_xor_si128(t1, t2);
    __m128i lo = _mm_xor_si128(t0, _mm_slli_si128(mid, 8));
    __m128i hi = _mm_xor_si128(t3, _mm_srli_si128(mid, 8));
    st128(got, lo);
    st128(got + 16, hi);
    gf128_mul_ref(x, y, want);
    if (!same_mem(got, want, 32)) ++fails;
  }
  report("pclmul.ghash_schoolbook", fails == 0);
}

void guest_main(long* sp) {
  (void)sp;
  puts_raw("== GuestCrypto: PCLMULQDQ ==\n");
  test_random();
  test_edges();
  test_alias();
  test_ghash_shape();
  puts_raw("pclmul: checks=");
  put_dec((u64)g_checks);
  puts_raw(" fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
