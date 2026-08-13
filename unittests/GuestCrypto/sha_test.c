// SHA-NI conformance: every instruction against an SDM-derived scalar
// reference (SHA1MSG1/MSG2/NEXTE/RNDS4 with all four function immediates,
// SHA256MSG1/MSG2/RNDS2), then full SHA-1 and SHA-256 digests over
// multi-block messages computed *with the instructions* and compared against
// clean scalar SHA implementations, plus NIST vectors and aliasing shapes.
#include <immintrin.h>
#include "crypto_common.h"

static void st128(u8* p, __m128i v) { _mm_storeu_si128((__m128i*)p, v); }
static __m128i ld128(const u8* p) { return _mm_loadu_si128((const __m128i*)p); }

/* ---------------- per-instruction randomized sweeps ---------------- */
static void test_sha1_ops(void) {
  rng_t r;
  rng_seed(&r, 0x51a1c0deu);
  u8 a[16], b[16], c[16], got[16], want[16];
  int f_m1 = 0, f_m2 = 0, f_ne = 0, f_r[4] = {0, 0, 0, 0};
  for (int i = 0; i < 1024; ++i) {
    rng_fill(&r, a, 16);
    rng_fill(&r, b, 16);
    rng_fill(&r, c, 16);
    __m128i va = ld128(a), vb = ld128(b);

    st128(got, _mm_sha1msg1_epu32(va, vb));
    ref_sha1msg1(want, a, b);
    if (!same_mem(got, want, 16)) ++f_m1;

    st128(got, _mm_sha1msg2_epu32(va, vb));
    ref_sha1msg2(want, a, b);
    if (!same_mem(got, want, 16)) ++f_m2;

    st128(got, _mm_sha1nexte_epu32(va, vb));
    ref_sha1nexte(want, a, b);
    if (!same_mem(got, want, 16)) ++f_ne;

    st128(got, _mm_sha1rnds4_epu32(va, vb, 0));
    ref_sha1rnds4(want, a, b, 0);
    if (!same_mem(got, want, 16)) ++f_r[0];
    st128(got, _mm_sha1rnds4_epu32(va, vb, 1));
    ref_sha1rnds4(want, a, b, 1);
    if (!same_mem(got, want, 16)) ++f_r[1];
    st128(got, _mm_sha1rnds4_epu32(va, vb, 2));
    ref_sha1rnds4(want, a, b, 2);
    if (!same_mem(got, want, 16)) ++f_r[2];
    st128(got, _mm_sha1rnds4_epu32(va, vb, 3));
    ref_sha1rnds4(want, a, b, 3);
    if (!same_mem(got, want, 16)) ++f_r[3];
  }
  report("sha1.random.msg1", f_m1 == 0);
  report("sha1.random.msg2", f_m2 == 0);
  report("sha1.random.nexte", f_ne == 0);
  report("sha1.random.rnds4.imm0", f_r[0] == 0);
  report("sha1.random.rnds4.imm1", f_r[1] == 0);
  report("sha1.random.rnds4.imm2", f_r[2] == 0);
  report("sha1.random.rnds4.imm3", f_r[3] == 0);
}

static void test_sha256_ops(void) {
  rng_t r;
  rng_seed(&r, 0x256c0de1u);
  u8 a[16], b[16], k[16], got[16], want[16];
  int f_m1 = 0, f_m2 = 0, f_r2 = 0;
  for (int i = 0; i < 1024; ++i) {
    rng_fill(&r, a, 16);
    rng_fill(&r, b, 16);
    rng_fill(&r, k, 16);
    __m128i va = ld128(a), vb = ld128(b);

    st128(got, _mm_sha256msg1_epu32(va, vb));
    ref_sha256msg1(want, a, b);
    if (!same_mem(got, want, 16)) ++f_m1;

    st128(got, _mm_sha256msg2_epu32(va, vb));
    ref_sha256msg2(want, a, b);
    if (!same_mem(got, want, 16)) ++f_m2;

    st128(got, _mm_sha256rnds2_epu32(va, vb, ld128(k)));
    ref_sha256rnds2(want, a, b, k);
    if (!same_mem(got, want, 16)) ++f_r2;
  }
  report("sha256.random.msg1", f_m1 == 0);
  report("sha256.random.msg2", f_m2 == 0);
  report("sha256.random.rnds2", f_r2 == 0);
}

/* ---------------- full SHA-1 via SHA-NI ---------------- */
static void sha1_ni(const u8* data, unsigned nblocks, u8* out20) {
  const __m128i MASK = _mm_set_epi64x((long long)0x0001020304050607ull, (long long)0x08090a0b0c0d0e0full);
  u32 state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
  __m128i ABCD = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)state), 0x1b);
  __m128i E = _mm_set_epi32((int)state[4], 0, 0, 0);

  for (unsigned blk = 0; blk < nblocks; ++blk) {
    const u8* p = data + 64 * blk;
    __m128i ABCD_SAVE = ABCD, E_SAVE = E;
    __m128i M[4];
    __m128i Ecur = E, Enxt;
    for (int g = 0; g < 20; ++g) {
      if (g < 4) M[g] = _mm_shuffle_epi8(ld128(p + 16 * g), MASK);
      if (g == 0)
        Ecur = _mm_add_epi32(Ecur, M[0]);
      else
        Ecur = _mm_sha1nexte_epu32(Ecur, M[g & 3]);
      if (g >= 3 && g <= 18) M[(g + 1) & 3] = _mm_sha1msg2_epu32(M[(g + 1) & 3], M[g & 3]);
      Enxt = ABCD;
      switch (g / 5) {
      case 0: ABCD = _mm_sha1rnds4_epu32(ABCD, Ecur, 0); break;
      case 1: ABCD = _mm_sha1rnds4_epu32(ABCD, Ecur, 1); break;
      case 2: ABCD = _mm_sha1rnds4_epu32(ABCD, Ecur, 2); break;
      default: ABCD = _mm_sha1rnds4_epu32(ABCD, Ecur, 3); break;
      }
      if (g >= 1 && g <= 16) M[(g + 3) & 3] = _mm_sha1msg1_epu32(M[(g + 3) & 3], M[g & 3]);
      if (g >= 2 && g <= 17) M[(g + 2) & 3] = _mm_xor_si128(M[(g + 2) & 3], M[g & 3]);
      Ecur = Enxt;
    }
    E = _mm_sha1nexte_epu32(Ecur, E_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
  }
  u8 tmp[16];
  st128(tmp, _mm_shuffle_epi32(ABCD, 0x1b));
  for (int i = 0; i < 4; ++i) st_be32(out20 + 4 * i, ld32(tmp + 4 * i));
  st128(tmp, E);
  st_be32(out20 + 16, ld32(tmp + 12));
}

/* ---------------- full SHA-256 via SHA-NI ---------------- */
static void sha256_ni(const u8* data, unsigned nblocks, u8* out32) {
  const __m128i MASK = _mm_set_epi64x((long long)0x0c0d0e0f08090a0bull, (long long)0x0405060700010203ull);
  u32 state[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  __m128i TMP = _mm_loadu_si128((const __m128i*)&state[0]);  /* DCBA */
  __m128i STATE1 = _mm_loadu_si128((const __m128i*)&state[4]); /* HGFE */
  TMP = _mm_shuffle_epi32(TMP, 0xb1);                          /* CDAB */
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1b);                    /* EFGH */
  __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);            /* ABEF */
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xf0);                 /* CDGH */

  for (unsigned blk = 0; blk < nblocks; ++blk) {
    const u8* p = data + 64 * blk;
    __m128i S0 = STATE0, S1 = STATE1;
    __m128i M[4];
    for (int i = 0; i < 4; ++i) M[i] = _mm_shuffle_epi8(ld128(p + 16 * i), MASK);
    for (int g = 0; g < 16; ++g) {
      __m128i MSG = _mm_add_epi32(M[g & 3], ld128((const u8*)&K256[4 * g]));
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
      if (g >= 3 && g <= 14) {
        __m128i T = _mm_alignr_epi8(M[g & 3], M[(g + 3) & 3], 4);
        M[(g + 1) & 3] = _mm_add_epi32(M[(g + 1) & 3], T);
        M[(g + 1) & 3] = _mm_sha256msg2_epu32(M[(g + 1) & 3], M[g & 3]);
      }
      MSG = _mm_shuffle_epi32(MSG, 0x0e);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
      if (g >= 1 && g <= 13) M[(g + 3) & 3] = _mm_sha256msg1_epu32(M[(g + 3) & 3], M[g & 3]);
    }
    STATE0 = _mm_add_epi32(STATE0, S0);
    STATE1 = _mm_add_epi32(STATE1, S1);
  }

  TMP = _mm_shuffle_epi32(STATE0, 0x1b);              /* FEBA */
  __m128i T1 = _mm_shuffle_epi32(STATE1, 0xb1);       /* DCHG */
  __m128i A = _mm_blend_epi16(TMP, T1, 0xf0);         /* DCBA */
  __m128i B = _mm_alignr_epi8(T1, TMP, 8);            /* HGFE */
  u8 tmp[32];
  st128(tmp, A);
  st128(tmp + 16, B);
  for (int i = 0; i < 8; ++i) st_be32(out32 + 4 * i, ld32(tmp + 4 * i));
}

/* NIST FIPS-180 sample digests for "abc" */
static const u8 SHA1_ABC[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                                0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
static const u8 SHA256_ABC[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                  0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                  0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static void pad_message(const u8* msg, unsigned len, u8* buf, unsigned* nblocks) {
  unsigned total = ((len + 9 + 63) / 64) * 64;
  memcpy(buf, msg, len);
  buf[len] = 0x80;
  for (unsigned i = len + 1; i < total; ++i) buf[i] = 0;
  u64 bits = (u64)len * 8;
  for (int i = 0; i < 8; ++i) buf[total - 1 - i] = (u8)(bits >> (8 * i));
  *nblocks = total / 64;
}

__attribute__((aligned(16))) static u8 msgbuf[64 * 40];

static void test_full_digests(void) {
  u8 got[32], want[32];
  unsigned nb;

  /* "abc" */
  {
    const u8 abc[3] = {'a', 'b', 'c'};
    pad_message(abc, 3, msgbuf, &nb);
    sha1_ni(msgbuf, nb, got);
    check_mem("sha1.nist.abc", got, SHA1_ABC, 20);
    sha256_ni(msgbuf, nb, got);
    check_mem("sha256.nist.abc", got, SHA256_ABC, 32);
  }

  /* 448-bit two-block NIST vector */
  {
    const char* m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned len = str_len(m);
    pad_message((const u8*)m, len, msgbuf, &nb);
    sha1_ni(msgbuf, nb, got);
    sha1_scalar(msgbuf, nb, want);
    check_mem("sha1.nist.2block", got, want, 20);
    sha256_ni(msgbuf, nb, got);
    sha256_scalar(msgbuf, nb, want);
    check_mem("sha256.nist.2block", got, want, 32);
  }

  /* randomized multi-block messages, 1..32 blocks */
  {
    rng_t r;
    rng_seed(&r, 0xfeedfaceu);
    int f1 = 0, f2 = 0;
    for (int i = 0; i < 64; ++i) {
      unsigned blocks = 1 + (unsigned)(rng_u32(&r) % 32);
      rng_fill(&r, msgbuf, blocks * 64);
      sha1_ni(msgbuf, blocks, got);
      sha1_scalar(msgbuf, blocks, want);
      if (!same_mem(got, want, 20)) ++f1;
      sha256_ni(msgbuf, blocks, got);
      sha256_scalar(msgbuf, blocks, want);
      if (!same_mem(got, want, 32)) ++f2;
    }
    report("sha1.random_multiblock", f1 == 0);
    report("sha256.random_multiblock", f2 == 0);
  }
}

/* ---------------- aliasing shapes ---------------- */
__attribute__((aligned(16))) static __m128i g_a, g_b, g_out;

static void test_alias(void) {
  rng_t r;
  rng_seed(&r, 0xa11a5111u);
  u8 a[16], got[16], want[16];
  int fails = 0;
  for (int i = 0; i < 256; ++i) {
    rng_fill(&r, a, 16);
    _mm_store_si128(&g_a, ld128(a));

    __asm__ volatile("movdqa %1, %%xmm5\n\t"
                     "sha1msg1 %%xmm5, %%xmm5\n\t"
                     "movdqa %%xmm5, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm5");
    st128(got, _mm_load_si128(&g_out));
    ref_sha1msg1(want, a, a);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm6\n\t"
                     "sha1msg2 %%xmm6, %%xmm6\n\t"
                     "movdqa %%xmm6, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm6");
    st128(got, _mm_load_si128(&g_out));
    ref_sha1msg2(want, a, a);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm7\n\t"
                     "sha1nexte %%xmm7, %%xmm7\n\t"
                     "movdqa %%xmm7, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm7");
    st128(got, _mm_load_si128(&g_out));
    ref_sha1nexte(want, a, a);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm3\n\t"
                     "sha1rnds4 $2, %%xmm3, %%xmm3\n\t"
                     "movdqa %%xmm3, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm3");
    st128(got, _mm_load_si128(&g_out));
    ref_sha1rnds4(want, a, a, 2);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm4\n\t"
                     "sha256msg1 %%xmm4, %%xmm4\n\t"
                     "sha256msg2 %%xmm4, %%xmm4\n\t"
                     "movdqa %%xmm4, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm4");
    st128(got, _mm_load_si128(&g_out));
    {
      u8 t[16];
      ref_sha256msg1(t, a, a);
      ref_sha256msg2(want, t, t);
    }
    if (!same_mem(got, want, 16)) ++fails;

    /* SHA256RNDS2 with dst == src and the implicit XMM0 operand also aliased */
    __asm__ volatile("movdqa %1, %%xmm0\n\t"
                     "sha256rnds2 %%xmm0, %%xmm0\n\t"
                     "movdqa %%xmm0, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm0");
    st128(got, _mm_load_si128(&g_out));
    ref_sha256rnds2(want, a, a, a);
    if (!same_mem(got, want, 16)) ++fails;
  }
  report("sha.alias.self_operand", fails == 0);

  /* SHA256RNDS2 explicit-XMM0 form across every source register */
  {
    rng_fill(&r, a, 16);
    u8 b[16], k[16];
    rng_fill(&r, b, 16);
    rng_fill(&r, k, 16);
    _mm_store_si128(&g_a, ld128(a));
    _mm_store_si128(&g_b, ld128(b));
    ref_sha256rnds2(want, a, b, b); /* xmm0 holds b in the asm below */
    int rf = 0;
#define RNDS2CASE(N)                                                                                                   \
  __asm__ volatile("movdqa %1, %%xmm" #N "\n\t"                                                                        \
                   "movdqa %2, %%xmm0\n\t"                                                                             \
                   "sha256rnds2 %%xmm0, %%xmm" #N "\n\t"                                                               \
                   "movdqa %%xmm" #N ", %0"                                                                            \
                   : "=m"(g_out)                                                                                       \
                   : "m"(g_a), "m"(g_b)                                                                                \
                   : "xmm0", "xmm" #N);                                                                                \
  st128(got, _mm_load_si128(&g_out));                                                                                  \
  if (!same_mem(got, want, 16)) ++rf;
    RNDS2CASE(1) RNDS2CASE(2) RNDS2CASE(3) RNDS2CASE(4) RNDS2CASE(5) RNDS2CASE(6) RNDS2CASE(7)
#ifdef __x86_64__
    RNDS2CASE(8) RNDS2CASE(9) RNDS2CASE(10) RNDS2CASE(11) RNDS2CASE(12) RNDS2CASE(13) RNDS2CASE(14) RNDS2CASE(15)
#endif
#undef RNDS2CASE
    report("sha256.rnds2.every_xmm", rf == 0);
  }
}

void guest_main(long* sp) {
  (void)sp;
  puts_raw("== GuestCrypto: SHA-NI ==\n");
  test_sha1_ops();
  test_sha256_ops();
  test_full_digests();
  test_alias();
  puts_raw("sha: checks=");
  put_dec((u64)g_checks);
  puts_raw(" fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
