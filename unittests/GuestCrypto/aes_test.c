// AES-NI conformance: every instruction against an SDM-derived scalar
// reference, the three FIPS-197 known-answer vectors (schedule + encrypt +
// equivalent-inverse decrypt), AESKEYGENASSIST over all RCONs and both lane
// shuffles (0xff for AES-128/256 odd steps, 0x55 for AES-192, 0xaa for the
// AES-256 even step), a 1024-block randomized sweep, and aliasing shapes
// (dst==src, src1==src2, in-place on every architectural XMM).
#include <immintrin.h>
#include "crypto_common.h"

static void st128(u8* p, __m128i v) { _mm_storeu_si128((__m128i*)p, v); }
static __m128i ld128(const u8* p) { return _mm_loadu_si128((const __m128i*)p); }

/* ---------------- randomized per-instruction sweep ---------------- */
static void test_random_ops(void) {
  rng_t r;
  rng_seed(&r, 0x1234abcdu);
  u8 a[16], b[16], got[16], want[16];
  int f_enc = 0, f_encl = 0, f_dec = 0, f_decl = 0, f_imc = 0, f_kga = 0;
  static const u8 rcons[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

  for (int i = 0; i < 1024; ++i) {
    rng_fill(&r, a, 16);
    rng_fill(&r, b, 16);
    __m128i va = ld128(a), vb = ld128(b);

    st128(got, _mm_aesenc_si128(va, vb));
    ref_aesenc(want, a, b);
    if (!same_mem(got, want, 16)) ++f_enc;

    st128(got, _mm_aesenclast_si128(va, vb));
    ref_aesenclast(want, a, b);
    if (!same_mem(got, want, 16)) ++f_encl;

    st128(got, _mm_aesdec_si128(va, vb));
    ref_aesdec(want, a, b);
    if (!same_mem(got, want, 16)) ++f_dec;

    st128(got, _mm_aesdeclast_si128(va, vb));
    ref_aesdeclast(want, a, b);
    if (!same_mem(got, want, 16)) ++f_decl;

    st128(got, _mm_aesimc_si128(va));
    ref_aesimc(want, a);
    if (!same_mem(got, want, 16)) ++f_imc;

    /* every RCON the AES key schedules use, cycled over the sweep */
    __m128i kg;
    u8 rc = rcons[i % 11];
    switch (rc) {
    case 0x00: kg = _mm_aeskeygenassist_si128(va, 0x00); break;
    case 0x01: kg = _mm_aeskeygenassist_si128(va, 0x01); break;
    case 0x02: kg = _mm_aeskeygenassist_si128(va, 0x02); break;
    case 0x04: kg = _mm_aeskeygenassist_si128(va, 0x04); break;
    case 0x08: kg = _mm_aeskeygenassist_si128(va, 0x08); break;
    case 0x10: kg = _mm_aeskeygenassist_si128(va, 0x10); break;
    case 0x20: kg = _mm_aeskeygenassist_si128(va, 0x20); break;
    case 0x40: kg = _mm_aeskeygenassist_si128(va, 0x40); break;
    case 0x80: kg = _mm_aeskeygenassist_si128(va, 0x80); break;
    case 0x1b: kg = _mm_aeskeygenassist_si128(va, 0x1b); break;
    default: kg = _mm_aeskeygenassist_si128(va, 0x36); break;
    }
    st128(got, kg);
    ref_aeskeygenassist(want, a, rc);
    if (!same_mem(got, want, 16)) ++f_kga;
  }
  report("aes.random.aesenc", f_enc == 0);
  report("aes.random.aesenclast", f_encl == 0);
  report("aes.random.aesdec", f_dec == 0);
  report("aes.random.aesdeclast", f_decl == 0);
  report("aes.random.aesimc", f_imc == 0);
  report("aes.random.aeskeygenassist", f_kga == 0);
}

/* ---------------- AESKEYGENASSIST lane-shuffle patterns ---------------- */
static void test_kga_shuffles(void) {
  rng_t r;
  rng_seed(&r, 0x9e3779b9u);
  u8 a[16], kg[16], got[16], want[16];
  int f55 = 0, faa = 0, fff = 0;
  for (int i = 0; i < 256; ++i) {
    rng_fill(&r, a, 16);
    __m128i va = ld128(a);
    /* 0xff: AES-128 / AES-256 odd step */
    st128(got, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(va, 0x08), 0xff));
    ref_aeskeygenassist(kg, a, 0x08);
    for (int j = 0; j < 4; ++j) memcpy(want + 4 * j, kg + 12, 4);
    if (!same_mem(got, want, 16)) ++fff;
    /* 0x55: AES-192 step */
    st128(got, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(va, 0x10), 0x55));
    ref_aeskeygenassist(kg, a, 0x10);
    for (int j = 0; j < 4; ++j) memcpy(want + 4 * j, kg + 4, 4);
    if (!same_mem(got, want, 16)) ++f55;
    /* 0xaa: AES-256 even step, RCON 0 */
    st128(got, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(va, 0x00), 0xaa));
    ref_aeskeygenassist(kg, a, 0x00);
    for (int j = 0; j < 4; ++j) memcpy(want + 4 * j, kg + 8, 4);
    if (!same_mem(got, want, 16)) ++faa;
  }
  report("aes.kga.shuffle_ff", fff == 0);
  report("aes.kga.shuffle_55", f55 == 0);
  report("aes.kga.shuffle_aa", faa == 0);
}

/* ---------------- AES-NI key schedules ---------------- */
static __m128i ks128_step(__m128i key, __m128i kga) {
  kga = _mm_shuffle_epi32(kga, 0xff);
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, kga);
}

static void expand128(const u8* key, u8* rk) {
  __m128i k = ld128(key);
  st128(rk, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x01));
  st128(rk + 16, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x02));
  st128(rk + 32, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x04));
  st128(rk + 48, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x08));
  st128(rk + 64, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x10));
  st128(rk + 80, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x20));
  st128(rk + 96, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x40));
  st128(rk + 112, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x80));
  st128(rk + 128, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x1b));
  st128(rk + 144, k);
  k = ks128_step(k, _mm_aeskeygenassist_si128(k, 0x36));
  st128(rk + 160, k);
}

/* Intel AES-NI whitepaper AES-192 expansion (0x55 lane shuffle) */
static void ks192_assist(__m128i* t1, __m128i* t2, __m128i* t3) {
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0x55);
  t4 = _mm_slli_si128(*t1, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  *t1 = _mm_xor_si128(*t1, *t2);
  *t2 = _mm_shuffle_epi32(*t1, 0xff);
  t4 = _mm_slli_si128(*t3, 4);
  *t3 = _mm_xor_si128(*t3, t4);
  *t3 = _mm_xor_si128(*t3, *t2);
}
#define SHUF_PD(a, b, i) _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(a), _mm_castsi128_pd(b), i))

static void expand192(const u8* key32 /* 24 key bytes in a 32-byte buffer */, u8* rk) {
  __m128i ks[13];
  __m128i t1 = ld128(key32);
  __m128i t3 = ld128(key32 + 16);
  __m128i t2;
  ks[0] = t1;
  ks[1] = t3;
  t2 = _mm_aeskeygenassist_si128(t3, 0x01);
  ks192_assist(&t1, &t2, &t3);
  ks[1] = SHUF_PD(ks[1], t1, 0);
  ks[2] = SHUF_PD(t1, t3, 1);
  t2 = _mm_aeskeygenassist_si128(t3, 0x02);
  ks192_assist(&t1, &t2, &t3);
  ks[3] = t1;
  ks[4] = t3;
  t2 = _mm_aeskeygenassist_si128(t3, 0x04);
  ks192_assist(&t1, &t2, &t3);
  ks[4] = SHUF_PD(ks[4], t1, 0);
  ks[5] = SHUF_PD(t1, t3, 1);
  t2 = _mm_aeskeygenassist_si128(t3, 0x08);
  ks192_assist(&t1, &t2, &t3);
  ks[6] = t1;
  ks[7] = t3;
  t2 = _mm_aeskeygenassist_si128(t3, 0x10);
  ks192_assist(&t1, &t2, &t3);
  ks[7] = SHUF_PD(ks[7], t1, 0);
  ks[8] = SHUF_PD(t1, t3, 1);
  t2 = _mm_aeskeygenassist_si128(t3, 0x20);
  ks192_assist(&t1, &t2, &t3);
  ks[9] = t1;
  ks[10] = t3;
  t2 = _mm_aeskeygenassist_si128(t3, 0x40);
  ks192_assist(&t1, &t2, &t3);
  ks[10] = SHUF_PD(ks[10], t1, 0);
  ks[11] = SHUF_PD(t1, t3, 1);
  t2 = _mm_aeskeygenassist_si128(t3, 0x80);
  ks192_assist(&t1, &t2, &t3);
  ks[12] = t1;
  for (int i = 0; i < 13; ++i) st128(rk + 16 * i, ks[i]);
}

/* Intel AES-NI whitepaper AES-256 expansion (0xff + 0xaa lane shuffles) */
static void ks256_assist1(__m128i* t1, __m128i* t2) {
  __m128i t4;
  *t2 = _mm_shuffle_epi32(*t2, 0xff);
  t4 = _mm_slli_si128(*t1, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t1 = _mm_xor_si128(*t1, t4);
  *t1 = _mm_xor_si128(*t1, *t2);
}
static void ks256_assist2(__m128i* t1, __m128i* t3) {
  __m128i t2, t4;
  t4 = _mm_aeskeygenassist_si128(*t1, 0x00);
  t2 = _mm_shuffle_epi32(t4, 0xaa);
  t4 = _mm_slli_si128(*t3, 4);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t3 = _mm_xor_si128(*t3, t4);
  t4 = _mm_slli_si128(t4, 4);
  *t3 = _mm_xor_si128(*t3, t4);
  *t3 = _mm_xor_si128(*t3, t2);
}
static void expand256(const u8* key, u8* rk) {
  __m128i t1 = ld128(key), t3 = ld128(key + 16), t2;
  st128(rk, t1);
  st128(rk + 16, t3);
#define KS256(rcon, idx)                                                                                               \
  t2 = _mm_aeskeygenassist_si128(t3, rcon);                                                                            \
  ks256_assist1(&t1, &t2);                                                                                             \
  st128(rk + 16 * (idx), t1);                                                                                          \
  ks256_assist2(&t1, &t3);                                                                                             \
  st128(rk + 16 * ((idx) + 1), t3);
  KS256(0x01, 2)
  KS256(0x02, 4)
  KS256(0x04, 6)
  KS256(0x08, 8)
  KS256(0x10, 10)
  KS256(0x20, 12)
#undef KS256
  t2 = _mm_aeskeygenassist_si128(t3, 0x40);
  ks256_assist1(&t1, &t2);
  st128(rk + 16 * 14, t1);
}

/* AES-NI encrypt / equivalent-inverse-cipher decrypt with a flat schedule */
static void ni_encrypt(const u8* rk, int rounds, const u8* in, u8* out) {
  __m128i s = _mm_xor_si128(ld128(in), ld128(rk));
  for (int r = 1; r < rounds; ++r) s = _mm_aesenc_si128(s, ld128(rk + 16 * r));
  s = _mm_aesenclast_si128(s, ld128(rk + 16 * rounds));
  st128(out, s);
}
static void ni_decrypt(const u8* rk, int rounds, const u8* in, u8* out) {
  __m128i s = _mm_xor_si128(ld128(in), ld128(rk + 16 * rounds));
  for (int r = rounds - 1; r >= 1; --r) s = _mm_aesdec_si128(s, _mm_aesimc_si128(ld128(rk + 16 * r)));
  s = _mm_aesdeclast_si128(s, ld128(rk));
  st128(out, s);
}

static const u8 FIPS_PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const u8 FIPS_CT128[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
static const u8 FIPS_CT192[16] = {0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                                  0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91};
static const u8 FIPS_CT256[16] = {0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                                  0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89};

static void test_fips_kats(void) {
  u8 key[32];
  for (int i = 0; i < 32; ++i) key[i] = (u8)i;
  u8 rk_ni[15 * 16], rk_ref[15 * 16], out[16];

  /* AES-128 */
  expand128(key, rk_ni);
  ref_key_expand(key, 16, rk_ref);
  check_mem("aes128.keyschedule", rk_ni, rk_ref, 11 * 16);
  ni_encrypt(rk_ni, 10, FIPS_PT, out);
  check_mem("aes128.fips197.encrypt", out, FIPS_CT128, 16);
  ni_decrypt(rk_ni, 10, FIPS_CT128, out);
  check_mem("aes128.fips197.decrypt", out, FIPS_PT, 16);

  /* AES-192 (24-byte key held in a 32-byte buffer) */
  u8 key192[32];
  memset(key192, 0, 32);
  memcpy(key192, key, 24);
  expand192(key192, rk_ni);
  ref_key_expand(key192, 24, rk_ref);
  check_mem("aes192.keyschedule", rk_ni, rk_ref, 13 * 16);
  ni_encrypt(rk_ni, 12, FIPS_PT, out);
  check_mem("aes192.fips197.encrypt", out, FIPS_CT192, 16);
  ni_decrypt(rk_ni, 12, FIPS_CT192, out);
  check_mem("aes192.fips197.decrypt", out, FIPS_PT, 16);

  /* AES-256 */
  expand256(key, rk_ni);
  ref_key_expand(key, 32, rk_ref);
  check_mem("aes256.keyschedule", rk_ni, rk_ref, 15 * 16);
  ni_encrypt(rk_ni, 14, FIPS_PT, out);
  check_mem("aes256.fips197.encrypt", out, FIPS_CT256, 16);
  ni_decrypt(rk_ni, 14, FIPS_CT256, out);
  check_mem("aes256.fips197.decrypt", out, FIPS_PT, 16);

  /* scalar reference must agree with the NI path on random keys/blocks too */
  rng_t r;
  rng_seed(&r, 0x5eed0001u);
  int fenc = 0, fdec = 0;
  for (int i = 0; i < 256; ++i) {
    u8 k[32], pt[16], ct[16], back[16], want[16];
    rng_fill(&r, k, 32);
    rng_fill(&r, pt, 16);
    int kb = (i % 3 == 0) ? 16 : (i % 3 == 1) ? 24 : 32;
    int rounds = kb / 4 + 6;
    if (kb == 16)
      expand128(k, rk_ni);
    else if (kb == 24) {
      memset(k + 24, 0, 8);
      expand192(k, rk_ni);
    } else
      expand256(k, rk_ni);
    ref_key_expand(k, kb, rk_ref);
    if (!same_mem(rk_ni, rk_ref, 16 * (rounds + 1))) {
      ++fenc;
      continue;
    }
    ni_encrypt(rk_ni, rounds, pt, ct);
    ref_aes_encrypt(rk_ref, rounds, pt, want);
    if (!same_mem(ct, want, 16)) ++fenc;
    ni_decrypt(rk_ni, rounds, ct, back);
    if (!same_mem(back, pt, 16)) ++fdec;
  }
  report("aes.random_keys.encrypt", fenc == 0);
  report("aes.random_keys.roundtrip", fdec == 0);
}

/* ---------------- aliasing shapes ---------------- */
__attribute__((aligned(16))) static __m128i g_a, g_b, g_out;

static void test_aliasing(void) {
  rng_t r;
  rng_seed(&r, 0xa11a5edu);
  u8 a[16], b[16], got[16], want[16], tmp[16];

  /* dst == src1 == src2 for every AES round instruction */
  int fails = 0;
  for (int i = 0; i < 128; ++i) {
    rng_fill(&r, a, 16);
    _mm_store_si128(&g_a, ld128(a));
    __asm__ volatile("movdqa %1, %%xmm5\n\t"
                     "aesenc %%xmm5, %%xmm5\n\t"
                     "movdqa %%xmm5, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm5");
    st128(got, _mm_load_si128(&g_out));
    ref_aesenc(want, a, a);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm2\n\t"
                     "aesdec %%xmm2, %%xmm2\n\t"
                     "movdqa %%xmm2, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm2");
    st128(got, _mm_load_si128(&g_out));
    ref_aesdec(want, a, a);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm7\n\t"
                     "aesenclast %%xmm7, %%xmm7\n\t"
                     "aesdeclast %%xmm7, %%xmm7\n\t"
                     "movdqa %%xmm7, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm7");
    st128(got, _mm_load_si128(&g_out));
    ref_aesenclast(tmp, a, a);
    ref_aesdeclast(want, tmp, tmp);
    if (!same_mem(got, want, 16)) ++fails;

    __asm__ volatile("movdqa %1, %%xmm1\n\t"
                     "aesimc %%xmm1, %%xmm1\n\t"
                     "aeskeygenassist $0x1b, %%xmm1, %%xmm1\n\t"
                     "movdqa %%xmm1, %0"
                     : "=m"(g_out)
                     : "m"(g_a)
                     : "xmm1");
    st128(got, _mm_load_si128(&g_out));
    ref_aesimc(tmp, a);
    ref_aeskeygenassist(want, tmp, 0x1b);
    if (!same_mem(got, want, 16)) ++fails;
  }
  report("aes.alias.self_operand", fails == 0);

  /* long dst==src chain: state accumulates through 64 dependent rounds */
  rng_fill(&r, a, 16);
  rng_fill(&r, b, 16);
  {
    __m128i s = ld128(a), k = ld128(b);
    memcpy(want, a, 16);
    for (int i = 0; i < 64; ++i) {
      s = _mm_aesenc_si128(s, k);
      ref_aesenc(tmp, want, b);
      memcpy(want, tmp, 16);
    }
    st128(got, s);
    check_mem("aes.alias.dst_eq_src_chain", got, want, 16);
  }

  /* in-place operation on every architectural XMM register */
  {
    rng_fill(&r, a, 16);
    rng_fill(&r, b, 16);
    _mm_store_si128(&g_a, ld128(a));
    _mm_store_si128(&g_b, ld128(b));
    ref_aesenc(tmp, a, b);
    ref_aesenclast(want, tmp, b);
    int rf = 0;
#define XMMCASE(N)                                                                                                     \
  __asm__ volatile("movdqa %1, %%xmm" #N "\n\t"                                                                        \
                   "aesenc %2, %%xmm" #N "\n\t"                                                                        \
                   "aesenclast %2, %%xmm" #N "\n\t"                                                                    \
                   "movdqa %%xmm" #N ", %0"                                                                            \
                   : "=m"(g_out)                                                                                       \
                   : "m"(g_a), "m"(g_b)                                                                                \
                   : "xmm" #N);                                                                                        \
  st128(got, _mm_load_si128(&g_out));                                                                                  \
  if (!same_mem(got, want, 16)) ++rf;
    XMMCASE(0) XMMCASE(1) XMMCASE(2) XMMCASE(3) XMMCASE(4) XMMCASE(5) XMMCASE(6) XMMCASE(7)
#ifdef __x86_64__
    XMMCASE(8) XMMCASE(9) XMMCASE(10) XMMCASE(11) XMMCASE(12) XMMCASE(13) XMMCASE(14) XMMCASE(15)
#endif
#undef XMMCASE
    report("aes.alias.every_xmm_inplace", rf == 0);
  }
}

void guest_main(long* sp) {
  (void)sp;
  aes_init_tables();
  puts_raw("== GuestCrypto: AES ==\n");
  test_random_ops();
  test_kga_shuffles();
  test_fips_kats();
  test_aliasing();
  puts_raw("aes: checks=");
  put_dec((u64)g_checks);
  puts_raw(" fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
