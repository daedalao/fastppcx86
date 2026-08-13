// STRESS MODE -- the reason this suite exists.
//
// Isolated conformance tests cannot see cross-call register-state corruption.
// A pinned host constant that is silently clobbered by a host libc call, or a
// guest XMM whose upper half is destroyed by a helper's callee-save sequence,
// produces perfect results in every isolated KAT and wrong results only when
// crypto is interleaved with other work -- which is exactly what real
// software does.
//
// So: run the crypto over and over with results known in advance, and between
// rounds do the things that make FEX leave the JIT and touch host state:
//   * syscalls (write to /dev/null, nanosleep(0), getpid)
//   * x87 80-bit transcendentals (fsin/f2xm1/fptan) -- these route through
//     FEX's FABI F80 helpers, i.e. real host C++ floating point code
//   * bulk memcpy-shaped loads and stores
//   * a block that holds every architectural XMM live *across* a host call
//     and verifies the registers survived it
// Every iteration is verified against precomputed values; the first divergent
// iteration number is reported.
//
// usage: stress_test [iterations]   (default 100000)
#include <immintrin.h>
#include "crypto_common.h"

static void st128(u8* p, __m128i v) { _mm_storeu_si128((__m128i*)p, v); }
static __m128i ld128(const u8* p) { return _mm_loadu_si128((const __m128i*)p); }

/* ------------------------- fixtures ------------------------- */
__attribute__((aligned(16))) static u8 ek[15 * 16], dk[15 * 16];
__attribute__((aligned(16))) static u8 pt[16 * 4], ctblk[16 * 4];
__attribute__((aligned(16))) static u8 shablk[64];
__attribute__((aligned(16))) static u8 crcbuf[256];
__attribute__((aligned(16))) static u8 clmul_a[16], clmul_b[16];
__attribute__((aligned(16))) static u8 bulk_src[8192], bulk_dst[8192];
__attribute__((aligned(16))) static u8 xmm_seed[16 * 16], xmm_back[16 * 16];

/* expectations, computed once by the scalar references */
static u8 exp_aes128[16];
static u8 exp_aes256_4way[16 * 4];
static u8 exp_sha256[32];
static u8 exp_sha1[20];
static u8 exp_clmul[16];
static u32 exp_crc;

static int devnull_fd;

#define ROUNDS256 14

static void build_fixtures(void) {
  rng_t r;
  rng_seed(&r, 0x57235501u);
  u8 key128[16], key256[32];
  rng_fill(&r, key128, 16);
  rng_fill(&r, key256, 32);
  rng_fill(&r, pt, sizeof pt);
  rng_fill(&r, ctblk, sizeof ctblk);
  rng_fill(&r, shablk, sizeof shablk);
  rng_fill(&r, crcbuf, sizeof crcbuf);
  rng_fill(&r, clmul_a, 16);
  rng_fill(&r, clmul_b, 16);
  rng_fill(&r, bulk_src, sizeof bulk_src);
  rng_fill(&r, xmm_seed, sizeof xmm_seed);

  /* AES-128 single block, scalar reference */
  u8 rk128[11 * 16];
  ref_key_expand(key128, 16, rk128);
  ref_aes_encrypt(rk128, 10, pt, exp_aes128);
  memcpy(ek, rk128, sizeof rk128);

  /* AES-256 equivalent inverse schedule for the 4-way decrypt */
  u8 rk256[15 * 16];
  ref_key_expand(key256, 32, rk256);
  memcpy(dk, rk256 + 16 * ROUNDS256, 16);
  for (int i = 1; i < ROUNDS256; ++i) ref_aesimc(dk + 16 * i, rk256 + 16 * (ROUNDS256 - i));
  memcpy(dk + 16 * ROUNDS256, rk256, 16);
  for (int b = 0; b < 4; ++b) ref_aes_decrypt(rk256, ROUNDS256, ctblk + 16 * b, exp_aes256_4way + 16 * b);

  /* SHA */
  sha256_scalar(shablk, 1, exp_sha256);
  sha1_scalar(shablk, 1, exp_sha1);

  /* PCLMUL */
  ref_pclmul(exp_clmul, clmul_a, clmul_b, 0x10);

  /* CRC-32C */
  u32 c = 0xffffffffu;
  for (unsigned i = 0; i < sizeof crcbuf; ++i) c = ref_crc32c_byte(c, crcbuf[i]);
  exp_crc = c;
}

/* ------------------------- crypto workers ------------------------- */
/* AES-128 encrypt, plain intrinsics, forced to reload its inputs. */
static void do_aes128(u8* out) {
  const u8* p = pt;
  const u8* k = ek;
  OPAQUE_PTR(p);
  OPAQUE_PTR(k);
  __m128i s = _mm_xor_si128(ld128(p), ld128(k));
  for (int r = 1; r < 10; ++r) s = _mm_aesenc_si128(s, ld128(k + 16 * r));
  s = _mm_aesenclast_si128(s, ld128(k + 160));
  st128(out, s);
}

/* 4-way AES-256 decrypt interleave: four states live at once. */
static void do_aes256_4way(u8* out) {
  const u8* c = ctblk;
  const u8* k = dk + 16;
  u8* o = out;
  unsigned cnt;
  OPAQUE_PTR(c);
  OPAQUE_PTR(k);
  __asm__ volatile("movdqu 0(%[c]), %%xmm0\n\t"
                   "movdqu 16(%[c]), %%xmm1\n\t"
                   "movdqu 32(%[c]), %%xmm2\n\t"
                   "movdqu 48(%[c]), %%xmm3\n\t"
                   "movdqu -16(%[k]), %%xmm4\n\t"
                   "pxor %%xmm4, %%xmm0\n\t"
                   "pxor %%xmm4, %%xmm1\n\t"
                   "pxor %%xmm4, %%xmm2\n\t"
                   "pxor %%xmm4, %%xmm3\n\t"
                   "movl $13, %[cnt]\n\t"
                   "1:\n\t"
                   "movdqu 0(%[k]), %%xmm4\n\t"
                   "lea 16(%[k]), %[k]\n\t"
                   "aesdec %%xmm4, %%xmm0\n\t"
                   "aesdec %%xmm4, %%xmm1\n\t"
                   "aesdec %%xmm4, %%xmm2\n\t"
                   "aesdec %%xmm4, %%xmm3\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 1b\n\t"
                   "movdqu 0(%[k]), %%xmm4\n\t"
                   "aesdeclast %%xmm4, %%xmm0\n\t"
                   "aesdeclast %%xmm4, %%xmm1\n\t"
                   "aesdeclast %%xmm4, %%xmm2\n\t"
                   "aesdeclast %%xmm4, %%xmm3\n\t"
                   "movdqu %%xmm0, 0(%[o])\n\t"
                   "movdqu %%xmm1, 16(%[o])\n\t"
                   "movdqu %%xmm2, 32(%[o])\n\t"
                   "movdqu %%xmm3, 48(%[o])\n\t"
                   : [k] "+r"(k), [cnt] "=&r"(cnt)
                   : [c] "r"(c), [o] "r"(o)
                   : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "memory", "cc");
}

static void do_sha256(u8* out32) {
  const __m128i MASK = _mm_set_epi64x((long long)0x0c0d0e0f08090a0bull, (long long)0x0405060700010203ull);
  u32 state[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  __m128i TMP = _mm_loadu_si128((const __m128i*)&state[0]);
  __m128i STATE1 = _mm_loadu_si128((const __m128i*)&state[4]);
  TMP = _mm_shuffle_epi32(TMP, 0xb1);
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1b);
  __m128i STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xf0);
  __m128i S0 = STATE0, S1 = STATE1;
  const u8* p = shablk;
  OPAQUE_PTR(p);
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
  TMP = _mm_shuffle_epi32(STATE0, 0x1b);
  __m128i T1 = _mm_shuffle_epi32(STATE1, 0xb1);
  u8 tmp[32];
  st128(tmp, _mm_blend_epi16(TMP, T1, 0xf0));
  st128(tmp + 16, _mm_alignr_epi8(T1, TMP, 8));
  for (int i = 0; i < 8; ++i) st_be32(out32 + 4 * i, ld32(tmp + 4 * i));
}

static void do_sha1(u8* out20) {
  const __m128i MASK = _mm_set_epi64x((long long)0x0001020304050607ull, (long long)0x08090a0b0c0d0e0full);
  u32 state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
  __m128i ABCD = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)state), 0x1b);
  __m128i E = _mm_set_epi32((int)state[4], 0, 0, 0);
  __m128i ABCD_SAVE = ABCD, E_SAVE = E;
  const u8* p = shablk;
  OPAQUE_PTR(p);
  __m128i M[4], Ecur = E, Enxt;
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
  u8 tmp[16];
  st128(tmp, _mm_shuffle_epi32(ABCD, 0x1b));
  for (int i = 0; i < 4; ++i) st_be32(out20 + 4 * i, ld32(tmp + 4 * i));
  st128(tmp, E);
  st_be32(out20 + 16, ld32(tmp + 12));
}

static void do_clmul(u8* out) {
  const u8* a = clmul_a;
  const u8* b = clmul_b;
  OPAQUE_PTR(a);
  OPAQUE_PTR(b);
  st128(out, _mm_clmulepi64_si128(ld128(a), ld128(b), 0x10));
}

static u32 do_crc(void) {
  const u8* p = crcbuf;
  OPAQUE_PTR(p);
  u32 c = 0xffffffffu;
  for (unsigned i = 0; i < 256; i += 4) c = (u32)__builtin_ia32_crc32si(c, ld32(p + i));
  return c;
}

/* ------------------------- host-side noise ------------------------- */
static double x87_sink;

static void noise_x87(void) {
  /* 80-bit transcendentals: fsin / f2xm1 / fptan all land in FEX's FABI
     F80 helper calls (host C++ long-double code). */
  double out;
  __asm__ volatile("fld1\n\t"
                   "fldpi\n\t"
                   "fsin\n\t"
                   "faddp %%st, %%st(1)\n\t"
                   "fldl2e\n\t"
                   "fld1\n\t"
                   "fdivp %%st, %%st(1)\n\t"
                   "f2xm1\n\t"
                   "fptan\n\t"
                   "fstp %%st(0)\n\t"
                   "faddp %%st, %%st(1)\n\t"
                   "fstpl %0\n\t"
                   : "=m"(out)
                   :
                   : "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)", "memory");
  x87_sink += out;
}

static void noise_syscalls(void) {
  sys_write(devnull_fd, "x", 1);
  sys_nanosleep_zero();
  (void)sys_getpid();
}

static void noise_bulk(void) {
  /* memcpy-shaped: large loads/stores that push through FEX's memcpy tier */
  memcpy(bulk_dst, bulk_src, 2048);
  bulk_dst[(bulk_src[0] + 1) & 2047] ^= 1;
  memcpy(bulk_src + 4096, bulk_dst, 2048);
}

/* Holds every architectural XMM live across a host call and checks that the
   registers survived.  This is the shape that cross-call clobbering breaks. */
static int xmm_live_across(int kind) {
  const u8* s = xmm_seed;
  u8* b = xmm_back;
  OPAQUE_PTR(s);
#ifdef __x86_64__
#define LOADX                                                                                                          \
  "movdqu 0(%[s]), %%xmm0\n\tmovdqu 16(%[s]), %%xmm1\n\tmovdqu 32(%[s]), %%xmm2\n\tmovdqu 48(%[s]), %%xmm3\n\t"        \
  "movdqu 64(%[s]), %%xmm4\n\tmovdqu 80(%[s]), %%xmm5\n\tmovdqu 96(%[s]), %%xmm6\n\tmovdqu 112(%[s]), %%xmm7\n\t"      \
  "movdqu 128(%[s]), %%xmm8\n\tmovdqu 144(%[s]), %%xmm9\n\tmovdqu 160(%[s]), %%xmm10\n\t"                              \
  "movdqu 176(%[s]), %%xmm11\n\tmovdqu 192(%[s]), %%xmm12\n\tmovdqu 208(%[s]), %%xmm13\n\t"                            \
  "movdqu 224(%[s]), %%xmm14\n\tmovdqu 240(%[s]), %%xmm15\n\t"
#define STOREX                                                                                                         \
  "movdqu %%xmm0, 0(%[b])\n\tmovdqu %%xmm1, 16(%[b])\n\tmovdqu %%xmm2, 32(%[b])\n\tmovdqu %%xmm3, 48(%[b])\n\t"        \
  "movdqu %%xmm4, 64(%[b])\n\tmovdqu %%xmm5, 80(%[b])\n\tmovdqu %%xmm6, 96(%[b])\n\tmovdqu %%xmm7, 112(%[b])\n\t"      \
  "movdqu %%xmm8, 128(%[b])\n\tmovdqu %%xmm9, 144(%[b])\n\tmovdqu %%xmm10, 160(%[b])\n\t"                              \
  "movdqu %%xmm11, 176(%[b])\n\tmovdqu %%xmm12, 192(%[b])\n\tmovdqu %%xmm13, 208(%[b])\n\t"                            \
  "movdqu %%xmm14, 224(%[b])\n\tmovdqu %%xmm15, 240(%[b])\n\t"
#define XCLOB                                                                                                          \
  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13",  \
      "xmm14", "xmm15"
#define NREGS 16
#define HOSTCALL "movl $39, %%eax\n\tsyscall\n\t"
#define HOSTCLOB "rax", "rcx", "r11"
#else
#define LOADX                                                                                                          \
  "movdqu 0(%[s]), %%xmm0\n\tmovdqu 16(%[s]), %%xmm1\n\tmovdqu 32(%[s]), %%xmm2\n\tmovdqu 48(%[s]), %%xmm3\n\t"        \
  "movdqu 64(%[s]), %%xmm4\n\tmovdqu 80(%[s]), %%xmm5\n\tmovdqu 96(%[s]), %%xmm6\n\tmovdqu 112(%[s]), %%xmm7\n\t"
#define STOREX                                                                                                         \
  "movdqu %%xmm0, 0(%[b])\n\tmovdqu %%xmm1, 16(%[b])\n\tmovdqu %%xmm2, 32(%[b])\n\tmovdqu %%xmm3, 48(%[b])\n\t"        \
  "movdqu %%xmm4, 64(%[b])\n\tmovdqu %%xmm5, 80(%[b])\n\tmovdqu %%xmm6, 96(%[b])\n\tmovdqu %%xmm7, 112(%[b])\n\t"
#define XCLOB "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"
#define NREGS 8
#define HOSTCALL "movl $20, %%eax\n\tint $0x80\n\t"
#define HOSTCLOB "eax"
#endif
  if (kind & 1) {
    __asm__ volatile(LOADX HOSTCALL STOREX : : [s] "r"(s), [b] "r"(b) : XCLOB, HOSTCLOB, "memory");
  } else {
    __asm__ volatile(LOADX
                     "fld1\n\tfldpi\n\tfsin\n\tfaddp %%st, %%st(1)\n\tfldl2e\n\tf2xm1\n\tfaddp %%st, %%st(1)\n\t"
                     "fstpl %[sink]\n\t" STOREX
                     : [sink] "=m"(x87_sink)
                     : [s] "r"(s), [b] "r"(b)
                     : XCLOB, "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)", "memory");
  }
  return same_mem(xmm_back, xmm_seed, 16 * NREGS) ? 0 : 1;
}

/* ------------------------- driver ------------------------- */
static u64 parse_u64(const char* s) {
  u64 v = 0;
  while (*s >= '0' && *s <= '9') v = v * 10 + (u64)(*s++ - '0');
  return v;
}

static void fail_at(const char* what, u64 iter) {
  puts_raw("FAIL stress.");
  puts_raw(what);
  puts_raw(" first divergence at iteration ");
  put_dec(iter);
  puts_raw("\n");
  ++g_fails;
}

void guest_main(long* sp) {
  long argc = sp[0];
  const char** argv = (const char**)(sp + 1);
  u64 iters = 100000;
  if (argc > 1) {
    u64 v = parse_u64(argv[1]);
    if (v) iters = v;
  }

  aes_init_tables();
  build_fixtures();
  devnull_fd = sys_open_wronly("/dev/null");
  if (devnull_fd < 0) devnull_fd = 2; /* fall back to stderr-less write */

  puts_raw("== GuestCrypto: STRESS (crypto interleaved with host calls) ==\n");
  puts_raw("iterations=");
  put_dec(iters);
  puts_raw("\n");

  u8 o_aes128[16], o_aes256[64], o_sha256[32], o_sha1[20], o_clmul[16];
  int bad_aes128 = 0, bad_aes256 = 0, bad_sha256 = 0, bad_sha1 = 0, bad_clmul = 0, bad_crc = 0, bad_xmm = 0;

  for (u64 it = 0; it < iters; ++it) {
    do_aes128(o_aes128);
    if (!same_mem(o_aes128, exp_aes128, 16) && !bad_aes128++) fail_at("aes128", it);

    do_aes256_4way(o_aes256);
    if (!same_mem(o_aes256, exp_aes256_4way, 64) && !bad_aes256++) fail_at("aes256_4way", it);

    do_sha256(o_sha256);
    if (!same_mem(o_sha256, exp_sha256, 32) && !bad_sha256++) fail_at("sha256", it);

    do_sha1(o_sha1);
    if (!same_mem(o_sha1, exp_sha1, 20) && !bad_sha1++) fail_at("sha1", it);

    do_clmul(o_clmul);
    if (!same_mem(o_clmul, exp_clmul, 16) && !bad_clmul++) fail_at("pclmul", it);

    if (do_crc() != exp_crc && !bad_crc++) fail_at("crc32", it);

    if (xmm_live_across((int)it) && !bad_xmm++) fail_at("xmm_live_across_hostcall", it);

    /* host-side noise, rotated so every combination of orderings occurs */
    switch ((unsigned)(it % 6)) {
    case 0: noise_syscalls(); break;
    case 1: noise_x87(); break;
    case 2: noise_bulk(); break;
    case 3:
      noise_x87();
      noise_syscalls();
      break;
    case 4:
      noise_syscalls();
      noise_bulk();
      break;
    default:
      noise_bulk();
      noise_x87();
      noise_syscalls();
      break;
    }

    if (bad_aes128 || bad_aes256 || bad_sha256 || bad_sha1 || bad_clmul || bad_crc || bad_xmm) break;
  }

  if (!g_fails) {
    report("stress.aes128", 1);
    report("stress.aes256_4way", 1);
    report("stress.sha256", 1);
    report("stress.sha1", 1);
    report("stress.pclmul", 1);
    report("stress.crc32", 1);
    report("stress.xmm_live_across_hostcall", 1);
  }
  puts_raw("stress: iterations_run fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
