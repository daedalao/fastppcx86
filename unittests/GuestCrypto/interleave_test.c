// Multiway/interleave register shapes: the exact loop bodies that real
// software emits, where several AES states live in registers simultaneously
// and round keys are reloaded or ping-ponged.  These shapes are what caught
// the steamclient manifest-decrypt failures, so they are first-class here.
//
//   2-way  : states xmm0/xmm1, key held in xmm2
//   4-way  : steamclient.so BDecryptFilenames inner loop (states xmm0-3,
//            key reloaded into xmm4 each round, CBC chain through xmm7)
//   6-way  : OpenSSL aesni-x86.pl _aesni_decrypt6 (states xmm2-7, keys
//            ping-ponging through xmm0/xmm1)
//   8-way  : maximum register pressure -- all 8 architectural XMMs hold
//            state, every round key comes straight from memory
//   4-way encrypt : CTR-style aesenc interleave
//
// The reference for all of them is the plain-C FIPS-197 inverse cipher, so a
// JIT bug cannot cancel out between the test and its expectation.
#include <immintrin.h>
#include "crypto_common.h"

#define ROUNDS 14
#define NBLK 8

__attribute__((aligned(16))) static u8 ek[15 * 16];  /* encryption schedule */
__attribute__((aligned(16))) static u8 dk[15 * 16];  /* equivalent inverse schedule */
__attribute__((aligned(16))) static u8 iv[16];
__attribute__((aligned(16))) static u8 ct[NBLK * 16];
__attribute__((aligned(16))) static u8 out[NBLK * 16];
__attribute__((aligned(16))) static u8 refbuf[NBLK * 16];
__attribute__((aligned(16))) static u8 save[2 * 16];
__attribute__((aligned(16))) static u8 rk0v[16], rklastv[16];

static void build_schedules(u32 seed) {
  rng_t r;
  rng_seed(&r, seed);
  u8 key[32];
  rng_fill(&r, key, 32);
  ref_key_expand(key, 32, ek);
  /* equivalent inverse cipher schedule: reversed, middle keys through IMC */
  memcpy(dk, ek + 16 * ROUNDS, 16);
  for (int i = 1; i < ROUNDS; ++i) ref_aesimc(dk + 16 * i, ek + 16 * (ROUNDS - i));
  memcpy(dk + 16 * ROUNDS, ek, 16);
  memcpy(rk0v, dk, 16);
  memcpy(rklastv, dk + 16 * ROUNDS, 16);
  rng_fill(&r, iv, 16);
  rng_fill(&r, ct, sizeof ct);
}

static void cbc_reference(unsigned nblk) {
  for (unsigned b = 0; b < nblk; ++b) {
    u8 d[16];
    ref_aes_decrypt(ek, ROUNDS, ct + 16 * b, d);
    const u8* prev = b ? ct + 16 * (b - 1) : iv;
    for (int i = 0; i < 16; ++i) refbuf[16 * b + i] = (u8)(d[i] ^ prev[i]);
  }
}
static void ecb_reference(unsigned nblk) {
  for (unsigned b = 0; b < nblk; ++b) ref_aes_decrypt(ek, ROUNDS, ct + 16 * b, refbuf + 16 * b);
}

/* ------------------------------ 2-way ------------------------------ */
static void dec2(const u8* c, u8* o, unsigned pairs) {
  const u8* kp = dk + 16;
  unsigned cnt;
  __asm__ volatile("1:\n\t"
                   "movdqu (%[c]), %%xmm0\n\t"
                   "movdqu 16(%[c]), %%xmm1\n\t"
                   "movdqa %[rk0], %%xmm2\n\t"
                   "pxor %%xmm2, %%xmm0\n\t"
                   "pxor %%xmm2, %%xmm1\n\t"
                   "movl $13, %[cnt]\n\t"
                   "2:\n\t"
                   "movdqu (%[kp]), %%xmm2\n\t"
                   "add $16, %[kp]\n\t"
                   "aesdec %%xmm2, %%xmm0\n\t"
                   "aesdec %%xmm2, %%xmm1\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 2b\n\t"
                   "movdqa %[rklast], %%xmm2\n\t"
                   "aesdeclast %%xmm2, %%xmm0\n\t"
                   "aesdeclast %%xmm2, %%xmm1\n\t"
                   "movdqu %%xmm0, (%[o])\n\t"
                   "movdqu %%xmm1, 16(%[o])\n\t"
                   "sub $208, %[kp]\n\t"
                   "add $32, %[c]\n\t"
                   "add $32, %[o]\n\t"
                   "dec %[pairs]\n\t"
                   "jnz 1b\n\t"
                   : [c] "+r"(c), [o] "+r"(o), [kp] "+r"(kp), [pairs] "+r"(pairs), [cnt] "=&r"(cnt)
                   : [rk0] "m"(*(const __m128i*)rk0v), [rklast] "m"(*(const __m128i*)rklastv)
                   : "xmm0", "xmm1", "xmm2", "memory", "cc");
}

/* ------------------- 4-way, steamclient.so shape ------------------- */
static void dec4(const u8* c, u8* o, unsigned outer) {
  const u8* kp = dk + 16;
  unsigned cnt;
  __asm__ volatile("movdqa %[ivv], %%xmm7\n\t"
                   "movdqa %[rk0], %%xmm6\n\t"
                   "movdqa %[rklast], %%xmm5\n\t"
                   "1:\n\t"
                   "movaps %%xmm7, %[sv0]\n\t"
                   "movdqu 16(%[c]), %%xmm4\n\t"
                   "movdqu (%[c]), %%xmm7\n\t"
                   "movdqa %%xmm4, %%xmm2\n\t"
                   "movaps %%xmm4, %[sv1]\n\t"
                   "movdqu 32(%[c]), %%xmm4\n\t"
                   "movdqu 48(%[c]), %%xmm0\n\t"
                   "movdqa %%xmm7, %%xmm3\n\t"
                   "pxor %%xmm6, %%xmm2\n\t"
                   "movdqa %%xmm4, %%xmm1\n\t"
                   "pxor %%xmm6, %%xmm3\n\t"
                   "pxor %%xmm6, %%xmm1\n\t"
                   "pxor %%xmm6, %%xmm0\n\t"
                   "movl $13, %[cnt]\n\t"
                   "2:\n\t"
                   "movdqu (%[kp]), %%xmm4\n\t"
                   "add $16, %[kp]\n\t"
                   "aesdec %%xmm4, %%xmm3\n\t"
                   "aesdec %%xmm4, %%xmm2\n\t"
                   "aesdec %%xmm4, %%xmm1\n\t"
                   "aesdec %%xmm4, %%xmm0\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 2b\n\t"
                   "sub $208, %[kp]\n\t"
                   "aesdeclast %%xmm5, %%xmm3\n\t"
                   "aesdeclast %%xmm5, %%xmm2\n\t"
                   "pxor %[sv0], %%xmm3\n\t"
                   "pxor %%xmm7, %%xmm2\n\t"
                   "movups %%xmm3, (%[o])\n\t"
                   "movups %%xmm2, 16(%[o])\n\t"
                   "movdqu 32(%[c]), %%xmm7\n\t"
                   "aesdeclast %%xmm5, %%xmm1\n\t"
                   "aesdeclast %%xmm5, %%xmm0\n\t"
                   "pxor %[sv1], %%xmm1\n\t"
                   "pxor %%xmm7, %%xmm0\n\t"
                   "movups %%xmm1, 32(%[o])\n\t"
                   "movups %%xmm0, 48(%[o])\n\t"
                   "movdqu 48(%[c]), %%xmm7\n\t"
                   "add $64, %[c]\n\t"
                   "add $64, %[o]\n\t"
                   "dec %[outer]\n\t"
                   "jnz 1b\n\t"
                   : [c] "+r"(c), [o] "+r"(o), [kp] "+r"(kp), [outer] "+r"(outer), [cnt] "=&r"(cnt),
                     [sv0] "=m"(*(__m128i*)save), [sv1] "=m"(*(__m128i*)(save + 16))
                   : [ivv] "m"(*(const __m128i*)iv), [rk0] "m"(*(const __m128i*)rk0v),
                     [rklast] "m"(*(const __m128i*)rklastv)
                   : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "memory", "cc");
}

/* ------------- 6-way, OpenSSL _aesni_decrypt6 register shape ------------- */
static void dec6(const u8* in, u8* o) {
  const u8* k = dk;
  unsigned cnt;
  __asm__ volatile("movdqu 0(%[in]), %%xmm2\n\t"
                   "movdqu 16(%[in]), %%xmm3\n\t"
                   "movdqu 32(%[in]), %%xmm4\n\t"
                   "movdqu 48(%[in]), %%xmm5\n\t"
                   "movdqu 64(%[in]), %%xmm6\n\t"
                   "movdqu 80(%[in]), %%xmm7\n\t"
                   "movdqa 0(%[k]), %%xmm0\n\t"
                   "pxor %%xmm0, %%xmm2\n\t"
                   "pxor %%xmm0, %%xmm3\n\t"
                   "pxor %%xmm0, %%xmm4\n\t"
                   "pxor %%xmm0, %%xmm5\n\t"
                   "pxor %%xmm0, %%xmm6\n\t"
                   "pxor %%xmm0, %%xmm7\n\t"
                   "lea 16(%[k]), %[k]\n\t"
                   "movl $6, %[cnt]\n\t"
                   "1:\n\t"
                   "movdqa 0(%[k]), %%xmm1\n\t"
                   "aesdec %%xmm1, %%xmm2\n\t"
                   "aesdec %%xmm1, %%xmm3\n\t"
                   "aesdec %%xmm1, %%xmm4\n\t"
                   "aesdec %%xmm1, %%xmm5\n\t"
                   "aesdec %%xmm1, %%xmm6\n\t"
                   "aesdec %%xmm1, %%xmm7\n\t"
                   "movdqa 16(%[k]), %%xmm0\n\t"
                   "aesdec %%xmm0, %%xmm2\n\t"
                   "aesdec %%xmm0, %%xmm3\n\t"
                   "aesdec %%xmm0, %%xmm4\n\t"
                   "aesdec %%xmm0, %%xmm5\n\t"
                   "aesdec %%xmm0, %%xmm6\n\t"
                   "aesdec %%xmm0, %%xmm7\n\t"
                   "lea 32(%[k]), %[k]\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 1b\n\t"
                   "movdqa 0(%[k]), %%xmm1\n\t"
                   "aesdec %%xmm1, %%xmm2\n\t"
                   "aesdec %%xmm1, %%xmm3\n\t"
                   "aesdec %%xmm1, %%xmm4\n\t"
                   "aesdec %%xmm1, %%xmm5\n\t"
                   "aesdec %%xmm1, %%xmm6\n\t"
                   "aesdec %%xmm1, %%xmm7\n\t"
                   "movdqa 16(%[k]), %%xmm0\n\t"
                   "aesdeclast %%xmm0, %%xmm2\n\t"
                   "aesdeclast %%xmm0, %%xmm3\n\t"
                   "aesdeclast %%xmm0, %%xmm4\n\t"
                   "aesdeclast %%xmm0, %%xmm5\n\t"
                   "aesdeclast %%xmm0, %%xmm6\n\t"
                   "aesdeclast %%xmm0, %%xmm7\n\t"
                   "movdqu %%xmm2, 0(%[o])\n\t"
                   "movdqu %%xmm3, 16(%[o])\n\t"
                   "movdqu %%xmm4, 32(%[o])\n\t"
                   "movdqu %%xmm5, 48(%[o])\n\t"
                   "movdqu %%xmm6, 64(%[o])\n\t"
                   "movdqu %%xmm7, 80(%[o])\n\t"
                   : [k] "+r"(k), [cnt] "=&r"(cnt)
                   : [in] "r"(in), [o] "r"(o)
                   : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "memory", "cc");
}

/* ---- 8-way: every architectural XMM holds state, keys from memory ---- */
static void dec8(const u8* in, u8* o) {
  const u8* k = dk;
  unsigned cnt;
  __asm__ volatile("movdqu 0(%[in]), %%xmm0\n\t"
                   "movdqu 16(%[in]), %%xmm1\n\t"
                   "movdqu 32(%[in]), %%xmm2\n\t"
                   "movdqu 48(%[in]), %%xmm3\n\t"
                   "movdqu 64(%[in]), %%xmm4\n\t"
                   "movdqu 80(%[in]), %%xmm5\n\t"
                   "movdqu 96(%[in]), %%xmm6\n\t"
                   "movdqu 112(%[in]), %%xmm7\n\t"
                   "pxor 0(%[k]), %%xmm0\n\t"
                   "pxor 0(%[k]), %%xmm1\n\t"
                   "pxor 0(%[k]), %%xmm2\n\t"
                   "pxor 0(%[k]), %%xmm3\n\t"
                   "pxor 0(%[k]), %%xmm4\n\t"
                   "pxor 0(%[k]), %%xmm5\n\t"
                   "pxor 0(%[k]), %%xmm6\n\t"
                   "pxor 0(%[k]), %%xmm7\n\t"
                   "lea 16(%[k]), %[k]\n\t"
                   "movl $13, %[cnt]\n\t"
                   "1:\n\t"
                   "aesdec 0(%[k]), %%xmm0\n\t"
                   "aesdec 0(%[k]), %%xmm1\n\t"
                   "aesdec 0(%[k]), %%xmm2\n\t"
                   "aesdec 0(%[k]), %%xmm3\n\t"
                   "aesdec 0(%[k]), %%xmm4\n\t"
                   "aesdec 0(%[k]), %%xmm5\n\t"
                   "aesdec 0(%[k]), %%xmm6\n\t"
                   "aesdec 0(%[k]), %%xmm7\n\t"
                   "lea 16(%[k]), %[k]\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 1b\n\t"
                   "aesdeclast 0(%[k]), %%xmm0\n\t"
                   "aesdeclast 0(%[k]), %%xmm1\n\t"
                   "aesdeclast 0(%[k]), %%xmm2\n\t"
                   "aesdeclast 0(%[k]), %%xmm3\n\t"
                   "aesdeclast 0(%[k]), %%xmm4\n\t"
                   "aesdeclast 0(%[k]), %%xmm5\n\t"
                   "aesdeclast 0(%[k]), %%xmm6\n\t"
                   "aesdeclast 0(%[k]), %%xmm7\n\t"
                   "movdqu %%xmm0, 0(%[o])\n\t"
                   "movdqu %%xmm1, 16(%[o])\n\t"
                   "movdqu %%xmm2, 32(%[o])\n\t"
                   "movdqu %%xmm3, 48(%[o])\n\t"
                   "movdqu %%xmm4, 64(%[o])\n\t"
                   "movdqu %%xmm5, 80(%[o])\n\t"
                   "movdqu %%xmm6, 96(%[o])\n\t"
                   "movdqu %%xmm7, 112(%[o])\n\t"
                   : [k] "+r"(k), [cnt] "=&r"(cnt)
                   : [in] "r"(in), [o] "r"(o)
                   : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "memory", "cc");
}

/* ---- 4-way encrypt interleave (CTR-style): states xmm0-3, key xmm4 ---- */
static void enc4(const u8* in, u8* o) {
  const u8* k = ek + 16;
  unsigned cnt;
  __asm__ volatile("movdqu 0(%[in]), %%xmm0\n\t"
                   "movdqu 16(%[in]), %%xmm1\n\t"
                   "movdqu 32(%[in]), %%xmm2\n\t"
                   "movdqu 48(%[in]), %%xmm3\n\t"
                   "movdqu -16(%[k]), %%xmm4\n\t"
                   "pxor %%xmm4, %%xmm0\n\t"
                   "pxor %%xmm4, %%xmm1\n\t"
                   "pxor %%xmm4, %%xmm2\n\t"
                   "pxor %%xmm4, %%xmm3\n\t"
                   "movl $13, %[cnt]\n\t"
                   "1:\n\t"
                   "movdqu 0(%[k]), %%xmm4\n\t"
                   "lea 16(%[k]), %[k]\n\t"
                   "aesenc %%xmm4, %%xmm0\n\t"
                   "aesenc %%xmm4, %%xmm1\n\t"
                   "aesenc %%xmm4, %%xmm2\n\t"
                   "aesenc %%xmm4, %%xmm3\n\t"
                   "dec %[cnt]\n\t"
                   "jnz 1b\n\t"
                   "movdqu 0(%[k]), %%xmm4\n\t"
                   "aesenclast %%xmm4, %%xmm0\n\t"
                   "aesenclast %%xmm4, %%xmm1\n\t"
                   "aesenclast %%xmm4, %%xmm2\n\t"
                   "aesenclast %%xmm4, %%xmm3\n\t"
                   "movdqu %%xmm0, 0(%[o])\n\t"
                   "movdqu %%xmm1, 16(%[o])\n\t"
                   "movdqu %%xmm2, 32(%[o])\n\t"
                   "movdqu %%xmm3, 48(%[o])\n\t"
                   : [k] "+r"(k), [cnt] "=&r"(cnt)
                   : [in] "r"(in), [o] "r"(o)
                   : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "memory", "cc");
}

static int cmp_blocks(const char* name, const u8* got, const u8* want, unsigned nblk) {
  int bad = 0;
  for (unsigned b = 0; b < nblk; ++b)
    if (!same_mem(got + 16 * b, want + 16 * b, 16)) {
      if (!bad && g_verbose_left > 0) {
        --g_verbose_left;
        puts_raw("  first bad block index ");
        put_dec(b);
        puts_raw("\n");
        put_hex_buf("  got  ", got + 16 * b, 16);
        put_hex_buf("  want ", want + 16 * b, 16);
      }
      ++bad;
    }
  report(name, bad == 0);
  return bad;
}

void guest_main(long* sp) {
  (void)sp;
  aes_init_tables();
  puts_raw("== GuestCrypto: interleave shapes ==\n");

  /* Repeat every shape with several independent key/data sets: a schedule
     dependent bug can hide behind one key. */
  for (int rep = 0; rep < 8; ++rep) {
    build_schedules(0x1000u + (u32)rep * 0x9e3779b9u);

    memset(out, 0, sizeof out);
    ecb_reference(2 * 4);
    dec2(ct, out, 4);
    if (rep == 0) cmp_blocks("interleave.2way_ecb", out, refbuf, 8);
    else if (!same_mem(out, refbuf, sizeof out)) cmp_blocks("interleave.2way_ecb.rep", out, refbuf, 8);

    memset(out, 0, sizeof out);
    cbc_reference(NBLK);
    dec4(ct, out, NBLK / 4);
    if (rep == 0) cmp_blocks("interleave.4way_cbc_steamclient", out, refbuf, NBLK);
    else if (!same_mem(out, refbuf, sizeof out)) cmp_blocks("interleave.4way_cbc_steamclient.rep", out, refbuf, NBLK);

    memset(out, 0, sizeof out);
    ecb_reference(6);
    dec6(ct, out);
    if (rep == 0) cmp_blocks("interleave.6way_openssl", out, refbuf, 6);
    else if (!same_mem(out, refbuf, 6 * 16)) cmp_blocks("interleave.6way_openssl.rep", out, refbuf, 6);

    memset(out, 0, sizeof out);
    ecb_reference(8);
    dec8(ct, out);
    if (rep == 0) cmp_blocks("interleave.8way_pressure", out, refbuf, 8);
    else if (!same_mem(out, refbuf, 8 * 16)) cmp_blocks("interleave.8way_pressure.rep", out, refbuf, 8);

    memset(out, 0, sizeof out);
    for (int b = 0; b < 4; ++b) ref_aes_encrypt(ek, ROUNDS, ct + 16 * b, refbuf + 16 * b);
    enc4(ct, out);
    if (rep == 0) cmp_blocks("interleave.4way_encrypt", out, refbuf, 4);
    else if (!same_mem(out, refbuf, 4 * 16)) cmp_blocks("interleave.4way_encrypt.rep", out, refbuf, 4);
  }
  report("interleave.all_reps_consistent", 1);

  puts_raw("interleave: checks=");
  put_dec((u64)g_checks);
  puts_raw(" fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
