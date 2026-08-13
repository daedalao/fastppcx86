// Shared freestanding runtime + scalar crypto reference implementations for
// the GuestCrypto suite.  No libc: direct syscalls (int 0x80 on i686,
// "syscall" on x86_64) so one source tree builds for both bitnesses.
//
// MUST be compiled with -ffreestanding: without it clang's <immintrin.h>
// chain pulls in mm_malloc.h, which includes the *host* (ppc64le) stdlib.h
// and the build explodes in confusing ways.
//
// Everything in here is plain C.  Reference implementations deliberately use
// no intrinsics at all -- they are transcribed from the Intel SDM pseudocode
// so that a JIT lowering bug cannot hide inside a shared helper.
#ifndef GUESTCRYPTO_COMMON_H
#define GUESTCRYPTO_COMMON_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#ifdef __x86_64__
typedef unsigned long usize;
#else
typedef unsigned int usize;
#endif

/* ------------------------------------------------------------------ */
/* entry point: a tiny asm shim so guest_main() gets the initial stack  */
/* pointer and can read argc/argv (used for the stress iteration count) */
/* ------------------------------------------------------------------ */
#ifdef __x86_64__
__asm__(".text\n"
        ".globl _start\n"
        "_start:\n\t"
        "movq %rsp, %rdi\n\t"
        "andq $-16, %rsp\n\t"
        "call guest_main\n\t"
        "hlt\n");
#else
__asm__(".text\n"
        ".globl _start\n"
        "_start:\n\t"
        "movl %esp, %eax\n\t"
        "andl $-16, %esp\n\t"
        "subl $12, %esp\n\t"
        "pushl %eax\n\t"
        "call guest_main\n\t"
        "hlt\n");
#endif

void guest_main(long* sp);

/* ------------------------------------------------------------------ */
/* syscalls                                                            */
/* ------------------------------------------------------------------ */
static long sys3(long nr, long a, long b, long c) {
#ifdef __x86_64__
  long ret;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(nr), "D"(a), "S"(b), "d"(c)
                   : "rcx", "r11", "memory");
  return ret;
#else
  long ret;
  __asm__ volatile("int $0x80" : "=a"(ret) : "a"(nr), "b"(a), "c"(b), "d"(c) : "memory");
  return ret;
#endif
}

#ifdef __x86_64__
#define SYS_write 1
#define SYS_open 2
#define SYS_exit 60
#define SYS_getpid 39
#define SYS_nanosleep 35
#else
#define SYS_write 4
#define SYS_open 5
#define SYS_exit 1
#define SYS_getpid 20
#define SYS_nanosleep 162
#endif

static void sys_write(int fd, const char* buf, unsigned len) {
  sys3(SYS_write, fd, (long)(usize)buf, (long)len);
}
static int sys_open_wronly(const char* path) {
  return (int)sys3(SYS_open, (long)(usize)path, 1 /*O_WRONLY*/, 0);
}
static int sys_getpid(void) { return (int)sys3(SYS_getpid, 0, 0, 0); }
static void sys_nanosleep_zero(void) {
  /* struct timespec { long tv_sec; long tv_nsec; } -- long is the guest long */
  volatile long ts[2] = {0, 0};
  sys3(SYS_nanosleep, (long)(usize)ts, 0, 0);
}
static void sys_exit(int code) {
#ifdef __x86_64__
  __asm__ volatile("syscall" : : "a"(60L), "D"((long)code));
#else
  __asm__ volatile("int $0x80" : : "a"(1), "b"(code));
#endif
  __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* freestanding libc bits clang may still reference                     */
/* ------------------------------------------------------------------ */
void* memcpy(void* d, const void* s, usize n) {
  u8* dd = (u8*)d;
  const u8* ss = (const u8*)s;
  for (usize i = 0; i < n; ++i) dd[i] = ss[i];
  return d;
}
void* memset(void* d, int c, usize n) {
  u8* dd = (u8*)d;
  for (usize i = 0; i < n; ++i) dd[i] = (u8)c;
  return d;
}
int memcmp(const void* a, const void* b, usize n) {
  const u8* x = (const u8*)a;
  const u8* y = (const u8*)b;
  for (usize i = 0; i < n; ++i)
    if (x[i] != y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

/* ------------------------------------------------------------------ */
/* output                                                              */
/* ------------------------------------------------------------------ */
static unsigned str_len(const char* s) {
  unsigned n = 0;
  while (s[n]) ++n;
  return n;
}
static void puts_raw(const char* s) { sys_write(1, s, str_len(s)); }

static void put_hex_buf(const char* tag, const u8* p, int n) {
  static const char hx[] = "0123456789abcdef";
  char out[8 + 2 * 64 + 2];
  unsigned k = 0;
  while (tag[k] && k < 8) {
    out[k] = tag[k];
    ++k;
  }
  if (n > 64) n = 64;
  for (int i = 0; i < n; ++i) {
    out[k++] = hx[p[i] >> 4];
    out[k++] = hx[p[i] & 15];
  }
  out[k++] = '\n';
  sys_write(1, out, k);
}

static void put_dec(u64 v) {
  char b[24];
  int k = 24;
  if (!v) b[--k] = '0';
  while (v) {
    b[--k] = (char)('0' + (v % 10));
    v /= 10;
  }
  sys_write(1, b + k, (unsigned)(24 - k));
}

/* ------------------------------------------------------------------ */
/* test bookkeeping                                                    */
/* ------------------------------------------------------------------ */
static int g_fails;
static int g_checks;
static int g_verbose_left = 8; /* limit hex dumps on mass failure */

static void report(const char* name, int ok) {
  ++g_checks;
  puts_raw(ok ? "PASS " : "FAIL ");
  puts_raw(name);
  puts_raw("\n");
  if (!ok) ++g_fails;
}

static int check_mem(const char* name, const void* got, const void* want, int n) {
  int ok = memcmp(got, want, (usize)n) == 0;
  report(name, ok);
  if (!ok && g_verbose_left > 0) {
    --g_verbose_left;
    put_hex_buf("  got  ", (const u8*)got, n);
    put_hex_buf("  want ", (const u8*)want, n);
  }
  return ok;
}

/* quiet variant for bulk loops: returns 1 on match, records nothing */
static int same_mem(const void* a, const void* b, int n) { return memcmp(a, b, (usize)n) == 0; }

/* ------------------------------------------------------------------ */
/* deterministic PRNG (xorshift32, identical in both bitnesses)         */
/* ------------------------------------------------------------------ */
typedef struct {
  u32 x;
} rng_t;
static void rng_seed(rng_t* r, u32 s) { r->x = s ? s : 0x2545f491u; }
static u32 rng_u32(rng_t* r) {
  u32 x = r->x;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  r->x = x;
  return x;
}
static void rng_fill(rng_t* r, u8* p, unsigned n) {
  for (unsigned i = 0; i < n; ++i) p[i] = (u8)rng_u32(r);
}

/* ------------------------------------------------------------------ */
/* little-endian scalar load/store helpers                              */
/* ------------------------------------------------------------------ */
static u32 ld32(const u8* p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }
static void st32(u8* p, u32 v) {
  p[0] = (u8)v;
  p[1] = (u8)(v >> 8);
  p[2] = (u8)(v >> 16);
  p[3] = (u8)(v >> 24);
}
static u64 ld64(const u8* p) { return (u64)ld32(p) | ((u64)ld32(p + 4) << 32); }
static void st64(u8* p, u64 v) {
  st32(p, (u32)v);
  st32(p + 4, (u32)(v >> 32));
}
static u32 be32(const u8* p) { return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3]; }
static void st_be32(u8* p, u32 v) {
  p[0] = (u8)(v >> 24);
  p[1] = (u8)(v >> 16);
  p[2] = (u8)(v >> 8);
  p[3] = (u8)v;
}
static u32 rotl32(u32 v, int n) { return (v << n) | (v >> (32 - n)); }
static u32 rotr32(u32 v, int n) { return (v >> n) | (v << (32 - n)); }

/* ================================================================== */
/* AES reference (FIPS-197 / Intel SDM semantics, no intrinsics)        */
/* ================================================================== */
static u8 AES_SBOX[256];
static u8 AES_ISBOX[256];
static int aes_tables_ready;

static u8 gf_mul(u8 a, u8 b) {
  u8 r = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) r ^= a;
    u8 hi = (u8)(a & 0x80);
    a = (u8)(a << 1);
    if (hi) a ^= 0x1b;
    b = (u8)(b >> 1);
  }
  return r;
}

static void aes_init_tables(void) {
  if (aes_tables_ready) return;
  aes_tables_ready = 1;
  for (int i = 0; i < 256; ++i) {
    u8 inv = 0;
    if (i) {
      for (int j = 1; j < 256; ++j)
        if (gf_mul((u8)i, (u8)j) == 1) {
          inv = (u8)j;
          break;
        }
    }
    u8 s = inv;
    u8 r = (u8)(s ^ (u8)((s << 1) | (s >> 7)) ^ (u8)((s << 2) | (s >> 6)) ^ (u8)((s << 3) | (s >> 5)) ^
                (u8)((s << 4) | (s >> 4)) ^ 0x63);
    AES_SBOX[i] = r;
  }
  for (int i = 0; i < 256; ++i) AES_ISBOX[AES_SBOX[i]] = (u8)i;
}

/* state bytes are in memory order: byte 4*c+r is row r, column c */
static void ref_shiftrows(u8* s) {
  u8 t[16];
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r) t[4 * c + r] = s[4 * ((c + r) & 3) + r];
  memcpy(s, t, 16);
}
static void ref_inv_shiftrows(u8* s) {
  u8 t[16];
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r) t[4 * c + r] = s[4 * ((c - r) & 3) + r];
  memcpy(s, t, 16);
}
static void ref_subbytes(u8* s) {
  for (int i = 0; i < 16; ++i) s[i] = AES_SBOX[s[i]];
}
static void ref_inv_subbytes(u8* s) {
  for (int i = 0; i < 16; ++i) s[i] = AES_ISBOX[s[i]];
}
static void ref_mixcolumns(u8* s) {
  for (int c = 0; c < 4; ++c) {
    u8* p = s + 4 * c;
    u8 a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    p[0] = (u8)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
    p[1] = (u8)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
    p[2] = (u8)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
    p[3] = (u8)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
  }
}
static void ref_inv_mixcolumns(u8* s) {
  for (int c = 0; c < 4; ++c) {
    u8* p = s + 4 * c;
    u8 a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
    p[0] = (u8)(gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09));
    p[1] = (u8)(gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d));
    p[2] = (u8)(gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b));
    p[3] = (u8)(gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e));
  }
}
static void xor16(u8* d, const u8* a, const u8* b) {
  for (int i = 0; i < 16; ++i) d[i] = (u8)(a[i] ^ b[i]);
}

/* SDM: AESENC  DEST = MixColumns(SubBytes(ShiftRows(SRC1))) XOR SRC2 */
static void ref_aesenc(u8* dst, const u8* s1, const u8* s2) {
  u8 t[16];
  memcpy(t, s1, 16);
  ref_shiftrows(t);
  ref_subbytes(t);
  ref_mixcolumns(t);
  xor16(dst, t, s2);
}
static void ref_aesenclast(u8* dst, const u8* s1, const u8* s2) {
  u8 t[16];
  memcpy(t, s1, 16);
  ref_shiftrows(t);
  ref_subbytes(t);
  xor16(dst, t, s2);
}
static void ref_aesdec(u8* dst, const u8* s1, const u8* s2) {
  u8 t[16];
  memcpy(t, s1, 16);
  ref_inv_shiftrows(t);
  ref_inv_subbytes(t);
  ref_inv_mixcolumns(t);
  xor16(dst, t, s2);
}
static void ref_aesdeclast(u8* dst, const u8* s1, const u8* s2) {
  u8 t[16];
  memcpy(t, s1, 16);
  ref_inv_shiftrows(t);
  ref_inv_subbytes(t);
  xor16(dst, t, s2);
}
static void ref_aesimc(u8* dst, const u8* src) {
  u8 t[16];
  memcpy(t, src, 16);
  ref_inv_mixcolumns(t);
  memcpy(dst, t, 16);
}
/* SDM: SubWord/RotWord on dwords 1 and 3 */
static u32 ref_subword(u32 w) {
  return (u32)AES_SBOX[w & 0xff] | ((u32)AES_SBOX[(w >> 8) & 0xff] << 8) | ((u32)AES_SBOX[(w >> 16) & 0xff] << 16) |
         ((u32)AES_SBOX[(w >> 24) & 0xff] << 24);
}
static u32 ref_rotword(u32 w) { return (w >> 8) | (w << 24); }
static void ref_aeskeygenassist(u8* dst, const u8* src, u8 rcon) {
  u32 x1 = ld32(src + 4);
  u32 x3 = ld32(src + 12);
  u32 s1 = ref_subword(x1);
  u32 s3 = ref_subword(x3);
  st32(dst + 0, s1);
  st32(dst + 4, ref_rotword(s1) ^ (u32)rcon);
  st32(dst + 8, s3);
  st32(dst + 12, ref_rotword(s3) ^ (u32)rcon);
}

/* Plain-C AES-128/192/256 (FIPS-197) used to cross-check the AES-NI path */
static void ref_key_expand(const u8* key, int keybytes, u8* rk /* (rounds+1)*16 */) {
  int nk = keybytes / 4;
  int rounds = nk + 6;
  int total = 4 * (rounds + 1);
  u8 w[60][4];
  for (int i = 0; i < nk; ++i)
    for (int j = 0; j < 4; ++j) w[i][j] = key[4 * i + j];
  u8 rcon = 1;
  for (int i = nk; i < total; ++i) {
    u8 t[4] = {w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3]};
    if (i % nk == 0) {
      u8 tmp = t[0];
      t[0] = AES_SBOX[t[1]];
      t[1] = AES_SBOX[t[2]];
      t[2] = AES_SBOX[t[3]];
      t[3] = AES_SBOX[tmp];
      t[0] ^= rcon;
      rcon = gf_mul(rcon, 2);
    } else if (nk > 6 && i % nk == 4) {
      for (int j = 0; j < 4; ++j) t[j] = AES_SBOX[t[j]];
    }
    for (int j = 0; j < 4; ++j) w[i][j] = (u8)(w[i - nk][j] ^ t[j]);
  }
  for (int i = 0; i < total; ++i)
    for (int j = 0; j < 4; ++j) rk[4 * i + j] = w[i][j];
}

static void ref_aes_encrypt(const u8* rk, int rounds, const u8* in, u8* out) {
  u8 s[16];
  xor16(s, in, rk);
  for (int r = 1; r < rounds; ++r) {
    ref_subbytes(s);
    ref_shiftrows(s);
    ref_mixcolumns(s);
    xor16(s, s, rk + 16 * r);
  }
  ref_subbytes(s);
  ref_shiftrows(s);
  xor16(out, s, rk + 16 * rounds);
}
static void ref_aes_decrypt(const u8* rk, int rounds, const u8* in, u8* out) {
  u8 s[16];
  xor16(s, in, rk + 16 * rounds);
  for (int r = rounds - 1; r >= 1; --r) {
    ref_inv_shiftrows(s);
    ref_inv_subbytes(s);
    xor16(s, s, rk + 16 * r);
    ref_inv_mixcolumns(s);
  }
  ref_inv_shiftrows(s);
  ref_inv_subbytes(s);
  xor16(out, s, rk);
}

/* ================================================================== */
/* PCLMULQDQ reference: 64x64 -> 128 carryless product                  */
/* ================================================================== */
static void ref_clmul(u64 a, u64 b, u64* lo, u64* hi) {
  u64 l = 0, h = 0;
  for (int i = 0; i < 64; ++i) {
    if ((b >> i) & 1) {
      l ^= a << i;
      if (i) h ^= a >> (64 - i);
    }
  }
  *lo = l;
  *hi = h;
}
static void ref_pclmul(u8* dst, const u8* s1, const u8* s2, int sel) {
  u64 a = ld64(s1 + ((sel & 1) ? 8 : 0));
  u64 b = ld64(s2 + ((sel & 0x10) ? 8 : 0));
  u64 lo, hi;
  ref_clmul(a, b, &lo, &hi);
  st64(dst, lo);
  st64(dst + 8, hi);
}

/* ================================================================== */
/* SHA-NI references (Intel SDM pseudocode)                             */
/* ================================================================== */
/* All xmm operands are handled as 4 little-endian dwords: d[0] is
   bits [31:0], d[3] is bits [127:96]. */
static void ld4(const u8* p, u32* d) {
  for (int i = 0; i < 4; ++i) d[i] = ld32(p + 4 * i);
}
static void st4(u8* p, const u32* d) {
  for (int i = 0; i < 4; ++i) st32(p + 4 * i, d[i]);
}

static void ref_sha1msg1(u8* dst, const u8* s1, const u8* s2) {
  u32 a[4], b[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  u32 W0 = a[3], W1 = a[2], W2 = a[1], W3 = a[0];
  u32 W4 = b[3], W5 = b[2];
  r[3] = W2 ^ W0;
  r[2] = W3 ^ W1;
  r[1] = W4 ^ W2;
  r[0] = W5 ^ W3;
  st4(dst, r);
}
static void ref_sha1msg2(u8* dst, const u8* s1, const u8* s2) {
  u32 a[4], b[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  u32 W13 = b[2], W14 = b[1], W15 = b[0];
  u32 W16 = rotl32(a[3] ^ W13, 1);
  u32 W17 = rotl32(a[2] ^ W14, 1);
  u32 W18 = rotl32(a[1] ^ W15, 1);
  u32 W19 = rotl32(a[0] ^ W16, 1);
  r[3] = W16;
  r[2] = W17;
  r[1] = W18;
  r[0] = W19;
  st4(dst, r);
}
static void ref_sha1nexte(u8* dst, const u8* s1, const u8* s2) {
  u32 a[4], b[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  r[3] = b[3] + rotl32(a[3], 30);
  r[2] = b[2];
  r[1] = b[1];
  r[0] = b[0];
  st4(dst, r);
}
static void ref_sha1rnds4(u8* dst, const u8* s1, const u8* s2, int imm) {
  u32 a[4], w[4], r[4];
  ld4(s1, a);
  ld4(s2, w);
  u32 A = a[3], B = a[2], C = a[1], D = a[0];
  u32 K;
  switch (imm & 3) {
  case 0: K = 0x5a827999u; break;
  case 1: K = 0x6ed9eba1u; break;
  case 2: K = 0x8f1bbcdcu; break;
  default: K = 0xca62c1d6u; break;
  }
  u32 Wv[4] = {w[3], w[2], w[1], w[0]}; /* W0E, W1, W2, W3 */
  u32 E = 0;
  for (int i = 0; i < 4; ++i) {
    u32 f;
    switch (imm & 3) {
    case 0: f = (B & C) ^ (~B & D); break;
    case 2: f = (B & C) ^ (B & D) ^ (C & D); break;
    default: f = B ^ C ^ D; break;
    }
    u32 An = f + rotl32(A, 5) + Wv[i] + K + (i == 0 ? 0u : E);
    E = D;
    D = C;
    C = rotl32(B, 30);
    B = A;
    A = An;
  }
  r[3] = A;
  r[2] = B;
  r[1] = C;
  r[0] = D;
  st4(dst, r);
}

static u32 s256_sig0(u32 x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
static u32 s256_sig1(u32 x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }
static u32 s256_SIG0(u32 x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
static u32 s256_SIG1(u32 x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
static u32 s256_ch(u32 x, u32 y, u32 z) { return (x & y) ^ (~x & z); }
static u32 s256_maj(u32 x, u32 y, u32 z) { return (x & y) ^ (x & z) ^ (y & z); }

static void ref_sha256msg1(u8* dst, const u8* s1, const u8* s2) {
  u32 a[4], b[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  u32 W0 = a[0], W1 = a[1], W2 = a[2], W3 = a[3], W4 = b[0];
  r[3] = W3 + s256_sig0(W4);
  r[2] = W2 + s256_sig0(W3);
  r[1] = W1 + s256_sig0(W2);
  r[0] = W0 + s256_sig0(W1);
  st4(dst, r);
}
static void ref_sha256msg2(u8* dst, const u8* s1, const u8* s2) {
  u32 a[4], b[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  u32 W14 = b[2], W15 = b[3];
  u32 W16 = a[0] + s256_sig1(W14);
  u32 W17 = a[1] + s256_sig1(W15);
  u32 W18 = a[2] + s256_sig1(W16);
  u32 W19 = a[3] + s256_sig1(W17);
  r[0] = W16;
  r[1] = W17;
  r[2] = W18;
  r[3] = W19;
  st4(dst, r);
}
/* dst/src1 = CDGH, src2 = ABEF, wk = xmm0 (two dwords in lanes 0,1) */
static void ref_sha256rnds2(u8* dst, const u8* s1, const u8* s2, const u8* wk) {
  u32 a[4], b[4], k[4], r[4];
  ld4(s1, a);
  ld4(s2, b);
  ld4(wk, k);
  u32 A = b[3], B = b[2], C = a[3], D = a[2];
  u32 E = b[1], F = b[0], G = a[1], H = a[0];
  u32 WK[2] = {k[0], k[1]};
  for (int i = 0; i < 2; ++i) {
    u32 t = s256_ch(E, F, G) + s256_SIG1(E) + WK[i] + H;
    u32 An = t + s256_maj(A, B, C) + s256_SIG0(A);
    u32 En = t + D;
    H = G;
    G = F;
    F = E;
    E = En;
    D = C;
    C = B;
    B = A;
    A = An;
  }
  r[3] = A;
  r[2] = B;
  r[1] = E;
  r[0] = F;
  st4(dst, r);
}

/* ---- clean scalar SHA-1 / SHA-256 over whole messages ---- */
typedef struct {
  u32 h[5];
} sha1_ctx;
static void sha1_init(sha1_ctx* c) {
  c->h[0] = 0x67452301u;
  c->h[1] = 0xefcdab89u;
  c->h[2] = 0x98badcfeu;
  c->h[3] = 0x10325476u;
  c->h[4] = 0xc3d2e1f0u;
}
static void sha1_block(sha1_ctx* c, const u8* p) {
  u32 w[80];
  for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
  for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  u32 a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3], f = c->h[4];
  for (int i = 0; i < 80; ++i) {
    u32 fn, k;
    if (i < 20) {
      fn = (b & d) ^ (~b & e);
      k = 0x5a827999u;
    } else if (i < 40) {
      fn = b ^ d ^ e;
      k = 0x6ed9eba1u;
    } else if (i < 60) {
      fn = (b & d) ^ (b & e) ^ (d & e);
      k = 0x8f1bbcdcu;
    } else {
      fn = b ^ d ^ e;
      k = 0xca62c1d6u;
    }
    u32 t = rotl32(a, 5) + fn + f + k + w[i];
    f = e;
    e = d;
    d = rotl32(b, 30);
    b = a;
    a = t;
  }
  c->h[0] += a;
  c->h[1] += b;
  c->h[2] += d;
  c->h[3] += e;
  c->h[4] += f;
}
/* message must already be a multiple of 64 bytes (callers pad explicitly) */
static void sha1_scalar(const u8* msg, unsigned nblocks, u8* out20) {
  sha1_ctx c;
  sha1_init(&c);
  for (unsigned i = 0; i < nblocks; ++i) sha1_block(&c, msg + 64 * i);
  for (int i = 0; i < 5; ++i) st_be32(out20 + 4 * i, c.h[i]);
}

static const u32 K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

typedef struct {
  u32 h[8];
} sha256_ctx;
static void sha256_init(sha256_ctx* c) {
  static const u32 iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
  for (int i = 0; i < 8; ++i) c->h[i] = iv[i];
}
static void sha256_block(sha256_ctx* c, const u8* p) {
  u32 w[64];
  for (int i = 0; i < 16; ++i) w[i] = be32(p + 4 * i);
  for (int i = 16; i < 64; ++i) w[i] = s256_sig1(w[i - 2]) + w[i - 7] + s256_sig0(w[i - 15]) + w[i - 16];
  u32 a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3];
  u32 f = c->h[4], g = c->h[5], hh = c->h[6], ii = c->h[7];
  for (int i = 0; i < 64; ++i) {
    u32 t1 = ii + s256_SIG1(f) + s256_ch(f, g, hh) + K256[i] + w[i];
    u32 t2 = s256_SIG0(a) + s256_maj(a, b, d);
    ii = hh;
    hh = g;
    g = f;
    f = e + t1;
    e = d;
    d = b;
    b = a;
    a = t1 + t2;
  }
  c->h[0] += a;
  c->h[1] += b;
  c->h[2] += d;
  c->h[3] += e;
  c->h[4] += f;
  c->h[5] += g;
  c->h[6] += hh;
  c->h[7] += ii;
}
static void sha256_scalar(const u8* msg, unsigned nblocks, u8* out32) {
  sha256_ctx c;
  sha256_init(&c);
  for (unsigned i = 0; i < nblocks; ++i) sha256_block(&c, msg + 64 * i);
  for (int i = 0; i < 8; ++i) st_be32(out32 + 4 * i, c.h[i]);
}

/* ================================================================== */
/* CRC-32C (Castagnoli) reference, bit-reflected                        */
/* ================================================================== */
static u32 ref_crc32c_byte(u32 crc, u8 b) {
  crc ^= b;
  for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ (0x82f63b78u & (u32)(-(int)(crc & 1)));
  return crc;
}
static u32 ref_crc32c_bits(u32 crc, u64 v, int nbits) {
  for (int i = 0; i < nbits; i += 8) crc = ref_crc32c_byte(crc, (u8)(v >> i));
  return crc;
}

/* Compiler barrier: forces a reload of *p and prevents hoisting of the
   computation that consumes it out of a loop. */
#define OPAQUE_PTR(p)                                                                                                  \
  do {                                                                                                                 \
    __asm__ volatile("" : "+r"(p) : : "memory");                                                                       \
  } while (0)

#endif /* GUESTCRYPTO_COMMON_H */
