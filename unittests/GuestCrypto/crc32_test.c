// SSE4.2 CRC32 (CRC-32C / Castagnoli) conformance against a bitwise
// reflected reference: all operand widths (r/m8, r/m16, r/m32, and r/m64 in
// 64-bit builds), incremental chaining across a buffer, memory-operand forms,
// the 8-bit high-byte register encodings, and known answers.
#include <immintrin.h>
#include "crypto_common.h"

static u32 crc8(u32 c, u8 v) { return (u32)__builtin_ia32_crc32qi(c, v); }
static u32 crc16(u32 c, u16 v) { return (u32)__builtin_ia32_crc32hi(c, v); }
static u32 crc32w(u32 c, u32 v) { return (u32)__builtin_ia32_crc32si(c, v); }
#ifdef __x86_64__
static u32 crc64(u32 c, u64 v) { return (u32)__builtin_ia32_crc32di((unsigned long long)c, v); }
#endif

static void test_widths(void) {
  rng_t r;
  rng_seed(&r, 0xc12c1111u);
  int f8 = 0, f16 = 0, f32 = 0, f64 = 0;
  for (int i = 0; i < 4096; ++i) {
    u32 seed = rng_u32(&r);
    u32 v32 = rng_u32(&r);
    u64 v64 = ((u64)rng_u32(&r) << 32) | rng_u32(&r);
    if (crc8(seed, (u8)v32) != ref_crc32c_bits(seed, v32, 8)) ++f8;
    if (crc16(seed, (u16)v32) != ref_crc32c_bits(seed, v32, 16)) ++f16;
    if (crc32w(seed, v32) != ref_crc32c_bits(seed, v32, 32)) ++f32;
#ifdef __x86_64__
    if (crc64(seed, v64) != ref_crc32c_bits(seed, v64, 64)) ++f64;
#else
    (void)v64;
#endif
  }
  report("crc32.width.r8", f8 == 0);
  report("crc32.width.r16", f16 == 0);
  report("crc32.width.r32", f32 == 0);
#ifdef __x86_64__
  report("crc32.width.r64", f64 == 0);
#endif
}

__attribute__((aligned(16))) static u8 buf[4096];

static void test_chaining(void) {
  rng_t r;
  rng_seed(&r, 0x5eedc12cu);
  rng_fill(&r, buf, sizeof buf);

  /* byte-at-a-time */
  u32 c = 0xffffffffu, want = 0xffffffffu;
  for (unsigned i = 0; i < sizeof buf; ++i) {
    c = crc8(c, buf[i]);
    want = ref_crc32c_byte(want, buf[i]);
  }
  report("crc32.chain.bytes", c == want);

  /* dword-at-a-time over the same buffer must agree */
  u32 c32 = 0xffffffffu;
  for (unsigned i = 0; i < sizeof buf; i += 4) c32 = crc32w(c32, ld32(buf + i));
  report("crc32.chain.dwords_match_bytes", c32 == want);

#ifdef __x86_64__
  u32 c64 = 0xffffffffu;
  for (unsigned i = 0; i < sizeof buf; i += 8) c64 = crc64(c64, ld64(buf + i));
  report("crc32.chain.qwords_match_bytes", c64 == want);
#endif

  /* mixed widths: 1 byte, 1 word, 1 dword, repeat -> same answer */
  u32 cm = 0xffffffffu;
  unsigned i = 0;
  while (i + 7 <= sizeof buf) {
    cm = crc8(cm, buf[i]);
    cm = crc16(cm, (u16)(buf[i + 1] | ((u16)buf[i + 2] << 8)));
    cm = crc32w(cm, ld32(buf + i + 3));
    i += 7;
  }
  u32 wm = 0xffffffffu;
  for (unsigned j = 0; j < i; ++j) wm = ref_crc32c_byte(wm, buf[j]);
  report("crc32.chain.mixed_widths", cm == wm);
}

static void test_known_answers(void) {
  /* CRC-32C("123456789") = 0xE3069283 (final xor-out applied) */
  const u8 msg[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  u32 c = 0xffffffffu;
  for (int i = 0; i < 9; ++i) c = crc8(c, msg[i]);
  report("crc32.kat.check123456789", (c ^ 0xffffffffu) == 0xe3069283u);

  /* crc32 with a zero accumulator and zero input must stay zero */
  report("crc32.kat.zero_identity", crc32w(0, 0) == 0);

  /* all-ones dword from an all-ones accumulator, versus reference */
  report("crc32.kat.ones", crc32w(0xffffffffu, 0xffffffffu) == ref_crc32c_bits(0xffffffffu, 0xffffffffu, 32));
}

static void test_operand_forms(void) {
  rng_t r;
  rng_seed(&r, 0x0be1a4d1u);
  int fails = 0;
  for (int i = 0; i < 1024; ++i) {
    u32 seed = rng_u32(&r);
    u32 v = rng_u32(&r);
    u32 got;
    /* memory operand forms */
    st32(buf, v);
    got = seed;
    __asm__ volatile("crc32b %1, %0" : "+r"(got) : "m"(buf[0]) : "cc");
    if (got != ref_crc32c_bits(seed, v, 8)) ++fails;
    got = seed;
    __asm__ volatile("crc32w %1, %0" : "+r"(got) : "m"(*(const u16*)buf) : "cc");
    if (got != ref_crc32c_bits(seed, v, 16)) ++fails;
    got = seed;
    __asm__ volatile("crc32l %1, %0" : "+r"(got) : "m"(*(const u32*)buf) : "cc");
    if (got != ref_crc32c_bits(seed, v, 32)) ++fails;
    /* high-byte source register (crc32 %ah, %eax style) */
    got = seed;
    {
      u32 src = v;
      /* dest pinned to eax: %ch cannot be encoded alongside a REX prefix */
      __asm__ volatile("crc32b %%ch, %0" : "+a"(got) : "c"(src) : "cc");
      if (got != ref_crc32c_bits(seed, v >> 8, 8)) ++fails;
    }
  }
  report("crc32.operand_forms", fails == 0);
}

void guest_main(long* sp) {
  (void)sp;
  puts_raw("== GuestCrypto: CRC32 (SSE4.2) ==\n");
  test_widths();
  test_chaining();
  test_known_answers();
  test_operand_forms();
  puts_raw("crc32: checks=");
  put_dec((u64)g_checks);
  puts_raw(" fails=");
  put_dec((u64)g_fails);
  puts_raw("\n");
  sys_exit(g_fails);
}
