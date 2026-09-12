// SPDX-License-Identifier: MIT
/*
$info$
tags: bridge|test
desc: 32-bit embedder-eye-view smoke for libfexbridge (fexbridge_process_init32).
$end_info$

  Regression for the 2026-09-12 Portal 2 finding: after ANY segment-register
  reload (`pop es`, `pop ds`, `mov es,ax`) every string instruction wrote to
  EDI + 0xF3000000.  UpdatePrefixFromSegment rebuilds the cached base from
  the GDT qword with `Orlshr(i32Bit, ..., desc, 16)`, and the ppc64 backend
  shifted the 64-bit register, dragging descriptor byte 5 (the access byte,
  0xF3 for the bridge's flat data segment: Type=3 S=1 DPL=3 P=1) into bits
  24..31 of es_cached/ds_cached.  Ordinary `mov [edi]` never consults that
  base in 32-bit mode, so only rep stos/movs/lods/scas/cmps died.

  The Linux frontend cannot see this: set_thread_area writes a descriptor
  base only (byte 5 stays 0), so the 32Bit_ASM suite -- whose harness
  prepends `mov es,ax` to every test -- was green throughout.  Only the
  bridge installs fully-formed descriptors, so the regression lives here.

  Pure C, dlopens the bridge, same shape as BridgeSmoke.c.  Everything the
  guest touches lives below 4 GiB, as the 32-bit contract requires.
*/
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fexbridge.h"

static uint32_t (*p_abi_version)(void);
static int (*p_process_init32)(uint64_t);
static int (*p_thread_init)(void**);
static void (*p_thread_term)(void*);
static int (*p_run)(void*, void*);
static void (*p_invalidate)(uint64_t, uint64_t);
static int (*p_fault_is_jit)(const void*);
static int (*p_fault_unwind)(void*);

static int checks, failures;
static void check(int cond, const char* what) {
  checks++;
  if (!cond) failures++;
  fprintf(stderr, "  [%s] %s\n", cond ? " ok " : "FAIL", what);
}
static void check_eq(uint64_t got, uint64_t want, const char* what) {
  checks++;
  if (got != want) {
    failures++;
    fprintf(stderr, "  [FAIL] %s: got 0x%llx want 0x%llx\n", what, (unsigned long long)got, (unsigned long long)want);
  } else {
    fprintf(stderr, "  [ ok ] %s\n", what);
  }
}

/* One low arena, 64K-page friendly: works on both the 4K and 64K hosts. */
#define ARENA_BASE 0x30000000ULL
#define ARENA_SIZE 0x80000ULL
#define OFF_EXIT   0x00000ULL /* hlt page (bridge exit trampoline) */
#define OFF_CODE   0x10000ULL
#define OFF_STACK  0x20000ULL /* 0x20000..0x40000, top at 0x40000 */
#define OFF_DATA   0x40000ULL
#define OFF_SRC    0x50000ULL

static volatile int fault_seen;
static void segv_handler(int sig, siginfo_t* si, void* uc) {
  (void)sig;
  fault_seen++;
  fprintf(stderr, "  host SIGSEGV at guest data address 0x%llx\n", (unsigned long long)(uintptr_t)si->si_addr);
  if (p_fault_is_jit(uc) && p_fault_unwind(uc)) {
    /* not reached: fault_unwind longjmps into fexbridge_run */
  }
  fprintf(stderr, "  FATAL: SIGSEGV outside JIT or fault_unwind refused\n");
  _exit(3);
}

typedef struct {
  const char* name;
  const uint8_t* code;
  size_t len;
  int movs; /* 1: rep movsd from OFF_SRC, else rep stosd */
  uint32_t fill;
} Scenario;

/* Every scenario: set up EDI/ECX/EAX(/ESI), optionally reload a segment,
   run one string instruction over 4 dwords, hlt.  Absolute addresses are
   patched at emit time (the 0x11111111 / 0x22222222 placeholders). */
#define DST_PH 0x11, 0x11, 0x11, 0x11
#define SRC_PH 0x22, 0x22, 0x22, 0x22
static const uint8_t c_stos_plain[] = {
  0xBF, DST_PH,                   /* mov edi, DST */
  0xB9, 0x04, 0x00, 0x00, 0x00,   /* mov ecx, 4 */
  0xB8, 0x41, 0x41, 0x41, 0x41,   /* mov eax, 0x41414141 */
  0xF3, 0xAB,                     /* rep stosd */
  0xF4 };
static const uint8_t c_stos_pop_es[] = {
  0x06, 0x07,                     /* push es; pop es */
  0xBF, DST_PH, 0xB9, 0x04, 0x00, 0x00, 0x00, 0xB8, 0x42, 0x42, 0x42, 0x42,
  0xF3, 0xAB, 0xF4 };
static const uint8_t c_movs_pop_ds[] = {
  0x1E, 0x1F,                     /* push ds; pop ds */
  0xBF, DST_PH,
  0xBE, SRC_PH,                   /* mov esi, SRC */
  0xB9, 0x04, 0x00, 0x00, 0x00,
  0xF3, 0xA5,                     /* rep movsd */
  0xF4 };
static const uint8_t c_stos_mov_es_ss[] = {
  0x8C, 0xD0,                     /* mov eax, ss */
  0x8E, 0xC0,                     /* mov es, eax */
  0xBF, DST_PH, 0xB9, 0x04, 0x00, 0x00, 0x00, 0xB8, 0x44, 0x44, 0x44, 0x44,
  0xF3, 0xAB, 0xF4 };

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <libfexbridge.so>\n", argv[0]);
    return 2;
  }
  void* so = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!so) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
#define SYM(var, name)                            \
  do {                                            \
    var = (__typeof__(var))dlsym(so, name);       \
    if (!var) {                                   \
      fprintf(stderr, "dlsym %s failed\n", name); \
      return 2;                                   \
    }                                             \
  } while (0)
  SYM(p_abi_version, "fexbridge_abi_version");
  SYM(p_process_init32, "fexbridge_process_init32");
  SYM(p_thread_init, "fexbridge_thread_init");
  SYM(p_thread_term, "fexbridge_thread_term");
  SYM(p_run, "fexbridge_run");
  SYM(p_invalidate, "fexbridge_invalidate_code_range");
  SYM(p_fault_is_jit, "fexbridge_fault_is_jit");
  SYM(p_fault_unwind, "fexbridge_fault_unwind");

  fprintf(stderr, "== S1: 32-bit process init ==\n");
  check_eq(p_abi_version(), FEXBRIDGE_ABI_VERSION, "ABI version");
  uint8_t* arena = mmap((void*)ARENA_BASE, ARENA_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (arena != (void*)ARENA_BASE) {
    fprintf(stderr, "low arena at 0x%llx unavailable (%p)\n", ARENA_BASE, (void*)arena);
    return 2;
  }
  memset(arena + OFF_EXIT, 0xF4, 0x10000);
  check_eq((uint64_t)p_process_init32(ARENA_BASE + OFF_EXIT), 0, "fexbridge_process_init32");
  void* thread = NULL;
  check_eq((uint64_t)p_thread_init(&thread), 0, "fexbridge_thread_init");

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = segv_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, NULL);

  const Scenario S[] = {
    {"rep stosd, no reload",          c_stos_plain,     sizeof c_stos_plain,     0, 0x41414141},
    {"rep stosd after push es/pop es", c_stos_pop_es,    sizeof c_stos_pop_es,    0, 0x42424242},
    {"rep movsd after push ds/pop ds", c_movs_pop_ds,    sizeof c_movs_pop_ds,    1, 0x43434343},
    {"rep stosd after mov es,ss",      c_stos_mov_es_ss, sizeof c_stos_mov_es_ss, 0, 0x44444444},
  };
  const uint32_t dst = (uint32_t)(ARENA_BASE + OFF_DATA);
  const uint32_t src = (uint32_t)(ARENA_BASE + OFF_SRC);
  uint32_t* dstp = (uint32_t*)(arena + OFF_DATA);
  uint32_t* srcp = (uint32_t*)(arena + OFF_SRC);

  for (unsigned i = 0; i < sizeof S / sizeof S[0]; i++) {
    fprintf(stderr, "\n== S%u: %s ==\n", i + 2, S[i].name);
    uint8_t* code = arena + OFF_CODE;
    memcpy(code, S[i].code, S[i].len);
    for (size_t k = 0; k + 4 <= S[i].len; k++) {
      if (!memcmp(code + k, "\x11\x11\x11\x11", 4)) memcpy(code + k, &dst, 4);
      if (!memcmp(code + k, "\x22\x22\x22\x22", 4)) memcpy(code + k, &src, 4);
    }
    p_invalidate(ARENA_BASE + OFF_CODE, 0x10000);
    memset(dstp, 0, 64);
    for (int k = 0; k < 4; k++) srcp[k] = S[i].fill;

    FEXBRIDGE_AMD64_CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = ARENA_BASE + OFF_CODE;
    ctx.Rsp = ARENA_BASE + OFF_STACK + 0x20000 - 0x100;
    ctx.EFlags = 0x202;
    fault_seen = 0;
    int r = p_run(thread, &ctx);
    if (r == FEXBRIDGE_RUN_FAULT) {
      fprintf(stderr, "  RUN_FAULT at guest rip 0x%llx  edi=0x%llx esi=0x%llx  (segment base leak: fault addr - edi)\n",
              (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rdi, (unsigned long long)ctx.Rsi);
    }
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "run returned RUN_HLT");
    check_eq((uint64_t)fault_seen, 0, "no host fault");
    check_eq(ctx.Rdi, dst + 16, "EDI advanced by 16");
    check_eq(ctx.Rcx, 0, "ECX exhausted");
    int filled = 1;
    for (int k = 0; k < 4; k++) filled &= (dstp[k] == S[i].fill);
    check(filled && dstp[4] == 0, "destination holds exactly the 4 dwords");
    if (S[i].movs) check_eq(ctx.Rsi, src + 16, "ESI advanced by 16");
  }

  p_thread_term(thread);
  fprintf(stderr, "\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
