// SPDX-License-Identifier: MIT
/*
  BridgeSmoke — the embedder's-eye view of libfexbridge.so.

  Deliberately everything the probe is not:
    - plain C, no C++ runtime of its own
    - no FEXCore headers, no fastppcx86 internals
    - NOT linked against fexbridge: dlopen + dlsym only, so the exported
      C ABI is provably the whole story.

  Usage: BridgeSmoke <path-to-libfexbridge.so>

  What it proves beyond the probe:
    S6: a faulting guest thread is REUSABLE — fix the page, re-run, the
        faulting store retires (the Wine guard-page/lazy-commit shape).
    S7: RUN_EXITED hands back a resumable continuation.
    S8: fexbridge_run nests: the trap callback re-enters the guest.
    S10: the 64-bit GS base an embedder sets is what `movq %gs:0x30, %rax`
        reads (the Windows TEB self-pointer), with the negative control that
        the same guest faults when no base is set.
*/
#define _GNU_SOURCE
#include "fexbridge.h"

#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ---- dlsym'd surface ---------------------------------------------------- */
static uint32_t (*p_abi_version)(void);
static int (*p_process_init)(void);
static void (*p_set_trap_handler)(fexbridge_trap_fn, void*);
static int (*p_thread_init)(void**);
static void (*p_thread_term)(void*);
static int (*p_run)(void*, void*);
static int (*p_get_context)(void*, void*);
static int (*p_set_context)(void*, const void*);
static void (*p_invalidate)(uint64_t, uint64_t);
static int (*p_fault_is_jit)(const void*);
static int (*p_fault_unwind)(void*);
static void* (*p_current_thread)(void);
static int (*p_set_gs_base)(void*, uint64_t);
static int (*p_get_gs_base)(void*, uint64_t*);
static int (*p_set_fs_base)(void*, uint64_t);
static int (*p_get_fs_base)(void*, uint64_t*);

static int checks, failures;
static void check(int cond, const char* what) {
  ++checks;
  if (!cond) {
    ++failures;
    fprintf(stderr, "  FAIL: %s\n", what);
  } else {
    fprintf(stderr, "  ok:   %s\n", what);
  }
}
static void check_eq(uint64_t got, uint64_t want, const char* what) {
  ++checks;
  if (got != want) {
    ++failures;
    fprintf(stderr, "  FAIL: %s (got 0x%llx want 0x%llx)\n", what, (unsigned long long)got, (unsigned long long)want);
  } else {
    fprintf(stderr, "  ok:   %s = 0x%llx\n", what, (unsigned long long)got);
  }
}

/* ---- tiny x86-64 emitter ------------------------------------------------ */
static uint8_t* emit(uint8_t* p, const uint8_t* b, size_t n) {
  memcpy(p, b, n);
  return p + n;
}
#define E(p, ...)                        \
  do {                                   \
    uint8_t b_[] = {__VA_ARGS__};        \
    p = emit(p, b_, sizeof(b_));         \
  } while (0)

/* movabs r10, imm64 ; call r10 */
static uint8_t* emit_call_abs(uint8_t* p, uint64_t target) {
  E(p, 0x49, 0xBA);
  memcpy(p, &target, 8);
  p += 8;
  E(p, 0x41, 0xFF, 0xD2);
  return p;
}
/* mov [rsp+disp8], reg  (reg = 0..15, x86 numbering) */
static uint8_t* emit_store_rsp(uint8_t* p, unsigned reg, int8_t disp) {
  E(p, (uint8_t)(0x48 | (reg >= 8 ? 0x04 : 0x00)), 0x89, (uint8_t)(0x44 | ((reg & 7) << 3)), 0x24, (uint8_t)disp);
  return p;
}
/* mov reg, imm32 (zero-ext via REX.W C7) */
static uint8_t* emit_mov_imm32(uint8_t* p, unsigned reg, uint32_t imm) {
  E(p, (uint8_t)(0x48 | (reg >= 8 ? 0x01 : 0x00)), 0xC7, (uint8_t)(0xC0 | (reg & 7)));
  memcpy(p, &imm, 4);
  p += 4;
  return p;
}

static void* map_rwx(size_t sz) {
  void* p = mmap(NULL, sz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    perror("mmap");
    exit(2);
  }
  memset(p, 0xCC, sz);
  return p;
}
static void* map_rw(size_t sz) {
  void* p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    perror("mmap");
    exit(2);
  }
  return p;
}

/* ---- trap callback ------------------------------------------------------ */
enum { MODE_NONE, MODE_BOP, MODE_NESTED, MODE_GS };
static int trap_mode = MODE_NONE;
static uint64_t bop1, bop2, bop3, bop4;
static uint64_t bop_hits[4];
static uint64_t gs_bop_hits;
static uint64_t nested_code, nested_stack_top, nested_result;
static const uint64_t REGBASE = 0x7700000000ULL;

static int trap_cb(void* thread, void* vctx, void* user) {
  FEXBRIDGE_AMD64_CONTEXT* ctx = vctx;
  check(thread == p_current_thread(), "trap cb: thread handle matches TLS");
  check(user == (void*)0x1234, "trap cb: user pointer delivered");

  /* the bop protocol: pop the guest CALL's return address, resume there */
  uint64_t ret = *(uint64_t*)ctx->Rsp;

  if (trap_mode == MODE_BOP && ctx->Rip == bop1) {
    bop_hits[0]++;
    ctx->Rax = 0x1111 + ctx->Rax;
  } else if (trap_mode == MODE_BOP && ctx->Rip == bop2) {
    bop_hits[1]++;
    /* write the whole upper file; the guest stores it back for inspection */
    ctx->Rsi = REGBASE + 6;
    ctx->Rdi = REGBASE + 7;
    ctx->R8 = REGBASE + 8;
    ctx->R9 = REGBASE + 9;
    ctx->R10 = REGBASE + 10;
    ctx->R11 = REGBASE + 11;
    ctx->R12 = REGBASE + 12;
    ctx->R13 = REGBASE + 13;
    ctx->R14 = REGBASE + 14;
    /* R15 deliberately left: guest checks it survived from before the trap */
    ctx->Rax = 0xDEAD0000;
  } else if (trap_mode == MODE_BOP && ctx->Rip == bop3) {
    bop_hits[2]++;
    ctx->Rax = 0x7777;
    ctx->Rsp += 8;
    ctx->Rip = ret;
    return FEXBRIDGE_TRAP_EXIT; /* leave run() with the continuation parked */
  } else if (trap_mode == MODE_NESTED && ctx->Rip == bop4) {
    bop_hits[3]++;
    /* re-enter the guest from inside the trap: run a second snippet on this
       same guest thread, with our own CONTEXT save/restore (the wow64
       KiUserCallbackDispatcher shape). */
    FEXBRIDGE_AMD64_CONTEXT nctx;
    memset(&nctx, 0, sizeof(nctx));
    nctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    nctx.Rip = nested_code;
    nctx.Rsp = nested_stack_top;
    nctx.EFlags = 0x202;
    int r = p_run(thread, &nctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "nested run ended at HLT");
    nested_result = nctx.Rax;
    /* outer state lives in OUR ctx; hand the nested result to the guest */
    ctx->Rax = nested_result + 1;
  } else if (trap_mode == MODE_GS && ctx->Rip == bop1) {
    /* S10: touch nothing. The point is that a full CONTEXT round trip through
       the callback (which carries selectors, never bases) leaves the guest's
       64-bit GS base alone. */
    gs_bop_hits++;
  } else {
    check(0, "trap cb: unexpected RIP");
    return FEXBRIDGE_TRAP_EXIT;
  }
  ctx->Rsp += 8;
  ctx->Rip = ret;
  return FEXBRIDGE_TRAP_CONTINUE;
}

/* ---- S7 worker: adopt this pthread, run a tiny guest, tear down --------- */
struct warg {
  uint32_t val;
  uint64_t out;
};
static void* thread_worker(void* arg);

/* ---- S10 helper: a fresh guest thread reports its own GS base ----------- */
static uint64_t gs_worker_seen = ~0ULL;
static int gs_worker_rc = -1;
static void* gs_thread_worker(void* unused) {
  void* th = NULL;
  (void)unused;
  if (p_thread_init(&th) != 0) {
    return NULL;
  }
  gs_worker_rc = p_get_gs_base(th, &gs_worker_seen);
  p_thread_term(th);
  return NULL;
}

/* ---- S6: host SIGSEGV handler, the Wine shape --------------------------- */
static volatile int fault_seen, fault_was_jit;
static void segv_handler(int sig, siginfo_t* si, void* uc) {
  fault_seen++;
  fault_was_jit = p_fault_is_jit(uc);
  if (fault_was_jit && p_fault_unwind(uc)) {
    /* not reached: fault_unwind longjmps into fexbridge_run on success */
  }
  /* non-JIT fault in this test program is fatal */
  if (!fault_was_jit) {
    fprintf(stderr, "  FATAL: native SIGSEGV outside JIT\n");
    _exit(3);
  }
  fprintf(stderr, "  FATAL: fault_unwind refused a JIT fault\n");
  _exit(3);
}

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
#define SYM(var, name)                          \
  do {                                          \
    var = (__typeof__(var))dlsym(so, name);     \
    if (!var) {                                 \
      fprintf(stderr, "dlsym %s failed\n", name); \
      return 2;                                 \
    }                                           \
  } while (0)
  SYM(p_abi_version, "fexbridge_abi_version");
  SYM(p_process_init, "fexbridge_process_init");
  SYM(p_set_trap_handler, "fexbridge_set_trap_handler");
  SYM(p_thread_init, "fexbridge_thread_init");
  SYM(p_thread_term, "fexbridge_thread_term");
  SYM(p_run, "fexbridge_run");
  SYM(p_get_context, "fexbridge_get_context");
  SYM(p_set_context, "fexbridge_set_context");
  SYM(p_invalidate, "fexbridge_invalidate_code_range");
  SYM(p_fault_is_jit, "fexbridge_fault_is_jit");
  SYM(p_fault_unwind, "fexbridge_fault_unwind");
  SYM(p_current_thread, "fexbridge_current_thread");
  SYM(p_set_gs_base, "fexbridge_set_gs_base");
  SYM(p_get_gs_base, "fexbridge_get_gs_base");
  SYM(p_set_fs_base, "fexbridge_set_fs_base");
  SYM(p_get_fs_base, "fexbridge_get_fs_base");

  fprintf(stderr, "== S1: dlopen'd surface ==\n");
  check_eq(p_abi_version(), FEXBRIDGE_ABI_VERSION, "ABI version");
  check_eq((uint64_t)(uintptr_t)p_current_thread(), 0, "no thread bound yet");

  fprintf(stderr, "\n== S2: process + thread init ==\n");
  check_eq((uint64_t)p_process_init(), 0, "fexbridge_process_init");
  check_eq((uint64_t)p_process_init(), 0, "process_init idempotent");
  void* thread = NULL;
  check_eq((uint64_t)p_thread_init(&thread), 0, "fexbridge_thread_init");
  check(thread != NULL, "thread handle non-NULL");
  check(p_current_thread() == thread, "current_thread == handle");

  /* ---- S3: plain run to HLT -------------------------------------------- */
  fprintf(stderr, "\n== S3: run to HLT ==\n");
  uint8_t* code = map_rwx(0x10000);
  uint8_t* stack = map_rw(0x10000);
  uint64_t stack_top = (uint64_t)stack + 0x8000;
  {
    uint8_t* p = code;
    E(p, 0x48, 0xB8); /* movabs rax, imm64 */
    uint64_t imm = 0x1122334455667788ULL;
    memcpy(p, &imm, 8);
    p += 8;
    E(p, 0x48, 0x83, 0xC0, 0x01); /* add rax, 1 */
    E(p, 0xF4);                   /* hlt */
  }
  p_invalidate((uint64_t)code, 0x10000);

  FEXBRIDGE_AMD64_CONTEXT ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  ctx.Rip = (uint64_t)code;
  ctx.Rsp = stack_top;
  ctx.EFlags = 0x202;
  int r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "run returned RUN_HLT");
  check_eq(ctx.Rax, 0x1122334455667789ULL, "guest RAX visible in returned CONTEXT");
  check_eq(ctx.Rsp, stack_top, "RSP unchanged");
  check((ctx.ContextFlags & FEXBRIDGE_CTX_FLOATING_POINT) != 0, "returned CONTEXT is full");

  /* ---- S4: bop protocol + full register writeback + exit/resume --------- */
  fprintf(stderr, "\n== S4: bop protocol, register writeback, RUN_EXITED continuation ==\n");
  uint8_t* boppage = map_rwx(0x1000);
  boppage[0] = 0x0F;
  boppage[1] = 0x05;
  boppage[2] = 0x0F;
  boppage[3] = 0x05;
  boppage[4] = 0x0F;
  boppage[5] = 0x05;
  p_invalidate((uint64_t)boppage, 0x1000);
  bop1 = (uint64_t)boppage;
  bop2 = bop1 + 2;
  bop3 = bop1 + 4;

  uint8_t* code2 = map_rwx(0x10000);
  uint64_t after_bop3;
  {
    uint8_t* p = code2;
    p = emit_mov_imm32(p, 0, 0x42);       /* mov rax, 0x42 */
    p = emit_call_abs(p, bop1);           /* -> 0x1111+0x42 */
    E(p, 0x49, 0x89, 0xC7);               /* mov r15, rax */
    p = emit_call_abs(p, bop2);           /* handler writes rsi/rdi/r8-r14 */
    p = emit_store_rsp(p, 6, 0x00);       /* rsi */
    p = emit_store_rsp(p, 7, 0x08);       /* rdi */
    p = emit_store_rsp(p, 8, 0x10);
    p = emit_store_rsp(p, 9, 0x18);
    p = emit_store_rsp(p, 10, 0x20);
    p = emit_store_rsp(p, 11, 0x28);
    p = emit_store_rsp(p, 12, 0x30);
    p = emit_store_rsp(p, 13, 0x38);
    p = emit_store_rsp(p, 14, 0x40);
    p = emit_store_rsp(p, 0, 0x48);       /* rax: handler return value */
    p = emit_call_abs(p, bop3);           /* handler exits the run here */
    after_bop3 = (uint64_t)(p - code2) + (uint64_t)code2;
    p = emit_mov_imm32(p, 3, 0xF00D);     /* mov rbx, 0xF00D (post-resume) */
    E(p, 0xF4);                           /* hlt */
  }
  p_invalidate((uint64_t)code2, 0x10000);

  trap_mode = MODE_BOP;
  p_set_trap_handler(trap_cb, (void*)0x1234);
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  ctx.Rip = (uint64_t)code2;
  ctx.Rsp = stack_top;
  ctx.EFlags = 0x202;
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_EXITED, "run returned RUN_EXITED at bop3");
  check_eq(bop_hits[0], 1, "bop1 dispatched by RIP");
  check_eq(bop_hits[1], 1, "bop2 dispatched by RIP");
  check_eq(bop_hits[2], 1, "bop3 dispatched by RIP");
  check_eq(ctx.Rip, after_bop3, "RUN_EXITED context Rip == continuation after CALL");
  check_eq(ctx.Rax, 0x7777, "RUN_EXITED context carries callback's RAX");
  check_eq(ctx.Rsp, stack_top, "stack balanced at exit");

  uint64_t* slots = (uint64_t*)stack_top;
  check_eq(slots[0], REGBASE + 6, "handler-written RSI reached the guest");
  check_eq(slots[1], REGBASE + 7, "handler-written RDI reached the guest");
  check_eq(slots[2], REGBASE + 8, "handler-written R8 reached the guest");
  check_eq(slots[3], REGBASE + 9, "handler-written R9 reached the guest");
  check_eq(slots[4], REGBASE + 10, "handler-written R10 reached the guest");
  check_eq(slots[5], REGBASE + 11, "handler-written R11 reached the guest");
  check_eq(slots[6], REGBASE + 12, "handler-written R12 reached the guest");
  check_eq(slots[7], REGBASE + 13, "handler-written R13 reached the guest");
  check_eq(slots[8], REGBASE + 14, "handler-written R14 reached the guest");
  check_eq(slots[9], 0xDEAD0000, "handler RAX reached the guest");
  check_eq(ctx.R15, 0x1111 + 0x42, "R15 survived across bop2 untouched");

  /* resume the parked continuation: same ctx straight back in */
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "continuation resumed to HLT");
  check_eq(ctx.Rbx, 0xF00D, "post-resume code executed");
  check_eq(ctx.R15, 0x1111 + 0x42, "register file survived exit/resume");

  /* ---- S5: get/set context between runs --------------------------------- */
  fprintf(stderr, "\n== S5: get/set context between runs ==\n");
  FEXBRIDGE_AMD64_CONTEXT c2;
  memset(&c2, 0, sizeof(c2));
  c2.ContextFlags = FEXBRIDGE_CTX_INTEGER;
  c2.Rax = 0x1000;
  check_eq((uint64_t)p_set_context(thread, &c2), 0, "set_context");
  memset(&c2, 0, sizeof(c2));
  c2.ContextFlags = FEXBRIDGE_CTX_INTEGER;
  check_eq((uint64_t)p_get_context(thread, &c2), 0, "get_context");
  check_eq(c2.Rax, 0x1000, "set/get round trip");

  uint8_t* code3 = map_rwx(0x1000);
  {
    uint8_t* p = code3;
    E(p, 0x48, 0x83, 0xC0, 0x05); /* add rax, 5 */
    E(p, 0xF4);
  }
  p_invalidate((uint64_t)code3, 0x1000);
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL; /* only steer rip/rsp; rax comes from set_context */
  ctx.Rip = (uint64_t)code3;
  ctx.Rsp = stack_top;
  ctx.EFlags = 0x202;
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "steered run to HLT");
  check_eq(ctx.Rax, 0x1005, "set_context state was live in the guest");

  /* ---- S6: fault -> reconstruct -> FIX -> re-run ------------------------- */
  fprintf(stderr, "\n== S6: host fault in JIT -> RUN_FAULT -> fix page -> resume ==\n");
  void* badpage = mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  uint64_t bad = (uint64_t)badpage;

  uint8_t* code4 = map_rwx(0x1000);
  uint64_t store_addr;
  {
    uint8_t* p = code4;
    p = emit_mov_imm32(p, 0, 0x5A5A); /* mov rax, 0x5A5A */
    E(p, 0x48, 0xBB);                 /* movabs rbx, bad */
    memcpy(p, &bad, 8);
    p += 8;
    store_addr = (uint64_t)p;
    E(p, 0x48, 0x89, 0x03);           /* mov [rbx], rax  <- faults */
    p = emit_mov_imm32(p, 1, 0x77);   /* mov rcx, 0x77 (post-fix) */
    E(p, 0xF4);
  }
  p_invalidate((uint64_t)code4, 0x1000);

  struct sigaction sa, old;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = segv_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSEGV, &sa, &old);

  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  ctx.Rip = (uint64_t)code4;
  ctx.Rsp = stack_top;
  ctx.EFlags = 0x202;
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_FAULT, "run returned RUN_FAULT");
  check_eq((uint64_t)fault_seen, 1, "exactly one host SIGSEGV");
  check_eq((uint64_t)fault_was_jit, 1, "fault_is_jit recognised JIT code");
  check_eq(ctx.Rip, store_addr, "fault CONTEXT.Rip == faulting guest instruction");
  check_eq(ctx.Rax, 0x5A5A, "fault CONTEXT.Rax reconstructed from host regs");
  check_eq(ctx.Rbx, bad, "fault CONTEXT.Rbx reconstructed from host regs");
  check_eq(ctx.Rsp, stack_top, "fault CONTEXT.Rsp");
  check((ctx.EFlags & 0x2) != 0, "fault CONTEXT.EFlags reconstructed (bit1)");

  /* Fix the page like Wine commits a guard page, then resume THE SAME
     thread at THE SAME instruction. */
  mprotect(badpage, 0x1000, PROT_READ | PROT_WRITE);
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "faulted thread re-ran to HLT");
  check_eq(*(uint64_t*)badpage, 0x5A5A, "faulting store retired after the fix");
  check_eq(ctx.Rcx, 0x77, "post-fault code executed");
  sigaction(SIGSEGV, &old, NULL);

  /* ---- S8: nested run from inside the trap callback ---------------------- */
  fprintf(stderr, "\n== S8: nested fexbridge_run from the trap callback ==\n");
  bop4 = bop1 + 4; /* reuse bop3 site under MODE_NESTED dispatch */
  uint8_t* ncode = map_rwx(0x1000);
  {
    uint8_t* p = ncode;
    p = emit_mov_imm32(p, 0, 0x99); /* mov rax, 0x99 */
    E(p, 0xF4);
  }
  p_invalidate((uint64_t)ncode, 0x1000);
  nested_code = (uint64_t)ncode;
  uint8_t* nstack = map_rw(0x10000);
  nested_stack_top = (uint64_t)nstack + 0x8000;

  uint8_t* code5 = map_rwx(0x1000);
  {
    uint8_t* p = code5;
    p = emit_call_abs(p, bop4); /* callback runs the nested snippet */
    E(p, 0x48, 0x89, 0xC3);     /* mov rbx, rax */
    E(p, 0xF4);
  }
  p_invalidate((uint64_t)code5, 0x1000);

  trap_mode = MODE_NESTED;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  ctx.Rip = (uint64_t)code5;
  ctx.Rsp = stack_top;
  ctx.EFlags = 0x202;
  r = p_run(thread, &ctx);
  check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "outer run completed");
  check_eq(bop_hits[3], 1, "nested-mode bop dispatched");
  check_eq(nested_result, 0x99, "nested run produced its result");
  check_eq(ctx.Rbx, 0x99 + 1, "nested result handed back to the outer guest");

  /* ---- S10: 64-bit GS/FS bases (the Windows TEB) ------------------------- */
  fprintf(stderr, "\n== S10: 64-bit GS base — movq %%gs:0x30 reads what the embedder set ==\n");
  {
    /* A stand-in TEB, laid out where a Windows x86-64 guest looks: the self
       pointer at +0x30, something identifiable at +0x08. */
    uint8_t* teb = map_rw(0x1000);
    const uint64_t teb_base = (uint64_t)teb;
    *(uint64_t*)(teb + 0x30) = teb_base; /* NtCurrentTeb()->Self */
    *(uint64_t*)(teb + 0x08) = 0xB0B0CAFEULL;

    uint8_t* fsarea = map_rw(0x1000);
    const uint64_t fs_base = (uint64_t)fsarea;
    *(uint64_t*)(fsarea + 0x10) = 0xF5F5BEEFULL;

    /* mov rax, gs:[0x30] ; mov rbx, gs:[0x08] ; hlt */
    uint8_t* gscode = map_rwx(0x1000);
    {
      uint8_t* p = gscode;
      E(p, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);
      E(p, 0x65, 0x48, 0x8B, 0x1C, 0x25, 0x08, 0x00, 0x00, 0x00);
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)gscode, 0x1000);

    /* mov rcx, fs:[0x10] ; hlt */
    uint8_t* fscode = map_rwx(0x1000);
    {
      uint8_t* p = fscode;
      E(p, 0x64, 0x48, 0x8B, 0x0C, 0x25, 0x10, 0x00, 0x00, 0x00);
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)fscode, 0x1000);

    /* call bop1 ; mov rax, gs:[0x30] ; hlt — GS across a trap round trip */
    uint8_t* gstrapcode = map_rwx(0x1000);
    {
      uint8_t* p = gstrapcode;
      p = emit_call_abs(p, bop1);
      E(p, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00);
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)gstrapcode, 0x1000);

    uint64_t base = ~0ULL;
    check_eq((uint64_t)p_get_gs_base(thread, &base), 0, "get_gs_base");
    check_eq(base, 0, "GS base starts at 0 on a fresh thread");

    /* NEGATIVE CONTROL: with no base set the guest dereferences absolute 0x30
       and faults — this is exactly the c0000005 a Windows PE takes today. */
    sigaction(SIGSEGV, &sa, &old);
    fault_seen = 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)gscode;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_FAULT, "negative control: %gs access faults with no base");
    check_eq((uint64_t)fault_seen, 1, "negative control: exactly one host SIGSEGV");
    check_eq(ctx.Rip, (uint64_t)gscode, "negative control: fault Rip == the %gs instruction");

    /* Now install the base the way Wine will, and re-run the SAME thread from
       the SAME instruction. */
    check_eq((uint64_t)p_set_gs_base(thread, teb_base), 0, "set_gs_base");
    base = ~0ULL;
    check_eq((uint64_t)p_get_gs_base(thread, &base), 0, "get_gs_base after set");
    check_eq(base, teb_base, "GS base round trips");

    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "guest ran to HLT with a GS base");
    check_eq(ctx.Rax, teb_base, "movq %gs:0x30 read the TEB self-pointer");
    check_eq(ctx.Rbx, 0xB0B0CAFEULL, "movq %gs:0x08 read through the same base");

    /* The base is guest state, not a per-run argument. */
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)gscode;
    ctx.Rsp = stack_top;
    ctx.Rax = 0;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "second run to HLT");
    check_eq(ctx.Rax, teb_base, "GS base persists across fexbridge_run");

    /* ...and across a trap callback round trip, which marshals SEGMENTS. */
    trap_mode = MODE_GS;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)gstrapcode;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    trap_mode = MODE_NONE;
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "trap-then-%gs run to HLT");
    check_eq(gs_bop_hits, 1, "MODE_GS bop dispatched");
    check_eq(ctx.Rax, teb_base, "GS base survives a trap CONTEXT round trip");

    /* FS is the same mechanism, independent register. */
    check_eq((uint64_t)p_set_fs_base(thread, fs_base), 0, "set_fs_base");
    base = ~0ULL;
    check_eq((uint64_t)p_get_fs_base(thread, &base), 0, "get_fs_base");
    check_eq(base, fs_base, "FS base round trips");
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)fscode;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "%fs run to HLT");
    check_eq(ctx.Rcx, 0xF5F5BEEFULL, "movq %fs:0x10 read through the FS base");
    base = ~0ULL;
    p_get_gs_base(thread, &base);
    check_eq(base, teb_base, "setting FS did not disturb GS");
    sigaction(SIGSEGV, &old, NULL);

    /* Per-thread, not per-process: a second guest thread starts at 0 while
       this one holds the TEB. Run sequentially so the check counters stay
       single-threaded. */
    {
      pthread_t t;
      pthread_create(&t, NULL, gs_thread_worker, NULL);
      pthread_join(t, NULL);
      check_eq((uint64_t)gs_worker_rc, 0, "fresh thread: get_gs_base");
      check_eq(gs_worker_seen, 0, "GS base is per-thread, not inherited");
    }

    check(p_set_gs_base(NULL, 1) != 0, "set_gs_base rejects a NULL thread");
    check(p_get_gs_base(thread, NULL) != 0, "get_gs_base rejects a NULL out");
  }

  /* ---- S7: adopted threads, concurrently --------------------------------- */
  fprintf(stderr, "\n== S7: two adopted pthreads run guests concurrently ==\n");
  trap_mode = MODE_NONE;
  {
    struct warg a1 = {0x1111, 0}, a2 = {0x2222, 0};
    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_worker, &a1);
    pthread_create(&t2, NULL, thread_worker, &a2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    check_eq(a1.out, 0x1111, "thread 1 result");
    check_eq(a2.out, 0x2222, "thread 2 result");
  }

  fprintf(stderr, "\n== teardown ==\n");
  p_thread_term(thread);
  check(p_current_thread() == NULL, "thread unbound after term");

  /* ---- S9: one-shot fexbridge_run_entry (Wine interim ABI) --------------- */
  fprintf(stderr, "\n== S9: fexbridge_run_entry one-shot ==\n");
  {
    int (*p_run_entry)(void*, void*, unsigned long long*, char*, unsigned int);
    SYM(p_run_entry, "fexbridge_run_entry");
    uint8_t* fn = map_rwx(0x1000);
    uint8_t* p = fn;
    E(p, 0x48, 0x89, 0xC8);       /* mov rax, rcx  (MS-x64 arg) */
    E(p, 0x48, 0x83, 0xC0, 0x03); /* add rax, 3 */
    E(p, 0xC3);                   /* ret -> HLT trampoline */
    p_invalidate((uint64_t)fn, 0x1000);
    unsigned long long rax = 0;
    char errbuf[128] = "";
    int rc = p_run_entry(fn, (void*)39, &rax, errbuf, sizeof(errbuf));
    check_eq((uint64_t)rc, 0, "run_entry returned 0");
    check_eq(rax, 42, "run_entry: guest RAX out");
    check(p_current_thread() == NULL, "run_entry cleaned up its transient thread");
    if (rc) {
      fprintf(stderr, "  err: %s\n", errbuf);
    }
  }

  fprintf(stderr, "\n===== %d checks, %d failures =====\n", checks, failures);
  return failures ? 1 : 0;
}

static void* thread_worker(void* argv) {
  struct warg* a = argv;
  void* th = NULL;
  if (p_thread_init(&th) != 0) {
    return NULL;
  }
  uint8_t* code = map_rwx(0x1000);
  uint8_t* stack = map_rw(0x10000);
  uint8_t* p = code;
  p = emit_mov_imm32(p, 0, a->val); /* mov rax, val */
  E(p, 0xF4);
  p_invalidate((uint64_t)code, 0x1000);

  FEXBRIDGE_AMD64_CONTEXT c;
  memset(&c, 0, sizeof(c));
  c.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
  c.Rip = (uint64_t)code;
  c.Rsp = (uint64_t)stack + 0x8000;
  c.EFlags = 0x202;
  if (p_run(th, &c) == FEXBRIDGE_RUN_HLT) {
    a->out = c.Rax;
  }
  p_thread_term(th);
  return NULL;
}
