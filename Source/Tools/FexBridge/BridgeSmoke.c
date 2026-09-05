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
#include <time.h>
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
static uint32_t (*p_declare_trap_ctx)(uint32_t);
static int (*p_ctx_materialize)(void*, void*, uint32_t);
static void (*p_set_trap_view_handler)(fexbridge_trap_view_fn, void*);
static int (*p_view_pull)(void*, void*, uint32_t);
static int (*p_view_push)(void*, const void*, uint32_t);
static int (*p_register_ec)(uint64_t, fexbridge_ec_fn, void*);
static int (*p_register_ec2)(const uint64_t*, const void* const*, uint32_t, fexbridge_ec_fn);
static int (*p_unregister_ec)(uint64_t, uint64_t);

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
enum { MODE_NONE, MODE_BOP, MODE_NESTED, MODE_GS, MODE_LAZY, MODE_VIEWKILL, MODE_ECSTUBS };
static int trap_mode = MODE_NONE;
static uint64_t bop1, bop2, bop3, bop4;
static uint64_t bop_hits[4];
static uint64_t gs_bop_hits;
static uint64_t nested_code, nested_stack_top, nested_result;
static const uint64_t REGBASE = 0x7700000000ULL;
static int lazy_poison_phase;   /* S11: expect poison bytes before materialize */
static uint64_t lazy_hits[2];
static int viewkill_ctx_hits;   /* S12: CONTEXT-handler hits under the veto */
static uint64_t ec_stub0, ec_stub1; /* S14: registered stub / trap sibling */
static uint64_t ec_trap_hits[2];    /* trap landings on stub0 / stub1 */

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
  } else if (trap_mode == MODE_LAZY && ctx->Rip == bop1) {
    /* S11 hop A: the materialize-and-modify path. */
    lazy_hits[0]++;
    check((ctx->ContextFlags & 0x100u) != 0, "lazy ctx carries LAZY_EFLAGS");
    check((ctx->ContextFlags & 0x200u) != 0, "lazy ctx carries LAZY_FLOAT");
    if (lazy_poison_phase) {
      check_eq(ctx->EFlags, 0xDEADF1A6u, "poison: unmaterialized EFlags is the pattern");
      check_eq(ctx->FltSave.XmmRegisters[0].Low, 0xDDDDDDDDDDDDDDDDULL, "poison: unmaterialized XMM0 is the pattern");
    }
    check_eq((uint64_t)p_ctx_materialize(thread, ctx, FEXBRIDGE_CTX_CONTROL), 0, "materialize(CONTROL)");
    check((ctx->ContextFlags & 0x100u) == 0, "LAZY_EFLAGS cleared by materialize");
    check((ctx->ContextFlags & 0x200u) != 0, "LAZY_FLOAT untouched by CONTROL materialize");
    check((ctx->EFlags & 0x1) != 0, "materialized EFlags: guest stc's CF");
    check((ctx->EFlags & 0x40) != 0, "materialized EFlags: guest sub's ZF");
    check_eq((uint64_t)p_ctx_materialize(thread, ctx, FEXBRIDGE_CTX_FLOATING_POINT), 0, "materialize(FLOATING_POINT)");
    check((ctx->ContextFlags & 0x200u) == 0, "LAZY_FLOAT cleared by materialize");
    check_eq(ctx->FltSave.XmmRegisters[0].Low, 0xA1B2C3D4E5F60718ULL, "materialized XMM0 is the guest's");
    uint32_t before = ctx->EFlags;
    check_eq((uint64_t)p_ctx_materialize(thread, ctx, FEXBRIDGE_CTX_CONTROL), 0, "materialize idempotent rc");
    check_eq(ctx->EFlags, before, "materialize idempotent value");
    /* modify both groups; the resume must apply exactly these */
    ctx->EFlags &= ~0x1u; /* clear CF */
    ctx->FltSave.XmmRegisters[0].Low = 0x1122334455667788ULL;
    ctx->FltSave.XmmRegisters[0].High = 0;
  } else if (trap_mode == MODE_LAZY && ctx->Rip == bop2) {
    /* S11 hop B: touch nothing lazy -- the guest's EFLAGS and XMM must
       survive the hop with no materialize and no write-back at all. */
    lazy_hits[1]++;
    ctx->Rax = 0x77;
  } else if (trap_mode == MODE_ECSTUBS && (ctx->Rip == ec_stub0 + 3 || ctx->Rip == ec_stub1 + 3)) {
    /* S14: a real `mov r10,rcx ; syscall` stub DECODED and TRAPPED -- the
       un-registered path.  Rip is stub+3 (the syscall), and the stub's
       rescue has run: R10 carries what the caller put in RCX. */
    if (ctx->Rip == ec_stub0 + 3) {
      ec_trap_hits[0]++;
      ctx->Rax = 0xFA11; /* the fallback leg's marker */
    } else {
      ec_trap_hits[1]++;
      check_eq(ctx->R10, 0x5678, "ec sibling stub: R10 rescued arg0");
      ctx->Rax = 0x51B;
    }
  } else if (trap_mode == MODE_VIEWKILL && ctx->Rip == bop1) {
    /* S12 kill switch: with the view registration vetoed by
       FEXBRIDGE_EAGER_CTX=1, traps must land HERE, on the CONTEXT
       protocol. */
    viewkill_ctx_hits++;
    ctx->Rax = 0xEA6E4;
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

/* ---- S12: the zero-copy trap view (ABI 6) ------------------------------- */
static int view_mode;
static uint64_t view_hits[3];
static uint64_t view_nested_result;

static int view_cb(void* thread, FEXBRIDGE_TRAP_VIEW* v, void* user) {
  uint64_t* g = v->gregs;
  check(thread == p_current_thread(), "view cb: thread handle matches TLS");
  check(user == (void*)0x5678, "view cb: user pointer delivered");

  if (view_mode == 1 && *v->rip == bop1) {
    /* plain read+write through the live file */
    view_hits[0]++;
    check_eq(g[FEXBRIDGE_GREG_RAX], 0x42, "view: guest RAX readable through gregs");
    g[FEXBRIDGE_GREG_RAX] = 0x4242;
  } else if (view_mode == 2 && *v->rip == bop1) {
    /* pull sees live truth; push applies edits (the S11 lazy-hop shape,
       re-proven through the view's cold path) */
    view_hits[1]++;
    FEXBRIDGE_AMD64_CONTEXT c;
    memset(&c, 0, sizeof(c));
    check_eq((uint64_t)p_view_pull(thread, &c, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER | FEXBRIDGE_CTX_FLOATING_POINT), 0,
             "view pull rc");
    check((c.EFlags & 0x1) != 0, "view pull: guest stc's CF");
    check((c.EFlags & 0x40) != 0, "view pull: guest sub's ZF");
    check_eq(c.Rip, *v->rip, "view pull: Rip matches view");
    check_eq(c.Rax, g[FEXBRIDGE_GREG_RAX], "view pull: RAX matches gregs");
    check_eq(c.Rsp, g[FEXBRIDGE_GREG_RSP], "view pull: RSP matches gregs");
    check_eq(c.FltSave.XmmRegisters[0].Low, 0xA1B2C3D4E5F60718ULL, "view pull: guest XMM0");
    c.EFlags &= ~0x1u; /* clear CF */
    c.FltSave.XmmRegisters[0].Low = 0x1122334455667788ULL;
    c.FltSave.XmmRegisters[0].High = 0;
    check_eq((uint64_t)p_view_push(thread, &c, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_FLOATING_POINT), 0, "view push rc");
    /* push(CONTROL) rewrote State.rip with the pulled (trap) address; the
       common epilogue below advances it, exactly as a callback that never
       pushed. */
  } else if (view_mode == 3 && *v->rip == bop2) {
    /* nested run under the view protocol: pull/push is the caller-side
       save/restore the ABI 6 changelog demands */
    view_hits[2]++;
    FEXBRIDGE_AMD64_CONTEXT save;
    memset(&save, 0, sizeof(save));
    check_eq((uint64_t)p_view_pull(thread, &save, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER), 0, "view nested: pull rc");
    FEXBRIDGE_AMD64_CONTEXT nctx;
    memset(&nctx, 0, sizeof(nctx));
    nctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    nctx.Rip = nested_code;
    nctx.Rsp = nested_stack_top;
    nctx.EFlags = 0x202;
    int r = p_run(thread, &nctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "view nested: run ended at HLT");
    view_nested_result = nctx.Rax;
    check_eq((uint64_t)p_view_push(thread, &save, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER), 0, "view nested: push rc");
    check_eq(g[FEXBRIDGE_GREG_RSP], save.Rsp, "view nested: push restored RSP in the live file");
    g[FEXBRIDGE_GREG_RAX] = view_nested_result + 1;
  } else {
    check(0, "view cb: unexpected RIP/mode");
    return FEXBRIDGE_TRAP_EXIT;
  }

  /* the bop protocol, spelled through the view */
  uint64_t rsp = g[FEXBRIDGE_GREG_RSP];
  *v->rip = *(uint64_t*)rsp;
  g[FEXBRIDGE_GREG_RSP] = rsp + 8;
  return FEXBRIDGE_TRAP_CONTINUE;
}

/* ---- S13: the trap floor microbench ------------------------------------- */
static uint64_t bench_count, bench_limit;

static int bench_ctx_cb(void* thread, void* vctx, void* user) {
  FEXBRIDGE_AMD64_CONTEXT* ctx = vctx;
  (void)thread;
  (void)user;
  uint64_t ret = *(uint64_t*)ctx->Rsp;
  ctx->Rsp += 8;
  ctx->Rip = ret;
  if (++bench_count >= bench_limit) {
    return FEXBRIDGE_TRAP_EXIT;
  }
  return FEXBRIDGE_TRAP_CONTINUE;
}

static int bench_view_cb(void* thread, FEXBRIDGE_TRAP_VIEW* v, void* user) {
  (void)thread;
  (void)user;
  uint64_t rsp = v->gregs[FEXBRIDGE_GREG_RSP];
  *v->rip = *(uint64_t*)rsp;
  v->gregs[FEXBRIDGE_GREG_RSP] = rsp + 8;
  if (++bench_count >= bench_limit) {
    return FEXBRIDGE_TRAP_EXIT;
  }
  return FEXBRIDGE_TRAP_CONTINUE;
}

static int bench_ec_cb(void* thread, FEXBRIDGE_TRAP_VIEW* v, void* cookie) {
  (void)thread;
  (void)cookie;
  uint64_t rsp = v->gregs[FEXBRIDGE_GREG_RSP];
  *v->rip = *(uint64_t*)rsp;
  v->gregs[FEXBRIDGE_GREG_RSP] = rsp + 8;
  if (++bench_count >= bench_limit) {
    return FEXBRIDGE_TRAP_EXIT;
  }
  return FEXBRIDGE_TRAP_CONTINUE;
}

/* ---- S14: EC targets (ABI 7) -------------------------------------------- */
static int ec_mode;
static uint64_t ec_hits[4];
static uint64_t ec_nested_result;

static int ec_cb(void* thread, FEXBRIDGE_TRAP_VIEW* v, void* cookie) {
  uint64_t* g = v->gregs;
  check(thread == p_current_thread(), "ec cb: thread handle matches TLS");
  check(cookie == (void*)0xC00C1E, "ec cb: registration cookie delivered");
  check_eq(*v->rip, ec_stub0, "ec cb: rip is the registered stub BASE, not base+trap_off");

  if (ec_mode == 1) {
    /* the calling-convention difference, both halves: arg0 still in RCX, and
       R10 holds what the CALLER left there (emit_call_abs's own target
       load), because the stub's `mov r10,rcx` never executed */
    ec_hits[0]++;
    check_eq(g[FEXBRIDGE_GREG_RCX], 0x1234, "ec: arg0 still in RCX");
    check_eq(g[FEXBRIDGE_GREG_R10], ec_stub0, "ec: R10 untouched by the never-run stub rescue");
    g[FEXBRIDGE_GREG_RAX] = 0xECEC;
  } else if (ec_mode == 3) {
    /* nested run from an EC handler, pull/push(CONTROL|INTEGER) around it,
       per the ABI 6 nested contract the EC handler inherits */
    ec_hits[2]++;
    FEXBRIDGE_AMD64_CONTEXT save;
    memset(&save, 0, sizeof(save));
    check_eq((uint64_t)p_view_pull(thread, &save, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER), 0, "ec nested: pull rc");
    FEXBRIDGE_AMD64_CONTEXT nctx;
    memset(&nctx, 0, sizeof(nctx));
    nctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    nctx.Rip = nested_code;
    nctx.Rsp = nested_stack_top;
    nctx.EFlags = 0x202;
    int r = p_run(thread, &nctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec nested: run ended at HLT");
    ec_nested_result = nctx.Rax;
    check_eq((uint64_t)p_view_push(thread, &save, FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER), 0, "ec nested: push rc");
    g[FEXBRIDGE_GREG_RAX] = ec_nested_result + 1;
  } else if (ec_mode == 4) {
    /* TRAP_EXIT: end the run cooperatively with the continuation parked */
    ec_hits[3]++;
    uint64_t rsp = g[FEXBRIDGE_GREG_RSP];
    *v->rip = *(uint64_t*)rsp;
    g[FEXBRIDGE_GREG_RSP] = rsp + 8;
    g[FEXBRIDGE_GREG_RAX] = 0xE817;
    return FEXBRIDGE_TRAP_EXIT;
  } else {
    check(0, "ec cb: unexpected mode");
    return FEXBRIDGE_TRAP_EXIT;
  }

  /* the return protocol, spelled through the view */
  uint64_t rsp = g[FEXBRIDGE_GREG_RSP];
  *v->rip = *(uint64_t*)rsp;
  g[FEXBRIDGE_GREG_RSP] = rsp + 8;
  return FEXBRIDGE_TRAP_CONTINUE;
}

/* S14 leg 5: the _targets2 form's per-rip cookies, recorded per stub */
static uint64_t ec2_cookie_seen[2];
static int ec2_cb(void* thread, FEXBRIDGE_TRAP_VIEW* v, void* cookie) {
  uint64_t* g = v->gregs;
  (void)thread;
  if (*v->rip == ec_stub0) {
    ec2_cookie_seen[0] = (uint64_t)cookie;
  } else if (*v->rip == ec_stub1) {
    ec2_cookie_seen[1] = (uint64_t)cookie;
  } else {
    check(0, "ec2 cb: unexpected rip");
  }
  g[FEXBRIDGE_GREG_RAX] = 0;
  uint64_t rsp = g[FEXBRIDGE_GREG_RSP];
  *v->rip = *(uint64_t*)rsp;
  g[FEXBRIDGE_GREG_RSP] = rsp + 8;
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
  SYM(p_declare_trap_ctx, "fexbridge_declare_trap_ctx");
  SYM(p_ctx_materialize, "fexbridge_ctx_materialize");
  SYM(p_set_trap_view_handler, "fexbridge_set_trap_view_handler");
  SYM(p_view_pull, "fexbridge_view_pull");
  SYM(p_view_push, "fexbridge_view_push");
  SYM(p_register_ec, "fexbridge_register_ec_target");
  SYM(p_register_ec2, "fexbridge_register_ec_targets2");
  SYM(p_unregister_ec, "fexbridge_unregister_ec_range");

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

  /* ---- S11: lazy trap contexts (ABI 5) ----------------------------------- */
  fprintf(stderr, "\n== S11: lazy trap contexts — declare, materialize, poison, eager veto ==\n");
  {
    /* hop A guest: known flags (ZF via sub, CF via stc) and a known XMM0,
       trap, then read back what the callback's materialize-and-modify left:
       pushfq -> rax, xmm0 -> rdx. */
    uint8_t* lcode1 = map_rwx(0x1000);
    {
      uint8_t* p = lcode1;
      p = emit_mov_imm32(p, 3, 1);          /* mov rbx, 1 */
      E(p, 0x48, 0x83, 0xEB, 0x01);         /* sub rbx, 1 -> ZF=1 */
      E(p, 0xF9);                           /* stc        -> CF=1 */
      E(p, 0x48, 0xB8);                     /* movabs rax, pattern */
      uint64_t pat = 0xA1B2C3D4E5F60718ULL;
      memcpy(p, &pat, 8);
      p += 8;
      E(p, 0x66, 0x48, 0x0F, 0x6E, 0xC0);   /* movq xmm0, rax */
      p = emit_call_abs(p, bop1);
      E(p, 0x9C);                           /* pushfq */
      E(p, 0x58);                           /* pop rax */
      E(p, 0x66, 0x48, 0x0F, 0x7E, 0xC2);   /* movq rdx, xmm0 */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)lcode1, 0x1000);

    /* hop B guest: CF/SF via a borrowing sub, a known XMM1, a trap the
       callback leaves lazy -- everything must come back intact. */
    uint8_t* lcode2 = map_rwx(0x1000);
    {
      uint8_t* p = lcode2;
      p = emit_mov_imm32(p, 3, 0);          /* mov rbx, 0 */
      E(p, 0x48, 0x83, 0xEB, 0x01);         /* sub rbx, 1 -> CF=1 SF=1 ZF=0 */
      E(p, 0x48, 0xB8);                     /* movabs rax, pattern2 */
      uint64_t pat2 = 0x0F1E2D3C4B5A6978ULL;
      memcpy(p, &pat2, 8);
      p += 8;
      E(p, 0x66, 0x48, 0x0F, 0x6E, 0xC8);   /* movq xmm1, rax */
      p = emit_call_abs(p, bop2);
      E(p, 0x9C);                           /* pushfq */
      E(p, 0x58);                           /* pop rax */
      E(p, 0x66, 0x48, 0x0F, 0x7E, 0xCA);   /* movq rdx, xmm1 */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)lcode2, 0x1000);

    check_eq(p_declare_trap_ctx(FEXBRIDGE_CTX_LAZY_EFLAGS | FEXBRIDGE_CTX_LAZY_FLOAT), 0x300, "declare accepts both lazy groups");

    trap_mode = MODE_LAZY;
    lazy_poison_phase = 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)lcode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "lazy hop A ran to HLT");
    check_eq(lazy_hits[0], 1, "lazy bop A dispatched");
    check((ctx.Rax & 0x1) == 0, "callback's CF clear reached the guest");
    check((ctx.Rax & 0x40) != 0, "guest's ZF survived the modified resume");
    check_eq(ctx.Rdx, 0x1122334455667788ULL, "callback's XMM0 write reached the guest");

    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)lcode2;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "lazy hop B ran to HLT");
    check_eq(lazy_hits[1], 1, "lazy bop B dispatched");
    check((ctx.Rax & 0x1) != 0, "guest CF survived an unmaterialized hop");
    check((ctx.Rax & 0x80) != 0, "guest SF survived an unmaterialized hop");
    check((ctx.Rax & 0x40) == 0, "guest ZF stayed clear across the hop");
    check_eq(ctx.Rdx, 0x0F1E2D3C4B5A6978ULL, "guest XMM1 survived an unmaterialized hop");

    /* poison: the same materialize path must first see the pattern */
    setenv("FEXBRIDGE_CTX_POISON", "1", 1);
    check_eq(p_declare_trap_ctx(FEXBRIDGE_CTX_LAZY_EFLAGS | FEXBRIDGE_CTX_LAZY_FLOAT), 0x300, "re-declare with poison armed");
    lazy_poison_phase = 1;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)lcode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "poisoned lazy hop ran to HLT");
    check_eq(lazy_hits[0], 2, "poisoned lazy bop dispatched");
    check_eq(ctx.Rdx, 0x1122334455667788ULL, "materialize under poison still yields the real state");
    unsetenv("FEXBRIDGE_CTX_POISON");
    lazy_poison_phase = 0;

    /* the eager kill switch vetoes a declaration */
    setenv("FEXBRIDGE_EAGER_CTX", "1", 1);
    check_eq(p_declare_trap_ctx(FEXBRIDGE_CTX_LAZY_EFLAGS | FEXBRIDGE_CTX_LAZY_FLOAT), 0, "FEXBRIDGE_EAGER_CTX=1 vetoes lazy");
    unsetenv("FEXBRIDGE_EAGER_CTX");

    /* back to eager for everything after this section */
    check_eq(p_declare_trap_ctx(0), 0, "declare(0) restores eager");
    trap_mode = MODE_NONE;
  }

  /* ---- S12: zero-copy trap view (ABI 6) ---------------------------------- */
  fprintf(stderr, "\n== S12: zero-copy trap view — gregs/rip in place, pull/push, veto, nesting ==\n");
  {
    /* leg 1 guest: mov rax,0x42 ; call bop1 ; mov rbx,rax ; hlt */
    uint8_t* vcode1 = map_rwx(0x1000);
    {
      uint8_t* p = vcode1;
      p = emit_mov_imm32(p, 0, 0x42);
      p = emit_call_abs(p, bop1);
      E(p, 0x48, 0x89, 0xC3); /* mov rbx, rax */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)vcode1, 0x1000);

    /* the CONTEXT handler stays registered in a mode that FAILS on any hit:
       precedence is proven by the run not failing. */
    trap_mode = MODE_NONE;
    p_set_trap_view_handler(view_cb, (void*)0x5678);
    view_mode = 1;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)vcode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "view leg 1 ran to HLT");
    check_eq(view_hits[0], 1, "view cb dispatched (and won precedence)");
    check_eq(ctx.Rbx, 0x4242, "view greg write reached the guest");
    check_eq(ctx.Rsp, stack_top, "view: stack balanced");

    /* leg 2 guest: the S11 hop-A shape — known flags + XMM0, trap, read back */
    uint8_t* vcode2 = map_rwx(0x1000);
    {
      uint8_t* p = vcode2;
      p = emit_mov_imm32(p, 3, 1);        /* mov rbx, 1 */
      E(p, 0x48, 0x83, 0xEB, 0x01);       /* sub rbx, 1 -> ZF=1 */
      E(p, 0xF9);                         /* stc        -> CF=1 */
      E(p, 0x48, 0xB8);                   /* movabs rax, pattern */
      uint64_t pat = 0xA1B2C3D4E5F60718ULL;
      memcpy(p, &pat, 8);
      p += 8;
      E(p, 0x66, 0x48, 0x0F, 0x6E, 0xC0); /* movq xmm0, rax */
      p = emit_call_abs(p, bop1);
      E(p, 0x9C);                         /* pushfq */
      E(p, 0x58);                         /* pop rax */
      E(p, 0x66, 0x48, 0x0F, 0x7E, 0xC2); /* movq rdx, xmm0 */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)vcode2, 0x1000);

    view_mode = 2;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)vcode2;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "view leg 2 ran to HLT");
    check_eq(view_hits[1], 1, "view pull/push cb dispatched");
    check((ctx.Rax & 0x1) == 0, "pushed CF-clear reached the guest");
    check((ctx.Rax & 0x40) != 0, "guest ZF survived the pushed resume");
    check_eq(ctx.Rdx, 0x1122334455667788ULL, "pushed XMM0 reached the guest");

    /* leg 3: nested run from a view callback, pull/push around it.
       guest: mov r15,imm ; call bop2 ; mov rbx,rax ; hlt */
    uint8_t* vcode3 = map_rwx(0x1000);
    {
      uint8_t* p = vcode3;
      p = emit_mov_imm32(p, 15, 0xBEEF);
      p = emit_call_abs(p, bop2);
      E(p, 0x48, 0x89, 0xC3); /* mov rbx, rax */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)vcode3, 0x1000);

    view_mode = 3;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)vcode3;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "view leg 3 ran to HLT");
    check_eq(view_hits[2], 1, "view nested cb dispatched");
    check_eq(view_nested_result, 0x99, "nested run produced its result");
    check_eq(ctx.Rbx, 0x99 + 1, "nested result handed back through the view");
    check_eq(ctx.R15, 0xBEEF, "outer R15 survived the nested run (push restored it)");

    /* the kill switch: FEXBRIDGE_EAGER_CTX=1 vetoes the view registration,
       traps land on the CONTEXT handler */
    setenv("FEXBRIDGE_EAGER_CTX", "1", 1);
    p_set_trap_view_handler(view_cb, (void*)0x5678); /* vetoed, loudly */
    trap_mode = MODE_VIEWKILL;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)vcode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "vetoed run ran to HLT");
    check_eq((uint64_t)viewkill_ctx_hits, 1, "veto: trap landed on the CONTEXT handler");
    check_eq(ctx.Rbx, 0xEA6E4, "veto: CONTEXT handler's RAX reached the guest");
    unsetenv("FEXBRIDGE_EAGER_CTX");
    trap_mode = MODE_NONE;
    p_set_trap_view_handler(NULL, NULL);
  }

  /* ---- S13: the trap floor microbench (Step 0 of the PPC64EC plan) ------- */
  fprintf(stderr, "\n== S13: trap floor microbench — eager / lazy / view ns per crossing ==\n");
  {
    /* guest: L: call bop1 ; jmp L — the callback ends the run at the limit */
    uint8_t* bcode = map_rwx(0x1000);
    {
      uint8_t* p = bcode;
      uint64_t loop_top = (uint64_t)p;
      p = emit_call_abs(p, bop1);
      int32_t rel = (int32_t)(loop_top - ((uint64_t)p + 5));
      E(p, 0xE9); /* jmp rel32 back to the call */
      memcpy(p, &rel, 4);
      p += 4;
    }
    p_invalidate((uint64_t)bcode, 0x1000);

    const uint64_t N = 1000000;
    struct leg {
      const char* name;
      int use_view;
      uint32_t lazy;
    } legs[4] = {
      {"eager", 0, 0},
      {"lazy", 0, FEXBRIDGE_CTX_LAZY_EFLAGS | FEXBRIDGE_CTX_LAZY_FLOAT},
      {"view", 1, 0},
      {"ec", 2, 0},
    };
    for (int i = 0; i < 4; i++) {
      if (legs[i].use_view == 2) {
        /* the ec leg: register bop1 itself as an EC target -- its 0F 05
           bytes stop being decoded, the call compiles to the transition */
        p_set_trap_view_handler(NULL, NULL);
        p_set_trap_handler(bench_ctx_cb, NULL); /* must NOT fire; count would break */
        check_eq((uint64_t)p_register_ec(bop1, bench_ec_cb, NULL), 0, "bench: ec target registered");
      } else if (legs[i].use_view) {
        p_set_trap_view_handler(bench_view_cb, NULL);
      } else {
        p_set_trap_view_handler(NULL, NULL);
        p_set_trap_handler(bench_ctx_cb, NULL);
        p_declare_trap_ctx(legs[i].lazy);
      }
      /* warmup: compile the block, fault in everything */
      bench_count = 0;
      bench_limit = 1000;
      memset(&ctx, 0, sizeof(ctx));
      ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
      ctx.Rip = (uint64_t)bcode;
      ctx.Rsp = stack_top;
      ctx.EFlags = 0x202;
      r = p_run(thread, &ctx);
      check_eq((uint64_t)r, FEXBRIDGE_RUN_EXITED, "bench warmup leg exited");

      bench_count = 0;
      bench_limit = N;
      memset(&ctx, 0, sizeof(ctx));
      ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
      ctx.Rip = (uint64_t)bcode;
      ctx.Rsp = stack_top;
      ctx.EFlags = 0x202;
      struct timespec t0, t1;
      clock_gettime(CLOCK_MONOTONIC, &t0);
      r = p_run(thread, &ctx);
      clock_gettime(CLOCK_MONOTONIC, &t1);
      check_eq((uint64_t)r, FEXBRIDGE_RUN_EXITED, "bench timed leg exited");
      check_eq(bench_count, N, "bench leg trap count");
      double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9 + (double)(t1.tv_nsec - t0.tv_nsec);
      fprintf(stderr, "  BENCH %s_ns_per_trap=%.1f (N=%llu)\n", legs[i].name, ns / (double)N, (unsigned long long)N);
    }
    /* restore the functional handlers/protocol for anything after */
    check_eq((uint64_t)p_unregister_ec(bop1, 1), 1, "bench: ec target unregistered");
    p_set_trap_view_handler(NULL, NULL);
    p_declare_trap_ctx(0);
    p_set_trap_handler(trap_cb, (void*)0x1234);
  }

  /* ---- S14: EC targets (ABI 7) ------------------------------------------- */
  fprintf(stderr, "\n== S14: EC targets — transition vs stub trap, fallback, nesting, exit, edges ==\n");
  {
    /* two REAL stubs, byte-identical `mov r10,rcx ; syscall`, 16 bytes
       apart, on their own page: stub0 gets registered, stub1 stays a trap */
    uint8_t* stubpage = map_rwx(0x1000);
    static const uint8_t stub_bytes[] = {0x49, 0x89, 0xCA, 0x0F, 0x05};
    memcpy(stubpage, stub_bytes, sizeof(stub_bytes));
    memcpy(stubpage + 16, stub_bytes, sizeof(stub_bytes));
    p_invalidate((uint64_t)stubpage, 0x1000);
    ec_stub0 = (uint64_t)stubpage;
    ec_stub1 = (uint64_t)stubpage + 16;

    /* registration edges first, on a clean map */
    check_eq((uint64_t)p_register_ec(0, ec_cb, (void*)0xC00C1E), (uint64_t)-1, "ec edge: rip 0 refused");
    check_eq((uint64_t)p_register_ec(ec_stub0, NULL, NULL), (uint64_t)-1, "ec edge: null handler refused");
    check_eq((uint64_t)p_register_ec(ec_stub0, ec_cb, (void*)0xC00C1E), 0, "ec: stub0 registered");
    check_eq((uint64_t)p_register_ec(ec_stub0, ec_cb, (void*)0xC00C1E), 0, "ec edge: identical re-register is idempotent");
    check_eq((uint64_t)p_register_ec(ec_stub0, ec_cb, (void*)0xBAD), (uint64_t)-2, "ec edge: different cookie refused");

    /* leg 1: registered stub transitions (arg0 in RCX), sibling stub traps
       (arg0 rescued into R10) -- both in one run */
    trap_mode = MODE_ECSTUBS;
    ec_mode = 1;
    uint8_t* ecode1 = map_rwx(0x1000);
    {
      uint8_t* p = ecode1;
      p = emit_mov_imm32(p, 1, 0x1234);   /* mov rcx, 0x1234 */
      p = emit_call_abs(p, ec_stub0);     /* EC transition */
      E(p, 0x48, 0x89, 0xC3);             /* mov rbx, rax */
      p = emit_mov_imm32(p, 1, 0x5678);   /* mov rcx, 0x5678 */
      p = emit_call_abs(p, ec_stub1);     /* real stub, real trap */
      E(p, 0x48, 0x89, 0xC6);             /* mov rsi, rax */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)ecode1, 0x1000);
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)ecode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec leg 1 ran to HLT");
    check_eq(ec_hits[0], 1, "ec: transition fired once");
    check_eq(ec_trap_hits[1], 1, "ec: sibling stub trapped once");
    check_eq(ec_trap_hits[0], 0, "ec: registered stub never trapped");
    check_eq(ctx.Rbx, 0xECEC, "ec: transition result reached the guest");
    check_eq(ctx.Rsi, 0x51B, "ec: sibling trap result reached the guest");
    check_eq(ctx.Rsp, stack_top, "ec: stack balanced");

    /* leg 2: nested run from the EC handler */
    ec_mode = 3;
    uint8_t* ecode2 = map_rwx(0x1000);
    {
      uint8_t* p = ecode2;
      p = emit_mov_imm32(p, 15, 0xBEEF);  /* mov r15, 0xBEEF */
      p = emit_call_abs(p, ec_stub0);
      E(p, 0x48, 0x89, 0xC3);             /* mov rbx, rax */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)ecode2, 0x1000);
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)ecode2;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec leg 2 ran to HLT");
    check_eq(ec_hits[2], 1, "ec nested cb fired");
    check_eq(ec_nested_result, 0x99, "ec nested run produced its result");
    check_eq(ctx.Rbx, 0x99 + 1, "ec nested result handed back");
    check_eq(ctx.R15, 0xBEEF, "ec: outer R15 survived the nested run");

    /* leg 3: TRAP_EXIT ends the run with the continuation parked; resuming
       the same ctx picks up exactly there */
    ec_mode = 4;
    uint8_t* ecode3 = map_rwx(0x1000);
    uint64_t ec_cont;
    {
      uint8_t* p = ecode3;
      p = emit_call_abs(p, ec_stub0);
      ec_cont = (uint64_t)p;              /* the instruction after the call */
      p = emit_mov_imm32(p, 3, 0xAF7E);   /* mov rbx, 0xAF7E */
      E(p, 0xF4);
    }
    p_invalidate((uint64_t)ecode3, 0x1000);
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)ecode3;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_EXITED, "ec TRAP_EXIT ended the run");
    check_eq(ec_hits[3], 1, "ec exit cb fired");
    check_eq(ctx.Rip, ec_cont, "ec exit: continuation RIP parked");
    check_eq(ctx.Rax, 0xE817, "ec exit: RAX written before exit");
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec exit: resumed run reached HLT");
    check_eq(ctx.Rbx, 0xAF7E, "ec exit: resumed exactly at the continuation");

    /* leg 4: the fallback -- unregister, and the SAME address decodes its
       stub bytes and traps like any stub */
    check_eq((uint64_t)p_unregister_ec(ec_stub0, 16), 1, "ec: unregister removed exactly one");
    ec_mode = 0;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
    ctx.Rip = (uint64_t)ecode1;
    ctx.Rsp = stack_top;
    ctx.EFlags = 0x202;
    r = p_run(thread, &ctx);
    check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec fallback run ran to HLT");
    check_eq(ec_trap_hits[0], 1, "ec fallback: the unregistered stub DECODED and TRAPPED");
    check_eq(ec_hits[0], 1, "ec fallback: the transition handler did not fire again");
    check_eq(ctx.Rbx, 0xFA11, "ec fallback: trap result reached the guest");

    /* re-register works after unregister */
    check_eq((uint64_t)p_register_ec(ec_stub0, ec_cb, (void*)0xC00C1E), 0, "ec: re-register after unregister");
    check_eq((uint64_t)p_unregister_ec(ec_stub0, 16), 1, "ec: cleaned up");
    trap_mode = MODE_NONE;

    /* leg 5: per-rip cookies (_targets2) -- two stubs, two cookies, each
       delivered to the handler for its own rip */
    {
      uint64_t rips2[2] = {ec_stub0, ec_stub1};
      const void* cookies2[2] = {(const void*)0xA110C0, (const void*)0xB220C1};
      uint8_t* ecode5 = map_rwx(0x1000);
      {
        uint8_t* p = ecode5;
        p = emit_call_abs(p, ec_stub0);
        p = emit_call_abs(p, ec_stub1);
        E(p, 0xF4);
      }
      p_invalidate((uint64_t)ecode5, 0x1000);
      check_eq((uint64_t)p_register_ec2(rips2, cookies2, 2, ec2_cb), 2, "ec2: both rips registered with own cookies");
      memset(&ctx, 0, sizeof(ctx));
      ctx.ContextFlags = FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER;
      ctx.Rip = (uint64_t)ecode5;
      ctx.Rsp = stack_top;
      ctx.EFlags = 0x202;
      r = p_run(thread, &ctx);
      check_eq((uint64_t)r, FEXBRIDGE_RUN_HLT, "ec2 run ran to HLT");
      check_eq(ec2_cookie_seen[0], 0xA110C0, "ec2: stub0's own cookie delivered");
      check_eq(ec2_cookie_seen[1], 0xB220C1, "ec2: stub1's own cookie delivered");
      check_eq((uint64_t)p_unregister_ec(ec_stub0, 32), 2, "ec2: cleaned up both");
    }
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
