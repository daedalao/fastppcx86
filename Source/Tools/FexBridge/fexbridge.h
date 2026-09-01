// SPDX-License-Identifier: MIT
/*
  fexbridge.h — C ABI for embedding FEXCore as the x86-64 CPU of a native
  ppc64le host process (Wine's ntdll unix side is the intended caller).

  This is the library form of the Wow64Probe findings: FEXCore linked WITHOUT
  LinuxEmulation, driven through the five primitives a CPU-DLL-shaped embedder
  needs. Everything the probe proved is behind this surface; nothing here
  requires _WIN32, a PE loader, or a particular trap opcode choice beyond the
  one documented below.

  ============================ PROCESS MODEL =================================
  - The emulator lives inside the caller's process. Guest x86-64 memory IS
    host memory: the caller mmaps/loads guest code wherever it wants and tells
    the bridge about executable bytes with fexbridge_invalidate_code_range().
  - The bridge installs NO signal handlers. The caller owns every host signal.
    On a host SIGSEGV/SIGBUS, the caller's handler asks the bridge whether the
    faulting PC is emulator JIT code (fexbridge_fault_is_jit) and, if so, hands
    the ucontext back (fexbridge_fault_unwind) — the bridge reconstructs the
    guest register file from the host fault context and unwinds to the
    innermost fexbridge_run(), which returns FEXBRIDGE_RUN_FAULT.
  - One host thread == one guest thread. fexbridge_thread_init() must be
    called ON the host thread that will run the guest (it binds thread-local
    state), and fexbridge_run() only accepts the calling thread's own handle.
    Threads the caller created by any means (pthread, Wine thread pool) can be
    adopted; the bridge never creates host threads.

  ============================ TRAP PROTOCOL =================================
  On this build the trap ("bop") opcode is x86-64 SYSCALL (0F 05). The caller
  places 0F 05 at guest addresses of its choosing (its BTCpuGetBopCode
  equivalent), publishes them with fexbridge_invalidate_code_range, and points
  guest dispatch stubs at them. When the guest executes any 0F 05 the trap
  callback fires with the COMPLETE guest register file marshalled into an
  AMD64 CONTEXT (ContextFlags = CONTROL|INTEGER|SEGMENTS|FLOATING_POINT).

  THE CALLBACK OWNS Rip. ctx->Rip on entry is the address OF the trapping
  instruction — deliberately not advanced, so the callback can tell which bop
  site fired by comparing Rip. A callback that returns FEXBRIDGE_TRAP_CONTINUE
  without changing Rip re-executes the trap forever. Typical bop handling:
      ret = *(uint64_t *)ctx->Rsp;   // pushed by the guest CALL
      ctx->Rsp += 8;
      ctx->Rax = <result>;
      ctx->Rip = ret;
  Every field of the CONTEXT written by the callback reaches the guest —
  including RSI/RDI/R8-R15 (this is one of the four FEXCore fixes carried on
  the wow64-probe branch; without it only 5 of 15 GPRs propagate).

  ============================ LIFECYCLE =====================================
    fexbridge_process_init()            once per process
    fexbridge_set_trap_handler(cb, u)   before the first run
    per guest thread, on its own host thread:
      fexbridge_thread_init(&t)
      fexbridge_set_gs_base(t, teb)     before the first run (Windows guests)
      fexbridge_run(t, &ctx)            repeatedly; ctx carries state in/out
      fexbridge_thread_term(t)
  fexbridge_run may be re-entered from inside the trap callback (guest
  callback dispatch, KiUserCallbackDispatcher-style). The guest register file
  is a single per-thread resource: the caller must save/restore the CONTEXT
  around a nested run itself, exactly as Windows' wow64 does.

  ============================ CONFIG ========================================
  process_init loads the FEX config layers (FEX_APP_CONFIG honoured) and then
  forces IS64BIT_MODE=1 and SMCCHECKS=0. Self-modifying/newly-loaded guest
  code is the CALLER's job to report via fexbridge_invalidate_code_range —
  call it after writing guest instructions to memory that may already have
  been executed from, and after any PE section load.
*/
#ifndef FEXBRIDGE_H
#define FEXBRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#define FEXBRIDGE_SASSERT(cond, name) static_assert(cond, #name)
#else
#define FEXBRIDGE_SASSERT(cond, name) _Static_assert(cond, #name)
#endif

/* 1 -> 2: added fexbridge_{set,get}_{gs,fs}_base (64-bit segment bases).
   2 -> 3: a guest jump to unfetchable memory (unmapped or PROT_NONE) now
           returns FEXBRIDGE_RUN_FAULT with Rip at the bad address, instead
           of taking a raw host SIGSEGV inside the frontend decoder with the
           code-invalidation lock held.  No surface change; the run result
           gained a source.
   3 -> 4: 32-bit (i386) guest mode.  fexbridge_process_init32() initializes
           the process for 32-bit guest execution; fexbridge_thread_init()
           then builds a 32-bit flat segment model (Windows-shaped selectors,
           CS=0x23 SS/DS/ES/GS=0x2B FS=0x53) instead of the 64-bit one, and
           fexbridge_set_fs_base() also writes the FS descriptor so a guest
           segment reload recomputes the same base.  One mode per process:
           FEXCore bakes IS64BIT_MODE into the Context at creation (decode
           tables, VirtualMemSize), and the embedder this exists for never
           mixes modes -- a WoW64 process's 64-bit side is native host code,
           not emulated.  fexbridge_run_entry() refuses in 32-bit mode.
   4 -> 5: lazy trap contexts.  fexbridge_declare_trap_ctx() lets the embedder
           declare that its trap callback will call fexbridge_ctx_materialize()
           before READING OR WRITING EFlags and/or the floating-point group
           (FltSave, both MxCsr homes) of a trap CONTEXT.  The trap path then
           skips the EFLAGS reconstruction and the XMM/x87 store on every
           crossing, marking the skipped groups with FEXBRIDGE_CTX_LAZY_* in
           ContextFlags, and the resume skips their write-back when they were
           never materialized (writes to an unmaterialized group are IGNORED
           at resume -- materialize first, then write).  An embedder that
           never declares keeps the fully eager contexts, so ABI 4 callers are
           unaffected.  FEXBRIDGE_EAGER_CTX=1 in the environment forces eager
           regardless of declaration (the kill switch); FEXBRIDGE_CTX_POISON=1
           fills the skipped groups with a recognizable pattern (EFlags
           0xDEADF1A6, FltSave 0xDD bytes) so a reader that forgot to
           materialize fails loudly -- the embedder's negative control.      */
/* 5 -> 6: the zero-copy trap (the trap view).  fexbridge_set_trap_view_handler()
           registers a callback that receives a FEXBRIDGE_TRAP_VIEW -- pointers
           into the LIVE guest register file -- instead of a marshalled AMD64
           CONTEXT.  On a view trap the bridge builds no CONTEXT at all: no
           GPR store, no EFLAGS reconstruction, no FP store, no write-back
           pass.  The callback reads and writes guest registers in place and
           owns RIP through the view exactly as the CONTEXT protocol owns
           ctx->Rip.  When both handlers are registered the view handler wins;
           FEXBRIDGE_EAGER_CTX=1 in the environment VETOES the view protocol
           at registration time (a loud line says so) and every trap then goes
           to the ABI<=5 CONTEXT handler -- which is why an embedder that
           registers a view handler must keep its CONTEXT handler registered
           too: the pair is the kill switch.
           fexbridge_view_pull()/fexbridge_view_push() are the cold-path
           bridge to CONTEXT land for the callbacks that need one (a debugger
           read, an exception, an FP-typed call): pull fills the named groups
           of a caller-provided CONTEXT from live guest state, push writes
           the named groups back.  NESTED RUNS under the view protocol:
           fexbridge_run's own nested-run save/restore already preserves the
           EFLAGS raw forms and the entire FP file (XMM/x87/MXCSR/FCW/FTW/
           YMM-high) around a nested run -- but the GPRs, RIP and RSP are
           loaded from the nested run's CONTEXT and clobbered by the nested
           guest, and with no outer CONTEXT there is no outer resume to put
           them back.  A view callback that starts a nested run must
           pull(CONTROL|INTEGER) first and push(CONTROL|INTEGER) after; that
           is the ABI<=5 "caller must save/restore the CONTEXT around a
           nested run" contract restated for the view.                        */
/* 6 -> 7: EC targets (PPC64EC).  fexbridge_register_ec_target() makes the
           emulator COMPILE a registered guest RIP as a direct host call to
           the handler instead of decoding the bytes at that address -- the
           whole marshalled-trap round trip (guest call -> stub -> SYSCALL
           decode -> trap sink) collapses into one JIT-emitted host call with
           the same spill/refill discipline the trap already pays.

           THE BYTES AT THE RIP ARE NEVER TOUCHED AND NEVER DECODED while the
           registration stands: registration lives in the emulator's compile
           path (a custom-IR entrypoint consulted before the frontend
           decoder), not in guest memory.  A reader (DRM checksums, Detours
           scans) sees the stub bytes unchanged, and every path that reaches
           the address without a registration -- after unregistration, or
           mid-stub -- decodes those bytes and traps exactly as before.  The
           stub is the always-correct fallback.

           CALLING-CONVENTION DIFFERENCE FROM A TRAP, read this twice: an EC
           transition fires at the STUB ENTRY, before the stub's
           `mov r10,rcx` has executed, so argument 0 is still in RCX
           (gregs[FEXBRIDGE_GREG_RCX]).  A trap-protocol handler reads the
           rescued copy from R10; an EC handler must NOT.  Likewise *view->rip
           on entry is the registered RIP itself (the stub base), not
           stub+trap_off.

           The handler receives the ABI 6 view (gregs/rip into live CPUState;
           fexbridge_view_pull/push work inside it, including around a nested
           fexbridge_run) plus its registration cookie, and owns *view->rip
           exactly like a trap callback: pop the return address, write
           results, set rip.  FEXBRIDGE_TRAP_CONTINUE resumes at *view->rip
           through the ordinary dispatcher; FEXBRIDGE_TRAP_EXIT ends the run
           cooperatively with *view->rip as the parked continuation.

           INVALIDATION: fexbridge_invalidate_code_range over a registered
           RIP drops the compiled transition block but NOT the registration
           -- the compile path re-consults registrations before the decoder,
           so the next execution recompiles the transition and SMC-style
           invalidation storms cannot silently downgrade an EC target to a
           trap.  Only fexbridge_unregister_ec_range removes registrations
           (module unload); it also invalidates the range so stale transition
           blocks die.  LIFETIME: a handler/cookie must stay callable until
           unregister_ec_range for its RIP has returned and no call that
           entered before it is still in flight -- the bridge retires its own
           per-registration descriptors without freeing them (bounded by the
           number of registrations ever made), but the embedder's cookie
           lifetime is the embedder's problem.

           64-bit guest processes only for now: registration in a 32-bit
           process is refused with -3 (the i386 lane keeps the trap
           protocol).                                                        */
#define FEXBRIDGE_ABI_VERSION 7u

/* ---- fexbridge_run() results ------------------------------------------- */
#define FEXBRIDGE_RUN_EXITED 0 /* trap callback returned FEXBRIDGE_TRAP_EXIT */
#define FEXBRIDGE_RUN_HLT 1    /* guest executed HLT */
#define FEXBRIDGE_RUN_FAULT 2  /* host fault in JIT code, unwound by
                                  fexbridge_fault_unwind; or a guest jump to
                                  unfetchable memory (Rip = the bad address,
                                  register file from CPUState between blocks) */
#define FEXBRIDGE_RUN_ERROR (-1)

/* ---- trap callback results --------------------------------------------- */
#define FEXBRIDGE_TRAP_CONTINUE 0 /* resume guest with the (modified) CONTEXT */
#define FEXBRIDGE_TRAP_EXIT 1     /* leave the innermost fexbridge_run */

/* ---- AMD64 CONTEXT, layout-identical to winnt.h CONTEXT for AMD64 ------ */
/* Callers that already have Wine/Windows headers may pass their own CONTEXT*
   (cast to void*); these definitions exist so a caller needs no Windows
   headers. Offsets are pinned by the asserts below.                        */
typedef struct fexbridge_m128a {
  uint64_t Low;
  int64_t High;
} FEXBRIDGE_M128A;

typedef struct fexbridge_xsave_format64 {
  uint16_t ControlWord;
  uint16_t StatusWord;
  uint8_t TagWord;
  uint8_t Reserved1;
  uint16_t ErrorOpcode;
  uint32_t ErrorOffset;
  uint16_t ErrorSelector;
  uint16_t Reserved2;
  uint32_t DataOffset;
  uint16_t DataSelector;
  uint16_t Reserved3;
  uint32_t MxCsr;
  uint32_t MxCsr_Mask;
  FEXBRIDGE_M128A FloatRegisters[8];
  FEXBRIDGE_M128A XmmRegisters[16];
  uint8_t Reserved4[96];
} FEXBRIDGE_XSAVE_FORMAT64;

typedef struct fexbridge_amd64_context {
  uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
  uint32_t ContextFlags;
  uint32_t MxCsr;
  uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
  uint32_t EFlags;
  uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
  uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
  uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
  uint64_t Rip;
  FEXBRIDGE_XSAVE_FORMAT64 FltSave;
  FEXBRIDGE_M128A VectorRegister[26];
  uint64_t VectorControl;
  uint64_t DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
}
#ifdef __cplusplus
__attribute__((aligned(16)))
#endif
FEXBRIDGE_AMD64_CONTEXT;

FEXBRIDGE_SASSERT(sizeof(FEXBRIDGE_AMD64_CONTEXT) == 1232, fexbridge_context_size);
FEXBRIDGE_SASSERT(offsetof(FEXBRIDGE_AMD64_CONTEXT, Rax) == 0x78, fexbridge_context_rax);
FEXBRIDGE_SASSERT(offsetof(FEXBRIDGE_AMD64_CONTEXT, Rip) == 0xF8, fexbridge_context_rip);
FEXBRIDGE_SASSERT(offsetof(FEXBRIDGE_AMD64_CONTEXT, FltSave) == 0x100, fexbridge_context_fltsave);

/* ContextFlags bits, same values as winnt.h CONTEXT_* for AMD64. */
#define FEXBRIDGE_CTX_AMD64 0x00100000u
#define FEXBRIDGE_CTX_CONTROL (FEXBRIDGE_CTX_AMD64 | 0x1u)        /* Rip, Rsp, EFlags, SegCs/SegSs */
#define FEXBRIDGE_CTX_INTEGER (FEXBRIDGE_CTX_AMD64 | 0x2u)        /* 14 GPRs (not Rsp/Rip) */
/* Ds/Es/Fs/Gs SELECTORS, read-only: the bridge owns the GDT. The 64-bit FS/GS
   BASES are not in a CONTEXT at all — see fexbridge_set_gs_base below.       */
#define FEXBRIDGE_CTX_SEGMENTS (FEXBRIDGE_CTX_AMD64 | 0x4u)
#define FEXBRIDGE_CTX_FLOATING_POINT (FEXBRIDGE_CTX_AMD64 | 0x8u) /* XMM0-15, x87, MXCSR */
#define FEXBRIDGE_CTX_FULL (FEXBRIDGE_CTX_CONTROL | FEXBRIDGE_CTX_INTEGER | FEXBRIDGE_CTX_FLOATING_POINT)

/* Lazy-trap markers (ABI 5).  Set by the bridge in a trap CONTEXT's
   ContextFlags when the embedder declared the group lazy: the group's bytes
   are NOT filled (or are poison under FEXBRIDGE_CTX_POISON=1) and its
   CONTEXT_* bit describes only the resume contract, not the content.
   fexbridge_ctx_materialize() fills the group and clears the marker.  The
   values sit outside every winnt.h AMD64 ContextFlags bit (those stop at
   CONTEXT_KERNEL_CET, 0x80) so a CONTEXT that leaves the trap path by being
   copied somewhere neutral carries them harmlessly.                        */
#define FEXBRIDGE_CTX_LAZY_EFLAGS (FEXBRIDGE_CTX_AMD64 | 0x100u)
#define FEXBRIDGE_CTX_LAZY_FLOAT  (FEXBRIDGE_CTX_AMD64 | 0x200u)

/* ------------------------------------------------------------------------ */

/* Compile-time vs runtime ABI check. */
uint32_t fexbridge_abi_version(void);

/* Optional: route bridge/FEXCore diagnostics somewhere better than stderr.
   level: 0 fatal/assert .. 5 debug. May be called before process_init.     */
typedef void (*fexbridge_log_fn)(int level, const char* message);
void fexbridge_set_log_handler(fexbridge_log_fn cb);

/* Once per process, before anything else (except set_log_handler).
   Returns 0 on success, negative on failure. Idempotent.                   */
int fexbridge_process_init(void);

/* 32-bit variant of process_init: the guest is i386, not x86-64.  Mutually
   exclusive with fexbridge_process_init() -- whichever runs first fixes the
   process's guest mode, and the other then fails with -5.

   exit_page names one page of 0xF4 (hlt) bytes the CALLER has allocated,
   made executable, and (if it manages emulator code visibility itself)
   published.  The bridge uses it as the cooperative-exit trampoline that a
   trap ending the run executes through.  It must be below 4 GiB: in 32-bit
   mode every address the guest executes from must fit the guest's address
   space, and only the embedder's own memory manager can place low pages
   without racing whatever else owns that range (Wine reserves it).  The
   64-bit init keeps allocating its own page precisely because it has no such
   constraint.  Zero, or a page at or above 4 GiB, is refused with -4.      */
int fexbridge_process_init32(uint64_t exit_page);

/* The trap callback. `thread` is the fexbridge thread handle the trap fired
   on; `ctx` is a FEXBRIDGE_AMD64_CONTEXT with the full guest state (see the
   trap protocol above); `user` is the pointer registered alongside.
   Return FEXBRIDGE_TRAP_CONTINUE or FEXBRIDGE_TRAP_EXIT.
   If NO handler is registered, a guest trap ends the run (RUN_EXITED) with
   Rip still at the trapping instruction.                                   */
typedef int (*fexbridge_trap_fn)(void* thread, void* ctx, void* user);
void fexbridge_set_trap_handler(fexbridge_trap_fn cb, void* user);

/* ---- lazy trap contexts (ABI 5) ---------------------------------------- */
/* Declare which trap-CONTEXT groups the embedder will materialize on demand
   instead of receiving eagerly on every crossing.  lazy_mask is a bitwise OR
   of FEXBRIDGE_CTX_LAZY_EFLAGS and FEXBRIDGE_CTX_LAZY_FLOAT (the AMD64 tag
   bit is tolerated and ignored).  Returns the mask actually in effect: 0
   when FEXBRIDGE_EAGER_CTX=1 vetoed it, and the environment's
   FEXBRIDGE_CTX_POISON is (re)sampled on every call.  Call it next to
   fexbridge_set_trap_handler, before the first run; it applies process-wide
   to every subsequent trap.

   THE CONTRACT the declaration buys into: for a declared group, the trap
   callback must call fexbridge_ctx_materialize() before it reads OR writes
   any field of that group.  Reads without it see unfilled bytes (poison
   under the lever); writes without it are ignored at resume.  The bridge
   parks its own resume bookkeeping in the CONTEXT's P2Home; a callback must
   leave P1Home..P6Home alone (winnt marks them spare, and nothing else on
   this path uses them).                                                    */
uint32_t fexbridge_declare_trap_ctx(uint32_t lazy_mask);

/* Fill the requested groups of a LAZY trap CONTEXT from the live guest state
   and clear their FEXBRIDGE_CTX_LAZY_* markers.  `thread` and `ctx` are the
   trap callback's own arguments -- this is only meaningful between trap
   entry and the callback's return, on the callback's own thread.  `flags`
   names the groups with the ordinary bits: FEXBRIDGE_CTX_CONTROL requests
   EFlags (the rest of the control group is always eager),
   FEXBRIDGE_CTX_FLOATING_POINT requests FltSave/MxCsr.  Idempotent: a group
   already materialized (or never lazy) is left exactly as is, so a callback
   may call it unconditionally on any path that touches the group.  Returns
   0, negative on a NULL argument.                                          */
int fexbridge_ctx_materialize(void* thread, void* ctx, uint32_t flags);

/* ---- zero-copy traps (ABI 6) ------------------------------------------- */
/* The view: pointers into the live guest register file, valid only from
   view-trap entry until the callback returns, on the callback's own thread.
   Both pointers alias CPUState, which is fully spilled for the whole trap
   window -- a write through them IS a write to guest state, applied at
   resume with no further copying.                                          */
typedef struct fexbridge_trap_view {
  uint64_t* gregs; /* the 16 guest GPRs in x86 encoding order:
                        RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15 */
  uint64_t* rip;   /* the live guest RIP.  On entry: the address OF the
                        trapping instruction (not advanced), exactly like the
                        CONTEXT protocol's Rip.  The callback owns it; return
                        without advancing and the trap re-executes.          */
  uint32_t reserved[4];
} FEXBRIDGE_TRAP_VIEW;

/* Convenience indices for view->gregs (x86 encoding order). */
#define FEXBRIDGE_GREG_RAX 0
#define FEXBRIDGE_GREG_RCX 1
#define FEXBRIDGE_GREG_RDX 2
#define FEXBRIDGE_GREG_RBX 3
#define FEXBRIDGE_GREG_RSP 4
#define FEXBRIDGE_GREG_RBP 5
#define FEXBRIDGE_GREG_RSI 6
#define FEXBRIDGE_GREG_RDI 7
#define FEXBRIDGE_GREG_R8 8
#define FEXBRIDGE_GREG_R9 9
#define FEXBRIDGE_GREG_R10 10
#define FEXBRIDGE_GREG_R11 11
#define FEXBRIDGE_GREG_R12 12
#define FEXBRIDGE_GREG_R13 13
#define FEXBRIDGE_GREG_R14 14
#define FEXBRIDGE_GREG_R15 15

/* Return FEXBRIDGE_TRAP_CONTINUE or FEXBRIDGE_TRAP_EXIT, same as the CONTEXT
   protocol; on EXIT the run leaves with *view->rip as the parked
   continuation.                                                            */
typedef int (*fexbridge_trap_view_fn)(void* thread, struct fexbridge_trap_view* view, void* user);

/* Register the view handler.  Takes precedence over the CONTEXT handler on
   every trap -- unless FEXBRIDGE_EAGER_CTX=1 is in the environment AT
   REGISTRATION TIME, which vetoes the view protocol process-wide (loudly)
   and leaves every trap on the CONTEXT handler.  Keep the CONTEXT handler
   registered: it is the veto's landing spot and the fallback for anything
   the view path cannot serve.  Same publication contract as
   fexbridge_set_trap_handler: register before the first run.               */
void fexbridge_set_trap_view_handler(fexbridge_trap_view_fn cb, void* user);

/* Cold-path CONTEXT bridge for view callbacks.  Callable between view-trap
   entry and the callback's return, on the callback's own thread (the same
   rule as fexbridge_ctx_materialize).  flags names groups with the ordinary
   FEXBRIDGE_CTX_* bits; the CONTEXT's own ContextFlags word is written by
   pull and IGNORED by push (the flags argument alone gates what push
   applies).
   pull fills the named groups of the caller's CONTEXT from live guest
   state: INTEGER and CONTROL are plain loads (CONTROL includes the
   reconstructed EFLAGS and CS/SS selectors); FLOATING_POINT is the full
   XMM/x87 store; SEGMENTS is the DS/ES/FS/GS selectors -- callers that
   synthesize selectors themselves (Wine does) can skip it.
   push writes the named groups back into live guest state: CONTROL applies
   Rip/Rsp and decomposes EFlags; INTEGER stores the 14 GPRs; FLOATING_POINT
   applies the full FP file.  Returns 0, negative on a NULL argument.       */
int fexbridge_view_pull(void* thread, void* amd64_ctx, uint32_t flags);
int fexbridge_view_push(void* thread, const void* amd64_ctx, uint32_t flags);

/* ---- EC targets (ABI 7) ------------------------------------------------- */
/* The EC handler.  `thread` is the fexbridge thread handle; `view` is the
   ABI 6 trap view (arg0 in RCX, not R10 -- see the 6->7 changelog);
   `cookie` is the registration's cookie.  Return FEXBRIDGE_TRAP_CONTINUE or
   FEXBRIDGE_TRAP_EXIT.                                                     */
typedef int (*fexbridge_ec_fn)(void* thread, struct fexbridge_trap_view* view, void* cookie);

/* Register `rip` to compile as a direct host call to `handler`.  Callable
   from any thread after process init; takes effect for every execution that
   dispatches to `rip` after the call returns (any ordinary block already
   compiled at exactly that address is invalidated here).  Idempotent for an
   identical (handler, cookie) pair.
   Returns 0 on success; -1 uninitialized/bad argument; -2 already registered
   with a DIFFERENT handler or cookie; -3 32-bit guest process.             */
int fexbridge_register_ec_target(uint64_t rip, fexbridge_ec_fn handler, void* cookie);

/* Remove every registration whose rip lies in [start, start+length) and
   invalidate the range so compiled transition blocks die with it.  Returns
   the number of registrations removed, or -1 uninitialized/bad argument.
   See the 6->7 changelog for handler/cookie lifetime.                      */
int fexbridge_unregister_ec_range(uint64_t start, uint64_t length);

/* Batch registration: every rip in rips[0..count) with ONE handler/cookie,
   ONE invalidation and ONE per-thread cache scrub over the whole span at the
   end.  Exists because per-target registration of a large module's stub
   array (ntdll: ~2400) costs a measurable stall -- ~1.1 ms -- inside
   whatever the guest was timing when the module armed.  Zero rips are
   skipped; a rip already registered with the SAME handler/cookie counts as
   standing; one claimed by anything else is skipped.  Returns the number of
   registrations standing from this call, or a negative from the same set as
   fexbridge_register_ec_target.  Same lifetime rules.                      */
int fexbridge_register_ec_targets(const uint64_t* rips, uint32_t count, fexbridge_ec_fn handler, void* cookie);

/* Create the guest-thread state for THE CALLING host thread. The guest
   register file starts zeroed; the first fexbridge_run's CONTEXT provides
   Rip/Rsp/etc. Returns 0 and a handle, negative on failure.                */
int fexbridge_thread_init(void** thread_out);

/* Destroy a guest thread. Must be called on the owning host thread, with no
   fexbridge_run active on it.                                              */
void fexbridge_thread_term(void* thread);

/* Execute the guest on the calling host thread.
   - On entry: if ctx is non-NULL, guest state is loaded from it according to
     ctx->ContextFlags (pass FEXBRIDGE_CTX_FULL for a fresh thread; EFlags
     0x202 is a sane initial value).
   - Runs until a trap callback returns FEXBRIDGE_TRAP_EXIT, the guest
     executes HLT, or a host fault is unwound into this run.
   - On return: if ctx is non-NULL it holds the complete final guest state
     (ContextFlags rewritten to CONTROL|INTEGER|SEGMENTS|FLOATING_POINT).
     After FEXBRIDGE_RUN_FAULT, ctx->Rip is the guest instruction that
     faulted, and the rest of the file is reconstructed from the host fault
     context (the T5 path). The thread remains usable: fix the cause (or
     redirect Rip) and call fexbridge_run again.
   Returns a FEXBRIDGE_RUN_* code.                                          */
int fexbridge_run(void* thread, void* ctx);

/* Read/write guest state of a NOT-currently-running thread (or the calling
   thread between runs). Honour ctx->ContextFlags in both directions.
   Inside a trap callback, use the callback's ctx instead. Returns 0.       */
int fexbridge_get_context(void* thread, void* ctx);
int fexbridge_set_context(void* thread, const void* ctx);

/* ---- 64-bit FS/GS segment bases ---------------------------------------- */
/* In 64-bit mode an FS/GS-prefixed access adds a full 64-bit base that has no
   home anywhere else in this ABI: a GDT descriptor carries only a 32-bit base,
   and an AMD64 CONTEXT carries selectors, not bases (which is why
   FEXBRIDGE_CTX_SEGMENTS is selectors-only and read-only). These four calls
   are that missing piece — the equivalent of Linux's
   arch_prctl(ARCH_SET_GS/ARCH_GET_GS/ARCH_SET_FS/ARCH_GET_FS), and of the base
   a WOW64 CPU module installs from the TEB.

   EVERY Windows x86-64 guest needs GS. The TEB self-pointer (gs:[0x30]), SEH,
   stack probes, TLS and the console-vs-GUI subsystem check all read through
   it. A guest that executes `movq %gs:0x30, %rax` with no base set
   dereferences absolute 0x30, takes a host SIGSEGV, and surfaces as
   FEXBRIDGE_RUN_FAULT — c0000005 to a Wine caller.

   CALLER CONTRACT
     - Per guest thread. Call once after fexbridge_thread_init() and before the
       first fexbridge_run() on that thread. Wine passes NtCurrentTeb(): its
       64-bit TEB/PEB field offsets already match what a Windows x86-64 guest
       expects, so the pointer needs no translation.
     - The base is part of the per-thread guest register file, so it does NOT
       need re-establishing on any transition: it persists across
       fexbridge_run() boundaries, across nested fexbridge_run(), across a trap
       callback round-trip (a CONTEXT carries no base, so none is clobbered),
       and across FEXBRIDGE_RUN_FAULT plus resume. fexbridge_set_context() does
       not touch it. It is per-thread and not inherited by other threads.
     - It IS overwritten if the guest loads the segment itself — a 32-bit-style
       `mov %ax, %gs` recomputes the base from the GDT, and WRGSBASE/WRFSBASE
       write it directly — exactly as on hardware.
     - FS exists for symmetry and for embedders running 32-bit or Linux-shaped
       guests. A Windows x86-64 guest does not use FS; leaving it 0 is correct.
       A 32-bit Windows guest (fexbridge_process_init32) reaches its TIB
       through FS: set it to the 32-bit TEB per thread.  In 32-bit mode the
       call also writes the FS descriptor in the emulated GDT, because a
       segment RELOAD (pop %fs / mov %ax,%fs) recomputes the cached base from
       the descriptor and must land on the same TIB.  The base must fit in
       32 bits there; a wider one is refused.  GS in 32-bit mode is the flat
       data selector and set_gs_base writes only the cached base (no 32-bit
       Windows ABI puts anything behind GS).
     - `thread` must not be executing: call from its own host thread between
       runs, or from inside the trap callback.
     - fexbridge_run_entry() creates a transient thread with no base set; use
       the primitives if the guest needs FS/GS.
   Return 0, negative on a bad argument.                                     */
int fexbridge_set_gs_base(void* thread, uint64_t base);
int fexbridge_get_gs_base(void* thread, uint64_t* base_out);
int fexbridge_set_fs_base(void* thread, uint64_t base);
int fexbridge_get_fs_base(void* thread, uint64_t* base_out);

/* Tell the emulator [start, start+length) may contain (new) guest code.
   Required after the caller writes guest instructions: PE section loads,
   relocations into executable pages, generated thunks, SMC detection.
   Callable from any thread; takes the code invalidation lock internally.   */
void fexbridge_invalidate_code_range(uint64_t start, uint64_t length);

/* ---- PROT_SAO hardware TSO (FEX_HWTSO), ppc64le ----------------------- */

/* Non-zero while hardware TSO is LIVE: the value is the mmap/mprotect PROT
   bit (PROT_SAO, 0x10) the caller must OR into every guest-visible mapping
   it creates or reprotects, because with it live the JIT emits NO TSO
   barriers and ordering is carried entirely by the pages.  Zero when the
   feature is off, was refused by the kernel at the startup probe, or has
   been revoked -- the JIT then emits barriers and the caller must stop
   adding the bit.  Decided during fexbridge_process_init*() from the same
   FEX_HWTSO/FEX_TSOENABLED configuration the frontend reads (litmus-proven
   semantics; see FEXInterpreter's SetupTSOEmulation); constant between
   calls except through fexbridge_hwtso_refused().  0 before process init. */
uint32_t fexbridge_hwtso_prot(void);

/* Report that the kernel refused a mapping or reprotection carrying the
   bit on ORDINARY memory (the caller retries without it after this call).
   Applies the frontend's refusal semantics: under FEX_HWTSO_STRICT it
   aborts naming the range; otherwise it revokes hardware TSO for the whole
   process -- every translation is dropped under the exclusive code
   invalidation lock and recompiles with barriers, the same closure
   FEX::HLE::SyscallHandler::RevokeHardwareTSO performs.  Returns the new
   fexbridge_hwtso_prot() value, i.e. 0.  Device/WC mappings the caller
   manages outside its page tables should simply never carry the bit; x86
   makes no TSO promise for WC memory, so no report is owed for them.      */
uint32_t fexbridge_hwtso_refused(uint64_t start, uint64_t length);

/* ---- fault handling, called from the CALLER's host signal handler ------ */

/* 1 if `host_ucontext` (a ppc64le ucontext_t*) points into this thread's JIT
   code — i.e. the fault belongs to the guest. 0 otherwise (fault is the
   caller's own, handle it natively). Safe to call on non-guest threads.    */
int fexbridge_fault_is_jit(const void* host_ucontext);

/* Reconstruct the guest register file from the host fault context and unwind
   to the innermost fexbridge_run on this thread, which returns
   FEXBRIDGE_RUN_FAULT. DOES NOT RETURN on success. Returns 0 (failure) if
   the PC is not in JIT code or no run is active — caller must then treat the
   fault as its own. Call only from the signal handler, on the faulting
   thread.                                                                  */
int fexbridge_fault_unwind(void* host_ucontext);

/* The thread handle bound to the calling host thread, or NULL. For signal
   handlers and TLS-less call sites.                                        */
void* fexbridge_current_thread(void);

/* ---- one-shot compatibility entry (Wine interim ABI) -------------------- */
/* Runs `entry(arg)` as MS-x64 guest code on the calling thread and returns
   when the entry returns (its return address is preloaded to a HLT
   trampoline; RCX = arg, 32-byte shadow space reserved, RSP ≡ 8 mod 16 at
   entry). Self-contained: performs process/thread init if needed, allocates
   and frees a guest stack. 0 on success with *rax_out = guest RAX; nonzero
   with err[] filled otherwise. A guest 0F 05 trap during the run is routed
   to the registered trap handler if any; with none it is an error. Prefer
   the primitives above for anything beyond "call one function".            */
int fexbridge_run_entry(void* entry, void* arg, unsigned long long* rax_out, char* err, unsigned int errlen);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* FEXBRIDGE_H */
