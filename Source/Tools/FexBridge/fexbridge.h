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
           gained a source.                                                */
#define FEXBRIDGE_ABI_VERSION 3u

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

/* The trap callback. `thread` is the fexbridge thread handle the trap fired
   on; `ctx` is a FEXBRIDGE_AMD64_CONTEXT with the full guest state (see the
   trap protocol above); `user` is the pointer registered alongside.
   Return FEXBRIDGE_TRAP_CONTINUE or FEXBRIDGE_TRAP_EXIT.
   If NO handler is registered, a guest trap ends the run (RUN_EXITED) with
   Rip still at the trapping instruction.                                   */
typedef int (*fexbridge_trap_fn)(void* thread, void* ctx, void* user);
void fexbridge_set_trap_handler(fexbridge_trap_fn cb, void* user);

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
