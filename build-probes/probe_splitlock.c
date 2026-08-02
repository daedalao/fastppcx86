// SPDX-License-Identifier: MIT
//
// probe_splitlock — x86 guest conformance probe for misaligned LOCK atomics.
//
// WHY THIS EXISTS
// ---------------
// FEX's ppc64le backend has two completely different implementations of an
// x86 LOCK-prefixed read-modify-write, selected at runtime by an alignment
// check on the effective address:
//
//   aligned    -> native lwarx/stwcx. (or lbarx/lharx/ldarx) reservation loop,
//                 bracketed hwsync ... isync.
//                 (FEXCore/Source/Interface/Core/JIT/PPC64LE/AtomicOps.cpp)
//   misaligned -> a call to PPC64_SplitLockEmulate(), which takes one of 64
//                 striped std::mutex and does memcpy-load / operate /
//                 memcpy-store.
//                 (FEXCore/Source/Utils/ArchHelpers/PPC64.cpp)
//
// The two mechanisms do not serialise against each other. A mutex does not
// stop an lwarx/stwcx. loop, and a reservation does not stop a memcpy. On x86
// both of these are the same instruction with the same guarantee, so a guest
// that mixes them sees a machine that violates its own architecture.
//
// Separately, CASPair (AtomicOps.cpp, the CMPXCHG8B path) handles a misaligned
// address with an inline non-atomic ld / cmpd / std and takes no mutex at all.
// In 32-bit guest code this is not an edge case: the i386 ABI aligns 8-byte
// types to 4 bytes, so a misaligned CMPXCHG8B is the *ordinary* case.
//
// This probe is the guest-side detector for those defects. It runs as an
// ordinary x86 program under FEX; it is not a FEX unit test and touches no
// FEX source.
//
// THE DESIGN RULE THAT MATTERS MOST
// ---------------------------------
// We have no x86 hardware to validate against, so every expected result here
// is derived from the Intel SDM, not from observation. Each subtest states an
// invariant that x86 guarantees unconditionally and is constructed so that the
// invariant holds under EVERY legal interleaving. There is therefore no such
// thing as a "racy failure" of this program: a reported FAIL is a proof that
// the implementation under test is not x86.
//
// The corollary is that a PASS is much weaker for some subtests than others,
// and the program says which is which rather than papering over it. Verdicts:
//
//   PASS    invariant checked, held, and the construction makes detection of
//           the defect near-certain if it is present. Real evidence.
//   FAIL    invariant violated. Proof of a bug. Never "maybe the test raced".
//   NOEVID  positive-only subtest; no violation seen. NOT evidence of
//           correctness — the window may simply never have opened.
//   VOID    the instrumentation says the race was never actually attempted, or
//           a control arm broke. The result means nothing; fix the harness.
//
// ARCHITECTURAL BASIS (Intel SDM Vol. 3A, ch. 9, "Multiple-Processor Management")
// ------------------------------------------------------------------------------
//   [A1] 9.1.2.1 / 9.1.2.2 — a LOCK-prefixed instruction performs an atomic
//        read-modify-write regardless of memory alignment; the processor falls
//        back to a bus lock when the operand is misaligned or crosses a cache
//        line. XCHG with a memory operand is locked implicitly.
//   [A2] 9.1.1 — the P6 family and later guarantee that unaligned 16-, 32- and
//        64-bit accesses to cached memory *that fit within a cache line* are
//        carried out atomically.
//   [A3] 9.2.3.9 — "Loads and stores are not reordered with locked
//        instructions." A LOCK-prefixed operation is a full barrier, including
//        StoreLoad, which is the one direction plain x86 TSO does not give.
//   [A4] 9.1.2.1 — CMPXCHG8B with a LOCK prefix is an atomic 64-bit
//        compare-and-swap. x86 does not require the operand to be aligned
//        (unlike CMPXCHG16B, which does).
//
// [A2] is the only place this file leans on an Intel-specific guarantee rather
// than a universal one; AMD's APM states a narrower rule (atomicity within an
// aligned 8-byte block). Subtest 2 is the only subtest that depends on it, and
// it is the weakest subtest here for unrelated reasons anyway.
//
// WHY INLINE ASM
// --------------
// No compiler will emit a misaligned locked RMW for you. __atomic builtins on
// a properly-typed object are aligned by construction and take the fast path,
// which is precisely the path that is NOT broken. Every operation under test is
// therefore written as explicit asm with a constant byte displacement, so the
// alignment of the effective address is a property of the source text and not
// of the register allocator's mood. Loop control uses `dec; jnz` throughout
// (ZF maps to CR0.EQ directly, no XER projection) — same reason bench_select.c
// does, so the scaffolding does not share a code path with the subject.
//
// WHAT THIS CANNOT TELL YOU
// -------------------------
// A lost update proves non-atomicity. It does NOT tell you which of the three
// mechanisms produced it (mutex-vs-reservation non-interlock, non-atomic memcpy
// store, or missing barriers), because all three manifest as a dropped
// increment. Attributing the cause needs the disassembly, not this program.
// See the per-subtest "A FAILURE PROVES" notes.
//
// CROSS-CHECK THAT THE PATH UNDER TEST WAS ACTUALLY TAKEN
// -------------------------------------------------------
// PPC64_SplitLockEmulate() bumps FEXCore telemetry TYPE_HAS_SPLIT_LOCKS on
// every entry. Telemetry is on by default and is dumped at process exit to
//   ~/.fex-emu/Telemetry/<appname>.telem
// as the line "64byte Split Locks: N". After a run N must be large (tens of
// millions at the default settings). If N is 0 the misaligned operations never
// reached the emulation path and every result in this program is void — check
// that the split-lock path is compiled in and check FEX's config for
// TSO/atomic-related overrides.
//
// BUILD
// -----
//   ROOT=/home/jbettcher/Development/fexrootfs        # or .../power9_development/fexrootfs
//   XT=$ROOT/x-tools
//
//   $XT/x86_64-linux-gnu/bin/x86_64-linux-gnu-gcc -O2 -Wall -pthread build-probes/probe_splitlock.c -o build-probes/probe_splitlock_64
//   $XT/i686-linux-gnu/bin/i686-linux-gnu-gcc     -O2 -Wall -pthread build-probes/probe_splitlock.c -o build-probes/probe_splitlock_32
//
// The i686 toolchain is already 32-bit targeted; no -m32 needed. Nothing here
// is called indirectly, so the missing endbr in the hand-written cas8_try is
// harmless; add -fcf-protection=none if a hardened toolchain complains.
//
// RUN
// ---
//   FEX ./build-probes/probe_splitlock_64
//   FEX ./build-probes/probe_splitlock_32
//
// Threads must land on different physical cores or the contention windows close
// and several arms go VOID (which the program will tell you). On the SMT2
// recipe used by the standing regression routine that is the default:
//
//   numactl --cpunodebind=0 --membind=0 FEX ./build-probes/probe_splitlock_64
//
// The 32-bit binary is the important one for subtest 4, because that is the
// bitness in which misaligned CMPXCHG8B is the common case.
//
// EXIT CODES  (deterministic; no window, no interaction, bounded runtime)
// ----------------------------------------------------------------------
//   0  PASS  — no x86 invariant was violated, every control held, and every
//              deterministic subtest proved its race was attempted.
//   1  FAIL  — at least one x86 invariant was violated on a non-control arm.
//              A proof that FEX is wrong.
//   2  VOID  — a control arm broke, or a deterministic subtest could not show
//              its race was ever attempted. Harness/host problem, not a FEX
//              verdict. Results untrusted.
//   3  ERROR — setup failure, or the watchdog fired (livelock/hang).
//
// The last line of output is always exactly one of
//   RESULT: PASS / RESULT: FAIL / RESULT: VOID / RESULT: ERROR
// which is what a regression script should key on. NOEVID on a positive-only
// arm never changes the exit code; it is counted and printed.
//
// BEHAVIOUR ON REAL x86 HARDWARE vs UNDER FEX
// -------------------------------------------
// Misaligned locked operations are legal but slow on real silicon, and modern
// Linux on modern Intel parts may enable split-lock detection
// (split_lock_detect=warn|fatal): a locked access crossing a cache line raises
// #AC and the kernel rate-limits or SIGBUSes the process. This probe keeps
// every misaligned locked operand inside a 64-byte cache line EXCEPT the lu64-*
// arms, which cross a 64-byte boundary on purpose to reach the two-stripe
// locking code in PPC64_SplitLockEmulate. On real hardware with
// split_lock_detect=fatal those two arms die with SIGBUS; that is a host kernel
// property, not a FEX result. Use --skip lu64 there. Under FEX there is no #AC
// and none of this applies.
//
// TUNABLES
//   --rounds N        lost-update rounds                    (default 40)
//   --iters N         RMWs per thread per round, <= 65535   (default 50000)
//   --sb-iters N      store-buffer litmus iterations        (default 400000)
//   --tear-iters N    torn-read writer iterations           (default 2000000)
//   --cas-iters N     CAS increments per thread             (default 300000)
//   --cas-threads N   threads on the CAS counter, 2..8      (default 2)
//   --no-jitter       disable the litmus inter-thread delay
//   --timeout S       watchdog, seconds                     (default 300)
//   --skip SUBSTR     skip arms whose name contains SUBSTR  (repeatable, <=8)
//   --only SUBSTR     run only arms whose name contains SUBSTR
//   --list            print the arm list and exit

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__i386__) && !defined(__x86_64__)
#error "probe_splitlock is x86 guest code; build it with the i686 or x86_64 cross toolchain."
#endif

// ---------------------------------------------------------------------------
// Verdict plumbing
// ---------------------------------------------------------------------------

typedef enum { V_PASS = 0, V_FAIL, V_NOEVID, V_VOID, V_SKIP } verdict_t;

static const char* verdict_name(verdict_t v) {
  switch (v) {
  case V_PASS:   return "PASS  ";
  case V_FAIL:   return "FAIL  ";
  case V_NOEVID: return "NOEVID";
  case V_VOID:   return "VOID  ";
  default:       return "SKIP  ";
  }
}

// is_control : arm that must hold on ANY correct implementation. A control
//              failure means the harness or the host is broken, and it outranks
//              every other verdict.
// void_fatal : whether a VOID from this arm should void the whole run. True for
//              the deterministic subtests (a VOID there means the race was
//              never attempted, which is a harness bug). False for the
//              positive-only subtests, where "no window opened" is an expected
//              and reportable outcome rather than a defect in the test.
#define MAX_ARMS 32
static struct {
  const char* name;
  verdict_t   v;
  int         is_control;
  int         void_fatal;
  char        detail[224];
} g_res[MAX_ARMS];
static int g_nres;

static void record(const char* name, int is_control, int void_fatal, verdict_t v, const char* fmt, ...) {
  va_list ap;
  if (g_nres >= MAX_ARMS) {
    return;
  }
  g_res[g_nres].name = name;
  g_res[g_nres].v = v;
  g_res[g_nres].is_control = is_control;
  g_res[g_nres].void_fatal = void_fatal;
  va_start(ap, fmt);
  vsnprintf(g_res[g_nres].detail, sizeof(g_res[g_nres].detail), fmt, ap);
  va_end(ap);
  printf("  [%s] %-24s %s%s\n", verdict_name(v), name, g_res[g_nres].detail, is_control ? "   (control)" : "");
  fflush(stdout);
  g_nres++;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

static unsigned long opt_rounds      = 40;
static unsigned long opt_iters       = 50000; // must be <= 65535, see lane check
static unsigned long opt_sb_iters    = 400000;
static unsigned long opt_tear_iters  = 2000000;
static unsigned long opt_cas_iters   = 300000;
static int           opt_cas_threads = 2;
static int           opt_jitter      = 1;
static unsigned long opt_timeout     = 300;
static const char*   opt_only        = NULL;
static const char*   opt_skip[8];
static int           opt_nskip = 0;
static int           opt_list  = 0;

static int arm_enabled(const char* name) {
  int i;
  if (opt_only && !strstr(name, opt_only)) {
    return 0;
  }
  for (i = 0; i < opt_nskip; i++) {
    if (strstr(name, opt_skip[i])) {
      return 0;
    }
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Watchdog. Every subtest can in principle livelock (a starved reservation
// loop, a CAS that never wins). A regression gate that hangs is worse than one
// that fails, so SIGALRM does an async-signal-safe write and _exit(3).
// ---------------------------------------------------------------------------

static void on_alarm(int sig) {
  static const char msg[] = "\nprobe_splitlock: WATCHDOG fired, aborting\nRESULT: ERROR\n";
  (void)sig;
  if (write(1, msg, sizeof(msg) - 1) < 0) {
    /* nothing useful to do in a signal handler */
  }
  _exit(3);
}

// ---------------------------------------------------------------------------
// Guest asm primitives.
//
// Everything below hard-codes its byte displacement so the alignment of the
// effective address is fixed by the source and cannot be perturbed by codegen.
// `base` is always a page-aligned pointer, so `off` is also the offset within
// the host cache line: FEX maps guest pages to host pages, and both the POWER
// cache line (128 B) and the 64-byte granularity of the split-lock stripe hash
// divide 4096, so a page-aligned guest allocation preserves offsets modulo 64
// and 128 on the host side. (Assumption, stated plainly: it holds for FEX's
// page-aligned guest->host mapping. If that ever gains a sub-page offset, the
// lu64-* arms lose their two-stripe property but every arm stays sound.)
// ---------------------------------------------------------------------------

// `lock add<sfx> $unit, off(base)` repeated n times.
//   "+&r"(n)  n is read and written; early-clobber so the allocator cannot
//             alias it with base.
//   "r"(base) must be a register; the displacement is the literal `off`.
//   "memory"  the loop writes memory the compiler cannot see.
//   "cc"      lock add writes flags.
#define DEF_ADD_LOOP(name, sfx, off, unit)                                                                             \
  static void name(volatile unsigned char* base, unsigned long n) {                                                    \
    if (!n) {                                                                                                          \
      return;                                                                                                          \
    }                                                                                                                  \
    __asm__ __volatile__("1:\n\t"                                                                                      \
                         "lock add" sfx " $" #unit ", " #off "(%[b])\n\t"                                              \
                         "dec %[n]\n\t"                                                                                \
                         "jnz 1b\n\t"                                                                                  \
                         : [n] "+&r"(n)                                                                                \
                         : [b] "r"(base)                                                                               \
                         : "memory", "cc");                                                                            \
  }

// 32-bit operands. Offset 3 is misaligned, offset 4 is aligned (base is page
// aligned). Both stay inside the first 64-byte line.
DEF_ADD_LOOP(add32_o3_u00000100, "l", 3, 0x00000100)
DEF_ADD_LOOP(add32_o3_u00000001, "l", 3, 0x00000001)
DEF_ADD_LOOP(add32_o3_u00010000, "l", 3, 0x00010000)
DEF_ADD_LOOP(add32_o4_u00000001, "l", 4, 0x00000001)
DEF_ADD_LOOP(add32_o4_u00010000, "l", 4, 0x00010000)

#ifdef __x86_64__
// 64-bit operands. Offset 61 is misaligned AND spans the 64-byte boundary at
// 64, which is the only way to reach the two-stripe path in
// PPC64_SplitLockEmulate.
DEF_ADD_LOOP(add64_o61_u01000000, "q", 61, 0x01000000)
DEF_ADD_LOOP(add64_o64_u01000000, "q", 64, 0x01000000)
DEF_ADD_LOOP(add64_o64_u00000001, "q", 64, 0x00000001)
#endif

// Torn-read writer: alternate the 4 bytes at `off` between two patterns using
// XCHG, which is locked implicitly with a memory operand [A1]. The patterns are
// immediates inside the asm so the loop needs only two registers, which matters
// on i386 under PIC where EBX is unavailable to the allocator.
#define DEF_TEAR_WRITER(name, off)                                                                                     \
  static void name(volatile unsigned char* base, unsigned long n) {                                                    \
    if (!n) {                                                                                                          \
      return;                                                                                                          \
    }                                                                                                                  \
    __asm__ __volatile__("1:\n\t"                                                                                      \
                         "movl $0xAAAAAAAA, %%eax\n\t"                                                                 \
                         "xchgl %%eax, " #off "(%[b])\n\t"                                                             \
                         "movl $0x55555555, %%eax\n\t"                                                                 \
                         "xchgl %%eax, " #off "(%[b])\n\t"                                                             \
                         "dec %[n]\n\t"                                                                                \
                         "jnz 1b\n\t"                                                                                  \
                         : [n] "+&r"(n)                                                                                \
                         : [b] "r"(base)                                                                               \
                         : "eax", "memory", "cc");                                                                     \
  }

// Offset 14: misaligned, crosses the 16-byte boundary at 16 (the granule a
// POWER LSU is most likely to split an unaligned access on), and stays inside
// one 64-byte cache line so [A2] applies to the reader.
DEF_TEAR_WRITER(tear_write_o14, 14)
// Offset 16: aligned control, same cache line.
DEF_TEAR_WRITER(tear_write_o16, 16)

#define DEF_TEAR_READER(name, off)                                                                                     \
  static unsigned int name(volatile unsigned char* base) {                                                             \
    unsigned int v;                                                                                                    \
    __asm__ __volatile__("movl " #off "(%[b]), %[v]" : [v] "=r"(v) : [b] "r"(base) : "memory");                        \
    return v;                                                                                                          \
  }
DEF_TEAR_READER(tear_read_o14, 14)
DEF_TEAR_READER(tear_read_o16, 16)

// Store-buffer litmus step: store 1 to my flag, execute FENCE, load the peer's
// flag. FENCE is a locked RMW at a per-thread private address (see subtest 3 —
// if the two threads shared a fence address the split-lock stripe mutex would
// serialise them and hide the defect). The fence op adds 1 rather than 0 so its
// execution count is checkable afterwards.
#define DEF_SB_STEP(name, FENCE)                                                                                       \
  static int name(volatile int* my, volatile int* peer, volatile unsigned char* f) {                                   \
    int r;                                                                                                             \
    __asm__ __volatile__("movl $1, (%[my])\n\t" FENCE "movl (%[peer]), %[r]\n\t"                                       \
                         : [r] "=&r"(r)                                                                                \
                         : [my] "r"(my), [peer] "r"(peer), [f] "r"(f)                                                  \
                         : "memory", "cc");                                                                            \
    return r;                                                                                                          \
  }
DEF_SB_STEP(sb_step_nofence, "")
DEF_SB_STEP(sb_step_misaligned, "lock addl $1, 3(%[f])\n\t")
DEF_SB_STEP(sb_step_aligned, "lock addl $1, 0(%[f])\n\t")

static void cpu_relax(void) {
  __asm__ __volatile__("pause" ::: "memory");
}

// ---------------------------------------------------------------------------
// cas8_try — one attempt at `lock cmpxchg8b`.
//
// Written as a file-scope assembly function rather than inline asm because
// CMPXCHG8B wants EDX:EAX and ECX:EBX, and on 32-bit PIC EBX is the GOT
// register and unavailable to the register allocator. Every "clever" inline
// formulation (xchg %ebx around the instruction, a "g" constraint that turns
// out to be %esp-relative across a push) has a way to be subtly wrong. This has
// none: the register assignment is written out.
//
//   int cas8_try(void* p, uint64_t expected, uint64_t desired, uint64_t* obs)
//     returns 1 if the CAS succeeded (ZF set), 0 otherwise.
//     *obs always receives the value that was actually in memory.
// ---------------------------------------------------------------------------

__attribute__((visibility("hidden"))) extern int cas8_try(volatile void* p, uint64_t expected, uint64_t desired,
                                                          uint64_t* obs);

__asm__(".text\n"
        ".globl cas8_try\n"
        ".hidden cas8_try\n"
        ".type cas8_try,@function\n"
        ".align 16\n"
        "cas8_try:\n"
#ifdef __i386__
        // cdecl: 8(%ebp)=p  12/16=expected lo/hi  20/24=desired lo/hi  28=obs
        "  push %ebp\n"
        "  mov  %esp, %ebp\n"
        "  push %ebx\n"
        "  push %esi\n"
        "  mov  8(%ebp),  %esi\n"
        "  mov  12(%ebp), %eax\n"
        "  mov  16(%ebp), %edx\n"
        "  mov  20(%ebp), %ebx\n"
        "  mov  24(%ebp), %ecx\n"
        "  lock cmpxchg8b (%esi)\n"
        "  setz %cl\n" // ecx is dead after the instruction
        "  mov  28(%ebp), %esi\n"
        "  mov  %eax, (%esi)\n"
        "  mov  %edx, 4(%esi)\n"
        "  movzbl %cl, %eax\n"
        "  pop  %esi\n"
        "  pop  %ebx\n"
        "  pop  %ebp\n"
        "  ret\n"
#else
        // SysV: rdi=p  rsi=expected  rdx=desired  rcx=obs
        "  push %rbx\n"
        "  mov  %rcx, %r8\n"  // obs, before rcx is reused for desired-hi
        "  mov  %edx, %ebx\n" // desired lo (do desired first, rdx dies)
        "  shr  $32, %rdx\n"
        "  mov  %edx, %ecx\n" // desired hi
        "  mov  %esi, %eax\n" // expected lo
        "  shr  $32, %rsi\n"
        "  mov  %esi, %edx\n" // expected hi
        "  lock cmpxchg8b (%rdi)\n"
        "  setz %r9b\n"
        "  mov  %eax, (%r8)\n"
        "  mov  %edx, 4(%r8)\n"
        "  movzbl %r9b, %eax\n"
        "  pop  %rbx\n"
        "  ret\n"
#endif
        ".size cas8_try,.-cas8_try\n");

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

static unsigned char* alloc_page(void) {
  void* p = NULL;
  if (posix_memalign(&p, 4096, 4096) != 0 || !p) {
    return NULL;
  }
  memset(p, 0, 4096);
  return (unsigned char*)p;
}

static double now_s(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

// Infinite-precision little-endian add of `v` at byte offset `off`, used to
// build the expected image of the shared region. It matches the hardware only
// because the lane check in run_lu_arm() proves no addition ever carries out of
// its operand. That check is what makes this model exact rather than
// approximate, and it runs before every arm.
static void add_at(unsigned char* r, size_t rlen, size_t off, uint64_t v) {
  unsigned carry = 0;
  size_t i;
  for (i = off; i < rlen && (v || carry); i++) {
    unsigned s = (unsigned)r[i] + (unsigned)(v & 0xFF) + carry;
    r[i] = (unsigned char)s;
    carry = s >> 8;
    v >>= 8;
  }
}

static uint64_t extract_bits(const unsigned char* r, unsigned lo, unsigned hi) {
  uint64_t v = 0;
  unsigned i;
  for (i = 0; i <= hi - lo; i++) {
    unsigned bit = lo + i;
    if (r[bit >> 3] & (1u << (bit & 7))) {
      v |= (uint64_t)1 << i;
    }
  }
  return v;
}

static unsigned highest_bit(uint64_t v) {
  unsigned b = 0;
  while (v >>= 1) {
    b++;
  }
  return b;
}

static unsigned lowest_bit(uint64_t v) {
  unsigned b = 0;
  while (v && !(v & 1)) {
    v >>= 1;
    b++;
  }
  return b;
}

// ===========================================================================
// SUBTEST 1 — LOST UPDATE
//
// INVARIANT
//   Two LOCK RMWs whose operands overlap are atomic with respect to each other
//   [A1]. Give each thread a bit-lane that lives inside the overlap and that
//   the other thread's operation adds zero to, and every legal interleaving
//   produces exactly the same final memory image: each lane holds its own
//   thread's iteration count, and every other bit is untouched.
//
//   For the headline arm:
//     thread 0: lock addl $0x00000100, 3(base)   -> writes bytes 3..6
//     thread 1: lock addl $0x00010000, 4(base)   -> writes bytes 4..7
//   The operands overlap on bytes 4,5,6. Thread 0's addend is zero in the bits
//   that are thread 1's lane and vice versa, so an atomic RMW passes the other
//   thread's lane through untouched. After N iterations each, the region must
//   read exactly (N << 32) | (N << 48), and nothing else is possible.
//
//   The startup lane check proves arithmetically that N*unit never carries out
//   of its lane and that the two lanes are disjoint. If it fails the program
//   exits 3 rather than reporting a result: the invariant is machine-verified,
//   not asserted in a comment.
//
// DETERMINISM
//   Fully deterministic expected value, and effectively deterministic
//   detection: the whole region is one cache line, both threads hammer it for
//   tens of thousands of iterations per round, and a SINGLE lost increment
//   anywhere in the run fails the check. A false negative requires the two
//   threads never to have been concurrent, which the overlap witness below
//   tests for directly — zero witnesses is VOID, not PASS.
//
// A FAILURE PROVES
//   The implementation does not provide atomic RMW for at least one of the two
//   operand alignments. It does NOT identify the mechanism. A short count in
//   lane 1 with lane 0 exact is the signature predicted for the
//   mutex-vs-reservation non-interlock (the reservation granule protects the
//   aligned side from the misaligned side's stores, so the misaligned operation
//   is the one that loses), but the program does not assume that — it reports
//   both lanes and lets you read the signature yourself.
//
// ARMS
//   lu32-mis-vs-aligned      the defect: misaligned RMW vs aligned RMW.
//   lu32-aligned-vs-aligned  CONTROL: both on the LL/SC path.
//   lu32-mis-vs-mis          diagnostic: both on the mutex path. Expected to
//                            pass, because the stripe hash puts overlapping
//                            operands in the same stripe. A failure here is a
//                            different and worse bug (broken striping).
//   lu64-mis-vs-aligned      64-bit; the misaligned operand spans the 64-byte
//                            stripe boundary, reaching the two-stripe locking
//                            code. x86_64 only.
//   lu64-aligned-vs-aligned  CONTROL for the above.
// ===========================================================================

// LU_CHUNKS controls how finely each thread publishes its progress, and it is
// load-bearing for the overlap witness rather than cosmetic. The two threads in
// the mis-vs-aligned arms have very different throughput — one is a function
// call plus a mutex, the other is an lwarx/stwcx. loop — so the fast thread can
// finish its whole round while the slow thread is still inside its first chunk.
// With 64 chunks the fast thread only fails to witness the slow one if the
// throughput ratio exceeds 64x, which is well outside anything plausible here.
// The witness is also taken at EVERY chunk boundary, not just the midpoint, and
// a witness from EITHER thread counts.
#define LU_REGION 128
#define LU_CHUNKS 64

typedef void (*add_fn_t)(volatile unsigned char*, unsigned long);

typedef struct {
  const char* name;
  int         is_control;
  // Whether a VOID from this arm should void the entire run. True only for the
  // arms that carry the headline claim: if the subject arm's race was never
  // attempted, its silence means nothing and the gate must say so. A control or
  // diagnostic arm that failed to overlap is worth printing but is not a reason
  // to discard the run — notably lu32-mis-vs-mis, where both threads contend on
  // the same stripe mutex and can convoy (one thread runs its whole round while
  // the other waits), which is genuine non-overlap rather than a harness fault.
  int      void_fatal;
  add_fn_t fn[2];
  unsigned off[2];     // byte displacement of the operand
  unsigned opbytes[2]; // 4 or 8
  uint64_t unit[2];    // the immediate added
} lu_arm_t;

typedef struct {
  int                     tid;
  volatile unsigned char* region;
  const lu_arm_t*         arm;
  unsigned long           n;
  unsigned long           rounds;
  pthread_barrier_t*      bar;
  volatile unsigned long* my_prog;
  volatile unsigned long* peer_prog;
  unsigned long           witnesses;
  double                  busy; // seconds spent inside the RMW loops
} lu_ctx_t;

// Progress counters, each on its own cache line so the witness sampling does
// not itself create the contention it is trying to measure.
static volatile unsigned long g_lu_prog[2 * 32] __attribute__((aligned(128)));
#define LU_PROG(i) (&g_lu_prog[(i) * 32])

// One round of work for one thread, split into chunks so progress is visible.
static void lu_round(lu_ctx_t* c) {
  const unsigned long per = c->n / LU_CHUNKS;
  unsigned long       done = 0;
  unsigned long       first_peer = 0, last_peer = 0;
  int                 witness = 0;
  unsigned            k;
  double              t0 = now_s();

  for (k = 0; k < LU_CHUNKS; k++) {
    unsigned long chunk = (k == LU_CHUNKS - 1) ? (c->n - done) : per;
    unsigned long peer;
    c->arm->fn[c->tid](c->region, chunk);
    done += chunk;
    *c->my_prog = done;

    // Overlap witness. Two independent ways to establish that the peer was
    // executing its RMW loop while we were executing ours — this is the direct
    // answer to "how do you know the race was actually attempted":
    //   (a) at this instant the peer had started and not finished, or
    //   (b) the peer's counter advanced between two of our own samples, which
    //       can only happen if it did work inside our round.
    // (b) matters because with a large throughput skew the fast thread may only
    // ever catch the slow one at 0 or at n.
    peer = *c->peer_prog;
    if (peer > 0 && peer < c->n) {
      witness = 1;
    }
    if (k == 0) {
      first_peer = peer;
    }
    last_peer = peer;
  }
  if (last_peer != first_peer) {
    witness = 1;
  }

  c->busy += now_s() - t0;
  if (witness) {
    c->witnesses++;
  }
}

static void* lu_thread(void* argp) {
  lu_ctx_t*     c = (lu_ctx_t*)argp;
  unsigned long r;

  for (r = 0; r < c->rounds; r++) {
    *c->my_prog = 0;
    pthread_barrier_wait(c->bar); // region zeroed by thread 0, progress reset
    lu_round(c);
    pthread_barrier_wait(c->bar); // both done; thread 0 checks and re-zeroes
  }
  return NULL;
}

static void run_lu_arm(const lu_arm_t* arm) {
  unsigned char*    page;
  unsigned char     expect[LU_REGION];
  pthread_barrier_t bar;
  pthread_t         th;
  lu_ctx_t          ctx[2];
  unsigned long     r, bad_rounds = 0, witnesses;
  unsigned          lo[2], hi[2];
  int               i;
  char              first_detail[160];

  if (!arm_enabled(arm->name)) {
    record(arm->name, arm->is_control, arm->void_fatal, V_SKIP, "skipped");
    return;
  }

  // --- lane check: this is what makes the expected value a proof -----------
  for (i = 0; i < 2; i++) {
    uint64_t total = (uint64_t)opt_iters * arm->unit[i];
    unsigned top   = highest_bit(total);
    if (top >= arm->opbytes[i] * 8) {
      fprintf(stderr, "lane check: %s thread %d overflows its %u-byte operand\n", arm->name, i, arm->opbytes[i]);
      exit(3);
    }
    lo[i] = arm->off[i] * 8 + lowest_bit(arm->unit[i]);
    hi[i] = arm->off[i] * 8 + top;
  }
  if (!(hi[0] < lo[1] || hi[1] < lo[0])) {
    fprintf(stderr, "lane check: %s lanes overlap ([%u,%u] vs [%u,%u])\n", arm->name, lo[0], hi[0], lo[1], hi[1]);
    exit(3);
  }

  page = alloc_page();
  if (!page) {
    record(arm->name, arm->is_control, arm->void_fatal, V_VOID, "allocation failed");
    return;
  }

  memset(expect, 0, sizeof(expect));
  add_at(expect, sizeof(expect), arm->off[0], (uint64_t)opt_iters * arm->unit[0]);
  add_at(expect, sizeof(expect), arm->off[1], (uint64_t)opt_iters * arm->unit[1]);

  pthread_barrier_init(&bar, NULL, 2);
  for (i = 0; i < 2; i++) {
    ctx[i].tid       = i;
    ctx[i].region    = page;
    ctx[i].arm       = arm;
    ctx[i].n         = opt_iters;
    ctx[i].rounds    = opt_rounds;
    ctx[i].bar       = &bar;
    ctx[i].my_prog   = LU_PROG(i);
    ctx[i].peer_prog = LU_PROG(1 - i);
    ctx[i].witnesses = 0;
    ctx[i].busy      = 0.0;
  }

  if (pthread_create(&th, NULL, lu_thread, &ctx[1]) != 0) {
    record(arm->name, arm->is_control, arm->void_fatal, V_VOID, "pthread_create failed");
    pthread_barrier_destroy(&bar);
    free(page);
    return;
  }

  // Thread 0 runs inline so it can do the per-round zeroing and checking
  // between the two barriers without a third rendezvous.
  first_detail[0] = 0;
  for (r = 0; r < opt_rounds; r++) {
    memset(page, 0, LU_REGION);
    *ctx[0].my_prog = 0;
    pthread_barrier_wait(&bar);

    lu_round(&ctx[0]);

    pthread_barrier_wait(&bar);

    if (memcmp(page, expect, LU_REGION) != 0) {
      bad_rounds++;
      if (!first_detail[0]) {
        uint64_t l0 = extract_bits(page, lo[0], hi[0]);
        uint64_t l1 = extract_bits(page, lo[1], hi[1]);
        snprintf(first_detail, sizeof(first_detail), "lane0 %" PRIu64 "/%lu lane1 %" PRIu64 "/%lu", l0, opt_iters, l1,
                 opt_iters);
      }
    }
  }

  pthread_join(th, NULL);
  pthread_barrier_destroy(&bar);
  // A witness from EITHER thread is proof the two were mid-flight together.
  witnesses = ctx[0].witnesses > ctx[1].witnesses ? ctx[0].witnesses : ctx[1].witnesses;
  // Throughput asymmetry is worth printing on its own: a mis-vs-aligned arm
  // where one side is orders of magnitude slower is exactly the shape that
  // erodes an overlap window, and it is also a standalone finding.
  {
    double ratio = (ctx[0].busy > 0.0 && ctx[1].busy > 0.0)
                     ? (ctx[0].busy > ctx[1].busy ? ctx[0].busy / ctx[1].busy : ctx[1].busy / ctx[0].busy)
                     : 0.0;

    if (bad_rounds) {
      record(arm->name, arm->is_control, arm->void_fatal, V_FAIL, "%lu/%lu rounds lost updates; first: %s (witness %lu/%lu, skew %.1fx)",
             bad_rounds, opt_rounds, first_detail, witnesses, opt_rounds, ratio);
    } else if (witnesses == 0) {
      record(arm->name, arm->is_control, arm->void_fatal, V_VOID,
             "no round had both threads mid-flight together (skew %.1fx) — race not attempted", ratio);
    } else {
      record(arm->name, arm->is_control, arm->void_fatal, V_PASS, "%lu rounds x %lu ops exact (witness %lu/%lu, skew %.1fx)",
             opt_rounds, opt_iters, witnesses, opt_rounds, ratio);
    }
  }
  free(page);
}

// ===========================================================================
// SUBTEST 2 — TORN READ
//
// INVARIANT
//   The writer performs `xchgl` on 4 bytes at a misaligned address. XCHG with a
//   memory operand is locked implicitly, so the write is atomic [A1]. The
//   operand sits at offset 14 of a page: misaligned, crossing the 16-byte
//   boundary at 16, and entirely inside one 64-byte cache line. The reader does
//   a plain unaligned 4-byte load of the same address, which is itself atomic
//   by [A2] because it fits within a cache line. Two atomic accesses to the
//   same bytes cannot interleave, so the reader must observe 0xAAAAAAAA or
//   0x55555555 and nothing else.
//
// DETERMINISM — READ THIS BEFORE BELIEVING A PASS
//   Positive-only and LOW POWER. A failure requires the reader to sample
//   between the two halves of a split host store, a window of a couple of
//   cycles at most, and it is entirely possible that the POWER LSU makes both
//   halves of an unaligned store within a cache line visible atomically — in
//   which case the true hit rate is exactly zero even though the code is
//   architecturally wrong. NOEVID here means "we did not catch it", never "it
//   does not happen". It does not contribute to the exit code.
//
//   The geometry is forced, and this is worth understanding before anyone tries
//   to "fix" the test by using an aligned observer: any naturally-aligned
//   access is contained within every power-of-two-aligned block at least as
//   large as itself, so an aligned observer can never straddle a hardware split
//   point. The observer must be unaligned, which is why this subtest and only
//   this subtest depends on [A2]. There is no sound construction that avoids
//   it — a locked observer would be serialised by the same stripe mutex, and an
//   observer straddling a 64-byte boundary is outside x86's own guarantee.
//
// INSTRUMENTATION
//   The reader counts value transitions. Zero transitions means it never once
//   saw the writer change the location, i.e. the two never overlapped in time,
//   and the arm is VOID rather than NOEVID.
//
// A FAILURE PROVES
//   The misaligned locked store is not single-copy atomic — the memcpy store in
//   PPC64_SplitLockEmulate is being split by the hardware. It does not
//   implicate the mutex or the barriers.
//
// ARMS
//   tear-misaligned  the defect.
//   tear-aligned     CONTROL: aligned 4-byte xchg and aligned 4-byte load. A
//                    failure here means the harness or the host is broken.
// ===========================================================================

typedef struct {
  volatile unsigned char* page;
  unsigned long           n;
  void (*writer)(volatile unsigned char*, unsigned long);
  volatile int started;
  volatile int done;
} tear_ctx_t;

static void* tear_writer_thread(void* argp) {
  tear_ctx_t* c = (tear_ctx_t*)argp;
  c->started    = 1;
  c->writer(c->page, c->n);
  c->done = 1;
  return NULL;
}

static void run_tear_arm(const char* name, int is_control, unsigned off, void (*writer)(volatile unsigned char*, unsigned long),
                         unsigned int (*reader)(volatile unsigned char*)) {
  unsigned char* page;
  pthread_t      th;
  tear_ctx_t     ctx;
  unsigned long  reads = 0, transitions = 0, torn = 0;
  unsigned int   prev, bad_value = 0;

  if (!arm_enabled(name)) {
    record(name, is_control, 0, V_SKIP, "skipped");
    return;
  }
  page = alloc_page();
  if (!page) {
    record(name, is_control, 1, V_VOID, "allocation failed");
    return;
  }
  // Seed with one of the two legal patterns so a read landing before the writer
  // starts cannot be mistaken for a tear.
  memcpy(page + off, "\x55\x55\x55\x55", 4);

  ctx.page    = page;
  ctx.n       = opt_tear_iters;
  ctx.writer  = writer;
  ctx.started = 0;
  ctx.done    = 0;
  if (pthread_create(&th, NULL, tear_writer_thread, &ctx) != 0) {
    record(name, is_control, 1, V_VOID, "pthread_create failed");
    free(page);
    return;
  }
  // `started` latches and is never cleared, so a writer that finishes early
  // cannot leave this spinning.
  while (!ctx.started) {
    cpu_relax();
  }

  prev = reader(page);
  while (!ctx.done) {
    unsigned int v = reader(page);
    reads++;
    if (v != prev) {
      transitions++;
      prev = v;
    }
    if (v != 0xAAAAAAAAu && v != 0x55555555u) {
      if (!torn) {
        bad_value = v;
      }
      torn++;
    }
  }
  pthread_join(th, NULL);

  if (torn) {
    record(name, is_control, 0, V_FAIL, "%lu torn reads in %lu (first 0x%08x; legal: AAAAAAAA/55555555)", torn, reads,
           bad_value);
  } else if (transitions == 0) {
    record(name, is_control, 0, V_VOID, "no value change in %lu reads — never overlapped the writer", reads);
  } else {
    record(name, is_control, 0, V_NOEVID, "%lu reads, %lu transitions, 0 torn (positive-only, not proof)", reads,
           transitions);
  }
  free(page);
}

// ===========================================================================
// SUBTEST 3 — STORE/LOAD ORDERING ACROSS A LOCKED OPERATION
//
// INVARIANT
//   Classic store-buffer (Dekker) litmus:
//       T0:  x = 1;  <locked op>;  r0 = y;
//       T1:  y = 1;  <locked op>;  r1 = x;
//   x86 does not reorder loads or stores with locked instructions [A3], so in
//   T0 the store to x is globally visible before y is read, and symmetrically
//   in T1. Therefore r0 == 0 && r1 == 0 is impossible when a locked operation
//   separates the store from the load.
//
//   FEX's misaligned path emits no hwsync/isync bracket at all (contrast the
//   aligned path, which emits both). The C++ mutex it takes instead gives at
//   best acquire on lock and release on unlock, which on POWER is
//   lwarx/stwcx./isync and lwsync — neither orders an earlier store against a
//   later load. FEX's plain guest loads and stores are lowered as lwsync-based
//   acquire/release (MemoryOps.cpp, LoadMemTSO / StoreMemTSO), which also
//   permits StoreLoad reordering. So the reordering is architecturally possible
//   on this backend, and the aligned path's hwsync is what makes the control
//   arm safe.
//
// DETERMINISM — READ THIS BEFORE BELIEVING A PASS
//   Positive-only and probabilistic. That is why the arm list includes an
//   UNFENCED arm: on x86 the unfenced shape is ALLOWED to produce r0==r1==0
//   (that is just TSO's store buffer), so it is not a violation — it is a
//   sensitivity calibration. Its firing rate is the upper bound on this
//   harness's ability to see StoreLoad reordering at all.
//
//     unfenced fires, misaligned does not -> real sensitivity, saw nothing.
//                                            Report both rates; claim nothing.
//     unfenced never fires                -> the harness has no power on this
//                                            machine. Subtest 3 is VOID. Do NOT
//                                            read the misaligned arm's silence
//                                            as a pass. This is the "15 trials
//                                            cannot establish a zero" rule
//                                            applied at design time rather than
//                                            after the fact.
//     misaligned fires                    -> proof, exit 1.
//
//   Calibration arithmetic: unfenced SB rates on bare POWER are typically 1e-3
//   to 1e-5 per iteration with a tuned harness; under FEX, with JIT dispatch
//   between guest instructions, expect substantially less. At the default 400k
//   iterations a true rate of 1e-5 gives ~4 hits and 1e-7 gives ~0.04 — i.e.
//   this test cannot distinguish 1e-7 from zero. Raise --sb-iters to push the
//   bound down; cost is linear.
//
// CONSTRUCTION NOTES
//   - The two threads' fence operands are on DIFFERENT cache lines. If they
//     shared one, the split-lock stripe mutex would serialise the threads and
//     the litmus would come back clean for a reason unrelated to barriers.
//   - x and y are on separate 128-byte lines.
//   - Inter-iteration synchronisation uses a sense-reversing barrier built on
//     seq_cst __atomic operations on ALIGNED words. The harness must not depend
//     on the mechanism under test; aligned atomics take the LL/SC path, which
//     is not what is being questioned here.
//   - A small per-thread delay (0..15 pause instructions, varying with the
//     iteration index) after the barrier explores different relative alignments
//     of the two threads. Standard litmus practice; --no-jitter turns it off.
//   - The fence op adds 1, so its final count must equal the iteration count.
//     If it does not, the arm did not run as written and is VOID.
//
// A FAILURE PROVES
//   The locked operation did not provide StoreLoad ordering. It does not by
//   itself prove the operation was non-atomic — barriers and atomicity are
//   separate defects that happen to share a code path here.
//
// ARMS
//   sb-unfenced    CALIBRATION. Firing is legal on x86; never a verdict.
//   sb-misaligned  the defect.
//   sb-aligned     CONTROL. Must never fire.
// ===========================================================================

typedef struct {
  volatile int count;
  char         pad0[128 - sizeof(int)];
  volatile int sense;
  char         pad1[128 - sizeof(int)];
} sbar_t;

static void bar2(sbar_t* b, int* local_sense) {
  *local_sense = !*local_sense;
  if (__atomic_add_fetch(&b->count, 1, __ATOMIC_SEQ_CST) == 2) {
    __atomic_store_n(&b->count, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&b->sense, *local_sense, __ATOMIC_SEQ_CST);
  } else {
    while (__atomic_load_n(&b->sense, __ATOMIC_SEQ_CST) != *local_sense) {
      cpu_relax();
    }
  }
}

typedef int (*sb_step_t)(volatile int*, volatile int*, volatile unsigned char*);

typedef struct {
  int                     tid;
  sb_step_t               step;
  volatile int*           my_flag;
  volatile int*           peer_flag;
  volatile unsigned char* fence;
  volatile int*           result;
  unsigned long           iters;
  sbar_t*                 bar;
} sb_ctx_t;

// Thread 1's side. Only thread 0 evaluates the outcome and resets the flags,
// which the second barrier makes safe: thread 1 cannot enter iteration i+1
// until thread 0 has arrived at the next barrier, and thread 0 arrives only
// after the reset.
static void* sb_thread(void* argp) {
  sb_ctx_t*     c     = (sb_ctx_t*)argp;
  int           sense = 0;
  unsigned long i;

  for (i = 0; i < c->iters; i++) {
    bar2(c->bar, &sense);
    if (opt_jitter) {
      int d = (int)((i * 7u) & 15u);
      while (d--) {
        cpu_relax();
      }
    }
    *c->result = c->step(c->my_flag, c->peer_flag, c->fence);
    bar2(c->bar, &sense);
  }
  return NULL;
}

static unsigned long g_sb_unfenced_hits = 0;
static int           g_sb_unfenced_run  = 0;

// kind: 0 = calibration (unfenced), 1 = subject (misaligned), 2 = control
static void run_sb_arm(const char* name, int kind, sb_step_t step) {
  unsigned char* page;
  sbar_t         bar;
  sb_ctx_t       ctx[2];
  pthread_t      th;
  unsigned long  both_zero = 0;
  volatile int * x, *y, *r0, *r1;
  int            sense = 0, is_control = (kind == 2);
  unsigned long  i;
  unsigned       fence_off = (kind == 1) ? 3 : 0;
  uint32_t       fc0 = 0, fc1 = 0;

  if (!arm_enabled(name)) {
    record(name, is_control, 0, V_SKIP, "skipped");
    return;
  }
  page = alloc_page();
  if (!page) {
    record(name, is_control, 1, V_VOID, "allocation failed");
    return;
  }

  // Layout: x @0, y @128, r0 @256, r1 @384, fence targets @512 and @640 — all
  // on distinct 128-byte lines.
  x  = (volatile int*)(page + 0);
  y  = (volatile int*)(page + 128);
  r0 = (volatile int*)(page + 256);
  r1 = (volatile int*)(page + 384);

  memset(&bar, 0, sizeof(bar));

  ctx[0].tid = 0;
  ctx[0].step = step;
  ctx[0].my_flag = x;
  ctx[0].peer_flag = y;
  ctx[0].fence = page + 512;
  ctx[0].result = r0;
  ctx[0].iters = opt_sb_iters;
  ctx[0].bar = &bar;

  ctx[1].tid = 1;
  ctx[1].step = step;
  ctx[1].my_flag = y;
  ctx[1].peer_flag = x;
  ctx[1].fence = page + 640;
  ctx[1].result = r1;
  ctx[1].iters = opt_sb_iters;
  ctx[1].bar = &bar;

  if (pthread_create(&th, NULL, sb_thread, &ctx[1]) != 0) {
    record(name, is_control, 1, V_VOID, "pthread_create failed");
    free(page);
    return;
  }

  for (i = 0; i < opt_sb_iters; i++) {
    bar2(&bar, &sense);
    if (opt_jitter) {
      int d = (int)((i * 11u) & 15u);
      while (d--) {
        cpu_relax();
      }
    }
    *r0 = step(ctx[0].my_flag, ctx[0].peer_flag, ctx[0].fence);
    bar2(&bar, &sense);
    if (*r0 == 0 && *r1 == 0) {
      both_zero++;
    }
    *x = 0;
    *y = 0;
  }
  pthread_join(th, NULL);

  if (kind == 0) {
    g_sb_unfenced_run  = 1;
    g_sb_unfenced_hits = both_zero;
    record(name, 0, 0, V_NOEVID, "%lu/%lu reordered — LEGAL on x86; this is the sensitivity calibration", both_zero,
           opt_sb_iters);
    free(page);
    return;
  }

  // Execution witness: each fence op incremented its private counter once per
  // iteration.
  memcpy(&fc0, page + 512 + fence_off, 4);
  memcpy(&fc1, page + 640 + fence_off, 4);
  if (fc0 != (uint32_t)opt_sb_iters || fc1 != (uint32_t)opt_sb_iters) {
    record(name, is_control, 1, V_VOID, "fence op ran %u/%u times, expected %lu — arm did not run as written", fc0, fc1,
           opt_sb_iters);
    free(page);
    return;
  }

  if (both_zero) {
    record(name, is_control, 0, V_FAIL, "%lu/%lu iterations observed r0==0 && r1==0 across a locked op", both_zero,
           opt_sb_iters);
  } else if (g_sb_unfenced_run && g_sb_unfenced_hits == 0) {
    record(name, is_control, 0, V_VOID, "0/%lu, but the unfenced calibration never fired — no power on this machine",
           opt_sb_iters);
  } else {
    record(name, is_control, 0, V_NOEVID, "0/%lu (calibration fired %lu; a bound, not a proof)", opt_sb_iters,
           g_sb_unfenced_hits);
  }
  free(page);
}

// ===========================================================================
// SUBTEST 4 — MISALIGNED CMPXCHG8B
//
// INVARIANT
//   LOCK CMPXCHG8B is an atomic 64-bit compare-and-swap at any alignment [A4].
//   T threads each perform N successful CAS-increments of a shared 64-bit
//   counter, retrying on failure. Under atomicity every successful CAS
//   increments the counter by exactly one and no update can be lost, so the
//   final value is exactly T*N. That holds under every interleaving; no
//   schedule produces any other number.
//
// DETERMINISM
//   Fully deterministic expected value, and near-certain detection. The
//   misaligned CASPair path is an inline ld / cmpd / std with NO mutex and no
//   reservation, so the window between the load and the store is several
//   instructions wide rather than a few cycles, and two contending threads
//   collide almost immediately. Of the four subtests this is the one most
//   likely to catch a real bug, and the one most likely to matter in
//   production: the i386 ABI gives 8-byte types only 4-byte alignment, so in
//   32-bit guest code a misaligned CMPXCHG8B is the ordinary case. Run the
//   32-bit binary.
//
// INSTRUMENTATION
//   Failed CAS attempts are counted. Zero retries across the whole run means
//   the threads never contended, and the result is VOID.
//
// A FAILURE PROVES
//   CMPXCHG8B is not atomic at this alignment. Unlike subtest 1 this one does
//   isolate the mechanism, because there is only one: the path takes no lock at
//   all.
//
// ARMS
//   cas8-misaligned  the defect. Counter at offset 3 of a page.
//   cas8-aligned     CONTROL. Counter at offset 0.
// ===========================================================================

typedef struct {
  volatile void* p;
  unsigned long  n;
  unsigned long  retries;
} cas_ctx_t;

static void* cas_thread(void* argp) {
  cas_ctx_t*    c = (cas_ctx_t*)argp;
  uint64_t      exp, obs = 0;
  unsigned long i;

  // Seed with a read. A CAS whose expected value can never be present acts as
  // an atomic load: the counter only counts up from zero so ~0 never matches,
  // and even if it did, desired == expected makes the store a no-op.
  cas8_try(c->p, ~(uint64_t)0, ~(uint64_t)0, &obs);
  exp = obs;

  for (i = 0; i < c->n; i++) {
    for (;;) {
      if (cas8_try(c->p, exp, exp + 1, &obs)) {
        exp = exp + 1;
        break;
      }
      exp = obs;
      c->retries++;
    }
  }
  return NULL;
}

static void run_cas_arm(const char* name, int is_control, unsigned off) {
  unsigned char* page;
  pthread_t      th[8];
  cas_ctx_t      ctx[8];
  int            i, nt = opt_cas_threads;
  uint64_t       final = 0, expected;
  unsigned long  retries = 0;

  if (!arm_enabled(name)) {
    record(name, is_control, 1, V_SKIP, "skipped");
    return;
  }
  if (nt < 2) {
    nt = 2;
  }
  if (nt > 8) {
    nt = 8;
  }
  page = alloc_page();
  if (!page) {
    record(name, is_control, 1, V_VOID, "allocation failed");
    return;
  }

  for (i = 0; i < nt; i++) {
    ctx[i].p       = page + off;
    ctx[i].n       = opt_cas_iters;
    ctx[i].retries = 0;
  }
  for (i = 1; i < nt; i++) {
    if (pthread_create(&th[i], NULL, cas_thread, &ctx[i]) != 0) {
      record(name, is_control, 1, V_VOID, "pthread_create failed");
      free(page);
      return;
    }
  }
  cas_thread(&ctx[0]);
  for (i = 1; i < nt; i++) {
    pthread_join(th[i], NULL);
  }

  cas8_try(page + off, ~(uint64_t)0, ~(uint64_t)0, &final);
  expected = (uint64_t)nt * (uint64_t)opt_cas_iters;
  for (i = 0; i < nt; i++) {
    retries += ctx[i].retries;
  }

  if (final != expected) {
    record(name, is_control, 1, V_FAIL, "counter %" PRIu64 " != %" PRIu64 " (%" PRId64 " lost, %lu retries)", final,
           expected, (int64_t)(expected - final), retries);
  } else if (retries == 0) {
    record(name, is_control, 1, V_VOID, "counter exact but 0 CAS retries — threads never contended");
  } else {
    record(name, is_control, 1, V_PASS, "counter %" PRIu64 " exact over %d threads (%lu retries)", final, nt, retries);
  }
  free(page);
}

// ===========================================================================
// Arm table and main
// ===========================================================================

static const lu_arm_t lu_arms[] = {
  {"lu32-mis-vs-aligned", 0, 1, {add32_o3_u00000100, add32_o4_u00010000}, {3, 4}, {4, 4}, {0x00000100, 0x00010000}},
  {"lu32-aligned-vs-aligned", 1, 0, {add32_o4_u00000001, add32_o4_u00010000}, {4, 4}, {4, 4}, {0x00000001, 0x00010000}},
  {"lu32-mis-vs-mis", 0, 0, {add32_o3_u00000001, add32_o3_u00010000}, {3, 3}, {4, 4}, {0x00000001, 0x00010000}},
#ifdef __x86_64__
  {"lu64-mis-vs-aligned", 0, 1, {add64_o61_u01000000, add64_o64_u01000000}, {61, 64}, {8, 8}, {0x01000000, 0x01000000}},
  {"lu64-aligned-vs-aligned", 1, 0, {add64_o64_u00000001, add64_o64_u01000000}, {64, 64}, {8, 8}, {0x00000001, 0x01000000}},
#endif
};
#define N_LU_ARMS ((int)(sizeof(lu_arms) / sizeof(lu_arms[0])))

static void usage(const char* argv0) {
  printf("usage: %s [--rounds N] [--iters N] [--sb-iters N] [--tear-iters N]\n"
         "          [--cas-iters N] [--cas-threads N] [--no-jitter]\n"
         "          [--timeout S] [--only SUBSTR] [--skip SUBSTR] [--list]\n",
         argv0);
}

int main(int argc, char** argv) {
  int    i, fails = 0, control_fails = 0, fatal_voids = 0, soft_voids = 0, noevid = 0;
  double t0;

  for (i = 1; i < argc; i++) {
#define NUMARG(flag, var)                                                                                              \
  if (!strcmp(argv[i], flag) && i + 1 < argc) {                                                                        \
    var = strtoul(argv[++i], NULL, 0);                                                                                 \
    continue;                                                                                                          \
  }
    NUMARG("--rounds", opt_rounds)
    NUMARG("--iters", opt_iters)
    NUMARG("--sb-iters", opt_sb_iters)
    NUMARG("--tear-iters", opt_tear_iters)
    NUMARG("--cas-iters", opt_cas_iters)
    NUMARG("--timeout", opt_timeout)
#undef NUMARG
    if (!strcmp(argv[i], "--cas-threads") && i + 1 < argc) {
      opt_cas_threads = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "--no-jitter")) {
      opt_jitter = 0;
    } else if (!strcmp(argv[i], "--only") && i + 1 < argc) {
      opt_only = argv[++i];
    } else if (!strcmp(argv[i], "--skip") && i + 1 < argc && opt_nskip < 8) {
      opt_skip[opt_nskip++] = argv[++i];
    } else if (!strcmp(argv[i], "--list")) {
      opt_list = 1;
    } else {
      usage(argv[0]);
      return 3;
    }
  }

  if (opt_list) {
    printf("subtest 1 — lost update (deterministic):\n");
    for (i = 0; i < N_LU_ARMS; i++) {
      printf("  %s%s\n", lu_arms[i].name, lu_arms[i].is_control ? "  (control)" : "");
    }
    printf("subtest 2 — torn read (positive-only):\n  tear-misaligned\n  tear-aligned  (control)\n");
    printf("subtest 3 — store/load ordering (positive-only):\n"
           "  sb-unfenced  (calibration)\n  sb-misaligned\n  sb-aligned  (control)\n");
    printf("subtest 4 — cmpxchg8b (deterministic):\n  cas8-misaligned\n  cas8-aligned  (control)\n");
    return 0;
  }

  if (opt_iters == 0 || opt_iters > 65535) {
    fprintf(stderr, "--iters must be in 1..65535 (the lane arithmetic depends on it)\n");
    return 3;
  }
  opt_iters -= opt_iters % LU_CHUNKS;
  if (!opt_iters) {
    opt_iters = LU_CHUNKS;
  }
  if (opt_timeout == 0 || opt_timeout > 3600) {
    fprintf(stderr, "--timeout must be in 1..3600\n");
    return 3;
  }

  signal(SIGALRM, on_alarm);
  alarm((unsigned)opt_timeout);

  printf("probe_splitlock — x86 %d-bit guest, misaligned LOCK atomics\n", (int)(sizeof(void*) * 8));
  printf("rounds=%lu iters=%lu sb-iters=%lu tear-iters=%lu cas-iters=%lu cas-threads=%d jitter=%d timeout=%lus\n\n",
         opt_rounds, opt_iters, opt_sb_iters, opt_tear_iters, opt_cas_iters, opt_cas_threads, opt_jitter, opt_timeout);

  t0 = now_s();

  printf("subtest 1 — lost update (deterministic; a FAIL is a proof)\n");
  for (i = 0; i < N_LU_ARMS; i++) {
    run_lu_arm(&lu_arms[i]);
  }

  printf("\nsubtest 2 — torn read (positive-only; NOEVID is not a pass)\n");
  run_tear_arm("tear-misaligned", 0, 14, tear_write_o14, tear_read_o14);
  run_tear_arm("tear-aligned", 1, 16, tear_write_o16, tear_read_o16);

  printf("\nsubtest 3 — store/load ordering (positive-only; read the calibration)\n");
  run_sb_arm("sb-unfenced", 0, sb_step_nofence);
  run_sb_arm("sb-misaligned", 1, sb_step_misaligned);
  run_sb_arm("sb-aligned", 2, sb_step_aligned);

  printf("\nsubtest 4 — misaligned cmpxchg8b (deterministic; a FAIL is a proof)\n");
  run_cas_arm("cas8-misaligned", 0, 3);
  run_cas_arm("cas8-aligned", 1, 0);

  printf("\nelapsed %.1f s\n", now_s() - t0);

  for (i = 0; i < g_nres; i++) {
    switch (g_res[i].v) {
    case V_FAIL:
      fails++;
      if (g_res[i].is_control) {
        control_fails++;
      }
      break;
    case V_VOID:
      if (g_res[i].void_fatal) {
        fatal_voids++;
      } else {
        soft_voids++;
      }
      break;
    case V_NOEVID: noevid++; break;
    default:       break;
    }
  }

  printf("\n%d arms: %d fail (%d control), %d void, %d no-window, %d inconclusive\n", g_nres, fails, control_fails,
         fatal_voids, soft_voids, noevid);
  printf("cross-check: ~/.fex-emu/Telemetry/<appname>.telem must show a large\n"
         "\"64byte Split Locks\" count. 0 means the misaligned path was never taken\n"
         "and every result above is void.\n");

  if (control_fails) {
    printf("RESULT: VOID\n");
    return 2;
  }
  if (fails) {
    printf("RESULT: FAIL\n");
    return 1;
  }
  if (fatal_voids) {
    printf("RESULT: VOID\n");
    return 2;
  }
  printf("RESULT: PASS\n");
  return 0;
}
