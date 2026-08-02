// SPDX-License-Identifier: MIT
//
// probe_lockword — does FEX's plain-store read-modify-write lowering widen the
// release window of the Unity game's lock enough to matter?
//
// ============================================================================
// 1. THE OBSERVATION THIS PROBE EXISTS TO EXPLAIN
// ============================================================================
// A 32-bit Unity title livelocks under FEX/ppc64le: 128 threads pinned at 100%
// CPU, reproduced across two independent captures, with a futex signature of
// 298 consecutive EAGAIN on one thread/address and several threads at 100%
// futex failure over 90 s against a 7.2% healthy baseline.
//
// The guest lock, extracted by disassembly of the running game:
//
//   acquire, 0x848adbd          release, 0x848b59f
//   ------------------          -------------------
//   mov  edx, 0x80000000        or DWORD PTR [ebx+0x8], 0x80000000
//   lock xadd [esi+0x8], edx                   ^ NOT lock-prefixed
//   cmp  edx, 0x80000000
//   je   got_it
//   (else unwind and retry)
//
// ============================================================================
// 2. WHAT THE GUEST'S SCHEME ACTUALLY IS  (requirement: work it out and say so)
// ============================================================================
// Two arithmetic facts settle it.
//
//   [F1] `xadd` of 0x80000000 into a 32-bit word is EXACTLY an atomic TOGGLE of
//        bit 31, returning the old word. Adding 0x80000000 mod 2^32 can never
//        carry into any other bit (the carry out of bit 31 is discarded), so
//        bits 0..30 are left untouched. This is a toggle, not a set.
//
//   [F2] `or 0x80000000` is an idempotent SET of bit 31. Not a toggle.
//        Bits 0..30 untouched. Non-atomic (no LOCK prefix).
//
// And the acquire tests `old == 0x80000000` — the whole word, not just the
// sign bit — so the protocol also asserts bits 0..30 are zero in the free
// state. What bits 0..30 are used for elsewhere we could not determine from
// the extracted fragment; nothing in this probe writes them (except the
// `swallow` arm, deliberately — see §5.2).
//
// So the encoding is:
//
//     word == 0x80000000  ->  FREE
//     word == 0x00000000  ->  HELD
//     acquire attempt     ->  toggle;  success iff it was FREE
//     release             ->  force to FREE (idempotent set)
//
// THE CONSEQUENCE, STATED PLAINLY: this is not a mutual-exclusion primitive.
// A toggle-based trylock cannot be one on any architecture. A *failed*
// acquirer flips FREE back on while the real owner still holds the lock, and
// the next arrival then "succeeds". Two threads in the critical section, on
// real x86 silicon, with no emulation involved:
//
//     W=0 (T1 holds)
//     T2 xadd -> old 0, W=0x80000000.  T2 fails, and has just published FREE.
//     T3 xadd -> old 0x80000000, W=0.  T3 SUCCEEDS. T1 and T3 both inside.
//
// This is not an artefact of modelling the "no undo" faithfully. Adding an
// undo does not fix it either: the undo is itself a toggle, and the same
// three-way interleaving reappears one step later. Only a CAS acquire closes
// it, which is what the `cas` arm here uses as a control.
//
// The two readings that make the shipped code sane are (a) it is a
// SINGLE-WAITER handshake — correct exactly when at most one thread can be in
// the acquire path at a time, mutual exclusion guaranteed by something upstream
// — or (b) a spurious success is caught by a downstream owner check we cannot
// see in the fragment, and the cost of one is a retry rather than corruption.
// Both are consistent with a program that works on x86 for years and falls over
// when the timing changes. We cannot distinguish them without the surrounding
// code, and this probe does not need to: variant A and variant B share the
// identical acquire, so whatever the scheme is, it is a CONSTANT across the
// experiment. See §6 for why that constant nevertheless limits what the
// lockword arm can prove.
//
// Per instruction: we model the fragment exactly and do not repair it. A
// failed acquirer leaves the word flipped, as the guest does.
//
// ============================================================================
// 3. THE FEX LOWERING UNDER SUSPICION  (verified in this tree, not assumed)
// ============================================================================
// `or [mem], imm` without a LOCK prefix takes the non-atomic path.
// OpcodeDispatcher.cpp:4584 `ALUOp` branches on `DestIsLockedMem(Op)`: locked
// -> `AtomicFetchOr`; unlocked -> LoadMemTSO / OR / StoreMemTSO.
//
// The ppc64le backend then emits, for the unlocked case:
//
//   MemoryOps.cpp:709-715  DEF_OP(LoadMemTSO)   lwzx ; lwsync   <- acquire
//   (ALU)                                       oris
//   MemoryOps.cpp:736      DEF_OP(StoreMemTSO)  lwsync ; stwx    <- release
//
//   ==>  lwzx | lwsync | oris | lwsync | stwx
//
// Two full barriers sit BETWEEN the load and the store of a read-modify-write
// that x86 performs as one instruction. That is the hypothesis: the
// architecturally-racy window in the guest's release goes from a couple of
// cycles (the core holds the line exclusive across a single locked-line RMW)
// to hundreds (two lwsyncs must drain).
//
// Note this sequence is a LOWER bound. Flag computation for `or` (SF/ZF/PF,
// clear OF/CF) is deferred by FEX but not always eliminated, and
// ComputeAddress folds the +0x8 displacement — the probe uses a +8
// displacement on purpose so it exercises the same folding path
// (MemoryOps.cpp:656, :732) the game does.
//
// ============================================================================
// 4. THE EXPERIMENT
// ============================================================================
// One program, two release variants, everything else byte-identical:
//
//   Variant A   or      DWORD PTR [mem], 0x80000000    <- what the game does
//   Variant B   lock or DWORD PTR [mem], 0x80000000    <- diagnostic only
//
// The workers are generated from one macro (DEF_LOCK_WORKER) so A and B differ
// in the literal string "lock " and in nothing else. Both are reachable in a
// single run (`--variant both`, the default) so the comparison never spans two
// processes with different machine state.
//
// Variant B is NOT a proposed fix. It changes the guest binary, which we do not
// control. It is the diagnostic arm that tells us whether the release's
// atomicity is what matters. If it is, the fix lives in the JIT.
//
// ============================================================================
// 5. THE THREE ARMS, AND WHICH ONE ACTUALLY CARRIES THE ARGUMENT
// ============================================================================
//
// 5.1 `lockword` — the ecological arm. Faithful reproduction: 128 threads
//     (default), the exact acquire, the exact release, a plain shared counter
//     bumped only inside the critical section, per-thread progress counters, a
//     sampling monitor and a hard watchdog. Answers "does it livelock, and does
//     the variant change that". Probabilistic and, for its exclusion counters,
//     CONFOUNDED — see §6.
//
// 5.2 `swallow` — the mechanism arm, and the one that carries the argument.
//     It does not use the game's protocol at all. One thread hammers
//     `<variant> or [w], 0x80000000` in a loop; K threads hammer
//     `lock add [w], 1` on the SAME word. Increments live in bits 0..30, which
//     the OR never touches, so the invariant is exact:
//
//         (w & 0x7fffffff)  ==  total increments
//
//     Every unit of shortfall is one `lock add` swallowed by the OR's
//     non-atomic load..store window. The shortfall is a DIRECT, UNCONFOUNDED,
//     QUANTITATIVE measurement of that window's width, and the arm converts it
//     to an estimated window in nanoseconds. Under variant B the shortfall must
//     be exactly zero — that is an invariant, not an expectation.
//
// 5.3 `cas` — the control. Same release variants, but the acquire is
//     `lock cmpxchg` (0x80000000 -> 0). Zero exclusion violations is then
//     guaranteed on any correct implementation *including under variant A*: a
//     failed cmpxchg does not write, and a successful one requires the word to
//     read FREE, which it cannot while the releaser is mid-window holding it.
//     So there is no window for the release to clobber. If this arm reports a
//     violation, either the harness is broken or FEX has a deeper defect than
//     the one under test, and every other number here is untrusted.
//
// ============================================================================
// 6. WHAT THIS EXPERIMENT CAN AND CANNOT SETTLE  (read before believing a run)
// ============================================================================
//
// (a) THE EXCLUSION COUNTERS IN `lockword` CANNOT BE A CLEAN A-vs-B
//     DISCRIMINATOR, and requirement-6's "counter must equal acquisitions" will
//     fail in BOTH variants. Not because of FEX — because of §2. The toggle
//     acquire manufactures spurious FREE publications all by itself, at a rate
//     set by the failure rate, which at 128-way contention is enormous. Variant
//     B removes the release's clobber but not the protocol's own breakage. So
//     the correct reference for `lockword`'s violation count is variant B's
//     number, never zero. The probe therefore reports lockword exclusion counts
//     as DATA, not as pass/fail, and reserves the "broken exclusion" exit code
//     for the two arms where zero is genuinely guaranteed (`swallow` variant B,
//     and `cas` both variants).
//
//     MEASURED, not merely argued. A native aarch64 shim build of this file
//     (asm replaced by C atomics, so the acquire is a true atomic toggle) run
//     at 16 threads for 3 s gave:
//
//         variant A   acq 35662459  overlap rate 0.9956  counter loss 0.546
//         variant B   acq 36358873  overlap rate 0.9932  counter loss 0.592
//
//     Both arms are pinned against the ceiling. The reason is a runaway: every
//     release forces FREE, so once two threads are inside, both release, the
//     word is FREE almost permanently (only 4608 failed acquires out of 35.7 M
//     attempts), everyone succeeds, and the "lock" degenerates to no lock at
//     all. A saturated metric has no discriminating power in either direction.
//     Do not compute an A-vs-B ratio from these columns and call it a result.
//     `--hold N` puts a bounded delay in the critical section and will move the
//     numbers, but it does not remove the runaway — nothing does, short of the
//     CAS acquire, which is a different protocol.
//
// (b) THE RELEASE CLOBBER CANNOT WEDGE THE WORD. The plain release always
//     stores a value with bit 31 SET. A lost update can only over-publish FREE,
//     never over-publish HELD. There is no interleaving in which the word gets
//     stuck at HELD with nobody holding it. Combined with (c), this is why the
//     author's expectation is that NEITHER variant livelocks in the `lockword`
//     arm.
//
// (c) A SPINNING THREAD CANNOT STARVE ON THIS WORD. Toggle semantics mean a
//     thread that fails, retries, and finds nothing else intervened will
//     succeed on its very next attempt — it flipped the word FREE itself. The
//     acquire loop is close to a fairness-free coin flip, not a starvation
//     trap. The game's 100%-CPU futex churn is therefore much more likely to
//     live DOWNSTREAM of this word — in whatever queue or futex protocol is
//     built on top and gets corrupted when exclusion is lost — than in the word
//     itself. This probe deliberately does not model that downstream, because
//     we do not know it, and inventing it would produce a number that looks
//     like evidence and is not.
//
// (d) CONSEQUENCE. If you run this and both variants come back CLEAN with no
//     livelock, that is the EXPECTED result and it does not kill the
//     hypothesis. The hypothesis lives or dies on `swallow`. Read that arm's
//     numbers first.
//
// (e) VARIANT B IS NOT "A BUT ATOMIC". `lock or` lowers to an
//     lwarx/stwcx. reservation loop bracketed by hwsync/isync
//     (AtomicOps.cpp). It is slower per release and, under heavy contention on
//     POWER, its reservation can be repeatedly stolen. If B ever livelocks
//     where A does not, suspect reservation starvation before concluding
//     anything about the guest.
//
// (f) NO NATIVE x86 BASELINE. Variant A is racy by construction on every
//     architecture; the question is only the observation RATE, and an absolute
//     rate is meaningless without an x86 number to compare against. We have no
//     x86 hardware. The substitute is a DOSE-RESPONSE sweep on FEX's own
//     barrier settings, which changes the window width without changing a byte
//     of the guest binary:
//
//         FEX_TSOENABLED=1 FEX_LOCKONLYTSO=0   both lwsyncs present (default)
//         FEX_TSOENABLED=1 FEX_LOCKONLYTSO=1   load-side lwsync dropped
//         FEX_TSOENABLED=0                     both dropped
//
//     If `swallow`'s measured window shrinks monotonically across those three,
//     the barriers are demonstrably the thing setting the window width. That is
//     a much stronger claim than any single A-vs-B number, and it is the run
//     to do first.
//
// (g) THE ASM IS HAND-REVIEWED, WITH ONE MACHINE CHECK. No x86 assembler and no
//     x86 compiler exists on the authoring host (aarch64: no gcc/clang x86
//     cross, no x86 binutils). The AT&T inline asm below was reviewed by hand
//     and has NOT been assembled. What WAS machine-checked is the instruction
//     set itself: every instruction used here was assembled with `nasm -f bin`
//     in Intel syntax and round-tripped through `ndisasm -b32`, confirming
//     encodability and operand forms in 32-bit mode:
//
//       F0 0F C1 56 08          lock xadd [esi+0x8],edx
//       81 4B 08 00 00 00 80    or dword [ebx+0x8],0x80000000
//       F0 81 4B 08 00 00 00 80 lock or dword [ebx+0x8],0x80000000
//       F0 83 43 08 01          lock add dword [ebx+0x8],byte +0x1
//       F0 0F B1 4B 08          lock cmpxchg [ebx+0x8],ecx
//       F3 90                   pause
//
//     That rules out "this instruction does not exist / cannot take this
//     operand". It does not rule out an AT&T syntax slip. FIRST BUILD ON THE
//     ppc64le HOST IS THE REAL SYNTAX CHECK — if it compiles, the asm is well
//     formed; then `objdump -d` it once and eyeball the five sequences before
//     trusting any number.
//
// ============================================================================
// 7. DETERMINISTIC vs PROBABILISTIC  (this project's standing rule applies)
// ============================================================================
// The standing rule is that 30 trials only rules out a true rate above ~10%.
// That rule is about PER-RUN BINARY outcomes. Two of the three arms here are
// not per-run binary outcomes, and the distinction is the whole reason
// `swallow` is worth more than `lockword`:
//
//   swallow, variant B  DETERMINISTIC INVARIANT. Shortfall must be 0 under
//                       every legal interleaving. One run falsifies. No trial
//                       count needed.
//
//   cas, both variants  DETERMINISTIC INVARIANT. Zero exclusion violations
//                       under every legal interleaving (§5.3). One run
//                       falsifies. No trial count needed.
//
//   swallow, variant A  PER-EVENT MEASUREMENT, not a per-run coin flip. A
//                       default run performs order 10^7-10^8 releases against
//                       8x10^7 increments, so a per-release loss probability as
//                       low as ~10^-7 produces a nonzero count in a SINGLE run, and
//                       the count is a rate estimate with a relative standard
//                       error of ~1/sqrt(count). At an expected count of 10^4
//                       that is 1%. One run is enough to state the window to
//                       within a few percent. Repeat 3-5 times only to bound
//                       run-to-run machine variation, not for statistics.
//                       A shortfall of exactly 0 or 1 is reported as no
//                       evidence: one tail loss is possible by construction.
//
//   lockword, livelock  PER-RUN BINARY. The standing rule applies in full.
//                       30 runs of one variant bounds nothing below ~10%.
//                       Run A and B ALTERNATING as pairs so machine state is
//                       controlled, and read it as a paired sign test:
//                         A livelocks 5/5 pairs, B 0/5   -> p = 0.031
//                         A 10/10, B 0/10                -> p = 0.001
//                         A 7/10, B 0/10                 -> p = 0.008
//                       Ten pairs is the sensible minimum; thirty is the point
//                       past which more pairs stop buying much. If A livelocks
//                       at a rate below ~20% you need >50 pairs and should stop
//                       and use `swallow` instead.
//
//   lockword, exclusion PER-EVENT, CONFOUNDED, and MEASURED SATURATED (§6a).
//                       Reported for the record. Do not build any conclusion on
//                       it. If a future run shows it well below 1.0, that is
//                       itself news and worth chasing.
//
// One more statistical note, because it is the trap this arm sets: `swallow`
// variant A's window estimate is only linear while the release duty cycle is
// small. The arm prints the duty cycle and refuses to interpret its own number
// above 0.30. A saturated shortfall still PROVES the window exists; it just
// cannot size it. Tune --release-gap until the duty cycle lands in 0.01..0.30
// BEFORE comparing anything across FEX settings, and keep the gap fixed across
// that comparison — changing it changes the estimator's operating point.
//
// ============================================================================
// 8. BUILD  (exact command; the toolchain lives in the rootfs on the ppc64le
//            host, not on the authoring host)
// ============================================================================
//   ROOT=/home/jbettcher/Development/fexrootfs
//   $ROOT/x-tools/i686-linux-gnu/bin/i686-linux-gnu-gcc -O2 -Wall -Wextra -pthread -o build-probes/probe_lockword build-probes/probe_lockword.c -lm
//
// An i686-linux-gnu compiler is already 32-bit targeted; no -m32. Then, once,
// before trusting output:
//
//   objdump -d build-probes/probe_lockword | grep -A2 -E 'xadd|lock or|orl.*0x80000000|cmpxchg'
//
// ============================================================================
// 9. RUN
// ============================================================================
//   # the run that matters: mechanism + dose-response
//   FEX ./build-probes/probe_lockword --test swallow --variant both
//   FEX_LOCKONLYTSO=1 FEX ./build-probes/probe_lockword --test swallow --variant a
//   FEX_TSOENABLED=0  FEX ./build-probes/probe_lockword --test swallow --variant a
//
//   # the ecological run, paired, for the livelock question
//   for i in $(seq 10); do
//     FEX ./build-probes/probe_lockword --test lockword --variant both --seconds 30
//   done
//
//   # the IR dump this program was kept small for
//   FEX_DUMPIR=stdout FEX_PASSMANAGERDUMPIR=afteropt FEX ./build-probes/probe_lockword --test lockword --variant both --minimal --threads 2 --seconds 1
//
// Pin to one node so the contention windows are real:
//   numactl --cpunodebind=0 --membind=0 FEX ./build-probes/probe_lockword ...
//
// ============================================================================
// 10. OUTPUT AND EXIT CODES
// ============================================================================
// Each arm emits a human line and one `DATA ...` line of key=value pairs for
// scripted campaigns. The last line is always exactly one of:
//   RESULT: CLEAN / RESULT: LIVELOCK / RESULT: BROKEN / RESULT: ERROR
//
//   0  CLEAN     no livelock, and every guaranteed-zero invariant held.
//   1  LIVELOCK  a lockword arm stalled or starved a thread. Ecological
//                finding; read alongside swallow before concluding.
//   2  BROKEN    a guaranteed-zero invariant was violated (swallow variant B
//                shortfall, or a cas exclusion violation). Strictly more
//                serious than a livelock: it means atomicity itself is lost,
//                or the harness is wrong. Investigate before anything else.
//   3  ERROR     setup failure, or the watchdog fired. No verdict.
//
// Precedence when several apply: ERROR > BROKEN > LIVELOCK > CLEAN.

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__i386__)
#error "probe_lockword models a 32-bit x86 guest lock; build it with the i686-linux-gnu cross toolchain."
#endif

// ---------------------------------------------------------------------------
// Constants of the guest protocol. Do not "improve" these.
// ---------------------------------------------------------------------------

#define FREE_WORD 0x80000000u // the free encoding, and the xadd addend, and the OR mask
#define HELD_WORD 0x00000000u
#define LOCK_DISP 8           // the +0x8 in [esi+0x8] / [ebx+0x8]

#define CACHELINE 128 // POWER9 line; also >= x86's 64

// ---------------------------------------------------------------------------
// Verdict plumbing
// ---------------------------------------------------------------------------

typedef enum { EX_CLEAN = 0, EX_LIVELOCK = 1, EX_BROKEN = 2, EX_ERROR = 3 } exit_code_t;

static int g_worst = EX_CLEAN;

static void worse(int code) {
  if (code > g_worst) {
    g_worst = code;
  }
}

static void die_setup(const char* what) {
  fprintf(stderr, "probe_lockword: setup failure: %s (%s)\n", what, strerror(errno));
  printf("RESULT: ERROR\n");
  fflush(NULL);
  exit(EX_ERROR);
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

static int           opt_do_lockword = 1;
static int           opt_do_swallow  = 1;
static int           opt_do_cas      = 1;
static int           opt_var_a       = 1;
static int           opt_var_b       = 1;
static int           opt_threads     = 128;     // the game had 128 spinning
static unsigned long opt_seconds     = 20;      // per lockword arm
static unsigned long opt_cas_seconds = 5;       // per cas arm
static unsigned long opt_sw_iters    = 20000000; // lock-add increments per incrementer
static int           opt_sw_threads  = 4;       // incrementer threads in `swallow`
static unsigned long opt_backoff     = 0;       // pause iterations after a failed acquire
static unsigned long opt_hold        = 0;       // pause iterations inside the critical section
static unsigned long opt_rel_gap     = 100;     // pause iterations between swallow releases;
                                                // this sets the release duty cycle, see run_swallow
static int           opt_minimal     = 0;       // strip instrumentation from the hot path
static unsigned long opt_stall_ms    = 2000;    // zero global progress for this long => livelock
static unsigned long opt_sample_ms   = 100;     // monitor sampling period
static unsigned long opt_timeout     = 600;     // hard watchdog, seconds. A full default
                                                // run is ~2-3 min under FEX; raise this if
                                                // you raise --swallow-iters.

// ---------------------------------------------------------------------------
// Hard watchdog. A regression gate that hangs is worse than one that fails.
// SIGALRM handler does an async-signal-safe write and _exit.
// ---------------------------------------------------------------------------

static void on_alarm(int sig) {
  static const char msg[] = "\nprobe_lockword: WATCHDOG fired\nRESULT: ERROR\n";
  (void)sig;
  if (write(1, msg, sizeof(msg) - 1) < 0) {
    /* nothing useful to do here */
  }
  _exit(EX_ERROR);
}

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// ---------------------------------------------------------------------------
// The lock object.
//
// The word sits at +8 so the effective address is `disp(base)`, matching the
// guest's [esi+0x8] / [ebx+0x8]. That is not cosmetic: FEX folds the
// displacement into LoadMemTSO/StoreMemTSO via ComputeAddress
// (MemoryOps.cpp:656, :732), and a zero displacement would exercise a
// different fold. Whole object is cacheline-isolated so nothing else on the
// line perturbs the contention.
// ---------------------------------------------------------------------------

typedef struct {
  uint32_t          pad_lo[LOCK_DISP / 4]; // +0..+7
  volatile uint32_t w;                     // +8  <- THE lock word
  uint8_t           pad_hi[CACHELINE - LOCK_DISP - 4];
} lockobj_t;

// ---------------------------------------------------------------------------
// GUEST ASM PRIMITIVES
//
// Every one of these hard-codes the +8 displacement in the instruction text so
// the addressing mode is a property of the source and not of the register
// allocator. `base` is always the lockobj_t start.
//
// Constraint notes, once, because they are the same everywhere below:
//
//   "+&r"(v)   xadd and cmpxchg READ AND WRITE their register operand, so it
//              must be an in-out ("+"), never "=r". The "&" (early clobber) is
//              belt-and-braces: it forbids the allocator from aliasing the
//              value register with the base register. It cannot actually
//              happen here (they hold different values on entry, so GCC will
//              not tie them), but if it ever did, `lock xaddl %eax, 8(%eax)`
//              would compute a garbage effective address, and the failure
//              would look like a memory-ordering bug. Costs nothing.
//   "r"(base)  the address must be in a register; the displacement is literal.
//   "memory"   REQUIRED. The memory operand is not named as an asm operand
//              (it is written out longhand as `8(%[b])`), so without this the
//              compiler does not know the word was touched, and would be free
//              to cache it in a register or move accesses across the asm. Also
//              carries the ordering: these are synchronising operations.
//   "cc"       REQUIRED. xadd, or, add and cmpxchg all write EFLAGS.
//   "=q"(ok)   `sete` needs a byte-addressable register. On i386 "q" is
//              {a,b,c,d}x; "r" would let the allocator pick esi/edi, which have
//              no 8-bit low half, and the build would fail.
// ---------------------------------------------------------------------------

#define STR_(x) #x
#define STR(x) STR_(x)
#define D STR(LOCK_DISP) // "8"

// ACQUIRE — the guest's, verbatim. Returns the OLD word.
//   lock xadd DWORD PTR [base+8], 0x80000000
// which by [F1] is an atomic toggle of bit 31 returning the old value.
// Identical in every arm and every variant: this is the experiment's constant.
static inline uint32_t acq_toggle(volatile unsigned char* base) {
  uint32_t v = FREE_WORD;
  __asm__ __volatile__("lock xaddl %[v], " D "(%[b])\n\t" : [v] "+&r"(v) : [b] "r"(base) : "memory", "cc");
  return v;
}

// CAS ACQUIRE — control arm only. Not what the guest does.
//   lock cmpxchg DWORD PTR [base+8], ecx   with eax = FREE, ecx = HELD
// "+a"(exp) is mandatory: cmpxchg's accumulator operand is implicit, both read
// (the comparand) and written (the observed value on failure).
static inline int cas_acquire(volatile unsigned char* base) {
  uint32_t exp = FREE_WORD;
  uint32_t des = HELD_WORD;
  uint8_t  ok;
  __asm__ __volatile__("lock cmpxchgl %[d], " D "(%[b])\n\t"
                       "sete %[ok]\n\t"
                       : [ok] "=q"(ok), "+a"(exp)
                       : [d] "r"(des), [b] "r"(base)
                       : "memory", "cc");
  return ok;
}

// RELEASE — the whole experiment. RELPFX is "" (variant A, what the game does)
// or "lock " (variant B). Nothing else differs.
#define REL_ASM(RELPFX, base)                                                                                          \
  __asm__ __volatile__(RELPFX "orl $0x80000000, " D "(%[b])\n\t" : : [b] "r"(base) : "memory", "cc")

// x86 spin hint. Present so a "retry later" is not a raw dependent-load storm;
// default backoff is 0 iterations, i.e. the game's observed pure spin.
static inline void cpu_pause(void) {
  __asm__ __volatile__("pause\n\t" ::: "memory");
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

// One padded slot per thread. `acq` is volatile so the store in the hot loop
// is guaranteed to be materialised for the monitor rather than sunk out of the
// loop. On i386 a 64-bit volatile store is two 32-bit stores, so the monitor
// can read a torn value; harmless here — a torn sample can perturb one
// 100 ms progress sample, it cannot manufacture a multi-second stall.
typedef struct {
  volatile uint64_t acq;     // successful acquisitions by this thread
  uint64_t          fail;    // failed attempts (each one flipped the word — see §2)
  uint64_t          overlap; // times this thread found the CS already occupied
  uint8_t           pad[CACHELINE - 3 * sizeof(uint64_t)];
} tstat_t;

static lockobj_t*        g_lock;      // page-aligned, cacheline-isolated
static tstat_t*          g_stat;      // one padded slot per thread
static volatile uint32_t g_shared;    // requirement 6: bumped ONLY inside the CS,
                                      // plain (non-atomic) on purpose — it is
                                      // itself a guest RMW, so losing exclusion
                                      // loses increments. Must equal total acq.
static volatile int      g_occupancy; // enable the in-CS occupancy check
static volatile int      g_stop;      // set by the driver to end an arm

// Occupancy counter, on its own cache line so the instrumentation does not sit
// in the same line as the lock word and change the very contention we measure.
typedef struct {
  int32_t n;
  uint8_t pad[CACHELINE - sizeof(int32_t)];
} occ_t;
static occ_t g_occ __attribute__((aligned(CACHELINE)));

// Monitor results for the arm currently running.
static volatile uint64_t g_mon_stall_max_ms;
static volatile uint64_t g_mon_samples;

typedef struct {
  int      id;
  unsigned char* base;
} targ_t;

// ---------------------------------------------------------------------------
// THE HOT PATH.
//
// Generated once per variant from a single macro so A and B are provably the
// same code apart from the literal "lock ". This is the code whose IR you want
// to dump; keep it free of anything that is not the lock pattern.
//
// The critical section is:
//   - optional occupancy check (atomic inc / test / atomic dec) — off under
//     --minimal, and the only instrumentation inside the lock;
//   - g_shared++, a plain 32-bit guest RMW, the correctness check.
//
// A FAILED ACQUIRE DOES NOT UNDO ITS TOGGLE. That is the guest's behaviour and
// it is the point. Do not add an undo.
// ---------------------------------------------------------------------------

#define DEF_LOCK_WORKER(fname, RELPFX)                                                                                 \
  static void* fname(void* arg) {                                                                                      \
    targ_t*        a = (targ_t*)arg;                                                                                   \
    volatile unsigned char* b = a->base;                                                                               \
    tstat_t*       s = &g_stat[a->id];                                                                                 \
    uint64_t       acq = 0, fail = 0, ovl = 0;                                                                         \
    while (!g_stop) {                                                                                                  \
      uint32_t old = acq_toggle(b);                                                                                    \
      if (old == FREE_WORD) {                                                                                          \
        /* ---- critical section ---- */                                                                               \
        if (g_occupancy) {                                                                                             \
          if (__atomic_fetch_add(&g_occ.n, 1, __ATOMIC_SEQ_CST) != 0) {                                                \
            ovl++;                                                                                                     \
          }                                                                                                            \
          g_shared++;                                                                                                  \
          __atomic_fetch_sub(&g_occ.n, 1, __ATOMIC_SEQ_CST);                                                           \
        } else {                                                                                                       \
          g_shared++;                                                                                                  \
        }                                                                                                              \
        for (unsigned long h = 0; h < opt_hold; h++) {                                                                 \
          cpu_pause();                                                                                                 \
        }                                                                                                              \
        /* ---- release: THE ONE DIFFERENCE BETWEEN A AND B ---- */                                                     \
        REL_ASM(RELPFX, b);                                                                                            \
        acq++;                                                                                                         \
        s->acq = acq; /* published for the monitor; only this thread writes it */                                      \
      } else {                                                                                                         \
        fail++;                                                                                                        \
        for (unsigned long p = 0; p < opt_backoff; p++) {                                                              \
          cpu_pause();                                                                                                 \
        }                                                                                                              \
      }                                                                                                                \
    }                                                                                                                  \
    s->acq = acq;                                                                                                      \
    s->fail = fail;                                                                                                    \
    s->overlap = ovl;                                                                                                  \
    return NULL;                                                                                                       \
  }

DEF_LOCK_WORKER(lock_worker_a, "")
DEF_LOCK_WORKER(lock_worker_b, "lock ")

// ---------------------------------------------------------------------------
// CAS control worker. Same release, correct acquire. Exclusion violations here
// must be zero on any correct implementation (§5.3).
// ---------------------------------------------------------------------------

#define DEF_CAS_WORKER(fname, RELPFX)                                                                                  \
  static void* fname(void* arg) {                                                                                      \
    targ_t*        a = (targ_t*)arg;                                                                                   \
    volatile unsigned char* b = a->base;                                                                               \
    tstat_t*       s = &g_stat[a->id];                                                                                 \
    uint64_t       acq = 0, fail = 0, ovl = 0;                                                                         \
    while (!g_stop) {                                                                                                  \
      if (cas_acquire(b)) {                                                                                            \
        if (__atomic_fetch_add(&g_occ.n, 1, __ATOMIC_SEQ_CST) != 0) {                                                  \
          ovl++;                                                                                                       \
        }                                                                                                              \
        g_shared++;                                                                                                    \
        __atomic_fetch_sub(&g_occ.n, 1, __ATOMIC_SEQ_CST);                                                             \
        REL_ASM(RELPFX, b);                                                                                            \
        acq++;                                                                                                         \
        s->acq = acq;                                                                                                  \
      } else {                                                                                                         \
        fail++;                                                                                                        \
      }                                                                                                                \
    }                                                                                                                  \
    s->acq = acq;                                                                                                      \
    s->fail = fail;                                                                                                    \
    s->overlap = ovl;                                                                                                  \
    return NULL;                                                                                                       \
  }

DEF_CAS_WORKER(cas_worker_a, "")
DEF_CAS_WORKER(cas_worker_b, "lock ")

// ---------------------------------------------------------------------------
// `swallow`: the mechanism arm (§5.2).
//
// Incrementer: `lock addl $1, 8(base)` exactly n times. dec/jnz for loop
// control (ZF maps straight to CR0.EQ on POWER, no XER projection), so the
// scaffolding does not share a code path with the subject.
//
// Releaser: `<variant> orl $0x80000000, 8(base)` one at a time, separated by
// --release-gap `pause` iterations, until stopped.
//
// Increments live in bits 0..30. The OR only ever touches bit 31. So
//   (w & 0x7fffffff) == total increments
// holds under every legal interleaving IF the OR is atomic. Each unit of
// shortfall is one increment swallowed by the OR's load..store window.
//
// WHY THE GAP EXISTS — this was found by running the arm, not by reasoning.
// A back-to-back release loop is inside a load..store window essentially 100%
// of the time, so it swallows essentially 100% of the increments and the
// measurement saturates: a 5 ns window and a 500 ns window both read as "all of
// them", and the derived window number is meaningless. Measured on a native
// aarch64 shim build: 5999540 of 6000000 increments lost, duty cycle 0.99992.
// Spacing the releases drops the duty cycle into a regime where
//
//     shortfall / increments  ==  duty cycle  ==  releases * window / elapsed
//
// is linear and the window falls out. Aim for a duty cycle of 0.01 .. 0.30:
// below that the shortfall gets noisy, above it the estimator is compressed.
// The arm reports the duty cycle and tells you which way to move the gap.
//
// THE ESTIMATE IS NOT GAP-INVARIANT, AND YOU MUST NOT TREAT IT AS ABSOLUTE.
// Same aarch64 shim, same machine, same everything but --release-gap:
//
//     gap  100   duty 0.0464     est window 19.4 ns   (shortfall 278116)
//     gap 4000   duty 0.000135   est window  2.2 ns   (shortfall 812)
//
// A 9x spread. This is not estimator error, it is physics: a releaser that
// hammers the line keeps it in a coherence tug-of-war, and its own load..store
// really does take longer. The number is a RELATIVE instrument. Hold
// --release-gap fixed across every comparison you intend to draw a conclusion
// from (A vs B, and the FEX_TSOENABLED / FEX_LOCKONLYTSO sweep in sec.6f), and
// never quote the nanoseconds as an absolute property of the lowering.
// ---------------------------------------------------------------------------

static volatile int g_sw_stop;

static void inc_loop(volatile unsigned char* base, unsigned long n) {
  if (!n) {
    return;
  }
  __asm__ __volatile__("1:\n\t"
                       "lock addl $1, " D "(%[b])\n\t"
                       "dec %[n]\n\t"
                       "jnz 1b\n\t"
                       : [n] "+&r"(n)
                       : [b] "r"(base)
                       : "memory", "cc");
}

#define DEF_REL_LOOP(fname, RELPFX)                                                                                    \
  static void fname(volatile unsigned char* base, unsigned long n) {                                                   \
    if (!n) {                                                                                                          \
      return;                                                                                                          \
    }                                                                                                                  \
    __asm__ __volatile__("1:\n\t" RELPFX "orl $0x80000000, " D "(%[b])\n\t"                                            \
                         "dec %[n]\n\t"                                                                                \
                         "jnz 1b\n\t"                                                                                  \
                         : [n] "+&r"(n)                                                                                \
                         : [b] "r"(base)                                                                               \
                         : "memory", "cc");                                                                            \
  }

DEF_REL_LOOP(rel_loop_a, "")
DEF_REL_LOOP(rel_loop_b, "lock ")

typedef struct {
  unsigned char* base;
  int            variant_b;
  uint64_t       releases;
} swrel_t;

static void* sw_releaser(void* arg) {
  swrel_t*      r = (swrel_t*)arg;
  uint64_t      n = 0;
  unsigned long gap = opt_rel_gap;
  while (!g_sw_stop) {
    if (r->variant_b) {
      rel_loop_b(r->base, 1);
    } else {
      rel_loop_a(r->base, 1);
    }
    n++;
    for (unsigned long p = 0; p < gap; p++) {
      cpu_pause();
    }
  }
  r->releases = n;
  return NULL;
}

static void* sw_incrementer(void* arg) {
  targ_t* a = (targ_t*)arg;
  inc_loop(a->base, opt_sw_iters);
  return NULL;
}

// ---------------------------------------------------------------------------
// Progress monitor: samples the sum of per-thread acquisition counters and
// records the longest stretch with zero global progress. Requirement 4.
// ---------------------------------------------------------------------------

typedef struct {
  int nthreads;
} monarg_t;

static void* monitor(void* arg) {
  monarg_t*      m = (monarg_t*)arg;
  uint64_t       prev = 0;
  uint64_t       stall_start = 0;
  uint64_t       stall_max = 0;
  uint64_t       samples = 0;
  struct timespec ts;

  ts.tv_sec = (time_t)(opt_sample_ms / 1000);
  ts.tv_nsec = (long)((opt_sample_ms % 1000) * 1000000ul);

  while (!g_stop) {
    uint64_t sum = 0;
    uint64_t t;
    int      i;
    nanosleep(&ts, NULL);
    for (i = 0; i < m->nthreads; i++) {
      sum += g_stat[i].acq;
    }
    t = now_ns();
    samples++;
    if (sum == prev) {
      if (stall_start == 0) {
        stall_start = t;
      } else if (t - stall_start > stall_max) {
        stall_max = t - stall_start;
      }
    } else {
      stall_start = 0;
      prev = sum;
    }
  }
  g_mon_stall_max_ms = stall_max / 1000000ull;
  g_mon_samples = samples;
  return NULL;
}

// ---------------------------------------------------------------------------
// Arm drivers
// ---------------------------------------------------------------------------

static void reset_state(int nthreads) {
  memset(g_stat, 0, (size_t)nthreads * sizeof(tstat_t));
  g_lock->w = FREE_WORD;
  g_shared = 0;
  g_occ.n = 0;
  g_stop = 0;
  g_sw_stop = 0;
  g_mon_stall_max_ms = 0;
  g_mon_samples = 0;
}

// Returns the exit code contribution.
static int run_contended(const char* armname, int variant_b, int use_cas, unsigned long seconds) {
  pthread_t*      th;
  targ_t*         ta;
  pthread_t       mon;
  monarg_t        marg;
  struct timespec ts;
  int             i, rc = EX_CLEAN;
  int             nthreads = opt_threads;
  uint64_t        total_acq = 0, total_fail = 0, total_ovl = 0;
  uint64_t        min_acq = UINT64_MAX, max_acq = 0;
  int             zero_progress_threads = 0;
  uint64_t        t0, t1;
  void* (*worker)(void*);

  if (use_cas) {
    worker = variant_b ? cas_worker_b : cas_worker_a;
  } else {
    worker = variant_b ? lock_worker_b : lock_worker_a;
  }

  th = (pthread_t*)calloc((size_t)nthreads, sizeof(pthread_t));
  ta = (targ_t*)calloc((size_t)nthreads, sizeof(targ_t));
  if (!th || !ta) {
    die_setup("calloc thread arrays");
  }

  reset_state(nthreads);
  g_occupancy = use_cas ? 1 : (opt_minimal ? 0 : 1);

  marg.nthreads = nthreads;
  if (pthread_create(&mon, NULL, monitor, &marg) != 0) {
    die_setup("pthread_create monitor");
  }

  t0 = now_ns();
  for (i = 0; i < nthreads; i++) {
    ta[i].id = i;
    ta[i].base = (unsigned char*)g_lock;
    if (pthread_create(&th[i], NULL, worker, &ta[i]) != 0) {
      g_stop = 1;
      die_setup("pthread_create worker");
    }
  }

  ts.tv_sec = (time_t)seconds;
  ts.tv_nsec = 0;
  nanosleep(&ts, NULL);
  g_stop = 1;

  for (i = 0; i < nthreads; i++) {
    pthread_join(th[i], NULL);
  }
  pthread_join(mon, NULL);
  t1 = now_ns();

  for (i = 0; i < nthreads; i++) {
    total_acq += g_stat[i].acq;
    total_fail += g_stat[i].fail;
    total_ovl += g_stat[i].overlap;
    if (g_stat[i].acq < min_acq) {
      min_acq = g_stat[i].acq;
    }
    if (g_stat[i].acq > max_acq) {
      max_acq = g_stat[i].acq;
    }
    if (g_stat[i].acq == 0) {
      zero_progress_threads++;
    }
  }
  if (min_acq == UINT64_MAX) {
    min_acq = 0;
  }

  {
    uint32_t counter = g_shared;
    uint32_t expect  = (uint32_t)total_acq;
    int64_t  lost    = (int64_t)(int32_t)(expect - counter);
    double   secs    = (double)(t1 - t0) / 1e9;

    printf("\n[%s] variant %c  threads=%d  %.2fs\n", armname, variant_b ? 'B' : 'A', nthreads, secs);
    printf("  acquisitions total ........ %" PRIu64 "  (%.0f/s)\n", total_acq, secs > 0 ? total_acq / secs : 0.0);
    printf("  failed attempts ........... %" PRIu64 "   <- each one flipped the word to FREE (see header sec.2)\n", total_fail);
    printf("  per-thread acq  min/max ... %" PRIu64 " / %" PRIu64 "\n", min_acq, max_acq);
    printf("  threads with zero progress  %d\n", zero_progress_threads);
    printf("  longest zero-progress gap . %" PRIu64 " ms  (%" PRIu64 " samples)\n", g_mon_stall_max_ms, g_mon_samples);
    printf("  shared counter ............ %" PRIu32 "  expected %" PRIu32 "  lost %" PRId64 "\n", counter, expect, lost);
    if (g_occupancy) {
      printf("  in-CS overlaps observed ... %" PRIu64 "\n", total_ovl);
    } else {
      printf("  in-CS overlaps observed ... (check DISABLED by --minimal; the 0 below is\n"
             "                              'not measured', not 'none happened')\n");
    }

    if (use_cas) {
      // GUARANTEED ZERO on any correct implementation (sec. 5.3).
      if (total_ovl != 0 || lost != 0) {
        printf("  VERDICT: BROKEN — the cas control lost exclusion. Either the harness is\n"
               "           wrong or FEX has a defect deeper than the one under test.\n"
               "           Every other number in this run is untrusted.\n");
        rc = EX_BROKEN;
      } else if (total_acq == 0) {
        printf("  VERDICT: ERROR — control arm made no progress at all.\n");
        rc = EX_ERROR;
      } else {
        printf("  VERDICT: control held (zero overlaps, counter exact).\n");
      }
    } else {
      // Exclusion counts here are DATA, not pass/fail (sec. 6a): the toggle
      // acquire manufactures spurious FREEs by itself, in both variants, on
      // any architecture. Compare A against B, never against zero.
      if (zero_progress_threads > 0 || g_mon_stall_max_ms >= opt_stall_ms || total_acq == 0) {
        printf("  VERDICT: LIVELOCK — %s\n", total_acq == 0            ? "no acquisitions at all" :
                                             zero_progress_threads > 0 ? "at least one thread never acquired" :
                                                                         "global progress stalled past the threshold");
        rc = EX_LIVELOCK;
      } else {
        printf("  VERDICT: no livelock. Exclusion loss above is EXPECTED in both variants\n"
               "           (toggle acquire, header sec.2/6a) — read it as a rate, A vs B.\n");
      }
    }

    printf("DATA arm=%s variant=%c threads=%d secs=%.3f acq=%" PRIu64 " fail=%" PRIu64 " min_acq=%" PRIu64
           " max_acq=%" PRIu64 " zeroprog=%d stall_max_ms=%" PRIu64 " counter=%" PRIu32 " expect=%" PRIu32
           " lost=%" PRId64 " overlap=%" PRIu64 " occupancy=%d lostrate=%.6g overlaprate=%.6g\n",
           armname, variant_b ? 'B' : 'A', nthreads, secs, total_acq, total_fail, min_acq, max_acq,
           zero_progress_threads, g_mon_stall_max_ms, counter, expect, lost, total_ovl, g_occupancy,
           total_acq ? (double)lost / (double)total_acq : 0.0, total_acq ? (double)total_ovl / (double)total_acq : 0.0);
  }

  free(th);
  free(ta);
  fflush(stdout);
  return rc;
}

static int run_swallow(int variant_b) {
  pthread_t* th;
  targ_t*    ta;
  pthread_t  relth;
  swrel_t    rel;
  int        i, rc = EX_CLEAN;
  int        k = opt_sw_threads;
  uint64_t   t0, t1;
  uint64_t   expect;
  uint32_t   got;
  int64_t    shortfall;

  expect = (uint64_t)k * (uint64_t)opt_sw_iters;
  if (expect >= 0x80000000ull) {
    fprintf(stderr, "probe_lockword: swallow: %d threads x %lu iters overflows bit 31; reduce --swallow-iters\n", k,
            opt_sw_iters);
    printf("RESULT: ERROR\n");
    exit(EX_ERROR);
  }

  th = (pthread_t*)calloc((size_t)k, sizeof(pthread_t));
  ta = (targ_t*)calloc((size_t)k, sizeof(targ_t));
  if (!th || !ta) {
    die_setup("calloc swallow arrays");
  }

  g_lock->w = 0; // bits 0..30 are the increment counter here; start clean
  g_sw_stop = 0;
  rel.base = (unsigned char*)g_lock;
  rel.variant_b = variant_b;
  rel.releases = 0;

  t0 = now_ns();
  if (pthread_create(&relth, NULL, sw_releaser, &rel) != 0) {
    die_setup("pthread_create releaser");
  }
  for (i = 0; i < k; i++) {
    ta[i].id = i;
    ta[i].base = (unsigned char*)g_lock;
    if (pthread_create(&th[i], NULL, sw_incrementer, &ta[i]) != 0) {
      g_sw_stop = 1;
      die_setup("pthread_create incrementer");
    }
  }
  for (i = 0; i < k; i++) {
    pthread_join(th[i], NULL);
  }
  g_sw_stop = 1;
  pthread_join(relth, NULL);
  t1 = now_ns();

  got = g_lock->w & 0x7fffffffu;
  shortfall = (int64_t)expect - (int64_t)got;

  {
    double secs = (double)(t1 - t0) / 1e9;
    double inc_rate_per_ns = secs > 0 ? (double)expect / (secs * 1e9) : 0.0;
    double loss_per_rel = rel.releases ? (double)shortfall / (double)rel.releases : 0.0;
    // duty = fraction of elapsed time the releaser spent inside a load..store
    // window. Because the increments are spread uniformly in time, the fraction
    // of increments lost estimates exactly that. It is also the linearity
    // check: the window estimate below is only meaningful while duty << 1.
    double duty = expect ? (double)shortfall / (double)expect : 0.0;
    double window_ns = inc_rate_per_ns > 0 ? loss_per_rel / inc_rate_per_ns : 0.0;
    int    saturated = (duty > 0.30);

    printf("\n[swallow] variant %c  incrementers=%d x %lu  release-gap=%lu  %.2fs\n", variant_b ? 'B' : 'A', k,
           opt_sw_iters, opt_rel_gap, secs);
    printf("  lock-add increments issued  %" PRIu64 "\n", expect);
    printf("  releases issued ........... %" PRIu64 "\n", rel.releases);
    printf("  word low31 observed ....... %" PRIu32 "\n", got);
    printf("  SHORTFALL (swallowed) ..... %" PRId64 "\n", shortfall);
    printf("  loss per release .......... %.6g\n", loss_per_rel);
    printf("  release duty cycle ........ %.6g   (want 0.01 .. 0.30)\n", duty);
    printf("  est. release window ....... %.1f ns   (shortfall * elapsed / (releases * increments))\n"
           "                                RELATIVE ONLY — varies with --release-gap by ~10x;\n"
           "                                hold the gap fixed across any comparison.\n",
           window_ns);
    if (shortfall > 1) {
      printf("  relative std. error ....... ~%.1f%%   (1/sqrt(shortfall))\n", 100.0 / sqrt((double)shortfall));
    }

    if (shortfall < 0) {
      printf("  VERDICT: ERROR — negative shortfall. Harness bug; the word gained\n"
             "           increments, which no interleaving permits.\n");
      rc = EX_ERROR;
    } else if (variant_b) {
      // DETERMINISTIC INVARIANT: lock or is atomic, so nothing can be swallowed.
      if (shortfall != 0) {
        printf("  VERDICT: BROKEN — a LOCK-prefixed OR lost an increment. This is an\n"
               "           atomicity failure in FEX itself, not the window under test.\n");
        rc = EX_BROKEN;
      } else {
        printf("  VERDICT: invariant held (must be exactly 0; it is).\n");
      }
    } else if (saturated) {
      printf("  VERDICT: SATURATED — duty cycle %.3f is too high for the window estimate\n"
             "           to mean anything; at this rate a 5 ns window and a 500 ns window\n"
             "           both read as 'nearly all of them'. RAISE --release-gap (try %lu)\n"
             "           and re-run. The shortfall is still proof the window exists.\n",
             duty, opt_rel_gap ? opt_rel_gap * 8 : 100);
    } else if (shortfall <= 1) {
      printf("  VERDICT: NO EVIDENCE — 0 or 1 is within the single tail loss possible by\n"
             "           construction. Either the window is genuinely tiny, or too few\n"
             "           releases landed: LOWER --release-gap (try %lu) or raise\n"
             "           --swallow-iters, then re-run before concluding anything.\n",
             opt_rel_gap / 4);
    } else {
      printf("  VERDICT: window measured. This is the number the hypothesis is about.\n"
             "           Compare across FEX_TSOENABLED / FEX_LOCKONLYTSO (header sec.6f);\n"
             "           a monotone shrink there is what implicates the barriers.\n");
    }

    printf("DATA arm=swallow variant=%c incthreads=%d iters=%lu relgap=%lu secs=%.3f increments=%" PRIu64
           " releases=%" PRIu64 " low31=%" PRIu32 " shortfall=%" PRId64
           " loss_per_release=%.6g duty=%.6g est_window_ns=%.3f saturated=%d\n",
           variant_b ? 'B' : 'A', k, opt_sw_iters, opt_rel_gap, secs, expect, rel.releases, got, shortfall,
           loss_per_rel, duty, window_ns, saturated);
  }

  free(th);
  free(ta);
  fflush(stdout);
  return rc;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

static void usage(void) {
  printf("probe_lockword — FEX ppc64le plain-store RMW release-window probe\n"
         "\n"
         "  --test lockword|swallow|cas|all   default all\n"
         "  --variant a|b|both                default both\n"
         "  --threads N                       contended threads, default 128\n"
         "  --seconds S                       per lockword arm, default 20\n"
         "  --cas-seconds S                   per cas arm, default 5\n"
         "  --swallow-iters N                 lock-adds per incrementer, default 20000000\n"
         "  --swallow-threads N               incrementer threads, default 4\n"
         "  --backoff N                       pause iterations after a failed acquire, default 0\n"
         "  --hold N                          pause iterations inside the critical section, default 0\n"
         "  --release-gap N                   pause iterations between swallow releases, default 100\n"
         "                                    (tune so the reported duty cycle lands in 0.01..0.30)\n"
         "  --minimal                         strip in-CS instrumentation (for IR dumps)\n"
         "  --stall-ms N                      zero-progress gap that counts as livelock, default 2000\n"
         "  --sample-ms N                     monitor period, default 100\n"
         "  --timeout S                       hard watchdog, default 600\n"
         "  --help\n"
         "\n"
         "Exit: 0 CLEAN, 1 LIVELOCK, 2 BROKEN (guaranteed-zero invariant violated), 3 ERROR\n");
}

static unsigned long need_ul(int argc, char** argv, int* i, const char* what) {
  if (*i + 1 >= argc) {
    fprintf(stderr, "probe_lockword: %s needs a value\n", what);
    printf("RESULT: ERROR\n");
    exit(EX_ERROR);
  }
  (*i)++;
  return strtoul(argv[*i], NULL, 0);
}

int main(int argc, char** argv) {
  int   i;
  void* mem;

  for (i = 1; i < argc; i++) {
    const char* a = argv[i];
    if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
      usage();
      return 0;
    } else if (!strcmp(a, "--test")) {
      if (i + 1 >= argc) {
        die_setup("--test needs a value");
      }
      i++;
      opt_do_lockword = opt_do_swallow = opt_do_cas = 0;
      if (!strcmp(argv[i], "all")) {
        opt_do_lockword = opt_do_swallow = opt_do_cas = 1;
      } else if (!strcmp(argv[i], "lockword")) {
        opt_do_lockword = 1;
      } else if (!strcmp(argv[i], "swallow")) {
        opt_do_swallow = 1;
      } else if (!strcmp(argv[i], "cas")) {
        opt_do_cas = 1;
      } else {
        fprintf(stderr, "probe_lockword: unknown --test %s\n", argv[i]);
        printf("RESULT: ERROR\n");
        return EX_ERROR;
      }
    } else if (!strcmp(a, "--variant")) {
      if (i + 1 >= argc) {
        die_setup("--variant needs a value");
      }
      i++;
      opt_var_a = opt_var_b = 0;
      if (!strcmp(argv[i], "a")) {
        opt_var_a = 1;
      } else if (!strcmp(argv[i], "b")) {
        opt_var_b = 1;
      } else if (!strcmp(argv[i], "both")) {
        opt_var_a = opt_var_b = 1;
      } else {
        fprintf(stderr, "probe_lockword: unknown --variant %s\n", argv[i]);
        printf("RESULT: ERROR\n");
        return EX_ERROR;
      }
    } else if (!strcmp(a, "--threads")) {
      opt_threads = (int)need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--seconds")) {
      opt_seconds = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--cas-seconds")) {
      opt_cas_seconds = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--swallow-iters")) {
      opt_sw_iters = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--swallow-threads")) {
      opt_sw_threads = (int)need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--backoff")) {
      opt_backoff = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--hold")) {
      opt_hold = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--release-gap")) {
      opt_rel_gap = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--minimal")) {
      opt_minimal = 1;
    } else if (!strcmp(a, "--stall-ms")) {
      opt_stall_ms = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--sample-ms")) {
      opt_sample_ms = need_ul(argc, argv, &i, a);
    } else if (!strcmp(a, "--timeout")) {
      opt_timeout = need_ul(argc, argv, &i, a);
    } else {
      fprintf(stderr, "probe_lockword: unknown option %s\n", a);
      usage();
      printf("RESULT: ERROR\n");
      return EX_ERROR;
    }
  }

  if (opt_threads < 1 || opt_threads > 4096) {
    fprintf(stderr, "probe_lockword: --threads out of range\n");
    printf("RESULT: ERROR\n");
    return EX_ERROR;
  }
  if (opt_sw_threads < 1 || opt_sw_threads > 256) {
    fprintf(stderr, "probe_lockword: --swallow-threads out of range\n");
    printf("RESULT: ERROR\n");
    return EX_ERROR;
  }
  if (opt_sample_ms < 1) {
    opt_sample_ms = 1;
  }

  if (posix_memalign(&mem, 4096, sizeof(lockobj_t)) != 0) {
    die_setup("posix_memalign lock object");
  }
  memset(mem, 0, sizeof(lockobj_t));
  g_lock = (lockobj_t*)mem;

  g_stat = (tstat_t*)calloc((size_t)opt_threads, sizeof(tstat_t));
  if (!g_stat) {
    die_setup("calloc stats");
  }

  if (signal(SIGALRM, on_alarm) == SIG_ERR) {
    die_setup("signal SIGALRM");
  }
  alarm((unsigned)opt_timeout);

  printf("probe_lockword: threads=%d seconds=%lu swallow=%dx%lu minimal=%d backoff=%lu\n", opt_threads, opt_seconds,
         opt_sw_threads, opt_sw_iters, opt_minimal, opt_backoff);
  printf("  variant A = plain   `or DWORD PTR [mem], 0x80000000`  (what the game does)\n");
  printf("  variant B = locked  `lock or DWORD PTR [mem], 0x80000000`  (diagnostic only)\n");
  fflush(stdout);

  // Mechanism arm first: it is the one that carries the argument, and it is
  // cheap. If it says nothing, the rest is atmosphere.
  if (opt_do_swallow) {
    if (opt_var_a) {
      worse(run_swallow(0));
    }
    if (opt_var_b) {
      worse(run_swallow(1));
    }
  }
  if (opt_do_cas) {
    if (opt_var_a) {
      worse(run_contended("cas", 0, 1, opt_cas_seconds));
    }
    if (opt_var_b) {
      worse(run_contended("cas", 1, 1, opt_cas_seconds));
    }
  }
  if (opt_do_lockword) {
    if (opt_var_a) {
      worse(run_contended("lockword", 0, 0, opt_seconds));
    }
    if (opt_var_b) {
      worse(run_contended("lockword", 1, 0, opt_seconds));
    }
  }

  printf("\nRESULT: %s\n", g_worst == EX_CLEAN      ? "CLEAN" :
                           g_worst == EX_LIVELOCK   ? "LIVELOCK" :
                           g_worst == EX_BROKEN     ? "BROKEN" :
                                                      "ERROR");
  fflush(stdout);
  return g_worst;
}
