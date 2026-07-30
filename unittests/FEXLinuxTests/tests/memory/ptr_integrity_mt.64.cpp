// SPDX-License-Identifier: MIT
/*
 * ptr_integrity_mt.64 — TIER 6 of the pointer-integrity ladder: everything under two
 * threads. Run this only after ptr_integrity.64 is clean; if tiers 0-5 fail, a failure
 * here tells you nothing new.
 *
 * WHY A SECOND BINARY RATHER THAN A SIXTH TIER IN THE FIRST ONE
 * ------------------------------------------------------------
 * Two reasons, both practical.
 *
 * 1. This is the only file in the pair that needs -lpthread. Keeping it separate means a
 *    forgotten link line cannot take tiers 0-5 down with it.
 * 2. Catch2's assertion macros are not thread-safe, so a worker thread must not call
 *    REQUIRE/CHECK/FAIL. Every check here therefore records into a per-thread counter and
 *    prints with printf (which is), and the Catch2 assertion happens once on the main
 *    thread after the join. Mixing that convention with the first file's
 *    throw-on-first-failure flow in one TU would be a trap for whoever edits it next.
 *
 * WHAT TIER 6 ADDS OVER TIER 5
 * ----------------------------
 * A second guest thread, which means:
 *   - a second dispatcher entry path: thread start. The r0 = 0 invariant comment at
 *     PPC64Dispatcher.cpp:184-190 names thread start alongside signal delivery as an
 *     entry that did not re-establish it.
 *   - cross-thread signal delivery (pthread_kill), so a handler runs on a thread that is
 *     parked in a PAUSE spin rather than on the one that called raise().
 *   - a real pointer handoff: one thread writes a 64-bit pointer to shared memory, the
 *     other loads it, checks the bits, and dereferences it. That is the Mono failure with
 *     the extra ingredient that made it hard to pin down.
 *   - PAUSE executed concurrently on two threads, so the per-thread PauseCount slow path
 *     fires on both, i.e. two threads inside the counter-gated helper call at once.
 *
 * WHAT IS AND IS NOT DETERMINISTIC HERE
 * -------------------------------------
 * Thread interleaving obviously is not. Nothing is asserted about it. The handoff is a
 * strict alternation with a bounded spin, every value compared is a fixed bit pattern, and
 * every per-thread check runs on that thread's own private arena. So the PASS/FAIL verdict
 * is deterministic even though the schedule is not. The one thing that varies run to run
 * is *where* a cross-thread signal lands, which is exactly the variation we want.
 *
 * MECHANISM TARGETED: primarily 2 (the r0 == 0 / rB index invariant), via entry paths that
 * only exist when there is more than one thread. Mechanism 1 (operand-width truncation) is
 * re-checked cheaply per thread, because a width bug that only shows up under concurrency
 * would be a register-allocation problem rather than a size-switch problem and is worth
 * distinguishing.
 *
 * =====================================================================================
 * REVIEWED BASELINE — NOT YET ESTABLISHED
 * =====================================================================================
 * Do not invent values. Fill this in from a real run and note who reviewed it.
 *
 *   date taken            : <NOT ESTABLISHED>
 *   FEX commit            : <NOT ESTABLISHED>   (written against cf608d750)
 *   host                  : <NOT ESTABLISHED>   (POWER9, model / kernel / page size)
 *   SMT setting           : <NOT ESTABLISHED>   ppc64_cpu --smt=?  — record it, because
 *                                               SMT4 vs SMT1 changes how often the two
 *                                               threads are actually concurrent, and thus
 *                                               how often the handoff spins at all
 *   pinning               : <NOT ESTABLISHED>   (none required)
 *   FEX_* vars            : ctest sets FEX_OUTPUTLOG=stderr FEX_SILENTLOG=0 FEX_MAXINST=500
 *   expected outcome      : all sub-tiers PASS on both threads, exit 0, zero FAIL lines
 *   handoff rounds        : 256 expected to complete
 *   cross-thread signals  : 16 expected to be delivered (round % 16 == 0)
 *   observed max spin     : <NOT ESTABLISHED>   printed at the end; if it ever approaches
 *                                               kMaxSpin the cap needs raising, and the
 *                                               run should not be trusted
 *   run time              : <NOT ESTABLISHED>   (must stay well under the 30s ctest timeout)
 * =====================================================================================
 *
 * BUILD REGISTRATION: needs one line added to unittests/FEXLinuxTests/tests/CMakeLists.txt
 * next to the other pthread users:
 *     target_link_libraries(ptr_integrity_mt.${BITNESS} PRIVATE pthread)
 * On glibc 2.34 and later pthread_create lives in libc proper and this may link without
 * it; add the line anyway so it does not depend on the rootfs.
 */

#include <catch2/catch_test_macros.hpp>

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

// =====================================================================================
// Patterns. Volatile so no check can be constant-folded into a tautology.
// =====================================================================================
static volatile uint64_t g_pat_a = 0xDEADBEEFCAFEBABEULL;
static volatile uint64_t g_pat_b = 0x1122334455667788ULL;
static volatile uint64_t g_pat_ptrlike = 0x0000036FE2F590D0ULL;
static volatile uint64_t g_deref_target = 0xA5A5F00DD00DBEEFULL;

static constexpr uint8_t kFill = 0x5A;
static constexpr uint64_t kFillWord = 0x5A5A5A5A5A5A5A5AULL;
static constexpr int kThreads = 2;
static constexpr int kPauseIters = 4096;   // > PAUSE_YIELD_LIMIT (1000)
static constexpr int kRounds = 256; // handoff rounds
// Hard cap on the handoff spin so a peer that bailed out early cannot hang ctest. Sized as
// a time budget, not a correctness threshold: ~2M iterations of (atomic load + pause) is
// roughly 20M guest instructions, i.e. a second or so under the JIT, which leaves plenty
// of room inside the 30s ctest timeout. In a healthy run the spin count stays in the tens.
static constexpr long kMaxSpin = 2000000;

static long g_page;

static inline void opaque() {
  __asm__ __volatile__("" ::: "memory");
}

// =====================================================================================
// Per-thread state. Each thread gets a private arena so its own checks cannot be
// disturbed by the other thread, and failures are attributed to a thread by construction.
// =====================================================================================
struct ThreadCtx {
  int id = 0;
  pthread_t tid {};
  uint8_t* arena = nullptr;
  size_t arena_size = 0;
  uint8_t* win = nullptr; // 256-byte window straddling a page boundary at win + 0x80
  int fails = 0;
  int checks = 0;
  bool stop_on_first = true;
  // Filled by the signal handler running on this thread.
  volatile int handler_hits = 0;
  volatile uint64_t handler_readback = 0;
  volatile uint64_t handler_inline_zero = 0;
  volatile uint64_t handler_call_result = 0;
  long max_spin = 0;
};

static ThreadCtx g_ctx[kThreads];

enum : size_t {
  OFF_W = 0x00,     // 16B width scratch
  OFF_PTR = 0x20,   // 8B pointer round trip
  OFF_VT = 0x28,    // 24B vtable {magic0, fn, magic1}
  OFF_T5 = 0x48,    // 8B pause/helper slot
  OFF_T5Z = 0x50,   // 8B inline-zero target
  OFF_SIGA = 0x58,  // 8B written by the thread, read by its handler
  OFF_STRAD = 0x7C, // 8B straddling the page boundary at 0x80
};
static constexpr size_t kWin = 256;

// =====================================================================================
// Reporting. printf only — no Catch2 from a worker thread.
// =====================================================================================
static void classify(int id, uint64_t exp, uint64_t got) {
  if ((got & 0xFFFFFFFFULL) == (exp & 0xFFFFFFFFULL) && (exp >> 32) != 0) {
    if ((got >> 32) == 0) {
      printf("  [t%d]   CLASS: high 32 bits zeroed -> 32-bit truncation (MECHANISM 1).\n", id);
      return;
    }
    if ((got >> 32) == 0xFFFFFFFFULL) {
      printf("  [t%d]   CLASS: high 32 bits all ones -> 32-bit sign extension.\n", id);
      return;
    }
  }
  if (got == kFillWord) {
    printf("  [t%d]   CLASS: arena filler -> nothing was written HERE; the access went to\n"
           "  [t%d]          EA + rB with rB != 0 (MECHANISM 2).\n",
           id, id);
    return;
  }
  if (got == 0) {
    printf("  [t%d]   CLASS: zero -> missed slot, or an inline-zero store (value operand r0)\n"
           "  [t%d]          landed on top of it.\n",
           id, id);
    return;
  }
  printf("  [t%d]   CLASS: unrelated value -> address offset or foreign data (MECHANISM 2).\n"
         "  [t%d]          A code-address-shaped value here is a leaked r0.\n",
         id, id);
}

static bool check_u64(ThreadCtx* c, const char* what, uint64_t exp, uint64_t got) {
  ++c->checks;
  if (exp == got) {
    return true;
  }
  ++c->fails;
  printf("  [t%d] FAIL %s\n"
         "  [t%d]   expect 0x%016" PRIx64 "\n"
         "  [t%d]   got    0x%016" PRIx64 "\n"
         "  [t%d]   xor    0x%016" PRIx64 "\n",
         c->id, what, c->id, exp, c->id, got, c->id, exp ^ got);
  classify(c->id, exp, got);
  fflush(stdout);
  return false;
}

// The canary: every byte of this thread's arena outside its 256-byte window must still be
// filler. A store that went to EA + rB lands out there, and the delta from the intended
// slot is the rB value.
static bool canary_ok(ThreadCtx* c, const char* where, uintptr_t intended_slot) {
  for (size_t i = 0; i < c->arena_size; ++i) {
    uint8_t* p = c->arena + i;
    if (p >= c->win && p < c->win + kWin) {
      continue;
    }
    if (*p != kFill) {
      uint64_t found = 0;
      for (int k = 0; k < 8; ++k) {
        size_t off = i + static_cast<size_t>(k);
        found |= static_cast<uint64_t>(off < c->arena_size ? c->arena[off] : 0) << (8 * k);
      }
      const ptrdiff_t delta = static_cast<ptrdiff_t>(reinterpret_cast<uintptr_t>(p) - intended_slot);
      ++c->fails;
      printf("  [t%d] FAIL canary after %s: arena+0x%zx damaged, 8 bytes there 0x%016" PRIx64 "\n"
             "  [t%d]   delta from this thread's window base: %+td\n",
             c->id, where, i, found, c->id, delta);
      if (delta > 0 && static_cast<uint64_t>(delta) == found) {
        printf("  [t%d]   *** CONFIRMED MECHANISM 2: the write landed `found` bytes past its\n"
               "  [t%d]       slot and the value written is that same number. r0 = 0x%016" PRIx64 ".\n",
               c->id, c->id, found);
      }
      fflush(stdout);
      return false;
    }
  }
  return true;
}

// =====================================================================================
// Shared handoff state. One cache line's worth of shared 64-bit slots; the pointer under
// test travels through `slot`.
// =====================================================================================
struct Shared {
  volatile uint64_t slot;
  volatile uint64_t echo;
  volatile uint32_t turn; // whose turn it is to write
  volatile uint32_t rounds_done;
  volatile uint32_t sigs_sent;
  volatile uint32_t sigs_seen;
  // Set by whichever thread leaves the handoff early. Without it the peer would spin to
  // kMaxSpin and bury the real diagnosis under a timeout message.
  volatile uint32_t abandon;
};
static Shared* g_shared;

// =====================================================================================
// Callees. The indirect-call target and the code the far stub loads through.
// =====================================================================================
using Fn1 = uint64_t (*)(const volatile uint64_t*);

__attribute__((noinline)) static uint64_t callee_load64(const volatile uint64_t* p) {
  return *p;
}

struct VTable {
  uint64_t magic0;
  Fn1 fn;
  uint64_t magic1;
};

// =====================================================================================
// The signal handler. Runs on whichever thread was signalled; identifies itself by
// pthread_self() rather than by TLS, so this test does not additionally depend on
// thread-local storage being correct inside a handler.
// =====================================================================================
static void usr1_handler(int, siginfo_t*, void*) {
  ThreadCtx* c = nullptr;
  const pthread_t self = pthread_self();
  for (int i = 0; i < kThreads; ++i) {
    if (pthread_equal(g_ctx[i].tid, self)) {
      c = &g_ctx[i];
      break;
    }
  }
  if (c == nullptr || c->win == nullptr) {
    return; // signalled before the thread published its context; nothing to check
  }
  c->handler_hits = c->handler_hits + 1;

  // Read a value the thread stored before it could have been interrupted.
  c->handler_readback = *reinterpret_cast<volatile uint64_t*>(c->win + OFF_SIGA);

  // An inline-constant zero store. On this backend the value operand of such a store is
  // r0, so a nonzero result here is r0's contents printed verbatim.
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(c->win + OFF_T5Z);
  *z = ~0ULL;
  *z = 0;
  c->handler_inline_zero = *z;

  // A pointer load plus an indirect call, from inside the handler.
  VTable* vt = reinterpret_cast<VTable*>(c->win + OFF_VT);
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(c->win + OFF_PTR);
  *slot = g_pat_ptrlike;
  c->handler_call_result = vt->fn(slot);

  __atomic_add_fetch(&g_shared->sigs_seen, 1U, __ATOMIC_SEQ_CST);
}

// =====================================================================================
// 6a — widths on a private arena, on this thread.
// =====================================================================================
static bool t6_widths(ThreadCtx* c) {
  uint8_t* slot = c->win + OFF_W;
  bool ok = true;
  static const int widths[] = {1, 2, 4, 8};
  for (size_t wi = 0; wi < sizeof(widths) / sizeof(widths[0]); ++wi) {
    const int w = widths[wi];
    for (int i = 0; i < 16; ++i) {
      reinterpret_cast<volatile uint8_t*>(slot)[i] = kFill;
    }
    opaque();
    const uint64_t v = (w >= 8) ? g_pat_a : (g_pat_a & ((1ULL << (8 * w)) - 1ULL));
    switch (w) {
    case 1: *reinterpret_cast<volatile uint8_t*>(slot) = static_cast<uint8_t>(v); break;
    case 2: *reinterpret_cast<volatile uint16_t*>(slot) = static_cast<uint16_t>(v); break;
    case 4: *reinterpret_cast<volatile uint32_t*>(slot) = static_cast<uint32_t>(v); break;
    case 8: *reinterpret_cast<volatile uint64_t*>(slot) = v; break;
    default: break;
    }
    opaque();
    // Read the whole 16 bytes back as bytes: catches a store that was too narrow (filler
    // survives where data belongs) and one that was too wide (data where filler belongs).
    uint64_t image_lo = 0, image_hi = 0;
    for (int i = 0; i < 8; ++i) {
      image_lo |= static_cast<uint64_t>(reinterpret_cast<volatile uint8_t*>(slot)[i]) << (8 * i);
      image_hi |= static_cast<uint64_t>(reinterpret_cast<volatile uint8_t*>(slot)[i + 8]) << (8 * i);
    }
    uint64_t want_lo = kFillWord;
    for (int i = 0; i < w; ++i) {
      want_lo &= ~(0xFFULL << (8 * i));
      want_lo |= (v & (0xFFULL << (8 * i)));
    }
    char name[96];
    snprintf(name, sizeof(name), "6a: %d-bit store, byte image of the first 8 bytes", w * 8);
    ok = check_u64(c, name, want_lo, image_lo) && ok;
    snprintf(name, sizeof(name), "6a: %d-bit store must not touch the next 8 bytes", w * 8);
    ok = check_u64(c, name, kFillWord, image_hi) && ok;
    if (!ok && c->stop_on_first) {
      return false;
    }
  }
  return ok;
}

// =====================================================================================
// 6b — pointer round trip and an indirect call, on this thread's private arena.
// =====================================================================================
static bool t6_pointer(ThreadCtx* c) {
  volatile uint64_t* raw = reinterpret_cast<volatile uint64_t*>(c->win + OFF_VT);
  VTable* vt = reinterpret_cast<VTable*>(c->win + OFF_VT);
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(c->win + OFF_PTR);
  bool ok = true;

  raw[0] = g_pat_a;
  vt->fn = &callee_load64;
  raw[2] = g_pat_b;
  opaque();
  ok = check_u64(c, "6b: guard word before the fn pointer", g_pat_a, raw[0]) && ok;
  ok = check_u64(c, "6b: fn pointer bits through memory", reinterpret_cast<uint64_t>(&callee_load64), raw[1]) && ok;
  ok = check_u64(c, "6b: guard word after the fn pointer", g_pat_b, raw[2]) && ok;
  if (!ok && c->stop_on_first) {
    return false;
  }

  *slot = g_pat_ptrlike;
  opaque();
  Fn1 fn = vt->fn;
  ok = check_u64(c, "6b: fn pointer loaded into a register", reinterpret_cast<uint64_t>(&callee_load64),
                 reinterpret_cast<uint64_t>(fn)) &&
       ok;
  ok = check_u64(c, "6b: value read by the indirectly-called callee", g_pat_ptrlike, fn(slot)) && ok;

  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  *slot = real;
  opaque();
  ok = check_u64(c, "6b: address of a real object through memory", real, *slot) && ok;
  if (ok) {
    ok = check_u64(c, "6b: that pointer dereferences", g_deref_target,
                   *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(*slot))) &&
         ok;
  }
  return ok;
}

// =====================================================================================
// 6c — PAUSE storm on this thread. Each thread has its own PauseCount in its own
// CpuStateFrame, so each must cross PAUSE_YIELD_LIMIT independently, and with two threads
// running this concurrently two of them are inside the counter-gated helper call at once.
// =====================================================================================
static bool t6_pause(ThreadCtx* c) {
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(c->win + OFF_T5);
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(c->win + OFF_T5Z);
  const uint64_t pat = g_pat_a;
  int bad_value = 0, bad_zero = 0, first_bad_i = -1, second_bad_i = -1;
  uint64_t first_bad_value = 0, first_bad_zero = 0;

  for (int i = 0; i < kPauseIters; ++i) {
    *p = pat;
    *z = ~0ULL;
    __asm__ __volatile__("pause" ::: "memory");
    const uint64_t got = *p;
    *z = 0;
    const uint64_t gotz = *z;
    if (got != pat) {
      if (!bad_value) {
        first_bad_value = got;
      }
      ++bad_value;
    }
    if (gotz != 0) {
      if (!bad_zero) {
        first_bad_zero = gotz;
      }
      ++bad_zero;
    }
    if ((got != pat || gotz != 0)) {
      if (first_bad_i < 0) {
        first_bad_i = i;
      } else if (second_bad_i < 0) {
        second_bad_i = i;
      }
    }
  }

  if (bad_value == 0 && bad_zero == 0) {
    return true;
  }
  c->fails += (bad_value ? 1 : 0) + (bad_zero ? 1 : 0);
  printf("  [t%d] FAIL 6c: PAUSE storm: %d/%d read-backs corrupt, %d/%d inline-zero stores\n"
         "  [t%d]   did not produce zero. first failing iteration %d",
         c->id, bad_value, kPauseIters, bad_zero, kPauseIters, c->id, first_bad_i);
  if (second_bad_i >= 0) {
    printf(", second %d, period %d", second_bad_i, second_bad_i - first_bad_i);
  }
  printf("\n");
  if (second_bad_i >= 0 && (second_bad_i - first_bad_i) >= 900 && (second_bad_i - first_bad_i) <= 1100) {
    printf("  [t%d]   *** period ~1000 = PAUSE_YIELD_LIMIT (ALUOps.cpp:3154). Only the\n"
           "  [t%d]       counter-gated slow path is broken: its helper call is not\n"
           "  [t%d]       restoring r0 = 0. MECHANISM 2.\n",
           c->id, c->id, c->id);
  }
  if (bad_value) {
    printf("  [t%d]   first corrupt read-back 0x%016" PRIx64 " (expected 0x%016" PRIx64 ")\n", c->id, first_bad_value,
           pat);
    classify(c->id, pat, first_bad_value);
  }
  if (bad_zero) {
    printf("  [t%d]   first non-zero result from an inline-zero store: 0x%016" PRIx64 "\n"
           "  [t%d]   that store's value operand is r0, so that number is r0's contents.\n",
           c->id, first_bad_zero, c->id);
  }
  fflush(stdout);
  return false;
}

// =====================================================================================
// 6d — a signal delivered to this thread while it is doing memory work. The thread
// signals itself here; the cross-thread case is driven from the handoff in 6e, which is
// the interesting one (a handler entering on a thread parked in a PAUSE spin).
// =====================================================================================
static bool t6_self_signal(ThreadCtx* c) {
  volatile uint64_t* a = reinterpret_cast<volatile uint64_t*>(c->win + OFF_SIGA);
  VTable* vt = reinterpret_cast<VTable*>(c->win + OFF_VT);
  vt->fn = &callee_load64;
  *a = g_pat_b;
  opaque();

  const int before = c->handler_hits;
  c->handler_readback = 0;
  c->handler_inline_zero = ~0ULL;
  c->handler_call_result = 0;

  // pthread_self() rather than c->tid: c->tid is published by the parent and this thread
  // must not depend on that store having become visible yet.
  if (pthread_kill(pthread_self(), SIGUSR1) != 0) {
    ++c->fails;
    printf("  [t%d] FAIL 6d: pthread_kill to self failed\n", c->id);
    return false;
  }
  // A self-directed signal is normally delivered before pthread_kill returns. Spin briefly
  // rather than assuming it, so a delivery delay reads as a delay and not as a corruption.
  for (long spin = 0; spin < 1000000 && c->handler_hits == before; ++spin) {
    __asm__ __volatile__("pause" ::: "memory");
  }
  opaque();

  bool ok = true;
  ok = check_u64(c, "6d: handler ran", static_cast<uint64_t>(before + 1), static_cast<uint64_t>(c->handler_hits)) && ok;
  ok = check_u64(c, "6d: handler read the pre-signal value", g_pat_b, c->handler_readback) && ok;
  ok = check_u64(c, "6d: handler's inline-zero store landed as zero", 0, c->handler_inline_zero) && ok;
  ok = check_u64(c, "6d: handler's indirect call result", g_pat_ptrlike, c->handler_call_result) && ok;
  ok = check_u64(c, "6d: pre-signal value intact after sigreturn", g_pat_b, *a) && ok;

  // And a fresh pointer round trip in the block resumed after sigreturn.
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(c->win + OFF_PTR);
  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  *slot = real;
  opaque();
  ok = check_u64(c, "6d: pointer round trip after sigreturn", real, *slot) && ok;
  return ok;
}

// =====================================================================================
// 6e — the handoff. Strict alternation, so the sequence of values is deterministic even
// though the timing is not. The spin uses PAUSE, which is both the realistic idiom and a
// second way to reach the counter-gated slow path. Every 16th round, whichever thread is
// about to hand over first pokes its peer with SIGUSR1, so a handler enters on a thread
// that is spinning inside a block rather than on one that asked for it.
// =====================================================================================
static bool t6_handoff(ThreadCtx* c) {
  const uint32_t me = static_cast<uint32_t>(c->id);
  const uint32_t peer = 1u - me;
  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  bool ok = true;

  for (int r = 0; r < kRounds; ++r) {
    // Wait for our turn.
    long spins = 0;
    while (__atomic_load_n(&g_shared->turn, __ATOMIC_ACQUIRE) != me) {
      __asm__ __volatile__("pause" ::: "memory");
      if (++spins > c->max_spin) {
        c->max_spin = spins;
      }
      if (__atomic_load_n(&g_shared->abandon, __ATOMIC_ACQUIRE) != 0) {
        printf("  [t%d] 6e: peer left the handoff at round %d; stopping too. The peer's\n"
               "  [t%d]   output above is the diagnosis, not this line.\n",
               c->id, r, c->id);
        fflush(stdout);
        return ok;
      }
      if (spins > kMaxSpin) {
        ++c->fails;
        printf("  [t%d] FAIL 6e: spun %ld times waiting for round %d; giving up rather than\n"
               "  [t%d]   hanging the test. Either the peer died without setting the abandon\n"
               "  [t%d]   flag, or a flag store is not becoming visible to this thread.\n",
               c->id, spins, r, c->id, c->id);
        fflush(stdout);
        __atomic_store_n(&g_shared->abandon, 1U, __ATOMIC_RELEASE);
        return false;
      }
      if ((spins & 0x3FF) == 0) {
        sched_yield();
      }
    }

    if (me == 0) {
      // Thread 0 first checks what thread 1 wrote back last round, so both threads are
      // making claims rather than one just feeding the other.
      if (r > 0) {
        char name[96];
        const uint64_t back_slot = g_shared->slot;
        const uint64_t back_echo = g_shared->echo;
        snprintf(name, sizeof(name), "6e round %d: value written back by the peer", r);
        ok = check_u64(c, name, g_pat_ptrlike, back_slot) && ok;
        snprintf(name, sizeof(name), "6e round %d: companion pattern written back by the peer", r);
        ok = check_u64(c, name, g_pat_b, back_echo) && ok;
        if (!ok && c->stop_on_first) {
          // Tell the peer to stop too; leaving it to spin to its cap would bury this
          // diagnosis under a timeout message from the other thread.
          __atomic_store_n(&g_shared->abandon, 1U, __ATOMIC_RELEASE);
          __atomic_store_n(&g_shared->turn, peer, __ATOMIC_RELEASE);
          return false;
        }
      }
      // Thread 0 publishes a real pointer, plus a pattern in `echo`.
      g_shared->slot = real;
      g_shared->echo = g_pat_a;
      opaque();
      if (r % 16 == 0) {
        __atomic_add_fetch(&g_shared->sigs_sent, 1U, __ATOMIC_SEQ_CST);
        pthread_kill(g_ctx[peer].tid, SIGUSR1);
      }
      __atomic_store_n(&g_shared->turn, peer, __ATOMIC_RELEASE);
    } else {
      // Thread 1 consumes it: check the bits, then dereference.
      const uint64_t got = g_shared->slot;
      const uint64_t got_echo = g_shared->echo;
      char name[96];
      snprintf(name, sizeof(name), "6e round %d: pointer bits across a thread handoff", r);
      const bool bits_ok = check_u64(c, name, real, got);
      snprintf(name, sizeof(name), "6e round %d: companion pattern across a thread handoff", r);
      ok = check_u64(c, name, g_pat_a, got_echo) && ok;
      if (bits_ok) {
        snprintf(name, sizeof(name), "6e round %d: dereference of the handed-over pointer", r);
        ok = check_u64(c, name, g_deref_target, *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(got))) && ok;
      } else {
        ok = false;
        // Do not dereference a pointer we already know is wrong; that is a crash, not a
        // diagnosis. The bits above are the diagnosis.
        printf("  [t%d]   not dereferencing a pointer already known to be wrong\n", c->id);
      }
      g_shared->slot = g_pat_ptrlike;
      g_shared->echo = g_pat_b;
      opaque();
      __atomic_add_fetch(&g_shared->rounds_done, 1U, __ATOMIC_SEQ_CST);
      if (!ok && c->stop_on_first) {
        __atomic_store_n(&g_shared->abandon, 1U, __ATOMIC_RELEASE);
        __atomic_store_n(&g_shared->turn, peer, __ATOMIC_RELEASE);
        return false;
      }
      __atomic_store_n(&g_shared->turn, peer, __ATOMIC_RELEASE);
    }
  }
  return ok;
}

// =====================================================================================
// Thread body.
// =====================================================================================
static void* thread_main(void* arg) {
  ThreadCtx* c = static_cast<ThreadCtx*>(arg);
  struct {
    const char* name;
    bool (*fn)(ThreadCtx*);
  } steps[] = {
    {"6a widths", &t6_widths},
    {"6b pointer round trip and indirect call", &t6_pointer},
    {"6c PAUSE storm", &t6_pause},
    {"6d self-directed signal", &t6_self_signal},
    {"6e cross-thread pointer handoff", &t6_handoff},
  };

  for (const auto& s : steps) {
    printf("  [t%d] ENTER %s\n", c->id, s.name);
    fflush(stdout);
    const bool ok = s.fn(c);
    if (!canary_ok(c, s.name, reinterpret_cast<uintptr_t>(c->win))) {
      if (c->stop_on_first) {
        return nullptr;
      }
    }
    if (!ok) {
      printf("  [t%d] FAILED at %s\n", c->id, s.name);
      fflush(stdout);
      if (c->stop_on_first) {
        return nullptr;
      }
    } else {
      printf("  [t%d] PASS %s\n", c->id, s.name);
      fflush(stdout);
    }
  }
  return nullptr;
}

// =====================================================================================
// Setup and the single Catch2 assertion.
// =====================================================================================
static bool make_arena(ThreadCtx* c) {
  c->arena_size = static_cast<size_t>(g_page) * 4;
  void* raw = mmap(nullptr, c->arena_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) {
    return false;
  }
  c->arena = static_cast<uint8_t*>(raw);
  memset(c->arena, kFill, c->arena_size);
  // Window straddles the boundary between arena page 1 and page 2, at window + 0x80.
  c->win = c->arena + static_cast<size_t>(g_page) * 2 - 0x80;
  return (reinterpret_cast<uintptr_t>(c->win) & 0xF) == 0;
}

TEST_CASE("64-bit value integrity through guest memory: tier 6, two threads") {
  setvbuf(stdout, nullptr, _IONBF, 0); // a crash must not eat the last marker printed

  g_page = sysconf(_SC_PAGESIZE);
  REQUIRE(g_page >= 4096);

  const char* all = getenv("PTR_INTEGRITY_ALL_TIERS");
  const bool run_all = all != nullptr && all[0] == '1';

  void* shared_raw = mmap(nullptr, static_cast<size_t>(g_page), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(shared_raw != MAP_FAILED);
  g_shared = static_cast<Shared*>(shared_raw);
  memset(g_shared, 0, sizeof(*g_shared));
  g_shared->turn = 0;

  for (int i = 0; i < kThreads; ++i) {
    g_ctx[i].id = i;
    g_ctx[i].stop_on_first = !run_all;
    REQUIRE(make_arena(&g_ctx[i]));
  }

  struct sigaction act {};
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = &usr1_handler;
  sigemptyset(&act.sa_mask);
  REQUIRE(sigaction(SIGUSR1, &act, nullptr) == 0);

  printf("ptr_integrity_mt.64: page size %ld, %d threads, %d handoff rounds, %d pause iterations\n", g_page, kThreads,
         kRounds, kPauseIters);
  printf("ptr_integrity_mt.64: mode = %s\n", run_all ? "run every step" : "each thread stops at its first failure");
  fflush(stdout);

  // Thread 0 is this thread; thread 1 is spawned. Doing it that way means one of the two
  // participants went through the guest thread-start dispatcher entry and the other did
  // not, so a failure that appears only on thread 1 implicates thread start specifically.
  g_ctx[0].tid = pthread_self();
  pthread_t worker {};
  REQUIRE(pthread_create(&worker, nullptr, &thread_main, &g_ctx[1]) == 0);
  // Published by the parent only; the worker never writes it, so there is no race on it.
  // Nothing reads it until the handoff, which is the worker's last step.
  g_ctx[1].tid = worker;
  thread_main(&g_ctx[0]);
  REQUIRE(pthread_join(worker, nullptr) == 0);

  // Copy the shared counters into plain locals before asserting on them: Catch2 binds the
  // operands of CHECK/REQUIRE by const reference, and a const reference cannot bind to a
  // volatile lvalue.
  const uint32_t rounds_done = g_shared->rounds_done;
  const uint32_t sigs_sent = g_shared->sigs_sent;
  const uint32_t sigs_seen = g_shared->sigs_seen;
  const uint32_t abandoned = g_shared->abandon;

  printf("ptr_integrity_mt.64: handoff rounds completed %u of %d, signals sent %u, seen %u, abandoned %u\n",
         rounds_done, kRounds, sigs_sent, sigs_seen, abandoned);
  for (int i = 0; i < kThreads; ++i) {
    printf("ptr_integrity_mt.64: thread %d: %d checks, %d failures, max spin %ld\n", i, g_ctx[i].checks, g_ctx[i].fails,
           g_ctx[i].max_spin);
  }
  fflush(stdout);

  // The Catch2 assertions, on the main thread, after the join.
  CHECK(g_ctx[0].fails == 0);
  CHECK(g_ctx[1].fails == 0);
  // A short handoff means a thread bailed out early. Assert it explicitly, otherwise a run
  // where nothing happened would look exactly like a clean one.
  CHECK(rounds_done == static_cast<uint32_t>(kRounds));
  REQUIRE(g_ctx[0].fails + g_ctx[1].fails == 0);
}
