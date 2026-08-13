/*
 * sao_litmus.c — memory-ordering litmus discriminator for PROT_SAO on POWER.
 *
 * Purpose: prove (or refute) that pages mapped with PROT_SAO (Strong Access
 * Ordering, powerpc, 0x10) give x86-TSO-like ordering to PLAIN loads/stores,
 * which is the gate for FEX's hardware-TSO integration (FEX_HWTSO): if guest
 * memory is hardware-ordered, the JIT stops emitting per-access lwsync.
 *
 * Shapes:
 *   MP (message passing) — writer: x=1 then y=1 (plain volatile stores, no
 *     barriers); reader: spin-load y (bounded) then load x. Violation =
 *     observed y==1 with x==0. Requires st-st + ld-ld ordering to forbid.
 *       - plain anonymous page: violations EXPECTED on POWER8 (validates the
 *         harness can see reordering at all — a 0 here proves nothing).
 *       - PROT_SAO page: must be EXACTLY 0. TSO forbids MP.
 *   SB (store buffering) — t0: x=1; r0=y.  t1: y=1; r1=x. Violation(SC) =
 *     r0==0 && r1==0. TSO ALLOWS this (store buffer), so SAO may legally
 *     show it — informational sanity check that SAO is TSO-like, not
 *     sequentially consistent.
 *
 * Mechanics: SLOTS independent {x[i], y[i]} pairs at 128B stride (P8 cache
 * line) inside ONE mapping (x array in first half, y array in second half —
 * both halves SAO when SAO is requested). Per round, a coordinator resets the
 * arrays, release-publishes a round number, both pinned threads
 * acquire-spin on it, apply random start jitter, then walk the slots. The
 * only atomics/barriers are in the round handshake, never between the test
 * accesses. Reader's bounded spin on y[i] then load of x[i] is ctrl-dep only
 * — POWER does NOT order ld-ctrl-ld without isync, so the reader side races
 * too (this is the standard high-yield MP+ctrl shape).
 *
 * Usage: ./sao_litmus <mp|sb> <plain|sao|sao-mprot|plain-addsao> <rounds> \
 *                     <cpu_writer> <cpu_reader>
 *   Both CPUs must be in the same NUMA node and DIFFERENT physical cores.
 *   Opportunities per run = rounds * SLOTS (2048), i.e. 500 rounds > 1M.
 *   sao-mprot / plain-addsao prove mprotect interactions (see main()).
 *
 * Build: cc -O2 -pthread -o sao_litmus sao_litmus.c
 *
 * ============================ RESULTS (op4k) ============================
 * 2026-08-13, op4k (POWER8 raw pvr 004d 0200, kernel 7.2.0-rc5-books-4k,
 * 4K pages, hash MMU). CPUs 4-7 are OFFLINE there; used writer=8 reader=16
 * (different physical cores, both NUMA node 0). No FEX/wine/proton running
 * (checked before each session; load avg ~0.9 background).
 *
 *   MP plain  500 rounds: opportunities=1019523  violations=10662
 *   MP plain 1000 rounds: opportunities=2037852  violations=24232
 *   MP plain 1000 rounds: opportunities=2038292  violations=22548
 *   MP plain 1000 rounds: opportunities=2038100  violations=24597
 *     -> harness observes real POWER8 MP reordering, ~1.1-1.2% of
 *        opportunities. A zero below is therefore meaningful.
 *
 *   MP sao   1000 rounds: opportunities=2038896  violations=0
 *   MP sao   1000 rounds: opportunities=2034638  violations=0
 *   MP sao   1000 rounds: opportunities=2034356  violations=0
 *   MP sao   5000 rounds: opportunities=10231877 violations=0
 *     -> 0 violations in ~16.34M observed y==1 windows total:
 *        PROT_SAO hardware-orders st-st and ld-ld for plain accesses.
 *
 *   SB plain  500 rounds: opportunities=1024000  violations=659950
 *   SB sao    500 rounds: opportunities=1024000  violations=687122
 *   SB sao    500 rounds: opportunities=1024000  violations=660255
 *   SB sao    500 rounds: opportunities=1024000  violations=484193
 *     -> store-buffer reordering REMAINS under SAO: SAO is TSO-like
 *        (st-ld stays unordered), NOT sequentially consistent. That is
 *        exactly the x86-TSO shape FEX needs — and means SAO is not
 *        secretly paying full-SC serialization costs.
 *
 *   MP sao-mprot    1000 rounds: opportunities=2036470 violations=0
 *   MP sao-mprot    1000 rounds: opportunities=2036804 violations=0
 *     -> a plain mprotect(RW) does NOT strip SAO from a SAO mapping.
 *        Load-bearing for FEX_HWTSO: FEX's internal SMC write-protect
 *        cycles mprotect guest pages without PROT_SAO and must not
 *        de-order them. (Do NOT trust /proc/self/smaps VmFlags for this
 *        on the books kernels — it never shows "sao" even on mappings the
 *        litmus proves ordered; test functionally.)
 *   MP plain-addsao 1000 rounds: opportunities=2037360 violations=0
 *   MP plain-addsao 1000 rounds: opportunities=2040925 violations=0
 *     -> mprotect(RW|SAO) DOES add SAO to an existing plain mapping,
 *        which is what FEX's shmat path relies on.
 * ========================================================================
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef PROT_SAO
#define PROT_SAO 0x10
#endif

#define STRIDE 128 /* POWER8 cache line */
#define SLOTS 2048
#define SPIN_BOUND 1024
#define JITTER_MASK 0x7ff

static volatile unsigned char* Region; /* x half then y half */
#define XV(i) (*(volatile uint32_t*)(Region + (size_t)(i) * STRIDE))
#define YV(i) (*(volatile uint32_t*)(Region + (size_t)(SLOTS + (i)) * STRIDE))

/* Round handshake, each on its own line so control traffic never shares a
 * line with test data (test data is in Region anyway). */
static _Atomic uint64_t Ctl __attribute__((aligned(128)));
static _Atomic uint64_t WDone __attribute__((aligned(128)));
static _Atomic uint64_t RDone __attribute__((aligned(128)));

/* Per-slot read results for SB (indexed [thread][slot], plain memory: only
 * examined by the coordinator after both Done handshakes). */
static uint32_t SBr0[SLOTS], SBr1[SLOTS];

static uint64_t Rounds;
static int CpuW, CpuR, ShapeSB;
static uint64_t Violations, Opportunities;

static inline uint32_t Rnd(uint32_t* s) {
  *s ^= *s << 13;
  *s ^= *s >> 17;
  *s ^= *s << 5;
  return *s;
}

static void Pin(int cpu) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  if (sched_setaffinity(0, sizeof(set), &set)) {
    perror("sched_setaffinity");
    exit(1);
  }
}

static void* Writer(void* arg) {
  (void)arg;
  Pin(CpuW);
  uint32_t seed = 0x2545F491u;
  for (uint64_t r = 1; r <= Rounds; ++r) {
    while (atomic_load_explicit(&Ctl, memory_order_acquire) != r) {}
    for (uint32_t j = Rnd(&seed) & JITTER_MASK; j; --j) {
      __asm__ volatile("");
    }
    if (!ShapeSB) {
      /* MP: x then y, plain stores, NO barrier between them. */
      for (int i = 0; i < SLOTS; ++i) {
        XV(i) = 1;
        YV(i) = 1;
      }
    } else {
      /* SB thread 0: x=1; r0=y. */
      for (int i = 0; i < SLOTS; ++i) {
        XV(i) = 1;
        SBr0[i] = YV(i);
      }
    }
    atomic_store_explicit(&WDone, r, memory_order_release);
  }
  return NULL;
}

static void* Reader(void* arg) {
  (void)arg;
  Pin(CpuR);
  uint32_t seed = 0x9E3779B9u;
  for (uint64_t r = 1; r <= Rounds; ++r) {
    while (atomic_load_explicit(&Ctl, memory_order_acquire) != r) {}
    for (uint32_t j = Rnd(&seed) & JITTER_MASK; j; --j) {
      __asm__ volatile("");
    }
    if (!ShapeSB) {
      /* MP: bounded spin for y[i]==1, then plain load of x[i]. The x load is
       * only control-dependent on the y load — POWER may satisfy it early
       * from a stale line; SAO must not. */
      for (int i = 0; i < SLOTS; ++i) {
        uint32_t y = 0;
        for (int spin = 0; spin < SPIN_BOUND; ++spin) {
          y = YV(i);
          if (y) {
            break;
          }
        }
        uint32_t x = XV(i);
        if (y == 1) {
          __atomic_fetch_add(&Opportunities, 1, __ATOMIC_RELAXED);
          if (x == 0) {
            __atomic_fetch_add(&Violations, 1, __ATOMIC_RELAXED);
          }
        }
      }
    } else {
      /* SB thread 1: y=1; r1=x. */
      for (int i = 0; i < SLOTS; ++i) {
        YV(i) = 1;
        SBr1[i] = XV(i);
      }
    }
    atomic_store_explicit(&RDone, r, memory_order_release);
  }
  return NULL;
}

int main(int argc, char** argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: %s <mp|sb> <plain|sao> <rounds> <cpu_writer> <cpu_reader>\n", argv[0]);
    return 2;
  }
  ShapeSB = !strcmp(argv[1], "sb");
  const char* Mem = argv[2];
  // Modes:
  //   plain        — anonymous RW page (harness-validation baseline)
  //   sao          — mmap(RW|SAO)
  //   sao-mprot    — mmap(RW|SAO), then mprotect(RW) WITHOUT SAO before the
  //                  test: does a plain mprotect strip SAO? (FEX's internal
  //                  SMC write-protect cycles mprotect guest pages without
  //                  SAO — the ordering must survive them.)
  //   plain-addsao — mmap(RW), then mprotect(RW|SAO): can mprotect ADD SAO
  //                  to an existing mapping? (FEX's shmat path does this.)
  const int WantSAO = !strcmp(Mem, "sao") || !strcmp(Mem, "sao-mprot");
  Rounds = strtoull(argv[3], NULL, 0);
  CpuW = atoi(argv[4]);
  CpuR = atoi(argv[5]);

  const size_t Size = (size_t)2 * SLOTS * STRIDE;
  int prot = PROT_READ | PROT_WRITE | (WantSAO ? PROT_SAO : 0);
  void* p = mmap(NULL, Size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) {
    perror(WantSAO ? "mmap(PROT_SAO)" : "mmap");
    return 2;
  }
  if (!strcmp(Mem, "sao-mprot")) {
    if (mprotect(p, Size, PROT_READ | PROT_WRITE)) {
      perror("mprotect(RW)");
      return 2;
    }
  } else if (!strcmp(Mem, "plain-addsao")) {
    if (mprotect(p, Size, PROT_READ | PROT_WRITE | PROT_SAO)) {
      perror("mprotect(RW|SAO)");
      return 2;
    }
  }
#ifdef MADV_NOHUGEPAGE
  madvise(p, Size, MADV_NOHUGEPAGE); /* keep SAO on base pages; best-effort */
#endif
  Region = p;
  memset(p, 0, Size); /* fault everything in before timing-sensitive rounds */

  pthread_t tw, tr;
  pthread_create(&tw, NULL, Writer, NULL);
  pthread_create(&tr, NULL, Reader, NULL);

  for (uint64_t r = 1; r <= Rounds; ++r) {
    for (int i = 0; i < SLOTS; ++i) {
      XV(i) = 0;
      YV(i) = 0;
      if (ShapeSB) {
        SBr0[i] = SBr1[i] = 2; /* sentinel: 2 = not written */
      }
    }
    /* Release-publish the round: resets are ordered before Ctl for the
     * acquire spinners. */
    atomic_store_explicit(&Ctl, r, memory_order_release);
    while (atomic_load_explicit(&WDone, memory_order_acquire) != r) {}
    while (atomic_load_explicit(&RDone, memory_order_acquire) != r) {}
    if (ShapeSB) {
      for (int i = 0; i < SLOTS; ++i) {
        Opportunities++;
        if (SBr0[i] == 0 && SBr1[i] == 0) {
          Violations++;
        }
      }
    }
  }

  pthread_join(tw, NULL);
  pthread_join(tr, NULL);

  printf("shape=%s mem=%s rounds=%llu slots=%d opportunities=%llu violations=%llu\n", ShapeSB ? "SB" : "MP", Mem,
         (unsigned long long)Rounds, SLOTS, (unsigned long long)Opportunities, (unsigned long long)Violations);
  return 0;
}
