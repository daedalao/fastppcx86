// futex_stress.c — lost-wakeup hunter for the FEX CM-wedge investigation.
// Build as a 32-bit x86 guest binary:  gcc -m32 -O2 -pthread -o futex_stress32 futex_stress.c
// (and -m64 for the control arm). Run under FEX on the POWER8 host.
//
// Mode "cond":  P pairs on pthread_cond_t, producer sets flag + signals
//               (broadcast every 4th round), consumer does the canonical
//               while(!flag) pthread_cond_wait — an UNTIMED wait, same shape
//               as steamclient's CJobMgr workers.
// Mode "futex": same protocol on a raw futex word via FUTEX_WAIT_BITSET /
//               FUTEX_WAKE_BITSET (PRIVATE, mask ~0), no glibc in the loop.
//
// A watchdog samples per-pair round counters once a second. If a pair makes
// no progress for --stall seconds while its predicate says work is pending,
// that is a lost wakeup: it prints LOSTWAKE with the pair state and exits 42.
// Clean completion of --rounds rounds per pair exits 0.
//
// Usage: futex_stress <cond|futex> [pairs=8] [rounds=200000] [stall=10] [spinners=0]

#define _GNU_SOURCE
#include <linux/futex.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_PAIRS 64

static int g_rounds = 200000;
static int g_stall = 10;

typedef struct {
  pthread_mutex_t m;
  pthread_cond_t c;
  int flag;               // predicate: 1 = work pending
  _Atomic int flag_atomic; // sig mode predicate
  _Atomic int done_rounds;
  _Atomic int futex_word; // futex mode: sequence number
  int id;
} Pair;

static Pair pairs[MAX_PAIRS];
static int g_npairs = 8;
static _Atomic int g_stop;

static long sys_futex(volatile void* uaddr, int op, int val, void* timeout, void* uaddr2, int val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

#define WAIT_BITSET_PRIV (FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define WAKE_BITSET_PRIV (FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)

// ---------------- cond mode ----------------

static void* cond_consumer(void* arg) {
  Pair* p = arg;
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop); r++) {
    pthread_mutex_lock(&p->m);
    while (!p->flag) {
      pthread_cond_wait(&p->c, &p->m);
    }
    p->flag = 0;
    pthread_mutex_unlock(&p->m);
    atomic_fetch_add(&p->done_rounds, 1);
  }
  return NULL;
}

static void* cond_producer(void* arg) {
  Pair* p = arg;
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop); r++) {
    // wait until consumer consumed the previous round
    while (atomic_load(&p->done_rounds) < r && !atomic_load(&g_stop)) {
      // tight poll: keep the pace high, the race is timing-sensitive
    }
    pthread_mutex_lock(&p->m);
    p->flag = 1;
    if ((r & 3) == 3) {
      pthread_cond_broadcast(&p->c);
    } else {
      pthread_cond_signal(&p->c);
    }
    pthread_mutex_unlock(&p->m);
  }
  return NULL;
}

// ---------------- raw futex mode ----------------

static void* futex_consumer(void* arg) {
  Pair* p = arg;
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop); r++) {
    // wait for word to advance past r
    for (;;) {
      int v = atomic_load(&p->futex_word);
      if (v > r) {
        break;
      }
      sys_futex(&p->futex_word, WAIT_BITSET_PRIV, v, NULL, NULL, ~0);
    }
    atomic_fetch_add(&p->done_rounds, 1);
  }
  return NULL;
}

static void* futex_producer(void* arg) {
  Pair* p = arg;
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop); r++) {
    while (atomic_load(&p->done_rounds) < r && !atomic_load(&g_stop)) {
    }
    atomic_fetch_add(&p->futex_word, 1);
    sys_futex(&p->futex_word, WAKE_BITSET_PRIV, INT32_MAX, NULL, NULL, ~0);
  }
  return NULL;
}

// ---------------- sig mode: deferral-window hunter ----------------
// Producer never issues FUTEX_WAKE; the ONLY wake vector is SIGUSR1 whose
// handler (running on the consumer) bumps the futex word. This is race-free
// on a real kernel: delivery before the wait makes FUTEX_WAIT return EAGAIN
// (word != val), delivery during the wait returns EINTR. A stall with the
// word NOT bumped means the emulator consumed the signal and parked it
// undeliverably while entering an untimed wait — the FEX
// DeferredSignalRefCountGuard window (audit finding #1).

static pthread_t consumer_thread[MAX_PAIRS];
static __thread Pair* tls_pair;

static void usr1_handler(int s) {
  (void)s;
  if (tls_pair) {
    atomic_fetch_add(&tls_pair->futex_word, 1);
  }
}

static _Atomic int sig_consumer_ready[MAX_PAIRS];

static void* sig_consumer(void* arg) {
  Pair* p = arg;
  tls_pair = p;
  // The producer must not fire its first SIGUSR1 until tls_pair is set:
  // a signal landing before it would no-op in the handler and report a
  // false LOSTWAKE at round 0 that is the test's fault, not the emulator's.
  atomic_store(&sig_consumer_ready[p->id], 1);
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop);) {
    int v = atomic_load(&p->futex_word);
    if (v > r) {
      atomic_fetch_add(&p->done_rounds, 1);
      r++;
      continue;
    }
    sys_futex(&p->futex_word, WAIT_BITSET_PRIV, v, NULL, NULL, ~0);
  }
  return NULL;
}

static void* sig_producer(void* arg) {
  Pair* p = arg;
  while (!atomic_load(&sig_consumer_ready[p->id]) && !atomic_load(&g_stop)) {
  }
  for (int r = 0; r < g_rounds && !atomic_load(&g_stop); r++) {
    while (atomic_load(&p->done_rounds) < r && !atomic_load(&g_stop)) {
    }
    pthread_kill(consumer_thread[p->id], SIGUSR1);
  }
  return NULL;
}

// ---------------- load generator ----------------

static void* spinner(void* arg) {
  (void)arg;
  volatile unsigned x = 1;
  while (!atomic_load(&g_stop)) {
    x = x * 1664525u + 1013904223u;
  }
  return NULL;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <cond|futex> [pairs] [rounds] [stall_s] [spinners]\n", argv[0]);
    return 2;
  }
  const int is_cond = strcmp(argv[1], "cond") == 0;
  const int is_sig = strcmp(argv[1], "sig") == 0;
  if (!is_cond && !is_sig && strcmp(argv[1], "futex") != 0) {
    fprintf(stderr, "bad mode %s\n", argv[1]);
    return 2;
  }
  if (is_sig) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler; // deliberately no SA_RESTART: EINTR is the signal path
    sigaction(SIGUSR1, &sa, NULL);
  }
  if (argc > 2) g_npairs = atoi(argv[2]);
  if (argc > 3) g_rounds = atoi(argv[3]);
  if (argc > 4) g_stall = atoi(argv[4]);
  int nspin = (argc > 5) ? atoi(argv[5]) : 0;
  if (g_npairs > MAX_PAIRS) g_npairs = MAX_PAIRS;

  pthread_t th[MAX_PAIRS * 2], sp[64];
  for (int i = 0; i < g_npairs; i++) {
    Pair* p = &pairs[i];
    p->id = i;
    pthread_mutex_init(&p->m, NULL);
    pthread_cond_init(&p->c, NULL);
    pthread_create(&th[i * 2], NULL, is_cond ? cond_consumer : (is_sig ? sig_consumer : futex_consumer), p);
    consumer_thread[i] = th[i * 2];
    pthread_create(&th[i * 2 + 1], NULL, is_cond ? cond_producer : (is_sig ? sig_producer : futex_producer), p);
  }
  if (nspin > 64) nspin = 64;
  for (int i = 0; i < nspin; i++) {
    pthread_create(&sp[i], NULL, spinner, NULL);
  }

  // watchdog
  int last[MAX_PAIRS] = {0};
  int stalled_for[MAX_PAIRS] = {0};
  for (;;) {
    sleep(1);
    int alldone = 1;
    for (int i = 0; i < g_npairs; i++) {
      int now = atomic_load(&pairs[i].done_rounds);
      if (now < g_rounds) {
        alldone = 0;
        if (now == last[i]) {
          if (++stalled_for[i] >= g_stall) {
            atomic_store(&g_stop, 1);
            fprintf(stderr,
                    "LOSTWAKE mode=%s pair=%d rounds=%d/%d flag=%d flag_atomic=%d futex_word=%d "
                    "(no progress for %ds)\n",
                    argv[1], i, now, g_rounds, pairs[i].flag,
                    atomic_load(&pairs[i].flag_atomic),
                    atomic_load(&pairs[i].futex_word), g_stall);
            return 42;
          }
        } else {
          stalled_for[i] = 0;
        }
      }
      last[i] = now;
    }
    if (alldone) {
      break;
    }
  }
  printf("OK mode=%s pairs=%d rounds=%d\n", argv[1], g_npairs, g_rounds);
  return 0;
}
