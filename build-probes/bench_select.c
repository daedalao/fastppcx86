/*
 * Guest-side CPU microbenchmark for select/flag codegen.
 *
 * WHY THIS EXISTS
 * ---------------
 * vkmark cannot measure JIT codegen quality. It is submit-bound: the work happens in native
 * ppc64le Mesa on the host side, while the guest just builds command buffers. Whatever CMOVcc,
 * SETcc or ADC/SBB the guest executes is a rounding error in frame time, so a large improvement in
 * select lowering could show up as nothing. High reproducibility on the wrong workload is still the
 * wrong measurement.
 *
 * This is the right workload: guest x86_64 code that does nothing but hammer the specific IR ops a
 * codegen change touches, with everything else stripped out.
 *
 * WHAT EACH CASE ISOLATES
 * -----------------------
 *   cmov-unpredictable  CMOVcc on random data. The branch predictor cannot learn it, so this is
 *                       where branch-free lowering (isel) should win. NZCVSelect / Select.
 *   cmov-predictable    The identical instruction sequence on data where the condition never
 *                       changes. A correctly-predicted branch costs ~nothing and resolves off the
 *                       dependent chain, so isel's cmp->CR->isel latency can LOSE here. This is
 *                       the regression check — if this got slower, we converted too much.
 *   setcc               SETcc materialisation, same unpredictable data.
 *   adc-chain           Bignum add through a carry chain. Hits NZCVSelectIncrement, which the
 *                       implementer called the strongest isel case (~50% mispredict in bignum).
 *   control             Plain dependent ALU adds. Exercises none of the above. If this moves
 *                       between builds, the measurement is contaminated and the others mean
 *                       nothing.
 *
 * All hot loops are hand-written inline asm rather than C. A ternary might or might not compile to
 * CMOV depending on compiler mood, and if it compiles to a branch this benchmark silently measures
 * the wrong thing. Explicit asm removes that doubt.
 *
 * LOOP CONTROL MUST NOT CONSUME CF — this cost us a measurement
 * -------------------------------------------------------------
 * The first version of this file used `inc; cmp; jb` for loop control in every case, including the
 * control. `jb` consumes the carry flag, and on this backend a carry-consuming condition routes
 * through `ProjectXERToCR1` (JIT.cpp) — which is exactly one of the sequences the codegen batch it
 * was built to measure had changed. So the "control" case was measuring the change too, and moved
 * ~2x between builds, making every relative reading meaningless.
 *
 * All loops now use `dec; jnz`. ZF maps to CR0.EQ directly with no XER projection, so loop control
 * touches none of the flag machinery under test. `dec` is also the last flag-setting instruction
 * before the branch in each body, which is what makes the ZF it tests the loop counter's rather
 * than the body's.
 *
 * General lesson for any future codegen benchmark here: the loop scaffolding is guest code too, and
 * it goes through the same JIT. Scaffolding that shares a code path with the thing under test is
 * not scaffolding.
 *
 * HOW TO USE IT
 * -------------
 * Absolute numbers are meaningless on their own — they only matter as a before/after on the same
 * machine, same config. Run it, change codegen, run it again. Use the standing recipe so the
 * numbers are comparable:
 *
 *   sudo ppc64_cpu --smt=2
 *   numactl --cpunodebind=0 --membind=0 FEX ./bench_select
 *
 * It reports the median of 7 timed repetitions per case plus the spread, so a run whose spread is
 * wide tells you to distrust its median rather than silently reporting noise.
 *
 * BUILD (on the POWER9 host):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O2 -g -o bench_select bench_select.c
 *
 * Verify the guest binary really contains the instructions before trusting a result:
 *   $XT/bin/x86_64-linux-gnu-objdump -d bench_select | grep -cE 'cmovg|setg|adc'
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* WORKING SET SIZING — the first version got this exactly wrong.
 *
 * It used 1<<16 elements = 512 KB per array. POWER9's L2 is 512 KB, 8-way set associative
 * (UM 18745), so a single array *precisely equalled* L2 capacity — the worst possible size, where
 * hit rate is decided by allocation alignment and whatever else happens to be resident. Five such
 * arrays totalled 2.5 MB, five times L2, so the cases evicted each other between runs.
 *
 * The symptom was intermittent 5-19% spreads that appeared on the shortest loops only (control,
 * cmov) and never on the longer ones (setcc, adc-chain) — because a loop with more compute per
 * element has more work available to hide an L2 miss. That looked like scheduler jitter or an
 * ISA-path difference; it was neither.
 *
 * Now 64 KB per array, 320 KB for all five together, comfortably inside a 512 KB L2 with room for
 * the JIT's own footprint. N_INNER is raised proportionally so total work per timed repetition is
 * unchanged.
 */
#define N_ELEMS   (1u << 13)   /* 64 KB of uint64 per array; 5 arrays = 320 KB, fits 512 KB L2 */
#define N_REPS    7            /* timed repetitions per case; median reported */
#define N_INNER   512          /* passes per timed repetition — keeps total ops at 1<<22 */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

/* xorshift64* — deterministic, so runs are comparable across builds. */
static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* ---- CMOVcc. Condition predictability is controlled entirely by the data. ---- */
static uint64_t bench_cmov(const uint64_t* data, uint64_t n, uint64_t thresh) {
    uint64_t acc = 0;
    __asm__ volatile(
        "mov %[n], %%rcx\n\t"
        "1:\n\t"
        "mov -8(%[d],%%rcx,8), %%rdx\n\t"
        "cmp %[t], %%rdx\n\t"
        "cmovg %%rdx, %[a]\n\t"      /* the instruction under test */
        "dec %%rcx\n\t"              /* ZF-based loop control: see note above */
        "jnz 1b\n\t"
        : [a] "+r"(acc)
        : [d] "r"(data), [n] "r"(n), [t] "r"(thresh)
        : "rcx", "rdx", "cc", "memory");
    return acc;
}

/* ---- SETcc ---- */
static uint64_t bench_setcc(const uint64_t* data, uint64_t n, uint64_t thresh) {
    uint64_t acc = 0;
    __asm__ volatile(
        "mov %[n], %%rcx\n\t"
        "1:\n\t"
        "mov -8(%[d],%%rcx,8), %%rdx\n\t"
        "cmp %[t], %%rdx\n\t"
        "setg %%dl\n\t"              /* the instruction under test */
        "movzbq %%dl, %%rdx\n\t"
        "add %%rdx, %[a]\n\t"
        "dec %%rcx\n\t"
        "jnz 1b\n\t"
        : [a] "+r"(acc)
        : [d] "r"(data), [n] "r"(n), [t] "r"(thresh)
        : "rcx", "rdx", "cc", "memory");
    return acc;
}

/* ---- ADC carry chain (bignum add). Loop control must not disturb CF: inc/dec and lea leave it
 * alone, cmp does not — hence dec/jnz with lea-advanced pointers rather than an indexed cmp. ---- */
static uint64_t bench_adc(const uint64_t* x, const uint64_t* y, uint64_t* z, uint64_t n) {
    uint64_t carry_out = 0;
    const uint64_t* xp = x;
    const uint64_t* yp = y;
    uint64_t* zp = z;
    __asm__ volatile(
        "mov %[n], %%rcx\n\t"
        "clc\n\t"
        "1:\n\t"
        "mov (%[x]), %%rdx\n\t"
        "adc (%[y]), %%rdx\n\t"      /* the instruction under test */
        "mov %%rdx, (%[z])\n\t"
        "lea 8(%[x]), %[x]\n\t"
        "lea 8(%[y]), %[y]\n\t"
        "lea 8(%[z]), %[z]\n\t"
        "dec %%rcx\n\t"
        "jnz 1b\n\t"
        "setc %%dl\n\t"
        "movzbq %%dl, %[co]\n\t"
        : [x] "+r"(xp), [y] "+r"(yp), [z] "+r"(zp), [co] "=r"(carry_out)
        : [n] "r"(n)
        : "rcx", "rdx", "cc", "memory");
    return carry_out;
}

/* ---- Control: dependent adds, no selects, no flags consumed. ---- */
static uint64_t bench_control(const uint64_t* data, uint64_t n) {
    uint64_t acc = 0;
    __asm__ volatile(
        "mov %[n], %%rcx\n\t"
        "1:\n\t"
        "add -8(%[d],%%rcx,8), %[a]\n\t"
        "dec %%rcx\n\t"
        "jnz 1b\n\t"
        : [a] "+r"(acc)
        : [d] "r"(data), [n] "r"(n)
        : "rcx", "cc", "memory");
    return acc;
}

static void report(const char* name, uint64_t* samples, uint64_t total_ops) {
    qsort(samples, N_REPS, sizeof samples[0], cmp_u64);
    uint64_t med = samples[N_REPS / 2];
    uint64_t lo = samples[0], hi = samples[N_REPS - 1];
    double spread_pct = med ? 100.0 * (double)(hi - lo) / (double)med : 0.0;
    printf("  %-20s median %8.2f ms   %6.3f ns/op   spread %5.1f%%%s\n",
           name, med / 1e6, (double)med / (double)total_ops, spread_pct,
           spread_pct > 5.0 ? "   <-- NOISY, distrust" : "");
}

int main(void) {
    printf("bench_select — guest CPU microbenchmark for select/flag codegen\n");
    printf("%u elements, %u inner passes, median of %u reps\n\n", N_ELEMS, N_INNER, N_REPS);

    uint64_t* rnd  = malloc(N_ELEMS * sizeof *rnd);
    uint64_t* pred = malloc(N_ELEMS * sizeof *pred);
    uint64_t* addx = malloc(N_ELEMS * sizeof *addx);
    uint64_t* addy = malloc(N_ELEMS * sizeof *addy);
    uint64_t* addz = malloc(N_ELEMS * sizeof *addz);
    if (!rnd || !pred || !addx || !addy || !addz) { fprintf(stderr, "OOM\n"); return 1; }

    for (unsigned i = 0; i < N_ELEMS; ++i) {
        rnd[i]  = rng_next();                 /* straddles the threshold ~50/50 */
        pred[i] = 1;                          /* always below threshold: perfectly predicted */
        addx[i] = rng_next();
        addy[i] = rng_next();
    }
    const uint64_t THRESH = 0x8000000000000000ULL;

    uint64_t samples[N_REPS];
    uint64_t sink = 0;
    const uint64_t ops = (uint64_t)N_ELEMS * N_INNER;

    /* Warm up: get the JIT to compile every loop before anything is timed. */
    for (int i = 0; i < 2; ++i) {
        sink += bench_cmov(rnd, N_ELEMS, THRESH);
        sink += bench_setcc(rnd, N_ELEMS, THRESH);
        sink += bench_adc(addx, addy, addz, N_ELEMS);
        sink += bench_control(rnd, N_ELEMS);
    }

    printf("results (lower ns/op is better):\n");

    for (unsigned r = 0; r < N_REPS; ++r) {
        uint64_t t0 = now_ns();
        for (unsigned k = 0; k < N_INNER; ++k) { sink += bench_cmov(rnd, N_ELEMS, THRESH); }
        samples[r] = now_ns() - t0;
    }
    report("cmov-unpredictable", samples, ops);

    for (unsigned r = 0; r < N_REPS; ++r) {
        uint64_t t0 = now_ns();
        for (unsigned k = 0; k < N_INNER; ++k) { sink += bench_cmov(pred, N_ELEMS, THRESH); }
        samples[r] = now_ns() - t0;
    }
    report("cmov-predictable", samples, ops);

    for (unsigned r = 0; r < N_REPS; ++r) {
        uint64_t t0 = now_ns();
        for (unsigned k = 0; k < N_INNER; ++k) { sink += bench_setcc(rnd, N_ELEMS, THRESH); }
        samples[r] = now_ns() - t0;
    }
    report("setcc", samples, ops);

    for (unsigned r = 0; r < N_REPS; ++r) {
        uint64_t t0 = now_ns();
        for (unsigned k = 0; k < N_INNER; ++k) { sink += bench_adc(addx, addy, addz, N_ELEMS); }
        samples[r] = now_ns() - t0;
    }
    report("adc-chain", samples, ops);

    for (unsigned r = 0; r < N_REPS; ++r) {
        uint64_t t0 = now_ns();
        for (unsigned k = 0; k < N_INNER; ++k) { sink += bench_control(rnd, N_ELEMS); }
        samples[r] = now_ns() - t0;
    }
    report("control", samples, ops);

    printf("\nsink=%016lx (ignore; exists so nothing is optimised away)\n", (unsigned long)sink);
    printf("\nREADING THIS\n");
    printf("  Absolute numbers mean nothing alone — compare against a run from a different build.\n");
    printf("  cmov-unpredictable improving is the isel win.\n");
    printf("  cmov-predictable regressing means isel was applied where a predicted branch was\n");
    printf("    cheaper; that is the signal to convert fewer sites.\n");
    printf("  control moving between builds means the comparison is contaminated — investigate\n");
    printf("    that before believing any other line.\n");

    free(rnd); free(pred); free(addx); free(addy); free(addz);
    return 0;
}
