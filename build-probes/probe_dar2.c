/*
 * POWER9 probe 1b — cross-page fault reporting for stxvx, ALL protection
 * patterns. Supersedes probe_dar.c.
 *
 * v1 asked only "second page protected". That is one of three cases FEX's SMC
 * fault handler must survive, so a clean v1 result was necessary but not
 * sufficient. This version adds the other two.
 *
 * FEX unprotects AlignDown(si_addr, PAGE) and re-executes
 * (SyscallsSMCTracking.cpp:37,:76). For a 16-byte stxvx straddling a page
 * boundary that requires:
 *
 *   B   second page protected  -> si_addr must name page 2
 *   B'  first page protected   -> si_addr must name page 1
 *   B'' both pages protected   -> first fault names one page; after
 *                                 unprotecting exactly that page, the retry
 *                                 must fault again naming the OTHER page.
 *                                 If instead it named the same page twice, or
 *                                 named a page that is already writable, the
 *                                 handler would livelock.
 *
 * Only if all three hold can the store path move from the 7-instruction
 * red-zone bounce to a single stxvx without reworking the fault handler.
 *
 * SCOPE: DAR content is an implementation property, not architecture. Book III
 * 7.2.3 requires only "an effective address associated with the storage
 * access". This result is valid for the CPU / MMU mode / kernel printed in the
 * header below and does NOT transfer to other POWER implementations, to HPT
 * mode, or under a hypervisor. Any FEX adoption should be gated on a runtime
 * check or a per-platform switch, not on this binary's output.
 *
 * v1's probe E (was the destination VSR partially written by a faulting load?)
 * has been REMOVED. It could not give a trustworthy answer in either
 * direction: in a volatile VSR the value is whatever the handler and glibc
 * left behind, and in a callee-saved VR glibc's siglongjmp restores the
 * pre-sigsetjmp value — reporting "intact" even if hardware had clobbered it.
 * It is also moot: FEX re-executes the faulting instruction after unprotect,
 * which rewrites the destination regardless.
 *
 * Build:
 *   powerpc64le-linux-gnu-gcc -O1 -mcpu=power9 -static -o probe_dar2 probe_dar2.c
 * Run on the POWER9 target. No arguments, no privileges.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/auxv.h>

typedef __attribute__((vector_size(16))) unsigned char v16u8;

static sigjmp_buf jb;
static volatile sig_atomic_t caught;
static void *volatile si_addr_seen;
static volatile int signo_seen, sicode_seen;

static void handler(int sig, siginfo_t *si, void *uc)
{
    (void)uc;
    caught = 1;
    signo_seen = sig;
    sicode_seen = si->si_code;
    si_addr_seen = si->si_addr;
    siglongjmp(jb, 1);
}

static long ps;
static uint8_t *page1, *page2, *ea;
static int failures;

static const char *where(void *a)
{
    if (a == NULL) return "NULL";
    if ((uint8_t *)a >= page1 && (uint8_t *)a < page2) return "page 1";
    if ((uint8_t *)a >= page2 && (uint8_t *)a < page2 + ps) return "page 2";
    return "OUTSIDE";
}

static void prot(uint8_t *p, int f)
{
    if (mprotect(p, ps, f) != 0) { perror("mprotect"); exit(1); }
}

/* Perform the straddling 16-byte stxvx; return 1 if it faulted. */
static int do_stxvx(void)
{
    v16u8 val;
    memset(&val, 0xA5, sizeof val);
    caught = 0;
    si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        asm volatile("stxvx %x0, 0, %1" :: "wa"(val), "r"(ea) : "memory");
        return 0;
    }
    return 1;
}

static void check(const char *name, int faulted, const char *want, const char *got)
{
    int ok = faulted && strcmp(want, got) == 0;
    if (!ok) failures++;
    printf("  %-40s %-8s (want %-8s)  %s\n",
           name, faulted ? got : "NO FAULT", want, ok ? "OK" : "*** MISMATCH ***");
}

int main(void)
{
    struct sigaction sa;
    uint8_t *region;
    FILE *f;
    char line[256];

    ps = sysconf(_SC_PAGESIZE);

    printf("probe_dar2 — stxvx cross-page fault reporting, all protection patterns\n");
    printf("page size : %ld\n", ps);
    printf("AT_HWCAP2 : 0x%lx  (ARCH_3_00 %s)\n", (unsigned long)getauxval(AT_HWCAP2),
           (getauxval(AT_HWCAP2) & 0x00800000UL) ? "SET" : "CLEAR");
    /* Scope labelling: this result is implementation-specific. */
    /* /proc/cpuinfo repeats per-thread lines — on a 128-thread machine that is
     * hundreds of duplicates. Print the first occurrence of each key only. */
    f = fopen("/proc/cpuinfo", "r");
    if (f) {
        int seen_cpu = 0, seen_mmu = 0, seen_plat = 0, seen_rev = 0;
        while (fgets(line, sizeof line, f)) {
            int *flag = NULL;
            if      (!strncmp(line, "cpu\t",   4) || !strncmp(line, "cpu ",   4)) flag = &seen_cpu;
            else if (!strncmp(line, "MMU",      3)) flag = &seen_mmu;
            else if (!strncmp(line, "platform", 8)) flag = &seen_plat;
            else if (!strncmp(line, "revision", 8)) flag = &seen_rev;
            if (flag && !*flag) { *flag = 1; printf("cpuinfo   : %s", line); }
            if (seen_cpu && seen_mmu && seen_plat && seen_rev) break;
        }
        fclose(f);
    }

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) || sigaction(SIGBUS, &sa, NULL)) {
        perror("sigaction"); return 1;
    }

    region = mmap(NULL, (size_t)ps * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; }
    page1 = region;
    page2 = region + ps;
    ea    = page2 - 8;              /* 8 bytes in each page */

    printf("\npage1=%p page2=%p straddling EA=%p\n\n", (void*)page1, (void*)page2, (void*)ea);

    /* ---- B: second page protected ---- */
    prot(page1, PROT_READ | PROT_WRITE);
    prot(page2, PROT_READ);
    check("B.  second page protected", do_stxvx(), "page 2", where(si_addr_seen));

    /* ---- B': first page protected ---- */
    prot(page1, PROT_READ);
    prot(page2, PROT_READ | PROT_WRITE);
    check("B'. first page protected", do_stxvx(), "page 1", where(si_addr_seen));

    /* ---- B'': both protected, then convergence ---- */
    prot(page1, PROT_READ);
    prot(page2, PROT_READ);
    {
        int f1 = do_stxvx();
        const char *first = where(si_addr_seen);
        uint8_t *named = (uint8_t *)si_addr_seen;
        printf("  %-40s %-8s (either is fine)\n",
               "B''.a both protected, first fault", f1 ? first : "NO FAULT");
        if (!f1) { failures++; }
        else {
            /* Unprotect exactly the page the kernel named, as FEX would. */
            prot((uint8_t *)((uintptr_t)named & ~(uintptr_t)(ps - 1)),
                 PROT_READ | PROT_WRITE);
            {
                int f2 = do_stxvx();
                const char *second = where(si_addr_seen);
                const char *want = strcmp(first, "page 1") == 0 ? "page 2" : "page 1";
                check("B''.b retry must name the OTHER page", f2, want, second);
            }
        }
    }

    /* ---- controls: whole access inside one protected page ---- */
    prot(page1, PROT_READ | PROT_WRITE);
    prot(page2, PROT_READ);
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        uint64_t z = 0;
        asm volatile("std %0, 0(%1)" :: "r"(z), "b"(page2) : "memory");
    }
    check("D.  CONTROL std wholly inside page 2", caught, "page 2", where(si_addr_seen));

    prot(page2, PROT_NONE);
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        uint64_t t;
        asm volatile("ld %0, 0(%1)" : "=r"(t) : "b"(page2) : "memory");
        (void)t;
    }
    check("F.  CONTROL ld wholly inside page 2", caught, "page 2", where(si_addr_seen));

    /* ---- load side, both directions ---- */
    prot(page1, PROT_READ | PROT_WRITE);
    prot(page2, PROT_NONE);
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        v16u8 d;
        asm volatile("lxvx %x0, 0, %1" : "=wa"(d) : "r"(ea) : "memory");
        (void)d;
    }
    check("E.  lxvx, second page protected", caught, "page 2", where(si_addr_seen));

    prot(page1, PROT_NONE);
    prot(page2, PROT_READ | PROT_WRITE);
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        v16u8 d;
        asm volatile("lxvx %x0, 0, %1" : "=wa"(d) : "r"(ea) : "memory");
        (void)d;
    }
    check("E'. lxvx, first page protected", caught, "page 1", where(si_addr_seen));

    printf("\n%s\n", failures == 0
        ? "ALL PASS — si_addr names the faulting page in every protection pattern.\n"
          "  stxvx/lxvx are safe with FEX's existing AlignDown(si_addr,PAGE) handler\n"
          "  ON THIS CPU/MMU/KERNEL. Gate adoption on a runtime check, not on this run."
        : "*** AT LEAST ONE MISMATCH — see above. If D or F mismatched, the harness\n"
          "  itself is broken and every other line is meaningless. Otherwise DAR is\n"
          "  imprecise for straddling accesses here and the store bounce must stay.");

    return failures != 0;
}
