/*
 * POWER9 probe 1 — cross-page fault reporting for stxvx / lxvx vs the
 * two-doubleword red-zone bounce that FEX-PPC64LE currently emits.
 *
 * DECISION THIS GATES
 * -------------------
 * FEXCore/Source/Interface/Core/JIT/PPC64LE/PPC64Emitter.cpp:285-318 implements
 * every 128-bit guest vector load/store as a 7-instruction bounce
 * (ld/ld -> std/std -> lvx). Replacing it with a single lxvx/stxvx is the
 * largest single codegen win identified for the POWER9 branch.
 *
 * The load side is safe. The store side is not obviously safe: Power ISA
 * Book III 7.2.3 requires DAR to hold only "an effective address associated
 * with the storage access", not necessarily the faulting byte. FEX's SMC
 * handler unprotects AlignDown(si_addr, PAGE) — if a 16-byte stxvx straddling
 * a page boundary reports si_addr in the FIRST page when only the SECOND is
 * protected, the handler unprotects the wrong page and refaults forever.
 *
 * The current two-std bounce cannot have that problem: each std is 8 bytes and
 * lies wholly within one page, so DAR is unambiguous.
 *
 * WHAT THIS MEASURES
 * ------------------
 * For each of three store forms straddling a page boundary where only the
 * second page is read-only, report the si_addr the kernel delivers, and
 * whether it lands in the writable first page or the protected second page.
 *
 *   A. two 8-byte std  (what FEX emits today)  - expected: page 2 (precise)
 *   B. one 16-byte stxvx (ISA 3.0, proposed)   - UNKNOWN, this is the question
 *   C. one 16-byte stxv  (ISA 3.0, D-form)     - UNKNOWN
 *
 * Then the same for the load side (lxvx), plus a check of whether the target
 * VSR was left partially modified by a faulting load, which x86 semantics
 * forbid for the guest destination.
 *
 * PASS/FAIL READING
 * -----------------
 *   si_addr in the PROTECTED page  -> precise; stxvx is safe to adopt.
 *   si_addr in the WRITABLE page   -> imprecise; adopting stxvx for stores
 *                                     requires reworking the SMC fault handler
 *                                     first. Loads may still proceed.
 *
 * Build (on any host with a ppc64le cross toolchain):
 *   powerpc64le-linux-gnu-gcc -O1 -mcpu=power9 -static -o probe_dar probe_dar.c
 * Run on the POWER9 target; no arguments, no privileges required.
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

static long page_size;
static uint8_t *region;      /* two contiguous pages */
static uint8_t *page1, *page2;

/* Re-arm both pages to a known state: page1 RW, page2 RO. */
static void arm(void)
{
    if (mprotect(page1, page_size, PROT_READ | PROT_WRITE) != 0) {
        perror("mprotect page1 rw");
        exit(1);
    }
    if (mprotect(page2, page_size, PROT_READ) != 0) {
        perror("mprotect page2 ro");
        exit(1);
    }
}

static const char *where(void *addr)
{
    if (addr == NULL)                       return "NULL";
    if ((uint8_t *)addr >= page1 && (uint8_t *)addr < page2) return "page 1 (WRITABLE)";
    if ((uint8_t *)addr >= page2 && (uint8_t *)addr < page2 + page_size) return "page 2 (PROTECTED)";
    return "outside both pages";
}

static void report(const char *name, const char *expectation)
{
    if (!caught) {
        printf("  %-34s NO FAULT (unexpected)\n", name);
        return;
    }
    long off = (long)((uint8_t *)si_addr_seen - page1);
    printf("  %-34s si_addr=%p  off=%+5ld  %-20s  sig=%d code=%d   %s\n",
           name, si_addr_seen, off, where(si_addr_seen),
           signo_seen, sicode_seen, expectation);
}

int main(void)
{
    struct sigaction sa;
    v16u8 val, dst;
    uint8_t *ea;

    page_size = sysconf(_SC_PAGESIZE);
    printf("probe_dar — cross-page fault reporting, stxvx/lxvx vs std-bounce\n");
    printf("page size: %ld\n", page_size);
    printf("AT_HWCAP2: 0x%lx   (ARCH_3_00 = %s)\n",
           (unsigned long)getauxval(AT_HWCAP2),
           (getauxval(AT_HWCAP2) & 0x00800000UL) ? "SET" : "CLEAR");

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0 || sigaction(SIGBUS, &sa, NULL) != 0) {
        perror("sigaction");
        return 1;
    }

    region = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; }
    page1 = region;
    page2 = region + page_size;

    /* Straddle: 8 bytes in page1, 8 bytes in page2. */
    ea = page2 - 8;

    memset(&val, 0xA5, sizeof val);

    printf("\nregion=%p page1=%p page2=%p  straddling EA=%p (page2-8)\n",
           (void *)region, (void *)page1, (void *)page2, (void *)ea);
    printf("page2 is PROT_READ; every store below must fault.\n\n");

    printf("STORES:\n");

    /* A. what FEX emits today: two 8-byte stores. The first lands wholly in
     *    page1 and succeeds; the second lands wholly in page2 and faults. */
    arm(); caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        uint64_t lo = 0xA5A5A5A5A5A5A5A5ULL, hi = 0xA5A5A5A5A5A5A5A5ULL;
        asm volatile("std %0, 0(%2)\n\t"
                     "std %1, 8(%2)\n\t"
                     :: "r"(lo), "r"(hi), "b"(ea) : "memory");
    }
    report("A. two std (current bounce)", "expect page 2 — precise by construction");

    /* B. the proposed replacement. */
    arm(); caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        asm volatile("stxvx %x0, 0, %1" :: "wa"(val), "r"(ea) : "memory");
    }
    report("B. stxvx (proposed)", "<-- THE QUESTION");

    /* C. D-form variant; EA must still be the straddling address. */
    arm(); caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        asm volatile("stxv %x0, 0(%1)" :: "wa"(val), "b"(ea) : "memory");
    }
    report("C. stxv (D-form)", "");

    /* D. Sanity: a plain 8-byte store wholly inside the protected page.
     *    If this does not report page 2, the harness itself is wrong. */
    arm(); caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        uint64_t z = 0;
        asm volatile("std %0, 0(%1)" :: "r"(z), "b"(page2) : "memory");
    }
    report("D. CONTROL std inside page 2", "must be page 2, else harness is broken");

    printf("\nLOADS (page2 is readable, so re-protect to PROT_NONE):\n");

    if (mprotect(page2, page_size, PROT_NONE) != 0) { perror("mprotect none"); return 1; }

    /* E. faulting lxvx: does the destination VSR get partially written?
     *    Seed dst with a recognisable pattern first. */
    memset(&dst, 0x3C, sizeof dst);
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        asm volatile("lxvx %x0, 0, %1" : "=wa"(dst) : "r"(ea) : "memory");
    }
    report("E. lxvx (load)", "");

    {
        unsigned char b[16];
        int intact = 1, i;
        memcpy(b, &dst, 16);
        for (i = 0; i < 16; i++) if (b[i] != 0x3C) intact = 0;
        printf("  destination VSR after faulting lxvx: ");
        for (i = 0; i < 16; i++) printf("%02x", b[i]);
        printf("  -> %s\n", intact ? "INTACT (all 0x3C)"
                                   : "MODIFIED (partial write observed)");
        printf("  note: the compiler may have spilled/reloaded dst around the\n"
               "        siglongjmp, so treat MODIFIED as needing confirmation\n"
               "        by disassembling this binary before trusting it.\n");
    }

    /* F. control: plain 8-byte load wholly inside the protected page. */
    arm();
    if (mprotect(page2, page_size, PROT_NONE) != 0) { perror("mprotect none"); return 1; }
    caught = 0; si_addr_seen = NULL;
    if (sigsetjmp(jb, 1) == 0) {
        uint64_t t;
        asm volatile("ld %0, 0(%1)" : "=r"(t) : "b"(page2) : "memory");
        (void)t;
    }
    report("F. CONTROL ld inside page 2", "must be page 2");

    printf("\nREADING THE RESULT\n");
    printf("  If B reports page 2 (PROTECTED): stxvx fault reporting is precise;\n");
    printf("    the store path can move to stxvx without touching the SMC handler.\n");
    printf("  If B reports page 1 (WRITABLE): imprecise; adopting stxvx for stores\n");
    printf("    would break FEX's AlignDown(si_addr, PAGE) unprotect logic\n");
    printf("    (SyscallsSMCTracking.cpp:37,:76) and cause a refault livelock.\n");
    printf("    Loads (lxvx) would still be adoptable.\n");
    printf("  D and F are harness controls: both MUST report page 2.\n");

    return 0;
}
