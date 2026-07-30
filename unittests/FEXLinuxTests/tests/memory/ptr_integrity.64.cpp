// SPDX-License-Identifier: MIT
/*
 * ptr_integrity.64 — graduated ladder for 64-bit value integrity through guest memory.
 *
 * WHY THIS EXISTS
 * ---------------
 * Mono's `mcs` died calling through a function pointer whose upper bits were gone: the
 * call target was 0x7feddff2, a sub-2GiB address, in a process whose legitimate pointers
 * look like 0x36fe2f590d0. Signal delivery and sigreturn were cleared by measurement, so
 * a 64-bit value is being damaged somewhere between being written to guest memory and
 * being read back. Two mechanisms can do that on the PPC64LE backend:
 *
 *   MECHANISM 1 — operand-width truncation.
 *     Guest loads/stores lower to size-switched X-form indexed instructions
 *     (MemoryOps.cpp: LoadMem :510, StoreMem :604, LoadMemTSO :715, StoreMemTSO :764,
 *     Load/StoreMemPair :550/:628, Push/Pop :805/:868, plus StoreFPRSized/LoadFPRSized).
 *     A wrong IROp->Size in any branch emits stwx where stdx was needed and a 64-bit
 *     pointer is stored truncated to 32 bits — exactly the observed signature. The bug
 *     has two directions, and BOTH are tested here: too narrow (upper bytes never
 *     written / read back as zero) and too wide (adjacent bytes clobbered / extra bytes
 *     read in).
 *
 *   MECHANISM 2 — a violated `r0 == 0` invariant.
 *     Every one of those instructions puts r0 in the *rB* slot. Power ISA's literal-zero
 *     rule covers rA only, so rB reads GPR0's contents and the effective address is
 *     EA + r0. A nonzero r0 silently offsets every access in the rest of the block.
 *     Known offenders, both fixed but neither previously covered by a test:
 *       - the dispatcher's DispatcherLoopTopFillSRA entry did not re-establish r0 = 0
 *         (PPC64Dispatcher.cpp:193, commit c1ac6dac6);
 *       - guest PAUSE routed LR through r0 and left it there (ALUOps.cpp:3219, commit
 *         cf608d750). That commit's own reproducer note: "a guest that merely executes
 *         PAUSE_YIELD_LIMIT PAUSE instructions dies with SIGSEGV on the first guest push
 *         after the threshold fires".
 *     Roughly 20 further sites route LR through r0 and restore it by hand — every helper
 *     call in ALUOps/AtomicOps/VectorOps/X87Ops. Tier 5 walks the reachable ones.
 *
 * HOW THE LADDER WORKS — READ THIS BEFORE READING THE OUTPUT
 * ---------------------------------------------------------
 * The tiers are ordered so each one adds exactly ONE new element over its predecessor,
 * and each tier assumes the previous one passes. The FIRST FAILING TIER IS THE DIAGNOSIS;
 * you should not need a debugger to get a usable bug report out of this.
 *
 *   Tier 0  store then load, every width, one basic block, no control flow
 *   Tier 1  ... with a conditional branch between store and load (block boundary)
 *   Tier 2  ... across a direct call/ret
 *   Tier 3  ... across an INDIRECT call through a pointer held in memory (dispatcher
 *              round trip; this is the shape the Mono bug takes)
 *   Tier 4  ... across signal-handler entry and sigreturn
 *   Tier 5  ... with PAUSE and other in-block host-helper calls interleaved
 *   Tier 6  ... under two threads  <-- lives in ptr_integrity_mt.64.cpp, run that after
 *              this binary is clean
 *
 * By default the run STOPS at the first failing tier. "Tier 3 fails, tiers 0-2 pass" is a
 * diagnosis; "some memory test failed" is not. Set PTR_INTEGRITY_ALL_TIERS=1 to run the
 * whole ladder anyway, or PTR_INTEGRITY_TIER=N to run exactly one tier.
 *
 * Every check compares against an expected bit pattern and prints expected, got, and xor
 * on mismatch, then classifies the delta (32-bit truncation vs sign extension vs
 * byte swap vs "you read the arena filler, so the access went somewhere else"). Patterns
 * are chosen so truncation and offsetting look different on sight:
 *   0xDEADBEEFCAFEBABE  truncated to 32 bits is unmistakable (0x00000000CAFEBABE)
 *   0x5A5A5A5A5A5A5A5A  is the arena filler: seeing it means the access missed its slot
 *   0x0000036FE2F590D0  is shaped like the real Mono heap pointer that got mangled
 *
 * Mechanism 1 and mechanism 2 are distinguished as follows:
 *   - A width bug is CONSISTENT: it fails in tier 0 already, at one specific width, and
 *     the wrong value is a bit-subset of the right one.
 *   - An r0 bug is POSITIONAL: tier 0 passes, some later tier fails, the value read back
 *     is unrelated (usually the filler), and the canary scan finds the write landed at
 *     g_win + delta. When the damaged 8 bytes EQUAL that delta, the leaked r0 has been
 *     caught red-handed and the test says so in as many words. Additionally tier 5 stores
 *     an *inline constant zero*, which this backend lowers with r0 as the value operand
 *     (StoreMem, MemoryOps.cpp:592) — so a nonzero r0 is printed verbatim as the value
 *     that appeared where a zero was written.
 *
 * =====================================================================================
 * REVIEWED BASELINE — NOT YET ESTABLISHED
 * =====================================================================================
 * Do NOT invent values here. If you are the first to run this, fill the block in from
 * your actual run and say so; a fabricated baseline is worse than none.
 *
 *   date taken            : <NOT ESTABLISHED>
 *   FEX commit            : <NOT ESTABLISHED>   (written against cf608d750)
 *   host                  : <NOT ESTABLISHED>   (POWER9, model / kernel / page size)
 *   SMT setting           : <NOT ESTABLISHED>   (ppc64_cpu --smt=?)
 *   pinning               : <NOT ESTABLISHED>   (none expected; this test is not timed)
 *   FEX_* vars            : ctest sets FEX_OUTPUTLOG=stderr FEX_SILENTLOG=0 FEX_MAXINST=500
 *   expected outcome      : all tiers PASS, exit 0, zero FAIL lines
 *   tier 5a pause iters   : 4096 executed, 0 corrupt expected
 *   tier 5c split-lock    : final value expected 0x0000000000001000 (4096 x xadd 1)
 *   run time              : <NOT ESTABLISHED>   (expect well under the 30s ctest timeout)
 *   second config         : FEX_TSOENABLED=0 result <NOT ESTABLISHED>
 *   third config          : FEX_PARANOIDTSO=1 result <NOT ESTABLISHED>
 *
 * The three configs matter because they select different lowerings for the same guest
 * instruction: TSO on (default) uses LoadMemTSO/StoreMemTSO, TSO off uses LoadMem/
 * StoreMem, paranoid TSO uses the atomic forms. Each has its own size switch, so each is
 * its own chance for mechanism 1. One clean run does not cover the other two.
 * =====================================================================================
 *
 * BUILD REGISTRATION: none beyond a cmake reconfigure. tests/CMakeLists.txt globs
 * *.cpp recursively with CONFIGURE_DEPENDS, and the .64.cpp suffix keeps it out of the
 * 32-bit build (it is a 64-bit-pointer test; it would be meaningless at 32-bit). No new
 * libraries are needed — that is deliberate, so a missing link line cannot take tiers 0-5
 * down with it. The pthread dependency lives only in ptr_integrity_mt.64.cpp.
 */

#include <catch2/catch_test_macros.hpp>

#include <cpuid.h>
#include <emmintrin.h>
#include <xmmintrin.h>

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

// =====================================================================================
// Patterns. Held in volatile globals so the compiler cannot constant-fold a check into
// a tautology, which is how a probe ends up passing while returning wrong data.
// =====================================================================================
static volatile uint64_t g_pat_a = 0xDEADBEEFCAFEBABEULL;
static volatile uint64_t g_pat_b = 0x1122334455667788ULL;
static volatile uint64_t g_pat_ptrlike = 0x0000036FE2F590D0ULL; // shaped like the real Mono pointer
static volatile uint64_t g_pat_hi = 0xFEDCBA9800000000ULL;      // all information above bit 32
static volatile uint64_t g_deref_target = 0xA5A5F00DD00DBEEFULL;

static constexpr uint8_t kFill = 0x5A;
static constexpr uint64_t kFillWord = 0x5A5A5A5A5A5A5A5AULL;

// =====================================================================================
// Arena. Four pages. The 256-byte working window straddles the middle page boundary so
// misaligned and page-crossing accesses are expressible. Everything outside the window
// stays at kFill for the whole run; canary_scan() reports the first byte that does not,
// which is how an offset (mechanism 2) store is caught even when the matching load is
// offset by the same amount and would otherwise read back its own wrong value happily.
// =====================================================================================
static long g_page;
static uint8_t* g_arena;
static size_t g_arena_size;
static uint8_t* g_win;
static constexpr size_t kWin = 256;

// Offsets inside the window. The page boundary is at +0x80.
enum : size_t {
  OFF_STW = 0x00,   // 16B tier0 store-width scratch
  OFF_LDW = 0x10,   // 16B tier0 load-width scratch
  OFF_T1 = 0x20,    // 8B
  OFF_T2 = 0x28,    // 8B
  OFF_VT = 0x30,    // 24B vtable {magic0, fn, magic1}
  OFF_T4A = 0x48,   // 8B written by main, read by handler
  OFF_T4B = 0x50,   // 8B written by handler, read by main
  OFF_T5 = 0x58,    // 8B
  OFF_T5Z = 0x60,   // 8B inline-zero-store target
  OFF_PTR = 0x68,   // 8B pointer round-trip slot
  OFF_MIS = 0x71,   // 8B deliberately misaligned (odd address)
  OFF_STRAD = 0x7C, // 8B straddles the page boundary at +0x80
  OFF_V128A = 0x90, // 16B, 16-byte aligned
  OFF_V128U = 0xA1, // 16B, deliberately misaligned
  OFF_FPR = 0xC0,   // 16B, 16-byte aligned, movq/movss width tests
  OFF_PAIR = 0xD0,  // 16B, two adjacent 64-bit slots (Load/StoreMemPair candidates)
};

// Guard mapping for the over-read / over-write tests: one readable page immediately
// followed by a PROT_NONE page. An access one size class too wide walks off the end and
// faults instead of silently returning garbage.
static uint8_t* g_guard_ok;   // start of the readable page
static uint8_t* g_guard_edge; // first byte of the PROT_NONE page

// =====================================================================================
// Reporting.
// =====================================================================================
static bool g_run_all = false;
static int g_only_tier = -1;
static int g_fail_count = 0;
static int g_tier = -1;
static const char* g_case = "";
static uintptr_t g_last_slot = 0; // for canary delta arithmetic

static inline void opaque() {
  __asm__ __volatile__("" ::: "memory");
}

// Record which slot the case in progress is writing, so canary_scan() can express any
// damage it finds as a delta from the intended address — which is the suspected rB value.
static inline void mark_slot(const volatile void* p) {
  g_last_slot = reinterpret_cast<uintptr_t>(p);
}

static void tier_begin(int n, const char* name) {
  g_tier = n;
  printf("[tier %d] ENTER %s\n", n, name);
  fflush(stdout);
}

static void tier_pass(int n) {
  printf("[tier %d] PASS\n", n);
  fflush(stdout);
}

static void classify(uint64_t exp, uint64_t got) {
  if ((got & 0xFFFFFFFFULL) == (exp & 0xFFFFFFFFULL) && (exp >> 32) != 0) {
    if ((got >> 32) == 0) {
      printf("         CLASS: low 32 bits intact, high 32 bits ZEROED\n"
             "                -> 32-bit truncation. MECHANISM 1: stwx/lwzx emitted where\n"
             "                   stdx/ldx was needed. This is the Mono signature.\n");
      return;
    }
    if ((got >> 32) == 0xFFFFFFFFULL) {
      printf("         CLASS: low 32 bits intact, high 32 bits ALL ONES\n"
             "                -> 32-bit sign extension (lwax where lwzx/ldx was needed).\n");
      return;
    }
    printf("         CLASS: low 32 bits intact, high 32 bits foreign -> partial-width\n"
           "                write, or a neighbouring store landed on the upper half.\n");
    return;
  }
  if ((got >> 16) == 0 && (got & 0xFFFFULL) == (exp & 0xFFFFULL) && (exp >> 16) != 0) {
    printf("         CLASS: 16-bit truncation (sthx/lhzx path).\n");
    return;
  }
  if ((got >> 8) == 0 && (got & 0xFFULL) == (exp & 0xFFULL) && (exp >> 8) != 0) {
    printf("         CLASS: 8-bit truncation (stbx/lbzx path).\n");
    return;
  }
  if (got == __builtin_bswap64(exp)) {
    printf("         CLASS: byte-swapped -> byte-reversed store/load form.\n");
    return;
  }
  if (got == kFillWord) {
    printf("         CLASS: read back the arena filler 0x5A.. -> nothing was ever written\n"
           "                HERE. MECHANISM 2: the store went to EA + rB with rB != 0.\n"
           "                Check the canary scan below for where it actually landed.\n");
    return;
  }
  if (got == 0) {
    printf("         CLASS: zero -> the load missed its slot, or an inline-zero store\n"
           "                (whose value operand is r0) overwrote it.\n");
    return;
  }
  printf("         CLASS: unrelated value. MECHANISM 2 likely (address offset or foreign\n"
         "                data). If it looks like a code address, it IS a leaked r0:\n"
         "                every guest access in that block used it as the rB index.\n");
}

// Declared before use by the checkers; defined after the arena helpers.
static void canary_scan(const char* where);

static void record_failure() {
  ++g_fail_count;
  fflush(stdout);
  if (!g_run_all) {
    FAIL("tier " << g_tier << " failed (" << g_case
                 << "); stopping here so the first failing tier is the diagnosis. "
                    "Set PTR_INTEGRITY_ALL_TIERS=1 to run the rest of the ladder.");
  }
  // Run-all mode: mark the Catch2 result but keep going.
  CHECK(g_fail_count == 0);
}

static void check_u64(const char* what, uint64_t exp, uint64_t got) {
  if (exp == got) {
    return;
  }
  g_case = what;
  printf("[tier %d] FAIL %s\n"
         "         expect 0x%016" PRIx64 "\n"
         "         got    0x%016" PRIx64 "\n"
         "         xor    0x%016" PRIx64 "\n",
         g_tier, what, exp, got, exp ^ got);
  classify(exp, got);
  canary_scan(what);
  record_failure();
}

static void check_bytes(const char* what, const uint8_t* exp, const uint8_t* got, size_t n) {
  size_t bad = n;
  for (size_t i = 0; i < n; ++i) {
    if (exp[i] != got[i]) {
      bad = i;
      break;
    }
  }
  if (bad == n) {
    return;
  }
  g_case = what;
  printf("[tier %d] FAIL %s (first differing byte at +%zu)\n", g_tier, what, bad);
  printf("         expect ");
  for (size_t i = 0; i < n; ++i) {
    printf("%02x", exp[i]);
  }
  printf("\n         got    ");
  for (size_t i = 0; i < n; ++i) {
    printf("%02x", got[i]);
  }
  printf("\n");
  // A too-narrow store leaves filler where data belongs; a too-wide store puts data
  // where filler belongs. Say which, because they point at opposite mistakes.
  bool filler_where_data = false, data_where_filler = false;
  for (size_t i = 0; i < n; ++i) {
    if (exp[i] != kFill && got[i] == kFill) {
      filler_where_data = true;
    }
    if (exp[i] == kFill && got[i] != kFill) {
      data_where_filler = true;
    }
  }
  if (filler_where_data && !data_where_filler) {
    printf("         CLASS: filler survives where data was expected -> the store was too\n"
           "                NARROW (e.g. stwx used for a 64-bit store). MECHANISM 1.\n");
  } else if (data_where_filler && !filler_where_data) {
    printf("         CLASS: data appears where filler was expected -> the store was too\n"
           "                WIDE (e.g. stdx used for a 32-bit store); it clobbered the\n"
           "                neighbouring bytes. MECHANISM 1.\n");
  }
  canary_scan(what);
  record_failure();
}

// =====================================================================================
// Arena management and the canary scan.
// =====================================================================================
static void arena_refill() {
  memset(g_arena, kFill, g_arena_size);
  opaque();
}

static void canary_scan(const char* where) {
  // Every byte outside the window must still be kFill.
  size_t bad = SIZE_MAX;
  for (size_t i = 0; i < g_arena_size; ++i) {
    uint8_t* p = g_arena + i;
    if (p >= g_win && p < g_win + kWin) {
      continue;
    }
    if (*p != kFill) {
      bad = i;
      break;
    }
  }
  if (bad == SIZE_MAX) {
    printf("         canary after %s: clean (every byte of the %zu-byte arena outside the\n"
           "                 256-byte working window is still 0x5A)\n",
           where, g_arena_size);
    return;
  }
  uint8_t* hit = g_arena + bad;
  // Read the 8 bytes at the damaged location, byte at a time (8-bit accesses are the
  // narrowest path and the one tier 0 validates first).
  uint64_t found = 0;
  for (int i = 0; i < 8; ++i) {
    size_t off = bad + static_cast<size_t>(i);
    uint8_t byte = (off < g_arena_size) ? g_arena[off] : 0;
    found |= static_cast<uint64_t>(byte) << (8 * i);
  }
  printf("         canary after %s:\n", where);
  printf("         canary: DAMAGED at arena+0x%zx (%+td from the window base)\n"
         "                 8 bytes there: 0x%016" PRIx64 "\n",
         bad, static_cast<ptrdiff_t>(hit - g_win), found);
  if (g_last_slot != 0) {
    const ptrdiff_t delta = static_cast<ptrdiff_t>(reinterpret_cast<uintptr_t>(hit) - g_last_slot);
    printf("                 delta from the slot this case last wrote: %+td (0x%tx)\n", delta, delta);
    if (delta > 0 && static_cast<uint64_t>(delta) == found) {
      printf("                 *** CONFIRMED MECHANISM 2: the write landed exactly `found`\n"
             "                     bytes past its slot AND the value written is that same\n"
             "                     number. That is r0 being used as both the rB index and\n"
             "                     the stored value: r0 = 0x%016" PRIx64 ", not 0.\n",
             found);
    } else if (delta != 0) {
      printf("                 *** MECHANISM 2: an indexed access used rB = %+td instead of 0.\n", delta);
    }
  }
  printf("                 (a nonzero rB index offsets EVERY access in the rest of the\n"
         "                  block, so treat this as the primary finding, not a side effect)\n");
}

// =====================================================================================
// Fault recovery, used only by the deliberate over-read/over-write cases.
// =====================================================================================
static sigjmp_buf g_jb;
static volatile sig_atomic_t g_jb_armed = 0;
static volatile uint64_t g_fault_addr = 0;
static volatile int g_fault_signo = 0;

static void fault_handler(int signo, siginfo_t* si, void*) {
  g_fault_signo = signo;
  g_fault_addr = reinterpret_cast<uint64_t>(si->si_addr);
  if (g_jb_armed) {
    g_jb_armed = 0;
    siglongjmp(g_jb, 1);
  }
  // Not armed: nothing sane left to do. Say where and die loudly.
  static char buf[128];
  int n = snprintf(buf, sizeof(buf), "\n[tier ?] unrecovered fault at %p\n", si->si_addr);
  ssize_t ignored = write(2, buf, static_cast<size_t>(n < 0 ? 0 : n));
  (void)ignored;
  _exit(139);
}

// `sigaction` names both a struct and a function, so spell the type out once here rather
// than relying on an elaborated-type-specifier in a member declaration.
using SigActionT = struct sigaction;

struct FaultGuard {
  SigActionT old_segv {};
  SigActionT old_bus {};
  FaultGuard() {
    struct sigaction act {};
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &fault_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGSEGV, &act, &old_segv);
    sigaction(SIGBUS, &act, &old_bus);
  }
  ~FaultGuard() {
    g_jb_armed = 0;
    sigaction(SIGSEGV, &old_segv, nullptr);
    sigaction(SIGBUS, &old_bus, nullptr);
  }
};

// =====================================================================================
// Tier 0 — store then load, every width, one basic block, no control flow.
// =====================================================================================
static uint64_t narrow(uint64_t v, int bytes) {
  if (bytes >= 8) {
    return v;
  }
  return v & ((1ULL << (8 * bytes)) - 1ULL);
}

// Store-side width check. Presets 16 bytes of filler, stores `bytes` bytes, then reads
// all 16 back one byte at a time. Catches a store that was too narrow AND one that was
// too wide, which are opposite mistakes with opposite fixes.
static void t0_store_width(uint8_t* slot, int bytes, const char* what) {
  mark_slot(slot);
  for (int i = 0; i < 16; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = kFill;
  }
  opaque();

  const uint64_t v = narrow(g_pat_a, bytes);
  switch (bytes) {
  case 1: *reinterpret_cast<volatile uint8_t*>(slot) = static_cast<uint8_t>(v); break;
  case 2: *reinterpret_cast<volatile uint16_t*>(slot) = static_cast<uint16_t>(v); break;
  case 4: *reinterpret_cast<volatile uint32_t*>(slot) = static_cast<uint32_t>(v); break;
  case 8: *reinterpret_cast<volatile uint64_t*>(slot) = v; break;
  default: return;
  }
  opaque();

  uint8_t got[16], exp[16];
  for (int i = 0; i < 16; ++i) {
    got[i] = reinterpret_cast<volatile uint8_t*>(slot)[i];
    exp[i] = kFill;
  }
  for (int i = 0; i < bytes; ++i) {
    exp[i] = static_cast<uint8_t>(v >> (8 * i));
  }
  check_bytes(what, exp, got, 16);
}

// Load-side width check. Presets 16 bytes of known data using only byte stores, then
// loads `bytes` bytes and compares against exactly those bytes. A load one size class
// too wide brings in extra high bits; too narrow leaves zeros.
static void t0_load_width(uint8_t* slot, int bytes, const char* what) {
  mark_slot(slot);
  const uint64_t src = g_pat_a;
  for (int i = 0; i < 16; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = static_cast<uint8_t>(src >> (8 * (i & 7)));
  }
  opaque();

  uint64_t got = 0;
  switch (bytes) {
  case 1: got = *reinterpret_cast<volatile uint8_t*>(slot); break;
  case 2: got = *reinterpret_cast<volatile uint16_t*>(slot); break;
  case 4: got = *reinterpret_cast<volatile uint32_t*>(slot); break;
  case 8: got = *reinterpret_cast<volatile uint64_t*>(slot); break;
  default: return;
  }
  check_u64(what, narrow(src, bytes), got);
}

union U128 {
  __m128i v;
  uint64_t u[2];
  uint8_t b[16];
};

static void t0_vector(uint8_t* slot, bool aligned_form, const char* tag) {
  mark_slot(slot);
  char name[96];

  // ---- 128-bit store, then byte read-back (catches wrong-width vector stores) ----
  for (int i = 0; i < 32; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = kFill;
  }
  opaque();
  U128 src {};
  src.u[0] = g_pat_a;
  src.u[1] = g_pat_b;
  if (aligned_form) {
    _mm_store_si128(reinterpret_cast<__m128i*>(slot), src.v); // movdqa
  } else {
    _mm_storeu_si128(reinterpret_cast<__m128i*>(slot), src.v); // movdqu
  }
  opaque();
  uint8_t got[32], exp[32];
  for (int i = 0; i < 32; ++i) {
    got[i] = reinterpret_cast<volatile uint8_t*>(slot)[i];
    exp[i] = kFill;
  }
  for (int i = 0; i < 16; ++i) {
    exp[i] = src.b[i];
  }
  snprintf(name, sizeof(name), "%s: 128-bit store (%s) byte image", tag, aligned_form ? "movdqa" : "movdqu");
  check_bytes(name, exp, got, 32);

  // ---- 128-bit load ----
  opaque();
  U128 back {};
  back.v = aligned_form ? _mm_load_si128(reinterpret_cast<const __m128i*>(slot)) :
                          _mm_loadu_si128(reinterpret_cast<const __m128i*>(slot));
  opaque();
  snprintf(name, sizeof(name), "%s: 128-bit load low half", tag);
  check_u64(name, g_pat_a, back.u[0]);
  snprintf(name, sizeof(name), "%s: 128-bit load high half", tag);
  check_u64(name, g_pat_b, back.u[1]);
}

// FPR-class narrow accesses. StoreFPRSized/LoadFPRSized must honour Op->Size: a movq
// store that writes 16 bytes stomps the next slot (this really happened — MemoryOps.cpp
// :585 records it wiping [rsp+8] in __tls_init_tp), and a movq load that reads 16 bytes
// leaves foreign data in the upper lane instead of the architectural zero.
static void t0_fpr_narrow(uint8_t* slot) {
  mark_slot(slot);

  // movq [mem], xmm — writes exactly 8 bytes.
  for (int i = 0; i < 16; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = kFill;
  }
  opaque();
  U128 src {};
  src.u[0] = g_pat_a;
  src.u[1] = g_pat_b;
  _mm_storel_epi64(reinterpret_cast<__m128i*>(slot), src.v);
  opaque();
  uint8_t got[16], exp[16];
  for (int i = 0; i < 16; ++i) {
    got[i] = reinterpret_cast<volatile uint8_t*>(slot)[i];
    exp[i] = (i < 8) ? static_cast<uint8_t>(g_pat_a >> (8 * i)) : kFill;
  }
  check_bytes("fpr: movq m64 must write 8 bytes and not 16", exp, got, 16);

  // movss [mem], xmm — writes exactly 4 bytes.
  for (int i = 0; i < 16; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = kFill;
  }
  opaque();
  _mm_store_ss(reinterpret_cast<float*>(slot), _mm_castsi128_ps(src.v));
  opaque();
  for (int i = 0; i < 16; ++i) {
    got[i] = reinterpret_cast<volatile uint8_t*>(slot)[i];
    exp[i] = (i < 4) ? static_cast<uint8_t>(g_pat_a >> (8 * i)) : kFill;
  }
  check_bytes("fpr: movss m32 must write 4 bytes and not 16", exp, got, 16);

  // movq xmm, [mem] — reads 8 bytes, zeroes the upper lane.
  for (int i = 0; i < 16; ++i) {
    reinterpret_cast<volatile uint8_t*>(slot)[i] = static_cast<uint8_t>(g_pat_a >> (8 * (i & 7)));
  }
  opaque();
  U128 back {};
  back.v = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(slot));
  opaque();
  check_u64("fpr: movq xmm,m64 low half", g_pat_a, back.u[0]);
  check_u64("fpr: movq xmm,m64 upper lane must be zeroed, not read from memory", 0, back.u[1]);

  // movss xmm, [mem] — reads 4 bytes, zeroes bits 32..127.
  opaque();
  U128 back2 {};
  back2.v = _mm_castps_si128(_mm_load_ss(reinterpret_cast<const float*>(slot)));
  opaque();
  check_u64("fpr: movss xmm,m32 low 32 bits", narrow(g_pat_a, 4), back2.u[0]);
  check_u64("fpr: movss xmm,m32 bits 64..127 must be zero", 0, back2.u[1]);
}

// Adjacent 64-bit accesses — the shape FEX's IR fuses into StoreMemPair/LoadMemPair
// (MemoryOps.cpp:628/:550), which have their own size switch and their own second-half
// address computation. Distinct patterns per half so a swap is visible.
static void t0_pair(uint8_t* slot) {
  mark_slot(slot);
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(slot);
  p[0] = g_pat_a;
  p[1] = g_pat_b;
  opaque();
  uint64_t a = p[0];
  uint64_t b = p[1];
  check_u64("pair: adjacent 64-bit store/load, first half", g_pat_a, a);
  check_u64("pair: adjacent 64-bit store/load, second half", g_pat_b, b);
}

// Deliberate over-read / over-write probe: put each slot flush against the end of a
// mapped page whose successor is PROT_NONE. An access one size class too wide faults, so
// a wrong-width lowering cannot hide behind a value that happens to look plausible.
//
// Everything the recovery path reads after siglongjmp lives in volatile globals: locals
// modified between sigsetjmp and siglongjmp have indeterminate values afterwards, and a
// diagnostic printed from garbage is worse than no diagnostic.
static volatile int g_edge_w = 0;
static volatile uintptr_t g_edge_slot = 0;
static char g_edge_name[96];

static void t0_edge(void) {
  FaultGuard guard;
  static const int widths[] = {1, 2, 4, 8};
  for (size_t wi = 0; wi < sizeof(widths) / sizeof(widths[0]); ++wi) {
    g_edge_w = widths[wi];
    g_edge_slot = reinterpret_cast<uintptr_t>(g_guard_edge - widths[wi]);
    mark_slot(reinterpret_cast<const volatile void*>(g_edge_slot));

    snprintf(g_edge_name, sizeof(g_edge_name), "edge: %d-bit store flush against a PROT_NONE page",
             widths[wi] * 8);
    g_case = g_edge_name;
    if (sigsetjmp(g_jb, 1) == 0) {
      volatile void* slot = reinterpret_cast<volatile void*>(g_edge_slot);
      const int w = g_edge_w;
      const uint64_t v = narrow(g_pat_a, w);
      g_jb_armed = 1;
      switch (w) {
      case 1: *static_cast<volatile uint8_t*>(slot) = static_cast<uint8_t>(v); break;
      case 2: *static_cast<volatile uint16_t*>(slot) = static_cast<uint16_t>(v); break;
      case 4: *static_cast<volatile uint32_t*>(slot) = static_cast<uint32_t>(v); break;
      case 8: *static_cast<volatile uint64_t*>(slot) = v; break;
      }
      g_jb_armed = 0;
    } else {
      printf("[tier %d] FAIL %s\n"
             "         faulted at 0x%016" PRIx64 " (signal %d); the slot is [0x%" PRIxPTR
             ", 0x%" PRIxPTR ") and everything from 0x%" PRIxPTR " up is PROT_NONE, so this\n"
             "         store wrote past its own width, or an indexed access used a nonzero\n"
             "         rB. delta from the slot base = %+td\n",
             g_tier, g_edge_name, g_fault_addr, g_fault_signo, g_edge_slot,
             g_edge_slot + static_cast<uintptr_t>(g_edge_w), reinterpret_cast<uintptr_t>(g_guard_edge),
             static_cast<ptrdiff_t>(g_fault_addr - g_edge_slot));
      record_failure();
      continue;
    }

    snprintf(g_edge_name, sizeof(g_edge_name), "edge: %d-bit load flush against a PROT_NONE page",
             widths[wi] * 8);
    g_case = g_edge_name;
    if (sigsetjmp(g_jb, 1) == 0) {
      volatile void* slot = reinterpret_cast<volatile void*>(g_edge_slot);
      const int w = g_edge_w;
      uint64_t got = 0;
      g_jb_armed = 1;
      switch (w) {
      case 1: got = *static_cast<volatile uint8_t*>(slot); break;
      case 2: got = *static_cast<volatile uint16_t*>(slot); break;
      case 4: got = *static_cast<volatile uint32_t*>(slot); break;
      case 8: got = *static_cast<volatile uint64_t*>(slot); break;
      }
      g_jb_armed = 0;
      check_u64(g_edge_name, narrow(g_pat_a, w), got);
    } else {
      printf("[tier %d] FAIL %s\n"
             "         faulted at 0x%016" PRIx64 " (signal %d); the load read past its own\n"
             "         width, or an indexed access used a nonzero rB. delta from the slot\n"
             "         base = %+td\n",
             g_tier, g_edge_name, g_fault_addr, g_fault_signo,
             static_cast<ptrdiff_t>(g_fault_addr - g_edge_slot));
      record_failure();
    }
  }
}

// A pointer round-tripping through memory — the actual Mono shape. Three separate
// claims: the bits survive the store/load, a pointer-shaped constant survives, and the
// value loaded back still dereferences to the right thing.
static void t0_pointer_roundtrip(uint8_t* slot) {
  mark_slot(slot);
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(slot);
  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);

  *p = real;
  opaque();
  uint64_t back = *p;
  check_u64("ptr: address of a real object through memory", real, back);

  *p = g_pat_ptrlike;
  opaque();
  check_u64("ptr: Mono-shaped constant 0x36FE2F590D0 through memory", g_pat_ptrlike, *p);

  *p = g_pat_hi;
  opaque();
  check_u64("ptr: value living entirely above bit 32", g_pat_hi, *p);

  *p = real;
  opaque();
  volatile uint64_t* indirect = reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(*p));
  check_u64("ptr: dereference of the pointer we read back", g_deref_target, *indirect);
}

static void tier0(void) {
  tier_begin(0, "store/load, all widths, straight line, no control flow");
  arena_refill();

  static const int widths[] = {1, 2, 4, 8};
  char name[96];

  // Aligned, then every misalignment that matters: odd address, and straddling a page.
  struct Site {
    size_t off;
    const char* tag;
  };
  static const Site sites[] = {
    {OFF_STW, "aligned"},
    {OFF_MIS, "misaligned (odd address)"},
    {OFF_STRAD, "straddling a page boundary"},
  };

  for (const Site& s : sites) {
    for (int w : widths) {
      snprintf(name, sizeof(name), "store width %d-bit, %s", w * 8, s.tag);
      t0_store_width(g_win + s.off, w, name);
    }
  }
  for (const Site& s : sites) {
    for (int w : widths) {
      snprintf(name, sizeof(name), "load width %d-bit, %s", w * 8, s.tag);
      t0_load_width(g_win + s.off, w, name);
    }
  }

  t0_load_width(g_win + OFF_LDW, 8, "load width 64-bit, second aligned site");

  t0_vector(g_win + OFF_V128A, true, "v128 aligned");
  t0_vector(g_win + OFF_V128U, false, "v128 misaligned");
  t0_fpr_narrow(g_win + OFF_FPR);
  t0_pair(g_win + OFF_PAIR);
  t0_pointer_roundtrip(g_win + OFF_PTR);
  t0_edge();

  canary_scan("end of tier 0");
  tier_pass(0);
}

// =====================================================================================
// Tier 1 — one conditional branch between the store and the load.
// =====================================================================================
static volatile int g_selector = 0;

// A guaranteed guest conditional branch, in both directions, with nothing else in it.
// Writing this in C is not good enough: two if/else arms that do the same thing get merged
// and the branch we are trying to test disappears. `cmp reg, 0` + `je` to the next
// instruction always survives to the guest binary, and FEX must lower it as a CondJump,
// which is what ends the block.
static inline void guest_cond_branch(int taken) {
  __asm__ __volatile__("cmp %[s], 0\n\t"
                       "je 1f\n\t"
                       "1:\n\t"
                       :
                       : [s] "r"(taken)
                       : "cc", "memory");
}

static void tier1(void) {
  tier_begin(1, "store, conditional branch, load (crosses a block boundary)");
  arena_refill();
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T1);
  mark_slot(p);

  // Both directions of the branch.
  for (int i = 0; i < 2; ++i) {
    *p = g_pat_a;
    guest_cond_branch(i);
    const uint64_t got = *p;
    check_u64(i ? "cond branch not taken between store and load" : "cond branch taken between store and load",
              g_pat_a, got);
  }

  // The C-level shape too, with arms that genuinely differ so they cannot be merged or
  // if-converted: each arm stores a different pattern and the check follows the branch.
  for (int i = 0; i < 2; ++i) {
    g_selector = i;
    uint64_t want_val;
    if (g_selector) {
      *p = g_pat_a;
      want_val = g_pat_a;
    } else {
      *p = g_pat_b;
      want_val = g_pat_b;
    }
    opaque();
    check_u64("store inside one arm of an if/else, load after the join", want_val, *p);
  }

  // An unconditional jump, which ends the guest block outright.
  *p = g_pat_b;
  __asm__ __volatile__("jmp 1f\n\t1:\n\t" ::: "memory");
  check_u64("unconditional jmp between store and load", g_pat_b, *p);

  // A backward branch: the loop back-edge is where FEX ends a block and re-enters the
  // dispatcher, which is one of the two sites that failed to re-establish r0 = 0.
  for (int i = 0; i < 16; ++i) {
    *p = g_pat_a + static_cast<uint64_t>(i);
    opaque();
    uint64_t got = *p;
    if (got != g_pat_a + static_cast<uint64_t>(i)) {
      char name[96];
      snprintf(name, sizeof(name), "loop iteration %d: store/load across a back-edge", i);
      check_u64(name, g_pat_a + static_cast<uint64_t>(i), got);
      break;
    }
  }

  // And the pointer round-trip again, now with a branch in the middle.
  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  *p = real;
  guest_cond_branch(1);
  check_u64("ptr through memory across a conditional branch", real, *p);
  guest_cond_branch(0);
  check_u64("that ptr still dereferences after a branch", g_deref_target,
            *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(*p)));

  canary_scan("end of tier 1");
  tier_pass(1);
}

// =====================================================================================
// Tier 2 — across a direct call and return.
// =====================================================================================
__attribute__((noinline)) static void call_barrier(void) {
  __asm__ __volatile__("" ::: "memory");
}

__attribute__((noinline)) static uint64_t callee_load64(const volatile uint64_t* p) {
  return *p;
}

__attribute__((noinline)) static void callee_store64(volatile uint64_t* p, uint64_t v) {
  *p = v;
}

static void tier2(void) {
  tier_begin(2, "store/load across a direct call and ret");
  arena_refill();
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T2);
  mark_slot(p);

  *p = g_pat_a;
  call_barrier();
  check_u64("store, direct call, load in the caller", g_pat_a, *p);

  *p = g_pat_b;
  check_u64("store in the caller, load inside the callee", g_pat_b, callee_load64(p));

  callee_store64(p, g_pat_ptrlike);
  check_u64("store inside the callee, load in the caller", g_pat_ptrlike, *p);

  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  callee_store64(p, real);
  uint64_t back = callee_load64(p);
  check_u64("ptr stored by a callee, loaded by another callee", real, back);
  check_u64("that ptr still dereferences", g_deref_target, *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(back)));

  // push/pop — the Push/Pop and PushTwo/PopTwo lowerings (MemoryOps.cpp:776-940) have
  // their own size switches and write through guest RSP rather than a computed EA.
  // rsp is moved down first so these pushes cannot land in the compiler's red zone.
  {
    uint64_t o1 = 0, o2 = 0;
    const uint64_t a = g_pat_a, b = g_pat_b;
    __asm__ __volatile__("sub rsp, 256\n\t"
                         "push %[a]\n\t"
                         "push %[b]\n\t"
                         "pop %[o2]\n\t"
                         "pop %[o1]\n\t"
                         "add rsp, 256\n\t"
                         : [o1] "=&r"(o1), [o2] "=&r"(o2)
                         : [a] "r"(a), [b] "r"(b)
                         : "cc", "memory");
    check_u64("push/pop pair: first value", g_pat_a, o1);
    check_u64("push/pop pair: second value", g_pat_b, o2);
  }

  canary_scan("end of tier 2");
  tier_pass(2);
}

// =====================================================================================
// Tier 3 — across an INDIRECT call through a pointer held in memory. This is the shape
// the Mono failure takes, and it forces a dispatcher round trip: FEX ends the block at
// an indirect branch, looks the target up in the L1 cache, and on a miss goes through
// ExitFunctionLinker — the slow path whose r0 handling is hand-written
// (PPC64Dispatcher.cpp:406-415).
// =====================================================================================
using Fn1 = uint64_t (*)(const volatile uint64_t*);

struct VTable {
  uint64_t magic0;
  Fn1 fn;
  uint64_t magic1;
};

// `mov rax, [rdi]; ret` — a whole function in four bytes. Copied into a far-away
// mapping so calling it forces a brand new translation block at an address nowhere near
// the main image, i.e. a fresh L1 miss and a fresh compile.
static const uint8_t kStubCode[] = {0x48, 0x8B, 0x07, 0xC3};

static void tier3(void) {
  tier_begin(3, "store/load across an indirect call through a pointer in memory");
  arena_refill();

  VTable* vt = reinterpret_cast<VTable*>(g_win + OFF_VT);
  volatile uint64_t* raw = reinterpret_cast<volatile uint64_t*>(g_win + OFF_VT);
  mark_slot(vt);

  // Stage 1: does the function pointer survive the round trip through memory at all?
  // Separating this from the call is the whole point — it splits "the pointer load was
  // truncated" from "the branch went somewhere else".
  raw[0] = g_pat_a;
  vt->fn = &callee_load64;
  raw[2] = g_pat_b;
  opaque();
  check_u64("vtable guard word before the fn pointer", g_pat_a, raw[0]);
  check_u64("fn pointer bits survive a store/load round trip", reinterpret_cast<uint64_t>(&callee_load64), raw[1]);
  check_u64("vtable guard word after the fn pointer", g_pat_b, raw[2]);

  // Stage 2: call through it, and have the callee read a value we stored beforehand.
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(g_win + OFF_PTR);
  *slot = g_pat_ptrlike;
  opaque();
  Fn1 fn = vt->fn; // 64-bit load of a code pointer out of guest memory
  check_u64("fn pointer loaded into a register", reinterpret_cast<uint64_t>(&callee_load64), reinterpret_cast<uint64_t>(fn));
  uint64_t r = fn(slot);
  check_u64("value read by the indirectly-called callee", g_pat_ptrlike, r);

  // Stage 3: store after the indirect call, in the block the dispatcher just entered.
  *slot = g_pat_hi;
  opaque();
  check_u64("store issued right after returning from an indirect call", g_pat_hi, *slot);

  // Stage 4: double round trip — pointer through memory, into a register, back out to a
  // different slot, and called from there.
  volatile uint64_t* slot2 = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T1);
  *slot2 = reinterpret_cast<uint64_t>(fn);
  opaque();
  Fn1 fn2 = reinterpret_cast<Fn1>(static_cast<uintptr_t>(*slot2));
  check_u64("fn pointer after two trips through memory", reinterpret_cast<uint64_t>(&callee_load64),
            reinterpret_cast<uint64_t>(fn2));
  *slot = g_pat_a;
  opaque();
  check_u64("value read through the twice-round-tripped pointer", g_pat_a, fn2(slot));

  // Stage 5: a far, freshly-written code page. First call compiles a new block (the
  // ExitFunctionLinker slow path); the second hits the L1 fast path. They restore r0 at
  // different sites, so report them separately.
  const size_t far_size = static_cast<size_t>(g_page) * 256; // ~1MiB with 4K pages
  void* far_raw = mmap(nullptr, far_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (far_raw == MAP_FAILED) {
    printf("[tier %d] SKIP far-stub case: mmap of an executable region failed (%s)\n", g_tier, strerror(errno));
  } else {
    uint8_t* far = static_cast<uint8_t*>(far_raw);
    uint8_t* stub_a = far;
    uint8_t* stub_b = far + far_size / 2; // deliberately far away: different L1 bucket
    memcpy(stub_a, kStubCode, sizeof(kStubCode));
    memcpy(stub_b, kStubCode, sizeof(kStubCode));
    opaque();

    // Publish both stub addresses through guest memory rather than keeping them in
    // registers, so the pointer itself is under test too.
    volatile uint64_t* pa = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4A);
    volatile uint64_t* pb = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4B);
    *pa = reinterpret_cast<uint64_t>(stub_a);
    *pb = reinterpret_cast<uint64_t>(stub_b);
    opaque();
    check_u64("far stub A pointer through memory", reinterpret_cast<uint64_t>(stub_a), *pa);
    check_u64("far stub B pointer through memory", reinterpret_cast<uint64_t>(stub_b), *pb);

    Fn1 sa = reinterpret_cast<Fn1>(static_cast<uintptr_t>(*pa));
    Fn1 sb = reinterpret_cast<Fn1>(static_cast<uintptr_t>(*pb));

    *slot = g_pat_a;
    opaque();
    check_u64("far stub A, first call (new block: compile + ExitFunctionLinker path)", g_pat_a, sa(slot));
    *slot = g_pat_b;
    opaque();
    check_u64("far stub A, second call (L1 cache fast path)", g_pat_b, sa(slot));
    *slot = g_pat_ptrlike;
    opaque();
    check_u64("far stub B, first call (second new block, ~512KiB away)", g_pat_ptrlike, sb(slot));
    *slot = g_pat_hi;
    opaque();
    check_u64("far stub B, second call", g_pat_hi, sb(slot));

    // And a store immediately after coming back from the freshly compiled block.
    *slot = g_pat_a;
    opaque();
    check_u64("store after returning from a freshly compiled far block", g_pat_a, *slot);

    munmap(far, far_size);
  }

  canary_scan("end of tier 3");
  tier_pass(3);
}

// =====================================================================================
// Tier 4 — across signal-handler entry and sigreturn. The handler runs from a fresh
// dispatcher entry (DispatcherLoopTopFillSRA), which is the other site that failed to
// re-establish r0 = 0.
//
// The handler records into globals and never asserts: throwing a Catch2 exception out of
// a signal handler is not something to rely on. All judging happens after return.
// =====================================================================================
static volatile sig_atomic_t g_handler_ran = 0;
static volatile uint64_t g_h_readback = 0;
static volatile uint64_t g_h_ptr_bits = 0;
static volatile uint64_t g_h_call_result = 0;
static volatile uint64_t g_h_inline_zero = 0;

static void usr1_handler(int, siginfo_t*, void*) {
  g_handler_ran = 1;

  // Read what the main flow stored before raising.
  g_h_readback = *reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4A);

  // Store for the main flow to read after sigreturn.
  *reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4B) = g_pat_b;

  // A pointer load and an indirect call from inside the handler (tier 3's shape, one
  // dispatcher entry deeper).
  VTable* vt = reinterpret_cast<VTable*>(g_win + OFF_VT);
  g_h_ptr_bits = reinterpret_cast<uint64_t>(vt->fn);
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(g_win + OFF_PTR);
  *slot = g_pat_ptrlike;
  g_h_call_result = vt->fn(slot);

  // An inline-constant zero store: this backend lowers the value operand to r0
  // (MemoryOps.cpp:592). If r0 is not zero, the value that lands here IS r0.
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5Z);
  *z = ~0ULL;
  *z = 0;
  g_h_inline_zero = *z;
}

static void tier4_once(bool altstack) {
  char name[128];
  struct sigaction act {};
  struct sigaction old {};
  act.sa_flags = SA_SIGINFO | (altstack ? SA_ONSTACK : 0);
  act.sa_sigaction = &usr1_handler;
  sigemptyset(&act.sa_mask);
  REQUIRE(sigaction(SIGUSR1, &act, &old) == 0);

  stack_t ss {}, old_ss {};
  bool ss_installed = false;
  if (altstack) {
    ss.ss_size = static_cast<size_t>(g_page) * 16;
    ss.ss_sp = mmap(nullptr, ss.ss_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ss.ss_sp == MAP_FAILED) {
      printf("[tier %d] SKIP altstack variant: mmap failed\n", g_tier);
      sigaction(SIGUSR1, &old, nullptr);
      return;
    }
    ss.ss_flags = 0;
    REQUIRE(sigaltstack(&ss, &old_ss) == 0);
    ss_installed = true;
  }

  VTable* vt = reinterpret_cast<VTable*>(g_win + OFF_VT);
  vt->fn = &callee_load64;
  volatile uint64_t* a = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4A);
  volatile uint64_t* b = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T4B);
  mark_slot(a);
  *a = g_pat_a;
  *b = kFillWord;
  opaque();

  g_handler_ran = 0;
  g_h_readback = 0;
  g_h_ptr_bits = 0;
  g_h_call_result = 0;
  g_h_inline_zero = ~0ULL;

  REQUIRE(raise(SIGUSR1) == 0);
  opaque();

  const char* tag = altstack ? "on sigaltstack" : "on the normal stack";
  snprintf(name, sizeof(name), "handler ran (%s)", tag);
  check_u64(name, 1, static_cast<uint64_t>(g_handler_ran));
  snprintf(name, sizeof(name), "handler read the value stored before raise (%s)", tag);
  check_u64(name, g_pat_a, g_h_readback);
  snprintf(name, sizeof(name), "handler's fn pointer load (%s)", tag);
  check_u64(name, reinterpret_cast<uint64_t>(&callee_load64), g_h_ptr_bits);
  snprintf(name, sizeof(name), "handler's indirect call result (%s)", tag);
  check_u64(name, g_pat_ptrlike, g_h_call_result);
  snprintf(name, sizeof(name), "handler's inline-zero store landed as zero (%s)", tag);
  check_u64(name, 0, g_h_inline_zero);
  snprintf(name, sizeof(name), "value the handler stored, read after sigreturn (%s)", tag);
  check_u64(name, g_pat_b, *b);
  snprintf(name, sizeof(name), "value stored before the signal is intact after sigreturn (%s)", tag);
  check_u64(name, g_pat_a, *a);

  // A fresh store/load and pointer round trip in the block resumed after sigreturn.
  volatile uint64_t* slot = reinterpret_cast<volatile uint64_t*>(g_win + OFF_PTR);
  const uint64_t real = reinterpret_cast<uint64_t>(&g_deref_target);
  *slot = real;
  opaque();
  snprintf(name, sizeof(name), "ptr round trip after sigreturn (%s)", tag);
  check_u64(name, real, *slot);
  snprintf(name, sizeof(name), "that ptr dereferences after sigreturn (%s)", tag);
  check_u64(name, g_deref_target, *reinterpret_cast<volatile uint64_t*>(static_cast<uintptr_t>(*slot)));

  if (ss_installed) {
    sigaltstack(&old_ss, nullptr);
    munmap(ss.ss_sp, ss.ss_size);
  }
  sigaction(SIGUSR1, &old, nullptr);
}

static void tier4(void) {
  tier_begin(4, "store/load across signal-handler entry and sigreturn");
  arena_refill();
  tier4_once(false);
  tier4_once(true);
  canary_scan("end of tier 4");
  tier_pass(4);
}

// =====================================================================================
// Tier 5 — in-block host-helper calls. Every helper the backend calls out to parks the
// link register in r0 and must put it back; roughly twenty sites do this by hand and one
// (guest PAUSE) did not. The corrupted r0 only lives until the next dispatcher entry, so
// each case keeps the store, the helper, and the load inside one guest block with no
// branch between them.
// =====================================================================================
static constexpr int kPauseIters = 4096; // > PAUSE_YIELD_LIMIT (1000), so the counter-gated
                                         // slow path is guaranteed to fire, ~4 times.

struct FailStream {
  int count = 0;
  int first[4] = {-1, -1, -1, -1};
  void note(int i) {
    if (count < 4) {
      first[count] = i;
    }
    ++count;
  }
  void report(const char* what, int total) {
    if (count == 0) {
      return;
    }
    g_case = what;
    printf("[tier %d] FAIL %s: %d of %d iterations corrupt\n", g_tier, what, count, total);
    printf("         first failing iterations:");
    for (int i = 0; i < 4 && first[i] >= 0; ++i) {
      printf(" %d", first[i]);
    }
    printf("\n");
    if (first[1] >= 0) {
      int period = first[1] - first[0];
      printf("         period between failures: %d\n", period);
      if (period >= 900 && period <= 1100) {
        printf("         *** that period is PAUSE_YIELD_LIMIT (1000, ALUOps.cpp:3154). Only\n"
               "             the counter-gated slow path is broken, i.e. the helper call it\n"
               "             makes does not restore r0 = 0 on the way out. MECHANISM 2.\n");
      }
    } else if (count == 1 && total > 1000) {
      printf("         a single failure in %d iterations is consistent with the one\n"
             "         counter-gated PAUSE slow path firing once. MECHANISM 2.\n", total);
    }
    record_failure();
  }
};

// 5a: PAUSE between the store and the load, plus an inline-constant zero store whose
// value operand is r0, plus a flag check (x86 PAUSE must preserve flags; routing the
// threshold compare through CR0 destroyed ZF on every PAUSE, ALUOps.cpp:3164-3171).
//
// The `*z = 0` stores below are load-bearing and depend on the compiler emitting the
// immediate form, `mov QWORD PTR [reg], 0`, rather than zeroing a register first. Only the
// immediate form reaches FEX's inline-constant path, which is the one that uses r0 as the
// value operand. Worth one objdump on the built binary to confirm:
//   objdump -d --no-show-raw-insn ptr_integrity.64 | grep -A2 -B2 'mov .*QWORD PTR.*,0x0'
// If the compiler chose `xor eax,eax; mov [rdx],rax` instead, this sub-case still tests
// the address side of mechanism 2 but loses the "print r0's contents verbatim" property,
// and the comment here is then wrong — say so rather than leaving it.
static void tier5_pause(void) {
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5);
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5Z);
  mark_slot(p);
  const uint64_t pat = g_pat_a;

  FailStream fs_value, fs_zero, fs_flags;
  uint64_t first_bad_value = 0, first_bad_zero = 0;

  for (int i = 0; i < kPauseIters; ++i) {
    *p = pat;
    *z = ~0ULL;
    __asm__ __volatile__("pause" ::: "memory");
    const uint64_t got = *p;
    *z = 0; // inline constant zero: lowered with r0 as the value operand
    const uint64_t gotz = *z;

    if (got != pat) {
      if (fs_value.count == 0) {
        first_bad_value = got;
      }
      fs_value.note(i);
    }
    if (gotz != 0) {
      if (fs_zero.count == 0) {
        first_bad_zero = gotz;
      }
      fs_zero.note(i);
    }
  }

  if (fs_value.count) {
    printf("[tier %d] first corrupt read-back after PAUSE: 0x%016" PRIx64 " (expected 0x%016" PRIx64 ")\n", g_tier,
           first_bad_value, pat);
    classify(pat, first_bad_value);
  }
  if (fs_zero.count) {
    printf("[tier %d] an inline-constant zero store did not produce zero; the value seen\n"
           "         was 0x%016" PRIx64 ". On this backend that store's value operand IS r0\n"
           "         (MemoryOps.cpp:592), so unless the slot was missed entirely, that\n"
           "         number is the contents of r0. A code-address-looking value here is\n"
           "         the leaked link register. MECHANISM 2, conclusively.\n",
           g_tier, first_bad_zero);
  }
  fs_value.report("PAUSE between store and load", kPauseIters);
  fs_zero.report("inline-zero store after PAUSE", kPauseIters);

  // Flags across PAUSE. Same iteration count so the slow path is included.
  for (int i = 0; i < kPauseIters; ++i) {
    uint8_t zf = 0xFF;
    const uint64_t v = pat;
    __asm__ __volatile__("cmp %[v], %[v]\n\t"
                         "pause\n\t"
                         "setz %[z]\n\t"
                         : [z] "=r"(zf)
                         : [v] "r"(v)
                         : "cc");
    if (zf != 1) {
      fs_flags.note(i);
    }
  }
  fs_flags.report("PAUSE must preserve ZF (cmp x,x / pause / setz)", kPauseIters);
}

// 5b: CPUID between the store and the load. CPUID is a host helper call (ALUOps.cpp:2865)
// that routes LR through r0, and it is available unconditionally.
static void tier5_cpuid(void) {
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5);
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5Z);
  mark_slot(p);
  const uint64_t pat = g_pat_b;
  FailStream fs_value, fs_zero;
  uint64_t first_bad = 0, first_bad_zero = 0;

  for (int i = 0; i < 64; ++i) {
    *p = pat;
    *z = ~0ULL;
    unsigned int a = 0, b = 0, c = 0, d = 0;
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0U));
    (void)a;
    (void)b;
    (void)c;
    (void)d;
    const uint64_t got = *p;
    *z = 0;
    const uint64_t gotz = *z;
    if (got != pat) {
      if (!fs_value.count) {
        first_bad = got;
      }
      fs_value.note(i);
    }
    if (gotz != 0) {
      if (!fs_zero.count) {
        first_bad_zero = gotz;
      }
      fs_zero.note(i);
    }
  }
  if (fs_value.count) {
    printf("[tier %d] first corrupt read-back after CPUID: 0x%016" PRIx64 "\n", g_tier, first_bad);
    classify(pat, first_bad);
  }
  if (fs_zero.count) {
    printf("[tier %d] inline-zero store after CPUID produced 0x%016" PRIx64 " (that is r0)\n", g_tier, first_bad_zero);
  }
  fs_value.report("CPUID between store and load", 64);
  fs_zero.report("inline-zero store after CPUID", 64);
}

// 5c: a LOCK RMW straddling a page boundary. FEX cannot do that with one PPC atomic, so
// it calls the split-lock helper (AtomicOps.cpp:109/:147) — another LR-through-r0 site.
// Single-threaded, so the arithmetic is exact and the result is deterministic.
static void tier5_splitlock(void) {
  volatile uint64_t* mis = reinterpret_cast<volatile uint64_t*>(g_win + OFF_STRAD);
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5);
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5Z);
  mark_slot(mis);

  // Zero the straddling counter with byte stores so the starting state is unambiguous.
  for (int i = 0; i < 8; ++i) {
    reinterpret_cast<volatile uint8_t*>(mis)[i] = 0;
  }
  opaque();

  const uint64_t pat = g_pat_ptrlike;
  const int iters = 4096;
  FailStream fs_value, fs_zero;
  uint64_t first_bad = 0, first_bad_zero = 0;

  for (int i = 0; i < iters; ++i) {
    *p = pat;
    *z = ~0ULL;
    uint64_t one = 1;
    __asm__ __volatile__("lock xadd qword ptr [%[m]], %[v]\n\t"
                         : [v] "+r"(one)
                         : [m] "r"(mis)
                         : "cc", "memory");
    const uint64_t got = *p;
    *z = 0;
    const uint64_t gotz = *z;
    if (got != pat) {
      if (!fs_value.count) {
        first_bad = got;
      }
      fs_value.note(i);
    }
    if (gotz != 0) {
      if (!fs_zero.count) {
        first_bad_zero = gotz;
      }
      fs_zero.note(i);
    }
  }

  if (fs_value.count) {
    printf("[tier %d] first corrupt read-back after a page-straddling lock xadd: 0x%016" PRIx64 "\n", g_tier, first_bad);
    classify(pat, first_bad);
  }
  if (fs_zero.count) {
    printf("[tier %d] inline-zero store after split-lock produced 0x%016" PRIx64 " (that is r0)\n", g_tier,
           first_bad_zero);
  }
  fs_value.report("page-straddling lock xadd between store and load", iters);
  fs_zero.report("inline-zero store after a page-straddling lock xadd", iters);

  // The counter itself: 4096 increments of 1, read back byte at a time.
  uint64_t counter = 0;
  for (int i = 0; i < 8; ++i) {
    counter |= static_cast<uint64_t>(reinterpret_cast<volatile uint8_t*>(mis)[i]) << (8 * i);
  }
  check_u64("page-straddling lock xadd accumulated exactly 4096", static_cast<uint64_t>(iters), counter);
}

// 5d: vector helpers. Vector_FToF, VAESImc, VAESKeyGenAssist and PCLMUL all call out to
// host code (VectorOps.cpp:4571, :5098, :5191, :5365) and all park LR in r0. Guarded on
// CPUID so an absent feature is a SKIP rather than a SIGILL. Written as inline asm, not
// intrinsics, so the guest instruction cannot be scheduled away from the memory accesses
// it is supposed to sit between.
static void tier5_vector_helpers(void) {
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5);
  volatile uint64_t* z = reinterpret_cast<volatile uint64_t*>(g_win + OFF_T5Z);
  mark_slot(p);
  const uint64_t pat = g_pat_a;

  unsigned int a = 0, b = 0, c = 0, d = 0;
  const bool have_cpuid1 = __get_cpuid(1, &a, &b, &c, &d) != 0;
  const bool have_aes = have_cpuid1 && (c & (1u << 25)) != 0;
  const bool have_pclmul = have_cpuid1 && (c & (1u << 1)) != 0;

  struct Case {
    const char* name;
    bool available;
    int which;
  };
  const Case cases[] = {
    {"cvtps2pd (Vector_FToF helper)", true, 0},
    {"aesimc (VAESImc helper)", have_aes, 1},
    {"aeskeygenassist (VAESKeyGenAssist helper)", have_aes, 2},
    {"pclmulqdq (PCLMUL helper)", have_pclmul, 3},
  };

  for (const Case& cs : cases) {
    if (!cs.available) {
      printf("[tier %d] SKIP %s: guest CPUID does not advertise the feature\n", g_tier, cs.name);
      continue;
    }
    FailStream fs_value, fs_zero;
    uint64_t first_bad = 0, first_bad_zero = 0;
    const int iters = 64;
    for (int i = 0; i < iters; ++i) {
      *p = pat;
      *z = ~0ULL;
      switch (cs.which) {
      case 0: __asm__ __volatile__("cvtps2pd xmm1, xmm0" ::: "xmm1", "memory"); break;
      case 1: __asm__ __volatile__("aesimc xmm1, xmm0" ::: "xmm1", "memory"); break;
      case 2: __asm__ __volatile__("aeskeygenassist xmm1, xmm0, 1" ::: "xmm1", "memory"); break;
      case 3: __asm__ __volatile__("pclmulqdq xmm1, xmm0, 0" ::: "xmm1", "memory"); break;
      default: break;
      }
      const uint64_t got = *p;
      *z = 0;
      const uint64_t gotz = *z;
      if (got != pat) {
        if (!fs_value.count) {
          first_bad = got;
        }
        fs_value.note(i);
      }
      if (gotz != 0) {
        if (!fs_zero.count) {
          first_bad_zero = gotz;
        }
        fs_zero.note(i);
      }
    }
    if (fs_value.count) {
      printf("[tier %d] first corrupt read-back after %s: 0x%016" PRIx64 "\n", g_tier, cs.name, first_bad);
      classify(pat, first_bad);
    }
    if (fs_zero.count) {
      printf("[tier %d] inline-zero store after %s produced 0x%016" PRIx64 " (that is r0)\n", g_tier, cs.name,
             first_bad_zero);
    }
    char name[128];
    snprintf(name, sizeof(name), "%s between store and load", cs.name);
    fs_value.report(name, iters);
    snprintf(name, sizeof(name), "inline-zero store after %s", cs.name);
    fs_zero.report(name, iters);
  }
}

static void tier5(void) {
  tier_begin(5, "store/load with PAUSE and other in-block host-helper calls interleaved");
  arena_refill();
  printf("[tier 5] 5a: PAUSE (%d iterations, PAUSE_YIELD_LIMIT is 1000)\n", kPauseIters);
  fflush(stdout);
  tier5_pause();
  printf("[tier 5] 5b: CPUID\n");
  fflush(stdout);
  tier5_cpuid();
  printf("[tier 5] 5c: page-straddling lock xadd (split-lock helper)\n");
  fflush(stdout);
  tier5_splitlock();
  printf("[tier 5] 5d: vector helpers\n");
  fflush(stdout);
  tier5_vector_helpers();
  canary_scan("end of tier 5");
  tier_pass(5);
}

// =====================================================================================
// Setup and the ladder itself.
// =====================================================================================
static void setup(void) {
  setvbuf(stdout, nullptr, _IONBF, 0); // a crash must not eat the tier marker

  g_page = sysconf(_SC_PAGESIZE);
  REQUIRE(g_page >= 4096);

  g_arena_size = static_cast<size_t>(g_page) * 4;
  void* arena_raw = mmap(nullptr, g_arena_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(arena_raw != MAP_FAILED);
  g_arena = static_cast<uint8_t*>(arena_raw);
  // Window straddles the boundary between arena page 1 and page 2, at window + 0x80.
  g_win = g_arena + static_cast<size_t>(g_page) * 2 - 0x80;
  REQUIRE((reinterpret_cast<uintptr_t>(g_win) & 0xF) == 0);

  // Guard mapping: readable page, then PROT_NONE.
  void* guard_raw =
    mmap(nullptr, static_cast<size_t>(g_page) * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  REQUIRE(guard_raw != MAP_FAILED);
  uint8_t* guard = static_cast<uint8_t*>(guard_raw);
  REQUIRE(mprotect(guard + g_page, static_cast<size_t>(g_page), PROT_NONE) == 0);
  g_guard_ok = guard;
  g_guard_edge = guard + g_page;
  memset(g_guard_ok, kFill, static_cast<size_t>(g_page));

  const char* all = getenv("PTR_INTEGRITY_ALL_TIERS");
  g_run_all = all != nullptr && all[0] == '1';
  const char* only = getenv("PTR_INTEGRITY_TIER");
  g_only_tier = only != nullptr ? atoi(only) : -1;

  printf("ptr_integrity.64: arena %p..%p (%zu bytes), window %p, page boundary at %p\n", static_cast<void*>(g_arena),
         static_cast<void*>(g_arena + g_arena_size), g_arena_size, static_cast<void*>(g_win),
         static_cast<void*>(g_win + 0x80));
  printf("ptr_integrity.64: guard page at %p, page size %ld\n", static_cast<void*>(g_guard_edge), g_page);
  printf("ptr_integrity.64: mode = %s%s\n", g_run_all ? "run all tiers" : "stop at first failing tier",
         g_only_tier >= 0 ? " (single tier selected)" : "");
  fflush(stdout);
}

static bool want(int n) {
  return g_only_tier < 0 || g_only_tier == n;
}

TEST_CASE("64-bit value integrity through guest memory: graduated ladder") {
  setup();

  if (want(0)) {
    tier0();
  }
  if (want(1)) {
    tier1();
  }
  if (want(2)) {
    tier2();
  }
  if (want(3)) {
    tier3();
  }
  if (want(4)) {
    tier4();
  }
  if (want(5)) {
    tier5();
  }

  printf("ptr_integrity.64: %d failing checks in total\n", g_fail_count);
  printf("ptr_integrity.64: tiers 0-5 done. Tier 6 (two threads) is ptr_integrity_mt.64.\n");
  fflush(stdout);
  REQUIRE(g_fail_count == 0);
}
