// Async-signal interruption at arbitrary points in emitted code.
//
// Every ASM test runs to completion and the signal tests are
// synchronous-fault-shaped, so nothing in the suite interrupts a JIT block
// mid-flight and checks that state reconstruction is exact. That is the class
// the per-instruction RIP markers, the deferred-signal futex fix, and the
// SpillSRA stride bug all lived in: a signal lands between two guest
// instructions, the emulator reconstructs guest state, the handler runs, and
// resume must be bit-exact -- flags, x87 stack, and XMM registers included.
//
// Harness: a SIGVTALRM storm (setitimer ITIMER_VIRTUAL, 2ms interval --
// tick-sampled by the kernel, so the real rate is bounded by CONFIG_HZ)
// interrupts three checksum workloads on the main thread:
//   (1) a flag-dense adc/sbb chain whose carry flag is live across the loop
//       backedge (dec preserves CF), so ANY interruption boundary that loses
//       or duplicates flag state changes the checksum;
//   (2) an x87 workload accumulating in four long-double variables (80-bit
//       x87 on both -m32 and -m64), sensitive to lost precision-control,
//       TOP/stack, or register-file bits;
//   (3) an SSE2 integer workload across four XMM accumulators (exact
//       arithmetic -- no rounding-mode dependence), sensitive to any XMM
//       save/restore corruption.
//
// Each workload first computes a reference checksum with the timer disarmed,
// then repeats the identical computation under the storm until a minimum
// number of signals has interrupted it (bounded by wall clock so a broken
// timer fails loudly instead of hanging). Every stormed repetition must match
// the reference exactly: the checksums are deterministic for a fixed
// iteration count, so the pass criterion does not depend on where or how
// often the signals land -- only that enough of them did.
//
// The handler is installed WITHOUT SA_SIGINFO, so the 32-bit build storms the
// classic non-RT frame path and the 64-bit build the (only) rt frame path.
//
// Oracle: native x86 Linux -- this harness must always pass natively (verified
// -m64 and -m32 on an x86 host); any FEX failure is then an emulation defect.

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <csignal>
#include <ctime>
#include <sys/time.h>

#include <emmintrin.h>

namespace {

volatile sig_atomic_t g_sigcount = 0;

void StormHandler(int) {
  g_sigcount = g_sigcount + 1;
}

// Minimum interruptions per workload before the storm run may stop. At the
// coarsest common tick rate (CONFIG_HZ=100 samples ITIMER_VIRTUAL every 10ms
// of CPU time) this needs ~250ms of stormed CPU per workload; faster ticks or
// slower hosts (emulators) only make it easier.
constexpr int MIN_SIGNALS = 25;

// Wall-clock bound for one storm run: generous for slow emulated hosts, but
// still finite so a storm that never fires fails the MIN_SIGNALS check
// instead of hanging the suite.
constexpr time_t STORM_TIME_LIMIT_SEC = 6;

struct StormGuard {
  struct sigaction OldAction {};

  StormGuard() {
    g_sigcount = 0;
    struct sigaction act {};
    act.sa_handler = StormHandler;
    act.sa_flags = 0; // no SA_SIGINFO: classic frame on 32-bit
    sigemptyset(&act.sa_mask);
    sigaction(SIGVTALRM, &act, &OldAction);

    itimerval timer {};
    timer.it_interval.tv_usec = 2000;
    timer.it_value.tv_usec = 2000;
    setitimer(ITIMER_VIRTUAL, &timer, nullptr);
  }

  ~StormGuard() {
    itimerval timer {}; // zero = disarm
    setitimer(ITIMER_VIRTUAL, &timer, nullptr);
    sigaction(SIGVTALRM, &OldAction, nullptr);
  }
};

double Monotonic() {
  timespec ts {};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) * 1e-9;
}

// Iteration counts are fixed (checksums must be reproducible) and sized so a
// single pass is well under a second natively; the storm loop repeats passes
// until MIN_SIGNALS is met, so faster hosts just run more identical passes.
// Read through a volatile so the compiler cannot prove the reference and
// stormed calls share arguments and merge them.
volatile uint32_t g_flag_iters = 3'000'000;
volatile uint32_t g_x87_iters = 1'000'000;
volatile uint32_t g_sse_iters = 2'000'000;

// ---- (1) flag-dense integer loop ------------------------------------------
// adc/sbb chain; dec preserves CF, so the carry is live across the backedge
// and across every instruction boundary a signal can land on. 32-bit
// registers only, so the same asm assembles in both bitnesses.
__attribute__((noinline)) uint64_t FlagWork(uint32_t iters) {
  uint32_t sum = 0x12345678u;
  uint32_t acc = 0x9E3779B9u;
  uint32_t i = iters;
  __asm volatile(R"(
  .Lflag_loop%=:
    add %[sum], %[k]
    adc %[acc], %[sum]
    add %[sum], %[acc]
    adc %[acc], %[k]
    sbb %[sum], %[acc]
    adc %[acc], %[sum]
    sbb %[sum], %[k]
    adc %[acc], %[sum]
    dec %[i]
    jnz .Lflag_loop%=
  )"
                 : [sum] "+r"(sum), [acc] "+r"(acc), [i] "+r"(i)
                 : [k] "r"(0x045D9F3Bu)
                 : "cc");
  return (static_cast<uint64_t>(sum) << 32) | acc;
}

// ---- (2) x87 long-double loop ----------------------------------------------
// long double is 80-bit x87 in both -m32 and -m64 (even with -mfpmath=sse),
// so this keeps four x87 stack slots hot. The recurrence is pure fmul/fadd/
// fsub with values that stay in range, so results are bit-deterministic for a
// fixed iteration count.
__attribute__((noinline)) uint64_t X87Work(uint32_t iters) {
  long double a = 1.0L;
  long double b = -0.5L;
  long double c = 3.25L;
  long double d = 0.125L;
  for (uint32_t i = 0; i < iters; ++i) {
    a = a * 1.000000119L + 0.25L;
    b = b - a * 0.0625L;
    c = c + b * 0.5L;
    d = d * 0.999999881L + c * 0.03125L;
  }

  // Hash the 10 significant bytes of each accumulator (the tail of the
  // 12/16-byte storage type is padding and undefined).
  uint64_t h = 0xcbf29ce484222325ULL;
  const long double vals[4] = {a, b, c, d};
  for (const long double& v : vals) {
    unsigned char bytes[sizeof(long double)] = {};
    std::memcpy(bytes, &v, sizeof(v));
    for (size_t j = 0; j < 10; ++j) {
      h = (h ^ bytes[j]) * 0x100000001b3ULL;
    }
  }
  return h;
}

// ---- (3) SSE2 packed-integer loop ------------------------------------------
// Four live XMM accumulators, exact integer arithmetic (no rounding-mode or
// denormal dependence), so the checksum is deterministic and any corruption
// of an XMM register across a signal shows up.
__attribute__((noinline)) uint64_t SSEWork(uint32_t iters) {
  __m128i a = _mm_set_epi32(0x243F6A88, static_cast<int>(0x85A308D3), 0x13198A2E, 0x03707344);
  __m128i b = _mm_set_epi32(static_cast<int>(0xA4093822), 0x299F31D0, 0x082EFA98, static_cast<int>(0xEC4E6C89));
  __m128i c = _mm_set_epi32(0x452821E6, 0x38D01377, static_cast<int>(0xBE5466CF), 0x34E90C6C);
  const __m128i k = _mm_set_epi32(static_cast<int>(0x9E3779B9), 0x7F4A7C15, static_cast<int>(0xF39CC060), 0x5CEDC834);
  for (uint32_t i = 0; i < iters; ++i) {
    a = _mm_add_epi32(a, k);
    b = _mm_xor_si128(b, a);
    b = _mm_add_epi32(b, _mm_slli_epi32(a, 7));
    c = _mm_add_epi64(c, _mm_mul_epu32(a, b));
    a = _mm_xor_si128(a, _mm_srli_epi32(c, 9));
    a = _mm_shuffle_epi32(a, 0x93);
  }

  const __m128i folded = _mm_xor_si128(_mm_xor_si128(a, b), c);
  alignas(16) uint64_t lanes[2];
  _mm_store_si128(reinterpret_cast<__m128i*>(lanes), folded);
  return lanes[0] ^ lanes[1];
}

void RunStorm(uint64_t (*work)(uint32_t), volatile uint32_t& iters_src) {
  const uint32_t iters = iters_src;

  // Reference pass: timer disarmed, clean process state.
  const uint64_t ref = work(iters);

  // Storm passes: identical computation, interrupted continuously. Every pass
  // must reproduce the reference bit-for-bit no matter where the signals hit.
  int passes = 0;
  int mismatches = 0;
  {
    StormGuard storm;
    const double deadline = Monotonic() + STORM_TIME_LIMIT_SEC;
    do {
      const uint64_t got = work(iters);
      ++passes;
      if (got != ref) {
        ++mismatches;
      }
    } while (g_sigcount < MIN_SIGNALS && Monotonic() < deadline);
  }

  CHECK(mismatches == 0);
  CHECK(passes > 0);
  // Harness sanity: the storm actually interrupted the work. Bounded from
  // below only -- exact counts depend on CONFIG_HZ and host speed.
  CHECK(g_sigcount >= MIN_SIGNALS);
}

} // namespace

TEST_CASE("signal storm: flag-dense adc/sbb loop") {
  RunStorm(FlagWork, g_flag_iters);
}

TEST_CASE("signal storm: x87 long-double loop") {
  RunStorm(X87Work, g_x87_iters);
}

TEST_CASE("signal storm: SSE2 packed-integer loop") {
  RunStorm(SSEWork, g_sse_iters);
}
