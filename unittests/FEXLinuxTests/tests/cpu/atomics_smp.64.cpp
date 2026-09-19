// SPDX-License-Identifier: MIT
//
// SMP atomics / PAUSE tests.
//
// The rest of the instruction suite (unittests/ASM) is single-threaded and runs
// each case to a fixed final state, so it cannot observe a contended-CAS bug, a
// lost RMW update, or a helper that corrupts state only on a slow path taken
// once every N executions. Everything here is a self-verifying arithmetic
// invariant, so no reference run on a native x86 host is needed.
//
// Regression coverage this was written for (PPC64LE host):
//   * DEF_OP(Yield) (guest PAUSE) compared its threshold counter into cr0,
//     which is that backend's live packed-NZCV -- so every PAUSE destroyed the
//     guest's flags. `pause preserves flags` pins this.
//   * The same op's every-1000th-PAUSE slow path routed the link register
//     through r0 and never restored the r0 == 0 zero-index invariant that JIT
//     blocks rely on for `ldx/stdx rX, rBase, r0`. The next guest push then
//     computed rBase + <code address> and SIGSEGV'd. `pause slow path` crosses
//     that threshold many times.
//
// NOTE ON INLINE ASM: this directory sets add_compile_options(-masm=intel), so
// the asm below is written in Intel syntax and references only hard registers.
// Do not switch dialect mid-block with .att_syntax/.intel_syntax to allow AT&T
// spelling -- that leaves the assembler in the wrong mode for the compiler's
// own following output and crashes at runtime. Everything that can avoid asm
// goes through __atomic_* builtins instead, which still emit `lock cmpxchg` /
// `lock xadd` and materialise the success bool straight out of ZF.

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <thread>
#include <vector>

namespace {

constexpr int kThreads = 4;
constexpr long kIters = 20000;

// Returns the old value; sets `swapped` to the CAS success flag, which the
// compiler materialises straight out of cmpxchg's ZF.
template<typename T>
inline T cas(volatile T* p, T expected, T desired, bool& swapped) {
  T seen = expected;
  swapped = __atomic_compare_exchange_n(const_cast<T*>(p), &seen, desired, false,
                                        __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
  // On success glibc/gcc leave `seen` untouched, and it already equals the old
  // value; on failure it is overwritten with what memory actually held.
  return seen;
}

template<typename T>
inline T xadd(volatile T* p, T v) {
  return __atomic_fetch_add(const_cast<T*>(p), v, __ATOMIC_SEQ_CST);
}

} // namespace

TEST_CASE("atomics_smp - cmpxchg truth table") {
  volatile uint32_t v32 = 0x11223344;
  bool ok;
  CHECK(cas<uint32_t>(&v32, 0x11223344, 0xAABBCCDD, ok) == 0x11223344);
  CHECK(ok);
  CHECK(v32 == 0xAABBCCDD);
  CHECK(cas<uint32_t>(&v32, 0xDEADBEEF, 0, ok) == 0xAABBCCDD);
  CHECK(!ok);
  CHECK(v32 == 0xAABBCCDD);

  volatile uint64_t v64 = 0x1122334455667788ULL;
  CHECK(cas<uint64_t>(&v64, 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL, ok) == 0x1122334455667788ULL);
  CHECK(ok);
  CHECK(cas<uint64_t>(&v64, 1, 2, ok) == 0x99AABBCCDDEEFF00ULL);
  CHECK(!ok);

  volatile uint16_t v16 = 0xBEEF;
  CHECK(cas<uint16_t>(&v16, 0xBEEF, 0x1234, ok) == 0xBEEF);
  CHECK(ok);
  CHECK(v16 == 0x1234);

  volatile uint8_t v8 = 0x5A;
  CHECK(cas<uint8_t>(&v8, 0x5A, 0xA5, ok) == 0x5A);
  CHECK(ok);
  CHECK(v8 == 0xA5);
}

TEST_CASE("atomics_smp - pause preserves flags") {
  // x86 PAUSE must not modify flags. The comparison and its use have to sit on
  // either side of the PAUSE, which the compiler will not arrange for us, so
  // this has to be written out by hand.
  unsigned char zf_eq = 0;
  __asm__ __volatile__("cmp rax, rax\n\t" // ZF = 1
                       "pause\n\t"
                       "setz cl"
                       : "=c"(zf_eq)
                       :
                       : "rax", "cc");
  CHECK(zf_eq == 1);

  unsigned char zf_ne = 0;
  __asm__ __volatile__("xor rax, rax\n\t"
                       "mov rdx, 1\n\t"
                       "cmp rax, rdx\n\t" // 0 vs 1 -> ZF = 0
                       "pause\n\t"
                       "setz cl"
                       : "=c"(zf_ne)
                       :
                       : "rax", "rdx", "cc");
  CHECK(zf_ne == 0);
}

TEST_CASE("atomics_smp - pause slow path") {
  // Cross any internal PAUSE-counter threshold repeatedly, checking flags each
  // time so a clobber that only occurs on the slow path is still caught. A
  // backend that corrupts guest state here crashes rather than fails.
  int clobbers = 0;
  for (long i = 0; i < 10000; i++) {
    unsigned char z = 0;
    __asm__ __volatile__("cmp rax, rax\n\t"
                         "pause\n\t"
                         "setz cl"
                         : "=c"(z)
                         :
                         : "rax", "cc");
    if (z != 1) clobbers++;
  }
  CHECK(clobbers == 0);
}

TEST_CASE("atomics_smp - contended cmpxchg") {
  static volatile uint32_t val;
  static uint64_t success[kThreads];
  static uint64_t flag_mismatch[kThreads];
  val = 0;
  memset(success, 0, sizeof(success));
  memset(flag_mismatch, 0, sizeof(flag_mismatch));

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([t] {
      uint64_t ok = 0, bad = 0;
      for (long i = 0; i < kIters; i++) {
        for (;;) {
          uint32_t old = val;
          bool swapped;
          uint32_t got = cas<uint32_t>(&val, old, old + 1, swapped);
          // x86 sets ZF exactly when the accumulator matched memory.
          if (swapped != (got == old)) bad++;
          if (swapped) {
            ok++;
            break;
          }
        }
      }
      success[t] = ok;
      flag_mismatch[t] = bad;
    });
  }
  for (auto& x : th) x.join();

  uint64_t total = 0, bad = 0;
  for (int t = 0; t < kThreads; t++) {
    total += success[t];
    bad += flag_mismatch[t];
  }
  CHECK(bad == 0);
  CHECK(total == (uint64_t)val);
  CHECK((uint64_t)val == (uint64_t)kThreads * kIters);
}

TEST_CASE("atomics_smp - contended xadd") {
  static volatile uint64_t val;
  static uint64_t sums[kThreads];
  val = 0;
  memset(sums, 0, sizeof(sums));

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([t] {
      uint64_t s = 0;
      for (long i = 0; i < kIters; i++) s += xadd<uint64_t>(&val, 1);
      sums[t] = s;
    });
  }
  for (auto& x : th) x.join();

  const uint64_t n = (uint64_t)kThreads * kIters;
  uint64_t sum = 0;
  for (int t = 0; t < kThreads; t++) sum += sums[t];
  CHECK(val == n);
  // The returned old values must be exactly 0..n-1 across all threads. A plain
  // final-value check would miss a duplicated or dropped return.
  CHECK(sum == n * (n - 1) / 2);
}

TEST_CASE("atomics_smp - cas spinlock mutual exclusion") {
  static volatile uint32_t lockw;
  static uint64_t guarded; // deliberately non-atomic, guarded by lockw
  static std::atomic<uint64_t> inside;
  static std::atomic<int> overlaps;
  lockw = 0;
  guarded = 0;
  inside = 0;
  overlaps = 0;

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([] {
      for (long i = 0; i < kIters; i++) {
        for (;;) {
          bool swapped;
          cas<uint32_t>(&lockw, 0, 1, swapped);
          if (swapped) break;
          __builtin_ia32_pause();
        }
        if (inside.fetch_add(1) != 0) overlaps++;
        guarded++;
        inside.fetch_sub(1);
        __atomic_store_n(const_cast<uint32_t*>(&lockw), 0u, __ATOMIC_SEQ_CST);
      }
    });
  }
  for (auto& x : th) x.join();

  CHECK(overlaps.load() == 0);
  CHECK(inside.load() == 0);
  CHECK(guarded == (uint64_t)kThreads * kIters);
}

TEST_CASE("atomics_smp - pthread_mutex") {
  static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
  static uint64_t counter;
  counter = 0;

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([] {
      for (long i = 0; i < kIters; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
      }
    });
  }
  for (auto& x : th) x.join();
  CHECK(counter == (uint64_t)kThreads * kIters);
}

TEST_CASE("atomics_smp - sub-word cas") {
  static volatile uint8_t v8;
  static volatile uint16_t v16;
  static uint64_t bad[kThreads];
  v8 = 0;
  v16 = 0;
  memset(bad, 0, sizeof(bad));

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([t] {
      uint64_t b = 0;
      for (long i = 0; i < kIters / 4; i++) {
        for (;;) {
          uint8_t old = v8;
          bool swapped;
          uint8_t got = cas<uint8_t>(&v8, old, (uint8_t)(old + 1), swapped);
          if (swapped != (got == old)) b++;
          if (swapped) break;
        }
        for (;;) {
          uint16_t old = v16;
          bool swapped;
          uint16_t got = cas<uint16_t>(&v16, old, (uint16_t)(old + 1), swapped);
          if (swapped != (got == old)) b++;
          if (swapped) break;
        }
      }
      bad[t] = b;
    });
  }
  for (auto& x : th) x.join();

  uint64_t total_bad = 0;
  for (int t = 0; t < kThreads; t++) total_bad += bad[t];
  CHECK(total_bad == 0);
}

TEST_CASE("atomics_smp - misaligned lock xadd") {
  // Exercises the split-lock fallback: PPC64's lwarx/ldarx require natural
  // alignment, so a misaligned LOCK RMW has to route through a serialising
  // helper rather than the LL/SC fast path.
  alignas(64) static uint8_t buf[64];
  memset(buf, 0, sizeof(buf));
  volatile uint64_t* p = reinterpret_cast<volatile uint64_t*>(buf + 3);

  std::vector<std::thread> th;
  for (int t = 0; t < kThreads; t++) {
    th.emplace_back([p] {
      for (long i = 0; i < kIters / 10; i++) xadd<uint64_t>(p, 1);
    });
  }
  for (auto& x : th) x.join();

  uint64_t got;
  memcpy(&got, buf + 3, 8);
  CHECK(got == (uint64_t)kThreads * (kIters / 10));
}
