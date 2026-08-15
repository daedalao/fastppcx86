// Memory-model regression gate for the guest-visible x86-TSO contract.
//
// MP (message passing): writer stores x=1 then y=1 with plain stores; reader
// loads y then x with plain loads. x86-TSO forbids observing y==1 && x==0.
// Any violation under FEX is a guest-visible memory-model break, in EVERY
// configuration: barrier emulation (default) and FEX_HWTSO=1 (PROT_SAO pages,
// no emitted barriers - the CMake registration runs this binary once per
// mode). On kernels without PROT_SAO the HWTSO leg falls back to barrier
// emulation and still gates the default model.
//
// SB (store buffering) runs as harness sanity only: both threads store their
// own flag then load the other's. TSO permits both loads reading 0, so
// nothing is asserted about its outcome; it exists so a future
// stronger-than-TSO regression (e.g. accidental SC mapping) is visible in the
// log without failing the gate.
//
// Threads are pinned to distinct CPUs on a best-effort basis; an unpinnable
// environment weakens the probe but cannot produce a false failure.
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <pthread.h>
#include <sched.h>

namespace {
constexpr int kRounds = 100000;

volatile uint32_t X, Y;
volatile uint32_t SbA, SbB, SbRa, SbRb;
std::atomic<int> Phase{};

void PinTo(int cpu) {
  cpu_set_t Set;
  CPU_ZERO(&Set);
  CPU_SET(cpu, &Set);
  sched_setaffinity(0, sizeof(Set), &Set); // best effort
}

void* Writer(void*) {
  PinTo(0);
  for (int R = 1; R <= kRounds; R++) {
    while (Phase.load(std::memory_order_seq_cst) != R) {
    }
    X = 1;
    Y = 1;
    SbA = 1;
    SbRa = SbB;
    Phase.store(-R, std::memory_order_seq_cst);
  }
  return nullptr;
}
} // namespace

int main() {
  pthread_t Thread;
  pthread_create(&Thread, nullptr, Writer, nullptr);
  PinTo(8);

  long MpViolations = 0, MpRaced = 0, SbBothZero = 0;
  for (int R = 1; R <= kRounds; R++) {
    X = 0;
    Y = 0;
    SbA = 0;
    SbB = 0;
    Phase.store(R, std::memory_order_seq_cst);
    // Race the writer with plain accesses.
    const uint32_t Ry = Y;
    const uint32_t Rx = X;
    SbB = 1;
    SbRb = SbA;
    if (Ry == 1) {
      MpRaced++;
      if (Rx == 0) {
        MpViolations++;
      }
    }
    while (Phase.load(std::memory_order_seq_cst) != -R) {
    }
    if (SbRa == 0 && SbRb == 0) {
      SbBothZero++; // legal under TSO; informational only
    }
  }
  pthread_join(Thread, nullptr);

  printf("MP: %ld violations / %d rounds (%ld raced)\n", MpViolations, kRounds, MpRaced);
  printf("SB: both-zero %ld / %d rounds (TSO-legal, informational)\n", SbBothZero, kRounds);
  return MpViolations != 0;
}
