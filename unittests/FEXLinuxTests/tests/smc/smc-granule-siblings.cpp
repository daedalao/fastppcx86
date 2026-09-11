/*
  Two 4K code regions inside ONE host granule, one rewritten, both must stay
  correct.

  On a host whose page is larger than the guest's 4K -- 64K ppc64le -- mtrack's
  protect/unprotect quantum is 16 guest pages, not 1. Servicing a write fault
  on guest page N therefore lifts the write protection from pages N+1..N+15 as
  well, and if their compiled blocks are left live the guest can rewrite one
  with no fault and no invalidation: the block keeps running the OLD bytes.
  That is the soundness rule of the 64K design (Part 2 section 5) and this is
  the minimum shape that exposes it.

  One mapping, two stubs a guest page apart, both executed so both are compiled
  and both armed. Then each is rewritten and called in turn, with the OTHER one
  called immediately afterwards and checked against the last value written to
  IT. A sibling whose invalidation was skipped returns a stale immediate.

  Three interleavings, because the fault path treats them differently:
    - alternating   : every write faults a page whose sibling is live code.
    - burst         : one page is rewritten repeatedly (only the first write
                      faults; the rest run on an already-unprotected granule)
                      before the sibling is called again.
    - data sibling  : a third guest page in the same granule holds plain DATA
                      written constantly. Every one of those stores faults a
                      granule that is armed only because of the code pages, and
                      must disturb neither stub. This is the mixed code/data
                      granule FEX_SMCGRANULEFLIPLOG exists to report.

  On a 4K host the two stubs are in different granules and this still passes --
  it just stops being interesting, which is correct for a test of a rule that
  only has content when a granule holds more than one guest page.

  Builds two ways. Normally it is a Catch2 test like the rest of
  FEXLinuxTests. Compiled with -DSMC_GRANULE_STANDALONE it brings its own main
  and uses nothing but libc, so it can be linked -static -- which is how it is
  run on a 64K host before the S4a loader work lands and dynamic guests load at
  all.
*/
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <sys/mman.h>
#include <unistd.h>

namespace {
// The guest's page is 4096 whatever the host does: FEX hands the guest
// AT_PAGESZ=4096 and that is the x86 ABI. Hard-coded rather than asked of
// sysconf, which must also answer 4096 here but is not what is being measured.
constexpr size_t GuestPage = 4096;
// One host granule on every host this can run on (ppc64le tops out at 64K), so
// the two stubs are guaranteed to share one.
constexpr size_t GranuleSize = 64 * 1024;

// mov eax, imm32 ; ret
constexpr unsigned char Stub[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};

int Failures = 0;

#define CHECK_EQ(Actual, Expected) \
  do { \
    const uint64_t A_ = (uint64_t)(Actual); \
    const uint64_t E_ = (uint64_t)(Expected); \
    if (A_ != E_) { \
      ++Failures; \
      if (Failures < 16) { \
        std::printf("FAIL %s:%d: %s = %#llx, expected %#llx\n", __FILE__, __LINE__, #Actual, (unsigned long long)A_, \
                    (unsigned long long)E_); \
      } \
    } \
  } while (0)

struct Region {
  unsigned char* Code {};

  bool Init() {
    Code = static_cast<unsigned char*>(mmap(nullptr, GranuleSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (Code == MAP_FAILED) {
      Code = nullptr;
      return false;
    }
    return true;
  }

  ~Region() {
    if (Code) {
      munmap(Code, GranuleSize);
    }
  }

  unsigned char* Page(size_t Index) {
    return Code + Index * GuestPage;
  }

  void Plant(size_t Index) {
    std::memcpy(Page(Index), Stub, sizeof(Stub));
  }

  // Rewrite the imm32 in place. This is the store that faults while the page is
  // armed, and whose granule-wide unprotect is what puts the sibling at risk.
  void Write(size_t Index, uint32_t Value) {
    std::memcpy(Page(Index) + 1, &Value, sizeof(Value));
  }

  uint32_t Call(size_t Index) {
    auto Fn = reinterpret_cast<uint32_t (*)()>(Page(Index));
    return Fn();
  }

  // Page 0 and page 1: adjacent guest pages, one host granule on a 64K host.
  // Compile and arm both.
  void Arm() {
    Plant(0);
    Plant(1);
    Write(0, 0xA0000000);
    Write(1, 0xB0000000);
    CHECK_EQ(Call(0), 0xA0000000);
    CHECK_EQ(Call(1), 0xB0000000);
  }
};

void RunAlternating() {
  Region R;
  if (!R.Init()) {
    ++Failures;
    return;
  }
  R.Arm();

  uint32_t Last[2] = {0xA0000000, 0xB0000000};
  for (uint32_t i = 1; i <= 256; ++i) {
    const size_t Target = i & 1;
    const size_t Sibling = Target ^ 1;

    Last[Target] = 0xA0000000 + i;
    R.Write(Target, Last[Target]);

    // The rewritten page must show the new value...
    CHECK_EQ(R.Call(Target), Last[Target]);
    // ...and the sibling, whose protection the same unprotect lifted, must
    // still show ITS last written value, not a stale one.
    CHECK_EQ(R.Call(Sibling), Last[Sibling]);
  }
}

void RunBurst() {
  Region R;
  if (!R.Init()) {
    ++Failures;
    return;
  }
  R.Arm();

  // Only the first store of each burst faults; the rest land on an already
  // unprotected granule. The sibling must survive the whole burst.
  uint32_t LastSibling = 0xB0000000;
  for (uint32_t Burst = 1; Burst <= 32; ++Burst) {
    uint32_t Last = 0;
    for (uint32_t i = 0; i < 16; ++i) {
      Last = 0xC0000000 + Burst * 16 + i;
      R.Write(0, Last);
    }
    CHECK_EQ(R.Call(0), Last);
    CHECK_EQ(R.Call(1), LastSibling);

    LastSibling = 0xB0000000 + Burst;
    R.Write(1, LastSibling);
    CHECK_EQ(R.Call(1), LastSibling);
    CHECK_EQ(R.Call(0), Last);
  }
}

void RunDataSibling() {
  Region R;
  if (!R.Init()) {
    ++Failures;
    return;
  }
  R.Arm();

  // Page 2 is pure data. On a 64K host it is inside the same granule as the two
  // code pages, so mtrack armed it as collateral and every store to it faults a
  // granule that holds live code. Neither stub may be disturbed, and the data
  // must read back.
  volatile uint64_t* Data = reinterpret_cast<volatile uint64_t*>(R.Page(2));
  for (uint32_t i = 1; i <= 512; ++i) {
    Data[i % 64] = 0x1122334400000000ull | i;
    if ((i & 63) == 0) {
      CHECK_EQ(R.Call(0), 0xA0000000);
      CHECK_EQ(R.Call(1), 0xB0000000);
    }
  }
  // 449..512 is one full pass of the 64 slots, each holding its last write.
  for (uint32_t i = 449; i <= 512; ++i) {
    CHECK_EQ(Data[i % 64], 0x1122334400000000ull | i);
  }

  // And a rewrite still works after all that data traffic.
  R.Write(0, 0xDEADBEEF);
  CHECK_EQ(R.Call(0), 0xDEADBEEF);
  CHECK_EQ(R.Call(1), 0xB0000000);
}

int RunOne(void (*Fn)(), const char* Name) {
  Failures = 0;
  Fn();
  std::printf("%s: %s (%d failure(s))\n", Name, Failures ? "FAIL" : "PASS", Failures);
  return Failures;
}
} // namespace

#ifdef SMC_GRANULE_STANDALONE
int main() {
  int Total = 0;
  Total += RunOne(&RunAlternating, "granule-alternating");
  Total += RunOne(&RunBurst, "granule-burst");
  Total += RunOne(&RunDataSibling, "granule-data-sibling");
  std::printf("smc-granule-siblings: %s\n", Total ? "FAIL" : "PASS");
  return Total ? 1 : 0;
}
#else
#include <catch2/catch_test_macros.hpp>

TEST_CASE("SMC: two code pages in one host granule, alternating rewrites") {
  REQUIRE(RunOne(&RunAlternating, "granule-alternating") == 0);
}

TEST_CASE("SMC: two code pages in one host granule, burst rewrites") {
  REQUIRE(RunOne(&RunBurst, "granule-burst") == 0);
}

TEST_CASE("SMC: a data page sharing a host granule with two code pages") {
  REQUIRE(RunOne(&RunDataSibling, "granule-data-sibling") == 0);
}
#endif
