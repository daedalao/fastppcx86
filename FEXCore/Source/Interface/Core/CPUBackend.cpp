// SPDX-License-Identifier: MIT
#include "FEXCore/Config/Config.h"
#include "Interface/Context/Context.h"
#include "Interface/Core/CPUBackend.h"
#include "Interface/Core/LookupCache.h"
#ifndef ARCHITECTURE_ppc64le
#include "Interface/Core/Dispatcher/Dispatcher.h"
#endif

#include <FEXCore/Core/Context.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/AllocatorHooks.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/PrctlUtils.h>
#include <FEXCore/Utils/Telemetry.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>

#ifndef _WIN32
#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#endif

namespace FEXCore {
namespace CPU {

  static constexpr size_t INITIAL_CODE_SIZE = 1024 * 1024 * 16;
  // We don't want to move above 128MB atm because that means we will have to encode longer jumps
  static constexpr size_t MAX_CODE_SIZE = 1024 * 1024 * 128;

  constexpr static uint64_t NamedVectorConstants[FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_CONST_POOL_MAX][2] = {
    {0x0003'0002'0001'0000ULL, 0x0007'0006'0005'0004ULL}, // NAMED_VECTOR_INCREMENTAL_U16_INDEX
    {0x000B'000A'0009'0008ULL, 0x000F'000E'000D'000CULL}, // NAMED_VECTOR_INCREMENTAL_U16_INDEX_UPPER
    {0x0000'0000'8000'0000ULL, 0x0000'0000'8000'0000ULL}, // NAMED_VECTOR_PADDSUBPS_INVERT
    {0x0000'0000'8000'0000ULL, 0x0000'0000'8000'0000ULL}, // NAMED_VECTOR_PADDSUBPS_INVERT_UPPER
    {0x8000'0000'0000'0000ULL, 0x0000'0000'0000'0000ULL}, // NAMED_VECTOR_PADDSUBPD_INVERT
    {0x8000'0000'0000'0000ULL, 0x0000'0000'0000'0000ULL}, // NAMED_VECTOR_PADDSUBPD_INVERT_UPPER
    {0x8000'0000'0000'0000ULL, 0x8000'0000'0000'0000ULL}, // NAMED_VECTOR_PSUBADDPS_INVERT
    {0x8000'0000'0000'0000ULL, 0x8000'0000'0000'0000ULL}, // NAMED_VECTOR_PSUBADDPS_INVERT_UPPER
    {0x0000'0000'0000'0000ULL, 0x8000'0000'0000'0000ULL}, // NAMED_VECTOR_PSUBADDPD_INVERT
    {0x0000'0000'0000'0000ULL, 0x8000'0000'0000'0000ULL}, // NAMED_VECTOR_PSUBADDPD_INVERT_UPPER
    {0x0000'0001'0000'0000ULL, 0x0000'0003'0000'0002ULL}, // NAMED_VECTOR_MOVMSKPS_SHIFT
    {0x040B'0E01'0B0E'0104ULL, 0x0C03'0609'0306'090CULL}, // NAMED_VECTOR_AESKEYGENASSIST_SWIZZLE
    {0x0706'0504'FFFF'FFFFULL, 0xFFFF'FFFF'0B0A'0908ULL}, // NAMED_VECTOR_BLENDPS_0110B
    {0x0706'0504'0302'0100ULL, 0xFFFF'FFFF'0B0A'0908ULL}, // NAMED_VECTOR_BLENDPS_0111B
    {0xFFFF'FFFF'0302'0100ULL, 0x0F0E'0D0C'FFFF'FFFFULL}, // NAMED_VECTOR_BLENDPS_1001B
    {0x0706'0504'0302'0100ULL, 0x0F0E'0D0C'FFFF'FFFFULL}, // NAMED_VECTOR_BLENDPS_1011B
    {0xFFFF'FFFF'0302'0100ULL, 0x0F0E'0D0C'0B0A'0908ULL}, // NAMED_VECTOR_BLENDPS_1101B
    {0x0706'0504'FFFF'FFFFULL, 0x0F0E'0D0C'0B0A'0908ULL}, // NAMED_VECTOR_BLENDPS_1110B
    {0x8040'2010'0804'0201ULL, 0x8040'2010'0804'0201ULL}, // NAMED_VECTOR_MOVMASKB
    {0x8040'2010'0804'0201ULL, 0x8040'2010'0804'0201ULL}, // NAMED_VECTOR_MOVMASKB_UPPER
    {0x8000'0000'0000'0000ULL, 0x0000'0000'0000'3FFFULL}, // NAMED_VECTOR_X87_ONE
    {0xD49A'784B'CD1B'8AFEULL, 0x0000'0000'0000'4000ULL}, // NAMED_VECTOR_X87_LOG2_10
    {0xB8AA'3B29'5C17'F0BCULL, 0x0000'0000'0000'3FFFULL}, // NAMED_VECTOR_X87_LOG2_E
    {0xC90F'DAA2'2168'C235ULL, 0x0000'0000'0000'4000ULL}, // NAMED_VECTOR_X87_PI
    {0x9A20'9A84'FBCF'F799ULL, 0x0000'0000'0000'3FFDULL}, // NAMED_VECTOR_X87_LOG10_2
    {0xB172'17F7'D1CF'79ACULL, 0x0000'0000'0000'3FFEULL}, // NAMED_VECTOR_X87_LOG_2
    {0x4F00'0000'4F00'0000ULL, 0x4F00'0000'4F00'0000ULL}, // NAMED_VECTOR_CVTMAX_F32_I32
    {0x4F00'0000'4F00'0000ULL, 0x4F00'0000'4F00'0000ULL}, // NAMED_VECTOR_CVTMAX_F32_I32_UPPER
    {0x5F00'0000'5F00'0000ULL, 0x5F00'0000'5F00'0000ULL}, // NAMED_VECTOR_CVTMAX_F32_I64
    {0x41E0'0000'0000'0000ULL, 0x41E0'0000'0000'0000ULL}, // NAMED_VECTOR_CVTMAX_F64_I32
    {0x41E0'0000'0000'0000ULL, 0x41E0'0000'0000'0000ULL}, // NAMED_VECTOR_CVTMAX_F64_I32_UPPER
    {0x43E0'0000'0000'0000ULL, 0x43E0'0000'0000'0000ULL}, // NAMED_VECTOR_CVTMAX_F64_I64
    {0x8000'0000'8000'0000ULL, 0x8000'0000'8000'0000ULL}, // NAMED_VECTOR_CVTMAX_I32
    {0x8000'0000'0000'0000ULL, 0x8000'0000'0000'0000ULL}, // NAMED_VECTOR_CVTMAX_I64
    {0x0000'0000'0000'0000ULL, 0x0000'0000'0000'8000ULL}, // NAMED_VECTOR_F80_SIGN_MASK
    {0x5A82'7999'5A82'7999ULL, 0x5A82'7999'5A82'7999ULL}, // NAMED_VECTOR_SHA1RNDS_K0
    {0x6ED9'EBA1'6ED9'EBA1ULL, 0x6ED9'EBA1'6ED9'EBA1ULL}, // NAMED_VECTOR_SHA1RNDS_K1
    {0x8F1B'BCDC'8F1B'BCDCULL, 0x8F1B'BCDC'8F1B'BCDCULL}, // NAMED_VECTOR_SHA1RNDS_K2
    {0xCA62'C1D6'CA62'C1D6ULL, 0xCA62'C1D6'CA62'C1D6ULL}, // NAMED_VECTOR_SHA1RNDS_K3
  };

  constexpr static auto PSHUFLW_LUT {[]() consteval {
    struct alignas(16) LUTType {
      uint64_t Val[2];
    };
    // Expectation for this LUT is to simulate PSHUFLW with ARM's TBL (single register) instruction
    // PSHUFLW behaviour:
    // 16-bit words in [63:48], [47:32], [31:16], [15:0] are selected using the 8-bit Index.
    // For 128-bit PSHUFLW, bits [127:64] are identity copied.
    constexpr uint64_t IdentityCopyUpper = 0x0f'0e'0d'0c'0b'0a'09'08;
    std::array<LUTType, 256> TotalLUT {};
    uint64_t WordSelection[4] = {
      0x01'00,
      0x03'02,
      0x05'04,
      0x07'06,
    };
    for (size_t i = 0; i < 256; ++i) {
      auto& LUT = TotalLUT[i];
      const auto Word0 = (i >> 0) & 0b11;
      const auto Word1 = (i >> 2) & 0b11;
      const auto Word2 = (i >> 4) & 0b11;
      const auto Word3 = (i >> 6) & 0b11;

      LUT.Val[0] = (WordSelection[Word0] << 0) | (WordSelection[Word1] << 16) | (WordSelection[Word2] << 32) | (WordSelection[Word3] << 48);

      LUT.Val[1] = IdentityCopyUpper;
    }
    return TotalLUT;
  }()};

  constexpr static auto PSHUFHW_LUT {[]() consteval {
    struct alignas(16) LUTType {
      uint64_t Val[2];
    };
    // Expectation for this LUT is to simulate PSHUFHW with ARM's TBL (single register) instruction
    // PSHUFHW behaviour:
    // 16-bit words in [127:112], [111:96], [95:80], [79:64] are selected using the 8-bit Index.
    // Incoming words come from bits [127:64] of the source.
    // Bits [63:0] are identity copied.
    constexpr uint64_t IdentityCopyLower = 0x07'06'05'04'03'02'01'00;
    std::array<LUTType, 256> TotalLUT {};
    uint64_t WordSelection[4] = {
      0x09'08,
      0x0b'0a,
      0x0d'0c,
      0x0f'0e,
    };
    for (size_t i = 0; i < 256; ++i) {
      auto& LUT = TotalLUT[i];
      const auto Word0 = (i >> 0) & 0b11;
      const auto Word1 = (i >> 2) & 0b11;
      const auto Word2 = (i >> 4) & 0b11;
      const auto Word3 = (i >> 6) & 0b11;

      LUT.Val[0] = IdentityCopyLower;

      LUT.Val[1] = (WordSelection[Word0] << 0) | (WordSelection[Word1] << 16) | (WordSelection[Word2] << 32) | (WordSelection[Word3] << 48);
    }
    return TotalLUT;
  }()};

  constexpr static auto PSHUFD_LUT {[]() consteval {
    struct alignas(16) LUTType {
      uint64_t Val[2];
    };
    // Expectation for this LUT is to simulate PSHUFD with ARM's TBL (single register) instruction
    // PSHUFD behaviour:
    // 32-bit words in [127:96], [95:64], [63:32], [31:0] are selected using the 8-bit Index.
    std::array<LUTType, 256> TotalLUT {};
    uint64_t WordSelection[4] = {
      0x03'02'01'00,
      0x07'06'05'04,
      0x0b'0a'09'08,
      0x0f'0e'0d'0c,
    };
    for (size_t i = 0; i < 256; ++i) {
      auto& LUT = TotalLUT[i];
      const auto Word0 = (i >> 0) & 0b11;
      const auto Word1 = (i >> 2) & 0b11;
      const auto Word2 = (i >> 4) & 0b11;
      const auto Word3 = (i >> 6) & 0b11;

      LUT.Val[0] = (WordSelection[Word0] << 0) | (WordSelection[Word1] << 32);

      LUT.Val[1] = (WordSelection[Word2] << 0) | (WordSelection[Word3] << 32);
    }
    return TotalLUT;
  }()};

  constexpr static auto SHUFPS_LUT {[]() consteval {
    struct alignas(16) LUTType {
      uint64_t Val[2];
    };
    // 32-bit words in [127:96], [95:64], [63:32], [31:0] are selected using the 8-bit Index.
    // Expectation for this LUT is to simulate SHUFPS with ARM's TBL (two register) instruction.
    // SHUFPS behaviour:
    // Two 32-bits words from each source are selected from each source in the lower and upper halves of the 128-bit destination.
    // Dest[31:0]   = Src1[<Word0>]
    // Dest[63:32]  = Src1[<Word1>]
    // Dest[95:64]  = Src2[<Word2>]
    // Dest[127:96] = Src2[<Word3>]

    std::array<LUTType, 256> TotalLUT {};
    const uint64_t WordSelectionSrc1[4] = {
      0x03'02'01'00,
      0x07'06'05'04,
      0x0b'0a'09'08,
      0x0f'0e'0d'0c,
    };

    // Src2 needs to offset each byte index by 16-bytes to pull from the second source.
    const uint64_t WordSelectionSrc2[4] = {
      0x03'02'01'00 + (0x10101010),
      0x07'06'05'04 + (0x10101010),
      0x0b'0a'09'08 + (0x10101010),
      0x0f'0e'0d'0c + (0x10101010),
    };

    for (size_t i = 0; i < 256; ++i) {
      auto& LUT = TotalLUT[i];
      const auto Word0 = (i >> 0) & 0b11;
      const auto Word1 = (i >> 2) & 0b11;
      const auto Word2 = (i >> 4) & 0b11;
      const auto Word3 = (i >> 6) & 0b11;

      LUT.Val[0] = (WordSelectionSrc1[Word0] << 0) | (WordSelectionSrc1[Word1] << 32);

      LUT.Val[1] = (WordSelectionSrc2[Word2] << 0) | (WordSelectionSrc2[Word3] << 32);
    }
    return TotalLUT;
  }()};

  constexpr static auto DPPS_MASK {[]() consteval {
    struct alignas(16) LUTType {
      uint32_t Val[4];
    };

    std::array<LUTType, 16> TotalLUT {};
    for (size_t i = 0; i < TotalLUT.size(); ++i) {
      auto& LUT = TotalLUT[i];
      constexpr auto GetLUT = [](size_t i, size_t Index) {
        if (i & (1U << Index)) {
          return -1U;
        }
        return 0U;
      };

      LUT.Val[0] = GetLUT(i, 0);
      LUT.Val[1] = GetLUT(i, 1);
      LUT.Val[2] = GetLUT(i, 2);
      LUT.Val[3] = GetLUT(i, 3);
    }
    return TotalLUT;
  }()};

  constexpr static auto DPPD_MASK {[]() consteval {
    struct alignas(16) LUTType {
      uint64_t Val[2];
    };

    std::array<LUTType, 4> TotalLUT {};
    for (size_t i = 0; i < TotalLUT.size(); ++i) {
      auto& LUT = TotalLUT[i];
      constexpr auto GetLUT = [](size_t i, size_t Index) {
        if (i & (1U << Index)) {
          return -1ULL;
        }
        return 0ULL;
      };

      LUT.Val[0] = GetLUT(i, 0);
      LUT.Val[1] = GetLUT(i, 1);
    }
    return TotalLUT;
  }()};

  constexpr static auto PBLENDW_LUT {[]() consteval {
    struct alignas(16) LUTType {
      uint16_t Val[8];
    };
    // 16-bit words in [127:112], [111:96], [95:80], [79:64], [63:48], [47:32], [31:16], [15:0] are selected using 8-bit swizzle.
    // Expectation for this LUT is to simulate PBLENDW with ARM's TBX (one register) instruction.
    // PBLENDW behaviour:
    // 16-bit words from the source is moved in to the destination based on the bit in the swizzle.
    // Dest[15:0]    = Swizzle[0] ? Src[15:0] : Dest[15:0]
    // Dest[31:16]   = Swizzle[1] ? Src[31:16] : Dest[31:16]
    // Dest[47:32]   = Swizzle[2] ? Src[47:32] : Dest[47:32]
    // Dest[63:48]   = Swizzle[3] ? Src[63:48] : Dest[63:48]
    // Dest[79:64]   = Swizzle[4] ? Src[79:64] : Dest[79:64]
    // Dest[95:80]   = Swizzle[5] ? Src[95:80] : Dest[95:80]
    // Dest[111:96]  = Swizzle[6] ? Src[111:96] : Dest[111:96]
    // Dest[127:112] = Swizzle[7] ? Src[127:112] : Dest[127:112]

    std::array<LUTType, 256> TotalLUT {};
    const uint16_t WordSelectionSrc[8] = {
      0x01'00, 0x03'02, 0x05'04, 0x07'06, 0x09'08, 0x0B'0A, 0x0D'0C, 0x0F'0E,
    };

    constexpr uint16_t OriginalDest = 0xFF'FF;

    for (size_t i = 0; i < 256; ++i) {
      auto& LUT = TotalLUT[i];
      for (size_t j = 0; j < 8; ++j) {
        LUT.Val[j] = ((i >> j) & 1) ? WordSelectionSrc[j] : OriginalDest;
      }
    }
    return TotalLUT;
  }()};

  CPUBackend::CPUBackend(CodeBufferManager& CodeBuffers, FEXCore::Core::InternalThreadState* ThreadState)
    : ThreadState(ThreadState)
    , CodeBuffers(CodeBuffers) {

    auto& Ptrs = ThreadState->CurrentFrame->Pointers;

    // Initialize named vector constants.
    for (size_t i = 0; i < FEXCore::IR::NamedVectorConstant::NAMED_VECTOR_CONST_POOL_MAX; ++i) {
      Ptrs.NamedVectorConstantPointers[i] = reinterpret_cast<uint64_t>(NamedVectorConstants[i]);
    }

    // Copy named vector constants.
    memcpy(Ptrs.NamedVectorConstants, NamedVectorConstants, sizeof(NamedVectorConstants));

    // Initialize Indexed named vector constants.
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFLW] =
      reinterpret_cast<uint64_t>(PSHUFLW_LUT.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFHW] =
      reinterpret_cast<uint64_t>(PSHUFHW_LUT.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PSHUFD] =
      reinterpret_cast<uint64_t>(PSHUFD_LUT.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_SHUFPS] =
      reinterpret_cast<uint64_t>(SHUFPS_LUT.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_DPPS_MASK] =
      reinterpret_cast<uint64_t>(DPPS_MASK.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_DPPD_MASK] =
      reinterpret_cast<uint64_t>(DPPD_MASK.data());
    Ptrs.IndexedNamedVectorConstantPointers[FEXCore::IR::IndexNamedVectorConstant::INDEXED_NAMED_VECTOR_PBLENDW] =
      reinterpret_cast<uint64_t>(PBLENDW_LUT.data());

#ifndef FEX_DISABLE_TELEMETRY
    // Fill in telemetry values. Bound is TYPE_JIT_ADDRESSABLE_LAST, not
    // TYPE_LAST: the Ptrs.TelemetryValueAddresses array is sized to the
    // JIT-addressable subrange (see CoreState.h:362 and the marker in
    // Telemetry.h). Writing past that clobbers DispatcherLoopTop et al.
    // — an OOB carry between the C5 array-resize and the C-helper-only
    // slots added above the marker.
    static_assert(sizeof(Ptrs.TelemetryValueAddresses) / sizeof(Ptrs.TelemetryValueAddresses[0]) ==
                    FEXCore::Telemetry::TYPE_JIT_ADDRESSABLE_LAST,
                  "Loop bound below must match the TelemetryValueAddresses extent; a mismatch is the cb57944a3 "
                  "dispatcher-pointer clobber. If the array grows, re-audit CoreState.h's 2*PAGE_SIZE invariant.");
    for (size_t i = 0; i < FEXCore::Telemetry::TYPE_JIT_ADDRESSABLE_LAST; ++i) {
      auto& Telem = FEXCore::Telemetry::GetTelemetryValue(static_cast<FEXCore::Telemetry::TelemetryType>(i));
      Ptrs.TelemetryValueAddresses[i] = reinterpret_cast<uint64_t>(&Telem);
    }
#endif
  }

  CPUBackend::~CPUBackend() = default;

  auto CPUBackend::GetEmptyCodeBuffer() -> CodeBuffer* {
    auto PrevCodeBuffer = CurrentCodeBuffer;

    // Resize the code buffer and reallocate our code size
    CurrentCodeBuffer = CodeBuffers.StartLargerCodeBuffer();

    RegisterForSignalHandler(std::move(PrevCodeBuffer));
    return CurrentCodeBuffer.get();
  }

  void CPUBackend::RegisterForSignalHandler(fextl::shared_ptr<CodeBuffer> CodeBuffer) {
    if (ThreadState->CurrentFrame->SignalHandlerRefCounter != 0) {
      // We have signal handlers that have generated code
      // This means that we can not safely clear the code at this point in time
      // Keep a reference to the old code buffer to delay deallocation
      SignalHandlerCodeBuffers.push_back(std::move(CodeBuffer));
    } else {
      SignalHandlerCodeBuffers.clear();
    }
  }

  fextl::shared_ptr<CodeBuffer> CPUBackend::CheckCodeBufferUpdate() {
    auto NewCodeBuffer = CodeBuffers.GetLatest();
    if (CurrentCodeBuffer != NewCodeBuffer) {
      RegisterForSignalHandler(CurrentCodeBuffer);
      return std::exchange(CurrentCodeBuffer, NewCodeBuffer);
    }
    return nullptr;
  }

  GuestToHostMap& GetLookupCache(const CodeBuffer& Buffer) {
    return *Buffer.LookupCache;
  }

  CodeBuffer::CodeBuffer(size_t Size)
    : AllocatedSize(Size) {
    Ptr = static_cast<uint8_t*>(FEXCore::Allocator::VirtualAlloc(Size, true));
    LOGMAN_THROW_A_FMT(!!Ptr, "Couldn't allocate code buffer");

    // Protect the last page of the allocated buffer to trigger SIGSEGV on write access
    uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Ptr) + Size - 1, FEXCore::Utils::FEX_PAGE_SIZE);
    if (!FEXCore::Allocator::VirtualProtect(reinterpret_cast<void*>(LastPageAddr), FEXCore::Utils::FEX_PAGE_SIZE,
                                            FEXCore::Allocator::ProtectOptions::None)) {
      LogMan::Msg::EFmt("Failed to mprotect last page of code buffer.");
    }

    FEXCore::Allocator::VirtualName("FEXMemJIT", reinterpret_cast<void*>(Ptr), Size);

    // Huge-pages reduce the amount of iTLB misses dramatically when it works.
    FEXCore::Allocator::VirtualTHPControl(reinterpret_cast<void*>(Ptr), Size, FEXCore::Allocator::THPControl::Enable);

    LookupCache = fextl::make_unique<GuestToHostMap>();
  }

  CodeBuffer::~CodeBuffer() {
    FEXCore::Allocator::VirtualFree(Ptr, AllocatedSize);
  }

  // ------------------------------------------------------------------
  // Code-buffer growth/rotation instrumentation
  // ------------------------------------------------------------------
  // Answers whether a workload's code footprint ever drives the geometric
  // buffer growth into the MAX_CODE_SIZE cap and, past it, into steady-state
  // rotation — every rotation discards all translated code, so at-cap
  // workloads pay a periodic whole-process retranslation storm. Everything
  // hangs off AllocateNew, the one funnel all CodeBuffer changes pass
  // through, so the cost in normal operation is a few counter updates per
  // buffer allocation (a session has a handful). Nothing runs per-block or
  // per-compile.

  // Relaxed atomic max; shared by the manager stats and the telemetry slots
  // (Telemetry::Value is the same std::atomic<uint64_t>).
  static void AtomicStoreMax(std::atomic<uint64_t>& Slot, uint64_t Value) {
    uint64_t Prev = Slot.load(std::memory_order_relaxed);
    while (Prev < Value && !Slot.compare_exchange_weak(Prev, Value, std::memory_order_relaxed)) {
    }
  }

#ifndef FEX_DISABLE_TELEMETRY
  // Instance reached by Telemetry::PreDumpHook (a plain function pointer, so
  // no captures). Last-constructed manager wins; in practice there is exactly
  // one per process (ContextImpl). Cleared by ~CodeBufferManager so the hook
  // can never reach a dead manager.
  static std::atomic<CodeBufferManager*> StatsInstance {nullptr};

  static void FlushStatsHook() {
    if (auto* Manager = StatsInstance.load(std::memory_order_relaxed)) {
      Manager->FlushCodeBufferTelemetry();
    }
  }
#endif

#ifndef _WIN32
  // FEX_BUFSTATS: append-only raw-fd timeline of CodeBuffer allocation
  // events, one line per event, same shape as FEX_SMC_AUDIT
  // (SyscallsSMCTracking.cpp). The telemetry slots give session totals but
  // only reach disk through Telemetry::Shutdown — a clean exit or a caught
  // fatal signal. A Proton session that gets SIGKILLed loses them, and
  // totals cannot show *when* rotations happened; this log answers both.
  // Env resolved once — an unset variable costs one getenv for the process
  // lifetime.
  static int BufStatsFD() {
    static int fd = [] {
      const char* p = getenv("FEX_BUFSTATS");
      if (!p) {
        return -1;
      }
      return ::open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }();
    return fd;
  }
#endif

  void CodeBufferManager::FlushCodeBufferTelemetry() {
#ifndef FEX_DISABLE_TELEMETRY
    // Unlocked LatestOffset read by design; see the declaration comment.
    const uint64_t LiveBytes = LatestOffset;
    FEXCORE_TELEMETRY_SET(TYPE_CODEBUFFER_TOTAL_EMITTED, StatsRetiredBytes.load(std::memory_order_relaxed) + LiveBytes);
    FEXCORE_TELEMETRY_SET(TYPE_CODEBUFFER_DISCARDED_BLOCKS, StatsRetiredBlocks.load(std::memory_order_relaxed));
    AtomicStoreMax(FEXCore::Telemetry::GetTelemetryValue(FEXCore::Telemetry::TYPE_CODEBUFFER_PEAK_LIVE),
                   std::max<uint64_t>(StatsPeakLiveBytes.load(std::memory_order_relaxed), LiveBytes));
#endif
  }

  CodeBufferManager::~CodeBufferManager() {
#ifndef FEX_DISABLE_TELEMETRY
    // Fold the final buffer in for teardown orders that destroy the Context
    // before dumping telemetry (FEXInterpreter dumps after Context teardown
    // begins on some paths; when the dump ran first this is a harmless
    // idempotent re-run), then detach so the hook can never reach a dead
    // manager. The hook itself stays installed — it null-checks StatsInstance.
    FlushCodeBufferTelemetry();
    CodeBufferManager* Expected = this;
    StatsInstance.compare_exchange_strong(Expected, nullptr, std::memory_order_relaxed);
#endif
  }

  auto CodeBufferManager::AllocateNew(size_t Size) -> fextl::shared_ptr<CodeBuffer> {
#ifndef _WIN32
// MDWE (Memory-Deny-Write-Execute) is a new Linux 6.3 feature.
// It's equivalent to systemd's `MemoryDenyWriteExecute` but implemented entirely in the kernel.
//
// MDWE prevents applications from creating RWX memory mappings.
// This prevents FEX from doing anything JIT related, as FEX uses RWX for JIT memory mappings.
//
// A potential workaround to make FEX work with MDWE is to call mprotect every time we need to write or modify code.
// Alternatively, FEX could use a memory mirror where one half is mapped as RW and the other is RX.
//
// Once MDWE is enabled with the prctl, the feature is sealed and it can /NOT/ be turned off.
//
// Status of MDWE is queried through prctl using `PR_GET_MDWE`:
// -1: The kernel doesn't support MDWE
// 0: MDWE is supported but disabled
// >0: MDWE is enabled, hence prohibiting RWX mappings
#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif
    int MDWE = ::prctl(PR_GET_MDWE, 0, 0, 0, 0);
    if (MDWE != -1 && MDWE != 0) {
      LogMan::Msg::EFmt("MDWE was set to 0x{:x} which means FEX can't allocate executable memory", MDWE);
    }
#endif

    // Growth/rotation statistics. Sample the departing buffer before Latest
    // and LatestOffset are replaced below. Reading BlockList without its lock
    // is sound on every path that has a departing buffer: once Latest is
    // non-null the only route here is GetEmptyCodeBuffer via the backends'
    // ClearCache (Arm64JITCore::ClearCache / PPC64JITCore::ClearCache), both
    // of which take the departing buffer's LookupCache write lock first.
    const uint64_t RetiredBytes = Latest ? LatestOffset : 0;
    const uint64_t RetiredBlocks = Latest ? Latest->LookupCache->BlockList.size() : 0;
    const size_t PrevSize = Latest ? Latest->AllocatedSize : 0;
    // A replacement that could not grow is a rotation; StartLargerCodeBuffer
    // only stops doubling once AllocatedSize saturates at MAX_CODE_SIZE.
    const bool Rotation = Latest && Size <= PrevSize;
    if (Latest) {
      StatsRetiredBytes.fetch_add(RetiredBytes, std::memory_order_relaxed);
      StatsRetiredBlocks.fetch_add(RetiredBlocks, std::memory_order_relaxed);
      AtomicStoreMax(StatsPeakLiveBytes, RetiredBytes);
    }
#ifndef FEX_DISABLE_TELEMETRY
    FEXCORE_TELEMETRY_INC(TYPE_CODEBUFFER_ALLOCATIONS);
    if (Rotation) {
      FEXCORE_TELEMETRY_INC(TYPE_CODEBUFFER_ROTATIONS);
    }
    AtomicStoreMax(FEXCore::Telemetry::GetTelemetryValue(FEXCore::Telemetry::TYPE_CODEBUFFER_PEAK_SIZE), Size);
    // Install the pre-dump flush so the live buffer's fill level reaches the
    // dump even in sessions that never outgrow their first buffer.
    StatsInstance.store(this, std::memory_order_relaxed);
    FEXCore::Telemetry::PreDumpHook.store(FlushStatsHook, std::memory_order_relaxed);
#endif
#ifndef _WIN32
    if (const int LogFD = BufStatsFD(); LogFD >= 0) {
      timespec Now {};
      clock_gettime(CLOCK_MONOTONIC, &Now);
      const uint64_t NowMS = static_cast<uint64_t>(Now.tv_sec) * 1000 + static_cast<uint64_t>(Now.tv_nsec) / 1000000;
      // T0 is this process's first allocation event. Each line carries the
      // pid because a Proton session is a tree of FEX processes appending to
      // the same file.
      static const uint64_t BaseMS = NowMS;
      const uint64_t Delta = NowMS - BaseMS;
      if (!Latest) {
        dprintf(LogFD, "[pid %d +%" PRIu64 ".%03" PRIu64 "s] codebuffer initial: %zu MiB\n", getpid(), Delta / 1000, Delta % 1000, Size >> 20);
      } else {
        dprintf(LogFD,
                "[pid %d +%" PRIu64 ".%03" PRIu64 "s] codebuffer %s: %zu MiB -> %zu MiB, discarding %" PRIu64 " bytes / %" PRIu64 " blocks\n",
                getpid(), Delta / 1000, Delta % 1000, Rotation ? "ROTATION" : "grow", PrevSize >> 20, Size >> 20, RetiredBytes, RetiredBlocks);
      }
    }
#endif

    auto Buffer = fextl::make_shared<CodeBuffer>(Size);

    Latest = Buffer;
    LatestOffset = 0;
    // Everything anyone cached about the previous buffer's addresses is now
    // stale; see CodeBufferGeneration.
    CodeBufferGeneration.fetch_add(1, std::memory_order_release);

#ifndef FEX_DISABLE_TELEMETRY
    // Refresh the derived totals only after the retired bytes have moved from
    // LatestOffset into StatsRetiredBytes (flushing before the reset would
    // count the departing buffer twice); keeps the slots correct if the
    // process dies before the shutdown dump runs its own flush.
    FlushCodeBufferTelemetry();
#endif

    OnCodeBufferAllocated(Buffer);

    return Buffer;
  }

  fextl::shared_ptr<CodeBuffer> CodeBufferManager::GetLatest() {
    if (!Latest) {
      if (FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
        // Start with a larger code buffer to avoid resizes that would discard
        // code loaded from caches
        AllocateNew(MAX_CODE_SIZE);
      } else {
        AllocateNew(INITIAL_CODE_SIZE);
      }
    }
    return Latest;
  }

  fextl::shared_ptr<CodeBuffer> CodeBufferManager::StartLargerCodeBuffer() {
    if (!Latest) {
      // Allocate initial CodeBuffer and return it
      return GetLatest();
    }

    auto NewCodeBufferSize = GetLatest()->AllocatedSize;
    NewCodeBufferSize = std::min<size_t>(NewCodeBufferSize * 2, MAX_CODE_SIZE);
    return AllocateNew(NewCodeBufferSize);
  }


  // ---------------------------------------------------------------------------
  // JIT auxiliary allocation (SMC store backpatching, ppc64le)
  //
  // The ppc64le SMC store backpatcher replaces a faulting host store inside a
  // code buffer with a `b` to a stub. `b` reaches +-32MiB, and the JIT's code
  // lives in a single large RWX mapping, so a fresh mmap() is useless here: an
  // address hint that lands inside that mapping is ignored by the kernel and
  // the returned address is far out of branch range. The only memory that is
  // reliably near JIT code is the code buffer itself, so hand out its free
  // tail.
  //
  // Carving a hole is invisible to block emission: PPC64JITCore rebases its
  // emitter on `Ptr + LatestOffset` at the start of every CompileCode (see
  // JIT/PPC64LE/JIT.cpp SetBuffer), so advancing LatestOffset here just means
  // the next block starts past our chunk.
  //
  // LOCKING. The caller is a SIGSEGV handler on a thread that faulted while
  // *executing* JIT code, so in practice it does not hold CodeBufferWriteMutex.
  // "In practice" is not good enough for a lock that, taken recursively,
  // deadlocks the whole process (see the CodeBufferWriteOwner comment in the
  // header), so this never blocks:
  //   - if this thread already owns the mutex, refuse. This covers the one
  //     path that could get here while compiling -- an emission overrun into
  //     the guard page -- and any future one.
  //   - otherwise try_lock, and refuse on contention rather than waiting on a
  //     compiling thread from inside a signal handler.
  // Refusal is always safe: the caller falls back to the pre-existing,
  // unpatched fault handling.
  // ---------------------------------------------------------------------------
  FEXCore::Context::JITAuxAllocation CodeBufferManager::TryAllocateAuxMemory(size_t Bytes, size_t Alignment, uint64_t NearHostPC, uint64_t MaxDelta) {
    FEXCore::Context::JITAuxAllocation Result {};
#ifdef ARCHITECTURE_ppc64le
    if (!Bytes || !Alignment || (Alignment & (Alignment - 1))) {
      return Result;
    }

    // Code caching serializes [0, LatestOffset) of the buffer and replays it
    // into a fresh mapping on the next run. Stub chunks are full of absolute
    // helper addresses and PC-relative branches to store sites, none of which
    // survive that, so refuse to mix the two features.
    if (FEXCore::Config::Get_ENABLECODECACHINGWIP()) {
      return Result;
    }

    const uint64_t SelfTID = static_cast<uint64_t>(::syscall(SYS_gettid));
    if (CodeBufferWriteOwner.load(std::memory_order_relaxed) == SelfTID) {
      return Result;
    }
    if (!CodeBufferWriteMutex.try_lock()) {
      return Result;
    }
    std::unique_lock Lock {CodeBufferWriteMutex, std::adopt_lock};
    CodeBufferWriteOwner.store(SelfTID, std::memory_order_relaxed);
    struct OwnerClear {
      std::atomic<uint64_t>& Owner;
      ~OwnerClear() {
        Owner.store(0, std::memory_order_relaxed);
      }
    } ClearOnExit {CodeBufferWriteOwner};

    // Deliberately not GetLatest(): that allocates a code buffer when none
    // exists yet, which is not something to do from a signal handler. No
    // buffer means no JIT code, so there is nothing to be near anyway.
    if (!Latest) {
      return Result;
    }

    const uint64_t Base = reinterpret_cast<uint64_t>(Latest->Ptr);
    const size_t Start = AlignUp(LatestOffset, Alignment);
    if (Start < LatestOffset || Start + Bytes < Start || Start + Bytes > Latest->UsableSize()) {
      // No headroom. Rotating the buffer from here is not an option (it frees
      // the code the faulting thread is standing in), so refuse.
      return Result;
    }

    const uint64_t Addr = Base + Start;
    if (MaxDelta) {
      const int64_t Low = static_cast<int64_t>(Addr) - static_cast<int64_t>(NearHostPC);
      const int64_t High = static_cast<int64_t>(Addr + Bytes) - static_cast<int64_t>(NearHostPC);
      if (Low < -static_cast<int64_t>(MaxDelta) || High > static_cast<int64_t>(MaxDelta)) {
        return Result;
      }
    }

    LatestOffset = Start + Bytes;

    Result.Ptr = reinterpret_cast<uint8_t*>(Addr);
    Result.BufferBase = Base;
    Result.Generation = CodeBufferGeneration.load(std::memory_order_acquire);
#else
    (void)Bytes;
    (void)Alignment;
    (void)NearHostPC;
    (void)MaxDelta;
#endif
    return Result;
  }

  bool CPUBackend::IsAddressInCodeBuffer(uintptr_t Address) const {
    auto CheckCodeBuffer = [](CodeBuffer& Buffer, uintptr_t Address) {
      // The last page of the code buffer is protected, so we need to exclude it from the valid range
      // when checking if the address is in the code buffer.
      uintptr_t LastPageAddr = AlignDown(reinterpret_cast<uintptr_t>(Buffer.Ptr) + Buffer.AllocatedSize - 1, FEXCore::Utils::FEX_PAGE_SIZE);
      return (Address >= reinterpret_cast<uintptr_t>(Buffer.Ptr) && Address < LastPageAddr);
    };

    if (CheckCodeBuffer(*CurrentCodeBuffer, Address)) {
      return true;
    }
    for (auto& Buffer : SignalHandlerCodeBuffers) {
      if (CheckCodeBuffer(*Buffer, Address)) {
        return true;
      }
    }
    return false;
  }

} // namespace CPU
} // namespace FEXCore
