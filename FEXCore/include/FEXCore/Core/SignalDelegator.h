// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstdint>
#include <csignal>

namespace FEXCore {
namespace Core {
  struct InternalThreadState;

  enum SignalNumber {
#ifndef _WIN32
    FAULT_SIGSEGV = SIGSEGV,
    FAULT_SIGTRAP = SIGTRAP,
    FAULT_SIGILL = SIGILL,
#else
    FAULT_SIGSEGV = 11,
    FAULT_SIGTRAP = 5,
    FAULT_SIGILL = 4,
#endif
  };
} // namespace Core

struct SignalDelegatorConfig {
  using SRAIndexMapping = std::array<uint8_t, 16>;

  // Dispatcher information
  uint64_t DispatcherBegin;
  uint64_t DispatcherEnd;

  // Dispatcher entrypoint.
  uint64_t AbsoluteLoopTopAddress {};
  uint64_t AbsoluteLoopTopAddressFillSRA {};

  // Signal return pointers.
  uint64_t SignalHandlerReturnAddress {};
  uint64_t SignalHandlerReturnAddressRT {};

  // Pause handlers.
  uint64_t PauseReturnInstruction {};
  uint64_t ThreadPauseHandlerAddressSpillSRA {};
  uint64_t ThreadPauseHandlerAddress {};

  // Stop handlers.
  uint64_t ThreadStopHandlerAddressSpillSRA;
  uint64_t ThreadStopHandlerAddress {};

  // SRA information.
  uint16_t SRAGPRCount;
  uint16_t SRAFPRCount;

  // SRA index mapping.
  SRAIndexMapping SRAGPRMapping;
  SRAIndexMapping SRAFPRMapping;

  // ppc64le AVX-high VSX bank (see AVXHIGH_BANK_FIRST in
  // ArchHelpers/PPC64Emitter.h): when Count is nonzero, guest YMM_hi[i] lives
  // in host VSX register vs(First+i) while the thread runs JIT code, and
  // SpillSRA must capture those from the signal frame into State.avx_high[]
  // exactly as it captures the SRA XMMs. Zero when AVX is not advertised (or
  // on hosts without the bank).
  uint16_t SRAAVXHighBankFirst {};
  uint16_t SRAAVXHighBankCount {};
};

class SignalDelegator {
public:
  virtual ~SignalDelegator() = default;

  void SetConfig(const SignalDelegatorConfig& Config) {
    this->Config = Config;
  }

  const SignalDelegatorConfig& GetConfig() const {
    return Config;
  }

  virtual uintptr_t GetThunkCallbackRET() const {
    return 0;
  }

protected:
  SignalDelegatorConfig Config;
};
} // namespace FEXCore
