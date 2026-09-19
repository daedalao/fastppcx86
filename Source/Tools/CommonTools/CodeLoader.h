// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>

#include <cstdint>
#include <unistd.h>

namespace FEX {

/**
 * @brief Code loader class so the CPU backend can load code in a generic fashion
 *
 * This class is expected to have multiple different style of code loaders
 */
class CodeLoader {
public:
  struct AuxvResult {
    uint64_t address;
    uint64_t size;
  };

  virtual ~CodeLoader() = default;

  /**
   * @brief CPU Core uses this to choose what the stack size should be for this code
   */
  virtual uint64_t StackSize() const = 0;

  /**
   * Returns the initial stack pointer
   */
  virtual uint64_t GetStackPointer() const = 0;

  /**
   * @brief Function to return the guest RIP that the code should start out at
   */
  virtual uint64_t DefaultRIP() const = 0;

  virtual fextl::vector<const char*> GetExecveArguments() const {
    return {};
  }

  virtual AuxvResult GetAuxv() const {
    return {};
  }

  // The guest's argument strings (argv[0] to the end of the last one), and
  // whether the kernel's /proc/<pid>/cmdline was pointed at them.
  struct ArgumentDataResult {
    uint64_t address;
    uint64_t size;
    bool KernelRemapped;
  };

  virtual ArgumentDataResult GetArgumentData() const {
    return {};
  }

  virtual uint64_t GetBaseOffset() const {
    return 0;
  }

  const fextl::vector<fextl::string>& GetApplicationArguments() const {
    return ApplicationArgs;
  }

protected:
  fextl::vector<fextl::string> ApplicationArgs;
};

} // namespace FEX
