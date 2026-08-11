// SPDX-License-Identifier: MIT
#pragma once
#include <atomic>
#include <cstdint>
#include <optional>

#include <FEXCore/Core/CodeCache.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/fextl/string.h>

namespace FEXCore::Context {
class Context;
}

namespace FEXCore::Core {
struct InternalThreadState;
struct CpuStateFrame;
} // namespace FEXCore::Core

namespace FEXCore::HLE {
struct SyscallArguments {
  static constexpr std::size_t MAX_ARGS = 7;
  uint64_t Argument[MAX_ARGS];
};

struct SyscallABI {
  // Expectation is that the backend will be aware of how to modify the arguments based on numbering
  // Only GPRs expected
  uint8_t NumArgs;
  // If the syscall has a return then it should be stored in the ABI specific syscall register
  // Linux = RAX
  bool HasReturn;

  int32_t HostSyscallNumber;
};

enum class SyscallOSABI {
  OS_UNKNOWN,
  OS_LINUX64,
  OS_LINUX32,
  OS_GENERIC, // No JIT-side argument handling, spill/fill all regs.
};

struct ExecutableRangeInfo {
  uint64_t Base;
  uint64_t Size;
  bool Writable;
};

class SyscallHandler;
class SourcecodeResolver;

class SyscallHandler {
public:
  virtual ~SyscallHandler() = default;

  virtual uint64_t HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) = 0;

  SyscallOSABI GetOSABI() const {
    return OSABI;
  }
  virtual void MarkGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  virtual void InvalidateGuestCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) {}
  virtual void MarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual void UnmarkOvercommitRange(uint64_t Start, uint64_t Length) {}
  virtual ExecutableRangeInfo QueryGuestExecutableRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Address) = 0;
  virtual std::optional<ExecutableFileSectionInfo> LookupExecutableFileSection(Core::InternalThreadState* Thread, uint64_t GuestAddr) = 0;

  // Fallback naming for executable code in mappings LookupExecutableFileSection
  // cannot attribute: anonymous memory holding a manually-loaded image. Wine
  // loads the MAIN PE image this way (anonymous reserve + copy-in), so without
  // this every sample in a Windows game's own engine code profiles as
  // [unknown] — ~90% of a Witcher 3 in-world capture. Returns a stable,
  // interned, human-readable label (e.g. "PE:witcher3.exe@0x140000000") or
  // nullptr when the address isn't in a recognizable image. The pointer stays
  // valid for the process lifetime; the label may go stale if the guest unmaps
  // the image and loads something else at the same base — acceptable for its
  // only consumer, profile symbol naming.
  virtual const char* LookupAnonymousExecImageName(Core::InternalThreadState* Thread, uint64_t GuestAddr) {
    return nullptr;
  }

  virtual void PreCompile() {}

  // FEX_SMCLAZYINVAL: with lazy SMC invalidation the SMC fault handler only
  // records dirtied guest code pages; the soft-invalidation itself happens at
  // the next "drain point", and a thread that is about to run code it doesn't
  // already have cached is one of them (ContextImpl::CompileBlock).
  //
  // The frontend owns the dirty set, so it publishes a pointer to its atomic
  // count here when -- and only when -- the option is active.  A null pointer
  // is the whole cost of the feature when it is off: one predictable load and
  // a not-taken branch per CompileBlock, no virtual call.  Never dereference
  // this without checking it; never call the drain with any code-invalidation
  // lock held (the drain takes the exclusive side of CodeInvalidationMutex and
  // force-releases pending shared locks to do it).
  // See Source/Tools/LinuxEmulation/LinuxSyscalls/SMCLazyInvalidate.h.
  std::atomic<uint64_t>* LazySMCDirtyCount {nullptr};
  virtual void DrainLazySMCInvalidations(FEXCore::Core::InternalThreadState* Thread) {}

  virtual SourcecodeResolver* GetSourcecodeResolver() {
    return nullptr;
  }

  virtual void SleepThread(FEXCore::Context::Context* CTX, FEXCore::Core::CpuStateFrame* Frame) {}

protected:
  SyscallOSABI OSABI;
};
} // namespace FEXCore::HLE
