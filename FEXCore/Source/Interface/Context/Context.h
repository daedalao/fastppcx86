// SPDX-License-Identifier: MIT
#pragma once

#include "Common/JitSymbols.h"
#include "Interface/Core/CPUBackend.h"
#ifdef ARCHITECTURE_ppc64le
#include "Interface/Core/JIT/PPC64LE/PPC64Dispatcher.h"
#endif
#include "Interface/Core/CPUID.h"
#include <Interface/IR/IntrusiveIRList.h>
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/unordered_map.h>
#include <FEXCore/fextl/vector.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <shared_mutex>

namespace FEXCore {
class SignalDelegator;
class ThunkHandler;
struct LookupCacheWriteLockToken;

namespace Core {
  struct DebugData;
  struct InternalThreadState;
} // namespace Core

namespace CPU {
#ifndef ARCHITECTURE_ppc64le
  class Dispatcher;
#endif
} // namespace CPU

namespace HLE {
  class SourcecodeResolver;
  class SyscallHandler;
} // namespace HLE
} // namespace FEXCore

namespace FEXCore::Context {
struct FEX_PACKED ExitFunctionLinkData {
  uint64_t HostCode;
  uint64_t GuestRIP;
  int64_t CallerOffset;
};

struct CustomIRResult {
  void* Creator;
  void* Data;

  CustomIRResult(void* Creator, void* Data)
    : Creator(Creator)
    , Data(Data) {}
};

using BlockDelinkerFunc = void (*)(FEXCore::Context::ExitFunctionLinkData* Record);
constexpr uint32_t TSC_SCALE_MAXIMUM = 1'000'000'000; ///< 1Ghz

class CodeCache : public AbstractCodeCache {
public:
  CodeCache(ContextImpl&);
  ~CodeCache();

  ContextImpl& CTX;
  fextl::unique_ptr<ContextImpl> ValidationCTX;
  fextl::unique_ptr<Core::InternalThreadState> ValidationThread;
  FEXCore::Core::CPUState::gdt_segment ValidationGDT[32] {};
  bool IsGeneratingCache = false;

  FEX_CONFIG_OPT(EnableCodeCaching, ENABLECODECACHINGWIP);
  FEX_CONFIG_OPT(EnableCodeCacheValidation, ENABLECODECACHEVALIDATION);

  uint64_t ComputeCodeMapId(std::string_view Filename, int FD) override;
  bool SaveData(Core::InternalThreadState&, int TargetFD, const ExecutableFileSectionInfo&, uint64_t SerializedBaseAddress) override;
  bool LoadData(Core::InternalThreadState*, std::byte* MappedCacheFile, size_t MappedCacheFileSize, const ExecutableFileSectionInfo&) override;

  /**
   * Performs expensive extra validation on the loaded code cache data.
   *
   * This kicks off an in-process recompile of all cached blocks and compares
   * them with the cached data. Differences will be reported as fatal errors,
   * which can uncover bugs like for example:
   * - mismatches of the JIT configuration used during cache generation
   * - hidden position dependencies due to missing FEX relocations
   * - incorrect instruction padding
   */
  void Validate(const ExecutableFileSectionInfo&, fextl::set<uint64_t> GuestBlocks, const fextl::set<uint64_t>& HostBlocks,
                std::span<std::byte> CachedCode);

  void InitiateCacheGeneration() override {
    IsGeneratingCache = true;
  }

  /**
   * Applies a set of FEX relocations to the given code section.
   *
   * FEX relocations describe runtime-dependencies of FEX-generated code.
   * When loading a code cache, they are used to move cached code to the
   * dynamically chosen base address of the guest binary.
   *
   * Conversely, relocations are applied in reverse when writing code caches
   * to ensure consistency across generation runs.
   *
   * Note that FEX relocations are unrelated to ELF/PE relocations.
   *
   * @param GuestDelta Guest address offset to apply to RIP-relative data
   * @param ForStorage True for serializing data (producing deterministic output); false for de-serializing it (resolving dynamic symbols)
   *
   * @return Returns true on success
   */
  [[nodiscard]]
  bool ApplyCodeRelocations(uint64_t GuestDelta, std::span<std::byte> Code, std::span<const CPU::Relocation> Relocations, bool ForStorage);
};

class ContextImpl final : public FEXCore::Context::Context, public CPU::CodeBufferManager {
public:
  // Context base class implementation.
  bool InitCore() override;

  void ExecuteThread(FEXCore::Core::InternalThreadState* Thread) override;

  bool CheckIfBlockIsCacheable(FEXCore::Core::InternalThreadState&, uint64_t GuestRIP, uint64_t MaxInst) override;
  void CompileRIP(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP) override;
  void CompileRIPCount(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst) override;

  void HandleCallback(FEXCore::Core::InternalThreadState* Thread, uint64_t RIP) override;

  bool IsAddressInCurrentBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t Address, uint64_t Size) override;
  bool IsCurrentBlockSingleInst(FEXCore::Core::InternalThreadState* Thread) override;
  uint64_t GetGuestBlockEntry(FEXCore::Core::InternalThreadState* Thread) override;

  uint64_t RestoreRIPFromHostPC(FEXCore::Core::InternalThreadState* Thread, uint64_t HostPC) override;
  uint32_t ReconstructCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, bool WasInJIT, const uint64_t* HostGPRs, uint64_t PSTATE) override;
  void SetFlagsFromCompactedEFLAGS(FEXCore::Core::InternalThreadState* Thread, uint32_t EFLAGS) override;

  void ReconstructXMMRegisters(const FEXCore::Core::InternalThreadState* Thread, __uint128_t* XMM_Low, __uint128_t* YMM_High) override;
  void SetXMMRegistersFromState(FEXCore::Core::InternalThreadState* Thread, const __uint128_t* XMM_Low, const __uint128_t* YMM_High) override;

  /**
   * @brief Used to create FEX thread objects in preparation for creating a true OS thread. Does set a TID or PID.
   *
   * @param InitialRIP The starting RIP of this thread
   * @param StackPointer The starting RSP of this thread
   * @param NewThreadState The initial thread state to setup for our state, if inheriting.
   *
   * @return The InternalThreadState object that tracks all of the emulated thread's state
   *
   * Usecases:
   *  Parent thread Creation:
   *    - Thread = CreateThread(InitialRIP, InitialStack, nullptr, 0);
   *    - CTX->ExecuteThread(Thread);
   *  OS thread Creation:
   *    - Thread = CreateThread(0, 0, NewState, PPID);
   *    - Thread->ExecutionThread = FEXCore::Threads::Thread::Create(ThreadHandler, Arg);
   *    - ThreadHandler calls `CTX->ExecuteThread(Thread)`
   *  OS fork (New thread created with a clone of thread state):
   *    - clone{2, 3}
   *    - Thread = CreateThread(0, 0, CopyOfThreadState, PPID);
   *    - ExecuteThread(Thread); // Starts executing without creating another host thread
   *  Thunk callback executing guest code from native host thread
   *    - Thread = CreateThread(0, 0, NewState, PPID);
   *    - HandleCallback(Thread, RIP);
   */

  FEXCore::Core::InternalThreadState* CreateThread(uint64_t InitialRIP, uint64_t StackPointer, const FEXCore::Core::CPUState* NewThreadState) override;

  /**
   * @brief Destroys this FEX thread object and stops tracking it internally
   *
   * @param Thread The internal FEX thread state object
   */
  void DestroyThread(FEXCore::Core::InternalThreadState* Thread) override;

#ifndef _WIN32
  void LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) override;
  void UnlockAfterFork(FEXCore::Core::InternalThreadState* Thread, bool Child) override;
#endif
  void SetSignalDelegator(FEXCore::SignalDelegator* SignalDelegation) override;
  void SetSyscallHandler(FEXCore::HLE::SyscallHandler* Handler) override;
  void SetThunkHandler(FEXCore::ThunkHandler* Handler) override;

  FEXCore::CPUID::FunctionResults RunCPUIDFunction(uint32_t Function, uint32_t Leaf) override;
  FEXCore::CPUID::XCRResults RunXCRFunction(uint32_t Function) override;
  FEXCore::CPUID::FunctionResults RunCPUIDFunctionName(uint32_t Function, uint32_t Leaf, uint32_t CPU) override;

  CodeCache& GetCodeCache() override {
    return CodeCache;
  }

  void SetCodeMapWriter(fextl::unique_ptr<CodeMapWriter> Writer) override {
    CodeMapWriter = std::move(Writer);
  }

  void FlushAndCloseCodeMap() override {
    if (CodeMapWriter) {
      CodeMapWriter.reset();
    }
  }

  void OnCodeBufferAllocated(const std::shared_ptr<CPU::CodeBuffer>&) override;
  void ClearCodeCache(FEXCore::Core::InternalThreadState* Thread, bool NewCodeBuffer = true) override;
  void InvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) override;
  void SoftInvalidateCodeBuffersCodeRange(uint64_t Start, uint64_t Length) override;
  void InvalidateThreadCachedCodeRange(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override;

  // SMC v3: attempts to revalidate and re-publish a soft-invalidated block for
  // this guest RIP. Returns its host code pointer on success, 0 if there is no
  // retained block or its guest bytes changed. Must be called with
  // CodeInvalidationMutex held (shared is enough; CompileBlock's lock).
  uintptr_t TryRelinkSoftInvalidatedBlock(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP);
  FEXCore::Utils::WritePriorityMutex::Mutex& GetCodeInvalidationMutex() override {
    return CodeInvalidationMutex;
  }

  void ConfigureAOTGen(FEXCore::Core::InternalThreadState* Thread, fextl::set<uint64_t>* ExternalBranches, uint64_t SectionMaxAddress) override;

  bool IsAddressInCodeBuffer(FEXCore::Core::InternalThreadState* Thread, uintptr_t Address) const override;
  bool GuestRangeOverlapsCompiledCode(FEXCore::Core::InternalThreadState* Thread, uint64_t Start, uint64_t Length) override;

  ///// Cheap compile tier for churn arenas (FEX_SMCCHEAPTIER) /////
  //
  // A runtime code arena (CP2077's scripting VM, mono, CoreCLR) overwrites the
  // same guest pages over and over -- the CP2077 SMC audit histogram showed
  // ~90 invalidations per page across thousands of pages.  Almost all of the
  // compile work spent on such a page is thrown away before it executes enough
  // to pay for itself, and a big multiblock compile is the most expensive kind
  // of work to throw away.  So: count invalidations per guest page, and once a
  // page is clearly churning, compile its blocks disposably -- a small
  // instruction cap and no multiblock formation.  Correctness is unaffected;
  // this only changes how much code a compilation is allowed to cover.
  //
  // The counters are a fixed-size direct-mapped table rather than a growable
  // map: it must be safe to bump from the invalidation path (which runs under
  // the code-invalidation write lock, but also from mmap/munmap/mprotect and
  // the SIGSEGV handler) with no allocation and no lock, and the arenas that
  // motivate this span thousands of pages, so an unbounded map would be pure
  // growth.  Two pages colliding on a slot simply steal it from each other and
  // lose their counts, which costs a heuristic miss and nothing else.
  static constexpr size_t SMCPageCounterSlots = 4096; // power of two
  struct SMCPageCounter {
    std::atomic<uint64_t> Page {0};
    std::atomic<uint32_t> Count {0};
  };
  std::array<SMCPageCounter, SMCPageCounterSlots> SMCPageCounters {};

  void RecordCodeRangeInvalidation(uint64_t Start, uint64_t Length);
  bool ShouldUseCheapTier(uint64_t GuestRIP);

  // returns false if a handler was already registered
  std::optional<CustomIRResult>
  AddCustomIREntrypoint(uintptr_t Entrypoint, CustomIREntrypointHandler Handler, void* Creator = nullptr, void* Data = nullptr);

  void AddThunkTrampolineIRHandler(uintptr_t Entrypoint, uintptr_t GuestThunkEntrypoint) override;

  void AddForceTSOInformation(const IntervalList<uint64_t>& ValidRanges, fextl::set<uint64_t>&& Instructions) override;

  void RemoveForceTSOInformation(uint64_t Address, uint64_t Size) override;

  void MarkMonoDetected() override {
    MonoDetected = true;
  }

  void MarkMonoBackpatcherBlock(uint64_t BlockEntry) override;

public:
  struct {
    uint64_t VirtualMemSize {1ULL << 36};
    uint64_t TSCScale = 0;

    // Used if the JIT needs to have its interrupt fault code emitted.
    bool NeedsPendingInterruptFaultCheck {false};

    FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
    FEX_CONFIG_OPT(SingleStepConfig, SINGLESTEP);
    FEX_CONFIG_OPT(GdbServer, GDBSERVER);
    FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
    FEX_CONFIG_OPT(TSOEnabled, TSOENABLED);
    FEX_CONFIG_OPT(LockOnlyTSO, LOCKONLYTSO);
    FEX_CONFIG_OPT(VectorTSOEnabled, VECTORTSOENABLED);
    FEX_CONFIG_OPT(MemcpySetTSOEnabled, MEMCPYSETTSOENABLED);
    FEX_CONFIG_OPT(SMCChecks, SMCCHECKS);
    FEX_CONFIG_OPT(SMCCheapTier, SMCCHEAPTIER);
    FEX_CONFIG_OPT(SMCCheapTierThreshold, SMCCHEAPTIERTHRESHOLD);
    FEX_CONFIG_OPT(SMCCheapTierMaxInst, SMCCHEAPTIERMAXINST);
    FEX_CONFIG_OPT(SMCSoftInvalidate, SMCSOFTINVALIDATE);
    FEX_CONFIG_OPT(MaxInstPerBlock, MAXINST);
    FEX_CONFIG_OPT(RootFSPath, ROOTFS);
    FEX_CONFIG_OPT(GlobalJITNaming, GLOBALJITNAMING);
    FEX_CONFIG_OPT(LibraryJITNaming, LIBRARYJITNAMING);
    FEX_CONFIG_OPT(BlockJITNaming, BLOCKJITNAMING);
    FEX_CONFIG_OPT(GDBSymbols, GDBSYMBOLS);
    FEX_CONFIG_OPT(JITOpSizeProfile, JITOPSIZEPROFILE);
    FEX_CONFIG_OPT(x87ReducedPrecision, X87REDUCEDPRECISION);
    FEX_CONFIG_OPT(DisableTelemetry, DISABLETELEMETRY);
    FEX_CONFIG_OPT(DisableVixlIndirectCalls, DISABLE_VIXL_INDIRECT_RUNTIME_CALLS);
    FEX_CONFIG_OPT(SmallTSCScale, SMALLTSCSCALE);
    FEX_CONFIG_OPT(StrictInProcessSplitLocks, STRICTINPROCESSSPLITLOCKS);
    FEX_CONFIG_OPT(MonoHacks, MONOHACKS);
  } Config;

  FEXCore::Utils::WritePriorityMutex::Mutex CodeInvalidationMutex {};

  uint32_t StrictSplitLockMutex {};

  FEXCore::HostFeatures HostFeatures;
  // CPUID depends on HostFeatures so needs to be initialized after that.
  FEXCore::CPUIDEmu CPUID;
  FEXCore::HLE::SyscallHandler* SyscallHandler {};
  FEXCore::HLE::SourcecodeResolver* SourcecodeResolver {};
  FEXCore::ThunkHandler* ThunkHandler {};
#ifdef ARCHITECTURE_ppc64le
  fextl::unique_ptr<FEXCore::CPU::PPC64Dispatcher> Dispatcher;
#else
  fextl::unique_ptr<FEXCore::CPU::Dispatcher> Dispatcher;
#endif
  CodeCache CodeCache;
  fextl::unique_ptr<CodeMapWriter> CodeMapWriter;

  SignalDelegator* SignalDelegation {};

  ContextImpl(const FEXCore::HostFeatures& Features);

  static void ThreadRemoveCodeEntryFromJit(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP);

  // This is used as a replacement for the SMC writes in the mono callsite backpatcher that avoids atomic operations
  // (safe as the invalidation mutex is locked) and manually invalidates the modified range. Allowing SMC to be detected
  // even if faulting is disabled.
  static void MonoBackpatcherWrite(FEXCore::Core::CpuStateFrame* Frame, uint8_t Size, uint64_t Address, uint64_t Value);

  void RemoveCustomIREntrypoint(FEXCore::Core::InternalThreadState* Thread, uintptr_t Entrypoint);

  struct GenerateIRResult {
    std::optional<IR::IRListView> IRView;
    uint64_t TotalInstructions;
    uint64_t TotalInstructionsLength;
    uint64_t StartAddr;
    uint64_t Length;
    bool NeedsAddGuestCodeRanges;
  };
  [[nodiscard]]
  GenerateIRResult GenerateIR(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, bool ExtendedDebugInfo, uint64_t MaxInst);

  struct CompileCodeResult {
    CPU::CPUBackend::CompiledCode CompiledCode;
    fextl::unique_ptr<FEXCore::Core::DebugData> DebugData;
    uint64_t StartAddr;
    uint64_t Length;
    bool NeedsAddGuestCodeRanges;
  };
  [[nodiscard]]
  CompileCodeResult CompileCode(FEXCore::Core::InternalThreadState* Thread, uint64_t GuestRIP, uint64_t MaxInst = 0);
  uintptr_t CompileBlock(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP, uint64_t MaxInst = 0);
  uintptr_t CompileSingleStep(FEXCore::Core::CpuStateFrame* Frame, uint64_t GuestRIP);

  FEXCore::JITSymbols Symbols;

  FEXCore::Utils::PooledAllocatorVirtual OpDispatcherAllocator {"FEXMem_OpDispatcher"};
  FEXCore::Utils::PooledAllocatorVirtual FrontendAllocator {"FEXMem_Frontend"};
  FEXCore::Utils::PooledAllocatorVirtualWithGuard CPUBackendAllocator {"FEXMem_CPUBackend"};

  // If Atomic-based TSO emulation is enabled or not.
  bool IsAtomicTSOEnabled() const {
    return AtomicTSOEmulationEnabled;
  }

  // If atomic-based TSO emulation is enabled for vector operations.
  bool IsVectorAtomicTSOEnabled() const {
    return VectorAtomicTSOEmulationEnabled;
  }

  // If atomic-based TSO emulation is enabled for memcpy operations.
  bool IsMemcpyAtomicTSOEnabled() const {
    return MemcpyAtomicTSOEmulationEnabled;
  }

  void SetHardwareTSOSupport(bool HardwareTSOSupported) override {
    SupportsHardwareTSO = HardwareTSOSupported;
    UpdateAtomicTSOEmulationConfig();
  }

  void EnableExitOnHLT() override {
    ExitOnHLT = true;
  }

  bool ExitOnHLTEnabled() const {
    return ExitOnHLT;
  }

  bool AreMonoHacksActive() const {
    return Config.MonoHacks && MonoDetected;
  }

protected:
  void UpdateAtomicTSOEmulationConfig() {
    if (SupportsHardwareTSO) {
      // If the hardware supports TSO then we don't need to emulate it through atomics.
      AtomicTSOEmulationEnabled = false;
      VectorAtomicTSOEmulationEnabled = false;
      MemcpyAtomicTSOEmulationEnabled = false;
    } else {
      AtomicTSOEmulationEnabled = Config.TSOEnabled;
      VectorAtomicTSOEmulationEnabled = Config.TSOEnabled && Config.VectorTSOEnabled;
      MemcpyAtomicTSOEmulationEnabled = Config.TSOEnabled && Config.MemcpySetTSOEnabled;
    }
  }

private:
  /**
   * @brief Initializes the JIT compilers for the thread
   *
   * @param State The internal FEX thread state object
   *
   * InitializeCompiler is called inside of CreateThread, so you likely don't need this
   */
  void InitializeCompiler(FEXCore::Core::InternalThreadState* Thread);

  bool SupportsHardwareTSO = false;
  bool AtomicTSOEmulationEnabled = true;
  bool VectorAtomicTSOEmulationEnabled = false;
  bool MemcpyAtomicTSOEmulationEnabled = false;

  bool ExitOnHLT = false;
  FEX_CONFIG_OPT(AppFilename, APP_FILENAME);

  std::shared_mutex CustomIRMutex;
  std::atomic<bool> HasCustomIRHandlers {};
  struct CustomIRHandlerEntry final {
    CustomIREntrypointHandler Handler;
    void* Creator;
    void* Data;
  };
  fextl::unordered_map<uint64_t, CustomIRHandlerEntry> CustomIRHandlers;
  IntervalList<uint64_t> ForceTSOValidRanges; // The ranges for which ForceTSOInstructions has populated data
  fextl::set<uint64_t> ForceTSOInstructions;

  bool MonoDetected = false;
  std::atomic<uint64_t> MonoBackpatcherBlock;

  std::mutex CodeBufferListLock;
  fextl::vector<std::weak_ptr<CPU::CodeBuffer>> CodeBufferList;
};
} // namespace FEXCore::Context
