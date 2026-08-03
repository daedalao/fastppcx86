// SPDX-License-Identifier: MIT
/*
$info$
category: backend ~ IR to host code generation
tags: backend|shared
$end_info$
*/

#pragma once

#include "Interface/Core/SMCSemanticPatch.h"

#include <FEXCore/Utils/CompilerDefs.h>
#include <atomic>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/fextl/memory.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXCore/fextl/map.h>

#include <cstdint>

namespace FEXCore::CPU {
union Relocation;
}

namespace FEXCore::Context {
struct JITAuxAllocation;
}

namespace FEXCore {

namespace IR {
  class IRListView;
} // namespace IR

namespace Core {
  struct DebugData;
  struct ThreadState;
  struct CpuStateFrame;
  struct InternalThreadState;
} // namespace Core

namespace CodeSerialize {
  struct CodeObjectFileSection;
}

struct GuestToHostMap;

namespace CPU {
  struct CodeBuffer {
    uint8_t* Ptr;
    size_t AllocatedSize; // including guard page; see UsableSize()

    fextl::unique_ptr<GuestToHostMap> LookupCache;

    CodeBuffer(size_t Size);
    CodeBuffer(const CodeBuffer&) = delete;
    CodeBuffer& operator=(const CodeBuffer&) = delete;
    CodeBuffer(CodeBuffer&& oth) = delete;
    CodeBuffer& operator=(CodeBuffer&&) = delete;

    ~CodeBuffer();

    /// Returns the number of bytes available for storing code
    size_t UsableSize() const {
      return AllocatedSize - FEXCore::Utils::FEX_PAGE_SIZE;
    }
  };

  /**
   * A manager that coordinates access to the CodeBuffer used for compiling new code across threads.
   *
   * The CodeBuffer is managed as a partially persistent data structure:
   * - Exactly one CodeBuffer is now designated as "active", which means data can be appended to it
   * - Lossy modifications to the active CodeBuffer will not invalidate any data in use by other threads (which is what enables save CodeBuffer sharing across threads)
   * - Instead, such lossy modifications trigger a new "version" of the data in the modifying thread. Old versions of the CodeBuffer persist as read-only data for use by the other threads.
   * - The other threads can update their version of the CodeBuffer. This will decrease the reference count and eventually trigger deallocation of the old version
   */
  class CodeBufferManager {
  public:
    // Get the CodeBuffer that was most recently allocated.
    // This is the only CodeBuffer that data may be written to.
    fextl::shared_ptr<CodeBuffer> GetLatest();

    // Allocate a new CodeBuffer with geometric growth up to an internal maximum.
    // Subsequent calls to GetLatest will point to the returned buffer.
    fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

    // Write offset into the latest CodeBuffer
    std::size_t LatestOffset {};

    // Protects writes to the latest CodeBuffer and changes to LatestOffset
    FEXCore::ForkableUniqueMutex CodeBufferWriteMutex;

    // TID of the thread currently holding CodeBufferWriteMutex, 0 when free.
    // CodeBufferWriteMutex is non-recursive, so a thread that re-enters while
    // already holding it deadlocks against itself.  On PPC64LE this is a live
    // hazard because the backend emits directly into the shared CurrentCodeBuffer
    // and holds the lock across the whole emission window (arm64 stages into a
    // per-thread TempCodeBuffer instead), so any control-flow escape from that
    // window leaves the mutex held forever.  Track the owner so the re-entry can
    // be detected and reported instead of silently hanging every thread.
    std::atomic<uint64_t> CodeBufferWriteOwner {0};

    // Monotonic id of `Latest`, bumped by AllocateNew. Anything cached by
    // address inside a code buffer (SMC backpatch stub pools, for instance) is
    // invalidated by a change here: the previous buffer can be freed once the
    // last shared_ptr to it drops, and its address range reused.
    std::atomic<uint64_t> CodeBufferGeneration {1};

    // Carve `Bytes` of the latest code buffer's free tail out for non-block
    // use. See FEXCore::Context::Context::AllocateJITAuxMemory for the full
    // contract; this is the implementation and does the actual locking.
    FEXCore::Context::JITAuxAllocation TryAllocateAuxMemory(size_t Bytes, size_t Alignment, uint64_t NearHostPC, uint64_t MaxDelta);

    virtual void OnCodeBufferAllocated(const std::shared_ptr<CodeBuffer>&) {};

    // Folds the live buffer's fill level into the code-buffer telemetry slots.
    // TOTAL_EMITTED/PEAK_LIVE are otherwise only updated when a buffer
    // retires, so a session that never outgrew its first buffer would dump
    // zeros. Idempotent (SET/max semantics, no accumulation), installed as
    // Telemetry::PreDumpHook by AllocateNew and re-run from the destructor.
    // Reads LatestOffset without CodeBufferWriteMutex: the fatal-signal dump
    // path can run this mid-compile, and a torn value only skews a statistic
    // — no safety property rests on it.
    void FlushCodeBufferTelemetry();

    ~CodeBufferManager();

  private:
    fextl::shared_ptr<CodeBuffer> Latest;

    fextl::shared_ptr<CodeBuffer> AllocateNew(size_t Size);

    // Code-buffer growth/rotation statistics (instrumentation only; see the
    // block in AllocateNew). Written at buffer-allocation events, which are
    // rare — a handful per session. Atomics because FlushCodeBufferTelemetry
    // can read them from the fatal-signal telemetry path on another thread.
    std::atomic<uint64_t> StatsRetiredBytes {};
    std::atomic<uint64_t> StatsRetiredBlocks {};
    std::atomic<uint64_t> StatsPeakLiveBytes {};
  };

  class CPUBackend {
  public:

    CPUBackend(CodeBufferManager&, FEXCore::Core::InternalThreadState*);

    virtual ~CPUBackend();

    struct CompiledCode {
      // Where this code block begins.
      uint8_t* BlockBegin;
      fextl::map<uint64_t, uint8_t*> EntryPoints;
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;

      // SMC Idea 4 (FEX_SMCSEMANTICPATCH): host addresses of the fixed-width
      // guest-RIP materialisation windows this block's ExitFunctions emitted
      // for compile-time-constant destinations. Populated by the PPC64LE
      // backend only, and only when the flag is on; empty otherwise, which
      // makes the block ineligible for semantic patching.
      // See Interface/Core/SMCSemanticPatch.h.
      FEXCore::SMC::ExitRIPSites ExitRIPSites;

      // SMC Idea 4, mov-immediate half: the fixed-width windows this block
      // materialised its tagged guest immediates into, each carrying the index
      // of the MovImmSite it came from. Same population rules as above.
      FEXCore::SMC::MovImmWindows MovImmWindows;
    };

    // Header that can live at the start of a JIT block.
    // We want the header to be quite small, with most data living in the tail object.
    struct JITCodeHeader {
      // Offset from the start of this header to where the tail lives.
      // Only 32-bit since the tail block won't ever be more than 4GB away.
      uint32_t OffsetToBlockTail;
    };

    // Header that can live at the end of the JIT block.
    // For any state reconstruction or other data, this is where it should live.
    // Any data that is explicitly tied to the JIT code and needs to be cached with it
    // should end up in this data structure.
    struct JITCodeTail {
      // The total size of the codeblock from [BlockBegin, BlockBegin+Size).
      size_t Size;

      // RIP that the block's entry comes from.
      uint64_t RIP;

      // The length of the guest code for this block.
      size_t GuestSize;

      // Number of RIP entries for this JIT Code section.
      uint32_t NumberOfRIPEntries;

      // Offset after this block to the start of the RIP entries.
      uint32_t OffsetToRIPEntries;

      // Shared-code modification spin-loop futex.
      uint32_t SpinLockFutex;

      // If this block represents a single guest instruction.
      bool SingleInst;

      uint8_t _Pad[3];
    };

    /**
     * @brief Tells this CPUBackend to compile code for the provided IR and DebugData
     *
     * The returned pointer needs to be long lived and be executable in the host environment
     * FEXCore's frontend will store this pointer in to a cache for the current RIP when this was executed
     *
     * This is a thread specific compilation unit since there is one CPUBackend per guest thread
     *
     * @param Size - The byte size of the guest code for this block
     * @param SingleInst - If this block represents a single guest instruction
     * @param IR -  IR that maps to the IR for this RIP
     * @param DebugData - Debug data that is available for this IR indirectly
     * @param CheckTF - If EFLAGS.TF checks should be emitted at the start of the block
     *
     * @return Information about the compiled code block.
     */
    [[nodiscard]]
    virtual CompiledCode CompileCode(uint64_t Entry, uint64_t Size, bool SingleInst, const FEXCore::IR::IRListView* IR,
                                     FEXCore::Core::DebugData* DebugData, bool CheckTF) = 0;

    virtual fextl::vector<FEXCore::CPU::Relocation> TakeRelocations(uint64_t GuestBaseAddress) = 0;

    virtual void ClearCache() {}

    /**
     * @brief Clear any relocations after JIT compiling
     */
    virtual void ClearRelocations() {}

    bool IsAddressInCodeBuffer(uintptr_t Address) const;

    // Updates the CodeBuffer if needed and returns a reference to the old one.
    // The returned reference should be kept alive carefully to avoid early deletion of resources.
    [[nodiscard]]
    fextl::shared_ptr<CodeBuffer> CheckCodeBufferUpdate();

  protected:
    // Max spill slot size in bytes. We need at most 32 bytes
    // to be able to handle a 256-bit vector store to a slot.
    constexpr static uint32_t MaxSpillSlotSize = 32;

    FEXCore::Core::InternalThreadState* ThreadState;

    [[nodiscard]]
    CodeBuffer* GetEmptyCodeBuffer();

    // This is the code buffer containing the main code under execution by this thread.
    // CheckCodeBufferUpdate must be used before compiling new code.
    fextl::shared_ptr<CodeBuffer> CurrentCodeBuffer;

    // Old CodeBuffer generations required to be valid until returning from signal handlers
    fextl::vector<fextl::shared_ptr<CodeBuffer>> SignalHandlerCodeBuffers;

    CodeBufferManager& CodeBuffers;

  private:
    void RegisterForSignalHandler(fextl::shared_ptr<CodeBuffer>);
  };

} // namespace CPU
} // namespace FEXCore
