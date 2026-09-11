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
  // Header that can live at the start of a JIT block.
  // We want the header to be quite small, with most data living in the tail object.
  //
  // Defined at namespace scope (rather than nested in CPUBackend as it used to
  // be) so that CodeBuffer, which is declared before CPUBackend, can name it in
  // its block-index accessors. CPUBackend keeps `using` aliases for both, so
  // the `CPUBackend::JITCodeHeader` spelling used throughout the tree is
  // unchanged.
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
    /// HOST: the trailing guard page is one host page (mprotect granularity), so on a
    /// 64K kernel the buffer gives up 64K rather than 4K. The allocation size itself is
    /// deliberately NOT grown: it keeps its power-of-two shape (the near-branch
    /// placement logic reasons about buffer extents) and 4K behaviour is bit-identical.
    size_t UsableSize() const {
      return AllocatedSize - FEXCore::HostPage::Size();
    }

    // ----------------------------------------------------------------------
    // Per-buffer block index (audit P1)
    // ----------------------------------------------------------------------
    // Maps a host PC back to the JITCodeHeader of the block containing it,
    // without the JIT publishing anything at run time. This replaces the old
    // scheme where every EntryPoint prologue stored its own header address
    // into CpuStateFrame::State.InlineJITBlockHeader (5 instructions on every
    // block entry, ppc64le); see FEX_NOBLOCKHEADER in the PPC64LE backend.
    //
    // Ownership/lifetime: the index belongs to *this* CodeBuffer, so
    // ClearCache and code-buffer rotation (CPUBackend::GetEmptyCodeBuffer ->
    // CodeBufferManager::StartLargerCodeBuffer -> a brand new CodeBuffer)
    // reset it implicitly — a rotated-away buffer keeps its own, still-correct
    // index for as long as some thread holds a shared_ptr to it (the
    // SignalHandlerCodeBuffers list). CodeBufferGeneration semantics are
    // unchanged; nothing here is keyed by generation.
    //
    // Concurrency: single writer (AppendBlock is only ever called with
    // CodeBufferManager::CodeBufferWriteMutex held), many lock-free readers.
    // Readers publish/consume through BlockCount with release/acquire, so a
    // reader either does not see a block at all or sees a fully written
    // BlockOffsets entry *and* the fully written header/tail it points at.

    // Block start offsets relative to Ptr, strictly ascending.
    // VirtualAlloc'd (mmap) rather than new[]: capacity is sized off the
    // buffer maximum (1 GiB by default via FEX_CODEBUFFERMAXSIZE => 64 MiB of
    // index) and the pages are only ever faulted in as blocks are appended.
    uint32_t* BlockOffsets {};

    // Number of valid entries in BlockOffsets. Release-stored by the writer,
    // acquire-loaded by readers.
    std::atomic<uint32_t> BlockCount {0};

    // UsableSize() / MinimumBlockSize + 1. A block is at least
    // MinimumBlockSize bytes, so this can never be exceeded.
    uint32_t BlockCapacity {};

    // Smallest possible block span: a 4-byte JITCodeHeader plus code rounded
    // up to 16, plus a 40-byte JITCodeTail plus its RIP entries rounded up to
    // 16 (PPC64LE JIT.cpp, Tail->Size = CodeSize + TailAndEntriesAligned).
    // 16 (code) + 48 (tail) = 64.
    static constexpr size_t MinimumBlockSize = 64;

    // Byte size of the BlockOffsets mapping; must be identical at
    // VirtualAlloc and VirtualFree time (BlockCapacity is fixed after
    // construction, so recomputing is exact).
    size_t BlockIndexBytes() const {
      return static_cast<size_t>(BlockCapacity) * sizeof(uint32_t);
    }

    // Appends a block to the index.
    //
    // MUST be called at the very end of CompileCode, while
    // CodeBufferManager::CodeBufferWriteMutex is held, and only AFTER both the
    // JITCodeHeader at Ptr+BlockOffset (its OffsetToBlockTail) and the
    // JITCodeTail (its Size) have been fully written — a reader that observes
    // the published count immediately dereferences both.
    void AppendBlock(uint32_t BlockOffset);

    // Maps a host PC to the JITCodeHeader of the block containing it, or
    // nullptr when the PC is outside this buffer or lands in no block (aux SMC
    // stub allocations and the buffer's free tail are the two live cases).
    //
    // ASYNC-SIGNAL-SAFE: no locks, no allocation, no logging, no fmt. It is
    // reached from SIGSEGV/SIGBUS handlers via ContextImpl::RestoreRIPFromHostPC.
    const JITCodeHeader* FindBlockHeader(uintptr_t HostPC) const;

    // Rebuilds the index by walking the block chain in
    // [StartOffset, StartOffset + Bytes), which must be a contiguous run of
    // header/tail-delimited blocks. Used for regions that arrive by memcpy
    // rather than through CompileCode (the code-cache loader, CodeCache.cpp).
    //
    // StartOffset == 0 resets the index first (the fresh-buffer form the
    // design calls for). A non-zero StartOffset *appends*, because every block
    // below it was already registered by AppendBlock and the loader always
    // places the cached image at the current (page-aligned) LatestOffset,
    // which is above every existing block.
    //
    // Caller must hold CodeBufferWriteMutex (same single-writer rule as
    // AppendBlock). Stops, with one EFmt, on the first structural
    // inconsistency rather than trusting file-controlled bytes.
    void RebuildBlockIndexByWalk(size_t Bytes, size_t StartOffset = 0);
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

    // Allocate a new CodeBuffer with geometric growth up to the configured maximum.
    // Subsequent calls to GetLatest will point to the returned buffer.
    fextl::shared_ptr<CodeBuffer> StartLargerCodeBuffer();

    // FEX_CODEBUFFERMAXSIZE / FEX_CODEBUFFERINITIALSIZE in bytes (see CPUBackend.cpp).
    static size_t ConfiguredMaxSize();
    static size_t ConfiguredInitialSize();

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

    // The block header/tail live at namespace scope (see above) so CodeBuffer
    // can name them; these aliases keep every `CPUBackend::JITCodeHeader` /
    // `CPUBackend::JITCodeTail` spelling in the tree working unchanged.
    using JITCodeHeader = FEXCore::CPU::JITCodeHeader;
    using JITCodeTail = FEXCore::CPU::JITCodeTail;

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

    // Maps a host PC to the JITCodeHeader of the block containing it, across
    // every code buffer this thread can still be executing in: the current one
    // plus the rotated-away buffers pinned by SignalHandlerCodeBuffers. Same
    // iteration (and the same lifetime argument) as IsAddressInCodeBuffer —
    // this thread's own shared_ptrs keep those buffers alive even if another
    // thread rotates the manager's Latest out from under it.
    //
    // ASYNC-SIGNAL-SAFE. Returns nullptr when the PC is in no block.
    const JITCodeHeader* FindBlockHeader(uintptr_t HostPC) const;

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
