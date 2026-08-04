// SPDX-License-Identifier: MIT
#include <FEXCore/Utils/SpinWaitLock.h>

#include <Interface/Context/Context.h>
#ifndef ARCHITECTURE_ppc64le
#include <Interface/Core/ArchHelpers/Arm64Emitter.h>
#include <Interface/Core/Dispatcher/Dispatcher.h>
#endif
#include <Interface/Core/JIT/DebugData.h>
#include <Interface/Core/JIT/Relocations.h>
#include <Interface/Core/LookupCache.h>
#include <Interface/Core/OpcodeDispatcher.h>
#include <Interface/IR/PassManager.h>

#include <FEXCore/Core/Thunks.h>
#include <FEXCore/HLE/SourcecodeResolver.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <FEXHeaderUtils/Filesystem.h>

#include <git_version.h>

#include <xxhash.h>

// ComputeCodeMapId streams the mapped file to derive a content-based cache
// identity. close() was already used unguarded in this file, so POSIX is
// assumed here rather than newly introduced.
#include <array>
#include <cerrno>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>

namespace FEXCore {

#if __clang_major__ < 16
ExecutableFileInfo::ExecutableFileInfo(fextl::unique_ptr<HLE::SourcecodeMap> Map, uint64_t FileId, fextl::string Filename)
  : SourcecodeMap(std::move(Map))
  , FileId(FileId)
  , Filename(Filename) {}
#endif
ExecutableFileInfo::~ExecutableFileInfo() = default;

fextl::string CodeMap::GetBaseFilename(const ExecutableFileInfo& MainExecutable, bool AddNombSuffix) {
  auto FileId = MainExecutable.FileId;

  std::string_view base_filename = FHU::Filesystem::GetFilename(std::string_view {MainExecutable.Filename});
  if (FileId != 0xffff'ffff'ffff'ffff) {
    return fextl::fmt::format("{}-{:016x}{}", base_filename, MainExecutable.FileId, AddNombSuffix ? "-nomb" : "");
  }

  return "";
}

fextl::map<CodeMapFileId, CodeMap::ParsedContents> CodeMap::ParseCodeMap(std::ifstream& File) {
  fextl::map<CodeMapFileId, CodeMap::ParsedContents> Ret;
  while (true) {
    Entry Entry;
    File.read(reinterpret_cast<char*>(&Entry), sizeof(Entry));
    if (!File) {
      break;
    }

    if (Entry.FileId == LoadExternalLibrary.FileId && Entry.BlockOffset == LoadExternalLibrary.BlockOffset) {
      ExternalLibraryInfo Info;
      File.read(reinterpret_cast<char*>(&Info), sizeof(Info));

      fextl::string Filename;
      std::getline(File, Filename, '\0');

      // Align to 4-byte boundary
      char Null[4];
      File.read(Null, AlignUp(Filename.size() + 1, 4) - Filename.size() - 1);
      if (!File) {
        break;
      }
      Ret[Info.ExternalFileId].Filename = std::move(Filename);
    } else if (Entry.FileId == SetExecutableFileId {}.Marker.FileId && Entry.BlockOffset == SetExecutableFileId {}.Marker.BlockOffset) {
      CodeMapFileId ExecutableFileId;
      File.read(reinterpret_cast<char*>(&ExecutableFileId), sizeof(ExecutableFileId));
      if (!File) {
        break;
      }
      Ret[ExecutableFileId].IsExecutable = true;
    } else {
      if (!Ret.contains(Entry.FileId)) {
        LogMan::Msg::EFmt("Code map referenced unknown file id {:016x}", Entry.FileId);
      } else {
        Ret[Entry.FileId].Blocks.insert(Entry.BlockOffset);
      }
    }

    if (!File) {
      break;
    }
  }
  return Ret;
}

CodeMapWriter::CodeMapWriter(CodeMapOpener& Opener, bool OpenEagerly)
  : Buffer(4096)
  , FileOpener(Opener) {
  if (OpenEagerly) {
    CodeMapFD = FileOpener.OpenCodeMapFile();
  }
}

CodeMapWriter::~CodeMapWriter() {
  if (CodeMapFD.value_or(-1) != -1) {
    Flush(BufferOffset);
    close(*CodeMapFD);
  }
}

bool CodeMapWriter::IsWriteEnabled(const ExecutableFileSectionInfo& Section) {
  if (CodeMapFD == -1) {
    return false;
  }

  // PV libraries can't yet be read by FEXServer, so skip dumping them
  if (Section.FileInfo.Filename.starts_with("/run/pressure-vessel")) {
    return false;
  }

  if (CodeMapFD) {
    return true;
  }

  // Acquire mutex and re-check CodeMapFD to avoid race conditions
  auto lk = std::unique_lock {Mutex};
  if (!CodeMapFD) {
    CodeMapFD = FileOpener.OpenCodeMapFile();
  }

  return CodeMapFD != -1;
}

void CodeMapWriter::Flush(size_t Offset) {
  // Acquire exclusive lock and flush circular buffer
  std::unique_lock Lock {Mutex};
  Flush(Offset, Lock);
}

void CodeMapWriter::Flush(size_t Offset, std::unique_lock<std::shared_mutex>&) {
  write(*CodeMapFD, Buffer.data(), Offset);
  BufferOffset = 0;
}

void CodeMapWriter::AppendBlock(const FEXCore::ExecutableFileSectionInfo& SectionInfo, uint64_t BlockEntry) {
  if (!IsWriteEnabled(SectionInfo)) {
    return;
  }

  BlockEntry -= SectionInfo.FileStartVA;
  if (BlockEntry > std::numeric_limits<uint32_t>::max()) {
    ERROR_AND_DIE_FMT("Cannot write code map");
  }

  // Register new library if not already known
  bool NewLibraryLoad = false;
  {
    // Check prior registration with shared lock
    std::shared_lock Lock {Mutex};
    NewLibraryLoad = !KnownFileIds.contains(SectionInfo.FileInfo.FileId);
  }
  if (NewLibraryLoad) {
    // Register to map with exclusive lock
    std::unique_lock Lock {Mutex};
    NewLibraryLoad &= KnownFileIds.insert(SectionInfo.FileInfo.FileId).second;
  }
  if (NewLibraryLoad) {
    // Add entry to code map
    AppendLibraryLoad(SectionInfo.FileInfo);
  }

  // Register the actual code block
  CodeMap::Entry DataEntry {SectionInfo.FileInfo.FileId, static_cast<uint32_t>(BlockEntry)};
  AppendData(std::as_bytes(std::span {&DataEntry, 1}));
}

void CodeMapWriter::AppendLibraryLoad(const FEXCore::ExecutableFileInfo& FileInfo) {
  // See CodeMap::ExternalLibraryInfo
  auto ExternalFileId = FileInfo.FileId;
  auto TotalSize = AlignUp(sizeof(CodeMap::LoadExternalLibrary) + sizeof(ExternalFileId) + FileInfo.Filename.size() + 1, 4);
  const auto Data = reinterpret_cast<char*>(alloca(TotalSize));
  auto WritePtr = std::copy_n(reinterpret_cast<const char*>(&CodeMap::LoadExternalLibrary), sizeof(CodeMap::LoadExternalLibrary), Data);
  WritePtr = std::copy_n(reinterpret_cast<const char*>(&ExternalFileId), sizeof(ExternalFileId), WritePtr);
  WritePtr = std::copy(FileInfo.Filename.begin(), FileInfo.Filename.end(), WritePtr);
  std::fill(WritePtr, Data + TotalSize, 0);
  AppendData(std::as_bytes(std::span {Data, TotalSize}));
}

void CodeMapWriter::AppendSetMainExecutable(const FEXCore::ExecutableFileInfo& FileInfo) {
  CodeMap::SetExecutableFileId Data {.ExecutableFileId = FileInfo.FileId};
  AppendData(std::span {reinterpret_cast<const std::byte*>(&Data), sizeof(Data)});
}

void CodeMapWriter::AppendData(std::span<const std::byte> Data) {
  std::shared_lock Lock {Mutex};
  auto Offset = BufferOffset.fetch_add(Data.size_bytes());
  if (Offset + Data.size_bytes() > Buffer.size()) {
    // Acquire exclusive lock and flush the buffer.
    // Under heavy pressure, multiple threads may observe an exhausted buffer simultaneously.
    // The thread with the last in-bounds Offset is responsible for flushing the buffer.
    Lock.unlock();
    bool IsResponsibleForFlush = false;
    {
      std::unique_lock ExclusiveLock {Mutex};
      IsResponsibleForFlush = (Offset <= Buffer.size());
      if (IsResponsibleForFlush) {
        Flush(Offset, ExclusiveLock);
      }
    }
    if (!IsResponsibleForFlush) {
      // Wait for the buffer to be flushed on the responsible thread
      Utils::SpinWaitLock::WaitPred<std::less_equal<>, size_t>(reinterpret_cast<size_t*>(&BufferOffset), Buffer.size());
    }
    AppendData(Data);
    return;
  }

  memcpy(&Buffer.at(Offset), Data.data(), Data.size_bytes());
}

} // namespace FEXCore

namespace FEXCore::Context {

CodeCache::CodeCache(ContextImpl& CTX_)
  : CTX(CTX_) {
  // B5: two properties of EnableCodeCacheValidation that no amount of code can
  // fix, and that both cost time to rediscover from a confusing result.
  //
  // Once per process, not once per section: LoadData runs per executable
  // section, and a validation context constructs a second CodeCache of its own.
  if (EnableCodeCacheValidation) {
    static std::once_flag WarnOnce;
    std::call_once(WarnOnce, []() {
      LogMan::Msg::EFmt("EnableCodeCacheValidation is set. Two things it does NOT mean:");
      LogMan::Msg::EFmt("  1. A pass does not say the cached code matches what a production run emits. The reference compile decodes with "
                        "the same section bounds and guest relocations the cache was generated with, so it compares cache-mode bytes "
                        "against cache-mode bytes. It catches JIT-config drift and missing FEX relocations, not differences between "
                        "cached and uncached codegen.");
      LogMan::Msg::EFmt("  2. It is not observation-only. This flag also puts the main thread's own decoding on the section-bounded, "
                        "relocation-aware path (Frontend.cpp), so it changes the code under test. A bug that reproduces only with it on, "
                        "or only with it off, is the flag doing its job, not a paradox.");
    });
  }
}
CodeCache::~CodeCache() = default;

uint64_t CodeCache::ComputeCodeMapId(std::string_view Filename, int FD) {
  if (Filename.empty()) {
    return 0xffff'ffff'ffff'ffff;
  }

  // Identity is derived from the file's CONTENT, never from its path.
  //
  // Keying on the path was a silent stale-code bug once the cache is enabled:
  // rebuild a binary, or let a game updater replace it, and the new file at the
  // same path loads the OLD file's cached translations — executing host code
  // compiled from guest bytes that no longer exist, persisted across restarts.
  // It also failed in the other direction, giving one binary two unrelated
  // caches when installed at two paths, which is what the original TODO here
  // asked to avoid ("independent of the installation location").
  //
  // The Windows path already keys on image identity rather than the name
  // (Source/Windows/Common/ImageTracker.cpp folds in TimeDateStamp and
  // SizeOfImage); this brings the Linux path to the same standard.
  //
  // Cost is one streamed hash per mapped executable file, once, at mmap time.
  // pread() throughout: FD is the descriptor the caller is mapping from, so its
  // file offset must not move.
  auto FallbackId = [&]() -> uint64_t {
    // Degrade to path+size+mtime rather than bare path. Strictly stronger than
    // the old behaviour, and any disagreement with the content hash costs a
    // cache miss (safe) rather than a stale hit (not).
    XXH3_state_t* S = XXH3_createState();
    if (!S) {
      return XXH3_64bits(Filename.data(), Filename.size());
    }
    XXH3_64bits_reset(S);
    XXH3_64bits_update(S, Filename.data(), Filename.size());
    struct stat St;
    if (FD >= 0 && ::fstat(FD, &St) == 0) {
      const uint64_t Size = static_cast<uint64_t>(St.st_size);
      const uint64_t MTime = static_cast<uint64_t>(St.st_mtime);
      XXH3_64bits_update(S, &Size, sizeof(Size));
      XXH3_64bits_update(S, &MTime, sizeof(MTime));
    }
    const uint64_t R = XXH3_64bits_digest(S);
    XXH3_freeState(S);
    return R;
  };

  struct stat Stat;
  if (FD < 0 || ::fstat(FD, &Stat) != 0 || !S_ISREG(Stat.st_mode)) {
    return FallbackId();
  }

  XXH3_state_t* State = XXH3_createState();
  if (!State) {
    return FallbackId();
  }
  XXH3_64bits_reset(State);

  // Fold the length in first so a truncated file can never hash equal to the
  // longer original that shares its prefix.
  const uint64_t FileSize = static_cast<uint64_t>(Stat.st_size);
  XXH3_64bits_update(State, &FileSize, sizeof(FileSize));

  std::array<uint8_t, 64 * 1024> Buffer;
  off_t Offset = 0;
  while (Offset < Stat.st_size) {
    const ssize_t BytesRead = ::pread(FD, Buffer.data(), Buffer.size(), Offset);
    if (BytesRead > 0) {
      XXH3_64bits_update(State, Buffer.data(), static_cast<size_t>(BytesRead));
      Offset += BytesRead;
      continue;
    }
    if (BytesRead < 0 && errno == EINTR) {
      continue;
    }
    // Short read or hard error: the content hash would be over a partial file
    // and is not trustworthy as an identity. Degrade rather than guess.
    XXH3_freeState(State);
    return FallbackId();
  }

  const uint64_t Result = XXH3_64bits_digest(State);
  XXH3_freeState(State);
  return Result;
}

struct CodeCacheHeader {
  std::array<char, 4> Magic = ExpectedMagic;
  // Bump on any on-disk layout change so stale caches are rejected rather
  // than misread. Bumped from 1 -> 2 by S3 (BlockBegin added to each
  // BlockList entry between HostCode and NumGuestPages).
  uint32_t FormatVersion = 2;
  uint8_t FEXVersion[20] = {};
  uint32_t NumBlocks;
  uint32_t NumCodePages;
  uint32_t CodeBufferSize;
  uint32_t NumRelocations;
  uint32_t padding;
  // Guest base address the code buffer was relocated to before being written.
  // SaveData applies relocations against this value, so LoadData's own
  // relocation pass is only correct if it matches what LoadData assumes, which
  // is 0. The only producer (FEXOfflineCompiler) passes 0, but nothing enforced
  // it: a non-zero value would have been written, ignored on load, and produced
  // code relocated against the wrong base. T8: LoadData now rejects anything
  // else. See the check there for why the field is kept rather than deleted.
  uint64_t SerializedBaseAddress;
  // TODO: Consider including information from LookupCache.BlockLinks

  static constexpr std::array<char, 4> ExpectedMagic = {'F', 'X', 'C', 'C'};
};

template<typename T>
concept OrderedContainer = requires { typename T::key_compare; };

bool CodeCache::SaveData(Core::InternalThreadState& Thread, int fd, const ExecutableFileSectionInfo& SourceBinary, uint64_t SerializedBaseAddress) {
  auto CodeBuffer = CTX.GetLatest();
  auto& LookupCache = *Thread.LookupCache->Shared;
  auto Relocations = Thread.CPUBackend->TakeRelocations(SourceBinary.FileStartVA);

  // Write file header
  CodeCacheHeader header {};
  static_assert(GIT_HASH.size() == sizeof(header.FEXVersion));
  std::ranges::copy(GIT_HASH, header.FEXVersion);
  header.NumBlocks = LookupCache.BlockList.size();
  header.NumCodePages = LookupCache.CodePages.size();
  header.CodeBufferSize = CTX.LatestOffset;
  header.NumRelocations = Relocations.size();
  header.SerializedBaseAddress = SerializedBaseAddress;
  ::write(fd, &header, sizeof(header));

  // Dump guest<->host block mappings
  {
    // Cache contents must be deterministic, so copy the unordered block list and then sort by key
    static_assert(!OrderedContainer<decltype(LookupCache.BlockList)>, "Already deterministic; drop temporary container");
    fextl::vector<std::pair<uint64_t, const GuestToHostMap::BlockEntry*>> BlockList;
    BlockList.reserve(LookupCache.BlockList.size());
    for (auto& [Guest, BlockEntry] : LookupCache.BlockList) {
      static_assert(sizeof(Guest) == 8, "Breaking change in code cache data layout");
      BlockList.emplace_back(Guest, &BlockEntry);
    }
    std::ranges::sort(BlockList);

    for (auto [Guest, Host] : BlockList) {
      static_assert(sizeof(Host->HostCode) == 8, "Breaking change in code cache data layout");
      static_assert(sizeof(Host->CodePages[0]) == 8, "Breaking change in code cache data layout");

      Guest -= SourceBinary.FileStartVA;
      ::write(fd, &Guest, sizeof(Guest));
      uint64_t HostCode = Host->HostCode - reinterpret_cast<uintptr_t>(CodeBuffer->Ptr);
      ::write(fd, &HostCode, sizeof(HostCode));
      // S3: write BlockBegin (buffer-relative) alongside HostCode. Format v2.
      uint64_t BlockBegin = Host->BlockBegin - reinterpret_cast<uintptr_t>(CodeBuffer->Ptr);
      ::write(fd, &BlockBegin, sizeof(BlockBegin));
      uint64_t NumCodePages = Host->CodePages.size();
      ::write(fd, &NumCodePages, sizeof(NumCodePages));
      LOGMAN_THROW_A_FMT(std::ranges::is_sorted(Host->CodePages), "Code pages aren't sorted");
      for (auto CodePage : Host->CodePages) {
        CodePage -= SourceBinary.FileStartVA;
        ::write(fd, &CodePage, sizeof(CodePage));
      }
    }
  }

  // Dump relocations
  static_assert(sizeof(Relocations[0]) == 48, "Breaking change in code cache data layout");
  ::write(fd, Relocations.data(), Relocations.size() * sizeof(Relocations[0]));

  // Pad to next page in file so that the CodeBuffer can be mmap'ed into process on load
  char Zero[64] {};
  auto Off = lseek(fd, 0, SEEK_CUR);
  while (Off != AlignUp(Off, Utils::FEX_PAGE_SIZE)) {
    auto BytesToWrite = std::min(AlignUp(Off, Utils::FEX_PAGE_SIZE) - Off, sizeof(Zero));
    ::write(fd, Zero, BytesToWrite);
    Off += BytesToWrite;
  }

  // Dump the host code (relocated for position-independent serialization)
  std::span CodeBufferData(reinterpret_cast<std::byte*>(CodeBuffer->Ptr), reinterpret_cast<std::byte*>(CodeBuffer->Ptr) + CTX.LatestOffset);
  if (!ApplyCodeRelocations(SerializedBaseAddress, CodeBufferData, Relocations, true)) {
    LOGMAN_THROW_A_FMT(false, "Failed to apply code relocations");
    return false;
  }
  ::write(fd, CodeBufferData.data(), CodeBufferData.size());

  // Dump code pages
  static_assert(OrderedContainer<decltype(LookupCache.CodePages)>, "Non-deterministic data source");
  for (const auto& [PageIndex, Entrypoints] : LookupCache.CodePages) {
    uint64_t PageAddr = (PageIndex << 12) - SourceBinary.FileStartVA;
    ::write(fd, &PageAddr, sizeof(PageAddr));
    uint64_t NumEntrypoints = Entrypoints.size();
    ::write(fd, &NumEntrypoints, sizeof(NumEntrypoints));
    for (uint64_t Entrypoint : Entrypoints) {
      Entrypoint -= SourceBinary.FileStartVA;
      ::write(fd, &Entrypoint, sizeof(Entrypoint));
    }
  }

  return true;
}

bool CodeCache::LoadData(Core::InternalThreadState* Thread, std::byte* MappedCacheFile, size_t MappedCacheFileSize,
                         const ExecutableFileSectionInfo& BinarySection) {
  if (!EnableCodeCaching) {
    return true;
  }

  namespace ranges = std::ranges;

  // F2: every offset and count consumed below comes straight out of a file FEX
  // does not control, and several of them turn into executable jump targets or
  // allocation sizes. MappedCacheFileSize is the length of the mapping the
  // caller handed us, and it is the only thing that bounds the reads; without
  // it a header that overstates its own contents walks off the end of the
  // mapping.
  const std::byte* const FileBegin = MappedCacheFile;
  const uint64_t FileSize = MappedCacheFileSize;

  // Bytes between the read cursor and the end of the mapping. Every read below
  // is checked against this before it happens, so the cursor always stays
  // within [FileBegin, FileBegin + FileSize] and this subtraction never wraps.
  auto Remaining = [&]() -> uint64_t {
    return FileSize - static_cast<uint64_t>(MappedCacheFile - FileBegin);
  };

  // Counts are file-controlled uint64_t/uint32_t values, so every bound below is
  // written as `Count > Remaining() / ElementSize` or `Bytes > Remaining()`,
  // never `Offset + Size > Limit`: a bounds check that itself wraps is worse
  // than none.
  auto RejectTruncated = [&](std::string_view What, uint64_t Needed) {
    LogMan::Msg::EFmt("Rejecting code cache for {}: {} needs {:#x} bytes but only {:#x} of the {:#x} byte file are left",
                      BinarySection.FileInfo.Filename, What, Needed, Remaining(), FileSize);
    return false;
  };

  // Read file header. Bound it before a single field is touched.
  if (FileSize < sizeof(CodeCacheHeader)) {
    LogMan::Msg::EFmt("Rejecting code cache for {}: file is {:#x} bytes, too small to hold the {:#x} byte header",
                      BinarySection.FileInfo.Filename, FileSize, sizeof(CodeCacheHeader));
    return false;
  }
  CodeCacheHeader header {};
  ::memcpy(&header, MappedCacheFile, sizeof(header));
  MappedCacheFile += sizeof(header);

  LogMan::Msg::IFmt("Cache load: {:5} blocks; base={:#14x}; off={:#9x}-{:#09x}; {:016x} {}", header.NumBlocks, BinarySection.FileStartVA,
                    BinarySection.BeginVA - BinarySection.FileStartVA, BinarySection.EndVA - BinarySection.FileStartVA,
                    BinarySection.FileInfo.FileId, BinarySection.FileInfo.Filename);

  if (!ranges::equal(header.Magic, header.ExpectedMagic)) {
    LogMan::Msg::EFmt("Invalid cache file header");
    return false;
  }

  if (header.FormatVersion != CodeCacheHeader {}.FormatVersion) {
    LogMan::Msg::IFmt("Cache format version {} does not match expected {}, skipping", header.FormatVersion,
                      CodeCacheHeader {}.FormatVersion);
    return false;
  }

  if (!ranges::equal(header.FEXVersion, GIT_HASH)) {
    LogMan::Msg::IFmt("Cache generated from old FEX version {:02x}, current is {:02x}; skipping", fmt::join(header.FEXVersion, ""),
                      fmt::join(GIT_HASH, ""));
    return false;
  }

  // T8: SerializedBaseAddress was written by SaveData and never read here.
  // LoadData's relocation pass rebases the code buffer from 0 to the current
  // BinarySection.FileStartVA, so it is only correct if the data on disk really
  // was serialized against base 0. That happens to hold — the only producer
  // passes 0 — but nothing checked it, so a producer that ever passed a real
  // base would have silently produced code relocated against the wrong one.
  //
  // Kept rather than deleted: removing it is an on-disk layout change and would
  // cost a FormatVersion bump (invalidating every existing cache) to delete a
  // field that will be needed the moment relocations stop being re-emitted on
  // both sides. Validating it costs one compare and makes the current
  // "always 0" assumption explicit instead of implicit.
  if (header.SerializedBaseAddress != 0) {
    LogMan::Msg::EFmt("Cache for {} was serialized against base {:#x}, but only base 0 is supported; skipping",
                      BinarySection.FileInfo.Filename, header.SerializedBaseAddress);
    return false;
  }

  if (header.NumBlocks == 0) {
    // Valid caches are never empty
    LogMan::Msg::IFmt("Code cache empty, aborting");
    return false;
  }

  // Each block entry occupies at least four 8-byte fields in the file and each
  // code page entry at least two, so the counts can be bounded against the file
  // before either is used as an allocation size. The block table, the code page
  // table and the relocation array are disjoint regions that all follow the
  // header, so bounding each against the whole remainder is conservative but
  // sound. Without this, a 32-bit count out of a corrupt header turns into a
  // multi-gigabyte resize before a single element has been read.
  constexpr uint64_t MinBlockEntrySize = 4 * sizeof(uint64_t);
  constexpr uint64_t MinCodePageEntrySize = 2 * sizeof(uint64_t);
  if (header.NumBlocks > Remaining() / MinBlockEntrySize) {
    return RejectTruncated("the block table", header.NumBlocks * MinBlockEntrySize);
  }
  if (header.NumCodePages > Remaining() / MinCodePageEntrySize) {
    return RejectTruncated("the code page table", header.NumCodePages * MinCodePageEntrySize);
  }
  if (header.NumRelocations > Remaining() / sizeof(FEXCore::CPU::Relocation)) {
    return RejectTruncated("the relocation array", header.NumRelocations * sizeof(FEXCore::CPU::Relocation));
  }

  // Read guest<->host block mappings
  using BlockListEntry = decltype(GuestToHostMap::BlockList)::value_type;
  fextl::vector<BlockListEntry> BlockList(header.NumBlocks);
  {
    for (auto& BlockPtr : BlockList) {
      // Fixed part of one entry: guest address, HostCode, BlockBegin, NumGuestPages.
      if (Remaining() < MinBlockEntrySize) {
        return RejectTruncated("a block table entry", MinBlockEntrySize);
      }

      ::memcpy(&BlockPtr.first, MappedCacheFile, sizeof(BlockPtr.first));
      MappedCacheFile += sizeof(BlockPtr.first);
      ::memcpy(&BlockPtr.second.HostCode, MappedCacheFile, sizeof(BlockPtr.second.HostCode));
      MappedCacheFile += sizeof(BlockPtr.second.HostCode);
      // S3: BlockBegin follows HostCode in format v2. Still buffer-relative
      // at this point; converted to an absolute pointer alongside HostCode
      // in the register-blocks-to-LookupCache loop below.
      ::memcpy(&BlockPtr.second.BlockBegin, MappedCacheFile, sizeof(BlockPtr.second.BlockBegin));
      MappedCacheFile += sizeof(BlockPtr.second.BlockBegin);
      uint64_t NumGuestPages;
      ::memcpy(&NumGuestPages, MappedCacheFile, sizeof(NumGuestPages));
      MappedCacheFile += sizeof(NumGuestPages);

      // F2: none of the three values above has been validated, and all three are
      // about to be trusted — HostCode and BlockBegin become absolute host
      // pointers that the LookupCache hands to the dispatcher as jump targets,
      // and NumGuestPages drives the resize plus memcpy immediately below.
      //
      // Comparisons are written as `X >= Limit` / `X > Limit - sizeof(...)`
      // rather than `X + sizeof(...) > Limit`: these are file-controlled
      // uint64_t values, so a bounds check that itself wraps is worse than none.
      //
      // NumGuestPages is bounded twice, and the two bounds are independent.
      // header.NumCodePages is the count of distinct guest code pages in the
      // whole cache and is therefore an upper bound on any one block's page list
      // (a block's pages are always registered into that same global set at
      // compile time) — an internal-consistency check that catches a header
      // which is self-contradictory but not truncated. Remaining() is the real
      // file-length bound and is what stops the memcpy below reading past the
      // end of the mapping.
      if (BlockPtr.second.HostCode >= header.CodeBufferSize || BlockPtr.second.BlockBegin >= header.CodeBufferSize) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block {:#x} has HostCode {:#x} / BlockBegin {:#x} outside the {:#x} byte code buffer",
                          BinarySection.FileInfo.Filename, BlockPtr.first, BlockPtr.second.HostCode, BlockPtr.second.BlockBegin,
                          header.CodeBufferSize);
        return false;
      }

      if (NumGuestPages > header.NumCodePages) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block {:#x} claims {} guest code pages, more than the {} the whole cache holds",
                          BinarySection.FileInfo.Filename, BlockPtr.first, NumGuestPages, header.NumCodePages);
        return false;
      }

      using CodePageEntry = decltype(BlockPtr.second.CodePages)::value_type;
      if (NumGuestPages > Remaining() / sizeof(CodePageEntry)) {
        return RejectTruncated("a block's guest code page list", NumGuestPages * sizeof(CodePageEntry));
      }

      BlockPtr.second.CodePages.resize(NumGuestPages);
      ::memcpy(BlockPtr.second.CodePages.data(), MappedCacheFile, std::span {BlockPtr.second.CodePages}.size_bytes());
      MappedCacheFile += std::span {BlockPtr.second.CodePages}.size_bytes();
    }

    // Constrain BlockList to the given ExecutableFileSectionInfo.
    //
    // The lower_bound/upper_bound pair below only selects the right subset if
    // the table is sorted by guest address. SaveData sorts it, so a cache this
    // build wrote always is — but this used to be LOGMAN_THROW_A_FMT, which
    // compiles to `(void)(pred)` in Release, so in a release build the ordering
    // was simply assumed of a file nothing had validated. An unsorted table is
    // not memory-unsafe (both bounds stay inside the vector), it silently loads
    // an arbitrary wrong subset of blocks, which is the harder failure to
    // notice. Same class as every other unvalidated field here: reject it.
    if (!ranges::is_sorted(BlockList, std::less {}, &BlockListEntry::first)) {
      LogMan::Msg::EFmt("Rejecting code cache for {}: block table is not sorted by guest address", BinarySection.FileInfo.Filename);
      return false;
    }
    auto begin = ranges::lower_bound(BlockList, BinarySection.BeginVA - BinarySection.FileStartVA, std::less {}, &BlockListEntry::first);
    auto end =
      ranges::upper_bound(begin, BlockList.end(), BinarySection.EndVA - BinarySection.FileStartVA - 1, std::less {}, &BlockListEntry::first);
    if (begin == end) {
      // Not an error since there is just no data to load
      LogMan::Msg::IFmt("No blocks cached in this range, aborting");
      return true;
    }
    BlockList.erase(end, BlockList.end());
    BlockList.erase(BlockList.begin(), begin);
  }

  // Read relocations. The up-front bound above was taken against the whole
  // post-header remainder; re-check against what the block table actually left.
  if (header.NumRelocations > Remaining() / sizeof(FEXCore::CPU::Relocation)) {
    return RejectTruncated("the relocation array", header.NumRelocations * sizeof(FEXCore::CPU::Relocation));
  }
  fextl::vector<FEXCore::CPU::Relocation> Relocations(header.NumRelocations, FEXCore::CPU::Relocation::Default());
  ::memcpy(Relocations.data(), MappedCacheFile, Relocations.size() * sizeof(Relocations[0]));
  MappedCacheFile += Relocations.size() * sizeof(Relocations[0]);

  // Pad to next page in file, which contains CodeBuffer data.
  // SaveData pads the file offset, and both callers map from offset 0 at a
  // page-aligned address, so aligning the cursor is the same thing as aligning
  // the file offset. The padding itself has to be inside the file: a cache
  // truncated in the middle of that pad would otherwise put the cursor past the
  // end of the mapping before the code buffer read even gets a chance to check.
  const uint64_t PageAlignPadding =
    AlignUp(reinterpret_cast<uintptr_t>(MappedCacheFile), Utils::FEX_PAGE_SIZE) - reinterpret_cast<uintptr_t>(MappedCacheFile);
  if (PageAlignPadding > Remaining()) {
    return RejectTruncated("the page alignment padding before the code buffer", PageAlignPadding);
  }
  MappedCacheFile += PageAlignPadding;

  // The code buffer is memcpy'd out of the file wholesale further below, after
  // the destination has been sized. Bound it here, before anything is allocated
  // or any context state is touched, so a rejection at this point is free.
  if (header.CodeBufferSize > Remaining()) {
    return RejectTruncated("the code buffer", header.CodeBufferSize);
  }

  // Prepare CodeBuffer: Page aligned and big enough to hold all cached data
  auto Lock = std::unique_lock {CTX.CodeBufferWriteMutex};
  if (Thread) {
    if (auto Prev = Thread->CPUBackend->CheckCodeBufferUpdate()) {
      Allocator::VirtualDontNeed(Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE);
      auto lk = Thread->LookupCache->AcquireWriteLock();
      Thread->LookupCache->ChangeGuestToHostMapping(*Prev, *CTX.GetLatest()->LookupCache, lk);
    }
  }

  auto CodeBuffer = CTX.GetLatest();
  LOGMAN_THROW_A_FMT(reinterpret_cast<uintptr_t>(CodeBuffer->Ptr) % 0x1000 == 0, "Expected CodeBuffer base to be page-aligned");
  const auto Delta = AlignUp(CTX.LatestOffset, 0x1000) - CTX.LatestOffset;
  CTX.LatestOffset += Delta;

  while (CTX.LatestOffset + header.CodeBufferSize > CodeBuffer->UsableSize()) {
    if (!Thread) {
      ERROR_AND_DIE_FMT("Cannot extend codebuffer without thread!");
    }

    const size_t PrevUsableSize = CodeBuffer->UsableSize();
    CTX.ClearCodeCache(Thread);
    CodeBuffer = CTX.GetLatest();
    LogMan::Msg::IFmt("Increased code buffer size to {} MiB for cache load", CodeBuffer->AllocatedSize / 1024 / 1024);

    // F1: StartLargerCodeBuffer grows geometrically but saturates at
    // MAX_CODE_SIZE, so once the buffer stops growing this condition can never
    // become false: the loop would spin forever, mapping and unmapping a
    // 128 MiB region on every iteration. header.CodeBufferSize is read straight
    // out of the file and is not otherwise validated, so a corrupt or hostile
    // header reaches this. A cache this build generated cannot (the generator
    // is itself bounded by the same UsableSize), so this is hardening, not a
    // live hang. Same shape as the PPC64 JIT's rotation guard in
    // JIT/PPC64LE/JIT.cpp.
    if (CodeBuffer->UsableSize() <= PrevUsableSize) {
      ERROR_AND_DIE_FMT("Code cache for {} declares a {} byte code buffer, but the maximum code buffer only has {} usable bytes. "
                        "Refusing to spin re-allocating it.",
                        BinarySection.FileInfo.Filename, header.CodeBufferSize, CodeBuffer->UsableSize());
    }
  }

  // Read CodeBuffer data from file. Make sure the destination is page-aligned.
  // TODO: Only load the data needed for the selected section
  auto CodeBufferRange =
    std::as_writable_bytes(std::span {CodeBuffer->Ptr, CodeBuffer->UsableSize()}).subspan(CTX.LatestOffset, header.CodeBufferSize);
  ::memcpy(CodeBufferRange.data(), MappedCacheFile, header.CodeBufferSize);
  MappedCacheFile += header.CodeBufferSize;
  CTX.LatestOffset += header.CodeBufferSize;

  // Walk the trailing code page table without consuming it, purely to bound it
  // against the file. The loop that actually reads it runs with the LookupCache
  // write lock held and after blocks have already been registered, so bailing
  // out of it halfway would leave the lookup cache holding part of a cache file
  // we just rejected. Checking it here means that loop can only ever be entered
  // when every read it is about to make is known to be in bounds.
  {
    const std::byte* Cursor = MappedCacheFile;
    for (uint32_t i = 0; i < header.NumCodePages; ++i) {
      const uint64_t Left = FileSize - static_cast<uint64_t>(Cursor - FileBegin);
      if (Left < MinCodePageEntrySize) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: code page entry {} of {} runs past the end of the {:#x} byte file",
                          BinarySection.FileInfo.Filename, i, header.NumCodePages, FileSize);
        CTX.LatestOffset -= header.CodeBufferSize;
        return false;
      }

      uint64_t NumEntrypoints;
      ::memcpy(&NumEntrypoints, Cursor + sizeof(uint64_t), sizeof(NumEntrypoints));
      Cursor += MinCodePageEntrySize;

      if (NumEntrypoints > (FileSize - static_cast<uint64_t>(Cursor - FileBegin)) / sizeof(uint64_t)) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: code page entry {} of {} claims {} entrypoints, more than the {:#x} byte file holds",
                          BinarySection.FileInfo.Filename, i, header.NumCodePages, NumEntrypoints, FileSize);
        CTX.LatestOffset -= header.CodeBufferSize;
        return false;
      }
      Cursor += NumEntrypoints * sizeof(uint64_t);
    }
  }

  // Apply FEX relocations. B2 (S3-REVISED): must check the return value with a
  // real branch, not LOGMAN_THROW_A_FMT — the latter expands to `(void)(pred)`
  // in Release, so a mid-loop failure (e.g. a thunk symbol Lookup returns ~0ULL
  // at ApplyCodeRelocations :671) would silently skip every later relocation and
  // fall through to the block-registration loop below, which then marks a
  // partially-patched buffer executable. SaveData at :315-318 handles the same
  // call correctly; mirror its shape.
  if (!ApplyCodeRelocations(BinarySection.FileStartVA, CodeBufferRange, Relocations, false)) {
    LogMan::Msg::EFmt("Failed to apply code cache relocations for {} — rejecting cache", BinarySection.FileInfo.Filename);
    // B1: give the bytes back. CTX.LatestOffset was advanced by
    // header.CodeBufferSize just above, and nothing consumes the region we are
    // now abandoning, so leaving the offset advanced permanently burns that much
    // of the code buffer on every rejected cache.
    CTX.LatestOffset -= header.CodeBufferSize;
    return false;
  }

  // B1: structural check of the guest -> host block mapping, before anything is
  // registered as an executable entry point. Deliberately NOT gated on
  // EnableCodeCacheValidation: this is a correctness gate on data that is about
  // to be jumped into, not a debugging aid, so it runs on every load.
  //
  // For each entry, walk BlockBegin -> JITCodeHeader::OffsetToBlockTail ->
  // JITCodeTail and require that the guest address the entry claims lies inside
  // the guest range the tail records, and that the entry's host code lies inside
  // the host block the tail sizes.
  //
  // This is a RANGE test, not an equality test: one BlockBegin and one tail
  // serve every entry point of a multiblock compile, while Tail->RIP names only
  // the primary entry.
  //
  // Portability: ARM64 has emitted the tail-RIP relocation since this cache
  // format existed, so the check is immediately valid there. The ppc64le
  // relocation work was catch-up, not a portability gate — this is not a
  // ppc64le-specific check.
  {
    const uint64_t BufSize = CodeBufferRange.size_bytes();
    constexpr uint64_t HeaderSize = sizeof(CPU::CPUBackend::JITCodeHeader);
    constexpr uint64_t TailSize = sizeof(CPU::CPUBackend::JITCodeTail);
    bool Rejected = false;

    // Every bounds test below is written as `X > Limit - sizeof(...)` rather
    // than `X + sizeof(...) > Limit`. These are file-controlled uint64_t values
    // and this check is precisely the mitigation for that, so it must not itself
    // be wrappable.
    for (const auto& [Guest, Host] : BlockList) {
      if (BufSize < HeaderSize || Host.BlockBegin > BufSize - HeaderSize) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block {:#x} has out-of-range BlockBegin {:#x} (code buffer is {:#x} bytes)",
                          BinarySection.FileInfo.Filename, Guest, Host.BlockBegin, BufSize);
        Rejected = true;
        break;
      }

      const auto* Header = reinterpret_cast<const CPU::CPUBackend::JITCodeHeader*>(CodeBufferRange.data() + Host.BlockBegin);
      // BlockBegin is bounded by BufSize (<= 4 GiB, CodeBufferSize is uint32_t)
      // and OffsetToBlockTail is uint32_t, so this sum cannot wrap.
      const uint64_t TailOffset = Host.BlockBegin + Header->OffsetToBlockTail;
      if (BufSize < TailSize || TailOffset > BufSize - TailSize) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block {:#x} at {:#x} has out-of-range tail offset {:#x} (code buffer is {:#x} bytes)",
                          BinarySection.FileInfo.Filename, Guest, Host.BlockBegin, TailOffset, BufSize);
        Rejected = true;
        break;
      }

      const auto* Tail = reinterpret_cast<const CPU::CPUBackend::JITCodeTail*>(CodeBufferRange.data() + TailOffset);

      // MANDATORY skip, not a rejection. A block whose *entry* instruction fails
      // to decode gets InstSize = 0, hence DecodedMax == DecodedMin, hence
      // GuestSize == 0. It survives block erasure because it is the entry block,
      // and it is still cacheable because the cacheability filter only looks for
      // bad relocations. Its own guest address can never satisfy
      // `RIP <= addr < RIP + 0`, so range-checking it would reject the entire
      // file — on the main load path, on ARM64 as well. It is reachable in
      // practice because the offline compiler re-maps the ELF statically, so an
      // address that decoded at runtime can fail to decode offline.
      if (Tail->GuestSize == 0) {
        continue;
      }

      const uint64_t GuestAbs = Guest + BinarySection.FileStartVA;
      if (GuestAbs < Tail->RIP || GuestAbs - Tail->RIP >= Tail->GuestSize) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block entry {:#x} is outside the guest range [{:#x}, {:#x}) recorded by the block it "
                          "maps to",
                          BinarySection.FileInfo.Filename, GuestAbs, Tail->RIP, Tail->RIP + Tail->GuestSize);
        Rejected = true;
        break;
      }

      if (Host.HostCode < Host.BlockBegin || Host.HostCode - Host.BlockBegin >= Tail->Size) {
        LogMan::Msg::EFmt("Rejecting code cache for {}: block entry {:#x} has host code {:#x} outside its block [{:#x}, {:#x})",
                          BinarySection.FileInfo.Filename, GuestAbs, Host.HostCode, Host.BlockBegin, Host.BlockBegin + Tail->Size);
        Rejected = true;
        break;
      }
    }

    if (Rejected) {
      // See the rewind above: the file has already been memcpy'd into the code
      // buffer and CTX.LatestOffset advanced past it. Nothing else will use that
      // region, so hand it back rather than leaking it on every rejection.
      CTX.LatestOffset -= header.CodeBufferSize;
      return false;
    }
  }

  {
    auto& LookupCache = *CodeBuffer->LookupCache;
    auto WriteLock = LookupCache.AcquireWriteLock();

    // Register blocks to LookupCache
    for (auto& [Guest, Host] : BlockList) {
      for (auto& CodePage : Host.CodePages) {
        CodePage += BinarySection.FileStartVA;
      }
      auto HostCode = reinterpret_cast<void*>(Host.HostCode + reinterpret_cast<uintptr_t>(CodeBufferRange.data()));
      // Convert BlockBegin to absolute alongside HostCode (S3).
      auto BlockBeginAbs = Host.BlockBegin + reinterpret_cast<uintptr_t>(CodeBufferRange.data());
      LookupCache.AddBlockMapping(Guest + BinarySection.FileStartVA, BlockBeginAbs, std::move(Host.CodePages), HostCode, WriteLock);
    }

    // Register loaded code ranges
    fextl::vector<uint64_t> Entrypoints;
    for (uint32_t i = 0; i < header.NumCodePages; ++i) {
      uint64_t CodePage;
      memcpy(&CodePage, MappedCacheFile, sizeof(CodePage));
      CodePage += BinarySection.FileStartVA;
      MappedCacheFile += sizeof(CodePage);

      uint64_t NumEntrypoints;
      memcpy(&NumEntrypoints, MappedCacheFile, sizeof(NumEntrypoints));
      MappedCacheFile += sizeof(NumEntrypoints);

      Entrypoints.resize(NumEntrypoints);
      memcpy(Entrypoints.data(), MappedCacheFile, NumEntrypoints * sizeof(Entrypoints[0]));
      MappedCacheFile += NumEntrypoints * sizeof(Entrypoints[0]);
      for (auto& Entrypoint : Entrypoints) {
        Entrypoint += BinarySection.FileStartVA;
      }

      if (LookupCache.AddBlockExecutableRange(Entrypoints, CodePage, FEXCore::Utils::FEX_PAGE_SIZE, WriteLock)) {
        CTX.SyscallHandler->MarkGuestExecutableRange(Thread, CodePage, FEXCore::Utils::FEX_PAGE_SIZE);
      }
    }
  }

  if (EnableCodeCacheValidation) {
    fextl::set<uint64_t> GuestBlocks, BlockBegins;
    for (auto& [Guest, Host] : BlockList) {
      GuestBlocks.insert(Guest + BinarySection.FileStartVA);
      // S3.6: pass BlockBegin (buffer-relative) instead of HostCode entry so
      // Validate's subspan lands at the start of the JITCodeHeader on every
      // arch. On ppc64le the entry point is ~200-270 bytes past BlockBegin
      // (FillStaticRegs + EmitEntryPoint sits between them), so the old
      // `HostBlocks.begin() - sizeof(JITCodeHeader)` arithmetic landed
      // mid-prologue and the byte-compare failed at offset 0x0 comparing
      // unrelated instructions. BlockBegin identifies the header directly.
      BlockBegins.insert(Host.BlockBegin);
    }

    Validate(BinarySection, std::move(GuestBlocks), BlockBegins, CodeBufferRange);
  }

  return true;
}

void CodeCache::Validate(const ExecutableFileSectionInfo& Section, fextl::set<uint64_t> GuestBlocks, const fextl::set<uint64_t>& BlockBegins,
                         std::span<std::byte> CachedCode) {
  LOGMAN_THROW_A_FMT(!BlockBegins.empty(), "Tried to validate without any host blocks");
  // Skip any cached data before the first block begin. BlockBegin points at
  // the JITCodeHeader on every arch (S3.6), so no per-arch arithmetic is
  // needed here — this used to be
  // `subspan(*HostBlocks.begin() - sizeof(JITCodeHeader))` which relied on
  // the ARM64 invariant that the entry point sits 4 bytes past BlockBegin.
  CachedCode = CachedCode.subspan(*BlockBegins.begin());

  if (!ValidationCTX) {
    ValidationCTX.reset(static_cast<ContextImpl*>(FEXCore::Context::Context::CreateNewContext(CTX.HostFeatures).release()));
    ValidationCTX->SetSignalDelegator(CTX.SignalDelegation);
    ValidationCTX->SetSyscallHandler(CTX.SyscallHandler);
    ValidationCTX->SetThunkHandler(CTX.ThunkHandler);
    if (!ValidationCTX->InitCore()) {
      ERROR_AND_DIE_FMT("Failed to create cache load validation context");
    }

    ValidationThread.reset(ValidationCTX->CreateThread(0, 0, nullptr));

    auto Frame = ValidationThread->CurrentFrame;
    Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_GDT] = &ValidationGDT[0];
    Frame->State.segment_arrays[FEXCore::Core::CPUState::SEGMENT_ARRAY_INDEX_LDT] = &ValidationGDT[0];
    Frame->State.cs_idx = 0;
    Frame->State.cs_cached = 0;

    if (ValidationCTX->Config.Is64BitMode()) {
      ValidationGDT[0].L = 1; // L = Long Mode = 64-bit
      ValidationGDT[0].D = 0; // D = Default Operand Size = Reserved
    } else {
      ValidationGDT[0].L = 0; // L = Long Mode = 32-bit
      ValidationGDT[0].D = 1; // D = Default Operand Size = 32-bit
    }
  }

  // Return the validation context to the state the next Validate call expects:
  // no reference blocks in the lookup cache and a write offset of 0. The
  // reference span below is always taken from offset 0, so leaving a non-zero
  // LatestOffset behind would make the next run compare bytes it never wrote.
  // Used by every path that abandons a validation run, and by the success path.
  auto ResetValidationState = [this]() {
    ValidationThread->LookupCache->ClearCache(ValidationThread->LookupCache->AcquireWriteLock());
    ValidationCTX->LatestOffset = 0;
  };

  // B3: both backends can rotate the code buffer in the middle of the compile
  // loop below — ppc64le pre-reserves at least 1 MiB of headroom per block
  // (JIT/PPC64LE/JIT.cpp), ARM64 does an exact-fit check before copying its
  // staged block into the shared buffer (JIT/JIT.cpp). This is not a ppc64le
  // peculiarity. Reserve the JIT's own headroom floor on top of the cached code
  // so the last block does not trip the rotation path; that only makes rotation
  // unlikely, and the post-loop check is what makes it safe.
  constexpr size_t JITBlockHeadroom = 1u << 20;

  auto NewCodeBuffer = ValidationCTX->GetLatest();
  while (CachedCode.size_bytes() + JITBlockHeadroom > NewCodeBuffer->UsableSize()) {
    const size_t PrevUsableSize = NewCodeBuffer->UsableSize();
    ValidationCTX->ClearCodeCache(ValidationThread.get());
    NewCodeBuffer = ValidationCTX->GetLatest();
    LogMan::Msg::IFmt("Increased cache validation code buffer size to {} MiB", NewCodeBuffer->AllocatedSize / 1024 / 1024);

    // F1: see the matching guard on the load path. Validation is optional, so
    // skip it rather than killing the process.
    if (NewCodeBuffer->UsableSize() <= PrevUsableSize) {
      LogMan::Msg::EFmt("Cache validation skipped for {}: {} bytes of cached code do not fit the maximum validation code buffer ({} usable "
                        "bytes)",
                        Section.FileInfo.Filename, CachedCode.size_bytes(), NewCodeBuffer->UsableSize());
      return;
    }
  }

  while (!GuestBlocks.empty()) {
    auto [CompiledBlocks, _, _2, _3, _4] = ValidationCTX->CompileCode(ValidationThread.get(), *GuestBlocks.begin(), 0 /* TODO: Set MaxInst? */);
    for (auto& Entry : CompiledBlocks.EntryPoints) {
      GuestBlocks.erase(Entry.first);
    }
  }

  // B3: if the buffer rotated during the compile, the reference bytes for every
  // block compiled before the rotation are in a buffer that has been abandoned,
  // and nothing in the new buffer can stand in for them. Report inconclusive
  // rather than comparing the cache against whatever the surviving fragment
  // happens to be. The pre-loop span capture this replaces silently compared
  // post-rotation bytes against pre-rotation cached code.
  if (ValidationCTX->GetLatest().get() != NewCodeBuffer.get()) {
    LogMan::Msg::EFmt("Cache validation INCONCLUSIVE for {}: the validation code buffer rotated during the reference compile, so the "
                      "reference bytes for the blocks compiled before the rotation are unrecoverable",
                      Section.FileInfo.Filename);
    ResetValidationState();
    return;
  }

  // Size the reference span to what the reference compile actually emitted, not
  // to the size of the cache. B3: this capture has to happen after the compile
  // loop, because NewCodeBuffer is only known to still be the live buffer once
  // the rotation check above has passed.
  std::span<std::byte> CodeBufferRangeRef =
    std::as_writable_bytes(std::span {NewCodeBuffer->Ptr, NewCodeBuffer->Ptr + NewCodeBuffer->UsableSize()}).subspan(0, ValidationCTX->LatestOffset);

  // Patch FEX-internal function addresses with values from the main Context to ensure the code blocks are comparable
  auto NewRelocations = ValidationThread->CPUBackend->TakeRelocations(Section.FileStartVA);
  NewRelocations.erase(std::remove_if(NewRelocations.begin(), NewRelocations.end(),
                                      [](const CPU::Relocation& Reloc) {
                                        return Reloc.Header.Type != CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL &&
                                               Reloc.Header.Type != CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE;
                                      }),
                       NewRelocations.end());
  // F3: do not discard this result. ApplyCodeRelocations bails out mid-loop
  // when a thunk symbol lookup returns ~0ULL, which leaves the reference buffer
  // patched up to that relocation and unpatched after it. Comparing that against
  // the cache reports a byte mismatch at whatever offset the first unpatched
  // relocation happens to sit at, which reads exactly like a codegen bug and
  // sends the reader hunting one that does not exist. Mirror the load path's
  // handling of the same call: log and return, validation inconclusive. Not
  // ERROR_AND_DIE — a missing thunk says nothing about whether the cached code
  // is correct.
  if (!ApplyCodeRelocations(Section.FileStartVA, CodeBufferRangeRef, NewRelocations, false)) {
    LogMan::Msg::EFmt("Cache validation INCONCLUSIVE for {}: failed to apply relocations to the reference compile", Section.FileInfo.Filename);
    ResetValidationState();
    return;
  }

  const size_t RefSize = CodeBufferRangeRef.size_bytes();
  const size_t CachedSize = CachedCode.size_bytes();
  const size_t CommonSize = std::min(RefSize, CachedSize);

  // B2: report what was actually compared on every run, not only on failure.
  // Without this the check can only ever speak by failing, and a passing run is
  // indistinguishable from one that compared almost nothing.
  LogMan::Msg::IFmt("\tCache validation for {}: reference compile emitted {:#x} bytes, cache holds {:#x} bytes, comparing {:#x}",
                    Section.FileInfo.Filename, RefSize, CachedSize, CommonSize);

  // B2: compare the common prefix first, so a genuine content divergence is
  // still reported at its first differing byte rather than being hidden behind
  // the length report below. The previous code truncated the reference span to
  // the cached length and then declared success, so a cache holding more bytes
  // than the reference compiles had the excess never examined at all.
  auto RefCommon = CodeBufferRangeRef.first(CommonSize);
  auto [Mismatch, _] = std::mismatch(RefCommon.begin(), RefCommon.end(), CachedCode.begin());
  if (Mismatch != RefCommon.end()) {
    // Align down to instruction size, then clamp so the 4-byte context windows
    // reported below stay inside both spans. CommonSize derives from a
    // file-supplied size and is not guaranteed to be 4-aligned, so
    // `subspan(Idx, 4)` on an aligned-down Idx can run off the end.
    const size_t ContextSize = std::min<size_t>(4, CommonSize);
    auto Idx = AlignDown(std::distance(RefCommon.begin(), Mismatch), 4);
    Idx = std::min<uint64_t>(Idx, CommonSize - ContextSize);

    // S3.6: find the owning block by its BlockBegin (the greatest BlockBegin
    // <= Idx-in-buffer). The prior form combined `HostBlocks.lower_bound` with
    // an AArch64 ADR-immediate decode to hop from entry-point back to header;
    // now that BlockBegin points directly at the header on every arch, the
    // decode is gone.
    auto BlockIt = std::prev(BlockBegins.lower_bound(*BlockBegins.begin() + Idx + 1));
    std::optional<uint64_t> GuestBlockAddr;
    std::optional<uint64_t> GuestBlockAddrRef;
    if (BlockIt != BlockBegins.end()) {
      for (int i : {0, 1}) {
        std::span Buffer = (i == 0 ? CachedCode : CodeBufferRangeRef);

        auto header = reinterpret_cast<CPU::CPUBackend::JITCodeHeader*>(&Buffer[*BlockIt - *BlockBegins.begin()]);
        auto tail = reinterpret_cast<CPU::CPUBackend::JITCodeTail*>(reinterpret_cast<uintptr_t>(header) + header->OffsetToBlockTail);
        (i == 0 ? GuestBlockAddr : GuestBlockAddrRef) = tail->RIP - Section.FileStartVA;
        LogMan::Msg::EFmt("Recorded rip {}: {:#x} (offset {:#x})", i, tail->RIP, tail->RIP - Section.FileStartVA);

        if (i == 1) {
          if (tail->RIP >= Section.BeginVA && tail->RIP < Section.EndVA) {
            auto [IRView, TotalInstructions, TotalInstructionsLength, StartAddr, Length, _] =
              ValidationCTX->GenerateIR(ValidationThread.get(), tail->RIP, false, FEXCore::Config::Get_MAXINST());
            fextl::stringstream ss;
            FEXCore::IR::Dump(&ss, &*IRView);
            LogMan::Msg::EFmt("IR:\n{}", ss.str());
          } else {
            LogMan::Msg::EFmt("Can't dump IR for out-of-range RIP {:#x}", tail->RIP);
          }
        }
      }
    }

    fextl::string GuestBlockInfo = "UNKNOWN";
    if (GuestBlockAddr) {
      GuestBlockInfo = fextl::fmt::format("{:#x}", GuestBlockAddr.value());
    }
    if (GuestBlockAddr != GuestBlockAddrRef) {
      GuestBlockInfo += " (MISMATCH)";
    }
    ERROR_AND_DIE_FMT("Cache validation failed at offset {:#x}: {:02x} <-> {:02x} (at {} <-> {}, guest block {})", Idx,
                      fmt::join(CachedCode.subspan(Idx, ContextSize), ""), fmt::join(CodeBufferRangeRef.subspan(Idx, ContextSize), ""),
                      fmt::ptr(CachedCode.data()), fmt::ptr(CodeBufferRangeRef.data()), GuestBlockInfo);
  }

  if (RefSize != CachedSize) {
    // B2: the common prefix matches but the two are not the same length, so
    // some bytes on one side were never examined. Deliberately NOT fatal: a
    // file with more than one block-bearing executable VMA legitimately makes
    // the reference compile a strict prefix of the cached buffer. LoadData
    // filters BlockList down to the section being loaded but memcpy's the whole
    // code buffer (see the "TODO: Only load the data needed for the selected
    // section" there), so the cache carries every section's code while the
    // reference only compiles this section's blocks. That case passes today and
    // killing the process on it would be a regression.
    LogMan::Msg::EFmt("Cache validation INCONCLUSIVE for {}: the common {:#x} byte prefix matches, but the reference compile emitted {:#x} "
                      "bytes against {:#x} cached bytes, leaving {:#x} bytes unexamined{}",
                      Section.FileInfo.Filename, CommonSize, RefSize, CachedSize, std::max(RefSize, CachedSize) - CommonSize,
                      RefSize < CachedSize ? " (expected when the cache covers more than one executable section of this file)" : "");
    ResetValidationState();
    return;
  }

  // Reset Context state for next validation
  ResetValidationState();

  LogMan::Msg::IFmt("\tSuccessfully validated cache ({:#x} bytes)", CachedSize);
}

bool CodeCache::ApplyCodeRelocations(uint64_t GuestEntry, std::span<std::byte> Code,
                                     std::span<const FEXCore::CPU::Relocation> EntryRelocations, bool ForStorage) {
#ifndef ARCHITECTURE_ppc64le
  CPU::Arm64Emitter Emitter(&CTX, Code.data(), Code.size_bytes());
  for (size_t j = 0; j < EntryRelocations.size(); ++j) {
    const FEXCore::CPU::Relocation& Reloc = EntryRelocations[j];
    Emitter.SetCursorOffset(Reloc.Header.Offset);

    switch (Reloc.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
      // Generate a literal so we can place it
      uint64_t Pointer = ForStorage ? 0 : GetNamedSymbolLiteral(CTX, Reloc.NamedSymbolLiteral.Symbol);
      Emitter.dc64(Pointer);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: {
      uint64_t Pointer = ForStorage ? 0 : reinterpret_cast<uint64_t>(CTX.ThunkHandler->LookupThunk(Reloc.NamedThunkMove.Symbol));
      if (Pointer == ~0ULL) {
        return false;
      }
      // TODO: Pointers are required to fit within 48-bit VA space.
      // But forcing 6-byte broke relocations.
      Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.NamedThunkMove.RegisterIndex), Pointer,
                           CPU::Arm64Emitter::PadType::DOPAD);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
      Emitter.dc64(GuestEntry + Reloc.GuestRIP.GuestRIP);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
      uint64_t Pointer = Reloc.GuestRIP.GuestRIP + GuestEntry;
      // TODO: Pointers are required to fit within 48-bit VA space.
      // But forcing 6-byte broke relocations.
      Emitter.LoadConstant(ARMEmitter::Size::i64Bit, ARMEmitter::Register(Reloc.GuestRIP.RegisterIndex), Pointer, CPU::Arm64Emitter::PadType::DOPAD);
      break;
    }

    default: ERROR_AND_DIE_FMT("Unknown relocation type {}", ToUnderlying(Reloc.Header.Type));
    }
  }

  return true;
#else
  // PPC64LE relocation patching
  for (size_t j = 0; j < EntryRelocations.size(); ++j) {
    const FEXCore::CPU::Relocation& Reloc = EntryRelocations[j];
    auto* Ptr = reinterpret_cast<uint8_t*>(Code.data()) + Reloc.Header.Offset;
    const size_t Remaining = Code.size() - Reloc.Header.Offset;

    switch (Reloc.Header.Type) {
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_SYMBOL_LITERAL: {
      uint64_t Pointer = ForStorage ? 0 : GetNamedSymbolLiteral(CTX, Reloc.NamedSymbolLiteral.Symbol);
      memcpy(Ptr, &Pointer, sizeof(Pointer));
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_NAMED_THUNK_MOVE: {
      uint64_t Pointer = ForStorage ? 0 : reinterpret_cast<uint64_t>(CTX.ThunkHandler->LookupThunk(Reloc.NamedThunkMove.Symbol));
      if (Pointer == ~0ULL) {
        return false;
      }
      // S3.7-C1: hard bounds check + fixed-width patch. The emitter's own
      // width assert is in LOGMAN_THROW which is (void)pred in Release, so
      // an under-sized Remaining would silently overrun. This is executable
      // code being patched — Reloc.Header.Offset comes from a file at load
      // time and from JIT emission at validation time.
      if (Reloc.Header.Offset + PPC64Emitter::Emitter::LoadConstantFixedBytes > Code.size()) {
        LogMan::Msg::EFmt("NamedThunkMove reloc @{:#x} would overrun buffer size {:#x}", Reloc.Header.Offset, Code.size());
        return false;
      }
      FEXCore::CPU::PPC64EmitterBase PatchEmitter(&CTX, Ptr, Remaining);
      PatchEmitter.LoadConstantFixed(PPC64Emitter::r(Reloc.NamedThunkMove.RegisterIndex), Pointer);
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_LITERAL: {
      uint64_t Val = GuestEntry + Reloc.GuestRIP.GuestRIP;
      memcpy(Ptr, &Val, sizeof(Val));
      break;
    }
    case FEXCore::CPU::RelocationTypes::RELOC_GUEST_RIP_MOVE: {
      uint64_t Pointer = Reloc.GuestRIP.GuestRIP + GuestEntry;
      // S3.7-C1: same bounds guard as above.
      if (Reloc.Header.Offset + PPC64Emitter::Emitter::LoadConstantFixedBytes > Code.size()) {
        LogMan::Msg::EFmt("GuestRIP MOVE reloc @{:#x} would overrun buffer size {:#x}", Reloc.Header.Offset, Code.size());
        return false;
      }
      FEXCore::CPU::PPC64EmitterBase PatchEmitter(&CTX, Ptr, Remaining);
      PatchEmitter.LoadConstantFixed(PPC64Emitter::r(Reloc.GuestRIP.RegisterIndex), Pointer);
      break;
    }
    default: ERROR_AND_DIE_FMT("Unknown relocation type {}", ToUnderlying(Reloc.Header.Type));
    }
  }
  return true;
#endif
}

} // namespace FEXCore::Context
