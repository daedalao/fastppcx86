// SPDX-License-Identifier: MIT
/*
$info$
category: LinuxSyscalls ~ Linux syscall emulation, marshaling and passthrough
tags: LinuxSyscalls|common
desc: Glue logic, brk allocations
$end_info$
*/

#include "CodeLoader.h"

#include "FEXHeaderUtils/StringArgumentParser.h"
#include "Linux/Utils/ELFContainer.h"
#include "Linux/Utils/ELFParser.h"

#include "LinuxSyscalls/LinuxAllocator.h"
#include "LinuxSyscalls/SignalDelegator.h"
#include "LinuxSyscalls/SMCStoreBackpatch.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/Syscalls/Thread.h"
#include "LinuxSyscalls/ThreadCensus.h"
#include "LinuxSyscalls/Utils/Threads.h"
#include "LinuxSyscalls/x32/Syscalls.h"
#include "LinuxSyscalls/x64/Syscalls.h"
#include "LinuxSyscalls/x32/Types.h"
#include "LinuxSyscalls/x64/Types.h"
#include "Thunks.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/SignalScopeGuards.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/MathUtils.h>
#include <FEXCore/Utils/TypeDefines.h>
#include <FEXCore/Utils/FileLoading.h>
#include <FEXCore/fextl/fmt.h>
#include <FEXCore/fextl/sstream.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/vector.h>
#include <FEXHeaderUtils/Filesystem.h>
#include <FEXHeaderUtils/Syscalls.h>

#include <algorithm>
#include <alloca.h>
#include <atomic>
#include <charconv>
#include <functional>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <memory>
#include <regex>
#include <sched.h>
#include <span>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <signal.h>
#include <system_error>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>

namespace FEX::HLE {
class SignalDelegator;
SyscallHandler* _SyscallHandler {};

// 2026-08-03 diagnostic: FEX_TRACE_CLONE=1 logs the guest-visible clone
// return value alongside child-thread bring-up, so we can correlate a
// crashing probe run's fault with the sequence of clone returns that
// preceded it.  Same async-signal-safe raw write() shape as
// FEX_TRACE_SIGNALS.  Cheap fast-path; no output when unset.
namespace CloneTrace {
static std::atomic<int> Fd {-2};
inline int Get() {
  int f = Fd.load(std::memory_order_acquire);
  if (f == -2) {
    if (getenv("FEX_TRACE_CLONE")) {
      f = ::open("/tmp/fex_clone_trace.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    } else {
      f = -1;
    }
    int expected = -2;
    if (!Fd.compare_exchange_strong(expected, f)) {
      if (f >= 0) ::close(f);
      f = Fd.load(std::memory_order_acquire);
    }
  }
  return f;
}
inline void Emit(const char* line, size_t n) {
  int f = Get();
  if (f < 0) return;
  ssize_t off = 0;
  while (off < static_cast<ssize_t>(n)) {
    ssize_t w = ::write(f, line + off, n - off);
    if (w <= 0) break;
    off += w;
  }
}
inline int Hex(char* dst, uint64_t v) {
  char tmp[18];
  int n = 0;
  if (v == 0) { tmp[n++] = '0'; }
  while (v) { int d = v & 0xf; tmp[n++] = (d < 10 ? '0' + d : 'a' + d - 10); v >>= 4; }
  int len = 0;
  dst[len++] = '0'; dst[len++] = 'x';
  while (n > 0) dst[len++] = tmp[--n];
  return len;
}
}  // namespace CloneTrace

template<bool IncrementOffset, typename T>
uint64_t GetDentsEmulation(int fd, T* dirp, uint32_t count) {
  uint64_t Result = syscall(SYSCALL_DEF(getdents64), static_cast<uint64_t>(fd), dirp, static_cast<uint64_t>(count));

  // Now copy back in to the array we were given
  if (Result != -1) {
    // If the outgoing d_ino is smaller than the incoming d_ino from the kernel
    // Then we need to check for overflow before writing any of the data back
    if constexpr (sizeof(decltype(FEX::HLE::x64::linux_dirent_64::d_ino)) > sizeof(decltype(T::d_ino))) {
      uint64_t TmpOffset = 0;
      while (TmpOffset < Result) {
        FEX::HLE::x64::linux_dirent_64* Tmp = (FEX::HLE::x64::linux_dirent_64*)(reinterpret_cast<uint64_t>(dirp) + TmpOffset);
        decltype(T::d_ino) Result_d_ino = Tmp->d_ino;

        if (Result_d_ino != Tmp->d_ino) {
          // The resulting d_ino truncated, return error
          return -EOVERFLOW;
        }
        TmpOffset += Tmp->d_reclen;
      }
    }

    uint64_t Offset = 0;
    uint64_t TmpOffset = 0;
    size_t OffsetIndex = 1;
    // With how the emulation occurs we will always return a smaller buffer than what was given to us.
    // We need to be careful with the in-place translation that occurs here, the data returning to the guest is guaranteed to be smaller
    // than the data returned by getdents64.
    // This means FEX is guaranteed to /never/ fill the full getdents buffer to the guest, but we may temporarily use it all.
    while (TmpOffset < Result) {
      T* Outgoing = (T*)(reinterpret_cast<uint64_t>(dirp) + Offset);
      FEX::HLE::x64::linux_dirent_64* Tmp = (FEX::HLE::x64::linux_dirent_64*)(reinterpret_cast<uint64_t>(dirp) + TmpOffset);

      if (!Tmp->d_reclen) {
        break;
      }

      size_t NewRecLen = FEXCore::AlignUp(Tmp->d_reclen - (sizeof(std::remove_reference<decltype(*Tmp)>::type) - sizeof(*Outgoing)),
                                          alignof(decltype(Tmp->d_ino)));
      Outgoing->d_ino = Tmp->d_ino;

      // 32-bit getdents can't safely handle d_off
      // A safe way of emulating this is to just use an incrementing offset from 1
      Outgoing->d_off = IncrementOffset ? OffsetIndex : Tmp->d_off;
      size_t OffsetOfName = offsetof(std::remove_reference<decltype(*Tmp)>::type, d_name);
      Outgoing->d_reclen = NewRecLen;

      // Copies null character as well
      size_t NameLength = Tmp->d_reclen - OffsetOfName - 1;
      memmove(Outgoing->d_name, Tmp->d_name, NameLength);

      // Copy the hidden d_type flag
      Outgoing->d_name[Outgoing->d_reclen - offsetof(T, d_name) - 1] = Tmp->d_type;

      TmpOffset += Tmp->d_reclen;

      if (FEX::HLE::_SyscallHandler->FM.IsProtectedFile(fd, Outgoing->d_ino)) {
        continue;
      }

      // Outgoing is 5 bytes smaller
      Offset += NewRecLen;

      ++OffsetIndex;
    }
    Result = Offset;
  }
  SYSCALL_ERRNO();
}

template uint64_t GetDentsEmulation<false>(int, FEX::HLE::x64::linux_dirent*, uint32_t);

template uint64_t GetDentsEmulation<true>(int, FEX::HLE::x32::linux_dirent_32*, uint32_t);

static fextl::string GetShebangInterpFile(std::span<char> Data) {
  // File isn't large enough to even contain a shebang.
  if (Data.size() <= 2) {
    return {};
  }

  // Handle shebang files.
  if (Data[0] == '#' && Data[1] == '!') {
    fextl::string InterpreterLine {Data.begin() + 2, // strip off "#!" prefix
                                   std::find(Data.begin(), Data.end(), '\n')};
    fextl::vector<std::string_view> ShebangArguments = FHU::ParseArgumentsFromString(InterpreterLine);

    if (ShebangArguments.empty()) {
      return {};
    }

    // Executable argument
    fextl::string ShebangProgram(ShebangArguments[0]);

    // For absolute interpreter paths, prefer the emulated path (rootfs / thunk overlay,
    // with symlink resolution) and fall back to the host path if the interpreter is
    // present only there. This mirrors the execve pathname lookup in ExecveHandler.
    if (ShebangProgram[0] == '/') {
      auto Path = FEX::HLE::_SyscallHandler->FM.GetEmulatedPath(ShebangProgram.c_str(), true);
      if (!Path.empty() && FHU::Filesystem::Exists(Path)) {
        return Path;
      }
    }

    if (FHU::Filesystem::Exists(ShebangProgram)) {
      return ShebangProgram;
    }
  }

  return {};
}

static fextl::string GetShebangInterpFD(int FD) {
  // We don't know the state of the FD coming in since this might be a guest tracked FD.
  // Need to be extra careful here not to adjust file offsets and status flags.
  //
  // Can't use dup since that makes the FD have the same file description backing both FDs.

  // The maximum length of the shebang line is `#!` + 255 chars
  std::array<char, 257> Header;
  const auto ChunkSize = 257l;
  const auto ReadSize = pread(FD, Header.data(), ChunkSize, 0);

  return GetShebangInterpFile(std::span<char>(Header.data(), ReadSize));
}

static fextl::string GetShebangInterpFilename(const fextl::string& Filename) {
  // Open the Filename to determine if it is a shebang file.
  int FD = open(Filename.c_str(), O_RDONLY | O_CLOEXEC);
  if (FD == -1) {
    return {};
  }

  auto Interp = GetShebangInterpFD(FD);
  close(FD);
  return Interp;
}

uint64_t ExecveHandler(FEXCore::Core::CpuStateFrame* Frame, const char* pathname, char* const* argv, char* const* envp, ExecveAtArgs Args) {
  auto SyscallHandler = FEX::HLE::_SyscallHandler;
  Frame->Thread->CTX->FlushAndCloseCodeMap();

  fextl::string Filename {};

  fextl::string RootFS = SyscallHandler->RootFSPath();
  ELFLoader::ELFContainer::ELFType Type {};
  ELFLoader::ELFContainer::ELFType InterpreterType {};

  // AT_EMPTY_PATH is only used if the pathname is empty.
  const bool IsFDExec = (Args.flags & AT_EMPTY_PATH) && strlen(pathname) == 0;
  fextl::string FDExecEnv;
  fextl::string FDSeccompEnv;

  fextl::string ShebangInterpreter {};

  if (IsFDExec) {
    Type = ELFLoader::ELFContainer::GetELFType(Args.dirfd);

    ShebangInterpreter = GetShebangInterpFD(Args.dirfd);
  } else {
    // For absolute paths, check the rootfs first (if available)
    if (pathname[0] == '/') {
      auto Path = SyscallHandler->FM.GetEmulatedPath(pathname, true);
      if (!Path.empty() && FHU::Filesystem::Exists(Path)) {
        Filename = std::move(Path);
      } else {
        Filename = pathname;
      }
    } else {
      Filename = pathname;
    }

    bool exists = FHU::Filesystem::Exists(Filename);
    if (!exists) {
      return -ENOENT;
    }

    int pid = getpid();

    char PidSelfPath[50];
    snprintf(PidSelfPath, 50, "/proc/%i/exe", pid);

    if (strcmp(pathname, "/proc/self/exe") == 0 || strcmp(pathname, "/proc/thread-self/exe") == 0 || strcmp(pathname, PidSelfPath) == 0) {
      // If the application is trying to execve `/proc/self/exe` or its variants,
      // then we need to redirect this path to the true application path.
      // This is because this path is a symlink to the executing application, which is always `FEX`.
      // ex: JRE and shapez.io do this self-execution.
      Filename = SyscallHandler->Filename();
    }

    Type = ELFLoader::ELFContainer::GetELFType(Filename);

    ShebangInterpreter = GetShebangInterpFilename(Filename);
  }

  const bool IsShebang = !ShebangInterpreter.empty();
  if (IsShebang) {
    InterpreterType = ELFLoader::ELFContainer::GetELFType(ShebangInterpreter);
  }

  if (!IsShebang && Type == ELFLoader::ELFContainer::ELFType::TYPE_NONE) {
    // If our interpeter doesn't support this file format AND ELF format is NONE then ENOEXEC
    // binfmt_misc could end up handling this case but we can't know that without parsing binfmt_misc ourselves
    // Return -ENOEXEC until proven otherwise
    return -ENOEXEC;
  }

  fextl::vector<const char*> EnvpArgs {};
  char* const* EnvpPtr = envp;
  bool FDExecCopy {};

  auto SeccompFD = SyscallHandler->SeccompEmulator.SerializeFilters(Frame);
  const auto HasSeccomp = SeccompFD.has_value() && *SeccompFD != -1;

  auto CloseSeccompFD = [&HasSeccomp, &SeccompFD]() {
    if (HasSeccomp) {
      close(*SeccompFD);
    }
  };

  auto CloseFDExecFD = [&FDExecCopy, &Args]() {
    if (FDExecCopy) {
      close(Args.dirfd);
    }
  };

  // If we don't have the interpreter installed we need to be extra careful for ENOEXEC
  // Reasoning is that if we try executing a file from FEXLoader then this process loses the ENOEXEC flag
  // Kernel does its own checks for file format support for this
  // We can only call execve directly if we both have an interpreter installed AND were ran with the interpreter
  // If the user ran FEX through FEXLoader then we must go down the emulated path
  uint64_t Result {};

  // In some cases the FD passed in to execveat needs to be copied.
  const bool NeedsFDCopy = [&]() {
    // No need for FD copy when not using FD.
    if (!IsFDExec) {
      return false;
    }

    if (SyscallHandler->IsHostKernelVersionAtLeast(999, 0, 0)) {
      // Older kernel versions have a bug with the combination of binfmt_misc and anonymous file FDs that set CLOEXEC.
      return false;
    }

    int Flags = fcntl(Args.dirfd, F_GETFD);
    if (!(Flags & FD_CLOEXEC)) {
      // No need for FD copy if FD_CLOEXEC isn't set.
      return false;
    }

    return true;
  }();

  // If the FEX interpreter is installed then just execve the ELF file
  // This will stay inside of our emulated environment since binfmt_misc will capture it
  const bool IsBinfmtCompatible = SyscallHandler->IsInterpreterInstalled() && !NeedsFDCopy &&
                                  (Type == ELFLoader::ELFContainer::ELFType::TYPE_X86_32 || Type == ELFLoader::ELFContainer::ELFType::TYPE_X86_64);

  // We are trying to execute an ELF of a different architecture
  // We can't know if we can support this without architecture specific checks and binfmt_misc parsing
  // Just execve it and let the kernel handle the process
  const bool IsOtherELF = Type == ELFLoader::ELFContainer::ELFType::TYPE_OTHER_ELF;

  // Need to copy over envp variables if we are appending data.
  // Only situation in which an envp copy needs to occur is if we are doing an FD execveat and binfmt_misc can't handle it.
  // Additional tasks that require envp copying in the future:
  // - seccomp inheritance
  // - FEXServer FD inheritance (unshare(CLONE_NEWNET))
  // - FD_CLOEXEC set on FD on anonymous file FD.
  const bool NeedsEnvpCopy = (IsFDExec && !(IsBinfmtCompatible || IsOtherELF)) || HasSeccomp || NeedsFDCopy;

  // We are trying to execute a shebang handled by a different architecture interpreter (e.g. /usr/bin/python from the host FS).
  // In this case we just defer to the kernel.
  const bool IsForeignShebang = (IsShebang && InterpreterType == ELFLoader::ELFContainer::ELFType::TYPE_OTHER_ELF);

  if (NeedsEnvpCopy) {
    if (envp) {
      auto OldEnvp = envp;
      while (*OldEnvp) {
        ///< Copy the pointers to our own vector of environment variables.
        EnvpArgs.emplace_back(*OldEnvp);
        ++OldEnvp;
      }
    }

    if (!IsBinfmtCompatible || NeedsFDCopy) {
      if (NeedsFDCopy) {
        // FEX needs the FD to live past execve when binfmt_misc isn't used,
        // so duplicate the FD if FD_CLOEXEC is set, which removes the FD_CLOEXEC flag.
        Args.dirfd = dup(Args.dirfd);
        FDExecCopy = true;
      }

      // Remove AT_EMPTY_PATH flag now.
      // We need to emulate this flag with `FEX_EXECVEFD` environment variable.
      // If we passed this flag through to the real `execveat` then the target FD wouldn't get emulated by FEX.
      Args.flags &= ~AT_EMPTY_PATH;

      // Create the environment variable to pass the FD to our FEX.
      // Needs to stick around until execveat completes.
      FDExecEnv = fextl::fmt::format("FEX_EXECVEFD={}", Args.dirfd);

      // Insert the FD for FEX to track.
      EnvpArgs.emplace_back(FDExecEnv.data());
    }

    if (HasSeccomp) {
      // Create the environment variable to pass the FD to our FEX.
      // Needs to stick around until execveat completes.
      FDSeccompEnv = fextl::fmt::format("FEX_SECCOMPFD={}", *SeccompFD);

      // Insert the FD for FEX to track.
      EnvpArgs.emplace_back(FDSeccompEnv.data());
    }

    // Emplace nullptr at the end to stop
    EnvpArgs.emplace_back(nullptr);

    ///< Set the EnvpPtr to our copy.
    EnvpPtr = const_cast<char* const*>(EnvpArgs.data());
  }

  if (!IsFDExec && (IsForeignShebang || IsOtherELF || !IsBinfmtCompatible)) {
    // With a merged RootFS, the entire real filesystem is visible through the rootfs
    // prefix. If we are executing a non-emulated binary, we should do so through the host
    // path.

    auto Path = SyscallHandler->FM.GetHostPath(Filename, true);
    if (!Path.empty() && FHU::Filesystem::Exists(Path)) {
      Filename = std::move(Path);
    }
  }

  if (IsBinfmtCompatible || IsOtherELF || IsForeignShebang) {
    Result = ::syscall(SYS_execveat, Args.dirfd, Filename.c_str(), argv, EnvpPtr, Args.flags);
    CloseSeccompFD();
    CloseFDExecFD();
    SYSCALL_ERRNO();
  }

  // If we are executing an emulated interpreter shebang file through the loader,
  // we need to strip the RootFS prefix. The loader will pass this filename to the
  // interpreter as-is, which will access it using RootFS redirection.
  // Note that unlike above, the prefix is stripped unconditionally (AliasedOnly=false),
  // and the script path need not exist in the host.
  if (IsShebang) {
    auto Path = SyscallHandler->FM.GetHostPath(Filename, false);
    if (!Path.empty()) {
      Filename = std::move(Path);
    }
  }

  // We don't have an interpreter installed or we are executing a non-ELF executable
  // We now need to munge the arguments
  const char NullString[] = "";
  fextl::vector<const char*> ExecveArgs = SyscallHandler->GetCodeLoader()->GetExecveArguments();

  if (argv) {
    // Overwrite the filename with the new one we are redirecting to
    ExecveArgs.emplace_back(Filename.c_str());

    auto OldArgv = argv;

    // It is valid to provide nullptr first argument.
    if (*OldArgv) {
      // Skip filename argument
      ++OldArgv;
      while (*OldArgv) {
        // Append the arguments together
        ExecveArgs.emplace_back(*OldArgv);
        ++OldArgv;
      }
    } else {
      // Linux kernel will stick an empty argument in to the argv list if none are provided.
      ExecveArgs.emplace_back(NullString);
    }

    // Emplace nullptr at the end to stop
    ExecveArgs.emplace_back(nullptr);
  }

  Result = ::syscall(SYS_execveat, Args.dirfd, "/proc/self/exe", const_cast<char* const*>(ExecveArgs.data()), EnvpPtr, Args.flags);
  CloseSeccompFD();
  CloseFDExecFD();

  SYSCALL_ERRNO();
}

static bool AnyFlagsSet(uint64_t Flags, uint64_t Mask) {
  return (Flags & Mask) != 0;
}

static bool AllFlagsSet(uint64_t Flags, uint64_t Mask) {
  return (Flags & Mask) == Mask;
}

struct StackFrameData {
  FEX::HLE::ThreadStateObject* Thread {};
  FEXCore::Context::Context* CTX {};
  FEXCore::Core::CpuStateFrame NewFrame {};
  FEX::HLE::clone3_args GuestArgs {};
};

struct StackFramePlusRet {
  uint64_t Ret;
  StackFrameData Data;
  uint64_t Pad;
};

[[noreturn]]
static void CloneBody(StackFrameData* Data, bool NeedsDataFree) {
  uint64_t Result = FEX::HLE::HandleNewClone(Data->Thread, Data->CTX, &Data->NewFrame, &Data->GuestArgs);
  auto Stack = Data->GuestArgs.NewStack;
  if (NeedsDataFree) {
    FEXCore::Allocator::free(Data);
  }

  FEX::LinuxEmulation::Threads::DeallocateStackObjectAndExit(Stack, Result);
  FEX_UNREACHABLE;
}

[[noreturn]]
static void Clone3HandlerRet() {
  StackFrameData* Data = (StackFrameData*)alloca(0);
  CloneBody(Data, false);
}

static int Clone2HandlerRet(void* arg) {
  StackFrameData* Data = (StackFrameData*)arg;
  CloneBody(Data, true);
}

// Clone3 flags
#ifndef CLONE_CLEAR_SIGHAND
#define CLONE_CLEAR_SIGHAND 0x100000000ULL
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef CLONE_NEWTIME
// Overlaps CSIGNAL, can only be used with clone3 and not clone2
#define CLONE_NEWTIME 0x00000080ULL
#endif

static void PrintFlags(uint64_t Flags) {
#define FLAGPRINT(x, y) \
  if (Flags & (y)) LogMan::Msg::IFmt("\tFlag: " #x)
  FLAGPRINT(CSIGNAL, 0x000000FF);
  FLAGPRINT(CLONE_VM, 0x00000100);
  FLAGPRINT(CLONE_FS, 0x00000200);
  FLAGPRINT(CLONE_FILES, 0x00000400);
  FLAGPRINT(CLONE_SIGHAND, 0x00000800);
  FLAGPRINT(CLONE_PTRACE, 0x00002000);
  FLAGPRINT(CLONE_VFORK, 0x00004000);
  FLAGPRINT(CLONE_PARENT, 0x00008000);
  FLAGPRINT(CLONE_THREAD, 0x00010000);
  FLAGPRINT(CLONE_NEWNS, 0x00020000);
  FLAGPRINT(CLONE_SYSVSEM, 0x00040000);
  FLAGPRINT(CLONE_SETTLS, 0x00080000);
  FLAGPRINT(CLONE_PARENT_SETTID, 0x00100000);
  FLAGPRINT(CLONE_CHILD_CLEARTID, 0x00200000);
  FLAGPRINT(CLONE_DETACHED, 0x00400000);
  FLAGPRINT(CLONE_UNTRACED, 0x00800000);
  FLAGPRINT(CLONE_CHILD_SETTID, 0x01000000);
  FLAGPRINT(CLONE_NEWCGROUP, 0x02000000);
  FLAGPRINT(CLONE_NEWUTS, 0x04000000);
  FLAGPRINT(CLONE_NEWIPC, 0x08000000);
  FLAGPRINT(CLONE_NEWUSER, 0x10000000);
  FLAGPRINT(CLONE_NEWPID, 0x20000000);
  FLAGPRINT(CLONE_NEWNET, 0x40000000);
  FLAGPRINT(CLONE_IO, 0x80000000);
  FLAGPRINT(CLONE_PIDFD, 0x00001000);
#undef FLAGPRINT
};

static uint64_t Clone2Handler(FEXCore::Core::CpuStateFrame* Frame, FEX::HLE::clone3_args* args) {
  StackFrameData* Data = (StackFrameData*)FEXCore::Allocator::malloc(sizeof(StackFrameData));
  Data->Thread = FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame);
  Data->CTX = Frame->Thread->CTX;
  Data->GuestArgs = *args;

  // Create a copy of the parent frame
  memcpy(&Data->NewFrame, Frame, sizeof(FEXCore::Core::CpuStateFrame));

  // Remove flags that will break us
  constexpr uint64_t INVALID_FOR_HOST = CLONE_SETTLS;
  uint64_t Flags = (args->args.flags & ~INVALID_FOR_HOST) | args->args.exit_signal;
  uint64_t Result = ::clone(Clone2HandlerRet,                                    // To be called function
                            (void*)((uint64_t)args->NewStack + args->StackSize), // Stack
                            Flags,                                               // Flags
                            Data,                                                // Argument
                            (pid_t*)args->args.parent_tid,                       // parent_tid
                            0,                                                   // XXX: What is correct for this? tls
                            (pid_t*)args->args.child_tid);                       // child_tid

  // Only parent will get here
  SYSCALL_ERRNO();
}

static uint64_t Clone3Handler(FEXCore::Core::CpuStateFrame* Frame, FEX::HLE::clone3_args* args) {
  constexpr size_t Offset = sizeof(StackFramePlusRet);
  StackFramePlusRet* Data = (StackFramePlusRet*)(reinterpret_cast<uint64_t>(args->NewStack) + args->StackSize - Offset);
  Data->Ret = (uint64_t)Clone3HandlerRet;
  Data->Data.Thread = FEX::HLE::ThreadManager::GetStateObjectFromCPUState(Frame);
  Data->Data.CTX = Frame->Thread->CTX;
  Data->Data.GuestArgs = *args;

  FEX::HLE::kernel_clone3_args HostArgs {};
  HostArgs.flags = args->args.flags;
  HostArgs.pidfd = args->args.pidfd;
  HostArgs.child_tid = args->args.child_tid;
  HostArgs.parent_tid = args->args.parent_tid;
  HostArgs.exit_signal = args->args.exit_signal;
  // Host stack is always created
  HostArgs.stack = reinterpret_cast<uint64_t>(args->NewStack);
  HostArgs.stack_size = args->StackSize - Offset; // Needs to be 16 byte aligned
  HostArgs.tls = 0;                               // XXX: What is correct for this?
  HostArgs.set_tid = args->args.set_tid;
  HostArgs.set_tid_size = args->args.set_tid_size;
  HostArgs.cgroup = args->args.cgroup;

  // Create a copy of the parent frame
  memcpy(&Data->Data.NewFrame, Frame, sizeof(FEXCore::Core::CpuStateFrame));
  uint64_t Result = ::syscall(SYSCALL_DEF(clone3), &HostArgs, sizeof(HostArgs));

  // Only parent will get here
  SYSCALL_ERRNO();
};

uint64_t CloneHandler(FEXCore::Core::CpuStateFrame* Frame, FEX::HLE::clone3_args* args) {
  uint64_t flags = args->args.flags;
  {
    // FEX_TRACE_CLONE=1 diagnostic entry: log the flags + calling TID
    // before we branch into any of the fork/thread paths.
    char buf[192];
    int len = 0;
    const char* p = "CLONE-ENTRY caller_tid=";
    while (*p) buf[len++] = *p++;
    len += CloneTrace::Hex(buf + len, (uint64_t)::syscall(SYS_gettid));
    p = " flags="; while (*p) buf[len++] = *p++;
    len += CloneTrace::Hex(buf + len, flags);
    p = " type="; while (*p) buf[len++] = *p++;
    len += CloneTrace::Hex(buf + len, (uint64_t)args->Type);
    p = " stack="; while (*p) buf[len++] = *p++;
    len += CloneTrace::Hex(buf + len, args->args.stack);
    p = " tls="; while (*p) buf[len++] = *p++;
    len += CloneTrace::Hex(buf + len, args->args.tls);
    buf[len++] = '\n';
    CloneTrace::Emit(buf, len);
  }

  // CLONE_CLEAR_SIGHAND (kernel 5.5+) is the posix_spawn-style optimisation:
  // the child resets all non-default sigactions to SIG_DFL atomically with the
  // clone, so glibc doesn't have to do a sigaction() loop after fork. We can't
  // pass the flag through to the host kernel because it would also reset
  // *FEX's own* host signal handlers (SIGSEGV/SIGILL/SIGBUS for the dispatcher,
  // SIGUSR1/SIGUSR2 for thread management, the SignalDelegator pause signal),
  // breaking the runtime — observed as a futex-wait deadlock on Steam i686.
  //
  // Silently strip the flag and proceed. The guest's tracked GuestAction
  // entries in SignalDelegator::HostHandlers will be slightly stale (set to
  // whatever the parent had rather than SIG_DFL), but the real consumers of
  // CLONE_CLEAR_SIGHAND (glibc posix_spawn and pressure-vessel container
  // setup) all execve() immediately after the clone, which resets the entire
  // SignalDelegator state in the new address space anyway. Returning EINVAL —
  // as we used to — left pressure-vessel stuck partway through container init.
  flags &= ~CLONE_CLEAR_SIGHAND;
  args->args.flags &= ~CLONE_CLEAR_SIGHAND;

  auto HasUnhandledFlags = [](FEX::HLE::clone3_args* args) -> bool {
    constexpr uint64_t UNHANDLED_FLAGS = CLONE_NEWNS |
                                         // CLONE_UNTRACED |
                                         CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET |
                                         CLONE_IO | CLONE_INTO_CGROUP;

    if ((args->args.flags & UNHANDLED_FLAGS) != 0) {
      // Basic unhandled flags
      return true;
    }

    if (args->args.set_tid_size > 0) {
      // set_tid isn't exposed through anything other than clone3
      return true;
    }

    if (args->Type == TypeOfClone::TYPE_CLONE3) {
      if (AnyFlagsSet(args->args.flags, CLONE_NEWTIME)) {
        // New time namespace overlaps with CSIGNAL, only available in clone3
        return true;
      }
    }

    if (AnyFlagsSet(args->args.flags, CLONE_THREAD)) {
      if (!AllFlagsSet(args->args.flags, CLONE_SYSVSEM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND)) {
        LogMan::Msg::IFmt("clone: CLONE_THREAD: Unsupported flags w/ CLONE_THREAD (Shared Resources), {:X}", args->args.flags);
        return false;
      }
    } else {
      if (AnyFlagsSet(args->args.flags, CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_VM)) {
        // CLONE_VM is particularly nasty here
        // Memory regions at the point of clone(More similar to a fork) are shared
        LogMan::Msg::IFmt("clone: Unsupported flags w/o CLONE_THREAD (Shared Resources), {:X}", args->args.flags);
        return false;
      }
    }

    // We support everything here
    return false;
  };

  // If there are flags that can't be handled regularly then we need to hand off to the true clone handler
  if (HasUnhandledFlags(args)) {
    if (!AnyFlagsSet(flags, CLONE_THREAD)) {
      // Has an unsupported flag
      // Fall to a handler that can handle this case

      args->SignalMask = ~0ULL;
      ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &args->SignalMask, &args->SignalMask, sizeof(args->SignalMask));

      // Need to create a stack for the host thread.
      // LockBeforeFork grabs the allocator mutex to block allocations temporarily, so this must be allocated before
      args->StackSize = FEX::LinuxEmulation::Threads::STACK_SIZE;
      args->NewStack = FEX::LinuxEmulation::Threads::AllocateStackObject();

      FEX::HLE::_SyscallHandler->LockBeforeFork(Frame->Thread);

      uint64_t Result {};
      if (args->Type == TYPE_CLONE2) {
        Result = Clone2Handler(Frame, args);
      } else {
        Result = Clone3Handler(Frame, args);
      }

      if (Result != 0) {
        // Parent
        // Unlock the mutexes on both sides of the fork
        FEX::HLE::_SyscallHandler->UnlockAfterFork(Frame->Thread, false);

        ::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &args->SignalMask, nullptr, sizeof(args->SignalMask));

        // Census: the "unhandled flags" path, where FEX hands the clone
        // straight to the host kernel instead of building a FEX thread
        // object. Result is the raw kernel return, so only a positive value
        // is a child TID.
        if (static_cast<int64_t>(Result) > 0 && FEX::HLE::ThreadCensus::Enabled()) {
          FEX::HLE::ThreadCensus::OnThreadCreate(FEX::HLE::ThreadCensus::CloneKind::RawClone, Result, Result, FHU::Syscalls::gettid(),
                                                 Frame->State.rip, args->args.flags);
        }
      }
      return Result;
    } else {
      LogMan::Msg::IFmt("Unsupported flag with CLONE_THREAD. This breaks TLS, falling down classic thread path");
      PrintFlags(flags);
    }
  }

  constexpr uint64_t TASK_MAX = (1ULL << 48); // 48-bits until we can query the host side VA sanely. AArch64 doesn't expose this in cpuinfo
  if (args->args.tls && args->args.tls >= TASK_MAX) {
    return -EPERM;
  }

  auto Thread = Frame->Thread;

  if (AnyFlagsSet(flags, CLONE_PTRACE)) {
    PrintFlags(flags);
    LogMan::Msg::DFmt("clone: Ptrace* not supported");
  }

  if (!(flags & CLONE_THREAD)) {
    // CLONE_PARENT is ignored (Implied by CLONE_THREAD)
    return FEX::HLE::ForkGuest(Thread, Frame, args);
  } else {
    auto NewThread = FEX::HLE::CreateNewThread(Thread->CTX, Frame, args);

    // Return the new threads TID
    uint64_t Result = NewThread->ThreadInfo.TID;

    if (flags & CLONE_VFORK) {
      // If VFORK is set then the calling process is suspended until the thread exits with execve or exit
      NewThread->ExecutionThread->join(nullptr);

      // Normally a thread cleans itself up on exit. But because we need to join, we are now responsible
      FEX::HLE::_SyscallHandler->TM.DestroyThread(NewThread);
    }

    // Belt-and-braces: zero is never a valid child TID and glibc's
    // create_thread only tests `< 0` for failure, so a stray 0 would be
    // accepted as success and stored as `pd->tid`, corrupting downstream
    // pthread_join / pthread_kill / pd-recycling. The primary fix moves
    // the DestroyThread zombie marker off TID (ThreadInfo.IsZombie), so
    // this branch should never be taken. If it is, we've introduced a
    // second instance of the same overload — surface it as EAGAIN, which
    // is the errno glibc treats as "transient, try again."
    if (Result == 0) {
      LogMan::Msg::EFmt("CLONE_THREAD returned TID=0 to guest (should be impossible); returning EAGAIN");
      Result = static_cast<uint64_t>(-EAGAIN);
    }

    {
      // FEX_TRACE_CLONE=1: log the value we return to the guest for the
      // thread-creating clone. Result carries the child TID unless the
      // never-return-zero guard rewrote it to -EAGAIN.
      char buf[192];
      int len = 0;
      const char* p = "CLONE-RETURN-THREAD caller_tid=";
      while (*p) buf[len++] = *p++;
      len += CloneTrace::Hex(buf + len, (uint64_t)::syscall(SYS_gettid));
      p = " child_tid=";
      while (*p) buf[len++] = *p++;
      len += CloneTrace::Hex(buf + len, Result);
      p = " errno=";
      while (*p) buf[len++] = *p++;
      len += CloneTrace::Hex(buf + len, (uint64_t)errno);
      buf[len++] = '\n';
      CloneTrace::Emit(buf, len);
    }
    SYSCALL_ERRNO();
  }
};

uint64_t SyscallHandler::HandleBRK(FEXCore::Core::CpuStateFrame* Frame, void* Addr) {
  std::lock_guard<std::mutex> lk(MMapMutex);

  uint64_t Result;

  if (Addr == nullptr) { // Just wants to get the location of the program break atm
    Result = DataSpace + DataSpaceSize;
  } else {
    // Allocating out data space
    uint64_t NewEnd = reinterpret_cast<uint64_t>(Addr);
    if (NewEnd < DataSpace) {
      // Not allowed to move brk end below original start
      // Set the size to zero
      DataSpaceSize = 0;

      // Munmap the whole space.
      [[maybe_unused]] auto ok = GuestMunmap(Frame->Thread, reinterpret_cast<void*>(DataSpace), DataSpaceMappedSize);
      LOGMAN_THROW_A_FMT(ok != -1, "Munmap failed");
      DataSpaceMappedSize = 0;
    } else {
      uint64_t NewSize = NewEnd - DataSpace;
      uint64_t NewSizeAligned = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE);

      if (NewSizeAligned < DataSpaceMappedSize) {
        // If we are shrinking the brk then munmap the ranges
        // That way we gain the memory back and also give the application zero pages if it allocates again
        // DataspaceMaxSize is always page aligned

        uint64_t RemainingSize = DataSpaceMappedSize - NewSizeAligned;
        // We have pages we can unmap
        auto ok = GuestMunmap(Frame->Thread, reinterpret_cast<void*>(DataSpace + NewSizeAligned), RemainingSize);
        LOGMAN_THROW_A_FMT(ok != -1, "Munmap failed");

        DataSpaceMappedSize = NewSizeAligned;
      } else if (NewSize > DataSpaceMappedSize) {
        uint64_t AllocateNewSize = FEXCore::AlignUp(NewSize, FEXCore::Utils::FEX_PAGE_SIZE) - DataSpaceMappedSize;
        if (!Is64BitMode() && (DataSpace + DataSpaceMappedSize + AllocateNewSize > 0x1'0000'0000ULL)) {
          // If we are 32bit and we tried going about the 32bit limit then out of memory
          return DataSpace + DataSpaceSize;
        }

        uint64_t NewBRK {};
        NewBRK = (uint64_t)GuestMmap(Frame->Thread, (void*)(DataSpace + DataSpaceMappedSize), AllocateNewSize, PROT_READ | PROT_WRITE,
                                     MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (FEX::HLE::HasSyscallError(NewBRK)) {
          // If we couldn't allocate a new region then out of memory
          return DataSpace + DataSpaceSize;
        } else {
          // Increase our BRK size
          DataSpaceMappedSize += AllocateNewSize;
        }
      }

      DataSpaceSize = NewSize;
    }
    Result = DataSpace + DataSpaceSize;
  }
  return Result;
}

void SyscallHandler::DefaultProgramBreak(uint64_t Base, uint64_t Size) {
  DataSpace = Base;

  // The frontend passes this a full 8MB of SBRK space that is mapped PROT_READ | PROT_WRITE.
  // This ensures there is some free space in front of brk, but isn't required to be reserved.
  // Unmap it now to ensure other allocations can be put in the intersecting range.
  [[maybe_unused]] auto ok = GuestMunmap(nullptr, reinterpret_cast<void*>(DataSpace), Size);
  LOGMAN_THROW_A_FMT(ok != -1, "Munmap failed");
  DataSpaceMappedSize = 0;
}

SyscallHandler::SyscallHandler(FEXCore::Context::Context* _CTX, FEX::HLE::SignalDelegator* _SignalDelegation, FEX::HLE::ThunkHandler* ThunkHandler)
  : TM {_CTX, _SignalDelegation}
  , SeccompEmulator {this, _SignalDelegation}
  , FM {_CTX}
  , CTX {_CTX}
  , SignalDelegation {_SignalDelegation}
  , ThunkHandler {ThunkHandler} {
  FEX::HLE::_SyscallHandler = this;
  HostKernelVersion = CalculateHostKernelVersion();
  GuestKernelVersion = CalculateGuestKernelVersion();
  Alloc32Handler = FEX::HLE::Create32BitAllocator();

  SignalDelegation->RegisterHostSignalHandler(SIGSEGV, HandleSegfault, true);

  ExtendedMetaData = FEX::VolatileMetadata::ParseExtendedVolatileMetadata(FEXCore::Config::Get_EXTENDEDVOLATILEMETADATA()());

  // The mtrack SMC path drives host mprotect() with FEX_PAGE_SIZE (4K) granularity
  // and the guest is told AT_PAGESZ=4096, but there is no host-page-size awareness
  // anywhere in LinuxEmulation.  On a host with a larger page size a 4K-aligned
  // mprotect is rejected outright (EINVAL -> the AFmt aborts in
  // SyscallsSMCTracking.cpp), and the cases that do go through degrade to
  // host-page-granularity protection with re-protect races.  Warn loudly rather
  // than let someone burn a day chasing the fallout.
  if (const long HostPageSize = sysconf(_SC_PAGESIZE); HostPageSize > 0 && static_cast<uint64_t>(HostPageSize) != FEXCore::Utils::FEX_PAGE_SIZE) {
    if (SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK) {
      LogMan::Msg::EFmt("Host page size is {} but FEX's SMC tracking assumes {}. "
                        "mtrack SMC detection is unsupported on this kernel and will misbehave or abort; "
                        "boot a {}-page kernel or run with FEX_SMCCHECKS=full.",
                        HostPageSize, FEXCore::Utils::FEX_PAGE_SIZE, FEXCore::Utils::FEX_PAGE_SIZE);
    } else {
      LogMan::Msg::IFmt("Host page size is {} but FEX assumes {}; SMCChecks is not mtrack so the SMC path is not affected.", HostPageSize,
                        FEXCore::Utils::FEX_PAGE_SIZE);
    }
  }

  // FEX_SMCFILEIMMUTABLE only has anything to skip where mtrack installs
  // protection in the first place; with SMCChecks=none nothing is tracked and
  // with =full every block is validated before it runs.  Log and ignore rather
  // than silently doing nothing.
  if (SMCFileImmutable()) {
    if (SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK) {
      LogMan::Msg::IFmt("FEX_SMCFILEIMMUTABLE: private file-backed code is assumed immutable and will NOT be "
                        "write-protected. Relaxed correctness: in-place patching of file-backed .text through an "
                        "already-writable mapping will go undetected.");
    } else {
      LogMan::Msg::EFmt("FEX_SMCFILEIMMUTABLE needs FEX_SMCCHECKS=mtrack; ignoring it.");
    }
  }

  // FEX_SMCLAZYINVAL (DELIBERATELY UNSOUND -- see
  // LinuxSyscalls/SMCLazyInvalidate.h). It is a relaxation of v3's drain
  // discipline, so v3's machinery has to be there for it to relax: without
  // SMCSoftInvalidate a deferred page would have to be hard-invalidated at the
  // drain (throwing away exactly the amortization this is chasing), and without
  // mtrack there are no SMC write faults to defer in the first place.
  // Publishing the dirty-count pointer is what arms drain point (a) inside
  // FEXCore; leaving it null is what makes the option cost nothing when off.
  if (SMCLazyInval() && SMCSoftInvalidate() && SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK) {
    SMCLazyInvalEnabled.store(true, std::memory_order_relaxed);
    LazySMCDirtyCount = &SMCLazyDirtyCount;
    // FEX_SMCLAZYSCRUB (default on) scrubs the faulting thread's L1 and makes
    // it drain in the lookup slow path, which closes the same-thread
    // patch-then-call hole. Only meaningful once lazy is actually armed.
    SMCLazyScrubEnabled.store(SMCLazyScrub(), std::memory_order_relaxed);
    if (SMCLazyScrub()) {
      LogMan::Msg::IFmt("FEX_SMCLAZYINVAL is ON: SMC invalidation is deferred to drain points. Same-thread "
                        "self-modifying code stays correct via FEX_SMCLAZYSCRUB; cross-thread modification "
                        "without a serializing event on the reader can still observe STALE translations, as "
                        "x86 already permits.");
    } else {
      LogMan::Msg::EFmt("FEX_SMCLAZYINVAL is ON with FEX_SMCLAZYSCRUB=0: SMC invalidation is deferred to drain "
                        "points and guest code can execute STALE translations, including code the SAME thread "
                        "just wrote. This is deliberately unsound -- expect self-modifying guests (runtime "
                        "codegen, JITs) to miscompute or crash.");
    }
  } else if (SMCLazyInval()) {
    LogMan::Msg::EFmt("FEX_SMCLAZYINVAL needs FEX_SMCSOFTINVALIDATE=1 and FEX_SMCCHECKS=mtrack; staying off.");
  }

#ifdef ARCHITECTURE_ppc64le
  // FEX_SMCSTOREBACKPATCH rides on the store decoder that SMCStoreEmulation
  // owns: without that path there is no fault site to rewrite. Arm the page
  // filter once, here, so every hot-path entry point is a relaxed atomic load
  // that is false for the entire process when the feature is off.
  if (SMCStoreBackpatch() && CodeCacheWriteEnabled()) {
    // Backpatching rewrites a store site inside an already-compiled block into
    // a branch to a stub carved out of the code buffer's free tail
    // (Context::AllocateJITAuxMemory). That stub lives outside the block's
    // JITCodeTail-recorded extent, which is exactly the extent the code cache
    // serializes — so a patched block would be written to disk with a relative
    // branch to bytes the cache file does not contain. Refuse the combination
    // rather than emit a cache that jumps into whatever follows on load.
    LogMan::Msg::EFmt("FEX_SMCSTOREBACKPATCH is incompatible with code cache writing; staying off.");
  } else if (SMCStoreBackpatch() && SMCStoreEmulation() && SMCChecks == FEXCore::Config::CONFIG_SMC_MTRACK) {
    FEX::HLE::SMCBackpatch::SetEnabled(true);
    LogMan::Msg::IFmt("SMC store backpatching enabled (FEX_SMCSTOREBACKPATCH).");
  } else if (SMCStoreBackpatch()) {
    LogMan::Msg::EFmt("FEX_SMCSTOREBACKPATCH needs FEX_SMCSTOREEMULATION=1 and FEX_SMCCHECKS=mtrack; staying off.");
  }
#endif
}

SyscallHandler::~SyscallHandler() {
  FEXCore::Allocator::munmap(reinterpret_cast<void*>(DataSpace), DataSpaceMappedSize);
}

uint32_t SyscallHandler::CalculateHostKernelVersion() {
  struct utsname buf {};
  if (uname(&buf) == -1) {
    return 0;
  }

  uint32_t Major {};
  uint32_t Minor {};
  uint32_t Patch {};

  // Parse kernel version in the form of `<Major>.<Minor>.<Patch>[Optional Data]`
  const auto End = buf.release + sizeof(buf.release);
  auto Results = std::from_chars(buf.release, End, Major, 10);
  Results = std::from_chars(Results.ptr + 1, End, Minor, 10);
  Results = std::from_chars(Results.ptr + 1, End, Patch, 10);

  return (Major << 24) | (Minor << 16) | Patch;
}

uint32_t SyscallHandler::CalculateGuestKernelVersion() {
  // We currently only emulate a kernel between the ranges of Kernel 5.15.0 and 6.11.0
  return std::max(KernelVersion(5, 15), std::min(KernelVersion(6, 11), GetHostKernelVersion()));
}

uint64_t SyscallHandler::HandleSyscall(FEXCore::Core::CpuStateFrame* Frame, FEXCore::HLE::SyscallArguments* Args) {
  // Phase 3 of signal-cluster fix: defer async signals across the entire
  // host syscall body. Background:
  //
  // Without this guard, the host kernel can deliver an async signal at any
  // point inside the host C++ syscall handler (often deep inside a libc
  // ::syscall call). FEX's signal handler then captures host context with
  // the guest SRA in a partially-mutated state -- some registers were spilled
  // to State by the JIT's Syscall op, some are still live in host registers
  // per the InSyscallInfo bitmask. When the guest signal handler runs and
  // returns, FEX restores that partially-spilled snapshot, leaving certain
  // guest registers wrong.
  //
  // The visible symptoms include: bash $() returning stack-pointer-shaped
  // bytes (project_steam_nul_underlying_cause.md); 4 POSIX signal API
  // conformance failures (project_posix_signal_cluster_open.md); and Steam
  // i686 SEGV'ing at __kernel_rt_sigreturn after 5.4M dispatches with EBX=0
  // (project_steam_vdso_sigreturn_segv.md).
  //
  // Deferring across the host syscall is safe: blocking host syscalls still
  // get interrupted by the kernel (::syscall returns -EINTR, which propagates
  // to the JIT exactly as a real Linux kernel would); the queued signal then
  // gets delivered at the natural clean point when this guard destructs.
  // The destructor's InterruptFaultPage->Store(0) is what triggers delivery
  // when a deferred signal is pending -- the page is PROT_NONE in that case,
  // the store faults, and FEX's SIGSEGV handler (recognising the InterruptFaultPage
  // address) drains the deferred queue and resumes.
  //
  // Phase 1 (commit 8774c7dda) added InSyscallInfo bookkeeping. Phase 2
  // (today's d441d9869) made PPC64LE handle the InterruptFaultPage refcount-store
  // fault correctly. This Phase 3 closes the loop by actually arming the guard
  // at the right scope.
  FEXCore::DeferredSignalRefCountGuard SignalGuard(Frame->Thread);

  // FEX_SMCLAZYINVAL drain point (b): guest syscall entry.
  //
  // x86 requires a serializing event before cross-modified code may run, and a
  // syscall is the one every real guest actually uses; it is also the natural
  // bound on how long a same-thread patch may stay invisible in practice. The
  // drain must happen at entry (before the syscall body can, say, hand the page
  // to another thread or change its protection), not on the way out.
  //
  // Lock protocol: nothing is held here. The JIT has exited its block, no
  // shared CodeInvalidationMutex is outstanding, and the drain's own
  // ReleaseAllPendingSharedLocks is therefore a no-op. Taking the exclusive
  // CodeInvalidationMutex from inside a syscall body is what every mm-related
  // syscall already does (GuestMunmap et al. via InvalidateCodeRangeIfNecessary),
  // including under this same DeferredSignalRefCountGuard.
  //
  // Cost with the option off: one relaxed load of SMCLazyInvalEnabled.
  if (SMCLazyInvalActive()) {
    DrainSMCLazyDirtyPages(Frame->Thread, FEX::HLE::SMCLazy::DrainPoint::Syscall);
  }

  // Grab the return address which will be inside the JIT.
  const uint64_t JITPC = reinterpret_cast<uint64_t>(__builtin_extract_return_addr(__builtin_return_address(0)));

  const auto SeccompResult = SeccompEmulator.ExecuteFilter(Frame, JITPC, Args);

  if (SeccompResult.EarlyReturn) {
    return SeccompResult.Result;
  }

  if (Args->Argument[0] >= Definitions.size()) {
    return -ENOSYS;
  }

  auto& Def = Definitions[Args->Argument[0]];
  uint64_t Result {};
  switch (Def.NumArgs) {
  case 0: Result = std::invoke(Def.Ptr0, Frame); break;
  case 1: Result = std::invoke(Def.Ptr1, Frame, Args->Argument[1]); break;
  case 2: Result = std::invoke(Def.Ptr2, Frame, Args->Argument[1], Args->Argument[2]); break;
  case 3: Result = std::invoke(Def.Ptr3, Frame, Args->Argument[1], Args->Argument[2], Args->Argument[3]); break;
  case 4: Result = std::invoke(Def.Ptr4, Frame, Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4]); break;
  case 5:
    Result = std::invoke(Def.Ptr5, Frame, Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4], Args->Argument[5]);
    break;
  case 6:
    Result = std::invoke(Def.Ptr6, Frame, Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4], Args->Argument[5],
                         Args->Argument[6]);
    break;
  // for missing syscalls
  case 255: return std::invoke(Def.Ptr1, Frame, Args->Argument[0]);
  default:
    LOGMAN_MSG_A_FMT("Unhandled syscall: {}", Args->Argument[0]);
    return -1;
    break;
  }
#ifdef DEBUG_STRACE
  Strace(Args, Result);
#endif
  return Result;
}

#ifdef DEBUG_STRACE
void SyscallHandler::Strace(FEXCore::HLE::SyscallArguments* Args, uint64_t Ret) {
  auto& Def = Definitions[Args->Argument[0]];
  switch (Def.NumArgs) {
  case 0: LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Ret); break;
  case 1: LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Ret); break;
  case 2: LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Args->Argument[2], Ret); break;
  case 3: LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Args->Argument[2], Args->Argument[3], Ret); break;
  case 4: LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4], Ret); break;
  case 5:
    LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4], Args->Argument[5], Ret);
    break;
  case 6:
    LogMan::Msg::DFmt(Def.StraceFmt.c_str(), Args->Argument[1], Args->Argument[2], Args->Argument[3], Args->Argument[4], Args->Argument[5],
                      Args->Argument[6], Ret);
    break;
  default: break;
  }
}
#endif

uint64_t UnimplementedSyscall(FEXCore::Core::CpuStateFrame* Frame, uint64_t SyscallNumber) {
  ERROR_AND_DIE_FMT("Unhandled system call: {}", SyscallNumber);
  return -ENOSYS;
}

uint64_t UnimplementedSyscallSafe(FEXCore::Core::CpuStateFrame* Frame, uint64_t SyscallNumber) {
  return -ENOSYS;
}

void SyscallHandler::LockBeforeFork(FEXCore::Core::InternalThreadState* Thread) {
  TM.LockBeforeFork();
  Thread->CTX->LockBeforeFork(Thread);
  VMATracking.Mutex.lock();
}

void SyscallHandler::UnlockAfterFork(FEXCore::Core::InternalThreadState* LiveThread, bool Child) {
  if (Child) {
    // Code maps are closed upon fork in the child
    FM.SetProtectedCodeMapFD(-1);

    // glibc reinstalls its SETXID handler when the child first calls
    // pthread_create.  Re-arm NeedToCheckXID so we re-capture that handler
    // for the child — without this the first setuid() in a forked child can
    // run glibc native handler in JIT context and corrupt the SRA.
    EnableXIDCheck();

    VMATracking.Mutex.StealAndDropActiveLocks();
  } else {
    VMATracking.Mutex.unlock();
  }

  CTX->UnlockAfterFork(LiveThread, Child);

  // Clear all the other threads that are being tracked
  TM.UnlockAfterFork(LiveThread, Child);
}

void SyscallHandler::RegisterTLSState(FEX::HLE::ThreadStateObject* Thread) {
  SignalDelegation->RegisterTLSState(Thread);
  ThunkHandler->RegisterTLSState(Thread);
}

void SyscallHandler::UninstallTLSState(FEX::HLE::ThreadStateObject* Thread) {
  SignalDelegation->UninstallTLSState(Thread);
}

static bool isHEX(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

fextl::unique_ptr<FEXCore::HLE::SourcecodeMap> SyscallHandler::GenerateMap(std::string_view GuestBinaryFile, std::string_view GuestBinaryFileId) {
  ELFParser GuestELF;

  if (!GuestELF.ReadElf(fextl::string(GuestBinaryFile))) {
    LogMan::Msg::DFmt("GenerateMap: '{}' is not an elf file?", GuestBinaryFile);
    return {};
  }

  struct stat GuestBinaryFileStat;

  if (stat(GuestBinaryFile.data(), &GuestBinaryFileStat)) {
    LogMan::Msg::DFmt("GenerateMap: failed to stat '{}'", GuestBinaryFile);
    return {};
  }

  const auto FexSrcPath = fextl::fmt::format("{}/fexsrc", FEXCore::Config::GetDataDirectory());

  if (!FHU::Filesystem::CreateDirectories(FexSrcPath)) {
    LogMan::Msg::DFmt("GenerateMap: failed to create_directories '{}'", FexSrcPath);
    return {};
  }

  auto GuestSourceFile = fextl::fmt::format("{}/{}.src", FexSrcPath, GuestBinaryFileId);

  struct stat GuestSourceFileStat;

  if (stat(GuestSourceFile.data(), &GuestSourceFileStat) != 0 || GuestBinaryFileStat.st_mtime > GuestSourceFileStat.st_mtime) {
    LogMan::Msg::DFmt("GenerateMap: Generating source for '{}'", GuestBinaryFile);
    auto command = fextl::fmt::format("x86_64-linux-gnu-objdump -SC \'{}\' > '{}'", GuestBinaryFile, GuestSourceFile);
    if (system(command.c_str()) != 0) {
      LogMan::Msg::DFmt("GenerateMap: '{}' failed", command);
      return {};
    }
  }

  const auto GuestIndexFile = fextl::fmt::format("{}/{}.idx", FexSrcPath, GuestBinaryFileId);
  struct stat GuestIndexFileStat;

  bool GenerateIndex = stat(GuestIndexFile.data(), &GuestIndexFileStat) != 0 || GuestSourceFileStat.st_mtime > GuestIndexFileStat.st_mtime;

  constexpr char SrcHeaderString[] = "fexsrcindex0";
  if (!GenerateIndex) {
    // Index file de-serialization
    LogMan::Msg::DFmt("GenerateMap: Reading index '{}'", GuestIndexFile);

    int FD = ::open(GuestIndexFile.c_str(), O_RDONLY | O_CLOEXEC);

    if (FD == -1) {
      LogMan::Msg::DFmt("GenerateMap: Failed to open '{}'", GuestIndexFile);
      goto DoGenerate;
    }

    //"fexsrcindex0"
    char filemagic[12];
    ::read(FD, filemagic, sizeof(filemagic));
    if (memcmp(filemagic, SrcHeaderString, sizeof(filemagic)) != 0) {
      LogMan::Msg::DFmt("GenerateMap: '{}' has invalid magic '{}'", GuestIndexFile, filemagic);
      close(FD);
      goto DoGenerate;
    }

    auto rv = fextl::make_unique<FEXCore::HLE::SourcecodeMap>();

    {
      auto len = rv->SourceFile.size();
      ::read(FD, (char*)&len, sizeof(len));
      rv->SourceFile.resize(len);
      ::read(FD, rv->SourceFile.data(), len);
    }

    {
      auto len = rv->SortedLineMappings.size();

      ::read(FD, (char*)&len, sizeof(len));

      rv->SortedLineMappings.resize(len);

      for (auto& Mapping : rv->SortedLineMappings) {
        ::read(FD, (char*)&Mapping.FileGuestBegin, sizeof(Mapping.FileGuestBegin));
        ::read(FD, (char*)&Mapping.FileGuestEnd, sizeof(Mapping.FileGuestEnd));
        ::read(FD, (char*)&Mapping.LineNumber, sizeof(Mapping.LineNumber));
      }
    }

    {
      auto len = rv->SortedSymbolMappings.size();

      ::read(FD, (char*)&len, sizeof(len));

      rv->SortedSymbolMappings.resize(len);

      for (auto& Mapping : rv->SortedSymbolMappings) {
        ::read(FD, (char*)&Mapping.FileGuestBegin, sizeof(Mapping.FileGuestBegin));
        ::read(FD, (char*)&Mapping.FileGuestEnd, sizeof(Mapping.FileGuestEnd));

        {
          auto len = Mapping.Name.size();
          ::read(FD, (char*)&len, sizeof(len));
          Mapping.Name.resize(len);
          ::read(FD, Mapping.Name.data(), len);
        }
      }
    }

    LogMan::Msg::DFmt("GenerateMap: Finished reading index");
    close(FD);
    return rv;
  } else {
// objdump output parsing,  index generation, index file serialization
DoGenerate:
    LogMan::Msg::DFmt("GenerateMap: Generating index for '{}'", GuestSourceFile);

    fextl::string SourceData;
    if (!FEXCore::FileLoading::LoadFile(SourceData, GuestSourceFile)) {
      LogMan::Msg::DFmt("GenerateMap: Failed to open '{}'", GuestSourceFile);
      return {};
    }
    fextl::istringstream Stream(SourceData);

    constexpr int USER_PERMS = S_IRWXU | S_IRWXG | S_IRWXO;
    int IndexStream = ::open(GuestIndexFile.c_str(), O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, USER_PERMS);

    if (IndexStream == -1) {
      LogMan::Msg::DFmt("GenerateMap: Failed to open '{}' for writing", GuestIndexFile);
      return {};
    }

    ::write(IndexStream, SrcHeaderString, strlen(SrcHeaderString));

    // objdump parsing
    fextl::string Line;
    int LineNum = 0;

    bool PreviousLineWasEmpty = false;

    uintptr_t LastSymbolOffset {};
    uintptr_t CurrentSymbolOffset {};
    fextl::string LastSymbolName;

    uintptr_t LastOffset {};
    uintptr_t CurrentOffset {};
    int LastOffsetLine;

    auto rv = fextl::make_unique<FEXCore::HLE::SourcecodeMap>();

    rv->SourceFile = std::move(GuestSourceFile);

    auto EndSymbol = [&] {
      if (LastSymbolOffset) {
        rv->SortedSymbolMappings.push_back({LastSymbolOffset, CurrentSymbolOffset, LastSymbolName});

        // LogMan::Msg::DFmt("Ended Symbol {} - {:x}...{:x}", LastSymbolName, LastSymbolOffset, CurrentSymbolOffset);
      }
      LastSymbolOffset = {};
    };

    auto EndLine = [&] {
      if (LastOffset) {
        rv->SortedLineMappings.push_back({LastOffset, CurrentOffset, LastOffsetLine});

        // LogMan::Msg::DFmt("Ended Line {} - {:x}...{:x}", LastOffsetLine, LastOffset, CurrentOffset);
      }
      LastOffset = {};
    };

    while (std::getline(Stream, Line)) {
      LineNum++;

      auto LineIsEmpty = Line.empty();

      if (LineIsEmpty) {
        PreviousLineWasEmpty = true;
      } else {

        // LogMan::Msg::DFmt("Line: '{}'", Line);

        if (isHEX(Line[0])) {
          fextl::string addr;
          int offs = 1;
          for (; offs < Line.size() && !isspace(Line[offs]); offs++)
            ;

          if (offs == Line.size()) {
            continue;
          }
          if (offs != 8 && offs != 16) {
            continue;
          }

          auto VAOffset = std::strtoul(Line.substr(0, offs).c_str(), nullptr, 16);

          auto FileOffset = GuestELF.VAToFile(VAOffset);

          if (FileOffset == 0) {
            LogMan::Msg::EFmt("File Offset {:x} did not map to file?! {}", VAOffset, Line);
          }

          CurrentSymbolOffset = FileOffset;

          if (PreviousLineWasEmpty) {
            EndSymbol();
          }
          LastSymbolOffset = CurrentSymbolOffset;

          for (; offs < Line.size() && Line[offs] != '<'; offs++)
            ;

          if (offs == Line.size()) {
            continue;
          }

          offs++;

          LastSymbolName = Line.substr(offs, Line.size() - 2 - offs);

          // LogMan::Msg::DFmt("Symbol {} @ {:x} -> Line {}", LastSymbolName, LastSymbolOffset, LineNum);
        } else if (isspace(Line[0])) {
          int offs = 1;
          for (; offs < Line.size() && isspace(Line[offs]); offs++)
            ;

          if (offs == Line.size()) {
            continue;
          }

          int start = offs;

          for (; offs < Line.size() && Line[offs] != ':'; offs++)
            ;

          if (offs == Line.size()) {
            continue;
          }

          if (Line[offs + 1] == '\t') {
            auto VAOffsetStr = Line.substr(start, offs - start);
            auto VAOffset = std::strtoul(VAOffsetStr.c_str(), nullptr, 16);
            auto FileOffset = GuestELF.VAToFile(VAOffset);
            if (FileOffset == 0) {
              LogMan::Msg::EFmt("File Offset {:x} did not map to file?! {}", VAOffset, Line);
            } else {
              if (LastOffset > FileOffset) {
                LogMan::Msg::EFmt("File Offset {:x} less than previous {:} ?!  {}", FileOffset, LastOffset, Line);
              }
              CurrentOffset = FileOffset;

              EndLine();

              LastOffset = CurrentOffset;
              LastOffsetLine = LineNum;
            }
          }
        }
        // something else -- keep going
      }
    }

    CurrentOffset = LastOffset + 4;
    CurrentSymbolOffset = CurrentOffset;

    EndSymbol();
    EndLine();

    // Index post processing - entires are sorted for faster lookups

    std::sort(rv->SortedLineMappings.begin(), rv->SortedLineMappings.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.FileGuestEnd <= rhs.FileGuestBegin; });

    std::sort(rv->SortedSymbolMappings.begin(), rv->SortedSymbolMappings.end(),
              [](const auto& lhs, const auto& rhs) { return lhs.FileGuestEnd <= rhs.FileGuestBegin; });

    // Index serialization
    {
      auto len = rv->SourceFile.size();
      ::write(IndexStream, (const char*)&len, sizeof(len));
      ::write(IndexStream, rv->SourceFile.c_str(), len);
    }

    {
      auto len = rv->SortedLineMappings.size();

      ::write(IndexStream, (const char*)&len, sizeof(len));

      for (const auto& Mapping : rv->SortedLineMappings) {
        ::write(IndexStream, (const char*)&Mapping.FileGuestBegin, sizeof(Mapping.FileGuestBegin));
        ::write(IndexStream, (const char*)&Mapping.FileGuestEnd, sizeof(Mapping.FileGuestEnd));
        ::write(IndexStream, (const char*)&Mapping.LineNumber, sizeof(Mapping.LineNumber));
      }
    }

    {
      auto len = rv->SortedSymbolMappings.size();

      ::write(IndexStream, (char*)&len, sizeof(len));

      for (const auto& Mapping : rv->SortedSymbolMappings) {
        ::write(IndexStream, (const char*)&Mapping.FileGuestBegin, sizeof(Mapping.FileGuestBegin));
        ::write(IndexStream, (const char*)&Mapping.FileGuestEnd, sizeof(Mapping.FileGuestEnd));

        {
          auto len = Mapping.Name.size();
          ::write(IndexStream, (const char*)&len, sizeof(len));
          ::write(IndexStream, Mapping.Name.c_str(), len);
        }
      }
    }

    if (IndexStream != -1) {
      close(IndexStream);
    }

    LogMan::Msg::DFmt("GenerateMap: Finished generating index", GuestIndexFile);
    return rv;
  }
}

// Linux Mono runtime detection — flip MonoDetected when the guest opens a
// libmono / libmonosgen / libmonoboehm / mono-2.0-bdwgc shared library.
// Cheap atomic gate after first detection so the openat hot path stays fast.
bool SyscallHandler::IsMonoRuntimeLibraryPath(std::string_view pathname) {
  // Take the basename — everything after the last '/'.
  if (auto Slash = pathname.find_last_of('/'); Slash != std::string_view::npos) {
    pathname.remove_prefix(Slash + 1);
  }
  // Match known Mono runtime library prefixes.  Cheap prefix match, no regex.
  return pathname.starts_with("libmonosgen-")   || // mainline mono runtime (sgen GC)
         pathname.starts_with("libmono-2.0")    || // older mono runtime
         pathname.starts_with("libmonoboehm-")  || // Boehm-GC mono variant
         pathname.starts_with("libmonobdwgc-")  || // Unity 2017+ / modern Unity runtime
         pathname.starts_with("libmono.so")     || // generic libmono (Unity 4/5)
         pathname.starts_with("mono-2.0-bdwgc") || // matches Windows-side name too
         pathname.starts_with("mono.so");
}

void SyscallHandler::MaybeDetectMonoFromPath(std::string_view pathname) {
  // Relaxed load is enough — we only need eventually-consistent short-circuit;
  // the first writer pays the cost of going through MarkMonoDetected once.
  if (MonoDetectionComplete.load(std::memory_order_relaxed)) {
    return;
  }
  // Skip the path check if MonoHacks isn't even configured — the detected
  // flag would have no consumers, so don't pay the strstr cost.
  FEX_CONFIG_OPT(MonoHacksConfig, MONOHACKS);
  if (!MonoHacksConfig()) {
    MonoDetectionComplete.store(true, std::memory_order_relaxed);
    return;
  }

  if (!IsMonoRuntimeLibraryPath(pathname)) {
    return;
  }

  // Windows gates the mono hacks on Multiblock with a large MaxInst, because the
  // scheme assumes every SMC site in the backpatcher can be hooked inside a
  // single recompiled block.  Apply the same gate here rather than half-enabling
  // the hacks under -O0-style configs.
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
  FEX_CONFIG_OPT(MaxInst, MAXINST);
  if (!Multiblock() || MaxInst() < 500) {
    if (!MonoDetectionComplete.exchange(true, std::memory_order_acq_rel)) {
      LogMan::Msg::IFmt("Mono runtime seen via '{}' but NOT applying mono hacks: "
                        "Multiblock with MaxInst >= 500 required (Multiblock={}, MaxInst={}).",
                        pathname, Multiblock(), MaxInst());
    }
    return;
  }

  // Mark only once.  compare_exchange ensures only the winning thread invokes
  // MarkMonoDetected; subsequent callers short-circuit.
  bool expected = false;
  if (MonoDetectionComplete.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    LogMan::Msg::IFmt("Mono runtime detected via '{}' — MonoHacks active.", pathname);
    CTX->MarkMonoDetected();
    MonoHacksActive.store(true, std::memory_order_release);
  }
}

namespace {
// FEX_MONO_DETECT: gates the statically-linked-Mono fallback signal (mono
// data-file opens -- mscorlib.dll / machine.config).  Default on.  Dynamic
// libmono*.so detection (MaybeDetectMonoFromPath / IsMonoRuntimeLibraryPath)
// is unaffected either way -- this only controls the *fallback*.
bool MonoDetectFallbackEnabled() {
  static const bool Enabled = [] {
    const char* p = getenv("FEX_MONO_DETECT");
    return !p || strtol(p, nullptr, 10) != 0;
  }();
  return Enabled;
}

// FEX_FORCE_MONO_DETECT: unconditionally treats the main executable as the
// mono runtime, bypassing both the dynamic-library and data-file signals.
// For experiments where neither signal is reachable -- default off.
bool ForceMonoDetectRequested() {
  static const bool Forced = [] {
    const char* p = getenv("FEX_FORCE_MONO_DETECT");
    return p && strtol(p, nullptr, 10) != 0;
  }();
  return Forced;
}
} // namespace

bool SyscallHandler::IsMonoDataFilePath(std::string_view Path) {
  // Require the match to land on a path-component boundary -- either the
  // whole path is the name, or the character immediately before it is '/'.
  // This is what keeps e.g. "custommscorlib.dll" from matching.
  auto EndsWithComponent = [](std::string_view P, std::string_view Name) {
    if (P.size() < Name.size() || !P.ends_with(Name)) {
      return false;
    }
    return P.size() == Name.size() || P[P.size() - Name.size() - 1] == '/';
  };
  return EndsWithComponent(Path, "mscorlib.dll") || EndsWithComponent(Path, "machine.config");
}

void SyscallHandler::ArmMonoFallbackRange(std::string_view Reason, std::string_view Detail) {
  // Dynamic-library detection (or an earlier fallback call) already owns a
  // range -- never move or re-register it.
  if (MonoHacksActive.load(std::memory_order_acquire) || MonoFallbackArmed.load(std::memory_order_acquire)) {
    return;
  }

  FEX_CONFIG_OPT(MonoHacksConfig, MONOHACKS);
  if (!MonoHacksConfig()) {
    return;
  }

  const uint64_t Base = MainExeBase.load(std::memory_order_relaxed);
  const uint64_t End = MainExeEnd.load(std::memory_order_relaxed);
  if (Base == 0 || End <= Base) {
    // The main executable's own range isn't known yet.  This can't happen
    // once the guest has started running (the main ELF finishes loading
    // before Execute() ever runs guest code), but bail defensively rather
    // than arming a bogus [0, 0) range; a later call can retry.
    return;
  }

  // Same Multiblock/MaxInst gate MaybeDetectMonoFromPath applies to the
  // dynamic-library path -- the backpatcher scheme assumes every SMC site
  // is hookable inside a single recompiled block.
  FEX_CONFIG_OPT(Multiblock, MULTIBLOCK);
  FEX_CONFIG_OPT(MaxInst, MAXINST);
  if (!Multiblock() || MaxInst() < 500) {
    if (!MonoFallbackArmed.exchange(true, std::memory_order_acq_rel)) {
      LogMan::Msg::IFmt("Mono runtime inferred from {} ('{}') but NOT applying mono hacks: "
                        "Multiblock with MaxInst >= 500 required (Multiblock={}, MaxInst={}).",
                        Reason, Detail, Multiblock(), MaxInst());
    }
    return;
  }

  // Claim the one-shot.  Whoever wins this is the only caller that mutates
  // MonoBase/MonoEnd/MonoHacksActive/MonoBackpatcherDetectionPending; the
  // range is immutable from here on.
  bool expected = false;
  if (!MonoFallbackArmed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    return;
  }

  MonoBase.store(Base, std::memory_order_relaxed);
  MonoEnd.store(End, std::memory_order_relaxed);
  LogMan::Msg::IFmt("Mono runtime inferred from {} ('{}') — assuming a statically-linked runtime "
                    "and registering the main executable's own range {:#x}-{:#x} as the backpatcher "
                    "range (watching for the XCHG backpatcher block).",
                    Reason, Detail, Base, End);
  if (FEX::HLE::ThreadCensus::Enabled()) {
    FEX::HLE::ThreadCensus::OnMonoFallbackArmed(Reason, Detail, Base, End);
  }
  CTX->MarkMonoDetected();
  MonoHacksActive.store(true, std::memory_order_release);
  MonoBackpatcherDetectionPending.store(true, std::memory_order_release);
}

void SyscallHandler::MaybeForceMonoDetect() {
  if (MonoFallbackArmed.load(std::memory_order_acquire) || MonoHacksActive.load(std::memory_order_acquire)) {
    return;
  }
  if (!ForceMonoDetectRequested()) {
    return;
  }
  ArmMonoFallbackRange("FEX_FORCE_MONO_DETECT", "main executable");
}

void SyscallHandler::MaybeDetectMonoFallbackFromPath(std::string_view pathname) {
  // Cheap relaxed gate: false for every process that isn't mono (or has
  // MonoHacks configured off), and for every call after we're done looking.
  if (MonoFallbackDetectionComplete.load(std::memory_order_relaxed)) {
    return;
  }

  FEX_CONFIG_OPT(MonoHacksConfig, MONOHACKS);
  if (!MonoHacksConfig()) {
    MonoFallbackDetectionComplete.store(true, std::memory_order_relaxed);
    return;
  }

  // Dynamic-library detection already gives us a range; nothing left for the
  // fallback to do once that's happened.
  if (MonoHacksActive.load(std::memory_order_acquire)) {
    MonoFallbackDetectionComplete.store(true, std::memory_order_relaxed);
    return;
  }

  // FEX_FORCE_MONO_DETECT is checked unconditionally (independent of
  // FEX_MONO_DETECT, which only gates the path-signal half below) on every
  // openat/openat2 call until something arms the range -- by the first
  // guest syscall the main executable is already fully mapped, so this
  // effectively fires "at startup" from the guest's perspective.
  MaybeForceMonoDetect();

  if (!MonoHacksActive.load(std::memory_order_acquire) && MonoDetectFallbackEnabled() && IsMonoDataFilePath(pathname)) {
    ArmMonoFallbackRange("mono data file open", pathname);
  }

  if (MonoHacksActive.load(std::memory_order_acquire)) {
    MonoFallbackDetectionComplete.store(true, std::memory_order_relaxed);
  }
}

} // namespace FEX::HLE
