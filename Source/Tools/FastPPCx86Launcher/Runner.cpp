// SPDX-License-Identifier: MIT
#include "Runner.h"

#include <FEXHeaderUtils/Filesystem.h>

#include <fmt/format.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace FastPPCx86::Launcher {

namespace {
  int64_t NowSeconds() {
    return static_cast<int64_t>(std::time(nullptr));
  }

  /// Seconds to keep reading after the child is reaped. Orphaned helpers can
  /// hold the write end open indefinitely, so the run is not held hostage to
  /// EOF -- but a well-behaved title's tail output still gets collected.
  constexpr int64_t DrainGraceSeconds = 2;

  void WriteAll(int FD, std::string_view Data) {
    while (!Data.empty()) {
      const ssize_t Written = ::write(FD, Data.data(), Data.size());
      if (Written <= 0) {
        if (errno == EINTR) {
          continue;
        }
        return;
      }
      Data.remove_prefix(static_cast<size_t>(Written));
    }
  }
} // namespace

Runner::~Runner() {
  CloseAll();
}

void Runner::CloseAll() {
  if (ReadFD >= 0) {
    ::close(ReadFD);
    ReadFD = -1;
  }
  if (LogFD >= 0) {
    ::close(LogFD);
    LogFD = -1;
  }
}

bool Runner::Start(const LaunchSpec& Spec, std::string& Error) {
  if (!Spec.Ok || Spec.Argv.empty()) {
    Error = "This title cannot be launched as configured.";
    return false;
  }

  LogFilePath = Spec.LogPath;
  TimeoutSeconds = Spec.TimeoutSeconds;

  if (!LogFilePath.empty()) {
    const auto Parent = FHU::Filesystem::ParentPath(LogFilePath.c_str());
    if (!Parent.empty() && !FHU::Filesystem::Exists(Parent)) {
      FHU::Filesystem::CreateDirectories(Parent);
    }
    LogFD = ::open(LogFilePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (LogFD < 0) {
      // Not fatal: a run without a log is worse than a run with one, but far
      // better than no run.
      LogFilePath.clear();
    }
  }

  // Everything the child needs must be built before the fork: between fork and
  // exec only async-signal-safe calls are legal, which rules out any allocation.
  std::vector<std::string> ArgvStorage = Spec.Argv;
  std::vector<char*> Argv;
  Argv.reserve(ArgvStorage.size() + 1);
  for (auto& Arg : ArgvStorage) {
    Argv.push_back(Arg.data());
  }
  Argv.push_back(nullptr);

  std::vector<std::string> EnvpStorage = Spec.Envp;
  std::vector<char*> Envp;
  Envp.reserve(EnvpStorage.size() + 1);
  for (auto& Entry : EnvpStorage) {
    Envp.push_back(Entry.data());
  }
  Envp.push_back(nullptr);

  const std::string WorkDir = Spec.WorkDir;
  const char* WorkDirPtr = WorkDir.empty() ? nullptr : WorkDir.c_str();

  cpu_set_t CPUSet;
  CPU_ZERO(&CPUSet);
  for (const int CPU : Spec.CageCPUs) {
    if (CPU >= 0 && CPU < CPU_SETSIZE) {
      CPU_SET(CPU, &CPUSet);
    }
  }
  const bool ApplyCage = !Spec.CageCPUs.empty();

  int Pipe[2] {-1, -1};
  if (::pipe(Pipe) != 0) {
    Error = fmt::format("could not create a pipe: {}", std::strerror(errno));
    CloseAll();
    return false;
  }

  const pid_t Pid = ::fork();
  if (Pid < 0) {
    Error = fmt::format("fork failed: {}", std::strerror(errno));
    ::close(Pipe[0]);
    ::close(Pipe[1]);
    CloseAll();
    return false;
  }

  if (Pid == 0) {
    // --- child ---
    ::close(Pipe[0]);

    // Its own process group, so stopping the run reaches wineserver and every
    // helper the title spawned rather than just the process we started.
    ::setpgid(0, 0);

    if (ApplyCage) {
      // Applied here rather than by exec'ing taskset: no extra process in the
      // tree, and the mask is in place before the emulator reads the affinity
      // it sizes the guest-visible CPU count from.
      ::sched_setaffinity(0, sizeof(CPUSet), &CPUSet);
    }

    if (WorkDirPtr && ::chdir(WorkDirPtr) != 0) {
      const char Message[] = "launcher: could not enter the working directory\n";
      ::write(Pipe[1], Message, sizeof(Message) - 1);
      ::_exit(127);
    }

    ::dup2(Pipe[1], STDOUT_FILENO);
    ::dup2(Pipe[1], STDERR_FILENO);
    if (Pipe[1] > STDERR_FILENO) {
      ::close(Pipe[1]);
    }

    ::execve(Argv[0], Argv.data(), Envp.data());

    const char Message[] = "launcher: could not start the emulator\n";
    ::write(STDERR_FILENO, Message, sizeof(Message) - 1);
    ::_exit(127);
  }

  // --- parent ---
  ::close(Pipe[1]);
  ReadFD = Pipe[0];
  // Also set it here: setpgid in the child races with the first waitpid, and
  // doing it on both sides means whichever wins, the group exists.
  ::setpgid(Pid, Pid);

  const int Flags = ::fcntl(ReadFD, F_GETFL, 0);
  ::fcntl(ReadFD, F_SETFL, Flags | O_NONBLOCK);

  ChildPid = Pid;
  Reaped = false;
  Drained = false;
  TimedOut = false;
  StartedAt = NowSeconds();
  ReapedAt = 0;
  return true;
}

bool Runner::Poll(const OutputCallback& OnOutput) {
  if (ChildPid <= 0) {
    return false;
  }

  char Buffer[8192];
  for (;;) {
    const ssize_t Read = ::read(ReadFD, Buffer, sizeof(Buffer));
    if (Read > 0) {
      const std::string_view Chunk {Buffer, static_cast<size_t>(Read)};
      if (LogFD >= 0) {
        WriteAll(LogFD, Chunk);
      }
      if (OnOutput) {
        OnOutput(Chunk);
      }
      continue;
    }
    if (Read == 0) {
      Drained = true;
      break;
    }
    if (errno == EINTR) {
      continue;
    }
    // EAGAIN: nothing available right now.
    break;
  }

  if (!Reaped) {
    int Status {};
    const pid_t Result = ::waitpid(ChildPid, &Status, WNOHANG);
    if (Result == ChildPid) {
      Reaped = true;
      ReapedAt = NowSeconds();
      if (WIFEXITED(Status)) {
        ExitStatus = WEXITSTATUS(Status);
      } else if (WIFSIGNALED(Status)) {
        BySignal = true;
        SignalNumber = WTERMSIG(Status);
        ExitStatus = 128 + SignalNumber;
      }
    } else if (Result < 0 && errno == ECHILD) {
      Reaped = true;
      ReapedAt = NowSeconds();
    }
  }

  if (!Reaped && TimeoutSeconds > 0 && NowSeconds() - StartedAt >= TimeoutSeconds) {
    TimedOut = true;
    Kill();
  }

  if (Reaped && !Drained && ReapedAt > 0 && NowSeconds() - ReapedAt >= DrainGraceSeconds) {
    // The child is gone but something still holds the write end -- an orphaned
    // wineserver, most often. Stop waiting for an EOF that will not come.
    Drained = true;
  }

  if (Finished()) {
    if (LogFD >= 0) {
      ::close(LogFD);
      LogFD = -1;
    }
    return false;
  }
  return true;
}

void Runner::RequestStop() {
  if (ChildPid > 0 && !Reaped) {
    ::kill(-ChildPid, SIGTERM);
  }
}

void Runner::Kill() {
  if (ChildPid > 0 && !Reaped) {
    ::kill(-ChildPid, SIGKILL);
  }
}

std::string Runner::ExitSummary() const {
  if (!Reaped) {
    return "still running";
  }
  if (TimedOut) {
    return fmt::format("killed after the {}s timeout", TimeoutSeconds);
  }
  if (BySignal) {
    return fmt::format("terminated by signal {} ({})", SignalNumber, ::strsignal(SignalNumber));
  }
  if (ExitStatus == 0) {
    return "exited cleanly";
  }
  return fmt::format("exited with status {}", ExitStatus);
}

} // namespace FastPPCx86::Launcher
