// SPDX-License-Identifier: MIT
#pragma once

#include "LaunchSpec.h"

#include <functional>
#include <string>
#include <string_view>
#include <sys/types.h>

/**
 * Starting a title and following its output.
 *
 * Plain fork/exec rather than a toolkit's process class, for two reasons. It
 * keeps the core free of Qt so the TUI and the headless modes share this exact
 * code; and it puts the window between fork and exec under direct control, which
 * is where the affinity cage has to be applied.
 *
 * Output is written to the log file by this process and handed to a callback,
 * never piped through `tee`. That matters: a `tee` on the end of an emulated
 * title inherits the pipe into every orphaned wine daemon the title leaves
 * behind, and those keep it -- and any ssh session wrapping it -- alive
 * indefinitely after the game itself is gone.
 */
namespace FastPPCx86::Launcher {

class Runner final {
public:
  using OutputCallback = std::function<void(std::string_view)>;

  Runner() = default;
  ~Runner();
  Runner(const Runner&) = delete;
  Runner& operator=(const Runner&) = delete;

  bool Start(const LaunchSpec& Spec, std::string& Error);

  /**
   * Reads whatever output is available and reaps the child if it has finished.
   * Non-blocking. Returns true while the run is still considered active.
   */
  bool Poll(const OutputCallback& OnOutput);

  /// Readable end of the child's merged output, for a frontend that wants to
  /// select()/poll() on it rather than spin.
  int OutputFD() const {
    return ReadFD;
  }

  bool Running() const {
    return ChildPid > 0 && !Reaped;
  }
  pid_t Pid() const {
    return ChildPid;
  }

  /// SIGTERM to the whole process group, so wine and its helpers go too.
  void RequestStop();
  void Kill();

  bool Finished() const {
    return Reaped && Drained;
  }
  int ExitCode() const {
    return ExitStatus;
  }
  bool ExitedBySignal() const {
    return BySignal;
  }
  int TerminatingSignal() const {
    return SignalNumber;
  }
  const std::string& LogPath() const {
    return LogFilePath;
  }
  /// A one-line summary of how the run ended, for the exit banner.
  std::string ExitSummary() const;

private:
  void CloseAll();

  pid_t ChildPid {-1};
  int ReadFD {-1};
  int LogFD {-1};
  std::string LogFilePath;

  bool Reaped {false};
  bool Drained {false};
  int ExitStatus {0};
  bool BySignal {false};
  int SignalNumber {0};

  int TimeoutSeconds {0};
  int64_t StartedAt {};
  bool TimedOut {false};
  int64_t ReapedAt {};
};

} // namespace FastPPCx86::Launcher
