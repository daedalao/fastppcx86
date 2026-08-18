// SPDX-License-Identifier: MIT
#include "HostEnv.h"
#include "Json.h"

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

extern char** environ;

namespace FastPPCx86::Launcher::HostEnv {

namespace {
  namespace fs = std::filesystem;

  bool Contains(std::string_view Haystack, std::string_view Needle) {
    return Haystack.find(Needle) != std::string_view::npos;
  }

  /// Splits a /proc/<pid>/cmdline blob on its NUL separators.
  std::vector<std::string> SplitCmdline(const std::string& Blob) {
    std::vector<std::string> Args;
    size_t Start {};
    for (size_t I = 0; I <= Blob.size(); ++I) {
      if (I == Blob.size() || Blob[I] == '\0') {
        if (I > Start) {
          Args.emplace_back(Blob.data() + Start, I - Start);
        }
        Start = I + 1;
      }
    }
    return Args;
  }

  struct ServerArgs {
    std::string Display;
    std::string AuthFile;
  };

  /**
   * Finds a running X server and reads its display and -auth argument.
   *
   * The shell equivalent of this scraped `ps -eo args`, which needed care: in
   * `Xwayland :1 -auth /path` the `-auth` token is not adjacent to the program
   * name, so a regex anchored on adjacency silently finds nothing. Walking argv
   * from /proc sidesteps the question entirely.
   */
  std::optional<ServerArgs> FindXServer() {
    std::error_code EC;
    for (fs::directory_iterator It {"/proc", fs::directory_options::skip_permission_denied, EC}; !EC && It != fs::directory_iterator {};
         It.increment(EC)) {
      const auto Name = It->path().filename().string();
      if (Name.empty() || !std::all_of(Name.begin(), Name.end(), [](unsigned char C) { return std::isdigit(C); })) {
        continue;
      }

      std::string Blob;
      if (!Json::ReadFile(It->path().string() + "/cmdline", Blob) || Blob.empty()) {
        continue;
      }

      const auto Args = SplitCmdline(Blob);
      if (Args.empty()) {
        continue;
      }

      const auto Program = fs::path {Args[0]}.filename().string();
      if (!Contains(Program, "Xwayland") && !Contains(Program, "Xorg") && Program != "X") {
        continue;
      }

      ServerArgs Found;
      for (size_t I = 1; I < Args.size(); ++I) {
        if (Args[I] == "-auth" && I + 1 < Args.size()) {
          Found.AuthFile = Args[I + 1];
          ++I;
        } else if (Args[I].size() >= 2 && Args[I][0] == ':' &&
                   std::all_of(Args[I].begin() + 1, Args[I].end(), [](unsigned char C) { return std::isdigit(C); })) {
          Found.Display = Args[I];
        }
      }

      if (!Found.Display.empty() || !Found.AuthFile.empty()) {
        return Found;
      }
    }
    return std::nullopt;
  }

  /// Newest readable $XDG_RUNTIME_DIR/xauth_* (or Xauthority). The filename
  /// changes on every boot, so it is resolved and never stored.
  std::string FindRuntimeXauthority() {
    const char* RuntimeDir = std::getenv("XDG_RUNTIME_DIR");
    std::string Dir = RuntimeDir && *RuntimeDir ? RuntimeDir : fmt::format("/run/user/{}", ::getuid());
    if (!fs::is_directory(Dir)) {
      return {};
    }

    std::string Best;
    time_t BestTime {};
    std::error_code EC;
    for (fs::directory_iterator It {Dir, fs::directory_options::skip_permission_denied, EC}; !EC && It != fs::directory_iterator {};
         It.increment(EC)) {
      const auto Name = It->path().filename().string();
      if (Name.rfind("xauth_", 0) != 0 && Name != "Xauthority") {
        continue;
      }
      const auto Path = It->path().string();
      if (::access(Path.c_str(), R_OK) != 0) {
        continue;
      }
      struct stat Info {};
      if (::stat(Path.c_str(), &Info) != 0) {
        continue;
      }
      if (Best.empty() || Info.st_mtime > BestTime) {
        Best = Path;
        BestTime = Info.st_mtime;
      }
    }
    return Best;
  }
} // namespace

Environment Environment::FromCurrent() {
  Environment Env;
  for (char** Entry = environ; Entry && *Entry; ++Entry) {
    const std::string_view Line {*Entry};
    const auto Equals = Line.find('=');
    if (Equals == std::string_view::npos) {
      continue;
    }
    Env.Values.emplace(std::string {Line.substr(0, Equals)}, std::string {Line.substr(Equals + 1)});
  }
  return Env;
}

void Environment::Set(std::string Key, std::string Value) {
  Values[std::move(Key)] = std::move(Value);
}

void Environment::SetIfUnset(std::string Key, std::string Value) {
  Values.emplace(std::move(Key), std::move(Value));
}

void Environment::Unset(std::string_view Key) {
  Values.erase(std::string {Key});
}

bool Environment::Has(std::string_view Key) const {
  return Values.count(std::string {Key}) != 0;
}

const std::string* Environment::Get(std::string_view Key) const {
  const auto Found = Values.find(std::string {Key});
  return Found == Values.end() ? nullptr : &Found->second;
}

std::vector<std::string> Environment::ToEnvp() const {
  std::vector<std::string> Out;
  Out.reserve(Values.size());
  for (const auto& [Key, Value] : Values) {
    Out.push_back(Key + "=" + Value);
  }
  return Out;
}

DisplayInfo ResolveDisplay(const Environment& Inherited) {
  DisplayInfo Info;

  // An interactive session already has both, and they are authoritative.
  if (const std::string* Display = Inherited.Get("DISPLAY"); Display && !Display->empty()) {
    Info.Display = *Display;
    Info.Source = "inherited from the environment";
    if (const std::string* Auth = Inherited.Get("XAUTHORITY"); Auth && !Auth->empty()) {
      Info.XAuthority = *Auth;
      return Info;
    }
  }

  const auto Server = FindXServer();
  if (Info.Display.empty()) {
    if (Server && !Server->Display.empty()) {
      Info.Display = Server->Display;
      Info.Source = "from the running X server's arguments";
    }
  }

  if (Info.XAuthority.empty() && Server && !Server->AuthFile.empty() && ::access(Server->AuthFile.c_str(), R_OK) == 0) {
    Info.XAuthority = Server->AuthFile;
    if (Info.Source.empty()) {
      Info.Source = "from the running X server's arguments";
    }
  }

  if (Info.XAuthority.empty()) {
    // The session manager's own cookie. Not every setup needs one, so an empty
    // result here is not by itself a failure.
    Info.XAuthority = FindRuntimeXauthority();
    if (!Info.XAuthority.empty() && Info.Source.empty()) {
      Info.Source = "from XDG_RUNTIME_DIR";
    }
  }

  if (Info.Display.empty()) {
    // Deliberately no fallback to ":0". Guessing produces a launch that fails
    // minutes later with a message that sends people looking at the GPU.
    Info.Problem = "No X display found. This port needs Xorg or Xwayland: the Wayland and Xlib "
                   "paths break on cross-architecture guest-callback dispatch, so XCB is the only "
                   "working window-system integration. Start an X session, or set DISPLAY yourself.";
  }

  return Info;
}

void ApplyWindowSystem(Environment& Env) {
  // Strip Wayland so SDL, GLFW, the Vulkan loader and Mesa's zink all fall back
  // to X11/XCB rather than picking a path that cannot work here.
  Env.Unset("WAYLAND_DISPLAY");
  Env.Unset("WAYLAND_SOCKET");
  Env.Unset("VK_USE_PLATFORM_WAYLAND_KHR");

  Env.Set("SDL_VIDEODRIVER", "x11");
  Env.Set("GDK_BACKEND", "x11");
  Env.Set("QT_QPA_PLATFORM", "xcb");
  Env.Set("CLUTTER_BACKEND", "x11");
  Env.Set("ECORE_EVAS_ENGINE", "software_x11");
  Env.Set("VK_USE_PLATFORM_XCB_KHR", "1");
}

void ApplyDisplay(Environment& Env, const DisplayInfo& Display) {
  if (!Display.Display.empty()) {
    Env.Set("DISPLAY", Display.Display);
  }
  if (!Display.XAuthority.empty()) {
    Env.Set("XAUTHORITY", Display.XAuthority);
  }
}

void ApplyRender(Environment& Env, RenderBackend Backend) {
  switch (Backend) {
  case RenderBackend::Zink:
    Env.Set("MESA_LOADER_DRIVER_OVERRIDE", "zink");
    Env.Set("__GLX_VENDOR_LIBRARY_NAME", "mesa");
    Env.Set("LIBGL_KOPPER_DRI2", "1");
    // Threaded GL has caused state-guard faults under emulation with zink.
    Env.Set("mesa_glthread", "false");
    Env.Unset("LIBGL_ALWAYS_SOFTWARE");
    Env.Unset("GALLIUM_DRIVER");
    break;

  case RenderBackend::Llvmpipe:
    Env.Set("LIBGL_ALWAYS_SOFTWARE", "1");
    Env.Set("GALLIUM_DRIVER", "llvmpipe");
    Env.Unset("MESA_LOADER_DRIVER_OVERRIDE");
    Env.Unset("LIBGL_KOPPER_DRI2");
    break;

  case RenderBackend::Native:
    // Only the overrides this launcher understands are cleared.
    // MESA_LOADER_DRIVER_OVERRIDE is deliberately left alone: a user's shell
    // profile may set it globally, and host Mesa translates GL to Vulkan
    // internally even when the guest sees a native libGL. Clearing it here
    // would silently change the graphics stack out from under those hosts.
    Env.Unset("LIBGL_ALWAYS_SOFTWARE");
    Env.Unset("GALLIUM_DRIVER");
    Env.Unset("LIBGL_KOPPER_DRI2");
    break;
  }
}

void PrependPath(Environment& Env, const std::string& Dir) {
  if (Dir.empty()) {
    return;
  }
  const std::string* Existing = Env.Get("PATH");
  Env.Set("PATH", Existing && !Existing->empty() ? Dir + ":" + *Existing : Dir);
}

void AppendToPathList(Environment& Env, const std::string& Key, const std::string& Value) {
  if (Value.empty()) {
    return;
  }
  const std::string* Existing = Env.Get(Key);
  Env.Set(Key, Existing && !Existing->empty() ? *Existing + ":" + Value : Value);
}

} // namespace FastPPCx86::Launcher::HostEnv
