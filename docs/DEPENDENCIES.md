# Build dependencies

Reference host: IBM POWER8 S822LC (8335-GCA), Arch POWER, ppc64le, 4K-page kernel.
Every package and version below is one actually installed on that host and resolved by
CMake there, not a guess from the build files.

Validated against a full-featured configuration (`CMakeCache.txt`, 2026-08-16): thunks
on, 32-bit guest stubs on, FEXConfig + launcher on, tests on.

Package names are Arch POWER, from the repositories ArchPOWER ships. **On other
distributions, match by the header or library file, not by the package name** — the
file columns below are the portable part; the names are not, and have not been
verified anywhere but ArchPOWER.

## 1. Core — required for every configuration

| Package | Version | Provides | Required by |
|---|---|---|---|
| `clang` | 22.1.8-1 | `/usr/bin/clang{,++}` | Hard requirement. GCC is a `FATAL_ERROR` (`CMakeLists.txt:94`); minimum is clang 13.0 (`:103`) |
| `lld` | 22.1.8-1 | `/usr/bin/ld.lld` | Default linker for the clang build |
| `cmake` | 4.4.0-1 | | `cmake_minimum_required(VERSION 3.14)` |
| `ninja` | 1.13.2-3 | | Generator |
| `python` | 3.14.6-1 | | `find_package(Python 3.9 REQUIRED COMPONENTS Interpreter)` (`:417`) — codegen |
| `git` | 2.55.0-1 | | Submodules; version/hash stamping (`:537`) |
| `pkgconf` | 2.5.1-1 | `pkg-config` | `Data/CMake/Findxxhash.cmake:5`; `pkg_check_modules` for ncursesw. Part of `base-devel` |
| `glibc` | 2.43+r37 | | |
| `gcc-libs` | 16.1.1+r346 | libstdc++ | C++20 (`CMAKE_CXX_STANDARD 20`, `:221`) |
| `fmt` | 12.1.0-2 | `/usr/lib/cmake/fmt` | `find_package(fmt QUIET)` (`:449`). Falls back to `External/fmt` |
| `xxhash` | 0.8.3-1 | `/usr/include/xxhash.h` | `CodeCache.cpp`, `Core.cpp`, `OpcodeDispatcher.h`, `SMCSoftInvalidate.h` |
| `range-v3` | 0.12.0-2.1 | `/usr/lib/cmake/range-v3` | `find_package(range-v3 QUIET)` (`:456`). Falls back to `External/range-v3` |

Optional but on by default in every known-good config:

| Package | Version | Gate |
|---|---|---|
| `gdb` | 17.2-1 | `ENABLE_GDB_SYMBOLS`, auto-detected from `gdb/jit-reader.h`. Silently OFF if absent |
| `ccache` | 4.13.2-1 | `ENABLE_CCACHE` (default ON) |

### Submodules

No system package exists for these; `git submodule update --init` or the build fails
at configure time with "does not contain a CMakeLists.txt".

| Submodule | Needed when |
|---|---|
| `External/unordered_dense` | Always — Arch POWER has no `unordered_dense` package (`unordered_dense_DIR-NOTFOUND`) |
| `External/jemalloc_glibc` | Always at default `ENABLE_JEMALLOC_GLIBC_ALLOC=ON` |
| `External/rpmalloc` | Always at default `ENABLE_FEX_ALLOCATOR=ON` |
| `Source/Common/cpp-optparse` | Always. No system package |
| `External/drm-headers` | Always — 32-bit ioctl emulation in LinuxEmulation. No system package |
| `External/fmt`, `External/xxhash`, `External/range-v3` | Only if the system copy is absent |
| `External/Vulkan-Headers` | `BUILD_THUNKS`. Used in preference to any system copy |
| `External/Catch2` | `BUILD_TESTING`. Arch POWER has no Catch2 3 package (`Catch2_DIR-NOTFOUND`) |
| `External/vixl` | `BUILD_TESTING` or `ENABLE_VIXL_{DISASSEMBLER,SIMULATOR}` (`:394`). aarch64 disassembler for emitter tests only |
| `External/zydis` | `ENABLE_ZYDIS` only (default OFF) |
| `External/tracy` | `ENABLE_FEXCORE_PROFILER` with `FEXCORE_PROFILER_BACKEND=tracy` |
| `External/fex-*-tests-bins` | Test-suite binaries only |

## 2. `BUILD_THUNKS=ON`

### Generator

| Package | Version | Resolved | Why |
|---|---|---|---|
| `clang` | 22.1.8-1 | `/usr/lib/cmake/clang` | `find_package(Clang REQUIRED CONFIG)` — `ThunkLibs/Generator/CMakeLists.txt:1` |
| `llvm` | 22.1.8-2 | `/usr/lib/cmake/llvm` | thunkgen links `clang-cpp LLVM` (`:16`) |

libclang-cpp is a build dependency independently of clang-the-compiler: thunkgen is a
libtooling program that parses the interface headers as x86.

### Host-side halves — compile and link time

| Package | Version | Header / library | Consumer |
|---|---|---|---|
| `libglvnd` | 1.7.0-3 | `GL/{gl,glx,glext,glxext}.h`, `EGL/egl.h`, `/usr/lib/libGLX.so` | `libGL_Host.cpp:24-27`, `libEGL_Host.cpp:10`; `find_package(OpenGL REQUIRED)` (`ThunkLibs/HostLibs/CMakeLists.txt:259`) |
| `libxcb` | 1.17.0-1.2 | `xcb/xcb.h` | `libGL_Host.cpp:28`, `include/common/X11Manager.h:11` |
| `libx11` | 1.8.13-1 | `X11/Xlib.h` | `include/common/X11Manager.h:10` |
| `libdrm` | 2.4.134-1 | `xf86drm.h`, `/usr/include/libdrm` | `libdrm/Host.cpp:9`, `libdrm_interface.cpp:3` |
| `libxshmfence` | 1.3.3-1.1 | `X11/xshmfence.h` | `libxshmfence/Host.cpp` |
| `wayland` | 1.25.0-1 | `wayland-client.h`, `/usr/include/wayland` | `libwayland-client/Host.cpp` |
| `alsa-lib` | 1.2.16.1-1 | `alsa/asoundlib.h` | `libasound/libasound_Host.cpp`. Built even though the thunk ships disabled |
| `vulkan-icd-loader` | 1.4.350.0-1 | `/usr/lib/libvulkan.so` | Vulkan thunk target |

SDL2 is **not** a dependency — that thunk is commented out at
`ThunkLibs/HostLibs/CMakeLists.txt:210`.

### Guest-side stubs

| Option | Default | Needs |
|---|---|---|
| `BUILD_GUEST_THUNKS` | ON | An x86-64 cross toolchain. Reference: `x86_64-pc-linux-gnu-gcc` 15.2.1 + `x86_64-pc-linux-gnu-glibc` 2.43, plus `-binutils`, `-libxcrypt`, `-linux-api-headers`. `Data/CMake/toolchain_x86_64.cmake:63` also accepts the `x86_64-linux-gnu-` and `x86_64-unknown-linux-gnu-` prefixes, so a crosstool-NG or Debian-style toolchain works too |
| `BUILD_GUEST_THUNKS_32` | ON | A **multilib/i686 sysroot**. No distribution packages one. Use an extracted x86-64 RootFS (`FEXRootFSFetcher` produces one; default location `$XDG_DATA_HOME/fex-emu/RootFS/<name>`), pass it as `X86_DEV_ROOTFS_32`, and set `ENABLE_CLANG_GUEST_THUNKS_32=ON` |

That RootFS needs the 32-bit gcc runtime installed into it — `crtbeginS.o` and
`libgcc.a`, owned by `gcc`, not by `lib32-gcc-libs` — or the stub link fails with
`cannot open crtbeginS.o` / `-lgcc`. Install `gcc`, `lib32-gcc-libs` and `lib32-glibc`
into the RootFS with your distribution's package manager pointed at it as root.

`X86_DEV_ROOTFS` may point at a standalone crosstool-NG x86-64 sysroot (~90M is
typical). Left at its default `"/"` it means "unset", and CMake falls back to the
`x86_64-pc-linux-gnu` cross toolchain's own sysroot — which is what the ArchPOWER
package does, and is the simpler path.

Never point the x86 interface parse at ppc64le headers to make a build succeed — that
parse decides guest data layout and will silently emit wrong repack code.

## 3. GUI and launcher

| Option | Package | Version | CMake |
|---|---|---|---|
| `BUILD_FEXCONFIG` | `qt6-base` + `qt6-declarative` | 6.11.1-1 / 6.11.1-3 | `find_package(Qt6 COMPONENTS Qml Quick Widgets)`, Qt5 fallback — `Source/Tools/CMakeLists.txt:5` |
| `BUILD_LAUNCHER` | `qt6-base` | 6.11.1-1 | Widgets only, deliberately no Qml/Quick — `:19` |
| `BUILD_LAUNCHER_TUI` | `ncurses` | 6.6-2 | `pkg_check_modules(NCURSESW REQUIRED)` — `FastPPCx86Launcher/CMakeLists.txt:82`. Links no Qt |

## 4. Tests (`BUILD_TESTING=ON`)

| Package | Version | Why |
|---|---|---|
| `nasm` | 3.01-1 | Assembles `unittests/ASM` and `unittests/32Bit_ASM` |

Plus the `Catch2`, `vixl` and `fex-*-tests-bins` submodules. A green ctest run also
needs `DISPLAY=:0` and `mesa-utils` + `vulkan-tools` inside the guest RootFS.

## 5. Runtime only

`dlopen`'d by the host thunks at load time, so invisible to the linker and to
`namcap`. A missing one makes `fexldr_init_<lib>` return false and the thunk silently
stops working.

`libglvnd` · `vulkan-icd-loader` + an ICD · `libdrm` · `libxshmfence` · `wayland` ·
`libx11` · `libxcb`

Optional: `squashfuse` / `erofs-utils` (RootFS images), `wget`, `xz`,
`pipewire-pulse` or `pulseaudio` (guests speak the PulseAudio protocol).

## 6. Availability

Everything in sections 1-4 is a stock package in the ArchPOWER repositories except
the items below. These are the only ones that need sourcing.

| Item | Where it comes from |
|---|---|
| Submodules (§1) | `git submodule update --init --recursive`. All public HTTPS; no credentials needed |
| x86-64 cross toolchain | ArchPOWER packages `x86_64-pc-linux-gnu-{gcc,glibc,binutils}`. Elsewhere: a distro `gcc-x86-64-linux-gnu` equivalent, or build one with crosstool-NG. Only the triple prefix matters — see `Data/CMake/toolchain_x86_64.cmake:63` for the three accepted spellings |
| Multilib x86 sysroot (32-bit guest stubs) | Not packaged by anyone. Run `FEXRootFSFetcher` to download an x86-64 RootFS, extract it, point `X86_DEV_ROOTFS_32` at it, then install the 32-bit gcc runtime into it as described in §2 |

Set `-DBUILD_GUEST_THUNKS_32=OFF` to skip the last two entirely. 64-bit titles still
get thunks; 32-bit titles fall back to emulated libraries.

Non-ppc64le and non-Arch builders: the file columns in §1-4 identify what is actually
`#include`d or linked. Resolve those to your distribution's package names locally —
this document does not claim to know them.

## 7. Install lines

Full configuration:

```sh
pacman -S --needed \
  clang lld llvm cmake ninja python git pkgconf ccache gdb nasm \
  fmt xxhash range-v3 \
  qt6-base qt6-declarative ncurses \
  libglvnd libx11 libxcb libdrm libxshmfence wayland alsa-lib vulkan-icd-loader \
  x86_64-pc-linux-gnu-gcc x86_64-pc-linux-gnu-glibc
git submodule update --init --recursive
```

Core only — no thunks, no GUI, no tests — needs section 1 alone:

```sh
cmake -S . -B build -GNinja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_THUNKS=OFF -DBUILD_FEXCONFIG=OFF \
  -DBUILD_LAUNCHER=OFF -DBUILD_LAUNCHER_TUI=OFF -DBUILD_TESTING=OFF
```

## 8. Host requirements

- **ppc64le.** `CMakeLists.txt:138` rejects other processors. x86-64 hosts need
  `ENABLE_X86_HOST_DEBUG=True` and are debug-only.
- **4K-page kernel** for `SMCChecks=mtrack`. See the note in `README.md`.
- `TUNE_CPU` defaults to `native`, which bakes `-march=native` into the binary. Set
  `-DTUNE_CPU=none` for anything another machine will run.
- `BUILD_TESTS=False` is not enough to skip tests — `unittests/` is gated on
  `BUILD_TESTING`.
- `libfexbridge.so` builds only with `-DCMAKE_POSITION_INDEPENDENT_CODE=ON`
  (`Source/Tools/CMakeLists.txt:45`). It adds no external dependency.

## 9. Divergence from the ArchPOWER package

`packaging/archpower/PKGBUILD` is the packaged subset, not a superset:

- It omits `ccache` and `nasm` (build caching off, tests off) — correct for a package.
- It does not set `CMAKE_POSITION_INDEPENDENT_CODE`, so the shipped package contains
  no `libfexbridge.so`.
- Its `pkgver` is a committed placeholder; `pkgver()` recomputes at build time.

`Data/Dockerfile` is inherited upstream scaffolding. It clones `FEX-Emu/FEX` from
GitHub, targets Ubuntu 22.04, and its package list (`libcap-dev libglfw3-dev
libepoxy-dev libsdl2-dev python3-dev`) does not describe this project. None of those
are dependencies here. Do not use it as a reference.
