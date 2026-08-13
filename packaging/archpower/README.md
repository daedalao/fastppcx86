# Arch Linux POWER packaging for FastPPCx86

`PKGBUILD` for `fastppcx86`, the ppc64le x86/x86-64 emulator (downstream port of
FEX-Emu). Targets [Arch Linux POWER](https://archlinuxpower.org/), whose
architecture name is `powerpc64le`.

## Host requirements

* An Arch POWER (`powerpc64le`) machine, POWER8 or newer. Cross-building is not
  supported here.
* `clang` and `lld`. FEX hard-fails on GCC (`FATAL_ERROR` in the top-level
  `CMakeLists.txt`). `clang` also supplies `libclang-cpp`, which the thunk
  generator links against.
* `cmake`, `ninja`, `python`, `git`, `gdb` (for `jit-reader.h`, used by the GDB
  symbol integration), `llvm`.
* `x86_64-pc-linux-gnu-gcc` and `x86_64-pc-linux-gnu-glibc`. Thunks are built
  from source and these supply the x86 target for the interface parse and the
  64-bit guest stub libraries.
* Development headers for the host thunks: `alsa-lib`, `libdrm`, `libglvnd`,
  `libx11`, `libxcb`, `libxshmfence`, `wayland`.
* `range-v3` is optional. If the system package is installed it is used,
  otherwise the bundled submodule is compiled.
* Network access for the first build: the third-party submodules are fetched as
  regular makepkg git sources.
* Roughly 15 GB of free space in the build directory and a fair amount of RAM;
  the build is ~1500 translation units of heavy C++.

`makedepends` in the PKGBUILD is the authoritative list.

### 4K page kernel

The SMC (self-modifying-code) `mtrack` path, which is what makes Mono/Unity
titles usable, needs a 4 KiB page-size kernel. Arch POWER's stock kernel builds
exist in both 4K and 64K page flavours; check with `getconf PAGESIZE` (must
print `4096`). On a 64K-page kernel the emulator still runs but must fall back
to `SMCChecks=full`, which validates code before every run and is much slower.

The package itself builds on either; this only affects runtime behaviour.

## Building

```sh
cd packaging/archpower
makepkg -s
```

The `source` array points at `https://github.com/daedalao/fastppcx86.git`,
branch `main`. `main` is the deployment branch: development happens on
`daedalao-wt` and is merged into `main` at release time (see
[docs/ReleaseProcess.md](../../docs/ReleaseProcess.md)). Building the working
branch or a local clone:

```sh
FASTPPCX86_GIT_BRANCH=daedalao-wt makepkg -s
FASTPPCX86_GIT_URL='file:///path/to/another/clone' makepkg -s
```

Regenerate `.SRCINFO` after changing package metadata, with the default URL so
no machine-local path leaks in:

```sh
makepkg --printsrcinfo > .SRCINFO
```

### 32-bit guest stubs

The 64-bit guest stub libraries always build, using the repo cross gcc. The
32-bit ones need an i686/multilib x86 sysroot, which the Arch POWER repos do not
carry. Point `FASTPPCX86_X86_ROOTFS` at an extracted multilib x86-64 RootFS to
build and ship them too:

```sh
FASTPPCX86_X86_ROOTFS=$HOME/.local/share/fex-emu/RootFS/ArchLinux makepkg -s
```

Without it, 64-bit titles get thunks and 32-bit titles fall back to the emulated
libraries in the rootfs. Nothing breaks; 32-bit graphics are just slower.

### Iterating

`makepkg -o` fetches and wires up the submodules only. `makepkg -e --noprepare`
reuses an existing `src/` tree so a failed build can be resumed without
re-cloning.

On a shared machine, keep the build polite:

```sh
flock /tmp/fex_build.lock nice -n19 taskset -c <high cores> makepkg -s
```

## What the package configures

| Option | Value | Why |
| --- | --- | --- |
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | matches the validated build |
| `CMAKE_C/CXX_COMPILER` | `clang` / `clang++` | GCC is rejected outright |
| `BUILD_TESTING` | `OFF` | no unit tests in a package; also why `nasm` is not a makedepend |
| `BUILD_THUNKS` | `ON` | host-side thunk libraries |
| `BUILD_GUEST_THUNKS` | `ON` | 64-bit guest stubs, via the repo cross gcc |
| `BUILD_GUEST_THUNKS_32` | conditional | `ON` only when `FASTPPCX86_X86_ROOTFS` is set |
| `BUILD_FEXCONFIG` | `ON` | the Qt6 settings GUI |
| `ENABLE_LTO` | `OFF` | as in the validated build; `options=('!lto')` keeps makepkg from re-adding it |
| `ENABLE_JEMALLOC_GLIBC_ALLOC` | `ON` | required for thunk execution |
| `ENABLE_FEX_ALLOCATOR` | `ON` | rpmalloc-backed `fextl` allocations |
| `ENABLE_GDB_SYMBOLS` | `ON` | installs the `FEXGDBReader` JIT reader |
| `ENABLE_ZYDIS` | `OFF` | guest disassembly is a debugging feature |
| `TUNE_CPU` | `none` | upstream defaults to `native`, which is wrong for a distributable package. Set `power9`/`power10` for a machine-specific rebuild |
| `OVERRIDE_VERSION` / `OVERRIDE_HASH` | from git | the commit hash is part of the JIT code-cache key, so it must be accurate |

`BUILD_THUNKS_32BIT` and `X86_DEV_ROOTFS` are deliberately left at their
CMakeLists defaults. See the comment in `build()`.

### Thunks

Thunks let guest OpenGL and Vulkan calls run in the host's own driver instead of
being emulated instruction by instruction, so they are the difference between
usable and unusable 3D. Everything is built from source against the ArchPOWER
x86_64 cross packages.

One rule matters more than the rest: thunkgen parses the interface headers with
an **x86** target, because the generated code encodes guest data layout. Parsing
them against ppc64le headers is unsound. It has produced silently different
repack code for libwayland-client and made thunkgen reject valid Vulkan structs.
Never relax the parse to host headers to make a build succeed.

The host thunks reach their target library with `dlopen()` rather than a link,
so those libraries are runtime `depends` that namcap cannot infer. They are
listed explicitly in the PKGBUILD.

## What gets installed

* `/usr/bin/`: `FEX` (the loader/interpreter), `FEXInterpreter` (compat symlink
  to `FEX`), `FEXServer`, `FEXBash`, `FEXConfig`, `FEXGetConfig`,
  `FEXRootFSFetcher`, `FEXOfflineCompiler`, `FEXpidof`
* `/usr/lib/libFEXCore.so`, `/usr/lib/gdb/libFEXGDBReader.so` and the FEXCore
  headers under `/usr/include/FEXCore/`
* `/usr/lib/fex-emu/HostThunks/`, `HostThunks_32/`: host-side thunk libraries
* `/usr/share/fex-emu/GuestThunks/` and, when `FASTPPCX86_X86_ROOTFS` was set,
  `GuestThunks_32/`: guest-side stub libraries
* `/usr/share/fex-emu/Config.json`: system-wide defaults. Ships a `ThunksDB`
  block enabling Vulkan, GL, EGL, WaylandClient, drm and xshmfence. `asound`
  ships `0`: the guest stub exports no ELF symbol versions, so versioned ALSA
  lookups fail and `steamwebhelper` crash-loops. Game audio goes through
  PulseAudio and does not need it.
* `/usr/share/fex-emu/ThunksDB.json` and the per-application config JSONs from
  `Data/AppConfig/`
* `/usr/lib/binfmt.d/FEX-x86.conf`, `FEX-x86_64.conf`: binfmt_misc handlers.
  Upstream installs these on aarch64 hosts only, so the PKGBUILD generates them
  from the same `.conf.in` templates. Activate with
  `systemctl restart systemd-binfmt`.
* `/usr/share/man/man1/FEX.1.gz`
* `/usr/share/doc/fastppcx86/`: `README.md`, `GAMING.md`, `CPUID.md`
* `/usr/share/licenses/fastppcx86/LICENSE` (MIT, from upstream FEX)

## Validation

Build the package and inspect it without installing:

```sh
namcap PKGBUILD
namcap fastppcx86-*.pkg.tar.zst
pacman -Qlp fastppcx86-*.pkg.tar.zst
```

Expect namcap to report `Dependency included, but may not be needed` for the
`dlopen`'d thunk libraries; it cannot see a dependency that is not DT_NEEDED.
It has also reported that warning for `glibc`, `gcc-libs`, `fmt`, `xxhash` and
`qt6-base` while simultaneously reporting those same libraries as referenced by
the binaries. All of them really are linked. The `fastppcx86-debug` package's
`Symlink ... points to non-existing` errors are the normal artefact of split
debug packages: the `.build-id` symlinks point at files in the main package.

Because `debug` is in the default Arch POWER `OPTIONS`, every build also
produces a `fastppcx86-debug` package. FEX resolves its own SIGILL/JIT frames
from symbols, so keep that package when debugging emulation problems.

The from-source thunk build was validated end to end on 2026-08-10
(`r14768.bb43a5b`), with thunkgen output byte-identical to the maintainer's
ct-ng x86 sysroot reference at both bitnesses.
