# Arch Linux POWER packaging for FastPPCx86

`PKGBUILD` for `fastppcx86` — the ppc64le x86/x86-64 emulator (downstream port of
FEX-Emu). Targets [Arch Linux POWER](https://archlinuxpower.org/), whose
architecture name is `powerpc64le`.

## Host requirements

* An Arch POWER (`powerpc64le`) machine — POWER8 or newer. Cross-building is not
  supported here.
* `clang` **and** `lld`. FEX hard-fails on GCC (`FATAL_ERROR` in the top-level
  `CMakeLists.txt`); clang 13+ is the minimum, and the build is validated with
  the current Arch POWER clang.
* `cmake`, `ninja`, `python`, `git`, `gdb` (for `jit-reader.h`, used by the
  GDB symbol integration), `llvm`.
* Optional: `range-v3` — if the system package is installed it is used, otherwise
  the bundled submodule is compiled.
* Network access for the first build: the third-party submodules (`fmt`,
  `xxhash`, `range-v3`, `unordered_dense`, `jemalloc_glibc`, `rpmalloc`,
  `drm-headers`, `cpp-optparse`) are fetched as regular makepkg git sources.
* Roughly 15 GB of free space in the build directory and a fair amount of RAM;
  the build is ~1500 translation units of heavy C++.

### 4K page kernel

The SMC (self-modifying-code) `mtrack` path — which is what makes Mono/Unity
titles usable — needs a **4 KiB page-size kernel**. Arch POWER's stock kernel
builds exist in both 4K and 64K page flavours; check with `getconf PAGESIZE`
(must print `4096`). On a 64K-page kernel the emulator still runs but falls back
to a slower software SMC path.

The package itself builds fine on either; this only affects runtime behaviour.

## Building

From a checkout of the repository:

```sh
cd packaging/archpower
makepkg -s
```

The `source` array points at the git repository this PKGBUILD lives in
(`$startdir/../..`), so the package always builds the checkout you are standing
in — including uncommitted *commits*, though not uncommitted working-tree
changes (makepkg clones from `HEAD` of the repo, not from the dirty tree).

To build a different checkout or a remote:

```sh
FASTPPCX86_GIT_URL='file:///path/to/another/clone' makepkg -s
```

When the repository goes public, uncomment the `https://` `_repourl` line at the
top of the PKGBUILD and drop the `file://` default.

The committed `.SRCINFO` was generated with the public URL, not the local
`file://` default (otherwise it would contain a machine-local absolute path).
Regenerate it the same way after changing package metadata:

```sh
FASTPPCX86_GIT_URL='https://github.com/daedalao/fastppcx86.git' \
  makepkg --printsrcinfo > .SRCINFO
```

### Iterating

Standard makepkg flags apply. `makepkg -o` fetches + wires up the submodules
only; `makepkg -e --noprepare` reuses an existing `src/` tree so a failed build
can be resumed without re-cloning.

On a shared machine, keep the build polite:

```sh
flock /tmp/fex_build.lock nice -n19 taskset -c <high cores> makepkg -s
```

## What the package configures

The CMake options mirror the known-good POWER9 development build:

| Option | Value | Why |
| --- | --- | --- |
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | matches the validated build |
| `CMAKE_C/CXX_COMPILER` | `clang` / `clang++` | GCC is rejected outright |
| `BUILD_TESTING` | `OFF` | no unit tests in a package; also why `nasm` is not a makedep |
| `BUILD_THUNKS` | `OFF` | needs an x86-64 (and i686) cross toolchain, not in the Arch POWER repos |
| `BUILD_FEXCONFIG` | `ON` | the Qt6 settings GUI |
| `ENABLE_LTO` | `OFF` | as in the validated build; `options=('!lto')` keeps makepkg from re-adding it |
| `ENABLE_JEMALLOC_GLIBC_ALLOC` | `ON` | required for thunk execution |
| `ENABLE_FEX_ALLOCATOR` | `ON` | rpmalloc-backed `fextl` allocations |
| `ENABLE_GDB_SYMBOLS` | `ON` | installs the `FEXGDBReader` JIT reader |
| `TUNE_CPU` | `none` | upstream defaults to `native`, which is wrong for a distributable package. Set `power9`/`power10` for a machine-specific rebuild |
| `OVERRIDE_VERSION` / `OVERRIDE_HASH` | from git | the commit hash is also the JIT code-cache key, so it must be accurate |

### Thunks

Host/guest thunk libraries (GL, Vulkan, X11, SDL2, ALSA, …) are **not** built by
this package. They need an `x86_64-pc-linux-gnu` cross toolchain — and the
32-bit set additionally an i686 one, which Arch POWER does not ship. Build them
out of tree with `-DBUILD_THUNKS=ON` and install into `/usr/lib/fex-emu` and
`/usr/share/fex-emu` alongside the package if you need them.

## What gets installed

* `/usr/bin/` — `FEX` (the loader/interpreter), `FEXInterpreter` (compat symlink
  to `FEX`), `FEXServer`, `FEXBash`, `FEXConfig`, `FEXGetConfig`,
  `FEXRootFSFetcher`, `FEXOfflineCompiler`, `FEXpidof`
* `/usr/lib/libFEXCore.so`, `/usr/lib/gdb/libFEXGDBReader.so` and the FEXCore
  headers under `/usr/include/FEXCore/` (upstream's `Development` install
  component; they are the companion to the installed shared library)
* `/usr/share/fex-emu/` — `ThunksDB.json` and the per-application config JSONs
  from `Data/AppConfig/`
* `/usr/lib/binfmt.d/FEX-x86.conf`, `FEX-x86_64.conf` — binfmt_misc handlers.
  Upstream only installs these on aarch64 hosts, so the PKGBUILD generates them
  from the same `.conf.in` templates. Activate with
  `systemctl restart systemd-binfmt`.
* `/usr/share/man/man1/FEX.1.gz`
* `/usr/share/doc/fastppcx86/` — `README.md` and, when present, `GAMING.md`
* `/usr/share/licenses/fastppcx86/LICENSE` (MIT, from upstream FEX)

## Validation

Build the package and inspect it without installing:

```sh
namcap PKGBUILD
namcap fastppcx86-*.pkg.tar.zst
pacman -Qlp fastppcx86-*.pkg.tar.zst
```

`namcap PKGBUILD` is clean. On the package itself the only remaining warnings
are `Dependency included, but may not be needed` for `glibc`, `gcc-libs`, `fmt`,
`xxhash` and `qt6-base` — namcap's provider resolution on Arch POWER is
inconsistent here (it simultaneously reports those same libraries as referenced
by the binaries), and all five really are linked. The `fastppcx86-debug`
package's `Symlink ... points to non-existing` errors are the normal artefact of
split debug packages: the `.build-id` symlinks point at files that live in the
main package.

Because `debug` is in the default Arch POWER `OPTIONS`, every build also
produces a `fastppcx86-debug` package. FEX resolves its own SIGILL/JIT frames
from symbols, so keep that package around when debugging emulation problems.

The build was validated on a POWER9 host (Arch POWER, clang 22.1.8, cmake 4.4,
ninja 1.13) — see the top of this file for the polite-build invocation.
