# Canonical build configuration

This file records the build-configuration invariants that make FEX on POWER9
(this branch, `power9`) render FTL and Factorio correctly. Any change to
anything listed here — CMake option, toolchain, sysroot, invocation — is a
config change and must be committed with an update to this file in the same
commit.

The rule exists because CMake options are invisible to `git bisect`, code
review, and `ctest`. `ENABLE_CLANG_THUNKS=ON` broke 64-bit GL for two days
while ctest reported 7014/7014, and finding it cost a full 127-commit bisect
followed by a rootfs / kernel / host-Mesa / shader-cache / guest-vendor
elimination round before it was named. A tracked file in the repo cannot
disappear the way a build-tree CMakeCache entry can.

## Canonical known-good — 2026-07-31 (25c8d3bff)

Confirmed with FTL 1.6.12 "Running Game!" and Factorio 2.x "Factorio
initialised" on a fresh minimal rootfs (fresh unsquashfs of Ubuntu 24.04, dev
headers extracted from packages.ubuntu.com debs, no apt-installed apps).

### Thunk build

| Option                    | Value | Why                                                                 |
|---------------------------|-------|---------------------------------------------------------------------|
| `ENABLE_CLANG_THUNKS`     | OFF   | ON corrupts the guest/host packed-args struct layout; FTL crashes at "Creating FBO..." and Factorio dies ~2 s after "OpenGL initialized". Guest stubs must be built with the ct-ng cross-GCC below. |
| `BUILD_THUNKS_32BIT`      | OFF   | Turning this on is what pulled in clang thunks. Leave off on this host until an i686 cross-GCC is available. |
| `BUILD_GUEST_THUNKS_32`   | OFF   | Same reason as above; both flags must be off together to prevent the ExternalProject from configuring a 32-bit guest sub-build. |
| `ENABLE_CLANG_GUEST_THUNKS` | OFF | Default. Do not enable without solving the layout divergence upstream. |
| `X86_DEV_ROOTFS`          | `/home/jbettcher/Development/fexrootfs/RootFS/Ubuntu_24_04` | Sysroot for guest thunk builds. Changing it requires a thunk rebuild. |
| `X86_DEV_GCC_TOOLCHAIN`   | `/home/jbettcher/Development/fexrootfs/x-tools/x86_64-linux-gnu` | ct-ng x86_64-linux-gnu-gcc 15.2.0; `PATH` must include its `bin/` for cmake to find `x86_64-linux-gnu-gcc`. |

### FEX build

| Option                    | Value    | Why                                                                 |
|---------------------------|----------|---------------------------------------------------------------------|
| `CMAKE_BUILD_TYPE`        | Release  | Debug/RelWithDebInfo change codegen paths and are separate work items. |
| `CMAKE_C_COMPILER`        | `/usr/bin/clang` | Host ppc64le clang builds FEX and the host thunks. This is independent of the guest-thunk toolchain choice. |
| `CMAKE_CXX_COMPILER`      | `/usr/bin/clang++` | Same. |
| `BUILD_THUNKS`            | ON (in the thunks build tree) / OFF (in the FEX build tree) | Two build trees: one for FEX, one for thunks. |
| `BUILD_TESTS`             | (unset — use default) | **WARNING: do not set to OFF.** `BUILD_TESTS=OFF` removes the `TestHarnessRunner` target from the build but does **not** disable ctest's test discovery — ctest will still enumerate the test suite and then fail every entry with `FileNotFoundError: TestHarnessRunner`, producing 7+ phantom failures that look identical to a real regression. This class of false signal has cost the investigation time twice this cycle (once when I passed `-DBUILD_TESTS=OFF` while reproducing the config change in `/tmp/ftl-clean`, and later when the same 7 failures reappeared and looked like a suspect commit). Leave the option unset. |

### Build invocations

Configure (FEX tree):
```
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=/usr/bin/clang \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
      -DBUILD_THUNKS=OFF ..
```

Configure (thunks tree):
```
PATH=/home/jbettcher/Development/fexrootfs/x-tools/x86_64-linux-gnu/bin:$PATH \
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=/usr/bin/clang \
      -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
      -DBUILD_THUNKS=TRUE \
      -DBUILD_THUNKS_32BIT=OFF -DBUILD_GUEST_THUNKS_32=OFF \
      -DENABLE_CLANG_THUNKS=OFF -DENABLE_CLANG_GUEST_THUNKS=OFF \
      -DX86_DEV_ROOTFS=$ROOTFS \
      -DX86_DEV_GCC_TOOLCHAIN=/home/jbettcher/Development/fexrootfs/x-tools/x86_64-linux-gnu ..
```

Build (both trees): `ninja -j128` on this 44-core box, with `PATH` still
pointing at the ct-ng bin dir for the thunks tree. Never `--target FEX`
alone — that skips TestHarnessRunner and every ctest run after fails with
`FileNotFoundError`.

### Rootfs

- Fresh unsquashfs of `Ubuntu_24_04.sqsh` (Dec 2025 snapshot).
- Chroot patch applied (`build-probes/patch_rootfs_chroot.py <rootfs>`).
- `chown -R $USER:$USER <rootfs>`.
- No `apt update` / `apt install`. Any additional guest binaries or dev
  headers are installed by extracting the specific `.deb`s manually
  (`ar x deb && tar --zstd -xf data.tar.zst -C $ROOTFS`) — see
  `~/Downloads/thunk-dev-debs/` for the 25 packages the thunks tree needs.

## Corollaries — reproducing a known-good commit

A `git worktree add <commit>` inherits the **source** at that commit only. It
does not inherit the build configuration that was in place when that commit
was written. If you rebuild a known-good commit as a control, you must also
reproduce the CMake options that were active then, or the control is not
valid — reading a source-only checkout as "the source is broken" is the
mistake that cost two days in this thread.

Look up the historical config from this file (past sections are kept below)
or from the CMakeCache of the earlier build if it survives.

## When to update this file

Any commit that changes:
- a CMake option default in a `CMakeLists.txt`
- the chosen toolchain for FEX or thunks
- the rootfs identity or its extraction recipe
- the standing build invocation

must include an update to this file in the same commit. If the CMake option
default is what changes, the "Value" column here changes with it. If the
recommended flag flips or a new option becomes load-bearing, add a row.
