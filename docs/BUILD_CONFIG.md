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

## Build identity / code-cache invalidation — 2026-08-01

**This change forces a cmake reconfigure on the next build.** `CMakeLists.txt`
and `FEXCore/CMakeLists.txt` both changed, so ninja re-runs cmake before the
first compile. That is expected; nothing needs to be wiped.

### What changed

`git_version.h` is now regenerated at **build** time, not only at cmake
configure time.

- `Scripts/GenerateGitVersion.cmake` is the single implementation of the
  build-identity computation. It is `include()`d by the top-level
  `CMakeLists.txt` at configure time (which also guarantees the header exists
  before anything compiles, and leaves `GIT_HASH` / `GIT_DESCRIBE_STRING` set
  for `Source/Steam/VERSIONS.txt.in`), and re-run via `cmake -P` by the
  `git_version_header` custom target on every `ninja` invocation.
- The two call sites must stay in lockstep. If they ever computed different
  content, the header would be rewritten on every build and cascade a rebuild
  of its consumers — which is why the logic lives in one file rather than
  being duplicated.

### Why

`FEXCore/Source/Interface/Core/CodeCache.cpp` gates code-cache loads on
`GIT_HASH` and on nothing else that tracks the build. The header check is
`Magic` / `FormatVersion` / `FEXVersion` / non-zero block count — no mtime, no
path, no size. With configure-time-only detection, an incremental `ninja`
after a JIT source edit produces a binary that happily loads caches emitted by
the *previous* build, so an A/B measurement across a codegen change compares
old code against old code and reads as "no regression".

`EnableCodeCachingWIP` defaults false, so this is a **benchmarking gate, not a
live correctness bug**. It matters when measuring, not when running.

### What the hash covers

| Covered | Not covered |
|---|---|
| `git rev-parse HEAD` | Untracked files (`git diff HEAD` does not see them) |
| `git diff HEAD --binary -- ':!External'` — every tracked, modified, non-submodule file in the tree, including `Source/` (volatile-metadata handling, Mono detection) and `Config.json.in` (defaults compile into `ConfigValues.inl`) | Uncommitted working-tree edits *inside* a submodule under `External/` |
| Submodule pointer bumps — a changed gitlink is a change to the top-level tree, so it still shows in the diff | Compiler version / CMake options / `CMAKE_BUILD_TYPE` (they were never covered) |

The `':!External'` exclusion is the only narrowing versus the previous
whole-tree `git diff`, and it is deliberate. `External/` is ~554 MB across 16
submodules and is essentially the entire cost. Measured on the aarch64 host:
whole-tree `git diff HEAD --binary` 76.6 s cold / ~2.1 s warm; with
`':!External'` ~0.7 s. Exclusion verified in this repo: `git ls-files` 3329
paths, `git ls-files -- ':!External'` 3188, `git ls-files -- External` 141.

A previously proposed variant that hashed only `FEXCore/Source`,
`FEXCore/include` and `CodeEmitter` was **rejected** — it drops `Source/` and
`Config.json.in`, both of which affect codegen. Do not reintroduce it.

### Requirements and costs

- **git >= 1.9** on the build host, for magic pathspec (`:!`) support.
- Every `ninja` invocation, including a no-op one, now runs one `git rev-parse`
  plus one `git diff` (~0.7 s measured on aarch64; faster on the POWER9 box)
  and prints `Refreshing FEX build identity (git_version.h)`.
- A no-op build does **not** recompile anything. The generator ends in
  `configure_file()`, which does not rewrite unchanged content, and the target
  declares the header as `BYPRODUCTS` so Ninja's `restat` stops the edge there.
  Verified on a standalone ninja reproducer: repeated no-op builds run only the
  refresh step; a dirty-tree edit changes the hash and rebuilds exactly the
  consuming TU plus the link, leaving unrelated objects alone.
- When the hash does change, nine translation units rebuild plus their links:
  `FEXCore/Source/Interface/Core/{CodeCache,CPUID}.cpp`,
  `Source/Common/SHMStats.cpp`,
  `Source/Tools/LinuxEmulation/LinuxSyscalls/{EmulatedFiles/EmulatedFiles,Syscalls/Info,ThreadManager,x32/Info}.cpp`,
  `Source/Tools/FEXGetConfig/Main.cpp`, `Source/Tools/FEXServer/ArgumentLoader.cpp`.
  Their five targets (`FEXCore_object`, `Common`, `LinuxEmulation`,
  `FEXGetConfig`, `FEXServer`) carry an `add_dependencies` edge on
  `git_version_header` at the end of the top-level `CMakeLists.txt`. **If you
  add a new `#include <git_version.h>`, add its target there.**

### Escape hatch — unchanged

`-DOVERRIDE_HASH=<hex>` and `-DOVERRIDE_VERSION=<string>` still bypass
detection entirely, for reproducible and release builds. With `OVERRIDE_HASH`
set to anything but `detect`, no git command runs at configure or build time.

| Option             | Value      | Why |
|--------------------|------------|-----|
| `OVERRIDE_HASH`    | `detect`   | Default. Leave it for development so code-cache invalidation tracks the working tree. Pin it for release/reproducible builds. |
| `OVERRIDE_VERSION` | `detect`   | Default. Note `git describe --abbrev=7` fails in this repo (no tags), so `GIT_DESCRIBE_STRING` renders empty — pre-existing behaviour, unchanged by this commit. |

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
