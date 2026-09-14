# 64K + 4K from one build: execution plan (2026-09-11)

Third document in the series. `PAGE_SIZE_AUDIT.md` (a4b9668b9) classified the
sites, `PAGE_SIZE_64K_PLAN.md` (4b7e6a202) is the design. This one is the
schedule: what to build, in what order, how each step is verified on BOTH
kernels, and what is allowed to touch the shipping 4K build. Read the other
two first; this one does not repeat their site lists.

Goal: the gaming build (`src/build-smc`, one tree, one binary) runs games on
the 64K kernel (op64k, `7.2.0-books-64k`) and on the 4K kernel (op4k) with
no rebuild and no `#ifdef`. Host page size is a runtime quantity.

---

## 0. What changed since the design was written (measured 2026-09-11)

1. **The GPU works on 64K.** `~/Projects/power8/REPORT-amdgpu-64k-power8.md`
   (final, 2026-09-11): user-VM DMA mistranslation was `max_pfn` growth from
   the KFD ZONE_DEVICE registration, fixed in powerpc `add_pages`. RADV
   26.1.5 on the V620 is live on op64k. The design's "Wine/games are out of
   scope on 64K" premise is gone; games are the goal.
2. **op64k shares `/home` with op4k.** Only the root drive differs. The gaming
   tree `~/projects/fex-emu-ppc64le/src/fex-src` (849d7ab4f) and
   `src/build-smc/Bin/FEX` (built 09-08) are already present on the 64K boot,
   as are `~/fex-scripts`, the rootfs, the wine build and the game library.
   No relay step is needed; the 64K boot just has no binfmt registration.
3. **Nothing from P0 has landed.** 182 raw `FEX_PAGE_SIZE` uses in 37 files;
   no `HostPage` module; no `FEX_GUEST_PAGE_SIZE`. Heaviest files:
   `SyscallsSMCTracking.cpp` 34, `64BitAllocator.cpp` 19, `FexBridge.cpp` 14,
   `FEXInterpreter.cpp` 12, `LinuxAllocator.cpp` 11.
4. **The first thing that dies on 64K is not FEX.** Running the current
   binary on op64k:
   ```
   <jemalloc>: Unsupported system page size
   terminate called without an active exception
   ```
   `External/jemalloc_glibc/pregen/.../jemalloc_internal_defs.h:193` bakes
   `LG_PAGE 12`. jemalloc refuses any host page larger than its compiled
   page. This aborts before `main`, before the page-size gate, with or
   without `FEX_ALLOW_UNSUPPORTED_PAGE_SIZE`. FEXCore's own allocator is
   rpmalloc (`AllocatorHooks.cpp:105`, already configured at 64K) and is not
   the problem.
5. **The design's three open questions are answered** (probe program on
   op64k, `AT_PAGESZ=65536`):

   | question | answer |
   |---|---|
   | `MAP_FIXED_NOREPLACE` hint at 2^48 | succeeds; 2^44 through 2^51 all succeed, 2^52 ENOMEM. The 48-bit steal allocator (`OSAllocator_64Bit`) WILL engage on 64K. In scope, as the design feared. |
   | `sbrk(0)` at main | 64K-aligned (`0x10001d80000`). |
   | `AT_PAGESZ` for FEX's own link | 65536, glibc handles it. Nothing in our link scripts assumes 4K. |
   | 4K-aligned `MAP_FIXED` / 4K `mprotect` | both `EINVAL`, as expected. |
6. **Wine already has the host-page machinery.** wine-ppc64le carries
   upstream's "host page larger than Windows page" work
   (`ee8a2bc88b6` server side, `virtual.c` `host_page_size`/`host_page_mask`,
   110 uses) from the macOS 16K effort. It is compiled in only under
   `#ifdef __aarch64__` (`virtual.c:188`, `:3733`; wineserver's
   `server/mapping.c:226` is already unconditional). The Windows-visible
   page size stays 4K (`page_shift = 12`, `page_mask = 0xfff` are const).
   `winegcc` sets 64K PE section alignment only for ARM64
   (`tools/winegcc/winegcc.c:2013`).
7. **Upstream FEX cannot help.** FEX-Emu upstream requires 4K pages; the
   Asahi (16K) community built `muvm` to run a 4K guest kernel around it
   rather than port FEX. We are the port.

---

## 1. Rules for the whole effort

- **One binary, runtime page size.** `FEXCore::HostPage::Size()/Shift()/Mask()`
  initialised from `sysconf` before any mapping. No compile-time page
  option, no second build directory ([[gaming-build-is-the-build]]).
- **The 4K build must not regress.** Exactly two changes are allowed to
  alter 4K behaviour: the jemalloc page change (§S1) and the P0 structural
  redesign (§S2). Both get the standard price check (fnvbench, spinrepro,
  guest gzip/sha256sum, CP2077 laps per `benchmark-scene-isolation`). Every
  later change is behind `HostPage::Size() != FEX_GUEST_PAGE_SIZE` and is
  unreachable on op4k.
- **Both kernels are verified for every stage.** kexec A/B between the 4K
  and 64K kernels off the one drive is ~15 min per cycle
  (`FINDINGS-64k-gpu.md`, "kexec A/B procedure"). Stage exit criteria list
  what runs on each kernel.
- **Never re-pin binfmt to a scratch build** ([[binfmt-pinned-interpreter]]).
  On op64k register binfmt only at the S4 exit, pointing at
  `src/build-smc/Bin/FEX`. Until then launch directly via `FEX_BIN_DIR`.
- **Governor.** op64k boots `ondemand`; set `performance` before any number
  is written down.

---

## 2. Which lane needs which stage

There are three ways a game reaches the GPU, and they need very different
amounts of this work. This table is the reason the order below is what it is.

| lane | launcher | what runs under FEX | who does guest memory syscalls | needs |
|---|---|---|---|---|
| **nw** (native wine + bridge) | `fex nw-<title>` | x86 code inside native `wine-ppc64le` via `FexBridge` | Wine's own `ntdll/unix/virtual.c`, native, host-granular | S1, S2 (bridge sites), S3 (Wine guard flip). **No** guest-syscall emulation, **no** mtrack (bridge forces `SMCCHECKS=0`, Wine calls `fexbridge_invalidate_code_range` explicitly). |
| **Linux-native** | `fex <title>` | x86 Linux game + VK/GL thunks | FEX's syscall layer | S1, S2, S4 (loader, allocators, granule table, thunk fixes). Steam client is in this lane. |
| **fexproton** | `fexproton` / `fex <proton-title>` | x86 GE-Proton wine under full emulation | FEX's syscall layer, with Wine's PAGE_GUARD semantics on top | everything: S4 + S5 (mtrack soundness + restrictive memfd tier). Last. |

Recommendation that follows: **on 64K the Windows lane is nw.** The bridge
lane inherits Wine's own 64K support and skips the two hardest phases of the
design (granule table + mtrack soundness). CP2077 and W3 already have nw rows
in the config book with 4K reference laps (23.03 / 14.8 fps class), so the
first 64K-vs-4K game comparison can happen at the end of S3, before any guest
syscall emulation exists.

---

## 3. Stages

### S0. op64k as a test host (half a day, no code)

- `sudo cpupower frequency-set -g performance` (both sockets); record.
- Script the kexec A/B (4K kernel image from the 4K drive staged in `/boot`,
  as FINDINGS describes) so `ab-kernel 4k|64k` is one command.
- ctest baseline on 64K with the CURRENT binary: expect near-total failure
  from the jemalloc abort. Keep the log as the "before".
- Confirm the sunshine/X stack on 64K (DISPLAY :1 is the real desktop on
  op4k; check which it is on op64k) so game runs in S3 have a display.

Exit: one command switches kernels; a page-size probe binary and the ctest
"before" log are in `notes/64k/`.

### S1. Start at all on 64K, unchanged on 4K (1 day)

1. `jemalloc_glibc`: `LG_PAGE 16` in the pregen defs (and `LG_HUGEPAGE`
   unchanged). jemalloc supports a host page **smaller** than its compiled
   page, so one build serves both kernels; this is how Fedora and Arch ship
   jemalloc on aarch64. Cost on 4K is RSS granularity in the glibc-hook
   allocator used by every host-native library (mesa, RADV, X client libs).
   **Measure it on op4k**: the microbench trio plus one CP2077 nw lap set.
   If it costs more than noise, the fallback is a runtime `LG_PAGE`
   patch to jemalloc's `pages.c` (jemalloc upstream refuses this; we would
   carry it), not a second build.
2. rpmalloc: `AllocatorHooks.cpp:241` already receives the page size; verify
   it is fed from `sysconf`, not from `FEX_PAGE_SIZE`, at every
   `InitializeAllocator` call (`FEXInterpreter.cpp:161` passes the FEX
   constant as the fallback).
3. `CheckHostPageSize` becomes a tri-state `FEX_HOSTPAGEMODE`
   (`abort` default until S4 exits, `degrade`, `force`), and the ungated
   binaries (`TestHarnessRunner`, `FEXOfflineCompiler`, `FexBridge`,
   `Wow64Probe`) call it.

Exit: on 64K, `FEX_HOSTPAGEMODE=force Bin/FEX /usr/bin/true` reaches the
FEX gate and dies in FEX code (the callret `mprotect`, expected), not in
jemalloc. On 4K, price recorded in `gaming-build-is-the-build`'s changelog.

### S2. P0: constant split and the structural sites (3 to 4 days, lands on 4K first)

Design §0, §1, §4 guard pages. This is the only stage that rewrites code the
4K build executes, so it lands and soaks on op4k BEFORE it is tried on 64K.

1. `TypeDefines.h`: `FEX_GUEST_PAGE_SIZE/SHIFT/MASK` (constexpr 4096) plus
   the `HostPage` runtime module. Rename every GUEST site; convert every
   HOST site; every BOTH site gets a one-line comment naming the decision.
   `git grep -c FEX_PAGE_SIZE` reaching 0 is the completion check for the
   mechanical part.
2. `InterruptFaultPage` leaves `InternalThreadState`: one host page mmap'd
   per thread, pointer in `CpuStateFrame`; the three JIT emission sites
   become `ld TMP, off(STATE); stb r0, 0(TMP)`; the five `mprotect` sites and
   the SIGSEGV identification predicate use the pointer; SMC lazy-link arms
   the writer's page through the same pointer (the cross-thread protocol from
   design Part 1 correction 2). `alignas`/`sizeof` asserts on the thread
   state go.
3. Call-ret guard: allocate `CALLRET_STACK_SIZE + 2*HostPage::Size()`, base
   at `AllocBase + HostPage::Size()`, **check** the `mprotect` result. Same
   fix in `FexBridge.cpp:478/1516/1518` (the bridge has its own copy of the
   bug) and its thread-stack guard at `:2140-2177` and hlt page at `:1318`.
4. Guard pages: `CPUBackend.cpp` code-buffer guard (`UsableSize()` contract),
   `ThreadPoolAllocator.h`, altstack in `SignalDelegator.cpp`,
   `JitSymbols.h` buffer (`FEX_GUEST_PAGE_SIZE` is fine there, it is a
   buffer size, but the `static_assert` on `sizeof == page` must say so).
5. `64BitAllocator.cpp`: `PageShift` parameterised; region header
   `static_assert(sizeof(LiveVMARegion) == page)` relaxes to `<=` with the
   header stride `HostPage::Size()`. The S0 probe proved this allocator
   engages on 64K, so it is not deferrable.
6. `DetermineVASize` probe steps in host pages; msync diagnostics in the
   mtrack fault decoder use the host mask; `SBRKAllocations.cpp` uses the
   host page (audit break-order item 1); `CodeCache.cpp:1442` literal.

Verification on 4K: ctest 11291 green, `Scripts/smoke-gauntlet.sh`, CP2077
nw + fexproton lap sets against the 09-08 references, W3 save-load 3/3,
the `smc-fork-inversion` test. The fault-page change is in the deferred
signal path; the audio-gap and SPINCOLLAPSE numbers are the sensitive ones.

Verification on 64K: `FEX_HOSTPAGEMODE=force Bin/FEX` on a **static** x86
hello world reaches guest `_start` and exits 0 (no file offsets involved).
Dynamic binaries still fail in the loader; that is S4.

### S3. The nw lane on 64K: Wine guard flip (3 to 5 days, in wine-ppc64le)

1. `virtual.c:188` and `:3733`: `#if defined(__aarch64__) || defined(__powerpc64__)`.
   Leave the ARM64EC-only blocks (`:2844`, `:3245`, `:4262`) alone.
   Read every `host_page_mask` use once (110 sites) for aarch64-specific
   assumptions; the image-mapping path (`:3105`, `:3199`) already handles PE
   sections that are not host-page aligned by copying instead of mapping.
2. `winegcc.c:2013`: 64K section alignment for the PPC64 target so our own
   builtin PE DLLs map instead of being read in. Rebuild wine.
3. `signal_ppc64.c`, `loader.c` (`page_size` at `:2019`, `:2834`, the
   `emu32_bop_page` invalidate at `:2914`), and `libs/winecom`: audit for
   `0x1000`/`4096` literals that mean the host page.
4. Native `dxvk-ppc64le` and `vkd3d-proton` builds: grep-audit only; they do
   not mmap.
5. NCS code cache: DONE 2026-09-12. Reading the loader settled the format
   question: the code buffer is memcpy'd out of the mmap'ed cache file, so the
   4K on-disk pad is only a cursor alignment and needs no widening; the JIT
   emits nothing that depends on the host page. The host page size is folded
   into the cache identity hash anyway (design §7's other half), so the two
   kernels keep separate cache namespaces. Enabled by default on 64K in the
   `fex` launcher (`FEX_ENABLECODECACHINGWIP=1`, `FEX_CODECACHESCOPE=all`,
   both overridable); the 4K default stays off per the 08-10 launch-time
   verdict.

Verification: `wineboot` in a fresh prefix on 64K, `notepad`, then the W3 nw
row (save-load 3/3, the 09-04 TLSF lock row) and the CP2077 nw row with
MangoHud laps. Compare to the 4K references in the same session via kexec.
This is the first real 64K-vs-4K performance number and the first evidence
for or against the HPT-pressure thesis that motivated 64K.

Known envelope: with the union-permissive host page, sub-64K `PAGE_GUARD`
and guard-page stack growth inside a live host page behave as upstream Wine
on 16K macOS behaves. Titles that depend on it are a config-book note, not a
blocker, until S5.

### S4. The Linux-native lane: loader, allocators, granule table (2 to 3 weeks)

Design P1 then P2, in the design's break-first order.

1. `ELFCodeLoader::MapFile` anon+`pread` fallback when `addr | off` is not
   host-aligned, explicit BSS tail zeroing, host-granular ASLR slide
   (`:587`, `:479`). `x32/Memory.cpp` `mmap2` offset product, same rule.
   Exit: dynamic hello world and `nproc` on 64K.
2. `brk` region rounded to host granules internally, 4K values reported.
3. Granule table in `SyscallsVMATracking` (per-guest-page intended prot,
   per-granule materialised prot, union rule); `mmap`/`munmap`/`mprotect`/
   `mremap` emulation, permissive tier; `mincore`/`msync`/`madvise` shims;
   `/proc/self/maps` synthesised from VMATracking (Wine's x86 loader under
   fexproton and glibc both read it). glibc arms a 4K guard per pthread
   stack, so this path is hot from the first `pthread_create`; design it as
   the hot path.
4. 32-bit `LinuxAllocator`: keep 4K accounting, allocate against the kernel
   in host granules through the same table. Needed for Steam's 32-bit
   helpers and the 32-bit thunks.
5. Thunks: `libvulkan/Host.cpp:970/1203/1271` placed-memory-map alignment
   (4K literal) and the 32-bit pool in `ThunkLibs/include/common/Host.h`.
6. Register binfmt on the 64K boot pointing at `build-smc/Bin/FEX` once
   Steam launches; flip `FEX_HOSTPAGEMODE` default to `degrade`
   (auto-forces `SMCCHECKS=full` on 64K until S5).

Verification: ctest on 64K approaches the 4K count (the 11291 figure will
not be matched exactly; mremap/clock_getres kernel-drift XFAILs already
exist), gvisor mapping tests, Steam client login and library, one
Linux-native title per engine class (Factorio-class, Dex-Linux, Doom
VK-native from the asset-streaming campaign). ctest on 4K unchanged.

### S5. SMC soundness and the restrictive tier (fexproton on 64K, 2 to 3 weeks)

Design §5 and §6. Only fexproton and Mono/Unity titles need this.

1. `UnprotectRegionCallback` widens to the granule and the fault path
   invalidates or re-arms every tracked guest page in it (the soundness
   rule). `SMCSoftInvalidate.h` hashes stay guest-4K. Expect code/data
   thrash on mixed granules; `SMCCHECKS=full` remains the correctness
   fallback, `FEX_SMCLAZYINVAL` stays off for HotSpot per
   [[pz-java-jvm-campaign]].
2. Restrictive tier: memfd-backed guest anon memory with a second RW view,
   granule set to the most restrictive union, fault reflection through the
   mirror, per-granule policy bit flipped on the first fault-bearing
   protection. This is what makes Wine's `PAGE_GUARD` exact under full
   emulation.

Verification: Mono/Unity (PZ, RimWorld) without `SMCCHECKS=full`; then the
fexproton CP2077 and W3 rows.

### S6. Keeping both kernels green (ongoing from S2)

- ctest and the smoke gauntlet on both kernels after every merge to
  `daedalao-wt` that touches `Source/Tools/LinuxEmulation`, `FEXCore/Source/Utils`,
  `FexBridge`, or the JIT dispatcher.
- New test bucket in `unittests/FEXLinuxTests`: partial `munmap`, prot
  ladders, `MAP_FIXED` collisions at 4K offsets, maps-file parsing, guard
  page fault delivery. Asserted identical on both kernels except the
  documented relaxed list (guard faults inside a live granule, union-prot
  leaks, misaligned `MAP_SHARED` EINVAL, freed sub-granule memory resident).
- Config book: rows gain a `host_page` column where a title needs a
  different setting per kernel (NCS off on 64K until S3.5 lands; SMC mode).
- Memory note per stage in `page-size-64k-plan` with the dates, and the 4K
  price of S1/S2 in `gaming-build-is-the-build`.

---

## 4. Risks and what settles them

| risk | settles it |
|---|---|
| jemalloc `LG_PAGE 16` costs the 4K build (RSS or fps) | S1 price check on op4k; fallback is a runtime-page patch to `pages.c`, never a second build |
| P0 fault-page indirection shifts the deferred-signal path | S2 audio-gap and SPINCOLLAPSE laps on 4K; it is one L1-resident dependent load |
| 64K is not actually faster (HPT thesis wrong, or 16x mtrack/guard granularity eats it) | S3 nw laps, same session, kexec A/B. If 64K loses on nw, S4/S5 are portability work, not gaming work, and drop in priority |
| Wine's union-permissive guard pages break a title (anti-cheat, custom allocators) | S3 title matrix; the restrictive tier in S5 is the answer, and until then the config book carries the row |
| `OSAllocator_64Bit` on 64K has never run anywhere | S2 item 5 plus the gvisor mapping tests on 64K; keep the 4K behaviour identical by construction (the allocator never engaged on 4K) |
| `PROT_SAO`/HWTSO on the 64K hash kernel | one litmus run of the existing SAO probe (`FexBridge.cpp:622`, `openworld-perf-review`) on 64K in S0 |
| sunshine/KMS capture on 64K | S0 display check |

---

## 5. Order and effort

| stage | days | 4K build touched | first payoff |
|---|---|---|---|
| S0 tooling | 0.5 | no | kexec A/B, baselines |
| S1 jemalloc + gate | 1 | yes (measured) | FEX reaches its own code on 64K |
| S2 P0 structural | 3-4 | yes (measured) | static guest runs on 64K; bridge internals clean |
| S3 Wine guard flip | 3-5 | no | **CP2077 / W3 nw laps on 64K vs 4K** |
| S4 loader + granule table | 10-15 | no | Steam and Linux-native titles on 64K |
| S5 mtrack + restrictive tier | 10-15 | no | fexproton and Mono/Unity on 64K |
| S6 both-kernel CI | ongoing | no | stays green |

S0 through S3 is about two weeks and produces the number that decides
whether S4 and S5 are gaming work or portability work. That is the whole
point of putting the nw lane first.

---

## 6. Wave 1 execution setup (agreed the night of 2026-09-10, launched 2026-09-11 ~10:45)

Agents write code; the user and the orchestrator test. Every writer gets a
dedicated worktree on op64k (booksmain is x86_64 and cannot build FEX) and
is reviewed inline by the orchestrator before anything merges to
`daedalao-wt`. Worktrees and build dirs are removed after merge.

### Trees of record

| repo | tree of record on op64k | commit | note |
|---|---|---|---|
| FEX | `~/projects/fex-emu-ppc64le/src/fex-src` (branch `daedalao-wt`) | 849d7ab4f | gaming build is `src/build-smc`; never touched by agents |
| Wine | `~/Projects/power8/wine-ppc64le` (capital P; the tree `fex nw-*` runs via `ppc64le/steamtool/run-native`) | 3d76e0283b4 (2026-09-06) | `~/projects/wine-ppc64le` is a month older (8072b3c, 08-14) and is NOT used. Rule: whichever commit is newer wins. The tree of record sits on branch `agent/peek-lock` with 4 modified files; leave them alone, cut the worktree from the commit. |

### Wave 1 writers (three, in parallel, no shared files)

| agent | model | worktree | branch | build dir | owns |
|---|---|---|---|---|---|
| S1 jemalloc + tooling | Opus | `~/projects/fex-emu-ppc64le/src/wt-64k-s1` | `wt/64k-s1-jemalloc` | `~/projects/fex-emu-ppc64le/src/build-wt-64k-s1` | `External/jemalloc_glibc/`, `Scripts/`, `notes/64k/`; nothing else |
| S2 P0 structural + tri-state gate | Opus | `~/projects/fex-emu-ppc64le/src/wt-64k-s2` | `wt/64k-s2-p0` | `~/projects/fex-emu-ppc64le/src/build-wt-64k-s2` | everything in `FEXCore/` and `Source/` (§S2 items 1-6) |
| S3 Wine host page | Fable orchestrating one Opus writer, Fable reviews before reporting | `~/projects/wine-ppc64le-wt-64k` | `daedalao-wt` itself (user rule 09-12: wine work stays on `daedalao-wt`, same commit rules, pushed to `origin/daedalao-wt` on the wine fork; op64k has no GitHub credentials so the orchestrator pushes from booksmain) | inside the worktree (find the recipe in `ppc64le/steamtool/run-native` first; build in the worktree, never in the tree of record) | `dlls/ntdll/unix/virtual.c`, `tools/winegcc/winegcc.c`, audit of `signal_ppc64.c`, `loader.c`, `libs/winecom` |

Wine commit check on 09-12: `origin/daedalao-wt` (f538823142e) was two commits
BEHIND the capital-P tree and booksmain (3d76e0283b4); newest wins, so the
worktree's `daedalao-wt` was reset to 3d76e0283b4 and the fork gets pushed
forward at merge time.

Scratch space: `~/projects/fex-emu-ppc64le/scratch-64k/<s1|s2|s3>/`. Never
`/tmp`.

Configure line for the FEX worktrees, copied from `build-smc`'s cache:
RelWithDebInfo, clang/clang++, `ENABLE_LTO=False`, `ENABLE_ASSERTIONS=False`,
`BUILD_THUNKS=True`, `BUILD_THUNKS_32BIT=True`, `BUILD_GUEST_THUNKS_32=ON`,
`ENABLE_CLANG_GUEST_THUNKS_32=ON`, `ENABLE_JEMALLOC_GLIBC_ALLOC=ON`,
`X86_DEV_ROOTFS=/`, `X86_DEV_ROOTFS_32=~/.local/share/fex-emu/RootFS/ArchLinux`,
`USE_LEGACY_BINFMTMISC=OFF`, `BUILD_TESTING=ON`, Ninja. New worktrees have no
submodules: `git submodule update --init` before configuring.

### Rules in every prompt

1. **Testing is limited so agents do not collide.** The box is shared by
   three writers. Each agent may run, sequentially, at most one short
   (under 60 s) guest process at a time, and only the smoke checks listed
   for its stage: S1 runs the page probe and `Bin/FEX /usr/bin/true`;
   S2 runs one static x86 hello world; S3 runs one `wineboot` in a fresh
   `WINEPREFIX` under its scratch dir. No ctest, no games, no Steam, no
   display (`DISPLAY` unset), no benchmarks. Never kill a FEXServer or wine
   process it did not start. Builds run with `-j 48` so three can overlap.
2. Never run `fex-binfmt-install.sh`; never invoke `fex` with a scratch
   `FEX_BIN_DIR`; never touch `build-smc` or the trees of record; never
   reboot, kexec, or change the governor.
3. No child agents except S3's single Opus writer. No `/tmp`.
4. Commit on the worktree branch only, as daedalao@hotmail.com, with no
   Claude trailers of any kind.
5. Report: what was changed and why, what compiled, what the one smoke check
   printed, and every site left undecided (BOTH sites the agent could not
   classify) so the review starts from a list.

### Status at the end of 2026-09-11

Waves 1 and 2 both landed the same day; `daedalao-wt` 562ede33d, wine fork
475502aa473. What runs on the 64K kernel (build-smc, binfmt pinned):

| lane | title | state |
|---|---|---|
| nw (native wine + bridge) | The Witcher 3 | runs, playable |
| nw | Cyberpunk 2077 | runs; one cold-cache benchmark lap logged (`~/benchlogs/64k-cp2077-nw-1`, scene 14.5 fps; warm laps still owed before comparing with the 4K reference) |
| nw | RimWorld (Windows build) | runs, loads defs (the first "black screen" was a missing `LANG` in an ssh launch, not 64K) |
| nw | Portal 2 (32-bit) | runs, playable (2026-09-12, several minutes in-game); the first title to exercise 32-bit segment reloads through the bridge, see below |
| Linux-native | `nproc`, `ls`, python3 with threads + mmap | run |
| Linux-native | RimWorld (Linux build) | runs at 60 fps under **mtrack** (`FEX_HOSTPAGEMODE=force GC_DISABLE_INCREMENTAL=1`, the 4K configuration) once the guard-region and MAPERR fixes (d151ae36f) landed; the degrade tier (SMCChecks=full) also loads but was slow and painted every window fill cyan, which turned out to be a full-mode codegen bug, not 64K (3bada1c9d, below). Mono's incremental GC write barrier stays unsound under the permissive tier (§6), hence the GC knob until S5 |

Fixes found only by running titles, all landed: wine dbghelp null map
(475502aa473), bridge gate default (c6745e89a), granule copy past EOF
(eddcc0e17), lock checkers (562ede33d), the gate running after the context
had cached SMCChecks so degrade never disabled mtrack (94ff5f5c3), a refused
shared lock being unlocked (b74b0581e), `TrackMadvise` called under the VMA
write lock -- a lock-order inversion whose fatal trap was delivered to the
guest and leaked the lock (a90c5cd26), and stale granule-table entries after
whole-granule munmap/MAP_FIXED that turned every write into a fake SMC fault
(3bdafb7d9). Diagnostics that found them, all env-gated and landed:
`FEX_INVALIDATESTALLSEC`, `FEX_LOCKDIAG=1` (acquirer backtrace + a report
when a guest signal is delivered on a thread holding the VMA write lock).
Under Unity, FEX's stderr lands in the game's Player.log. Environment gaps found: op64k root
drift (fmt 12.1 vs 12.2, cross gcc, MangoHud), all recorded in memory notes.

Evening of 2026-09-11, the cyan window fills: RimWorld's runtime solid-colour
textures came out (0,255,255) under the degrade tier. Native radeonsi on the
64K kernel uploads and draws a 1x1 texture correctly (`scratch-64k/gltest`),
the same binary under mtrack draws the fills correctly, and the JIT suite
under `FEX_SMCCHECKS=full` failed ~170 `jit_500` tests (multi-instruction
blocks) while every `jit_1` test passed. The IR dump of
`Test_64Bit_OpSize/66_5B` showed it: full mode resumes each instruction in a
fresh IR block via `SetCurrentCodeBlock` without dropping the
`CachedNamedVectorConstants` refs, the RA ends live ranges at the block edge,
and the second and third cvtps2dq read a clobbered cvtmax mask. Fixed by
`StartContinuationBlock()` (3bada1c9d). Lesson: the degrade tier was never
exercised by the test suite; `FEX_SMCCHECKS=full` needs a CI row (S6). The
gate must be `force` for the suite on 64K (`FEX_HOSTPAGEMODE=force`, else
every test aborts at the banner). `Test_64Bit_Displacement_Encoding` fails
on 64K in every mode (it maps a 4K page at 0x7FFFF000; granule/loader item,
open).

User note, 2026-09-11 evening: the RimWorld tutorial is "so slow". That was
observed on the degrade instance (SMC full, ~8 fps at the menu); the mtrack
instance did 60 fps at the menu. Before calling it a 64K problem, measure the
tutorial under mtrack on 64K and on op4k; RimWorld's Linux lane has not been
profiled on either kernel. Queued under (8) below.

Open items, in priority order: (1) DONE 09-14: a fatal trap or fault raised
in FEX's own host code is no longer delivered to the guest as a signal (the
host-fault gate in `HandleGuestSignal`, below); (2) DONE 09-14: mtrack arming
heuristic for mixed code/data granules (`FEX_SMCGRANULEMIXED`, below; S4c's
tracked count and flip rate are its inputs); (3) DONE 09-14: the
S4b/S4c wiring (below; the raw `GuestM*` host calls are reached only for
whole-granule ranges, whose table entries the `Granule::*` front already
keeps in step); (4) DONE 09-14: HWTSO
SAO refusal on an emulated granule now retries plain and revokes (the
whole-granule file mmap inside `Granule::Mmap` was the only refusable site;
the anonymous mmaps and the FEX-backed mprotects cannot refuse); (5) the 4K price
check for S1/S2 and the 4K regression run of S4 (`granule_page` test) on the
op4k boot; (6) `Scripts/granule_page_64k.sh` can go now the loader fallback
exists; (7) DONE 09-12: NCS code cache on 64K (host page in the identity hash, no format change needed, launcher default on); (8) RimWorld Linux-lane performance (tutorial fps under mtrack, 64K vs 4K, then profile).

2026-09-12, Portal 2: the "wow64 SEH storm" every 64K run died in was not
64K, WoW64 or ntsync. Every fault was at a guest register + 0xF3000000:
`UpdatePrefixFromSegment` merges the GDT qword with `Orlshr(i32Bit, .., 16)`
and the ppc64 backend shifted the 64-bit register, so the descriptor's access
byte (0xF3 for the bridge's flat data segment) landed in bits 24..31 of the
cached ES/DS base after any `pop es`/`pop ds`/`mov es,ax`; only string
instructions consult that base, which is why the thread ran for minutes
first. Fixed in 3f1908f77 (`Ornror` had the same shape). The 32Bit_ASM suite
cannot see it because the Linux frontend writes descriptor bases only; the
regression is `Bin/BridgeSmoke32`, run by hand after bridge or emitter
changes. Diagnosed from the wine side (wine-ppc64le
`ppc64le/docs/sessions/2026-09-12/portal2-segment-base-handoff.md`). 4K
Portal 2 had never reached this point, so the bug was never 64K-specific.
Second blocker behind it: the steamtool's i386 steam-bridge helper build
refused the Arch rootfs (its preflight looks only for Debian's
`usr/lib/i386-linux-gnu/Scrt1.o`; Arch multilib has it under `usr/lib32`).
The helper builds and serves once the path is accepted; the artifact is
installed, the one-line preflight fix in `build-helper.sh` is still owed on
the wine side. Also found: the 64-bit `Bin/BridgeSmoke` SIGSEGVs on op64k in
its EC direct-transition leg with the pre-fix emitter too (`FEX_NO_EC_DIRECT=1`
passes 254/254); never checked on op4k, open.

2026-09-12 afternoon, code cache on 64K (open item 7), now ON by default in
the `fex` launcher on the 64K boot. Two FEX changes: the host page size joins
the cache identity hash (no format change was needed, see S3.5 above), and
the granule layer's emulated mmap/mprotect paths now run the same tail as
GuestMmap/GuestMprotect (`FinishTrackedMmap` / `FinishTrackedMprotect`).
Before that, every segment ld.so maps at a 4K file offset took the emulated
path, which dropped TrackMmap's cacheable section AND its late volatile
metadata, and its mprotect never ran the delayed-load heuristic; measured
python3 x3: only the vDSO ever loaded, five libraries re-translated and
re-written per run. After: run 2 loads libpython (10221 blocks), libc, libm
and the vDSO, writes nothing. Found on the way, both pre-existing and not
64K-specific: (a) FEXServer's `RunOfflineCompiler` execs the bare name
`FEXOfflineCompiler` via execvp, which is never on PATH, so every
server-side cache generation fails with status -1 -- the server's own log
prints it and nobody reads that log; (b) FEXOfflineCompiler loads config
with an EMPTY envp, so its cache id (e.g. `190e75fa222be8b6`) never matches
the interpreter's (`2187aa67e50f8900` with the same env), and the id also
folds in the launcher's `FEX_X87REDUCEDPRECISION=1`. The runtime writer
(`SaveCodeCaches`, scope=all) is the only generator whose id matches its
reader, and it is the one now in use; leave the server path dead until
(b) is designed properly (the requesting client's config has to reach the
generator). Also: `conformance-interfaces-mmap-3-1` fails on 64K because
the granule layer refuses an unaligned MAP_SHARED file mapping (EINVAL, the
survey's known refusal); pre-existing, the ld.so and main-executable
mappings placed by the ELF loader itself are not cache-loaded on either
kernel.

2026-09-14, the host-fault gate (open item 1). `HandleGuestSignal` now
classifies a synchronous fatal-class signal (kernel `si_code`) whose host PC
is outside every JIT code buffer: raised in a deferred-signal section (syscall
body, block linker/compiler, VMA tracking), at a dispatcher or FABI-stub PC or
inside a FABI crossing, or a SIGTRAP/SIGILL/SIGFPE anywhere in host text, it is
FEX's own fault. Such a fault is reported on stderr with the host backtrace
(and the VMA lock holder under `FEX_LOCKDIAG`), then the signal's default
disposition is restored and the handler returns, so the kernel re-raises it
at the original instruction and the core carries the real context. The Break
op's synthesized guest faults are exempt by their state marker
(`FaultToTopAndGeneratedException`), in-JIT faults and SMC faults never reach
the gate, and a SIGSEGV/SIGBUS inside a thunk's host library with no deferred
section active keeps the historical outside-JIT delivery (no FEX lock is held
there). `FEX_HOSTFAULTTOGUEST=1` restores the old delivery after the report.
Test: `unittests/FEXLinuxTests/tests/signal/hostfault_gate.cpp`, driven by
the `FEX_HOSTFAULT_INJECT=<syscall nr>[,segv]` hook in `HandleSyscallImpl`.

2026-09-14, S4b/S4c wiring (open item 3). The hole: mtrack arms a whole
granule with its own `mprotect(PROT_READ)` and nothing told the VMATracking
granule table, so the next sub-granule guest mprotect that changed the
granule's union (a JIT engine `mprotect(RWX)`-ing a data page next to
compiled code) rematerialised the union and silently undid the arm. The
`SetSMCOverlay` push the design sketched cannot be called from the SMC fault
path (which holds no VMATracking lock, by the fork lock-order rule), so the
table pulls instead: `GranuleTable::WantedProt` leaves `PROT_WRITE` out
while `SMCGranule::Table().Armed(G)`, and `RematerialiseIfNeeded` no longer
trusts its cached `HostProt` to skip the syscall for a granule mtrack has
ever touched (`Known(G)`). `SMCOverlay`/`SetSMCOverlay` are gone. The arm
side cannot race a rematerialisation (VMATracking shared vs unique); the
fault side's losing order leaves the granule read-only with its mask
cleared, which the next store settles with one spurious SMC fault.
`GranuleFullyBacked` is not needed: a granule with any live page is mapped in
full by the permissive tier's construction (recorded in SMCHostGranule.h).
Found on the way: `RematerialiseIfNeeded` issued its mprotect without
`ApplyGuestProt`, so under `FEX_HWTSO` every rematerialisation stripped
`PROT_SAO` from the granule; now applied (item 4's refusal-revoke plumbing
is still open, but a refusal there is impossible once an mmap-time refusal
has revoked).

64K survey items seen 2026-09-14 while running the mapping subset of ctest
(26 rows, `-R "granule|mmap|mprotect|madvise|mremap"`): besides the known
`conformance-interfaces-mmap-3-1` refusal, `madvise_test.jit.gvisor` fails
three cases that need sub-granule madvise semantics the granule layer cannot
express (`CleansPrivateFilePage`: DONTNEED on a private file page must
refill from the file, not zero; `DontforkShared`/`DontforkAnonPrivate`:
DONTFORK over a sub-64K range). Pre-existing by mechanism (none of them
reaches the mprotect path); a future madvise emulation could split the
granule into FEX-backed private memory the way sub-granule MAP_FIXED does.

2026-09-14, the 64K CP2077 reference (nw lane, `FEX_HWTSO=1`, launcher
defaults, `~/fex-scripts/cp2077_64k_ref.sh`): laps 2-4 after a warm-up
`64k-nts-2..4` = 23.74 / 23.61 / 23.48 fps (scene p50 37.9-38.8 ms), against
the 4K nw references of 23.03 (lock batch) and 24.2 (pre-lock). Parity. The
first attempt (`64k-ref-1..4`, 11.8-13.8 fps, p50 70-81 ms, GameThread at
100% with every worker in `anon_pipe_read`) ran without ntsync: the
out-of-tree `ntsync.ko` in `~/ntsync-mod-64k` had a stale vermagic after the
7.2.5-books-64k kernel update and was not loaded. Rebuilt against the running
kernel, installed under `/lib/modules/<ver>/extra`, `/etc/modules-load.d/
ntsync.conf` added. `ls /dev/ntsync` is part of the pre-lap checklist now.

2026-09-14, THP and TLB baseline on the 64K kernel (CP2077 nw lane, mid
benchmark, whole process, 10 s `perf stat`). THP is `madvise` with 16 MB
huge pages (POWER8 hash MMU has THP only with a 64K base page, so every
`MADV_HUGEPAGE` hint in FEX is live for the first time). Coverage:
AnonHugePages 426 MB of 5.37 GB anonymous RSS (8%); 3.3 GB resident sits in
anonymous VMAs with no huge pages, the two largest (1.65 GB, 0.6 GB) being
wine's own guest heap views, which FEX does not allocate. Miss rates per
1000 instructions: DERAT 64K 0.75, DERAT 16M 0.11, IERAT 64K 0.28, IERAT
16M 0.13, TLB 0.20, dTLB 0.09, iTLB 0.005; CPI 1.9. At tens of cycles per
reload that is about 1% of cycles, so huge pages are bounded to roughly
that on the nw lane; the instruction-count wall stands. Also recorded: the
box had rebooted with `ondemand`; `/etc/default/cpupower` now pins
`performance` and `cpupower.service` is enabled, next to the ntsync
modules-load entry.

2026-09-14, test infrastructure for the 64K workstream (branch
`wt/64k-tests`, verified in `src/build-wt-tests` on op64k, a copy of
build-smc's configuration). Two pieces.

(a) FEXLinuxTests build in the gaming configuration. build-smc had
`BUILD_FEX_LINUX_TESTS=OFF`, so `hostfault_gate` (bd60de758) had never been
built through ctest. Turning it on hit four breaks, all fixed on the
branch: the 32-bit tests project was handed `X86_DEV_ROOTFS` (the x86_64
cross sysroot, no i686 crt/libgcc: `cannot open crtbeginS.o`, `-lgcc`);
`X86_DEV_ROOTFS_32` is now declared at the top of the tree and the 32-bit
tests use it (91591fe04). `ptr_integrity_mt` is 64-only but its
`target_link_libraries` was unconditional (32-bit configure error);
`greg_mutation.64` spun on a numeric `1: ... jz 1b` label that clang
22's Intel-syntax parser reads as a binary number (e7467600a); and
`atomics_smp.cpp` names rax/rdx in every asm block, so it is now
`atomics_smp.64.cpp` (bed81f74c, ctest name unchanged). Nothing in the
toolchain files needed to change: `toolchain_x86_64.cmake` autodetects
`/usr/x86_64-pc-linux-gnu` as the sysroot and clang finds that gcc's
libstdc++ on its own, so `X86_DEV_ROOTFS=/` is fine for the 64-bit side.

To flip build-smc (its cache already carries `X86_DEV_ROOTFS_32`; merge
`wt/64k-tests` first, then reconfigure in place):

```bash
cd ~/projects/fex-emu-ppc64le/src
cmake -DBUILD_FEX_LINUX_TESTS=ON -DENABLE_SMC_FULL_TESTS=ON build-smc
nice ninja -C build-smc
```

The full fresh-configure line that reproduced build-smc plus these two
options is `~/scratch-64k/tests/configure.sh` on op64k (RelWithDebInfo,
clang + lld, `ENABLE_LTO=False`, `ENABLE_ASSERTIONS=False`,
`BUILD_TESTS=True`, `BUILD_THUNKS=True`, `BUILD_THUNKS_32BIT=True`,
`BUILD_GUEST_THUNKS_32=ON`, `ENABLE_CLANG_GUEST_THUNKS_32=ON`,
`X86_DEV_ROOTFS_32=$HOME/.local/share/fex-emu/RootFS/ArchLinux`,
`BUILD_FEX_LINUX_TESTS=ON`, `ENABLE_SMC_FULL_TESTS=ON`). Suite census
with both on: 13437 tests; the FEXLinuxTests binaries land in
`unittests/FEXLinuxTests/FEXLinuxTests_{64,32}/` (58 and 50).

Results on 64K (`ulimit -c 0; FEX_HOSTPAGEMODE=force ctest -R hostfault_gate`):
`hostfault_gate.64.jit.flt` and `hostfault_gate.32.jit.flt` both pass,
and the verbose log shows the injection firing (`FEX: FATAL host fault:
signal 5 ... raised in a deferred-signal section ... Not delivered to the
guest`, 4 assertions), so the pass is not the vacuous no-injection path.

(b) The SMC-full CI row (229672b95). `ENABLE_SMC_FULL_TESTS` (default
OFF, so the 4K count is unchanged) adds `jit_500_smcfull/Test_64Bit_*`:
jit_500's configuration plus `FEX_SMCCHECKS=full`, 2019 rows, the same
2019 as `jit_500/Test_64Bit_*`. Known failures and disabled tests apply
per variant by full name (`jit_500_smcfull/Test_64Bit_<path>.asm`) in
`Known_Failures_jit` / `Disabled_Tests`; `testharness_runner.py` now
matches the disabled list by full name too. Run on 64K
(`FEX_HOSTPAGEMODE=force ctest -j16 -R jit_500_smcfull`, 10 s wall):
**2018/2019 pass**. The one failure, `Displacement_Encoding`, fails the
same way under `jit_1` and `jit_500` on this host (the 4K page at
0x7FFFF000, the open granule/loader item above), so it is a 64K-host
failure and not an SMC-full one; it is deliberately not on a known-
failures list, since it passes on 4K. This confirms the 09-11 state: the
~170 `jit_500` failures under full mode are gone after 3bada1c9d, and
the row would now catch a regression of that class.

2026-09-14, the mixed code/data granule heuristic (open item 2,
`FEX_SMCGRANULEMIXED`, branch `wt/64k-mixed`). The measurement that framed
it: RimWorld Linux (Mono) under mtrack on this kernel, lazy recipe, code
cache on, 4m20s (`~/benchlogs/rimworld-64k-smoke-0914.log`): the flip log
reported 172 times over 81 distinct granules flipping >= 64 times a second,
103 of the reports with exactly 1 of 16 guest pages tracked (the hottest
granule re-reported 12 times); each flip is a granule-wide unprotect, an
invalidation across every thread and a re-arm at the next compile, and on a
4K host none of those granules would ever flip. Design chosen: (a) from the
prompt's three. A granule that reaches N faults inside a one-second window
while holding at most M tracked pages is *demoted*: mtrack never arms it
again, and every block compiled from any of its guest pages carries the
per-instruction `ValidateCode` guard that `SMCCHECKS=full` wraps around
every instruction -- the per-block opt-in already existed
(`Block.ForceFullSMCDetection`, the mono tailcall block, and the 3bada1c9d
continuation-block fix covers this path); `GuestCodePageValidateOnly` on the
syscall handler is the page-driven input. (b) is unsound by the `rearm`
policy's own construction; (c) is the `FEX_SMCLAZYINVAL` argument HotSpot
disproved. Soundness (section 5's rule): an unguarded block may live on a
page only while its granule is armed; demotion happens in `NoteFault`, on a
fault whose service invalidates the whole granule under the exclusive
`CodeInvalidationMutex` (forced granule-wide under `rearm` and never
deferred by the lazy path for the demoting fault), so it orders after every
compile that read "not demoted" and kills what they published, and every
later compile (under the shared lock, the same hold in which
`MarkGuestExecutableRange` reads the bit) guards. All three block publishers
consult it: the fresh compile guards a block if any of its `CodePages` is
demoted, `TryRelinkSoftInvalidatedBlock` refuses a retained (unguarded)
block on a demoted page, and the code cache rejects a section whose page
table touches a demoted granule before registering any block. `Forget`
keeps a demoted entry while the granule is only partially retired (the mark
path is NewPage-gated and would not run again for the surviving pages). The
S4b contract holds: `Armed()` stays false for a demoted granule, so
`WantedProt` keeps `PROT_WRITE` in the union. Full argument in
`SMCHostGranule.h`. Knobs: `FEX_SMCGRANULEMIXED=<flips/s>` (default 64, 0
off, forced off on 4K), `FEX_SMCGRANULEMIXEDMAXTRACKED` (default 4). The one
smoke run (budget: one, the box carried a concurrent ctest run at load ~24;
`build-wt-mixed`, same launcher env as the baseline via `fexplay-wtsmc`,
3 minutes, `op64k:~/scratch-64k/mixed/play_rimworld_20260914-081548.log`):
40 flip-log lines, every one a demotion of a distinct granule at its 64th
flip (28 with 1/16 tracked, 7 with 2/16, 5 with 3/16), and no granule
reported again after its demotion -- against the baseline's 172 reports
with granules re-reporting up to 12 times per session. No code-cache
rejection fired, no error, RimWorld 1.6.4850 loaded and the engine ran the
full 3 minutes (61642 UnityPlayer blocks saved at exit). Default ON on that
evidence. NOT verified: the invalidator's CPU share (the mid-run
`perf record` failed to find the game pid by comm and the budget did not
allow a second run), fps, and the cost of the guarded blocks themselves
(28 demoted granules hold one code page each; if a hot Mono method lives
there its block runs the full-mode guard per instruction). Next: a
counterbalanced fps lap pair with `FEX_SMCGRANULEMIXED=0` vs default, and
`perf` on the game pid (comm under FEX is not `RimWorldLinux`; find it by
args).

### 2026-09-14, transparent huge pages on 64K: audit and the FEX_THP knob

On a POWER8 hash MMU THP exists only with a 64K base page; op64k runs
`/sys/kernel/mm/transparent_hugepage/enabled = madvise`, `hpage_pmd_size` =
16 MiB. So every `MADV_HUGEPAGE` FEX ever issued was dead on the 4K box and is
live on 64K -- but a hint only takes for a 16 MiB-aligned, 16 MiB window that
lies entirely inside one VMA, and FEX's internal placement hint
(`GetInternalPlacementHint`, 4K-granular, bumps by size + one 4K page) makes
every reservation misaligned by construction. An `mprotect` or `MADV_DONTNEED`
over part of a huge page splits it back to base pages (correct, just no longer
huge). The table is every large anonymous reservation FEX makes, with the
state *before* this change in the "hinted" column.

| site | size / count | lifetime | 16 MiB-aligned & sized? | sub-16 MiB mprotect / DONTNEED? | hinted before | verdict |
|---|---|---|---|---|---|---|
| JIT code buffers, `CodeBuffer` (`FEXMemJIT`, CPUBackend.cpp) | 16 -> 32 -> 64 -> 128 MiB, geometric; starts at 128 MiB when the code cache is on; process-wide, old buffers linger while a thread still runs them | process | sized yes; aligned NO (placement hint) | the trailing guard page (`PROT_NONE`, one host page) splits the last PMD; nothing else | yes, unconditional | **can benefit**: aligned now under `code`; a 128 MiB buffer gets 7 huge pages (the guard page costs the 8th), 16 MiB gets none |
| per-buffer block index (`FEXBlockIndex`) | AllocatedSize/64*4 = 8 MiB at 128 MiB | with its buffer | no (< 16 MiB) | no | no | cannot |
| L2 page-pointer table (`FEXMem_Lookup` head, LookupCache.cpp) | VirtualMemSize/4K*8: 128 MiB (64-bit), 8 MiB (32-bit); **per thread** | thread | sized only for 64-bit; aligned NO | whole-table DONTNEED only (ClearL2Cache) | yes (Enable), dead by alignment | can benefit (sparse by guest VA: one huge page per 1 GiB of guest VA that has code) -- `lookup`, OFF |
| L2 entry pool (`FEXMem_Lookup` middle) | 128 MiB per thread, bump-allocated in 32 KiB steps | thread | sized yes; aligned NO | whole-pool DONTNEED only | explicitly NOHUGEPAGE | left off: dense while it grows, but 100 threads x 16 MiB first-touch is the RSS story below |
| L1 lookup table (`FEXMem_Lookup_L1`) | 16 MiB per thread, dynamic L1 starts at 128 KiB | thread | sized yes; aligned NO (base + 8/128 MiB) | whole-L1 DONTNEED on resize/scrub (zaps, never splits) | yes (Enable), dead by alignment | can benefit -- `lookup`, OFF: every thread's first touch faults a whole 16 MiB (100 threads: +1.6 GiB RSS) |
| 64-bit allocator object arena (`FEXMem_Misc`, 64BitAllocator.cpp) | 64 MiB, forward-only, dense | process | sized yes; aligned by luck (a `/proc/self/maps` gap edge) | no | yes, unconditional | **can benefit**: aligned now under `alloc64` |
| FEX-internal mappings through the 64-bit allocator (`VirtualAlloc` -> `OSAllocator_64Bit::Mmap`, MAP_FIXED into the 48-bit reservations) | the code buffers, lookup caches, block index, callret stacks land here for a 64-bit guest | varies | per site above | per site above | per site above | covered by the per-site rows; the allocator itself adds nothing |
| 64-bit guest mappings (`SyscallHandler::GuestMmap`, straight to the host kernel, kernel-placed below the 48-bit region) | guest-sized | guest | guest's choice | guest mprotect (4K-granular via the granule layer) splits | no; guest `madvise` passes through | `guest`, OFF: hint anon-private only, measured not assumed |
| 32-bit guest mappings (`GuestMmap` -> `LinuxAllocator.cpp`) | guest-sized | guest | guest's choice | same | no | `guest`, OFF, same site |
| rpmalloc spans (`FEXAllocator`, AllocatorHooks.cpp `FEX_rp_mmap`) | 256 MiB span mapped as 512 MiB VA and aligned to 256 MiB, per thread heap per page class (64K / 4M / 64M) | thread heap | sized and aligned YES | DONTNEED decommit per page class splits | explicitly NOHUGEPAGE | `rpmalloc`, OFF: would take, but sparse per-heap spans make it an RSS bet |
| granule private backing (`MakeGranuleFEXBacked`, GranuleMemory.cpp) | one 64K host page per call, MAP_FIXED | guest | no (one host page) | it *is* the sub-16 MiB unit | no | cannot |
| thunk low-4G trampoline pool (`ThunkLibs/include/common/Host.h`) | max(64K, host page) per pool | process | no | no | no | cannot |
| dispatcher code (`PPC64Dispatcher.cpp`) | 64 KiB | process | no | no | no | cannot |
| callret shadow stacks (`FEXMem_CallRetStacks`, ThreadManager.cpp) | CALLRET_STACK_SIZE + 2 guard pages per thread, mapped PROT_NONE then mprotected | thread | no | guard pages | explicitly NOHUGEPAGE | cannot; keep off |
| bridge thread stacks, HLT page, SAO probe (FexBridge.cpp) | stack-sized / one page | thread | no | guard page | no | cannot; bridge code buffers are FEXCore's `CodeBuffer` (covered by `code`) |
| stats shm (`ThreadManager::StatAlloc`), fault page, guest-trace ring | 4 MiB shared / 1 page / file-backed | process | no / shared / file | -- | no | not anonymous-THP material |

Implemented (`FEXCore/include/FEXCore/Utils/THP.h`, header-only so the
bundled-allocator static library, FEXCore, the syscall layer and the bridge
all read one mask): `FEX_THP=<names|mask>` with `code`=1, `lookup`=2,
`alloc64`=4, `rpmalloc`=8, `guest`=16, `all`, `none`; **default `code,alloc64`**
-- the two dense sites that were hinted before, now placed so the hint can
take (over-map by one PMD and trim, or skip to the boundary in the stolen
region; address space only, no RSS, and on a kernel without THP `PMDSize()`
is 0 and every layout is the historical one, bit for bit). `lookup` also
pads the L2 table up to a PMD multiple so the entry pool and L1 land on
boundaries (`L2TableSpan`; ClearL2Cache scrubs by it). `rpmalloc` off keeps
the historical `MADV_NOHUGEPAGE`; `guest` hints anonymous private mappings
once, at `SyscallHandler::GuestMmap`'s success path (both widths; the first
cut put it in the 64-bit *allocator*, which only FEX's own reservations go
through -- the live-process `smaps` check caught the guest VMA without `hg`),
the guest's own madvise still passing through. The interpreter applies the merged config
(`THP`/`THPLog` rows in Config.json.in, so a config-book row can carry them)
before `InitAllocator`; the bridge reads the environment raw, as it does for
every knob. `FEX_THPLOG=1` prints one `[FEX THP] pid= exit= mask= pmd=
enabled= AnonHugePages= Rss=` line from `/proc/self/smaps_rollup` at
`exit_group`, on the fatal-signal path (open/read/write only, no allocation)
and through `atexit` for the bridge lane; `=2` adds a per-VMA-name breakdown
(`FEXMemJIT`, `FEXMem_Lookup_L1`, `FEXMem_Misc`, `FEXAllocator`, `[anon]`,
library basenames) from `/proc/self/smaps`. Branch `wt/64k-thp`.

Verified on op64k (`build-wt-thp`, python3 allocating and touching 200 MB
under `FEX_HOSTPAGEMODE=force FEX_THPLOG=2`; the guest reads its own
`smaps_rollup` while the block is live, FEX reports at `exit_group` after
python has freed it):

| FEX_THP | guest-visible AnonHugePages (block live) | FEX exit report | per name |
|---|---|---|---|
| `none` | 0 kB | 0 kB, Rss 65 MB | -- |
| default (`code,alloc64`) | 32 MB | 32 MB, Rss 85 MB | FEXMem_Misc 16 MB, code buffer 16 MB (the first PMD of the 1 GiB buffer; python compiles a few MB of code, so THP rounds that up to 16 MB RSS) |
| `guest` | 192 MB (12 of the 200 MB block's 12 aligned windows) | 0 kB (freed) | -- |
| `all` | 256 MB | 64 MB, Rss 101 MB | + FEXAllocator 16 MB; the L1/L2 hints took (`madvise` seen in strace) but python's single thread touched less than a huge page of each |

Two things the runs caught, both fixed on the branch: (1) the first cut
tested `flags & MAP_SHARED_VALIDATE`, which is `MAP_SHARED|MAP_PRIVATE` as a
bit pattern and so rejected every private mapping -- the `hg` flag missing
from the guest VMA in a live `smaps` was the tell; (2) `VirtualName` latched
"unsupported" on the first `EINVAL`, and Core.cpp's naming of the malloc'd
`InternalThreadState` (unaligned, 4224 bytes) is always EINVAL, so
`FEXMem_Lookup`, `FEXMemJIT`, `FEXBlockIndex` and `FEXMem_CallRetStacks`
were never named on either kernel; unaligned requests are skipped now and
EINVAL no longer latches. Not run: `ctest` in `build-wt-thp` (only `Bin/FEX`
and `Bin/FEXServer` were built there, per the one-run budget); the mapping
subset is the orchestrator's to run on the merged tree.

Measurement plan (orchestrator): each lane at `FEX_THP=none` (the true
pre-64K baseline: no hint takes), default, `code,alloc64,lookup`, `all`, with
`FEX_THPLOG=2` to read coverage and the per-name RSS; watch Rss against the
`none` run before reading fps. nw lane (CP2077, W3): `code` is the only site
that matters (Wine owns guest memory, FEX's `guest` bit is inert there;
`lookup` is the RSS question with ~100 threads). Linux lane (RimWorld,
python): `guest` is the interesting bit -- it is the only one that can move a
data-TLB-bound workload, and the only one that can cost real memory.

2026-09-14, FEX_SMCGRANULEMIXED A/B on RimWorld Linux (`-quicktest`, a
generated map straight into play, mtrack + lazy recipe, code cache on; driver
`~/fex-scripts/rimworld_granule_ab.sh`, `perf stat` over the 20 s window
starting 120 s after launch; MangoHud cannot see the GL thunk, so no fps
column). Heuristic off (`FEX_SMCGRANULEMIXED=0`) vs on (default 64):
page faults 879,368 vs 5,141 per window (44 K/s vs 260/s), kernel cycles
28.3 G (8.7%) vs 17.7 G (4.9%), user instructions retired 68.6 G vs 141.7 G
at 296 G vs 340 G user cycles (IPC 0.23 vs 0.42), task-clock 95 s vs 104 s.
Flip reports 201 (storms for the whole lap) vs 77 with 75 demotions, none
repeated. Guarded blocks add instructions, but retiring twice the user work
for 15% more cycles is the off arm stalling in the fault storms and their
granule-wide invalidations, not guard overhead. Verdict: default ON stands.
Open: an in-game frame or tick counter for the Linux lane (the GL thunk
needs a MangoHud path or a RimWorld-side TPS log) before a fps number is
claimed. Found on the way: FEXServer's offline cache generation was live on
the Linux lane (the fexplay launcher puts Bin on PATH) and spawned
`FEXOfflineCompiler` runs at every launch (a second or two of a core each,
per the ps sampler) for caches nobody loads; the
client request is now opt-in (`FEX_SERVERCODECACHE=1`, e2a106ee3).

2026-09-14 13:36, FEX_SMCGRANULEMIXED verdict REVERSED by the frame log.
With `FEX_FRAMELOG` (f74dffe96) and `vblank_mode=0`, the same quicktest A/B
measured in-world frametimes (60-220 s in, counterbalanced, 2 laps each):
heuristic off p50 4.30 / 4.16 ms (185.8 / 159.0 fps), on p50 8.50 / 8.45 ms
(99.7 / 100.3 fps). The per-instruction validation on the demoted code pages
halves the main thread's throughput; the fault storms it removes land mostly
on worker threads. The perf-stat reading earlier today ("twice the user
instructions retired at higher IPC") was the guards, not extra work: a
counter A/B without a frame counter is not a verdict. Default is now 0
(off); the knob and the mechanism stay for a cheaper validation form (per
block entry rather than per instruction) or a hotness-aware demotion.
Next: the same fps A/B for `FEX_SMCGRANULEPOLICY=rearm`, the other way to
narrow the storms without guarding code.

2026-09-14 14:18, `FEX_SMCGRANULEPOLICY=rearm` vs default (`invalidate`),
same frame-log A/B, five legs each alternating: default p50 medians 4.04,
4.10, 4.13, 4.17, 4.24 ms (median 4.13); rearm 1.24, 4.18, 4.19, 4.24, 4.25
(median 4.19; the 1.24 ms leg was a lighter random map, quicktest seeds
differ per launch). No effect. Together with the mixed-heuristic reversal
above: on a young quicktest colony the granule flip storms (44 K faults/s,
~200 hot-granule reports per lap) do not bound the main thread, so neither
way of suppressing them buys fps, and the guards actively cost it. Open
item 2 is closed as "measured, not a bottleneck here"; the knobs stay. What
bounds RimWorld's frame on 64K is unmeasured: the next step is a main-thread
profile in-world (select the game with `pgrep -f "Bin/FEX .*RimWorldLinux"`,
not `pgrep -x FEX`), and a late-game save for the load that matters.

2026-09-14 14:30, CORRECTION (user caught it): every RimWorld fps number
above was taken on the world-gen LOADING SCREEN. One long quicktest leg with
the frame log gives the phases (seconds since launch, p50 frametime): 0-60
menu/splash 1.2-1.4 ms; 60-210 world-gen loading screen 4.2-4.8 ms (the
window all of today's A/Bs used); 210-240 map load, a 13 s hitch; in world
from ~240 s at 28.6-29.3 ms (~34 fps), drifting to 31-41 ms (24-32 fps) by
480 s as the colony ages. So: the mixed-heuristic "halves fps" and the
"rearm no effect" verdicts are loading-screen results and are VOID for play;
the in-world RimWorld reference on 64K is ~29 ms p50 on a fresh quicktest
map. The driver now runs 540 s legs and reports 270-450 s only; the in-world
A/Bs are being redone (mixed on/off first, rearm after). Lesson for the
harness: a scene window must be located from the frame log's phase change,
never assumed from a wall-clock offset.

### Morning kickoff checklist (orchestrator)

1. `ssh op64k`: confirm the box is on the 64K kernel, idle
   ([[op4k-check-before-benchmarking]]), /home free space.
2. Create the three worktrees and branches from the commits above; init
   submodules in the FEX ones; create `scratch-64k/`.
3. Launch S1, S2, S3 in one shot with the prompts built from §S1-S3 and the
   rules above.
4. On completion: inline review of each branch, fixes, merge to
   `daedalao-wt`, rebuild `build-smc`, then hand over the test list (S1/S2
   price checks need a 4K boot via kexec; S3 payoff is the CP2077/W3 nw laps
   on 64K).
5. Delete the wave-1 build dirs and worktrees after merge.
