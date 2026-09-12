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
5. NCS code cache: disabled on 64K until the cache format pads to 64K and
   the identity hash includes the host page size (design §7). On 64K the
   loss is the first-run compile cost, nothing else.

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

Open items, in priority order: (1) a fatal trap or fault raised in FEX's own
host code must never be delivered to the guest as a signal (it abandons the
host frame with its locks); (2) mtrack arming
heuristic for mixed code/data granules (S4c's `TrackedCount` is the input;
also the flip log prints the count after clearing it); (3) route the raw
`GuestM*` host calls in `SyscallsSMCTracking.cpp` through the granule layer
and wire `SetSMCOverlay`/`GranuleFullyBacked` between S4b and S4c; (4) HWTSO
SAO refusal on an emulated granule does not revoke HWTSO; (5) the 4K price
check for S1/S2 and the 4K regression run of S4 (`granule_page` test) on the
op4k boot; (6) `Scripts/granule_page_64k.sh` can go now the loader fallback
exists; (7) NCS code cache stays off on 64K until the cache pads to 64K; (8) RimWorld Linux-lane performance (tutorial fps under mtrack, 64K vs 4K, then profile).

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
