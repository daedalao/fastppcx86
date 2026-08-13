# FastPPCx86: run x86 programs on POWER

FastPPCx86 is an x86/x86-64 user-mode emulator for **PPC64LE** hosts (POWER8 and later,
little-endian). It JITs guest x86 code to PPC64LE machine code and thunks guest libraries (GL,
Vulkan, EGL, etc.) through to the host's own implementations, so graphics and compute do not go
through the emulator. The codegen backend, the memory-model work (weak-ordering TSO emulation,
split-lock handling) and the self-modifying-code subsystem are written for POWER.

- **Minimum ISA: POWER8.** All emitted code must stay POWER8-legal; POWER9-only instructions are
  gated behind runtime feature detection, not assumed.
- **POWER9 hosts are supported** and get additional codegen improvements where the ISA allows it,
  but nothing requires POWER9.
- **Host page size:** the self-modifying-code tracker (`SMCChecks=mtrack`) mprotect()s guest pages
  at FEX's fixed 4K granularity to match the AT_PAGESZ=4096 the guest is told. On a host booted
  with a larger page size, mtrack-based SMC detection is unsupported and will misbehave or abort;
  boot a 4K-page kernel, or run with `FEX_SMCCHECKS=full` on larger-page hosts.

## Provenance

FastPPCx86 is derived from the FEX-Emu project (<https://github.com/FEX-Emu/FEX>) and is
distributed under the same MIT license. See [`LICENSE`](LICENSE), which is unmodified. This
project was forked and heavily uses LLM generated code.

This is a permanent fork with no plan to merge back. The PPC64LE backend, the memory-model work
and the SMC subsystem diverge deliberately from how upstream solves the same problems on ARM64.
The upstream README is preserved verbatim as [`README.upstream.md`](README.upstream.md) (with its
translation [`docs/Readme_CN.md`](docs/Readme_CN.md)) and is not maintained here. Everything else
in `docs/` describes *this* project.

**Binaries and environment variables keep the historical `FEX` prefix.** The programs are still
called `FEX`, `FEXBash`, `FEXServer`, `FEXRootFSFetcher`, config keys are unchanged, and every
environment variable is still `FEX_<NAME>`. Only the documentation has been renamed; renaming the
code would break every existing config file, launcher and script for no benefit.

## Build

Standard CMake/Ninja build:

```sh
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
```

Notable CMake options (see top-level `CMakeLists.txt` for the full list):

| Option | Default | Notes |
|---|---|---|
| `BUILD_THUNKS` | OFF | Build the host-side thunk libraries (GL/Vulkan/EGL/etc.). |
| `BUILD_THUNKS_32BIT` | ON | Build 32-bit guest thunk libraries; requires a working 32-bit guest toolchain. |
| `ENABLE_CLANG_THUNKS` | OFF | Build thunks with clang instead of the configured cross-GCC. |
| `ENABLE_ZYDIS` | OFF | Required for `FEX_X86DISASSEMBLE` guest disassembly output. |
| `ENABLE_JIT_OPSIZE_PROFILE` | OFF | Compiles in the PPC64LE per-IR-op host-code-size profiler; runtime opt-in is separate (`FEX_JITOPSIZEPROFILE`, see below). Fork-specific. |
| `ENABLE_GDB_SYMBOLS` | auto-detected | GDB JIT-interface integration. |
| `ENABLE_FEXCORE_PROFILER` | OFF | Timeline profiling support. |

x86_64/x86 guest-side stub libraries (`libGL-guest.so`, `libvulkan-guest.so`, etc., when
`BUILD_THUNKS`/`BUILD_THUNKS_32BIT` are enabled) are cross-compiled for the guest architecture and
need an x86 toolchain and sysroot; see `Data/CMake/toolchain_x86_64.cmake` and
`ThunkLibs/GuestLibs/CMakeLists.txt`.

## Configuration

Every option below is settable as an environment variable `FEX_<NAME>` (the option name upper-cased,
no separators, so `SMCStoreEmulation` becomes `FEX_SMCSTOREEMULATION=1`), or via JSON config layers
loaded in this order (later layers override earlier ones): global main config, per-user main
config, global/local Steam-app config, global/local per-app config, command-line arguments, a
user-override layer, then environment variables, then a final top layer.

Config file locations follow XDG conventions, with a legacy fallback:

- If `$HOME/.fex-emu/` exists, it is used directly (legacy layout).
- Otherwise the config directory is `$XDG_CONFIG_HOME/fex-emu/` (default `~/.config/fex-emu/`) and
  the data directory is `$XDG_DATA_HOME/fex-emu/` (default `~/.local/share/fex-emu/`).
- The main config file is `Config.json` in the config directory.
- Per-application overrides live in `AppConfig/<program-name>.json` under the config directory.
  This is what lets you enable a flag (e.g. `SMCLazyInval`) for one game without affecting every
  other guest process.

## Running games: Mono/Unity titles require a CPU cage

**Always launch Mono/Unity games under `taskset`** (or another affinity cage) on many-core hosts.
Unity sizes its worker/job pools from the reported CPU count; on an 80-thread POWER8 an uncaged
guest builds ~79-worker pools whose quiesce/park handshakes are statistically unreachable at that
scale. The pool spins instead of parking, saturating the machine while the game crawls (Hard
West: 79 workers, park gate `[obj+0x74]==0` never satisfied, ~2 fps). Since commit `9a0f8e1be`
the emulated `/proc/cpuinfo` is bounded by the process affinity mask, so the cage also shrinks
the guest-visible CPU count and the pools stay sane.

Recommended launch shape (POWER8 in SMT4; 8 cores by 2 threads). Online CPU numbering is sparse
(`0-3,8-11,...`), so list explicit thread pairs:

```sh
taskset -c 0-1,8-9,16-17,24-25,32-33,40-41,48-49,56-57 FEX <game>
```

- `FEX_REPORTED_CPUS=N` forces the guest-visible count regardless of cage. Use it when you want
  a small pool but a wide cage, or on pre-`9a0f8e1be` builds.
- One thread per core (`taskset -c 0,8,16,...`) trades parallelism for POWER8 single-thread mode
  throughput. Worth trying for main-thread-bound titles.
- Host clock matters: the `ondemand` governor often never ramps under JIT'd load (observed parked
  at 59% of max mid-game). Set `performance` while gaming:
  `sudo cpupower frequency-set -g performance` (or via sysfs `scaling_governor`).
- `FEX_ENABLEAVX=0` pushes guest code onto SSE paths, which emulate much faster on 128-bit vector
  hardware (36 to 67% measured on glibc string routines).
- SMC recipe is per-title: `lazy` batches invalidation (best where Mono churns code) but disables
  block linking; `strict`/`off` keep linking. Profile before assuming: a flat guest profile means
  raw throughput, not recipe overhead, is the limit.
- `SpinLoopClampAuto=1` short-circuits recognized library spin-wait loops. No longer needed for
  correctness anywhere, but measurable as a perf opt-in.

[`docs/GAMING.md`](docs/GAMING.md) is the full launch guide: prerequisites, launch shapes, SMC
recipes, Steam, and where the logs actually go.

## Flags reference

Grouped by area. **Fork** marks an option added in this port and not present upstream;
everything else is inherited from upstream, though some upstream options (SMCChecks, TSOEnabled,
the vector/memcpy TSO knobs, MonoHacks) carry PPC64LE-specific behavior or caveats noted inline.
Types: bool options accept 0/1/true/false; `strenum` options take one of the listed string values.

### CPU / codegen

| Flag | Type (default) | Description |
|---|---|---|
| `Multiblock` | bool (true) | Compile multiple basic blocks per JIT compilation unit. Improves codegen quality; can increase JIT stutter on first hit. |
| `MaxInst` | int32 (5000) | Maximum guest instructions per compiled block. |
| `EnableCodeCachingWIP` | bool (false) | Master switch for the (work-in-progress) on-disk code cache subsystem. With it off, nothing is loaded or written no matter what `CodeCacheScope` says. Cache files are named `<content-hash of the guest file>-<hash of the FEX build + every codegen-affecting option>`, so a rebuilt library, a rebuilt FEX or a flipped codegen flag is a cache *miss*, never a mismatched load. |
| `CodeCacheScope` | str ("off") | **Fork.** Which guest files may be cached, and whether the running process writes cache files at all. `off` (default) is the legacy behaviour: caches are loaded for any file but only `FEXOfflineCompiler` ever writes them. `rootfs` loads *and writes* caches only for files under the configured `RootFS`; system libraries, which are immutable in practice and shared between titles, so their translations are the ones worth keeping across runs. `all` extends that to game-side native libraries and the main executable. Anything other than `off` makes the process a cache generator: FEX retains FEX relocations and decodes section-bounded for every block (costing memory and forbidding cross-file multiblock), checkpoints caches periodically from the memory-management syscalls, and writes a final checkpoint at exit. Writes go to a temp file plus `rename(2)`, so a process killed mid-save can only lose translations made since the last checkpoint; never an existing cache. Files carrying code relocations FEX cannot normalize, and files this process itself loaded a cache for, are never written. Requires `EnableCodeCachingWIP`. |
| `EnableCodeCacheValidation` | bool (false) | Expensive validation pass when loading a code cache. Recompiles every cached block and compares: the guest→host block-mapping table against the fresh compile's, then the code bytes. Mismatches are fatal. Only meaningful for caches produced by `FEXOfflineCompiler`; it recompiles in ascending guest order, whereas a runtime-generated cache (`CodeCacheScope != off`) is laid out in execution order, so the two legitimately differ. |
| `HostFeatures` | strenum (off) | Force-enable or force-disable individual host ISA feature bits used by the JIT (SVE, AVX, AFP, LRCPC/LRCPC2, CSSC, PMULL128, RNG, CLZERO, atomics, FCMA, FLAGM/FLAGM2, FRINTTS, crypto, RPRES, SVE bit-permute, preserve-all ABI, WFXT, 3DNow, SSE4a, MOPS), overriding autodetection. Mostly a testing/debugging knob. |
| `SmallTSCScale` | bool (true) | Scales the emulated cycle counter down on hosts with a low native timebase frequency. |
| `HideHybrid` | bool (true) | Hides a hybrid (big.LITTLE-style) core arrangement from the guest's CPU topology view. |
| `CPUFeatureRegisters` | str ("") | Manual override string for CPU feature registers, for testing. |

### Runtime / emulation environment

| Flag | Type (default) | Description |
|---|---|---|
| `RootFS` | str ("") | Guest root filesystem: a path, or a name resolved under the FEX data folder's `RootFS/` directory. |
| `ThunkHostLibs` | str (install libdir `/fex-emu/HostThunks`) | Directory containing host-side thunk libraries. |
| `ThunkGuestLibs` | str (install prefix `/share/fex-emu/GuestThunks`) | Directory containing guest-side thunk libraries. |
| `ThunkConfig` | str ("") | JSON file describing thunk library overlay/mapping; path or named config under the data folder. |
| `Env` | strarray | Environment variable(s) to inject into the emulated (guest) process. |
| `HostEnv` | strarray | Environment variable(s) to inject into the host process; useful for variables a thunk's host side needs to see. |
| `AdditionalArguments` | strarray | Extra arguments appended to the guest application's argv. |
| `DisableL2Cache` | bool (true) | Disables the JIT's L2 block-lookup cache to save memory; can increase stutter. |
| `DynamicL1Cache` | bool (true) | Lets the JIT's L1 lookup cache resize dynamically to save memory. |
| `DynamicL1CacheIncreaseCountHeuristic` | uint64 (250) | Lookups/sec threshold above which the dynamic L1 cache grows. Lower = more aggressive growth. |
| `DynamicL1CacheDecreaseCountHeuristic` | uint64 (50) | Lookups/sec threshold below which the dynamic L1 cache shrinks. Must stay ≤ the increase threshold. |

### Memory model / TSO / atomics

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `TSOEnabled` | bool (true) | | Emits x86 TSO-preserving memory ordering. Disabling it will break almost any multithreaded guest. |
| `LockOnlyTSO` | bool (false) | **Fork** | Opt-in relaxation for weakly-ordered hosts (PPC64LE): with TSO enabled, only emit the acquire/release dance for instructions actually carrying `LOCK` (or explicitly forced via `MonoHacks`/volatile-metadata ranges); plain `mov reg,[mem]` uses a cheap load instead. Meant to remove per-load ordering overhead that dominates tight libc/pthread loops. **Unsound, measured:** the x86-forbidden `MP` litmus outcome fired 659/12/51 per 30,000 rounds with it on versus 0/150,000 with it off, same guest binary; a seq_cst-shaped test does not detect it. Lock-free or `volatile`-based guest code can silently compute wrong results. glibc futex/PLT lazy-resolve are `LOCK CMPXCHG`-backed and stay correct, which is the limit of what is safe. FEX warns once at startup. See `docs/GAMING.md` &sect; "Knobs that are known-unsound". No effect if `TSOEnabled` is false. |
| `VectorTSOEnabled` | bool (false) | | Also makes vector load/store TSO-atomic when TSO is enabled. |
| `MemcpySetTSOEnabled` | bool (false) | | Also makes `REP MOVS`/`REP STOS` (memcpy/memset) TSO-atomic when TSO is enabled. |
| `HalfBarrierTSOEnabled` | bool (true) | | Backpatches unaligned loads/stores to half-barrier atomics under TSO. Can make aligned load/stores through the same patched code non-atomic; read the upstream caveat before disabling. |
| `StrictInProcessSplitLocks` | bool (false) | | Global lock around unaligned atomics that cross a 16-byte/cacheline boundary, to stop them from tearing within the process. |
| `KernelUnalignedAtomicBackpatching` | bool (true) | | When the kernel unaligned-atomic handler is active, backpatch call sites to cut kernel context-switch overhead. |
| `VolatileMetadata` | bool (true) | | Use PE volatile-metadata (when present) to decide per-instruction TSO needs; falls back to the other TSO flags when metadata is absent. |
| `ExtendedVolatileMetadata` | str ("") | | (Misc group) Manually specified volatile-metadata ranges (module/offset/instruction syntax), for WoW64/arm64ec-style TSO exemptions. |

### Self-modifying code (SMC): fork-specific subsystem

Upstream has one SMC knob (`SMCChecks`). This fork adds a family of PPC64LE-oriented SMC
mechanisms layered on top of it, aimed at cutting the cost of mprotect-fault-driven invalidation
for guests that write frequently near their own code (JIT runtimes, packers/DRM, Mono AOT). Most
are off by default and must be opted into (globally or per-app).

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `SMCChecks` | uint8 (mtrack) | | Base SMC detection mode: `none` (no checks), `mtrack` (page-tracking-based invalidation, default), `full` (validate code before every run; slow, but works when the host page size doesn't match FEX's 4K assumption). |
| `SMCSoftInvalidate` | bool (false) | **Fork** | On an SMC write fault, soft-invalidate the page's blocks (unlink from lookup caches, sever inbound links) but keep the compiled code and a hash of its source bytes instead of discarding it. The next dispatch re-hashes and relinks if unchanged; only genuinely modified blocks recompile. |
| `SMCFileImmutable` | bool (false) | **Fork** | Treats code from a private file-backed mapping (Wine DLLs, libc, an executable's own `.text`) as immutable and skips mtrack write-protection on it, since such mappings are normally only written at load time. Guest mmap/munmap/mprotect still invalidate unconditionally. **Known breakage:** in-place patching of file-backed `.text` through an already-writable mapping (some DRM/packers, some Mono AOT fixups) goes undetected. Only meaningful with `SMCChecks=mtrack`; opt in per application. |
| `SMCLazyInval` | bool (false) | **Fork** | On an SMC write fault, unprotect the page and mark it dirty but invalidate nothing immediately; the writer runs at native speed. Soft-invalidation is deferred to the next drain point (a thread entering the block compiler, a guest syscall, guest signal delivery, or a guest `mprotect` granting `PROT_EXEC`). **Sound by default** for same-thread self-modifying code: `SMCLazyScrub` (below, on by default) scrubs the faulting thread's block-lookup fast path so that thread cannot re-enter translated code without draining first. What remains deferred is cross-thread modification, which x86 does not guarantee either; the reading thread must serialize, and every way it can (syscall, signal, dispatching new code) is a drain point. Setting `SMCLazyScrub=0` restores the older, faster, **deliberately unsound** behaviour in which a thread can execute a stale translation of code it just wrote. Requires `SMCSoftInvalidate` and `SMCChecks=mtrack`. |
| `SMCLazyScrub` | bool (**true**) | **Fork** | Only meaningful with `SMCLazyInval=1`. When an SMC write fault takes the lazy route, zero the faulting thread's L1 block-lookup cache and flag that thread as owing a drain. With no block linking on this backend, an empty L1 forces the thread's very next dispatch through the C++ lookup slow path, which runs the deferred soft-invalidation *before* consulting the shared L2/L3 caches; so the thread that patched the code cannot reach a stale translation. Costs one `madvise` on the writer per fault plus one drain at its next dispatch; writers that never re-dispatch into the page they dirtied (false-sharing storms) keep lazy's full speedup. Set to `0` to A/B against the original unsound-but-faster lazy behaviour. |
| `SMCLazyLink` | bool (false) | **Fork** | Only meaningful with `SMCLazyInval=1` + `SMCLazyScrub=1`. Keep block linking (direct block-to-block branches) enabled under lazy invalidation instead of interlocking it off. The same-thread guarantee is rebuilt on a trap a linked chain cannot skip: the SMC fault handler additionally arms the writer's `InterruptFaultPage`, and the fault-page poke every block entry executes (linked arrivals included; links target block entries) faults the thread into a drain at its next block transfer. Costs one `mprotect` + one extra fault per lazy SMC fault, writer only. Motivation: with linking interlocked off, `ExitFunctionLink` measured as the single hottest symbol (7.3%) in Unity combat profiling. Refused with `SMCSemanticPatch` (a patched destination-RIP immediate cannot retarget an already-linked branch). |
| `SMCStoreEmulation` | bool (false) | **Fork** | On a fault from a guest store to an SMC-tracked page, emulate the store via `/proc/self/mem` in the signal handler when the written bytes don't overlap any compiled block, instead of invalidating and re-protecting the page. Removes false-sharing invalidation storms (code and unrelated data sharing a guest page). Stores that do overlap compiled code still fall back to normal invalidation. |
| `SMCSemanticPatch` | bool (false) | **Fork** | Recognizes a guest store that rewrites only a patchable immediate inside an already-compiled block and patches the translated code directly instead of invalidating; the page stays protected and the block stays live. Two shapes: the rel32 target of a direct call/jmp/jcc (patches the destination RIP baked into the block's translated exit), and the immediate of `mov r32, imm32` / `mov r64, imm64` / `C7 /0 reg, imm32` (patches the fixed-width materialization window the backend emitted for that immediate, located by provenance carried through the IR, not by value). The store may lie inside the immediate field or cover it entirely as long as the bytes it writes outside the field are unchanged. Anything else (partial/oversized writes, writes that also change instruction bytes, ambiguous or non-atomically publishable constants) falls back to the normal path. |
| `SMCStoreBackpatch` | bool (false) | **Fork** | When an SMC fault lands on a decodable host store instruction, rewrites that store site to branch to a generated stub instead of faulting again on every hit. The stub recomputes the effective address, checks a lock-free filter of mtrack-protected pages, and either performs the store natively or routes through the `/proc/self/mem` helper. Removes the ~17 µs signal round-trip that otherwise dominates repeated-fault SMC storms. Requires `SMCStoreEmulation`. |
| `SMCCheapTier` | bool (false) | **Fork** | Compiles blocks on pages that keep getting invalidated with a cheap, disposable tier (small instruction cap, no multiblock) instead of full-quality codegen, since repeatedly-overwritten runtime-codegen pages throw most of that compile work away anyway. |
| `SMCCheapTierThreshold` | uint32 (8) | **Fork** | Number of invalidations of a page before its blocks drop to the cheap tier. Only meaningful with `SMCCheapTier`. |
| `SMCCheapTierMaxInst` | uint32 (500) | **Fork** | Max guest instructions per block in the cheap tier. Only meaningful with `SMCCheapTier`. |
| `SMCMprotectDefer` | bool (false) | **Fork** | Treats a guest `mprotect` that removes `PROT_EXEC` (but adds write) from a tracked page as the real invalidation point rather than invalidating immediately: the page is marked deferred-dirty and left unprotected so guest writes run at full speed, with invalidation actually applied when/if the guest mprotects it back to `PROT_EXEC`. Only sound because the guest cannot execute code through the intermediate non-exec mapping; a W+X mprotect keeps legacy (immediate) behavior. |
| `MonoHacks` | bool (true) | | Upstream option enabling a hook-based SMC approach and smaller JIT blocks specifically for Mono-hosted guests; several of this fork's SMC mechanisms (e.g. `LockOnlyTSO`'s forced-TSO ranges) key off it. |

`MonoHacks`' dynamic-library detection (`libmono*.so`/`libmonobdwgc-2.0.so`/etc.) never fires for a
statically-linked Mono runtime (MonoKickstart, the scheme Stardew Valley-class titles use to bundle
mono directly into the game executable). Two raw environment variables, **not** part of the
`FEX_<Name>` config-layering system above and so with no JSON-config equivalent, extend detection to that
case by registering the main executable's own mapped range as the backpatcher range instead of a
library's:

| Variable | Default | Fork? | Description |
|---|---|---|---|
| `FEX_MONO_DETECT` | on (`1`) | **Fork** | Set to `0` to disable the statically-linked-Mono fallback: watching guest `open`/`openat`/`openat2` calls for a path ending in `/mscorlib.dll` or `/machine.config` (mono's own canonical data files) and, on the first match, treating the main executable as the mono runtime. Does not affect dynamic `libmono*.so` detection. |
| `FEX_FORCE_MONO_DETECT` | off | **Fork** | Set to `1` to unconditionally treat the main executable as the mono runtime from the first guest syscall on, bypassing both the dynamic-library and data-file signals; for experiments where neither is reachable. |

### Concurrency diagnostics: fork-specific

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `SyscallObserve` | bool (false) | **Fork** | Wraps pathology-prone passthrough syscalls (`futex`, `tgkill`) with per-thread state tracking and structured logging. Zero cost when disabled. Currently detects futex EAGAIN-storms (same addr/op/val repeated in a short window) and logs cross-thread `tgkill` signal delivery (useful for Mono GC stop-the-world diagnosis). |
| `FutexMitigate` | bool (false) | **Fork** | Companion to `SyscallObserve`: when a futex EAGAIN-storm is detected for the current thread, emits `sched_yield()` before returning to the guest, to let a competing waker thread make progress and break userspace-mutex livelock that can occur when a guest assumes x86-TSO visibility on PPC64LE's weaker ordering. Inert unless `SyscallObserve` is also set. |

### Debug / JIT introspection

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `SingleStep` | bool (false) | | Single-steps guest execution. |
| `GdbServer` | bool (false) | | Enables the GDB remote-serial-protocol server. |
| `DumpIR` | str (no) | | Dump FEX's IR: `no`, `stdout`, `stderr`, `server`, or a folder path. |
| `PassManagerDumpIR` | strenum (off) | | When to dump IR relative to optimization passes: `beforeopt`, `afteropt`, `beforepass`, `afterpass`. |
| `DumpGPRs` | bool (false) | | Print GPR state when the test harness ends. |
| `O0` | bool (false) | | Disables IR optimization passes, for debugging. |
| `GlobalJITNaming` | bool (false) | | Names all JIT code as a single symbol (`FEXJIT`), useful for measuring aggregate time-in-JIT with a profiler. |
| `LibraryJITNaming` | bool (false) | | Names JIT symbols grouped by guest library, useful for per-library time breakdown and guiding thunk work. |
| `BlockJITNaming` | bool (false) | | Names JIT symbols per compiled block (hot-block identification); has file-writing overhead per block. |
| `GDBSymbols` | bool (false) | | Integrates with GDB's JIT interface (needs FEX's GDB JIT reader loaded and `x86_64-linux-gnu-objdump` in `PATH`). Can be slow. |
| `JITOpSizeProfile` | bool (false) | **Fork** | PPC64LE-only: measures how many host bytes each IR op expands to, accumulating count/total/max per `IROps` value and periodically rewriting `/tmp/fex-jit-opsize-<pid>.txt`. Used to validate the JIT's per-op code-buffer size budget. Requires building with `ENABLE_JIT_OPSIZE_PROFILE=ON`. |
| `InjectLibSegFault` | bool (false) | | Sets `LD_PRELOAD=libSegFault.so` in the guest environment automatically. Requires x86/x86_64 `libSegFault.so` to be installed in the guest rootfs. |
| `Disassemble` | strenum (off) | | vixl disassembler output for generated host code: `dispatcher`, `blocks`, or `stats`. |
| `X86Disassemble` | bool (false) | | Guest x86/x86-64 disassembly for compiled blocks. Requires building with `ENABLE_ZYDIS=ON`. |
| `ForceSVEWidth` | uint32 (0) | | Overrides the SVE vector width in the vixl simulator, for debugging. |
| `DisableTelemetry` | bool (false) | | Disables telemetry at runtime (mainly for `instcountCI`). |
| `StallProcess` | bool (false) | | Stalls the process on startup; useful for attaching a debugger to something that would otherwise crash too fast. |
| `StartupSleep` | uint32 (0) | | Sleeps the process N seconds at startup. |
| `StartupSleepProcName` | str ("") | | Restricts `StartupSleep` to processes whose name matches. |
| `HideHypervisorBit` | bool (false) | | Hides the hypervisor CPUID bit for guests that misbehave when they see it. |
| `X87ReducedPrecision` | bool (false) | | Emulates x87 using 64-bit precision instead of full 80-bit; faster, less accurate, can cause rendering bugs. |
| `NeedsSeccomp` | str→bool (false) | | Disables inline (fast-path) syscalls so seccomp filtering sees every syscall. |

### Logging

| Flag | Type (default) | Description |
|---|---|---|
| `SilentLog` | bool (true) | Disables FEX's own logging output. |
| `OutputLog` | str (server) | Where FEX writes its output: `stderr`, `server`, or a filename. |
| `TelemetryDirectory` | str ("") | Overrides where telemetry data is written (default under the data directory's `Telemetry/`). |
| `ProfileStats` | bool (false) | Enables low-overhead sampling profile statistics; requires a Mangohud build that understands them to view. |
| `EnableGpuvisProfiling` | bool (false) | Enables gpuvis-backend profiling, if FEX was built with it. |
| `ThreadCensus` | str ("") | **Fork.** Diagnostic. Appends a plain-text thread census to the given path, one line per event: `<monotonic-ms> tid=<n> event=<type> <key=val>...`. Events: `thread_create` (guest/host TID, parent TID, raw guest RIP of the clone caller, clone flags), `set_name` (`prctl(PR_SET_NAME)`), `sched_setscheduler`/`sched_setattr`/`sched_setparam` (policy, priority, and what FEX did with the request; always `passthrough-ok`/`passthrough-fail`; FEX fakes none of them), `sched_setaffinity` (mask popcount plus lowest/highest set CPU), and `sched_boost` (the `SchedPassthrough` ladder). Observation only; never changes a guest-visible return value. |
| `SchedPassthrough` | bool (false) | **Fork.** FEX forwards guest scheduler calls to the host verbatim, so an unprivileged host refuses guest `SCHED_FIFO`/`SCHED_RR` requests with `EPERM` and audio/render threads end up at plain `SCHED_OTHER`. With this set, an `EPERM`'d RT request is retried on the host with progressively weaker boosts: `SCHED_RR` at the lowest permitted priority, then a niceness boost to −10 (clamped by `RLIMIT_NICE`), then give up. Changes real host scheduling only; the guest still receives exactly the value it would have without the flag. Log the ladder with `ThreadCensus`. |

### Misc

| Flag | Type (default) | Description |
|---|---|---|
| `ServerSocketPath` | str ("") | Overrides the FEXServer socket path; mainly for chroot setups. |

## License

MIT. See [`LICENSE`](LICENSE), which is preserved unmodified, original copyright notice
included. The PPC64LE backend and the SMC/memory-model work in this repository are additional
contributions under the same terms. See [Provenance](#provenance).
