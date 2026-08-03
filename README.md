# ppcFEX — a PPC64LE fork of FEX-Emu

ppcFEX is a permanent fork of [FEX-Emu](https://github.com/FEX-Emu/FEX) that targets **PPC64LE**
(POWER8 and later, little-endian) as a JIT host instead of ARM64. FEX is an x86/x86-64 user-mode
emulator: it JITs guest x86 code to host machine code and thunks guest libraries (GL, Vulkan, EGL,
etc.) through to host implementations. This fork replaces the ARM64 codegen backend with a
PPC64LE one and adapts the parts of the runtime (TSO/memory-model emulation, self-modifying-code
detection, atomics) that are architecture-sensitive.

- **Minimum ISA: POWER8.** All emitted code must stay POWER8-legal; POWER9-only instructions are
  gated behind runtime feature detection, not assumed.
- **POWER9 hosts are supported** and get additional codegen improvements where the ISA allows it,
  but nothing requires POWER9.
- **Host page size:** the self-modifying-code tracker (`SMCChecks=mtrack`) mprotect()s guest pages
  at FEX's fixed 4K granularity to match the AT_PAGESZ=4096 the guest is told. On a host booted
  with a larger page size, mtrack-based SMC detection is unsupported and will misbehave or abort;
  boot a 4K-page kernel, or run with `FEX_SMCCHECKS=full` on larger-page hosts.

## Relationship to upstream FEX-Emu

**This is a permanent fork. It will not be upstreamed to FEX-Emu.** The PPC64LE codegen backend,
the PPC64LE-specific memory-model work (weak-ordering TSO emulation, split-lock handling), and the
self-modifying-code (SMC) subsystem rewrite in this repo are PPC-specific and diverge deliberately
from how upstream FEX-Emu's ARM64/x86-64 hosts solve the same problems. There is no intent to
reconcile this fork's design back into upstream.

- Upstream credit and license are unchanged — see [License](#license).
- The original upstream README (as of the point this fork's README was rewritten) is preserved at
  [`README.upstream.md`](README.upstream.md) for reference.
- Everything in this document describes *this* fork's state, build, and configuration surface —
  not upstream FEX-Emu's.

## Build

Standard CMake/Ninja build, same as upstream FEX:

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
`ThunkLibs/GuestLibs/CMakeLists.txt`. `docs/BUILD_CONFIG.md` records one project's known-good
thunk/toolchain configuration in more detail.

## Configuration

Every option below is settable as an environment variable `FEX_<NAME>` (the option name upper-cased,
no separators — e.g. `SMCStoreEmulation` → `FEX_SMCSTOREEMULATION=1`), or via JSON config layers
loaded in this order (later layers override earlier ones): global main config, per-user main
config, global/local Steam-app config, global/local per-app config, command-line arguments, a
user-override layer, then environment variables, then a final top layer.

Config file locations follow XDG conventions, with a legacy fallback:

- If `$HOME/.fex-emu/` exists, it is used directly (legacy layout).
- Otherwise the config directory is `$XDG_CONFIG_HOME/fex-emu/` (default `~/.config/fex-emu/`) and
  the data directory is `$XDG_DATA_HOME/fex-emu/` (default `~/.local/share/fex-emu/`).
- The main config file is `Config.json` in the config directory.
- Per-application overrides live in `AppConfig/<program-name>.json` under the config directory —
  this is what lets you enable a flag (e.g. `SMCLazyInval`) for one game without affecting every
  other guest process.

## Flags reference

Grouped by area. **Fork** marks an option added in this port and not present in upstream FEX-Emu;
everything else is inherited from upstream (though some upstream options — SMCChecks, TSOEnabled,
the vector/memcpy TSO knobs, MonoHacks — carry PPC64LE-specific behavior or caveats noted inline.
Types: bool options accept 0/1/true/false; `strenum` options take one of the listed string values.

### CPU / codegen

| Flag | Type (default) | Description |
|---|---|---|
| `Multiblock` | bool (true) | Compile multiple basic blocks per JIT compilation unit. Improves codegen quality; can increase JIT stutter on first hit. |
| `MaxInst` | int32 (5000) | Maximum guest instructions per compiled block. |
| `EnableCodeCachingWIP` | bool (false) | Enables the (work-in-progress) on-disk code cache subsystem. |
| `EnableCodeCacheValidation` | bool (false) | Expensive validation pass when loading a code cache, to detect corruption/staleness. |
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
| `HostEnv` | strarray | Environment variable(s) to inject into the host process — useful for variables a thunk's host side needs to see. |
| `AdditionalArguments` | strarray | Extra arguments appended to the guest application's argv. |
| `DisableL2Cache` | bool (true) | Disables the JIT's L2 block-lookup cache to save memory; can increase stutter. |
| `DynamicL1Cache` | bool (true) | Lets the JIT's L1 lookup cache resize dynamically to save memory. |
| `DynamicL1CacheIncreaseCountHeuristic` | uint64 (250) | Lookups/sec threshold above which the dynamic L1 cache grows. Lower = more aggressive growth. |
| `DynamicL1CacheDecreaseCountHeuristic` | uint64 (50) | Lookups/sec threshold below which the dynamic L1 cache shrinks. Must stay ≤ the increase threshold. |

### Memory model / TSO / atomics

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `TSOEnabled` | bool (true) | | Emits x86 TSO-preserving memory ordering. Disabling it will break almost any multithreaded guest. |
| `LockOnlyTSO` | bool (false) | **Fork** | Opt-in relaxation for weakly-ordered hosts (PPC64LE): with TSO enabled, only emit the acquire/release dance for instructions actually carrying `LOCK` (or explicitly forced via `MonoHacks`/volatile-metadata ranges); plain `mov reg,[mem]` uses a cheap load instead. Meant to remove per-load ordering overhead that dominates tight libc/pthread loops. Risk: real concurrent code relying on non-LOCK volatile-read visibility could race, though glibc futex/PLT lazy-resolve paths are understood to be safe. No effect if `TSOEnabled` is false. |
| `VectorTSOEnabled` | bool (false) | | Also makes vector load/store TSO-atomic when TSO is enabled. |
| `MemcpySetTSOEnabled` | bool (false) | | Also makes `REP MOVS`/`REP STOS` (memcpy/memset) TSO-atomic when TSO is enabled. |
| `HalfBarrierTSOEnabled` | bool (true) | | Backpatches unaligned loads/stores to half-barrier atomics under TSO. Can make aligned load/stores through the same patched code non-atomic — read the upstream caveat before disabling. |
| `StrictInProcessSplitLocks` | bool (false) | | Global lock around unaligned atomics that cross a 16-byte/cacheline boundary, to stop them from tearing within the process. |
| `KernelUnalignedAtomicBackpatching` | bool (true) | | When the kernel unaligned-atomic handler is active, backpatch call sites to cut kernel context-switch overhead. |
| `VolatileMetadata` | bool (true) | | Use PE volatile-metadata (when present) to decide per-instruction TSO needs; falls back to the other TSO flags when metadata is absent. |
| `ExtendedVolatileMetadata` | str ("") | | (Misc group) Manually specified volatile-metadata ranges (module/offset/instruction syntax), for WoW64/arm64ec-style TSO exemptions. |

### Self-modifying code (SMC) — fork-specific subsystem

Upstream FEX has one SMC knob (`SMCChecks`). This fork adds a family of PPC64LE-oriented SMC
mechanisms layered on top of it, aimed at cutting the cost of mprotect-fault-driven invalidation
for guests that write frequently near their own code (JIT runtimes, packers/DRM, Mono AOT). Most
are off by default and must be opted into (globally or per-app).

| Flag | Type (default) | Fork? | Description |
|---|---|---|---|
| `SMCChecks` | uint8 (mtrack) | | Base SMC detection mode: `none` (no checks), `mtrack` (page-tracking-based invalidation, default), `full` (validate code before every run — slow, but works when the host page size doesn't match FEX's 4K assumption). |
| `SMCSoftInvalidate` | bool (false) | **Fork** | On an SMC write fault, soft-invalidate the page's blocks (unlink from lookup caches, sever inbound links) but keep the compiled code and a hash of its source bytes instead of discarding it. The next dispatch re-hashes and relinks if unchanged; only genuinely modified blocks recompile. |
| `SMCFileImmutable` | bool (false) | **Fork** | Treats code from a private file-backed mapping (Wine DLLs, libc, an executable's own `.text`) as immutable and skips mtrack write-protection on it, since such mappings are normally only written at load time. Guest mmap/munmap/mprotect still invalidate unconditionally. **Known breakage:** in-place patching of file-backed `.text` through an already-writable mapping (some DRM/packers, some Mono AOT fixups) goes undetected. Only meaningful with `SMCChecks=mtrack`; opt in per application. |
| `SMCLazyInval` | bool (false) | **Fork** | **Deliberately unsound, for speed.** On an SMC write fault, unprotect the page and mark it dirty but invalidate nothing immediately — the writer runs at native speed. Soft-invalidation is deferred to the next drain point (thread entering the block compiler, a guest syscall, or guest signal delivery). A thread can therefore execute a **stale** translation between the write and that drain; a same-thread patch-then-call that hits the L1 lookup cache is the known exposure and can make a guest miscompute or crash. This is a per-game opt-in, not a safe default — unsafe for JIT-heavy guest titles unless verified. Requires `SMCSoftInvalidate` and `SMCChecks=mtrack`. |
| `SMCStoreEmulation` | bool (false) | **Fork** | On a fault from a guest store to an SMC-tracked page, emulate the store via `/proc/self/mem` in the signal handler when the written bytes don't overlap any compiled block, instead of invalidating and re-protecting the page. Removes false-sharing invalidation storms (code and unrelated data sharing a guest page). Stores that do overlap compiled code still fall back to normal invalidation. |
| `SMCSemanticPatch` | bool (false) | **Fork** | Recognizes a guest store that rewrites only the rel32 target of a direct call/jmp/jcc inside an already-compiled block, and patches the compiled block's translated exit target directly instead of invalidating — the page stays protected and the block stays live. Anything else (mov-immediate patches, partial/oversized/ambiguous writes) falls back to the normal path. |
| `SMCStoreBackpatch` | bool (false) | **Fork** | When an SMC fault lands on a decodable host store instruction, rewrites that store site to branch to a generated stub instead of faulting again on every hit. The stub recomputes the effective address, checks a lock-free filter of mtrack-protected pages, and either performs the store natively or routes through the `/proc/self/mem` helper. Removes the ~17 µs signal round-trip that otherwise dominates repeated-fault SMC storms. Requires `SMCStoreEmulation`. |
| `SMCCheapTier` | bool (false) | **Fork** | Compiles blocks on pages that keep getting invalidated with a cheap, disposable tier (small instruction cap, no multiblock) instead of full-quality codegen, since repeatedly-overwritten runtime-codegen pages throw most of that compile work away anyway. |
| `SMCCheapTierThreshold` | uint32 (8) | **Fork** | Number of invalidations of a page before its blocks drop to the cheap tier. Only meaningful with `SMCCheapTier`. |
| `SMCCheapTierMaxInst` | uint32 (500) | **Fork** | Max guest instructions per block in the cheap tier. Only meaningful with `SMCCheapTier`. |
| `SMCMprotectDefer` | bool (false) | **Fork** | Treats a guest `mprotect` that removes `PROT_EXEC` (but adds write) from a tracked page as the real invalidation point rather than invalidating immediately: the page is marked deferred-dirty and left unprotected so guest writes run at full speed, with invalidation actually applied when/if the guest mprotects it back to `PROT_EXEC`. Only sound because the guest cannot execute code through the intermediate non-exec mapping; a W+X mprotect keeps legacy (immediate) behavior. |
| `MonoHacks` | bool (true) | | Upstream option enabling a hook-based SMC approach and smaller JIT blocks specifically for Mono-hosted guests; several of this fork's SMC mechanisms (e.g. `LockOnlyTSO`'s forced-TSO ranges) key off it. |

### Concurrency diagnostics — fork-specific

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
| `StallProcess` | bool (false) | | Stalls the process on startup — useful for attaching a debugger to something that would otherwise crash too fast. |
| `StartupSleep` | uint32 (0) | | Sleeps the process N seconds at startup. |
| `StartupSleepProcName` | str ("") | | Restricts `StartupSleep` to processes whose name matches. |
| `HideHypervisorBit` | bool (false) | | Hides the hypervisor CPUID bit for guests that misbehave when they see it. |
| `X87ReducedPrecision` | bool (false) | | Emulates x87 using 64-bit precision instead of full 80-bit — faster, less accurate, can cause rendering bugs. |
| `NeedsSeccomp` | str→bool (false) | | Disables inline (fast-path) syscalls so seccomp filtering sees every syscall. |

### Logging

| Flag | Type (default) | Description |
|---|---|---|
| `SilentLog` | bool (true) | Disables FEX's own logging output. |
| `OutputLog` | str (server) | Where FEX writes its output: `stderr`, `server`, or a filename. |
| `TelemetryDirectory` | str ("") | Overrides where telemetry data is written (default under the data directory's `Telemetry/`). |
| `ProfileStats` | bool (false) | Enables low-overhead sampling profile statistics; requires a Mangohud build that understands them to view. |
| `EnableGpuvisProfiling` | bool (false) | Enables gpuvis-backend profiling, if FEX was built with it. |

### Misc

| Flag | Type (default) | Description |
|---|---|---|
| `ServerSocketPath` | str ("") | Overrides the FEXServer socket path — mainly for chroot setups. |

## License

ppcFEX is distributed under the same MIT license as upstream FEX-Emu — see [`LICENSE`](LICENSE).
Upstream copyright (Ryan Houdek and the FEX-Emu contributors) is unchanged; this fork's PPC64LE
backend and SMC/memory-model work are additional contributions under the same terms.
