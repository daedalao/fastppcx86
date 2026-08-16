# FEX tunable reference (ppc64le port)

Every knob this build exposes, what it does, and what its default is. Two
separate mechanisms, and they are easy to confuse:

| | Bare `getenv` switches | Config options |
|---|---|---|
| count | 56 | 97 |
| set via | environment only | environment **or** AppConfig JSON |
| spelling | exactly as listed | `FEX_<OPTIONNAME>` |
| tested for | **presence**, mostly — `=0` often still enables | value |
| hashed into the code-cache id | some | most codegen-affecting ones |

⚠ **Most bare switches are presence-tested, not value-tested.** `FEX_FALLTHROUGH=0`
*enables* it. Unset them to turn them off. The exceptions are called out below.

AppConfig lives at **`~/.config/fex-emu/AppConfig/<binary name>.json`** — that is
the *config* directory (`GetConfigDirectory`), not the data directory. Format:

```json
{ "Config": { "SMCChecks": "mtrack", "MaxInst": "50000" } }
```

---

## Triage: hunting a codegen regression

Everything below runs on one binary, no rebuild. Bisect in this order.

```bash
# 1. memset dcbz tier — DEFAULT ON, and the only REP-string path that is.
#    Fires on guest `rep stosb`, which glibc avoids but CoreCLR and Mono
#    emit inline. If managed-runtime titles break and native ones don't,
#    start here.
FEX_MEMSETDCBZ=0

# 2. the 2026-08-16 block-transfer changes, all three
FEX_NOSHIFTIMM32=1 FEX_NOHDRADDI=1 FEX_NOR0ELIDE=1

# 3. r0 invariant, made loud instead of elided (same instruction count)
FEX_R0TRAP=1

# 4. blunt instrument — disables optimisation passes wholesale
FEX_O0=1

# 5. see what is actually happening
FEX_SILENTLOG=0 FEX_OUTPUTLOG=stderr
```

Titles differ in which paths they exercise. Managed runtimes (CoreCLR, Mono)
emit `rep stosb`/`rep movsb` directly in generated code; native C++ titles go
through glibc, which resolves to `__memmove_ssse3` and has no REP path at all.
A change to `DEF_OP(MemSet)` or `DEF_OP(MemCpy)` can therefore break Stardew and
RimWorld while leaving Cyberpunk untouched.

---

## Bare `getenv` switches

### Codegen kill switches
All of these change emitted code. Unless noted, presence-tested.

| Switch | Default | Effect |
|---|---|---|
| `FEX_MEMSETDCBZ` | **ON** | `dcbz` cache-line tier in `rep stosb`. **Value-tested**: `=0` disables. Block size is `HostFeatures.DCacheLineSize` (128 on POWER8). |
| `FEX_MEMCPYDCBZ` | off | Same tier for `rep movsb`. Additionally hard-gated on `!IsHardwareTSOSupported()` — a 63% regression under SAO. **Value-tested.** |
| `FEX_NOSHIFTIMM32` | off | Disables `LoadImm64`'s shifted-32 rule (3 insns instead of 4 for `v<<tz`). |
| `FEX_NOHDRADDI` | off | Restores `LoadImm32`+`subf` for the inline-header delta instead of `addi` / `addis`+`addi`. The two-instruction arm only fires when `Delta > 32768`, i.e. in very large compile units (high `MaxInst`). |
| `FEX_NOR0ELIDE` | off | Always emit `li r0,0` at block exits instead of eliding it in units that never dirty r0. |
| `FEX_R0TRAP` | off | Emit `tdnei r0,0` in place of every *elided* re-zero. Same instruction count, traps if the invariant was ever violated. Release-usable. |
| `FEX_SINKEXITRIP` | off | Sink the exit RIP constant and `std State.rip` below the block-link patch site. Linked exit becomes `[ResetStack] ; [li r0,0] ; b`. Retires the P5.0.1 invariant — see `FEX_RIPFALLBACKTRAP`. |
| `FEX_ZEXTOPT` | on | Dead `clrldi` / 32-bit tail-mask elision. `=0` disables. |
| `FEX_NOXERARITH` | off | Restore the old `mfspr`/`rlwimi`/`mtspr` XER round trips instead of the arithmetic generators. |
| `FEX_NOCONSTCACHE` | off | Disable the last-constant delta cache (`addi` off a still-live constant). |
| `FEX_NOSPLATFUSION` | off | Disable load-and-splat fusion (`lxvdsx` for FMA multiplicands). |
| `FEX_TSOPAIRELIDE` | off | TSO barrier-pair elision. |
| `FEX_FALLTHROUGH` | off | Branch-to-next elision. Measured −4.7% on a tight RMW loop from fetch-group alignment; blocked on loop-top alignment work. |
| `FEX_NO_DFCE_NOWRITE` | off | Disable the DFCE flags-only rewrite (64-bit guests). |
| `FEX_NO_ABI_LIVEMASK` | off | Disable the FABI live-register mask. |
| `FEX_DEADPROLOGUE` | off | `=trap` emits the dead `EmitEntryPoint` prologue behind an unconditional `tw`; `=emit` emits it for real. The methodology for proving a path unreachable. |
| `FEX_ENTRYWATCH` | off | Emit a ring-buffer store at matching entry points. Changes emitted code. |
| `FEX_SPINHINT_ANYLOOP` | off | Widen SMT priority hints to any loop, not just stationary polls. |

### Diagnostics and tripwires
Absorb-by-default behaviours; setting these makes them loud.

| Switch | Effect |
|---|---|
| `FEX_RIPFALLBACKTRAP` | Counts `RestoreRIPFromHostPC` fallbacks taken with an in-code-buffer host PC. Kind 0 = PC outside the block `InlineJITBlockHeader` names — the window `FEX_SINKEXITRIP` would expose. `=1` logs, `=abort` dies on first. |
| `FEX_NOEXEC_ABORT` | Abort on the entry-block NoExec tripwire instead of absorbing. |
| `FEX_EXITLINK_ABORT` | Abort on a suspect `ExitFunctionLink` instead of absorbing. |
| `FEX_EXITLINK_NOBYPASS` | Disable the `ExitFunctionLink` bypass. |
| `FEX_ABORT_TRIPWIRE` | Log every guest-delivered fatal-class sync signal with `si_addr`/`si_code` and the guest RIP. |
| `FEX_TRIPWIRE_PROBE` | Post-mortem probe of memory pointed at by SRA-reconstructed block-entry GPRs. Written for RimWorld's UnityPlayer fault. |
| `FEX_SIGRIPWATCH` | Signals arriving while the guest is in JIT code with static registers live; reports host PC and loop registers. |
| `FEX_SIGFAULTWATCH` | Broader than `SIGRIPWATCH`, which only sees in-JIT arrivals via `SpillSRA`. |
| `FEX_HWTSO_STRICT` | Make a refused `PROT_SAO` range diagnosable instead of silently unordered. **Important**: under `FEX_HWTSO` the JIT emits no barriers, so a refused range has *no ordering at all*. |
| `FEX_SMC_LOOPTRAP` | Trap on a stuck SMC fault address. Note store-emulation / semantic-patch / mono-storm workloads legitimately fault one address hundreds of thousands of times. |
| `FEX_SMC_AUDIT` | Compile-side SMC logger, `O_APPEND` alongside the syscall-side one. |
| `FEX_BUFSTATS` | Code-buffer rotation log, written as it goes so a SIGKILLed Proton session still leaves it. |
| `FEX_LOG_UNEXPECTED_FUTEX` | Log futex returns glibc treats as fatal (the "unexpected error code" panic). |

### Tracing
Two-stage arming where noted: set the var, then `touch` the trigger file.

| Switch | Effect |
|---|---|
| `FEX_SIGTRACE` | Raw `write()` trace of signal delivery / defer / drain / sigreturn. |
| `FEX_TRACE_SIGNALS` | Signal tracing (cheap fast path; no output when unset). |
| `FEX_TRACE_CLONE` | Clone tracing, same discipline. |
| `FEX_FUTEX_TRACE` | `=1`, then `touch /tmp/ftx_on` to start, `rm` to stop. Logs every futex call with tid. Armable mid-run once a wedge is established. |
| `FEX_NTSYNC_TRACE` | `=1`, then `touch /tmp/nts_on`. Logs to `/tmp/nts.<pid>.log`. |
| `FEX_A32_TRACE` | 32-bit allocator: no-hint allocation failures and `EEXIST` collision recoveries. |
| `FEX_DECODEDUMP` | FEX's own decoded view of guest instructions in a range — mnemonic, operand shape, REX flags. |
| `FEX_SPINCOLLAPSE_TRACE` | Trace spin-collapse pattern matches. |

### Behaviour / compatibility
| Switch | Effect |
|---|---|
| `FEX_MONO_DETECT` | **Default on.** Gates the statically-linked-Mono fallback signal (`mscorlib.dll` / `machine.config` opens). |
| `FEX_FORCE_MONO_DETECT` | Unconditionally treat the main executable as the Mono runtime, bypassing both dynamic-library and data-file signals. |
| `FEX_NO_GUEST_SA_RESTART` | Disable guest `SA_RESTART` syscall restarting. |
| `FEX_SA_RESTART_TIMED` | Restart behaviour for timed syscalls. |
| `FEX_FUTEX_EINTR_PASSTHRU` | Escape hatch: restore always-surface `EINTR` on futex. |
| `FEX_FUTEX_RESCUE` | Futex wedge rescue path. |
| `FEX_NO_THUNK_PARTIAL_FILL` | Disable partial thunk fill. Presence-tested — `=0` enables it. |

### Paths and test hooks
`FEX_APP_CONFIG`, `FEX_APP_CONFIG_LOCATION`, `FEX_APP_DATA_LOCATION`,
`FEX_APP_CACHE_LOCATION`, `FEX_PORTABLE`, `FEX_PROFILE_TARGET_NAME`,
`FEX_PROFILE_TARGET_PATH`, `FEX_PROFILE_WAIT_FOR_FORK`,
`FEX_TEST_HOSTOWNED_ADD` (test hook: extra host-owned ranges, `<hex>-<hex>[,...]`).

---

## Config options

Settable as `FEX_<NAME>` in the environment or by name in an AppConfig JSON.
Descriptions below are generated verbatim from `Config.json.in`.

### `FEX_ADDITIONALARGUMENTS`
`strarray` · default ``

Allows the user to pass additional arguments to the application

### `FEX_APP_CONFIG_NAME`
`str` · default ``

This is the application config name that has been loaded. This differs from APP_FILENAME in two
ways Where APP_FILENAME always points to the executable path that FEX-Emu is executing. This
matches what is used to load the AppLayer configuration name. When running through a
compatibility layer like wine, this will only be the exe name, instead of wine full path.

### `FEX_APP_FILENAME`
`str` · default ``

_(no description in Config.json.in)_

### `FEX_BLOCKJITNAMING`
`bool` · default `false`

Uses JITSymbols to name JIT symbols Useful for determining hot blocks of code Has some file
writing overhead per JIT block

### `FEX_BLOCKLINKING`
`bool` · default `true`

PPC64LE: backpatch constant-target JUMP block exits into direct branches to the destination
block (block linking), skipping the inlined L1 probe on subsequent executions. Call, return and
register-indirect exits keep the inlined L1 probe regardless. Ignored (forced off) while
EnableCodeCachingWIP is set: link thunk records embed absolute host addresses as data inside the
code stream, which would be serialized by the code cache and reloaded stale at a different base.
Default on: cleared by the 2026-08-03 real-workload regression set (probe_thread_spawn 0/30 +
0/30, ctest 7024/7024, Factorio oil-refinery ×5, FTL, stress-ng, OpenSSL 128-thread 162/162,
Dex, Steam-in-Proton), all run with FEX_BLOCKLINKING=1 for the entire cycle.

### `FEX_CODECACHESCOPE`
`str` · default `off`

Which guest files the code cache subsystem may write caches for at runtime. EnableCodeCachingWIP
remains the master switch: with it off nothing is loaded or written regardless of this value.
off (default): legacy behaviour. Caches are LOADED for any file, but never written by the
running process -- only FEXOfflineCompiler produces them. rootfs: load and write caches only for
files whose resolved path lies under the configured RootFS. These are system libraries:
immutable in practice and shared between titles, so their translations are the ones worth
keeping across runs. all: additionally load and write caches for game-side native libraries and
the main executable. Any value other than off makes the process a cache *generator*: FEX keeps
FEX relocations and decodes section-bounded for every block, which costs memory and forbids
cross-file multiblock. Unrecognised values are treated as off. NOTE: EnableCodeCacheValidation
only applies to caches produced by FEXOfflineCompiler. It recompiles in ascending guest order,
while a runtime-generated cache is laid out in execution order, so the two legitimately differ
and validation will report a mismatch.

### `FEX_CPUFEATUREREGISTERS`
`str` · default ``

Allows overriding cpu feature flags for manual testing

### `FEX_DISABLE_VIXL_INDIRECT_RUNTIME_CALLS`
`bool` · default `true`

This option is used for the InstructionCountCI so it can generate the same codegen between Arm64
hosts and vixl simulator hosts. Vixl simulator indirect runtime calls are a special hlt
instruction with metadata after it. Effectively making a custom call instruction. With visual
simulator calls disabled, the code generation would be the same as on a native Arm64 host, but
running the code is broken.

### `FEX_DISABLECMPBRANCHFUSION`
`bool` · default `false`

Kill switch for the CompareBranchFusion IR pass (FEX_DISABLECMPBRANCHFUSION=1 turns the pass
OFF). x86 'cmp a,b; jcc' arrives as SubWithFlags + a FromNZCV CondJump, and the PPC64LE lowering
of that branch has to rebuild C/V out of XER (mfxer + rlwinm + mtocrf + a cr-logical composite
before the bc); mfxer serialises on POWER8 and this sits on every hot loop backedge. The pass
rewrites the branch into the backend's existing direct-compare form (cmp into cr7 + bc) when the
NZCV it reads provably comes from a SubWithFlags earlier in the same block, letting
DeadFlagCalculationElimination then drop the flag computation. Only the ten register-comparable
conditions are fused (EQ/NEQ/UGE/ULT/UGT/ULE/SGE/SLT/SGT/SLE); MI/PL and VS/VC are excluded
because the compare form cannot reproduce N-alone or V. A mis-fused branch is a wrong-direction
conditional jump -- silent and data-dependent -- hence a field kill switch of its own.

### `FEX_DISABLEDFCE`
`bool` · default `false`

Kill switch for the DeadFlagCalculationElimination IR pass (FEX_DISABLEDFCE=1 turns the pass
OFF). The pass rewrites flag-producing IR ops in place (e.g. AdcWithFlags -> Adc) when their
flag writes are provably dead, and folds SubNZCV/AXFlag compares into the following CondJump. It
was disabled on PPC64LE from 2026-05-11 to 2026-08-05 because of two reproducers (32-bit ld.so
_dl_sort_maps_dfs 'rpo_head == rpo'; bash setup_variables SEGV on a stale base register) that
were later traced to a missing !HasSideEffects() guard at the pass's Remove site. Because a
wrong flag elimination shows up as a wrong conditional branch -- silent and data-dependent --
this knob exists so the pass can be turned off in the field without a rebuild. Unlike FEX_O0
this affects only this one pass; X87StackOptimization and the rest of the default pass set stay
enabled.

### `FEX_DISABLEDFCESTOREELIM`
`bool` · default `false`

Kill switch for the Remove arm of DeadFlagCalculationElimination (FEX_DISABLEDFCESTOREELIM=1
turns it OFF; the rest of the pass stays on). HISTORY: briefly default-off on 2026-08-12 after a
differential probe (alias_probe.c, native checksum 7a09edb86a169f26) showed wrong seto output
after adc r,r. Root cause was NOT this arm: it was the Adc/Sbb/AdcZero-WithFlags i32 lowerings
reading their sources for the OF computation AFTER writing Dst -- the arm's store elimination
merely let the RA coalesce Dst onto a source (adc eax,eax -> Dst==S1==S2), exposing the latent
aliasing bug. Fixed in the same-day ALUOps commit; the probe is green with the arm on since. The
arm deletes side-effecting flag writers (StorePF/StoreAF/StoreNZCV/ShiftFlags/TestNZ/...) whose
written flags are dead per the pass's converged cross-block liveness and whose SSA result is
unused. Enabled by default because variable-shift/parity flag chains that stay dead-but-emitted
dominate hot decompressor loops on PPC64LE, where NZCV lives in CR0/XER and every survived write
costs an mfocrf/mfxer/rlwimi packing storm. A wrong elimination surfaces as wrong flags/branches
-- silent and data-dependent -- hence the field kill switch.

### `FEX_DISABLEL2CACHE`
`bool` · default `true`

Disables FEXCore's JIT L2 cache lookup. Saving memory. Can potentially introduce more stutters.

### `FEX_DISABLESCALARSPLATCHAIN`
`bool` · default `true`

Kill switch for the ScalarSplatChain IR pass (FEX_DISABLESCALARSPLATCHAIN=0 opts IN; the pass is
OFF by default). DEFAULT OFF 2026-08-11: the superseded-store rule is unsound under mid-block
fault resume. A guest fault inside a marked chain (Witcher 3 save-load = SMC fault storm) spills
the splat-form register, resumes at the fault RIP in a fresh block, and the superseding store of
the ORIGINAL block never runs -- the splatted upper elements become architectural state and
propagate (two reproducible save-load crashes; clean with the pass off). Sound rescue paths are
documented in the pass header; do not re-enable by default without solving mid-block re-entry. A
guest scalar-SSE float chain (movss; subss; mulss; movss) becomes a chain of VF*ScalarInsert
ops, each of which the PPC64LE backend lowers as splat(Vector1) + splat(Vector2) + one xv*sp + a
two-instruction lane-0 merge -- and the next link then splats the merged value straight back
apart. Since xv*sp over two splatted operands yields an already-splatted result, both the merge
and the consumer's re-splat are dead work whenever nothing observes the upper elements. The pass
proves that (every use is another ScalarInsert of the same element size, a narrow FPR store, or
a guest-XMM writeback that a later one in the block supersedes) and sets the SplatResult /
SplatElementSize permission bits the backend then honours, taking a chain-internal scalar op
down to one or two instructions. It has to model the frontend's per-instruction register-cache
flush to see the chains at all, since every guest XMM def is written back and re-read rather
than forwarded along an SSA edge. ACCEPTED IMPRECISION: a splat may be live in a guest XMM's
static register between two guest instructions inside a block, so a signal taken there delivers
a frame whose XMM UPPER elements read as the replicated element 0. Element 0 itself, every GPR,
and all state at block boundaries and across syscalls/thunks stay exact. Setting this to 1
restores exact upper elements everywhere. The bits are permissions, so mis-marking does not
crash -- it silently leaves the splat where architectural upper elements belong, which is
exactly the kind of data-dependent corruption that wants a field kill switch of its own.

### `FEX_DISABLESPINLOOPHINT`
`bool` · default `false`

Kill switch for spin-loop SMT priority hints in the PPC64LE JIT (FEX_DISABLESPINLOOPHINT=1 turns
them OFF). The backend detects tiny memory-polling loops (<=3 blocks, no
stores/atomics/syscalls, at least one memory load) and emits POWER thread-priority nops: `or
r31,r31,r31` (very low) on the spin backedge, `or r2,r2,r2` (medium, the default) on every loop-
exit edge plus a safety net at the dispatcher loop top. A spinning guest thread then donates its
SMT sibling's dispatch bandwidth instead of stealing it -- measured motivation: one iteration-
counted spin block was 25% of ALL CP2077 CPU across 19 redDispatcher workers, starving same-core
audio threads (see cp2077-reddispatcher-spin-anatomy). The hints are architecturally nops, so
misdetection cannot change program semantics -- worst case is a priority dip in a loop that was
about to do real work.

### `FEX_DISABLETELEMETRY`
`bool` · default `false`

Disables telemetry at runtime. Useful for CI instcountCI mostly

### `FEX_DISASSEMBLE`
`strenum` · default `Disassemble::OFF`

Allows controlling of the vixl disassembler for generated ARM code. off: No disassembly will be
output dispatcher: Will enable disassembly of the JIT dispatcher loop blocks: Will enable
disassembly of the translated instruction code blocks stats: Will print stats when disassembling
the code

### `FEX_DUMPGPRS`
`bool` · default `false`

When the test harness ends, print the GPR state.

### `FEX_DUMPIR`
`str` · default `no`

Folder to dump the IR in to. [no, stdout, stderr, server, <Folder>]

### `FEX_DYNAMICL1CACHE`
`bool` · default `false`

Switches FEXCore's JIT L1 cache to be dynamically sized. Saving memory. Can potentially
introduce more stutters. Default OFF on this ppc64le port (2026-08-05): an L1 miss costs a
~62-insn spill + 2 locks + ~63-insn fill here, every resize flushes the entire 16MiB table cold,
and the 250/50-per-second thresholds oscillate under Mono/Unity code footprints. A Ziggurat load
profile put the miss path (ExitFunctionLink->FindBlock) at 4.1% of CPU. Static sizing also lets
the JIT emit a constant-mask L1 probe (rldic) instead of loading L1Mask per block exit. The
table is lazily faulted with THP, so full size costs virtual space only.

### `FEX_DYNAMICL1CACHEDECREASECOUNTHEURISTIC`
`uint64` · default `50`

Threshold of lookups per second that the L1 dynamic cache should decrease its size. The higher
the number, the more aggressively it reduces the L1 cache size. Lower numbers means more
conservative memory savings. Can potentially introduce more stutters, more likely the higher the
number. Don't have this number larger than the increase count!

### `FEX_DYNAMICL1CACHEINCREASECOUNTHEURISTIC`
`uint64` · default `250`

Threshold of lookups per second that the L1 dynamic cache should increase its size. Lower
numbers means more aggressive scaling upward to the maximum size. Higher numbers means more
conservative scaling, using less memory. Can potentially introduce stutters, more likely the
higher the number. Don't have this number smaller than the decrease count!

### `FEX_ENABLECODECACHEVALIDATION`
`bool` · default `false`

Enable expensive validation when loading code caches

### `FEX_ENABLECODECACHINGWIP`
`bool` · default `false`

Enable the code caching subsystem

### `FEX_ENABLEGPUVISPROFILING`
`bool` · default `false`

Enables profiling when FEX was built with the gpuvis profiler backend.

### `FEX_ENV`
`strarray` · default ``

Adds an environment variable to the emulated environment.

### `FEX_EXTENDEDVOLATILEMETADATA`
`str` · default ``

Configuration provided volatile metadata. Only implemented for WoW64/arm64ec. Limited in its use
but can be handy. Extends on top of what Microsoft has for volatile metadata, but also supported
for WoW64. Colon delimited modules, then semi-colon delimited instructions, then comma delimited
ranges Default disables TSO in the module, unless instructions overlap the range
<module>;<offset begin>-<offset-end>,...;<instruction offset to force TSO>,...:<another>
examples: * Disable TSO for a full module: Just provide the module name: `hl2_linux` * Disable
TSO for a part of the module: `hl2_linux;<offset begin>-<offset-end>` * Disable TSO for a part
of the module, but enable TSO for some instructions within the module `hl2_linux;<offset
begin>-<offset-end>;<instruction offset>,<instruction offset>` * Disable TSO for multiple
modules `hl2_linux:libsdl2.so`

### `FEX_FORCESVEWIDTH`
`uint32` · default `0`

Allows overriding the SVE width in the vixl simulator. Useful as a debugging feature.

### `FEX_FORCETSODISPLACEMENTS`
`str` · default ``

Extra guest displacements (comma-separated, e.g. 0x70,0x74,0x78) added to the built-in
Unity-2015+ set (0x80,0x84,0xC0,0xC4) that MonoHacks force-orders for plain MOV loads/stores.
The built-in numbers came from upstream's ARM64 work on Unity's SPSC ringbuffer; older engine
versions place the same fields at different offsets — supply a title's own special numbers here
(census table in docs/MONO_UNITY_CENSUS.md). Only active when MonoHacks is active.

### `FEX_FUTEXMITIGATE`
`bool` · default `false`

Companion to SyscallObserve. When set AND a futex EAGAIN-storm is detected for the current
thread, emit sched_yield() before returning to guest. Lets a competing waker thread make
progress, breaking userspace mutex livelock that PPC64LE weak memory ordering can induce when
the guest expects x86-TSO visibility. Inert when SyscallObserve is false.

### `FEX_GDBSERVER`
`bool` · default `false`

Enables the GDB server.

### `FEX_GDBSYMBOLS`
`bool` · default `false`

Integrates with GDB using the JIT interface. Needs the fex jit loader in GDB, which can be
loaded via `jit-reader-load libFEXGDBReader.so.` Also needs x86_64-linux-gnu-objdump in PATH.
Can be very slow.

### `FEX_GLOBALJITNAMING`
`bool` · default `false`

Uses JITSymbols to name all JIT state as one symbol Useful for querying how much time is spent
inside of the JIT Profiling tools will show JIT time as FEXJIT

### `FEX_HALFBARRIERTSOENABLED`
`bool` · default `true`

When TSO emulation is enabled, controls if unaligned loads and stores should be backpatched to
half-barrier atomics. Can be dangerous due to aligned loadstores through the same code now
become non-atomic.

### `FEX_HIDEHYBRID`
`bool` · default `true`

Hides hybrid CPU core arrangement.

### `FEX_HIDEHYPERVISORBIT`
`bool` · default `false`

Hides the hypervisor CPUID bit when set. Should only be used for applications that have issues
with this set.

### `FEX_HOSTENV`
`strarray` · default ``

Adds an environment variable to the host environment. This can be useful for setting environment
variables that thunks can pick up. Typically isn't necessary since the guest libc isn't thunked.
But is possible.

### `FEX_HOSTFEATURES`
`strenum` · default `HostFeatures::OFF`

Allows controlling of the CPU features in the JIT. off: Default CPU features queried from CPU
features {enable,disable}sve: Will force enable or disable sve even if the host doesn't support
it {enable,disable}avx: Will force enable or disable avx even if the host doesn't support it
{enable,disable}afp: Will force enable or disable afp even if the host doesn't support it
{enable,disable}lrcpc: Will force enable or disable lrcpc even if the host doesn't support it
{enable,disable}lrcpc2: Will force enable or disable lrcpc2 even if the host doesn't support it
{enable,disable}cssc: Will force enable or disable cssc even if the host doesn't support it
{enable,disable}pmull128: Will force enable or disable pmull128 even if the host doesn't support
it {enable,disable}rng: Will force enable or disable rng even if the host doesn't support it
{enable,disable}clzero: Will force enable or disable clzero even if the host doesn't support it
{enable,disable}atomics: Will force enable or disable ARMv8.1 LSE atomics even if the host
doesn't support it {enable,disable}fcma: Will force enable or disable fcma even if the host
doesn't support it {enable,disable}flagm: Will force enable or disable flagm even if the host
doesn't support it {enable,disable}flagm2: Will force enable or disable flagm2 even if the host
doesn't support it {enable,disable}crypto: Will force enable or disable crypto extensions even
if the host doesn't support it {enable,disable}rpres: Will force enable or disable rpres even if
the host doesn't support it {enable,disable}svebitperm: Will force enable or disable svebitperm
even if the host doesn't support it {enable,disable}preserveallabi: Will force enable or disable
preserve_all abi even if the host doesn't support it {enable,disable}wfxt: Will force enable or
disable wfxt even if the host doesn't support it {enable,disable}3dnow: Will force enable or
disable 3DNow! even if the host doesn't support it {enable,disable}sse4a: Will force enable or
disable SSE4a even if the host doesn't support it {enable,disable}mops: Will force enable or
disable FEAT_MOPS even if the host doesn't support it

### `FEX_HWTSO`
`bool` · default `false`

ppc64le: hardware TSO via PROT_SAO (Strong Access Ordering) pages instead of per-access barrier
emulation. When enabled and the kernel accepts PROT_SAO (probed at startup), every guest-visible
mapping is created with SAO and the JIT stops emitting TSO IR ops entirely (scalar, vector and
memcpy barriers all vanish). SOUND, unlike LockOnlyTSO: SAO pages are hardware-TSO — the MP
litmus that fires ~1.2%/round on plain POWER8 pages showed 0 violations in 16.3M rounds on SAO
pages (notes/tools/sao_litmus.c, 2026-08-13). If the kernel rejects PROT_SAO (radix MMU, missing
CPU feature) FEX warns once and falls back to barrier emulation. Inert when off or when
TSOEnabled is false.

### `FEX_INJECTLIBSEGFAULT`
`bool` · default `false`

Sets the environment variable LD_PRELOAD=libSegFault.so This allows the user to very easily
enable libSegFault without dealing with environment variables Very useful for applications that
have launch scripts that set the variable to nothing at launch Set this in an application
configuration for injecting in to only specific applications. Note: If x86/x86_64 libSegFault.so
isn't installed then this option won't work.

### `FEX_INTERPRETER_INSTALLED`
`bool` · default `false`

_(no description in Config.json.in)_

### `FEX_IS64BIT_MODE`
`bool` · default `false`

_(no description in Config.json.in)_

### `FEX_JITOPSIZEPROFILE`
`bool` · default `false`

PPC64LE only: measure how many host bytes each IR op expands to. Accumulates count/total/max
host bytes per IROps enum value and periodically rewrites /tmp/fex-jit-opsize-<pid>.txt. Used to
validate the JIT's kMaxHostBytesPerIROp code-buffer reserve. Grep the dump for IROP_OVER_BUDGET
and BLOCK_BUDGET.

### `FEX_KERNELUNALIGNEDATOMICBACKPATCHING`
`bool` · default `true`

When the kernel unaligned atomic handler is enabled, use backpatching to reduce kernel context
switches.

### `FEX_LIBRARYJITNAMING`
`bool` · default `false`

Uses JITSymbols to name JIT symbols grouped by library Useful for querying how much time is
spent in each guest library Can be used to help guide thunk generation

### `FEX_LOCKONLYTSO`
`bool` · default `false`

Opt-in: when TSOEnabled is also true, restrict TSO acquire/release emission to x86 instructions
carrying FLAG_LOCK (LOCK CMPXCHG, LOCK XADD, implicit-LOCK XCHG-mem, etc.) plus any
FLAG_FORCE_TSO ranges from MonoHacks.  Plain MOV reg,[mem] uses the cheap LoadMem path instead
of LoadMemTSO.  Designed for weakly-ordered hosts (PPC64LE) where the per-load acquire dance is
microarchitecturally cheap but cumulatively dominates runtime in libc / pthread tight loops.
UNSOUND, and measured so: the MP litmus shape (forbidden on x86) fired 659, 12 and 51 times per
30000 rounds with this enabled and 0 times in 150000 rounds with it disabled, same guest binary.
Only LOCK ops keep TSO; plain loads and stores lose their barriers, so lock-free or volatile-
based guest code can silently compute wrong results.  glibc futex / PLT lazy resolve are backed
by LOCK CMPXCHG and stay correct, which is the limit of what is safe here.  FEX warns once at
startup when this is enabled. Inert (no effect) when TSOEnabled is false.

### `FEX_MAXINST`
`int32` · default `5000`

Maximum number of instruction to store in a block

### `FEX_MEMCPYSETTSOENABLED`
`bool` · default `false`

When TSO emulation is enabled, controls if memcpy and memset should also be atomic. Only affects
REP MOVS and REP STOS instructions

### `FEX_MONOHACKS`
`bool` · default `true`

Permits a hook-based SMC approach and smaller JIT blocks when mono is detected.

### `FEX_MULTIBLOCK`
`bool` · default `true`

Controls multiblock code compilation Can cause long JIT compilation times and stutter

### `FEX_NEEDSSECCOMP`
`bool` · default `false`

Disables inline syscalls in order to support seccomp handling

### `FEX_NONTSORBP`
`bool` · default `false`

Opt-in: extend the RSP thread-private-stack TSO exemption to RBP-based accesses. Accesses
addressed through RSP already skip TSO barriers on the assumption that the stack is thread-
private; titles that keep frame pointers address the same stack slots through RBP and pay full
barriers for every local-variable access (all EBP frame chains in 32-bit code). Same soundness
class as the existing RSP exemption: unsound if the guest shares stack memory between threads
and relies on x86-TSO ordering for it. Per-app opt-in, default off.

### `FEX_O0`
`bool` · default `false`

Disables optimizations passes for debugging.

### `FEX_OUTPUTLOG`
`str` · default `server`

File to write FEX output to. [stderr, server, <Filename>]

### `FEX_PASSMANAGERDUMPIR`
`strenum` · default `PassManagerDumpIR::OFF`

Allows controlling when FEX dumps its IR. off: IR dumping will be disabled beforeopt: Dump IR
before any optimizations afteropt: Dump IR after all optimizations beforepass: Dump IR before
every optimization pass afterpass: Dump IR after every optimization pass

### `FEX_PROFILESTATS`
`bool` · default `false`

Enables FEX's low-overhead sampling profile statistics. Requires a supported version of Mangohud
to see the results

### `FEX_REPORTED_CPUS`
`uint32` · default `0`

Overrides the guest-visible CPU count returned by CPUID and sysconf. Zero (default) reports the
real host thread count. Clamped to 1..4096 in Source/Common/CPUInfo.cpp. Useful for guests whose
worker pools scale with the reported count and misbehave at high thread counts.

### `FEX_ROOTFS`
`str` · default ``

Which Root filesystem prefix to use This can be a filesystem path eg: ~/RootFS/Debian_x86_64 Or
this can be a name of a rootfs If the named rootfs exists in the FEX data folder then it will
use that one eg: $XDG_DATA_HOME/fex-emu/RootFS/<RootFS name>/ If XDG_DATA_HOME is unset,
~/.local/share will be used in its place. eg: $HOME/.local/share/fex-emu/RootFS/<RootFS name>/

### `FEX_SCHEDPASSTHROUGH`
`bool` · default `false`

Opt-in. FEX forwards guest sched_setscheduler/sched_setattr to the host verbatim, so an
unprivileged host with no RLIMIT_RTPRIO budget refuses every guest SCHED_FIFO/SCHED_RR request
with EPERM and the guest's audio/render threads run at plain SCHED_OTHER. With this set, an
EPERM'd RT request is retried on the host with progressively weaker boosts: SCHED_RR at the
lowest permitted priority, then a niceness boost to -10 (clamped by RLIMIT_NICE), then give up.
Only real host scheduling changes -- the guest still receives exactly the return value it would
have without this option. Log the ladder with ThreadCensus. Off: no effect.

### `FEX_SERVERSOCKETPATH`
`str` · default ``

Override for a FEXServer socket path. Only useful for chroots.

### `FEX_SHADOWRETSTACK`
`bool` · default `false`

PPC64LE (EXPERIMENTAL, default OFF): maintain a per-thread shadow return-address stack. A guest
CALL exit pushes {guest-return-RIP, host-trampoline} and a guest RET exit pops it, taking a
direct branch to the recorded host code when the popped guest RIP matches the RET target --
skipping the inlined L1 probe on the hot call/ret path. A mismatch, an empty/overflowed stack,
or any invalidation falls back to the L1 probe, which is the correctness net. Reuses the
existing frontend-owned call-ret stack allocation and CPUState.callret_sp. Every code-buffer
rotation/invalidation zeroes the stack (VirtualDontNeed), so a stale host trampoline can never
be reached. Forced OFF under FEX_SMCLAZYINVAL unless FEX_SMCLAZYLINK is also set (same same-
thread stale-hole reasoning as BlockLinking): the RET fast path skips ExitFunctionLink's drain,
and only the LAZYLINK InterruptFaultPage poke at the return block's entry re-closes that window.

### `FEX_SILENTLOG`
`bool` · default `true`

Disables logging

### `FEX_SINGLESTEP`
`bool` · default `false`

Single stepping configuration.

### `FEX_SMALLTSCSCALE`
`bool` · default `true`

Scales the cycle counter on systems that have low frequencies.

### `FEX_SMCCHEAPTIER`
`bool` · default `false`

Compile blocks on repeatedly-invalidated guest pages with a cheap, disposable tier: a small
instruction cap and no multiblock. Runtime code arenas overwrite the same pages dozens of times,
so most of the compile work spent on them is thrown away before it ever pays off.

### `FEX_SMCCHEAPTIERMAXINST`
`uint32` · default `500`

Maximum guest instructions per block in the cheap compile tier. Only meaningful with
SMCCheapTier enabled.

### `FEX_SMCCHEAPTIERTHRESHOLD`
`uint32` · default `8`

Invalidations of a guest page before its blocks drop to the cheap compile tier. Only meaningful
with SMCCheapTier enabled.

### `FEX_SMCCHECKS`
`uint8` · default `CONFIG_SMC_MTRACK`

Checks code for modification before execution. none: No checks mtrack: Page tracking based
invalidation (default) full: Validate code before every run (slow)

### `FEX_SMCFILEIMMUTABLE`
`bool` · default `false`

Relaxed correctness for speed: treat code that came from a private file-backed mapping (Wine
DLLs, libc, an executable's .text) as immutable, and skip installing mtrack write-protection on
it. Such mappings are written at load time (relocations, CoW) before any code is compiled from
them and essentially never after, so the protection mostly buys false-sharing faults on
neighbouring data. Guest mmap/munmap/mprotect still invalidate unconditionally, and an mprotect
that adds PROT_WRITE to a skipped range revokes the assumption for that mapping. Only meaningful
with SMCChecks=mtrack. KNOWN BREAKAGE: in-place patching of file-backed .text through an
already-writable mapping (some DRM/packers, some Mono AOT fixups) goes undetected. Opt in per
application.

### `FEX_SMCLAZYINVAL`
`bool` · default `false`

On an SMC write fault, unprotect the page and record it as dirty but invalidate NOTHING, so the
writer runs at native speed. The recorded pages are soft-invalidated later, at the next drain
point (a thread entering the block compiler, a guest syscall, guest signal delivery, or a guest
mprotect granting PROT_EXEC). Sound for same-thread self-modifying code because SMCLazyScrub (on
by default) forces the writing thread through a drain before its next dispatch; cross-thread
modification stays as unsound as x86 already allows it to be (the reader must serialize, and
every way it can is a drain point). Setting SMCLazyScrub=0 restores the older, faster, unsound
behaviour. Requires SMCSoftInvalidate and SMCChecks=mtrack. Off: no effect.

### `FEX_SMCLAZYLINK`
`bool` · default `false`

Only meaningful with SMCLazyInval=1 + SMCLazyScrub=1. Keep block linking (direct block-to-block
branches) enabled under lazy SMC invalidation instead of hard-disabling it. The same-thread
soundness guarantee normally relies on every block exit re-probing the lookup path; linked exits
skip it, so this option additionally arms the writing thread's InterruptFaultPage at SMC fault
time — the fault- page poke every block entry executes (including entries reached by linked
branches) then faults, and the deferred-drain debt is settled in that handler before any further
translated code runs. Costs one extra mprotect + one extra fault per lazy SMC fault, on the
writer only. Incompatible with SMCSemanticPatch (linking stays off there: a patched exit
immediate does not retarget an already-linked branch).

### `FEX_SMCLAZYSCRUB`
`bool` · default `true`

Only meaningful with SMCLazyInval=1. When an SMC write fault takes the lazy route, scrub the
faulting thread's L1 block-lookup cache and mark that thread as owing a drain, so its very next
dispatch misses every fast path, lands in the lookup slow path, and drains the deferred
invalidations before it can consult the shared L2/L3 caches. This is what makes lazy
invalidation sound for same-thread patch-then-call (smcstorm/patchloop). Set to 0 to measure --
or restore -- the original unsound-but-faster lazy behaviour, in which a thread can execute a
STALE translation of code it just wrote.

### `FEX_SMCMARKMEMO`
`bool` · default `true`

Memoise the no-op case of MarkGuestExecutableRange (FEX_SMCMARKMEMO=0 disables). A 16.5-minute
Witcher 3 SMC audit measured 114K of 120K mark calls as pure no-ops that still took the VMA
mutex on the compile path. The memo answers those lock-free, invalidated wholesale by a VMA-map
generation counter bumped in every mutating funnel. Throughput effect is small (0.4% hit rate on
W3); the knob exists because the mark path contends the VMA mutex with the syscall side, so the
memo's real effect is on hitch/latency tails -- A/B it with stutterwatch (audio zero-runs, hitch
stats), not with perf means.

### `FEX_SMCMPROTECTDEFER`
`bool` · default `false`

Treat guest mprotect as the SMC validation point for W^X code flips. An mprotect that makes a
tracked page writable but NOT executable no longer invalidates: the page is recorded as
deferred-dirty and left unprotected, so the guest's writes run at full speed. The deferred
invalidation is performed when the guest mprotects the page back to PROT_EXEC, before that
syscall returns. Only legal because the guest cannot execute the intermediate, non-PROT_EXEC
protection; a W+X request keeps legacy behaviour.

### `FEX_SMCSEMANTICPATCH`
`bool` · default `false`

SMC Idea 4 (ppc64le): recognise a guest store that overwrites only a patchable immediate inside
an already-compiled block -- the rel32 target of a direct call/jmp/jcc, or the immediate of a
mov r32,imm32 / mov r64,imm64 / C7 /0 reg,imm32. Instead of invalidating, emulate the store and
patch the value baked into the block's translated code (the destination RIP of the exit, or the
tagged constant's fixed-width materialisation window), leaving the page protected and the block
live. Anything else (partial/oversized writes, writes that also change instruction bytes,
ambiguous or non-atomically patchable constants) falls back to the normal path. Off: no effect.

### `FEX_SMCSOFTINVALIDATE`
`bool` · default `false`

SMC v3: on an SMC write fault, soft-invalidate the page's blocks (delink from the lookup caches
and sever inbound block links) while retaining their compiled code and a hash of their guest
source bytes, instead of discarding them. The next dispatch of an affected block re-hashes the
guest bytes and relinks it if unchanged, and only recompiles genuinely modified blocks. Off:
legacy behaviour.

### `FEX_SMCSTOREBACKPATCH`
`bool` · default `false`

ppc64le: when an SMC write fault lands on a decodable host store, rewrite that store site to
branch to a generated stub instead of faulting again. The stub recomputes the effective address,
checks a lock-free filter of mtrack-write-protected pages, and either performs the store
natively or calls a helper that writes through /proc/self/mem when the bytes do not overlap
compiled code. Removes the ~17us signal round trip that dominates the SMC storm cycle. Writes
that DO overlap compiled code keep faulting, and are invalidated exactly as they are today.
Requires SMCStoreEmulation.

### `FEX_SMCSTOREEMULATION`
`bool` · default `false`

ppc64le: emulate faulting guest stores to SMC-tracked pages in the signal handler (via
/proc/self/mem) when the written bytes do not overlap any compiled block, instead of
invalidating and re-protecting the page. Eliminates false-sharing invalidation storms (data and
code on the same guest page). Writes that DO overlap compiled code fall back to the normal
invalidation path.

### `FEX_SPINCOLLAPSE`
`uint32` · default `0`

PPC64LE JIT: batched budget decrement for counted spin-poll loops. 0 (default) disables the
feature entirely; 1 enables it at the default K; 2..1024 enables it at that K; anything larger
falls back to the default K. K corrects the EMULATION INFLATION of a spin iteration rather than
minimizing spinning: the engine tuned its budget for native iteration cost, and an emulated
iteration runs several times slower, so retiring K units per iteration restores the intended
spin duration and lets worker threads park on time. MEASURED 2026-08-15, Cyberpunk 2077
benchmark scene under FEX_HWTSO=1, benchmark-scene frames only: p50 frametime 51.64 -> 32.66ms
(-36.8%), mean -37.5%, p99 ~156 -> 75ms (-52%), scene fps 17.43 -> 27.94 (+60.3%). Seven off
laps against three K=32 laps with no overlap on any metric; an off lap run between two K=32 laps
landed on the historical off baseline, so drift is excluded. Pacing improves MORE than the
average, which is the opposite of the failure mode this was held opt-in for. Still off by
default: that is one title and one scene, and there is a KNOWN SEMANTIC COARSENING -- on the
found-exit the budget register holds a K-granular value instead of the exact iteration count, so
guest code that consumed the leftover count would misbehave. Set it per-title via AppConfig (see
Data/AppConfig/Cyberpunk2077.exe.json).

### `FEX_SPINLOOPCLAMP`
`str` · default ``

Workaround for a guest loop entered with a corrupted induction variable (e.g. the Ziggurat
finalize spin: RBX += 4 exiting only on RBX == R15). Format: 0xBEGIN-0xEND:ind:bound with x86
register names, e.g. 0x551330-0x5515e5:rbx:r15. Every 64-bit register-register CMP between ind
and bound whose guest RIP falls in [BEGIN, END) is compiled with an overshoot clamp: if ind is
unsigned-above bound at the compare, it is forced equal to bound so the equality exit fires
instead of spinning forever. A sane loop never trips the clamp; empty string disables it.

### `FEX_SPINLOOPCLAMPAUTO`
`uint32` · default `0`

Systemic version of SpinLoopClamp: a post-decode pass structurally detects tight loops whose
only exit for a register is exact equality against a loop-invariant register while that register
steps by a positive constant, and compiles their compare with the overshoot clamp automatically
(no RIPs needed). Auto sites clamp only on SIGNED overshoot beyond a 2^30 margin, so negative
inductions and small legitimate overshoots in multi-exit scan loops are never touched;
unclassifiable loops are left alone entirely. 0 (default) = off — opt-in per title; the census
showed most Mono/Unity wedges are not this class, and surgical per-title FEX_SPINLOOPCLAMP
ranges are preferred. 1 = Mono-detected titles only, and only loops in the low (< 4GiB) main-
executable range — the observed wedge class is game-binary text; shared libraries are never
instrumented. 2 = every process, every address (testing/diagnosis).

### `FEX_SPLITLOCKINLINECONTAINED`
`bool` · default `true`

PPC64LE: JIT-inline doubleword-contained misaligned LOCK RMW and CAS ops ((EA & 7) + size <= 8,
2-/4-byte operands) as aligned ldarx/stdcx. container loops instead of routing them through the
mutex-serialized split-lock helper. Crossing and quadword-contained cases still use the helper.
While enabled these ops bypass the helper entirely, so the doubleword-contained split-lock
telemetry counter no longer observes them.

### `FEX_STALLPROCESS`
`bool` · default `false`

Forces a process to stall out on initialization Useful for a process that keeps restarting and
doesn't work

### `FEX_STARTUPSLEEP`
`uint32` · default `0`

Sleeps the process at startup for a duration of seconds. Useful if an application crashes too
quickly to attach a debugger.

### `FEX_STARTUPSLEEPPROCNAME`
`str` · default ``

Contrains the startup sleep to only apply to processes that match this name.

### `FEX_STRICTINPROCESSSPLITLOCKS`
`bool` · default `false`

Strict global lock when handling an unaligned atomic that crosses a 16-byte or cacheline
granularity This is required to ensure a split-lock doesn't tear inside the process

### `FEX_SYSCALLOBSERVE`
`bool` · default `false`

Opt-in: enable the FEX SyscallObserver. Wraps the bare-passthrough implementations of pathology-
prone syscalls (futex, tgkill) with per-thread state tracking and structured log emission. Zero
perf cost when disabled; runtime-toggleable.  Currently provides: - futex EAGAIN-storm detection
(same addr/op/val repeated within a small time window) with an `IFmt` log on first crossing. -
tgkill call logging (cross-thread signal delivery — Mono GC stop-the-world surfaces here).

### `FEX_TELEMETRYDIRECTORY`
`str` · default ``

Redirects the telemetry folder that FEX usually writes to. By default telemetry data is stored
in {$FEX_APP_DATA_LOCATION,{$XDG_DATA_HOME,$HOME}/fex-emu/Telemetry/}

### `FEX_THREADCENSUS`
`str` · default ``

Diagnostic. Path of a plain-text file to append a thread census to. One line per event, written
with a single append per line: <monotonic-ms> tid=<n> event=<type> <key=val>... Events:
thread_create (guest/host TID, parent TID, raw guest RIP of the clone caller, clone flags),
set_name (prctl PR_SET_NAME), sched_setscheduler / sched_setattr / sched_setparam (policy,
priority and what FEX did with the request),  sched_setaffinity (mask popcount plus
lowest/highest set CPU), and sched_boost (the SchedPassthrough ladder). Observation only --
never changes what a guest syscall returns. Unset: the file is never opened and every hook
short-circuits on a single load.

### `FEX_THUNKCONFIG`
`str` · default ``

A json file specifying where to overlay the thunks. This can be a filesystem path eg:
~/MyThunkConfig.json Or this can be a named of a Thunk config file If the named config file
exists in the FEX data folder folder the it will use that one eg: $XDG_DATA_HOME/fex-
emu/ThunkConfigs/<ThunkConfig name> If XDG_DATA_HOME is unset, ~/.local/share will be used in
its place. eg: $HOME/.local/share/fex-emu/ThunkConfigs/<ThunkConfig name>

### `FEX_THUNKGUESTLIBS`
`str` · default `@CMAKE_INSTALL_PREFIX@/share/fex-emu/GuestThunks`

Folder to find the guest-side thunking libraries.

### `FEX_THUNKHOSTLIBS`
`str` · default `@CMAKE_INSTALL_FULL_LIBDIR@/fex-emu/HostThunks`

Folder to find the host-side thunking libraries.

### `FEX_TSOENABLED`
`bool` · default `true`

Controls TSO IR ops. Highly likely to break any multithreaded application if disabled.

### `FEX_VCMPFUSION`
`bool` · default `false`

Fuse the glibc vector-scan idiom -- pcmpeq{b,w,d} ; pmovmskb ; test r32,r32 ; jz/jnz -- into a
single conditional branch driven by a record-form vector compare, so the lane mask never crosses
from the vector unit to a GPR on the loop back edge. This is the inner loop of
strlen/strchr/strcmp/memchr and friends. Only forms when the backend advertises
HostFeatures.SupportsVCmpFlagBranch (ppc64le). The elided PMOVMSKB destination is still
architecturally correct on both edges: it is provably zero on the no-match edge, and is
recomputed on the match edge.  DEFAULT OFF, and the reason is a measurement, not a doubt about
correctness. Before the vbpermq PMOVMSKB lowering landed this was worth 4.6x on an SSE2 strlen
loop (123 -> 12 host instructions). vbpermq independently took the same loop 8.9x faster, and
against THAT baseline the fusion measures 16 -> 13 host instructions but 1.3% slower wall clock,
reproducibly. See docs/VCMPEQ_FUSION_DESIGN.md section 11 for where the 1.3% goes and the
specific change that would most likely recover it. Turn it on to re-measure -- in particular on
POWER8, where the mfvsrd this removes from the loop-carried dependency is costlier than on the
POWER9 the numbers above were taken on.

### `FEX_VECTORTSOENABLED`
`bool` · default `false`

When TSO emulation is enabled, controls if vector loadstores should also be atomic.

### `FEX_VOLATILEMETADATA`
`bool` · default `true`

Use volatile metadata in PE files to inform TSO instructions when available. When metadata is
unavailable falls back to the currently enabled TSO options.

### `FEX_X86DISASSEMBLE`
`bool` · default `false`

Enables x86/x86-64 guest disassembly output for compiled blocks. Requires FEX to be built with
-DENABLE_ZYDIS=TRUE

### `FEX_X87REDUCEDPRECISION`
`bool` · default `false`

Emulates X87 floating point using 64-bit precision. This reduces emulation accuracy and may
result in rendering bugs.

