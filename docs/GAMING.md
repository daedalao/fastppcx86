# Running games

This is the practical guide: what a POWER8/POWER9 box needs before it can run an x86 game, what a
launch command should look like, which knobs are worth setting per title, and where the output
goes when something breaks. Flag semantics are in the [flags reference](../README.md#flags-reference).

Binaries and environment variables keep the historical `FEX` prefix. `FEX` is the emulator,
`FEXBash` runs a shell inside the guest rootfs, `FEXServer` is the background helper that owns the
rootfs mount and the log socket.

## The launcher

`ppcx86-launch` is the normal way to run a title, and `ppcx86-launch-tui` is the same launcher in a
terminal for when you are on ssh with no display. Everything below this section is still correct and
still worth reading — the launcher does not hide it, it performs it and shows you what it did.

What it takes care of, all of which is otherwise manual:

- Finds installed games, emulator builds, RootFS images, thunk sets, Proton, Wine, DXVK and
  VKD3D-Proton, and lets you add anything it missed. Every one of those is a list you can extend,
  and any of them can be chosen per title.
- Derives the CPU cage from this machine's live topology — one NUMA node, N cores, two threads per
  core — instead of a hardcoded CPU list. It recomputes on every launch, because `ppc64_cpu --smt=N`
  changes which CPUs are online without renumbering them.
- Sets `FEX_BIN` and `FEXBASH` together from one choice, so the failure described under
  [Steam](#steam) — a new build in one and the old build in the other — cannot happen.
- Forces the XCB window-system environment and resolves `DISPLAY`/`XAUTHORITY`, including the
  per-boot xauth filename.
- Arms `FEX_SMCCHECKS` explicitly whenever an SMC recipe is set, which is what stops a stale
  AppConfig from silently disarming it.

Two views are worth knowing about:

- **Command** shows the exact command the launch runs, generated from the same call that performs
  it. Copy it to reproduce a run in a terminal or to attach to a bug report.
- **Verify** reads the `FEX_*` environment back off the live process and compares it with what was
  asked for, and flags a `/proc/<pid>/exe` that has become `(deleted)`. That is the
  [troubleshooting](#troubleshooting) ritual below, performed for you — worth using any time a flag
  appears to have done nothing.

Non-interactive modes, which go through the same code as the GUI:

```sh
ppcx86-launch --list             # configured titles
ppcx86-launch --print <id>       # the exact command, without running it
ppcx86-launch --launch <id>      # run it and stream the output
ppcx86-launch --paths            # every configured location, and whether it is usable
ppcx86-launch --cage             # this host's topology and the cage it produces
ppcx86-launch --recipes          # the tuning recipes and knobs, with the reasoning
```

Titles, locations and per-title tuning live in `$XDG_CONFIG_HOME/fex-emu/Launcher/Titles.json`.
Paths are stored exactly as typed, with `~` and `$VARS` expanded only when used, so that file
survives being copied to another machine.

## Prerequisites

**A 4K-page kernel.** The self-modifying-code tracker (`SMCChecks=mtrack`, the default)
write-protects guest pages at a fixed 4K granularity, matching the `AT_PAGESZ=4096` the guest is
told. On a host booted with 64K pages, mtrack misbehaves or aborts. Boot a 4K kernel, or run
everything with `FEX_SMCCHECKS=full`, which validates code before every run and is much slower.
Check with `getconf PAGESIZE`.

**An x86-64 root filesystem.** Everything the guest links against (glibc, SDL, libX11, Mesa's
guest-side stubs) comes from the rootfs, not from the host. `FEXRootFSFetcher` downloads a
prebuilt image, or point `FEX_ROOTFS` at a directory you populated yourself. Games that ship their
own bundled libraries still need the rootfs for libc.

**Thunk libraries, if you want working graphics.** Build with `-DBUILD_THUNKS=ON` so guest OpenGL
and Vulkan calls land in the host's driver instead of being emulated instruction by instruction.
Thunks are enabled per library in the `ThunksDB` block of `Config.json`. 32-bit games need both
halves of the 32-bit pair: `BUILD_THUNKS_32BIT` (on by default) for the host side, and
`BUILD_GUEST_THUNKS_32` with `X86_DEV_ROOTFS_32` pointed at a multilib x86 sysroot for the guest
stubs. Without the guest half, 32-bit titles fall back to the emulated libraries in the rootfs.

**An X display.** XCB is the only working window-system integration for an x86 guest on a PPC64LE
host; the Wayland and Xlib paths break on cross-architecture guest-callback dispatch. Launch under
Xorg or Xwayland and push everything onto X11:

```sh
unset WAYLAND_DISPLAY WAYLAND_SOCKET
export SDL_VIDEODRIVER=x11 GDK_BACKEND=x11 QT_QPA_PLATFORM=xcb
export VK_USE_PLATFORM_XCB_KHR=1
```

If you launch over ssh rather than from a terminal inside the session, `DISPLAY` and `XAUTHORITY`
will not be inherited. Set both. The xauth filename changes on every boot, so resolve it rather
than hardcoding it:

```sh
export DISPLAY=:0
export XAUTHORITY=$(ls -t "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"/xauth_* | head -1)
```

A stale `XAUTHORITY` fails late, after the guest has started and linked, with "Unable to open
display", which reads like a graphics bug and is not one.

## The CPU cage

**Launch Mono/Unity titles under `taskset`.** This is not tuning; without it several titles are
unplayable.

Unity sizes its worker and job pools from the CPU count the guest reports. On an 80-thread POWER8
an uncaged guest builds a pool of about 79 workers, and the pool's park gate is a check that no
worker is currently inside the steal window. At that oversubscription the gate is never satisfied
(occupancy was measured between 20 and 51 across 13000 samples and never reached zero), so the
pool spins instead of parking, saturating the machine while the game crawls. Hard West ran at
roughly 2 fps this way. The cage fixes it by shrinking the pool: since commit `9a0f8e1be` the
emulated `/proc/cpuinfo` is bounded by the process affinity mask, so a caged process reports the
caged count and Unity sizes its pools accordingly.

POWER8 and POWER9 number online CPUs sparsely. In SMT4 the online set looks like `0-3,8-11,...`,
one group of four per core, so list explicit threads rather than a range.

Two threads per core, eight cores:

```sh
taskset -c 0-1,8-9,16-17,24-25,32-33,40-41,48-49,56-57 FEX /path/to/Game.x86_64
```

One thread per core trades parallelism for single-thread throughput, and is worth trying on any
title that is main-thread-bound:

```sh
taskset -c 0,8,16,24,32,40,48,56 FEX /path/to/Game.x86_64
```

The census runs that first got RimWorld through worldgen to a live colony used a two-thread-per-core
cage of this shape. Start there and widen only if a title is visibly starved.

`FEX_REPORTED_CPUS=N` sets the guest-visible count directly, independent of the cage. Use it when
you want a small pool but a wide affinity mask, or on a build older than `9a0f8e1be`.

## SMC recipes

Guests that generate code at runtime, which is every Mono or .NET title, write to pages the emulator has
translated. The tracker faults on those writes and throws away the affected translations. How
aggressively it does that is a per-title tradeoff, and the recipes below are the combinations
worth trying. All of them require `FEX_SMCCHECKS=mtrack`.

**Legacy.** No extra flags. Every write to a tracked page invalidates and recompiles. Correct,
and the baseline everything else is measured against.

```sh
FEX_SMCCHECKS=mtrack
```

**Strict.** Keeps the compiled code and a hash of the bytes it came from instead of discarding it,
and relinks on the next dispatch if the bytes turn out to be unchanged. Only genuinely modified
blocks recompile. Fully correct, modest gains.

```sh
FEX_SMCCHECKS=mtrack FEX_SMCSOFTINVALIDATE=1
```

**Semantic patching.** Adds recognition of writes that only rewrite a branch target or an
immediate inside an already-compiled block; those are patched into the translated code directly
and the block stays live. Best guess for Mono, .NET and other scripting-JIT titles. Also treats
private file-backed code as immutable, which skips write-protection on library text.

```sh
FEX_SMCCHECKS=mtrack FEX_SMCSOFTINVALIDATE=1 FEX_SMCSEMANTICPATCH=1 FEX_SMCFILEIMMUTABLE=1
```

**Lazy.** Defers invalidation instead of doing it at the fault, so the writing thread runs at full
speed and the work happens at the next point where the guest must serialize anyway. Best for
titles whose code generation is cross-thread heavy. Sound by default: `SMCLazyScrub` (on) makes
the writing thread take the slow dispatch path so it cannot reach a stale translation of code it
just wrote. Setting `FEX_SMCLAZYSCRUB=0` restores older, faster, deliberately unsound behaviour
and is for A/B measurement only.

```sh
FEX_SMCCHECKS=mtrack FEX_SMCSOFTINVALIDATE=1 FEX_SMCLAZYINVAL=1 FEX_SMCFILEIMMUTABLE=1
```

Pair lazy with `FEX_SMCLAZYLINK=1`. Without it, lazy invalidation turns off block-to-block linking,
and in Moonlighter combat profiling `ExitFunctionLink` became the hottest symbol at 7.3%; with
lazy linking it drops to 0.10%, and the improvement scales with the number of on-screen entities.

The recipes stack, and everything at once is a valid experiment, but each piece has far more
mileage individually than the full combination does. Prefer semantic patching or lazy.

Profile before assuming a recipe is the answer. A flat guest profile means raw emulated throughput
is the limit and no SMC recipe will move it; Moonlighter's frame rate, for one, is bound by entity
count, not by invalidation.

## Per-title knobs worth setting

These are the ones that earned their place in real sessions.

`FEX_HOSTFEATURES=enableavx` re-advertises AVX to the guest. **AVX is hidden by default on this
port**, so guests pick their SSE paths. POWER's vector units are 128-bit and the dispatcher
decomposes every 256-bit YMM op into a pair of 128-bit ops plus high-half spill traffic, which
costs more than the guest gains: glibc string routines measured 36 to 67% faster on their SSE
paths, and a driven Witcher 3 capture burned 16% less CPU with AVX hidden.

Turn it on for the titles that need it. Moonlighter measured faster with it on.
`FEX_HOSTFEATURES=disableavx` forces it back off if a config layer enabled it.

**Witcher 3 needs it to load, and that is why `witcher3.exe.json` sets it.** Confirmed 2026-08-15:
with `enableavx` removed and everything else identical, W3 crashes loading a save that loads fine
with it on. So the `-16%` CPU figure above is a cost knowingly paid for the title to run, not a
tuning mistake — do not "fix" that config by deleting the line. An A/B of AVX on this title is not
merely noisy, it is not runnable: one arm never reaches the measurement.

The general shape is worth internalising: on this port AVX is sometimes a FUNCTIONAL requirement
rather than a performance choice, so a per-title `enableavx` may be paying for correctness. Check
whether the title still launches before attributing the setting to performance.

**Cyberpunk 2077 does not need it, and is slower with it.** This page previously said CP2077
refuses to start without AVX; that does not reproduce. Measured 2026-08-15 with nothing setting
`FEX_HOSTFEATURES` anywhere (launcher, `launchers.bak`, AppConfig all checked, and the guest's own
`CPUID.1:ECX.AVX` read back as 0): the title launches and completes its built-in benchmark
normally. With `enableavx` on top of `FEX_HWTSO=1 FEX_SPINCOLLAPSE=32`, three counterbalanced laps
per arm, benchmark scene isolated:

| metric | AVX hidden | AVX advertised |
|--------|-----------|----------------|
| scene fps | 27.65 | 26.79 (-3.1%) |
| p50 frametime | 32.31 ms | 32.56 ms |
| **p99 frametime** | **94.08 ms** | **118.69 ms (+26%)** |

p99 separates completely (all three AVX laps worse than all three hidden laps); the central
metrics do not separate at that sample size. The shape matters more than the size: p50 barely
moves while mean and p99 blow out, i.e. AVX is not slowing the typical frame, it is adding tail
latency — the worst place for it in a game.

Attribution: advertising AVX flips *two* things, guest glibc's ifunc selection (`cpu-features.c`
gates `Fast_Rep_String | Fast_Unaligned_Load | Fast_Unaligned_Copy` behind `CPUID.1:ECX.AVX`) and
the JIT's own AVX paths. Setting only the glibc half via
`GLIBC_TUNABLES=glibc.cpu.hwcaps=Fast_Unaligned_Copy,Fast_Unaligned_Load,Fast_Rep_String` measured
neutral (fps +0.7%, p99 -2.9%, no separation). **So the regression is JIT codegen, not ifunc
selection.**

Note that this is a value of the `HostFeatures` option, not an option of its own. There is no
`FEX_ENABLEAVX`; setting one does nothing.

`FEX_REPORTED_CPUS=N`: see the cage section above.

`FEX_SMCLAZYLINK=1`: see the lazy recipe above.

`FEX_SPINLOOPCLAMP` / `FEX_SPINLOOPCLAMPAUTO=1` short-circuits recognized library spin-wait
loops. No longer required for correctness anywhere in the census, but the automatic form was
short-circuiting around 1017 library spin loops in Ziggurat, so it remains a measurable
performance opt-in. Off by default; arm it per title.

`FEX_SPINCOLLAPSE=32` — **the largest measured per-title win on this port so far.** Batches the
budget decrement of counted spin-poll loops so each iteration retires K units instead of one,
correcting for the fact that an emulated spin iteration costs several times a native one. Measured
2026-08-15, Cyberpunk 2077 benchmark scene under `FEX_HWTSO=1`, scene-isolated:

| metric | off | K=32 |
|--------|-----|------|
| p50 frametime | 51.64 ms | **32.66 ms (-36.8%)** |
| mean frametime | 57.26 ms | **35.79 ms (-37.5%)** |
| p99 frametime | ~156 ms | **75 ms (-52%)** |
| scene fps | 17.43 | **27.94 (+60.3%)** |

Seven off laps against three K=32 laps, no overlap on any metric (Mann-Whitney U = 0). An off lap
run *between* two K=32 laps landed on the historical off baseline, so drift and warming are ruled
out. Reproducible to 0.14% across the K=32 laps — uncollapsed spin is a variance source as well as
a cost. Result survives every scene-detection threshold tried and is even larger (+75%) on the raw
unsegmented log.

Pacing improves *more* than the average (p99 -52% vs p50 -37%), which is the opposite of the
failure mode this feature was kept opt-in for: too large a K exhausts the budget early, workers
park, and the wake round trip costs pacing invisibly. That does not appear at K=32 here.

★ **Unset is not K=32.** `kSpinCollapseKDefault = 32` is the K *value* once the feature is enabled;
with `FEX_SPINCOLLAPSE` absent the feature is off entirely. Any benchmark that did not set the
variable measured the off path. `benchrun.sh` writes the full `FEX_*` environment to
`env-*.txt` per run — read that, not the banner, which prints only a few variables.

Still opt-in: the K=32 evidence above is one title and one scene. Known semantic coarsening — on
the found-exit the budget register holds a K-granular value rather than the exact iteration count,
so code that consumed the leftover count would misbehave.

## Hardware TSO (experimental)

`FEX_HWTSO=1` replaces per-access barrier emulation with POWER's Strong Access
Ordering. Every guest mapping is created `PROT_SAO`, the hardware orders the
accesses, and the JIT stops emitting TSO IR ops entirely: scalar, vector and
memcpy barriers all disappear. Default off.

Unlike `FEX_LOCKONLYTSO` this is sound. SAO pages are hardware TSO, and the MP
litmus that fires roughly 1.2% per round on ordinary POWER8 pages produced zero
violations in 16.3 million rounds on SAO pages.

It is marked experimental because it depends on the host honouring `PROT_SAO`,
which not every kernel and MMU configuration does. FEX probes at startup; if the
kernel refuses, it warns once and falls back to barrier emulation, so enabling it
on a host that cannot do it costs nothing but the warning. It was proven on the
4K-page box only. Run `notes/tools/sao_litmus.c` on any new host class before
trusting it there.

Inert when off, and inert when `FEX_TSOENABLED=0`.

## Knobs that are known-unsound

These are not in the list above and should not be treated as tuning. They make the emulator produce
answers x86 says are impossible. They are documented because they exist and are fast, not because
they are advisable.

`FEX_LOCKONLYTSO=1` is **unsound: measured, not theoretical.** The emulator normally emits
acquire/release sequences around every guest load and store to preserve x86's memory ordering on a
weakly-ordered host. This restricts that to instructions actually carrying a `LOCK` prefix, plus
ranges explicitly forced by Mono detection; plain loads and stores lose their barriers entirely.

The `MP` litmus shape (two stores on one thread, two loads on another) is *forbidden* on x86.
Under FEX on POWER9, same guest binary, only the environment variable changed:

| configuration | MP observations |
|---|---|
| default | **0** in 150,000 rounds (0/30000, 0/60000, 0/60000) |
| `FEX_LOCKONLYTSO=1` | **659 / 30,000**, then **12 / 30,000**, then **51 / 30,000** |

Every one of those is a guest-visible violation of the memory model FEX exists to emulate. The rate
swings ~50x between repetitions, so the specific numbers mean nothing; zero-every-time versus
nonzero-every-time is the result. It costs about 1.6x in speed to be correct here.

A second, independent litmus shape agrees. `IRIW`, also forbidden on x86, was observed **552
times in 1,000,000 iterations** under `FEX_LOCKONLYTSO=1`, against **0 in 67,200,000 iterations**
on the default config, with native `lwsync` and `hwsync` controls both at 0/200,000,000. Two
different forbidden outcomes, two harnesses, same verdict.

A sequential-consistency test does *not* detect this: `seqcst_discriminator.c` reads 0/60,000 both
ways, because `LOCK` operations keep their full fence. It takes the MP or IRIW shape to see it.
Reproduce with `powerpc64le-handbook/probes/atomics_litmus.c` (MP is the discriminator),
`powerpc64le-handbook/probes/iriw.c`, and `powerpc64le-handbook/probes/seqcst_discriminator.c`.

glibc futex and lazy-symbol-resolution are backed by `LOCK CMPXCHG` and therefore keep working,
which is the only reason this option is usable at all. That is not a general reassurance. Anything
in the guest doing its own lock-free or `volatile`-based cross-thread communication may silently
compute wrong results rather than crash. Use it only where a wrong answer is acceptable. FEX prints
a warning on startup when it is enabled. It does nothing if `FEX_TSOENABLED=0`.

`FEX_NONTSORBP=1` is a narrower member of the same family. Accesses addressed
through `RSP` already skip TSO barriers, on the assumption that the stack is
thread-private. This extends that exemption to `RBP`, which matters for titles
that keep frame pointers: every local-variable access through an `EBP` frame
chain currently pays full barriers, and 32-bit code is built that way
throughout. The soundness caveat is exactly the caveat on the existing `RSP`
exemption, which is that a guest sharing stack memory between threads and
relying on x86 ordering for it will get wrong answers. Per-app opt-in, off by
default.

## Kill switches and triage knobs

These exist to bisect a regression, not to tune. Each disables an optimization
that is on by default, or turns on logging that is off by default.

`FEX_TSOPAIRELIDE=0` disables elision of the leading barrier in an adjacent
TSO load/store pair. Set it if a title misbehaves in a way that smells like
memory ordering, to rule the elision pass in or out.

`FEX_NO_THUNK_PARTIAL_FILL=1` disables the sentinel-guarded partial GPR refill
on thunk and host-call crossings, restoring the full refill. Suspect it when a
crash lands in or just after a thunk call.

`FEX_X11_SYNC_EVERY_CALL=1` restores a guest `XSync` on every Display-taking
call. That was the default until 2026-08-13; it is now first-only, which is what
makes the display lookup lock-free on the hot path. Set it when bisecting a
`BadDrawable` or `BadMatch` at GL bootstrap or mode change.

`FEX_VK_PROCADDR_TRACE=1` logs every Vulkan proc-address the guest successfully
links. Useful when a Vulkan title fails at startup and you need to see which
entry points resolved.

`FEX_MEMSETDCBZ=0` removes the `dcbz` block-zero path from the `rep stosb` fast
path, leaving plain stores. On by default and it should stay that way: it is
11.4x faster than plain stores with ordinary pages and still 1.64x faster under
`PROT_SAO`. The switch exists because that second number was worth checking —
SAO penalises `dcbz` far harder than it penalises ordinary stores — and because
an A/B of it in Cyberpunk 2077 found no significant frametime difference either
way (n=6 per arm), which is the honest ceiling on how much this path matters to
a real title.

`FEX_MEMCPYDCBZ=1` (off by default) adds a cache-line `dcbz` store tier to the
forward `rep movsb` fast path, killing the destination read-for-ownership.
Measured +28.6% at 4 KB and +18.6% at 64 KB on explicit `rep movsb` — but only
where `PROT_SAO` is *not* live. Under `FEX_HWTSO=1` the same tier is a 63%
regression, so it is hard-gated off whenever hardware TSO actually engaged. That
gate keys on SAO being live, not on the CPU: a POWER9 radix host cannot use
`PROT_SAO` at all, so the tier stays enabled and beneficial there.

Note it reaches very little today. Guest glibc resolves `memcpy` to
`__memmove_ssse3`, which has no `rep movsb` path, so `DEF_OP(MemCpy)` is close to
dead for ordinary Linux guest memcpy. The cause is that `cpu-features.c` gates
its `Fast_Unaligned_Copy` selection behind `CPUID.1:ECX.AVX`, which this port
reports as 0 — see the AVX section above.

Both `FEX_NO_THUNK_PARTIAL_FILL` and `FEX_VK_PROCADDR_TRACE` are tested for
presence, not value, so `=0` enables them just as `=1` does. Unset them to turn
them off. `FEX_TSOPAIRELIDE`, `FEX_X11_SYNC_EVERY_CALL`, `FEX_MEMSETDCBZ`,
`FEX_MEMCPYDCBZ` and `FEX_SPINCOLLAPSE` do read their value.

## Per-application config files

Setting these on the command line every time gets old. A JSON file at
`~/.config/fex-emu/AppConfig/<guest-binary-basename>.json` applies to that title only:

```json
{ "Config": { "SMCChecks": "mtrack", "SMCSoftInvalidate": "1", "SMCLazyInval": "1" } }
```

Environment variables override AppConfig, which is what makes a launcher script's exports win.
The trap is the same rule read backwards: **an AppConfig can silently disarm flags you thought you
set.** `"SMCChecks": "none"` in an AppConfig turns off mtrack, and every SMC feature gates on
mtrack, so they all stay off with no diagnostic. Read a title's AppConfig before interpreting any
measurement of it. More templates are in [AppConfigRecipes.md](AppConfigRecipes.md).

## Steam

Steam runs, logs in, and launches titles, with caveats.

Launch it through `FEXBash` rather than `FEX`. `steam.sh` is a shell script, and the whole client
is a tree of scripts and helper processes that must all end up inside the guest:

```sh
FEXBash ~/.local/share/Steam/steam.sh -tcp
```

`-tcp` forces Steam's networking off UDP, which is emulated more conservatively.

If you wrap that in a launcher script, watch three things.

**Override `FEXBASH`, not just `FEX_BIN`.** A script that points `FEX_BIN` at a freshly built
emulator but leaves `FEXBASH` at its default runs the entire Steam session on the other binary,
silently. This has cost whole afternoons: an A/B of two builds showed no difference because
neither was actually in use. Confirm with `pgrep -af FEX` before trusting a result.

**Use `--timeout 0`, or no timeout wrapper at all.** Launchers that wrap the run in
`timeout --signal=KILL 300` kill Steam at exactly five minutes. Since container setup and logon
take a couple of minutes on their own, that reads as "Steam crashes after a few minutes of use".
If a session ends suspiciously punctually, check for a timeout wrapper first.

**Keep the ALSA thunk off.** `"asound": 1` in the `ThunksDB` block crash-loops `steamwebhelper`
every ten seconds with a "steamwebhelper is not responding" dialog: the guest-side stub exports no
ELF symbol versions, so every versioned ALSA lookup out of `libcef.so` fails. Set `"asound": 0`.
Nothing needs it; game audio goes through PulseAudio.

### Adding a library folder on another drive

Steam enumerates mountable drives through udisks, which is not present in the guest rootfs, so
"Add Library Folder" will not offer your other disks. Add the mount to the rootfs's own
`/etc/fstab` instead. An entry there makes the path visible to the guest as a mount, and Steam
will accept it as a library location. The host must have the filesystem mounted at the same path.

## Troubleshooting

**Unity games swallow their own output.** The Unity player redirects stdout and stderr into its
own log, so anything the emulator prints after the player starts will not appear in your terminal
or your `tee`'d log file. Read `~/.config/unity3d/<Company>/<Product>/Player.log`. This includes
the emulator's diagnostics, not just the game's. If a trace flag "produced no output", look there
before concluding it did not arm.

**A running FEXServer swallows banner lines.** `OutputLog` defaults to `server`, so log output
goes to whichever `FEXServer` is already running, not to the process you launched. A server left
over from an earlier session keeps serving, and startup banners land somewhere you are not
looking. For a session you want to read directly:

```sh
FEX_SILENTLOG=0 FEX_OUTPUTLOG=stderr FEX ...
```

**Verify a flag actually armed.** Do not trust that an export reached the process. Config layers,
AppConfig files and launcher defaults all get between you and the guest. Read the environment off
the live process:

```sh
tr '\0' '\n' < /proc/$(pgrep -n FEX)/environ | grep '^FEX_'
```

The same suspicion applies to the binary itself. `ls -l /proc/<pid>/exe` showing `(deleted)` means
the process is running a build you have since overwritten, and a rebuild did not take effect.

**A slow game is not necessarily a broken one.** Distinguish spinning from working before
debugging: CPU percentage does not tell you which, but the spread of distinct program counters
does. A wedge sits on a handful of addresses; real work moves.

## Host tuning

Set the CPU governor to `performance` while gaming. The `ondemand` governor frequently fails to
ramp under emulated load (clock was observed parked at 59% of maximum mid-game) because the JIT's
access pattern does not look like the sustained busy loop the governor is watching for.

```sh
sudo cpupower frequency-set -g performance
```

Failing that, write `performance` into each
`/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`.

Check for leftover processes before measuring anything. An emulator or game left running from a
previous session invalidates every number you collect afterwards.
