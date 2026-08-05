# Running games

This is the practical guide: what a POWER8/POWER9 box needs before it can run an x86 game, what a
launch command should look like, which knobs are worth setting per title, and where the output
goes when something breaks. Flag semantics are in the [flags reference](../README.md#flags-reference);
per-title verdicts are in [MONO_UNITY_CENSUS.md](MONO_UNITY_CENSUS.md).

Binaries and environment variables keep the historical `FEX` prefix. `FEX` is the emulator,
`FEXBash` runs a shell inside the guest rootfs, `FEXServer` is the background helper that owns the
rootfs mount and the log socket.

## Prerequisites

**A 4K-page kernel.** The self-modifying-code tracker (`SMCChecks=mtrack`, the default)
write-protects guest pages at a fixed 4K granularity, matching the `AT_PAGESZ=4096` the guest is
told. On a host booted with 64K pages, mtrack misbehaves or aborts. Boot a 4K kernel, or run
everything with `FEX_SMCCHECKS=full`, which validates code before every run and is much slower.
Check with `getconf PAGESIZE`.

**An x86-64 root filesystem.** Everything the guest links against — glibc, SDL, libX11, Mesa's
guest-side stubs — comes from the rootfs, not from the host. `FEXRootFSFetcher` downloads a
prebuilt image, or point `FEX_ROOTFS` at a directory you populated yourself. Games that ship their
own bundled libraries still need the rootfs for libc.

**Thunk libraries, if you want working graphics.** Build with `-DBUILD_THUNKS=ON` so guest OpenGL
and Vulkan calls land in the host's driver instead of being emulated instruction by instruction.
Thunks are enabled per library in the `ThunksDB` block of `Config.json`. 32-bit games additionally
need `BUILD_THUNKS_32BIT` and a 32-bit guest toolchain.

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

A stale `XAUTHORITY` fails late — after the guest has started and linked — with "Unable to open
display", which reads like a graphics bug and is not one.

## The CPU cage

**Launch Mono/Unity titles under `taskset`.** This is not tuning; without it several titles are
unplayable.

Unity sizes its worker and job pools from the CPU count the guest reports. On an 80-thread POWER8
an uncaged guest builds a pool of about 79 workers, and the pool's park gate is a check that no
worker is currently inside the steal window. At that oversubscription the gate is never satisfied
— occupancy was measured between 20 and 51 across 13000 samples and never reached zero — so the
pool spins instead of parking, saturating the machine while the game crawls. Hard West ran at
roughly 2 fps this way. The cage fixes it by shrinking the pool: since commit `9a0f8e1be` the
emulated `/proc/cpuinfo` is bounded by the process affinity mask, so a caged process reports the
caged count and Unity sizes its pools accordingly.

POWER8 and POWER9 number online CPUs sparsely — in SMT4 the online set looks like `0-3,8-11,…`,
one group of four per core — so list explicit threads rather than a range.

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

Guests that generate code at runtime — every Mono or .NET title — write to pages the emulator has
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

The recipes stack — everything at once is a valid experiment — but each piece has far more
mileage individually than the full combination does. Prefer semantic patching or lazy.

Profile before assuming a recipe is the answer. A flat guest profile means raw emulated throughput
is the limit and no SMC recipe will move it; Moonlighter's frame rate, for one, is bound by entity
count, not by invalidation.

## Per-title knobs worth setting

These are the ones that earned their place in real sessions.

`FEX_ENABLEAVX=0` — pushes guest code onto SSE paths. POWER's vector units are 128-bit, so
emulating 256-bit AVX costs more than the guest saves by using it; glibc string routines measured
36–67% faster with AVX reporting off. Not a universal win — A/B it. Moonlighter was faster with
AVX left on.

`FEX_REPORTED_CPUS=N` — see the cage section above.

`FEX_SMCLAZYLINK=1` — see the lazy recipe above.

`FEX_LOCKONLYTSO=1` — the emulator normally emits acquire/release sequences around every guest
load and store to preserve x86's memory ordering on a weakly-ordered host. This restricts that to
instructions actually carrying a `LOCK` prefix, plus ranges explicitly forced by Mono detection.
Plain loads become cheap loads. **This is a real correctness tradeoff, not free speed:** guest code
that relies on a non-`LOCK` volatile read being visible across threads can race under it. The
glibc futex and lazy-symbol-resolution paths are understood to be safe, which is why it is usable
at all; anything beyond that is your risk. It does nothing if `FEX_TSOENABLED=0`.

`FEX_SPINLOOPCLAMP` / `FEX_SPINLOOPCLAMPAUTO=1` — short-circuits recognized library spin-wait
loops. No longer required for correctness anywhere in the census, but the automatic form was
short-circuiting around 1017 library spin loops in Ziggurat, so it remains a measurable
performance opt-in. Off by default; arm it per title.

### Per-application config files

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

Launch it through `FEXBash` rather than `FEX` — `steam.sh` is a shell script, and the whole client
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
Nothing needs it — game audio goes through PulseAudio.

### Adding a library folder on another drive

Steam enumerates mountable drives through udisks, which is not present in the guest rootfs, so
"Add Library Folder" will not offer your other disks. Add the mount to the rootfs's own
`/etc/fstab` instead — an entry there makes the path visible to the guest as a mount, and Steam
will accept it as a library location. The host must have the filesystem mounted at the same path.

## Troubleshooting

**Unity games swallow their own output.** The Unity player redirects stdout and stderr into its
own log, so anything the emulator prints after the player starts will not appear in your terminal
or your `tee`'d log file. Read `~/.config/unity3d/<Company>/<Product>/Player.log`. This includes
the emulator's diagnostics, not just the game's — if a trace flag "produced no output", look there
before concluding it did not arm.

**A running FEXServer swallows banner lines.** `OutputLog` defaults to `server`, so log output
goes to whichever `FEXServer` is already running, not to the process you launched. A server left
over from an earlier session keeps serving, and startup banners land somewhere you are not
looking. For a session you want to read directly:

```sh
FEX_SILENTLOG=0 FEX_OUTPUTLOG=stderr FEX ...
```

**Verify a flag actually armed.** Do not trust that an export reached the process — config layers,
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
ramp under emulated load — clock was observed parked at 59% of maximum mid-game — because the JIT's
access pattern does not look like the sustained busy loop the governor is watching for.

```sh
sudo cpupower frequency-set -g performance
```

Failing that, write `performance` into each
`/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor`.

Check for leftover processes before measuring anything. An emulator or game left running from a
previous session invalidates every number you collect afterwards.
