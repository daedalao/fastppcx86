# FEX on POWER — Gaming Play Book (ppc64le, 64K kernel)

Running x86 games under FEX on a little-endian IBM POWER machine (POWER8 or
later, ppc64le), on a 64K-page kernel. This is written for other POWER owners,
not for one specific box: the recipes below are the settings that transfer —
which lane a game needs, the SMC recipe, whether ntsync must be off, the real
launch arguments — not any one machine's file paths.

Companion to the census (`docs/GAME_CENSUS_64K_2026-09-14.md`), which records
*why* each verdict is what it is. This doc is *how to play*.

---

## The three lanes

A Windows or Linux x86 game can reach the screen three ways. Pick the first one
that has a working recipe for your title.

| Lane | What runs native, what is emulated | Use it for |
|---|---|---|
| **Native Linux** | The game's own Linux x86 build runs under FEX. | Any game with a Linux build. Simplest, usually best. |
| **Native wine** | Native ppc64le wine + DXVK; only the game's x86 code is emulated. | Windows games — fastest option when a recipe works. Needs the ppc64le-native wine/DXVK port. |
| **Full emulation** | x86-64 wine (GE-Proton) runs *entirely* under FEX. | Windows games with no native-wine recipe. The reliable fallback. |

The examples below use a launcher-style shorthand (`fex <game>`,
`fex nw-<game>`). Substitute your own invocation — what matters is the lane and
the environment/arguments in each recipe, which are portable across POWER boxes.

---

## 64K-kernel baseline (set these once)

On a 64K-page POWER kernel, set these defaults for every FEX game launch. A
launcher wrapper is the sane way to apply them; otherwise export them in the
game's environment.

| Setting | Value | Why |
|---|---|---|
| `FEX_HOSTPAGEMODE` | `force` | Run the 4K memory-tracking (mtrack) configuration on a 64K host. The default for FEXInterpreter lanes would otherwise abort. |
| `FEX_ENABLECODECACHINGWIP` | `1` | Persistent x86→ppc64le translation cache. The host page size is part of the cache identity, so 64K and 4K caches never collide. |
| `FEX_CODECACHESCOPE` | `all` | Generate and load the cache. |
| `PROTON_NO_NTSYNC` | `1` | Full-emulation lane only. ntsync under full emulation is an open wedge on 64K; leave it off there. The native-wine lane keeps ntsync. |
| `FEX_X87REDUCEDPRECISION` | `1` | x87 at double precision. ~9% faster, no observed physics/audio artifacts. Set `0` to restore exact 80-bit for a precision-sensitive title. |
| `MESA_SHADER_CACHE_MAX_SIZE` | `10G` | RADV's on-disk cache. The 1 GB default fills and then every launch recompiles shaders. Set it system-wide too, for Steam-launched titles. |

If your FEX build re-registers a `binfmt_misc` handler, re-register it after
every rebuild: the kernel pins the interpreter at registration time, so wine and
Proton children keep running a stale FEX until you do.

---

## SMC recipes

Self-modifying guests (game scripting VMs, .NET/CoreCLR, the JVM, JS JITs) are
sensitive to how FEX tracks self-modifying code. Two recipes cover every game
here:

- **lazy** (default) — `FEX_SMCCHECKS=mtrack`, `FEX_SMCSOFTINVALIDATE=1`,
  `FEX_SMCLAZYINVAL=1`, `FEX_SMCFILEIMMUTABLE=1`, `FEX_SMCLAZYLINK=1`. Fast;
  sound for ordinary games.
- **strict** — `FEX_SMCCHECKS=mtrack`, `FEX_SMCSOFTINVALIDATE=1` (no lazy
  deferral). Required for self-modifying JITs. A hair slower, fully correct for
  the concurrent-patch case that lazy defers.

Rule of thumb: if a .NET, Java, or scripting-VM game crashes within seconds of a
level load, switch it to **strict**.

---

## Recipe book

Status: **Plays** = played through, good experience. **Plays (recipe)** = works
with the settings in the Notes column. **Renders** = starts and draws, not
confirmed past a loading screen. **Not yet** = known broken, cause noted.

### Native Linux — the game's Linux x86 build under FEX

| Game | Status | Recipe |
|---|---|---|
| FTL: Advanced Edition | Plays | Defaults. |
| Ziggurat | Plays | Defaults. |
| Legend of Grimrock | Plays | Defaults. |
| Hard West | Plays | Defaults. |
| Moonlighter | Plays | Defaults. |
| Among the Sleep | Plays | Defaults. |
| Shadowrun: Hong Kong | Plays | Defaults. |
| The Witcher 2 (i386) | Plays | Defaults. 32-bit build. |
| Dex (i386) | Plays | Defaults. 32-bit Unity. |
| RimWorld | Plays | Defaults. |
| Project Zomboid | Plays (recipe) | **strict** SMC. JVM tuning helps: `FEX_SPINCOLLAPSE=128`, `-XX:TieredStopAtLevel=1`. Self-modifying JIT. |
| Stardew Valley | Plays (recipe) | ~60 fps. **strict** SMC + `DOTNET_TieredCompilation=0` + `DOTNET_TieredPGO=0` + `SDL_JOYSTICK_DISABLE_UDEV=1`. CoreCLR tiering re-patches call sites from background threads; disabling tiering avoids the concurrent-SMC race. |
| Psychonauts (i386) | Renders (dark) | Engine runs; sticks on a dark loading screen. Marginal. |

### Windows games — native wine (`nw-`), preferred for Windows

Needs the ppc64le-native wine + DXVK port. Only the game's x86 code is emulated,
so this is the fastest Windows lane.

| Game | Status | Recipe |
|---|---|---|
| Vampire: The Masquerade – Bloodlines | Plays | ~24–25 fps in-level. **Install the Unofficial Patch** and launch its exe with `-game Unofficial_Patch -dxlevel 90 -w 1920 -h 1080 -fullscreen`. Native-wine lane only — do not use full emulation for this game. |
| The Witcher 3 GOTY | Plays | Defaults. |
| Cyberpunk 2077 | Plays | ~23 fps. An SMT2 CPU pin smooths audio (drop SMT or pin the game's threads to two per core). |
| RimWorld (Windows build) | Plays | Defaults. |
| Dex (Windows build) | Not yet | 32-bit native-wine gap (nested exception on the signal stack). Use the native Linux Dex instead. |

### Windows games — full emulation (GE-Proton under FEX)

The fallback lane. Defaults include `PROTON_NO_NTSYNC=1` on 64K.

| Game | Status | Recipe |
|---|---|---|
| The Witcher 3 GOTY | Plays | A save-load crash is fixed by a per-title guest-anchor spec (`FEX_GUESTANCHOR` + `FEX_GUESTSERIALIZE_RVA`) tuned to the exe's build; see the census/launcher for the exact RVAs. |
| Cyberpunk 2077 | Plays | ntsync off. Launch arg `-skipStartScreen`. Slow cold start (~180 s: JIT + shader compile); warm launches are quick. |
| Outward Definitive Edition | Plays | ntsync off. |
| RimWorld (Windows build) | Plays | ntsync off. |
| Dex (Windows build) | Plays | ntsync off. |
| Tomb Raider 2013 | Renders (dark) | Window draws; not confirmed past the loading screen. |
| Arcanum (2001) | Not yet | D3D8/DirectDraw path renders black. Wine-side; also poor on x86 wine. |

### Through Steam

Skyrim Special Edition plays through the Steam client on the Proton lane. The
lockpicking minigame that hung after a successful pick is fixed (the Windows
shared-data clocks, previously frozen under the granule memory path, now
refresh).

---

## When a game misbehaves

- **Windows game hangs at boot, no window (full-emulation lane).** Usually
  ntsync — make sure `PROTON_NO_NTSYNC=1` is set.
- **Self-modifying game crashes seconds in (.NET / Java / scripting VM).** Use
  the **strict** SMC recipe. For a CoreCLR title also set
  `DOTNET_TieredCompilation=0`.
- **Single-threaded game feels CPU-starved.** Drop SMT so each thread gets more
  of the core: `sudo ppc64_cpu --smt=2` (or `--smt=4`); restore with `--smt=8`.
  Lower SMT = more resources per thread; higher = more parallel threads.
- **Physics/audio artifacts.** Restore exact 80-bit x87:
  `FEX_X87REDUCEDPRECISION=0`.
- **A Windows game runs on both lanes.** Try native wine (`nw-`) first; fall
  back to full emulation.

Give every game its own wine prefix; sharing one between titles is how you end
up with a prefix nothing runs in. Deleting a game's prefix forces a clean
re-create.

---

## Setting up a POWER box for this

This is bleeding-edge; there is no package to install. What has to be in place:

**Machine and kernel.** A little-endian POWER machine (POWER8 or later),
ppc64le Linux, on a **64K base-page** kernel. Many ppc64le distributions already
default to 64K pages on the POWER hash MMU; that is the target here (it is also
where transparent huge pages and the granule SMC path live). A 4K-page kernel
works but is a different, slower configuration.

**FEX for ppc64le.** Build FEX with the POWER backend, using the gaming build
configuration (the SMC-tracking options above enabled). This port is the subject
of this repository.

**x86 root filesystem.** An x86_64 RootFS for FEX (its rootfs tooling can fetch
an Arch or Ubuntu image) — the x86 glibc, loader and system libraries the guest
needs. Keep a 32-bit multilib layout too, for i386 titles.

**For Windows games, one or both of:**
- **GE-Proton** (x86-64) run under FEX — the full-emulation lane. Invoke
  Proton's runner directly under the emulator rather than through the Steam
  pressure-vessel.
- **The ppc64le-native wine + DXVK port** — the native-wine lane. This is the
  fast path; it is a separate build (native ppc64le wine with a FEX bridge for
  the 32-bit COM crossings).

**ntsync.** The full-emulation lane defaults ntsync *off* on 64K, so most
Windows games do not need it. Where you do want it (native-wine lane), use a
kernel with ntsync and confirm `/dev/ntsync` exists; rebuild any out-of-tree
module after each kernel update.

**GPU.** A working Vulkan driver (RADV on AMD has been the reference). Raise the
shader cache cap as above. FEX thunks the guest's Vulkan/GL through to the host
driver.

**Governor / SMT.** `performance` governor for consistent results; SMT 8 by
default, lower for single-threaded titles.

**Locale (ssh launches).** Export `LANG=en_US.UTF-8` plus `DISPLAY`,
`XAUTHORITY`, `XDG_RUNTIME_DIR`. A POSIX locale gives the guest an ASCII code
page, which some Unity titles render as a black screen — a locale bug, not a
64K bug.

---

## What is not settled

- **VtMB, Arcanum, Tomb Raider, Psychonauts** are the rough edges. VtMB works on
  native wine only, with the Unofficial Patch. Arcanum's DirectDraw path renders
  black. Tomb Raider and Psychonauts draw but are unconfirmed past their loading
  screens.
- **ntsync under full emulation** is an open wedge (a cross-mechanism deadlock
  between a futex poll and ntsync waits). Until it is root-caused, keep the
  full-emulation lane on `PROTON_NO_NTSYNC=1`.
- **The 64K granule SMC** is not fully sound under concurrent guest
  self-modification. Strict SMC + tiering-off is the interim for CoreCLR/JVM
  titles; the core fix is in progress.
