# 64K game census, 2026-09-14

Every registered title through `~/fex-scripts/smoke64k.sh` (gauntlet v3:
one systemd cgroup per title, render verification through `xwininfo` +
`import` + pixel stddev, screenshots under `/tmp/smoke/shots`, results
copied to `~/benchlogs/smoke64k-*`), on op64k, kernel 7.2.5-books-64k,
build-smc at the commits named per row. Three lanes: Linux-native
(FEXInterpreter, `fex <title>`), fexproton (GE-Proton11-3 x86-64 wine under
full emulation, `fex <title>`), native wine + bridge (`fex nw-<title>`).

Harness gaps found first, both on the 64K root drive and both fixed before
any verdict below was taken: `xwininfo` was not installed (every windowed
leg reported "no window"; `xorg-xwininfo` installed), and `pkill -f` from a
shell whose command line carries the pattern kills that shell (kill by pid).

## Linux-native lane

| title | verdict | notes |
|---|---|---|
| vkcube | PASS | Vulkan thunk canary |
| ftl | PASS | |
| ziggurat | PASS | |
| rimworld | FAIL then FIXED | host SIGSEGV in `CodeCacheFilename`: the delayed code-cache load ran after the VMATracking lock was released with a *reference* into a `MappedResource` that Mono's unmap had freed. `MappedFile` is a `shared_ptr` now and `ExecutableFileSectionInfo` carries a keep-alive (8d064877a). Menu path 150 s clean after the fix. |
| grimrock | PASS | leaks guest procs past the cgroup stop |
| stardew | FAIL, OPEN | CoreCLR. Guest SIGSEGV within ~60 s in every SMC mode (mtrack, lazy trio off, file-immutable off, full validation) and with `DOTNET_EnableWriteXorExecute=0`; decoder reports "Missing LOCK HANDLER" on ADD/FILD/JLE and a GS selector write in 64-bit mode before it, i.e. it executes garbage bytes. No granule refusals except benign guard regions. Ran on 4K (2026-07-30 fix). Needs a debugging session: map the guest RIP (0x7fff4f072cc0 in the tripwire run) to its library and diff the loaded bytes against the file. The launcher rule that put it on the full tier is retracted (that tier crashes too). |
| hardwest | PASS | |
| moonlighter | PASS | |
| amongthesleep | PASS | |
| shadowrunhk | PASS | |
| zomboid | PASS | |
| dex (i386) | FAIL then FIXED | exit 0 within seconds: "NoExec instruction in entry block" at 0x8079ED0. The loader fallback's overlap window was unclamped, so the first PT_LOAD of a non-PIE i386 executable got `mprotect(0, ...)` and kept its read-write pread window: text never executable (6a7831058). Runs to Unity asset loading after the fix. |
| psychonauts (i386) | PASS (dark) | engine running (animation loads in the log); the screenshot's pixel stddev was 0.0199 against the harness's 0.02 bar, a dark loading screen, not a fault |
| witcher2 (i386) | PASS | passes only after the loader fix |

## fexproton lane (full emulation)

All nine titles died at boot in the first pass: wine 11 stopped at
`virtual_map_user_shared_data`. Two granule-layer additions make wine start
(`cmd /c ver` prints "Microsoft Windows 10.0.19045", exit 0):

1. A MAP_SHARED file mapping whose only sub-granule dimension is its length,
   at a host-aligned address and offset, is mapped as the whole granule from
   that offset (the USD page: 4K, fixed at 0x7ffe0000, offset 0). The tail
   past EOF is never touched; a PROT_NONE reservation in the tail does not
   block (wine maps into its own reserved space).
2. A private sub-granule request into such a granule (wine's per-process
   syscall-dispatcher pointer page at 0x7ffe1000) re-maps the granule
   MAP_PRIVATE from the same file: untouched pages keep tracking the file
   through the page cache (the live USD), written pages are copied on write
   (the dispatcher page). The file is extended to cover the granule.

3. The first rerun then died in the JIT's link path on every title: the
   code-cache writer (on by default on 64K) asserted in
   `CodeMapWriter::AppendBlock` when a block lay below its section's
   `FileStartVA`, which wine's multi-view PE mappings produce. Fatal for an
   optimisation; it skips the block now (f3d00249f).

Rerun on the fixed build (`~/benchlogs/smoke64k-win-*`):

| title | verdict | notes |
|---|---|---|
| witcher3 | PASS | rendering, 15 procs |
| dexwin | PASS | its registry row carries `PROTON_NO_NTSYNC=1` |
| cp2077 | WEDGE then PASS | alive, no window with ntsync; rendering (15 procs) in round 3 with `PROTON_NO_NTSYNC=1` |
| outward | FAIL then PASS | exit 3 at boot with ntsync; rendering (16 procs) in round 3 with `PROTON_NO_NTSYNC=1` |
| tombraider | PASS (dark) | window at 0.0195 pixel stddev against the 0.02 bar: a dark loading screen |
| vtmb, vtmbup | WEDGE then FIXED | alive, no window, 75 s CPU. With `PROTON_NO_NTSYNC=1` VtMB opens its 1920x1080 window in 200 s. The ntsync wedge (memory: FreeInfantry, Portal 2-proton) is the open root cause; the launcher now defaults `PROTON_NO_NTSYNC=1` for the fexproton lane on the 64K boot |
| arcanum | WEDGE | window present, pixel stddev 0: truly black (D3D8 path); not diagnosed |
| rimworldwin | FAIL then PASS | died in the play window with ntsync; rendering (16 procs) in round 3 with `PROTON_NO_NTSYNC=1`. Its "Failed to get home directory" / PulseAudio lines are noise (present in the passing run) |


## Native wine + bridge lane

| title | verdict | notes |
|---|---|---|
| nw-dexwin (32-bit) | WEDGE | first pass died with `Unknown ALU Op: 0x15`: opcode 0x82, the 32-bit-only alias of 0x80, was missing from `SecondaryALUOp` (e7c26503e, 32-bit ASM test). After the fix it parks with a 1x1 window, which is the known nw-lane 32-bit Windows gap (nested exception on the signal stack; memory notes). |
| nw-witcher3 | PASS | 12 procs, rendering |
| nw-cp2077 | PASS | rendering, 15 procs (its first leg had run through a launcher I had just broken) |
| nw-rimworldwin | PASS | rendering, 14 procs (first leg had hit the same launcher incident) |

## Also found on the way

- Every Linux-lane launch was spawning `FEXOfflineCompiler` runs whose
  caches nobody loads (the fexplay launcher puts Bin on PATH); the client's
  server-side request is opt-in now (`FEX_SERVERCODECACHE=1`, e2a106ee3).
- The gauntlet's process-count boot check cannot tell "exited 0 in a second"
  from a crash; a title that dies through the silent SIGSEGV stub reads as
  a clean exit. The host-fault gate's report lands in Unity's Player.log,
  which captures FEX's stderr.
