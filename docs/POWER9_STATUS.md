# power9 branch status log (preserved from power9's README at merge e7e4f7cfd)

A SIGABRT on exit remains (deferred; not blocking gameplay).

## Milestone — POWER9: CPU frame time roughly halved

On a POWER9 AC922, Factorio's `cpu-frame` median went **37.7 ms → 19.6 ms**. Two changes, both removing
work from the block-transition path:

- **`36299af03`** — gated a debug RIP-trace counter that ran unconditionally in Release builds, writing
  process-global counters from every guest thread on every block transition. **−35%** single-socket,
  **−57%** cross-socket.
- **`c6c8d8dde` + `7f5e92bbb`** — inlined the dispatcher's L1 lookup into `ExitFunction` and moved the SRA
  spill to the miss leg. Hit path: **84 instructions → 16**. **−21%** on top.

Verified by byte-identical Factorio map checksums, ctest 7024/7024, and FTL reaching "Running Game!".

Also landed: guest-RIP reconstruction, so crashes now resolve to a guest instruction rather than a host
address in a JIT buffer; a fix for guest arithmetic flags being corrupted after every in-JIT signal; an
out-of-bounds FPSCR write reachable from `_MM_SET_FLUSH_ZERO_MODE`; and ELFv2 r2/TOC preservation across
cross-DSO thunk calls.

## Milestone — code cache validates on PPC64LE

`CodeCache::Validate` reports **`Successfully validated cache`** — the first time the code-cache detector
has passed on this backend. Cache-mode compilation is now provably byte-identical between sessions modulo
ASLR.

Getting there took nine commits. The detector itself was crashing (a malformed erase-remove idiom left a
relocation vector corrupted), and underneath that the backend emitted only one of the four relocation
types, recorded relocation offsets block-relative while consuming them buffer-relative, never rebased
guest addresses, and materialised constants with a value-dependent instruction count so patch sites could
not be rewritten in place.

The cache is **not** enabled yet — validation proves cache-mode compilation is reproducible, not that
cached code is safe to run. Remaining before it can be trusted: `Validate`'s own blind spots (it does not
check the block-mapping table, and has no length-equality check) and cache invalidation, which currently
keys on the guest binary's *path string* rather than its identity.

**Update — cache identity, Validate's blind spots and crash-safe saving are addressed.** All three items
above landed under the `CodeCache:` prefix, unverified on hardware (the backend only builds on the POWER8
host):

- **Identity.** `ComputeCodeMapId` now hashes file *content* (size + first/last 64 KiB) instead of the
  path, and `CodeCacheConfigId` — previously hardcoded `0` with a TODO in two places — is a hash of
  `GIT_HASH` plus every codegen-affecting option (SMC flags incl. `SMCSemanticPatch`, the TSO/atomics
  knobs, block shape, host features, L1/L2 lookup shape). A stale or mismatched key names a file that does
  not exist, so it is a miss rather than a load.
- **Validate.** It now checks the guest→host block-mapping table against the reference compile (presence,
  per-block entry offset, layout) before comparing bytes, and treats "reference compile emitted more bytes
  than the cache holds" as fatal. The reverse (cache longer than the reference) stays non-fatal — a cache
  legitimately covers more than one section of a file.
- **Saving.** `SaveData` was previously called only by `FEXOfflineCompiler`, and it relocated the *live*
  code buffer in place. It now snapshots into a private copy, filters the block table to the file being
  written, and draws relocations from a context-wide sink instead of the compiling thread's backend. The
  runtime writes caches when `CodeCacheScope != off`, periodically from the memory-management syscalls and
  once at exit, via temp file + `rename(2)`.

Still open: cached code carries no SMC metadata (correct and documented in `LookupCache.h`); a cache file
holds the whole code buffer rather than just its own file's blocks; and files with `Skip` code relocations
are excluded wholesale rather than per block.

Detail is in the commit messages and `docs/POWER9_PORT_PLAN.md`.

## Milestone — the thread-spawn corruption is fixed

**`clone3` could return 0 to the parent, and glibc read that as success** — producing a `pthread` carrying
`tid = 0`: a handle that looks valid, gets used, and corrupts on teardown.

The cause was one line of our own. `DestroyThread` zeroed `ThreadInfo.TID` as a zombie marker while the
parent's syscall-return path still read that field as data. Marker and data shared a slot.

**`76b36f6c0`** splits them: a new `std::atomic<bool> IsZombie` carries the marker with release ordering,
`TID` is never zeroed, and both `TID == 0` consumers migrate to the flag with acquire ordering. A
belt-and-braces guard rewrites any surviving `Result == 0` to `-EAGAIN`.

`probe_thread_spawn` goes **10–17 % failure → 0/30 foreground and 0/30 background.** The guard never fired
across 7,200 `clone3` calls, so the marker split closes the race on its own.

This retires a cluster we had treated as separate bugs: **Factorio's `execute_native_thread_routine`
SIGSEGV on save-load**, Factorio's intermittent crash at ~3 % load, and Steam's crash dialogs and general
sluggishness. All one race.

## Milestone — misaligned atomics run without the mutex fallback

x86 permits `LOCK` on unaligned addresses; POWER's `larx`/`stcx.` require natural alignment, so every
misaligned guest atomic previously fell back to striped-mutex emulation. Six commits move the common cases
onto real hardware atomics:

| Commit | Case |
|---|---|
| `00d64c59c` | **C3** — access fits inside one aligned doubleword: `ldarx`/`stdcx.` on the container |
| `e5eff0e3d` | **C4** — quadword container via `lqarx`/`stqcx.` (ISA 2.07) |
| `c48a741f6` | **C4.5** — CAS crossing a dual-doubleword boundary |
| `2613c73a6` | **C5** — split-lock telemetry three ways + retry high-water |
| `6a4bcddd0` `7904276aa` | **C6/C7** — JIT-inline container loops; contained cases take no helper call at all |

Frequency is sharply title-dependent and it is **a 32-bit/Mono phenomenon**: Dex records 14,794 misaligned
atomics, Factorio/FTL/OpenSSL record zero.

Two unrelated defects fell out of the same batch. **`cb57944a3`** — the C5 telemetry init loop was bounded
by `TYPE_LAST` (23) against an array sized `TYPE_JIT_ADDRESSABLE_LAST` (17), overwriting dispatcher pointers;
it passed the full regression gate while corrupting memory. **`8970907ef`** — CPUID topology used
`bit_ceil` where a log2 was meant, an upstream regression that made `cpu_count.64` fail; now PASS.

## Headline wins on this branch

Each entry corresponds to a real commit. Pick the keystones if reading top-to-bottom:

| Commit | What it fixes |
|---|---|
| `b21ee0205` | **The keystone.** `mfcr(TMP2)` in `PushCalleeSavedRegisters` was clobbering r4 (the incoming RIP arg) on every JIT entry — leaving every cross-arch callback dispatching to State.rip=0xC0. Stash r4→r7 before the prologue. Without this, ~no game beyond a splash screen could survive Mesa/SDL/Mono interaction. |
| `fb7447370` | Phase 3 unaligned-atomic recovery: SIGBUS-driven LL/SC pattern decode + `PPC64_SplitLockEmulate` fallback. Flips `SupportsAtomics=true`. |
| `694f81668` | Striped `SplitLockEmulate` mutex 64-way by cacheline (`addr >> 6 & 63`) — removes the single-mutex contention point under concurrent atomic recovery. |
| `f5117a0f8` | Overlay-aware FM.\* wrappers for the full path-mutating syscall cluster (chmod/chown/creat/link/mkdir/rename/truncate/symlink/unlink + \*at variants). Makes gvisor's chmod/chown/creat/link/mkdir/rename/truncate cluster 100% green. Invariants: ENOENT-only fallback, per-leg translation for renameat2/linkat/symlinkat. |
| `58973e69e` `017ebd9f8` `3caaf4a6e` | Cross-arch callback unpacker registrations in libGL + libvulkan thunks (`FvjE`, `FvvE`, glTexImage2D-class, `FPKhjE` / `const unsigned char*(unsigned int)`). Mesa's GLX dispatch pulls these from the guest's callback table; without registration the fallback wrap returns NULL and Mesa derefs. |
| `be0c74ae3` `0a9c80dce` `ddccce961` | libEGL thunk wired into the build + ThunksDB catalog (was already built, missing catalog entry). libxshmfence build wiring + catalog also landed (7 fns — DRI3 explicit-sync) but the **rootfs symlink redirect was reverted 2026-05-19** after the active thunk caused `malloc(): corrupted unsorted chunks` heap corruption in extended FTL gameplay. Source-tree wiring kept; activation deferred pending thunk audit. |
| `c8dab0af3` | **Cross-arch fallback wrap discriminates host vs guest pointers.** When guest gets a host pointer from `glXGetProcAddress` (or any host override) and calls through it indirectly, the wrapper was unconditionally treating cb as a guest VA → routing through `CallbackUnpack` trap stubs for opaque/layout-wrapper signatures → SIGILL. Use `dladdr` to detect host pointers and call them directly. Eliminates the SIGILL crash class and noisy "no guest unpacker registered for signature ..." warnings. |
| `a331160bb` | CPUID/rdtsc scales to host POWER8 timebase via `GetCycleCounterFrequency()` so guest x86_64 sees a coherent rdtsc rate. |
| `62ea24ce4` | Cross-arch thunk callback passes `TrampolineInstanceInfo` via TLS (`__fex_callback_guestcall_ptr`) instead of r11 — r11 is the small-toc register on PPC64 ELFv2 and gets clobbered. |
| (earlier session) `d91959d2f` | xcb is the only working Vulkan/GL WSI for x86_64 guest on PPC64LE host — wayland and xlib WSIs break cross-arch guest-callback dispatch. Recorded as a bank note. |

## Subsystem audits + smaller fixes

- **128-byte cache-line padding** for `CpuStateFrame` on POWER8 (vs ARM64's 64-byte) — false sharing of guest GPR state under JIT was costing measurable throughput.
- **gvisor `ioctl(TIOCOUTQ)` family translation** — was returning the raw kernel struct instead of guest layout.
- **PPC64LE-specific sidestep removal** — earlier audit pass that found and removed several `#ifdef PPC64LE` workarounds that became dead weight as the JIT matured. Branch is now `arm64-vs-ppc64le-parity-by-default`.
- **r0 zero-index gotcha**, `JumpTargets` reset on each block, FillStaticRegs r0 corner cases, 32-bit zero-extend semantics, flag-subsystem coverage gaps — all individually painful, all fixed.
- **ASM differential test suite**: 11213 instruction-level diffs run clean on POWER8 except 6 SSSE3 PSIGN cases (tracked, deferred).

## What works today

| Game | Status |
|---|---|
| **FTL: Advanced Edition** | **Playable** — menu + gameplay + audio. SIGABRT on exit (deferred). |
| **Factorio 2.x** | **Playable, and the primary performance workload.** Renders, benchmarks to completion, map checksums byte-identical across every change landed. `cpu-frame` median 19.6 ms on POWER9 (was 37.7 ms). **The `execute_native_thread_routine` SIGSEGV on save-load is fixed** — it was the `clone3` thread-spawn race, not a Factorio-specific defect (`76b36f6c0`). Five consecutive clean `oil_refinery` benchmark runs. |
| **Dex** (32-bit Unity/Mono) | **Playable** — runs to gameplay and exits cleanly through the in-game menu. The primary misaligned-atomics and SMC workload: 14,794 misaligned atomics and ~23,000 code-page invalidations in one session. Startup/cutscene video renders markedly slower than gameplay — open, and the reason an SSE-heavy vector workload is now on the queue. |
| RimWorld (Unity/Mono) | Boots, loads, **deterministic** fatal signal 11 in `mono_runtime_invoke` at ~90 s — still open. Now debuggable: guest-RIP reconstruction resolves the fault to a specific guest instruction. Also a standing SMC-audit workload. Note Mono uses SIGSEGV for null checks on an altstack, so startup SIGSEGVs are expected behaviour, not defects. |
| Hard West (Unity/Mono) | Loads. Used as an x86_64 Mono workload for the SMC audit; not yet taken to gameplay here, so no playability claim. |
| SuperTuxKart (Vulkan) | Vulkan window opens; cross-arch GL callback dispatch is the next blocker. |
| Stardew Valley | Main thread spins on FUTEX_WAIT→EAGAIN after cold JIT; pre-existing project_stardew_main_thread_spin note. |
| Ziggurat (Unity/Mono) | Mono-specific EAGAIN spin in `libmono.so` (not a general FEX bug — strace diff vs other games proves it). |
| Legend of Grimrock | Bundled SDL2 (2014) heap-corrupts under modern glibc → workaround `LD_PRELOAD=/usr/lib/libSDL2-2.0.so.0`. Layer-2: `glXChooseVisual`-shape callback (`XVisualInfo*(_XDisplay*, unsigned int, unsigned int*)`) needs custom_host_impl in libGL_interface.cpp following the `MapToGuestVisualInfo` pattern (commit `41d9771a1`). Generic `RegisterGuestCallbackUnpacker` doesn't work for opaque/layout-wrapper types. |
| Steam | Boots and logs in. **The TLS theory is disproven** — a 32-bit probe linked against Steam's own bundled OpenSSL 1.1.1i completes the handshake against Steam's CDN on TLS 1.2, TLS 1.3, and with HelloRetryRequest forced, single-threaded *and* on a spawned pthread, 30/30 in every configuration, with a matched 64-bit control. FEX's 32-bit TLS path is fine. The remaining `http error 0` is inside Valve's closed-source bootstrap. Shelved as not-a-FEX-defect. (`build-probes/probe_ossl11*.c`) |
