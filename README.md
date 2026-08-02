# FEX-Emu — PPC64LE backend (`fex-ppc64le`)

A port of [FEX-Emu](https://github.com/FEX-Emu/FEX) to **PPC64LE (POWER8+)** hosts. FEX is an x86_64 user-mode emulator that JITs x86 code to the host architecture; upstream supports ARM64. This fork adds a complete PPC64LE JIT backend.

## Milestone — FTL: Advanced Edition is playable

**FTL: Advanced Edition is the first x86_64 game to run to gameplay on PPC64LE/FEX.** Window opens, main menu reaches, game launches, music + sound effects play. Confirmed end-to-end on POWER8 at the commit stack below.

[![FTL running on FEX-PPC64LE — click to play](https://img.youtube.com/vi/Dtj-Lqw4zKA/maxresdefault.jpg)](https://www.youtube.com/watch?v=Dtj-Lqw4zKA "FTL: Advanced Edition running on FEX/PPC64LE — click to watch")

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

Detail is in the commit messages and `docs/POWER9_PORT_PLAN.md`.

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
| **Factorio 2.x** | **Playable, and the primary performance workload.** Renders, benchmarks to completion, map checksums byte-identical across every change landed. `cpu-frame` median 19.6 ms on POWER9 (was 37.7 ms). An intermittent `execute_native_thread_routine` SIGSEGV on save-load is under investigation — same signature as the open `probe_thread_spawn` corruption. |
| RimWorld (Unity/Mono) | Boots, loads, **deterministic** fatal signal 11 in `mono_runtime_invoke` at ~90 s. Now debuggable — guest-RIP reconstruction resolves the fault to a specific guest instruction. Note Mono uses SIGSEGV for null checks on an altstack, so startup SIGSEGVs are expected behaviour, not defects. |
| SuperTuxKart (Vulkan) | Vulkan window opens; cross-arch GL callback dispatch is the next blocker. |
| Stardew Valley | Main thread spins on FUTEX_WAIT→EAGAIN after cold JIT; pre-existing project_stardew_main_thread_spin note. |
| Ziggurat (Unity/Mono) | Mono-specific EAGAIN spin in `libmono.so` (not a general FEX bug — strace diff vs other games proves it). |
| Legend of Grimrock | Bundled SDL2 (2014) heap-corrupts under modern glibc → workaround `LD_PRELOAD=/usr/lib/libSDL2-2.0.so.0`. Layer-2: `glXChooseVisual`-shape callback (`XVisualInfo*(_XDisplay*, unsigned int, unsigned int*)`) needs custom_host_impl in libGL_interface.cpp following the `MapToGuestVisualInfo` pattern (commit `41d9771a1`). Generic `RegisterGuestCallbackUnpacker` doesn't work for opaque/layout-wrapper types. |
| Steam | Boots and logs in. **The TLS theory is disproven** — a 32-bit probe linked against Steam's own bundled OpenSSL 1.1.1i completes the handshake against Steam's CDN on TLS 1.2, TLS 1.3, and with HelloRetryRequest forced, single-threaded *and* on a spawned pthread, 30/30 in every configuration, with a matched 64-bit control. FEX's 32-bit TLS path is fine. The remaining `http error 0` is inside Valve's closed-source bootstrap. Shelved as not-a-FEX-defect. (`build-probes/probe_ossl11*.c`) |

## Build

PPC64LE host build is standard FEX cmake:

```
mkdir build && cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja -j96   # POWER8 8-core/64-thread sweet spot
```

Guest stub libraries (libGL-guest.so / libvulkan-guest.so / libEGL-guest.so / libxshmfence-guest.so) cross-compile to x86_64; the POWER8 cross-sysroot is incomplete in this repo, so guest stubs are typically built on a native x86_64 host and copied back. See `Data/CMake/toolchain_x86_64.cmake` and `ThunkLibs/GuestLibs/CMakeLists.txt`.

## Upstream

This branch tracks FEX-Emu upstream main. Drop the `bank-power8-*` keystone fixes onto a fresh upstream and they apply cleanly modulo trivial conflict on dispatcher/atomics files. PRs upstream pending review of the ABI invariants we've codified (in particular the mfcr-clobbers-arg-reg constraint which is genuinely a PPC64 ELFv2 ABI gotcha, not FEX-specific).

## Acknowledgements

- The FEX-Emu team for the core JIT/dispatch architecture.
- Mesa, SDL, libxcb, libX11 upstream — the cross-arch frictions hit during this port are illuminating, not blaming.
