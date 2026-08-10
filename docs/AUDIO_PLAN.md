# Audio: what we know, and the plan

_2026-08-10. Sources: pulse-wedge investigation 07-29→08-05, Witcher 3 capture
analysis 08-08, perf-sweep retests 08-05._

## The class is THREE separate diseases, not one

Years of "audio cuts out" reports collapse into three mechanisms with
different owners:

**A. One-time sample-bank corruption ×2^63 (native Mono/FNA/FAudio titles —
Stardew is the specimen).** Audio is perfect for many minutes, then a single
corruption event scales the decoded sample bank by ~2^63 (`0x5F000000`-shaped)
and everything after is garbage-then-perceived-silence. Established by payload
decode (real waveform × 2^58-59), register snapshot (corrupted samples
multiplied by a *sane* 0.9548 volume in-flight), and negative results on every
stored-gain theory (gain_scan pokes, volume sliders). The mechanism family is
signal-delivery/SRA register corruption. **The SpillSRA XMM-stride bug (fixed
79ecc6004) is the first concrete instance of exactly that family**: on any
signal with multiple XMMs live, xmm[k] scattered to xmm[2k], odd regs zeroed —
a vectorized convert/scale loop eating that once explains a persistently
poisoned decoded bank.

**B. Buffer-quantised dropouts inside wine (Proton titles — Witcher 3 is the
specimen).** Whole power-of-two buffers (64…2048 samples) arrive **on time but
all-zero**; `pw-top` shows ERR=0 everywhere, ~1% PipeWire load; both channels
identical. NOT gain corruption, NOT starvation, and **NOT FEX's audio path**:
the rootfs's own emulated `paplay` through the same FEX/PipeWire/sink is
0.0%-loss clean. Suspicion is winepulse / FAudio / the game mixer inside wine.

**C. Starvation/interleaving (historical).** Largely fixed by the perf sweep +
SA_RESTART/EINTR work: Stardew ambience became audible on an unloaded box for
the first time on the merged perf build (08-05). The old "load makes audio
better" paradox was this disease, and it is no longer the dominant symptom.
Keep `asound: 0` (thunk stub deadlocks FMOD titles) and the SMT2/taskset and
`PULSE_LATENCY_MSEC=60` mitigations documented for stragglers.

## Plan, cheapest-decisive-first

### 1. Retest disease A on the current build — possibly already dead
The SpillSRA fix (79ecc6004) landed AFTER the last corruption specimen
(08-05, build-mono). Nobody has run the retest.
- 2-3 long Stardew sessions (30+ min into gameplay, past the historical
  cutout point) on the current smc build.
- If no cutout across sessions: declare A fixed by 79ecc6004, note it, close.
- Instrument to make this objective instead of by-ear: the **sine-FFT
  discriminator** — loop a known tone via the game-adjacent path, capture the
  sink monitor, FFT-check scale/continuity. Cheap script; also becomes the
  regression tripwire for every future audio claim.

### 2. If A survives: catch the event live
Post-hoc scans found the damage but never the moment. Two instruments, both
already sketched:
- **sigstorm + SSE-constant-checksum guest repro**: guest program keeps a
  known splat (e.g. 1/32768) in XMMs across heavy signal traffic, checksums
  every iteration, aborts on first mismatch. Under 30s to fail if the family
  is still live; doubles as a ctest.
- **FEX State.xmm dump tooling**: on a magic guest syscall, dump the SRA/XMM
  view so the guest checksum failure pinpoints which register and when.

### 3. Disease B: isolate which wine layer zeroes the buffers
- A/B a second Proton title with heavy audio (dexwin qualifies) — is it
  wine-wide or W3-specific? (W3 uniquely keeps two sink inputs.)
- Switch wine's audio backend (winepulse → winealsa via registry
  `HKCU\Software\Wine\Drivers Audio=alsa`) — if dropouts vanish, it's
  winepulse's timer/callback loop under FEX timing; if they persist, it's
  FAudio/XAudio2 or the game mixer.
- Per-stream capture needs `module-loopback` per sink input (`pw-record`
  cannot target stream nodes) — only worth it after the backend A/B.
- Candidate FEX-side mechanisms if it comes back to us: timer slack /
  clock_nanosleep precision in the guest (winepulse uses timing-based
  writes), and mmap'd timing pages. The paplay control says plain PA
  streaming is fine, so only timing-sensitive paths remain.

### 4. User-facing mitigations meanwhile (already known-good)
- `PULSE_LATENCY_MSEC=60` for FMOD/Unity titles that abort at audio init.
- `"asound": 0` stays the global default (the packaged Config.json ships it).
- SMT2/taskset pinning for Unity titles (fairness, disease C stragglers).

## Standing rules
- Never re-run the exonerated list (paplay, patml, paunder, polltest,
  cvt_test, PULSE_LOG, host futex passthrough) — see the pulse-wedge notes.
- strace perturbs the symptom; prefer passive capture (`pw-dump`, monitor
  parec, `ss -xpm`).
- Any new audio theory must first survive the paplay control experiment and
  the ERR=0/zeros-on-time facts above.
