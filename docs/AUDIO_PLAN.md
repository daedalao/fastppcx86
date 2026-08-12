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

## New data point 2026-08-10: stutter tracks title weight, not wine

Witcher 3 (Proton), dexwin (Proton) AND Dex-Linux (native) all stutter hard;
FTL is clean. Dex-Linux stuttering **breaks the "it's inside wine" framing of
disease B** — whatever zeroes/starves buffers is shared between the native and
wine paths, i.e. FEX-side (JIT throughput, timing precision, signal traffic)
or graph-side, and it scales with title heaviness. The tracker below exists
to classify these events objectively per title.

## Tracker (implemented 2026-08-10)

`notes/audio_tracker.py` + `notes/stutterwatch.sh`, deployed to
`op4k:~/fex-scripts/`. Passive capture (parec on the default sink monitor,
48kHz f32 stereo), live classification:

- `ZERO-RUN Nf (ms) po2:BxK|unquantised` — silence mid-signal; po2-quantised
  runs are the disease-B signature.
- `HUGESCALE` / `NANINF` — disease-A scale corruption in-flight.
- `STALL` — monitor delivery fell behind realtime: the graph itself starved
  (disease C), as opposed to zeros arriving on time.
- Exit summary prints an event histogram and a per-disease verdict.

Usage on op4k: `~/fex-scripts/stutterwatch.sh <title>` then start the game;
ctrl-C ends the session. Logs land in `~/audio-tracks/<ts>-<title>/`
(events.log, pwtop.log with 1Hz ERR/quantum, load.log). Offline mode:
`audio_tracker.py --stdin < capture.f32` (also the self-test path).

Immediate matrix to run: FTL (control), Witcher 3, Dex-Linux, dexwin — one
session each. Compare zero-run quantisation and STALL totals across the four;
identical signatures native-vs-wine confirms the shared-layer theory.

### ⚠ 2026-08-10 late: TWO retroactive data caveats

1. **binfmt F-flag pin**: all wine/proton processes (including witcher3.exe
   and Dex.exe themselves) ran a months-old PINNED build-mono FEX all day —
   only direct-launch guests (Dex.x86, FTL) ran the smc build. Fixed by
   re-registering binfmt to build-smc; must re-register after every rebuild.
   W3/dexwin numbers below measure the OLD build.
2. **Cage masks hit offline CPUs**: op4k is SMT4-of-8 (online groups
   0-3,8-11,16-19,…), so "8-thread" cages were really 4 and "16-thread"
   really 8. Correct SMT2 cage: 0,1,8,9,16,17,24,25 (+32,33,… to widen).

### Full matrix results 2026-08-10 (pinned = taskset 4c×SMT2 + FEX_REPORTED_CPUS=8)

| title | free-run | pinned | reduction |
|---|---|---|---|
| Dex-Linux | 716 zero-runs, all 256f-quantised | 9, one 0.4s burst | **~80×** |
| FTL (control) | 241, unquantised/tiny (content silence) | 240 identical | none — clean title confirmed |
| Witcher 3 | **5160**, median 1024f (21ms), max 393ms | 103 (rerun; first pinned attempt crashed once, unreproduced) | **~50×** |
| dexwin | 3–5 (only load screens) | 10–18 | already few zeros — its disease differs |

All sessions: zeros ON TIME, 0 STALL, 0 corruption. Raw f32 captures kept
per session in ~/audio-tracks/ (op4k).

**dexwin's audible "repeating + static" is NOT in the sink stream**: repeat
detector live + offline wide sweep (lags 32..19200, r>0.99) found nothing in
16min of capture while the user heard constant repeats. The damage is
downstream of the sink — prime suspect the Sunshine capture→Opus→network
path under load; user was skeptical and was RIGHT.

**TONE TEST VERDICT (2026-08-10 ~18:20, W3 pinned, user driving): game audio
audibly stuttering, 220Hz reference tone through the same sink→Sunshine→
client path STEADY. Transport exonerated, graph exonerated.** With the sink
also near-clean of zeros/repeats under pinning, the remaining audible
stutter is the game PRODUCING hitchy-but-continuous audio: engine threads
hiccup (JIT compile bursts / SMC storms / GC pauses) and the content itself
stutters. Audio was the messenger, not the disease.

Next: hitch-correlation — run a session with SMC_AUDIT=1 + thread census +
JIT profile stats timestamped, user marks audible stutter-fest moments, line
them up. (Tone recipe: paplay --raw a f32 sine into sink-sunshine-stereo;
pw-play cannot play headerless raw — fails silently.)

### Hitch-correlation session results (w3-wide16, 2026-08-10 18:20-18:37)

**CORRECTION: the earlier "W3 pinned = 50× better" claim is RETRACTED** —
workload confound: the 103-event pinned session idled in menus (user wasn't
driving); the 5160-event free session and this one were driven gameplay.
Only the Dex 80× result (matched automated workloads) stands.

w3-wide16 (8 cores × SMT2 = 16 threads, FEX_REPORTED_CPUS=16, user driving
heavy scenes): **14,851 real zero-runs / 16.5 min** — worse per-minute than
free-run; dropouts scale with scene weight and the cage didn't cure driven
W3. User: "running like shit"; cage aggregate NOT saturated (~4.8/16
threads busy at a stutter moment) → **single-thread JIT throughput is the
bottleneck** (consistent with the 08-08 profile: ~90% engine JIT code).

Mark-vs-SMC-rate correlation (4 user marks, 1Hz audit growth): marks at
0/s, 47/s, 9072/s, 994/s peaks — stutter non-stop while storms are
intermittent (session p50=22/s, p90=997/s, max=14.8K/s). **SMC churn is an
aggravator, not the driver.** Audit composition over 16.5min: 240K mark
events, 12.9K guest-mprotect, 12.6K guest-mmap, 6.5K faults (52MB log).

Fix priorities now: (1) single-thread JIT code quality = the real W3 fix;
(2) SMC mark/mprotect cost reduction for the storm spikes; (3) matched-
workload cage A/B (same save, driven both) if cage tuning is to be retried;
(4) audit-off control to quantify instrumentation overhead (journald +
udisksd were burning host CPU during the session).

**Conclusion: "disease B" on native titles is guest mixer-thread deadline
misses under CPU oversubscription — the mixer submits whole silent buffers on
time when its callback misses. B and C are one disease mechanically; the
zeros-on-time vs starved distinction is about WHERE the deadline dies (guest
mixer vs graph), not a different bug.** The wine-internal theory is dead for
the native case; rerun the same A/B on Witcher 3 before closing it there.

Fix direction (we-are-upstream, no per-title workarounds): the oversubscription
comes from guest thread pools sized off 80 host CPUs contending with FEX's own
JIT/compile threads. Candidates: default FEX_REPORTED_CPUS to the affinity
mask everywhere (not just witcher2), and/or elevate guest audio-mixer thread
priority (FMOD mixer threads request SCHED_FIFO/high prio — check whether FEX
passes guest sched_setscheduler/setpriority through, or silently drops it).

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

## Track D (opened 2026-08-10): reverb/echo placement wrong on dexwin

User report: reverb/echo effects on Dex (Windows build) sound displaced.
Backend audit says NOT FP semantics: PMULHRSW is decomposed (perf gap only),
and the un-emulated MXCSR.FTZ only diverges below audibility (denormal-flat
xv* lowering computes tails exactly). Remaining suspects: wine-layer period
size / latency negotiation shifting wet/dry alignment, or a genuine JIT
correctness bug in a DSP hot loop.

Objective test (uses the dex/dexwin A/B pair): stand at the same reverberant
in-game location in both builds, capture the sink monitor while triggering
the same one-shot sound, cross-correlate the echo tail offsets between the
two captures. If dexwin's wet signal is time-shifted vs native at identical
sample rate, it's the wine audio path; if the tail SHAPE differs, it's DSP
math and worth a JIT hunt.

## Track E (opened 2026-08-10): Dex video decode corruption

Cutscene videos corrupt (alternating-column striping + chroma splotches; UI
crisp) in Dex while audio/subtitles run — deterministic decode corruption,
"all videos". Videos are Unity MovieTexture Theora/Ogg embedded in
resources.assets (first OggS at offset 1153904016); decoder is the bundled
32-bit libtheora = MMX/SSE2 asm (IDCT/loop-filter/unpack) — prime suspect is
a JIT vector bug in the MMX class (pack/unpack/saturate shaped, given the
striping).

Repro without the game: extract the Ogg stream, run x86 ffmpeg under FEX
`-cpuflags 0` (C path) vs default (SIMD) with `-f framemd5`, diff both
against host-native ppc64le ffmpeg output. C==native + SIMD!=native proves
the JIT bug; bisect -cpuflags mmx/mmxext/sse2/ssse3 to the family, then
per-op ASM tests.

## Standing rules
- Never re-run the exonerated list (paplay, patml, paunder, polltest,
  cvt_test, PULSE_LOG, host futex passthrough) — see the pulse-wedge notes.
- strace perturbs the symptom; prefer passive capture (`pw-dump`, monitor
  parec, `ss -xpm`).
- Any new audio theory must first survive the paplay control experiment and
  the ERR=0/zeros-on-time facts above.
