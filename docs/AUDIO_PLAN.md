# Audio status

Status of the audio investigation. Session logs, retracted measurements and
superseded theories are in the git history; this file records only what is
currently believed and what is still open.

Last reviewed 2026-08-13.

## Settled

**Dropouts are guest-side deadline misses, not FEX's audio path.** When a title
drops audio, whole buffers arrive on time and all-zero, with the graph reporting
no errors. Three controls place the fault ahead of the sink: the rootfs's own
emulated `paplay` through the same FEX/PipeWire path is clean, a reference tone
played through the same sink is steady while game audio stutters, and native
titles stutter as badly as Proton ones. The guest mixer submits a silent buffer
when its callback misses its deadline, so the audible symptom is a report of CPU
starvation rather than a bug in audio handling.

The corollary is that audio work is mostly JIT throughput work. In Witcher 3,
dropout counts scale with scene weight while the CPU cage sits well short of
saturation, which points at single-thread throughput rather than parallelism.
SMC churn aggravates it (invalidation storms peak around 15k/s) but is
intermittent while the stutter is continuous, so it is not the driver.

**Vector correctness caused at least one audible defect.** A same-register
aliasing bug in the MMX pack helpers (`VSQXTNPair`/`VSQXTUNPair`, fixed in
`f82194265`) decorrelated Portal 2's audio. Confirmed fixed in-game. The
same-register sweep added in `1ac807100` covers the class.

**Starvation and interleaving** are largely resolved by the performance sweep
and the `SA_RESTART`/`EINTR` work. This was the source of the old "host load
makes audio better" paradox, and it is no longer the dominant symptom.

**Mitigations that were once proposals have shipped.** `/proc/cpuinfo` is
bounded by the process affinity mask (`9a0f8e1be`), so a `taskset` cage now
shrinks guest thread pools without a separate override. Guest scheduler
requests are visible through the `ThreadCensus` option and can be retried at
weaker priorities with `SchedPassthrough`, which answers the open question of
whether FEX was silently dropping guest `SCHED_FIFO` requests: it forwards them
verbatim, and an unprivileged host refuses them.

## Open

**Sample-bank scale corruption.** In native Mono/FNA/FAudio titles (Stardew
Valley is the specimen) audio plays correctly for minutes, then a single event
scales the decoded sample bank by roughly 2^63 and everything after is garbage.
Established by payload decode and by a register snapshot showing corrupted
samples being multiplied by a sane volume in flight, so the damage is upstream
of the mixer. Every stored-gain theory was tested and failed.

The mechanism family is signal-delivery register corruption. The `SpillSRA`
XMM-stride bug fixed in `79ecc6004` is a confirmed instance of exactly that
family: on a signal with multiple XMMs live, `xmm[k]` scattered to `xmm[2k]` and
odd registers were zeroed, which is enough to poison a vectorized scale loop
once and permanently.

That fix landed after the last corruption specimen was captured and the retest
has never been run. Next step is two or three long Stardew sessions past the
historical cutout point on a current build. If no cutout appears, close it
against `79ecc6004`.

If it survives the retest, catch it live rather than post hoc: a guest program
that holds a known constant in its XMM registers across heavy signal traffic and
checksums every iteration will fail within seconds if the family is still
active, and works as a regression test afterwards.

**Reverb placement on dexwin.** Reverb and echo sound displaced in the Windows
build of Dex. Not floating-point semantics: `PMULHRSW` is decomposed exactly,
and the un-emulated `MXCSR.FTZ` only diverges below audibility. Remaining
suspects are wine-layer latency negotiation shifting wet/dry alignment, or a JIT
bug in a DSP loop. The dex/dexwin pair makes this testable: capture the same
one-shot sound at the same in-game location in both builds and cross-correlate
the echo tails. A time shift implicates the wine audio path; a different tail
shape implicates the arithmetic.

**Dex video decode corruption** (tracked here for lack of a better home, though
it is not an audio defect). Cutscenes show alternating-column striping and
chroma splotches while UI stays crisp. The decoder is the bundled 32-bit
libtheora, whose IDCT and loop filter are MMX/SSE2 assembly, and the striping is
pack/unpack/saturate shaped. Reproducible without the game: extract the Ogg
stream and run x86 `ffmpeg` under FEX with `-cpuflags 0` against the default,
comparing `-f framemd5` output to host-native ffmpeg. C matching native while
SIMD does not proves a JIT bug; bisect `-cpuflags` to the instruction family
from there.

## Standing rules

Keep `asound: 0`. The guest ALSA stub exports no ELF symbol versions, so
versioned lookups fail; it crash-loops `steamwebhelper` and deadlocks FMOD
titles. Game audio goes through PulseAudio and does not need it. The packaged
`Config.json` ships it disabled.

`PULSE_LATENCY_MSEC=60` fixes FMOD/Unity titles that abort at audio init.

Cage Mono/Unity titles with `taskset`. See [GAMING.md](GAMING.md).

Do not re-run the exonerated experiments: `paplay`, `patml`, `paunder`,
`polltest`, `cvt_test`, `PULSE_LOG` and host futex passthrough all came back
clean. `strace` perturbs the symptom badly enough to be useless here; prefer
passive capture (`pw-dump`, a `parec` on the sink monitor, `ss -xpm`).

Any new theory has to survive the `paplay` control and the zeros-arrive-on-time
observation before it is worth pursuing.

## Measurement traps

These invalidated whole sessions of audio data before they were understood.

The binfmt_misc `F` flag pins the interpreter binary at registration time, so
every wine and Proton child runs whichever FEX build was registered, not the one
you just built. Re-register after every rebuild.

POWER8 numbers online CPUs sparsely. In SMT4 the online set is `0-3,8-11,...`,
so a cage written as a dense range silently gets half the threads intended. Use
explicit thread lists.

Unity titles redirect stdout and stderr into `Player.log`, so FEX diagnostics
printed after the player starts never reach your terminal.

## Tooling

The passive capture and classification tooling (`audio_tracker.py`,
`stutterwatch.sh`) lives on the op4k box under `~/fex-scripts/` and is not in
this repository. It records a `parec` capture of the default sink monitor and
classifies zero runs (flagging power-of-two-quantised ones, the deadline-miss
signature), in-flight scale corruption, and delivery falling behind realtime.
