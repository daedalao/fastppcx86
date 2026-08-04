# Ziggurat dungeon-load finalize spin — live capture, 2026-08-04

Build `09449d7b1` (all of the 2026-08-03/04 correctness + vector work), recipe
`off` (legacy SMC), absorb tripwires on, POWER8 op4k, performance governor.
Captured by Claude Fable with the game paused at the wedge and ptrace enabled.

## What the failure actually is

**Not** a slow load and **not** a deadlock. The level finishes loading, then a
single guest thread enters a bounded loop whose exit condition is already
unreachable, and spins forever at ~140% CPU while the renderer and audio
threads stay healthy.

Evidence it fully loaded:
- `Player.log` last line: `Unloading 0 unused Assets... Loaded Objects now:
  **138438**` (the pre-fix stalls died at 2312 objects — this is a complete
  dungeon).
- Music plays continuously through the wedge; the window renders Ziggurat's
  normal loading art (a **still image by design** — frame-identical
  screenshots are NOT a wedge signal for this title; that cost earlier
  sessions several wrong calls).
- Only the transition into the dungeon never fires.

## The spin, disassembled

Hot region = 58% of samples across ~128 bytes, zero FEX symbols (so the cost
is guest code executing, not FEX machinery). Guest regs via the PPC64LE SRA
map (`PPC64Emitter.h`: r7=RAX r8=RCX r9=RDX **r10=RBX** r11=RSP r12=RBP
r14=RSI r15=RDI r16..r23 = R8..**R15**):

```
li      r6,4
addco.  r28,r10,r6        # RBX + 4
mr      r10,r28           # RBX = RBX + 4
...
xor     r29,r10,r23       # RBX ^ R15
subfco. r28,r23,r10       # RBX - R15  (sets flags)
bne     <loop body>       # continue while RBX != R15
b       <exit>            # exit only on RBX == R15
```

Live values, sampled twice two seconds apart:

| reg | guest | t | t+2s |
|---|---|---|---|
| r10 | RBX | `0xc6a99649c` | `0xc7b4e5490` |
| r23 | R15 | `0x4` | `0x4` |
| r20 | R12 | `0` | `0` |
| r22 | R14 | `1` | `1` |

RBX climbs by 4 per iteration (~53e9 already, ~13e9 iterations in) and is
≡ 0 mod 4, so it stepped **past** the `== 4` exit long ago and can never
return. R15 is a constant 4 — this reads as a loop meant to run **once**
over 4 bytes / one element.

**Conclusion: RBX (or R15) was already wrong when the loop was entered.** The
loop itself is executing correctly; its induction variable or bound arrived
corrupted, or the initialisation that should have zeroed RBX was skipped.
This matches the long-standing "RBX misses ==4 exit" note in
`ziggurat-dispatcher-window-corruption` — first time it has been caught with
values attached.

## Where to look next (ranked)

1. **Signal-delivery register restore.** The historical suspect is
   `RestoreRIPFromHostPC` resuming one instruction off, which would skip a
   loop's init. Related fixes exist but were never verified against this
   wedge: RIP-reconstruction candidates `667b59685` / `244075383`, and the
   `InSyscallInfo` leak fix `1e5a99b7d`. Mono fires GC suspend signals
   constantly during level finalize — highest-prior mechanism.
2. **SRA spill/fill around the block.** RBX is SRA-mapped to r10; a spill
   path that writes the wrong slot would produce exactly this. Note today's
   SA_RESTART work touches the syscall/signal return path; test with
   `FEX_NO_GUEST_SA_RESTART=1` to rule tonight's changes in or out.
3. **MonoHacks interaction.** `MonoHacks` was ACTIVE in this capture (Mono
   detected via `libmono.so`). A/B with `FEX_MONOHACKS=0` is the cheapest
   discriminator and was started immediately after this capture.
4. SMC is **not** implicated in this capture: recipe was `off`, and the audit
   shows no patch/relink traffic (62008 lines, 271 `UNHANDLED`, nothing else).

## Reproduce + capture (procedure that worked)

```sh
sudo sysctl -w kernel.yama.ptrace_scope=0        # op4k HAS passwordless sudo
SMC_RECIPE=off SMC_ABSORB=1 SMC_AUDIT=1 SMC_CENSUS=1 fexplay-smc ziggurat
# drive to New Game; wedge = Player.log silent >120s at the asset-GC line
P=$(pgrep -f Ziggurat.x86_64 | head -1)
perf record -o /tmp/z.perf -p $P -F 400 -g -- sleep 10
perf report -i /tmp/z.perf --stdio --no-children | head
```

**Trap:** `perf` reports **offsets within the `[anon:FEXMemJIT]` mapping**,
and there are several such mappings. Add the offset to the base of the *large*
one (`grep FEXMemJIT /proc/$P/maps` — the 128 MB entry), not the first.

Dump and disassemble the block, then read guest regs:

```sh
gdb -p $P -batch -ex "dump binary memory /tmp/sb.bin <va> <va+512>"
objdump -D -b binary -m powerpc:common64 -EL /tmp/sb.bin
gdb -p $P -batch -ex "info registers r10 r23 r20 r22"   # RBX R15 R12 R14
```

`/proc/PID/mem` reads are **denied even with ptrace_scope=0** for a
non-descendant; use gdb's `dump binary memory` instead.

## Guest RIP decoding (built, not yet exercised on a live wedge)

`scratchpad/jitrip.py` (also `/tmp/jitrip.py` on op4k) scans backwards from a
host PC for the `JITCodeHeader {u32 OffsetToBlockTail}` whose `JITCodeTail
{size_t Size; u64 RIP; size_t GuestSize; u32 NumberOfRIPEntries; ...}`
(`CPUBackend.h:175-208`) is self-consistent and covers the PC, printing the
block's **guest RIP**. That RIP plus `/proc/PID/maps` names the guest module —
i.e. whether this loop belongs to Mono, UnityPlayer, or game code, which is
the one fact this capture is still missing. Run it at the next wedge before
killing the process.

## Second capture, 2026-08-04 — guest RIP resolved, MonoHacks exonerated

Independent run, **`FEX_MONOHACKS=0`** (everything else identical). Same wedge.

**Guest RIP of the hot block: `0x551330`.** Decoded with `jitrip.py` after
trying every `[anon:FEXMemJIT]` base — the correct one was the **first, 16 MB**
mapping (`0x10011001000`), not the large buffer; `perf` offsets do not say
which mapping they belong to, so try all of them:

```
block_begin=0x10011712860 (pc-0x468) size=0x2d30
guest_rip=0x551330 guest_size=693 rip_entries=124
```

`0x551330` falls inside `00400000-01585000 r-xp .../Ziggurat.x86_64` — the
**game's own executable text**. Ziggurat statically links its Unity player, so
this is engine/game code, *not* `libmono.so` and *not* a separate
`UnityPlayer.so`. (A second plausible decode, `0x3fff5baca1d6`, lands in the
high mmap region — that one is JIT'd/managed code, a different block.)

**Register signature reproduces exactly with MonoHacks off:**

| reg | guest | capture 1 (MonoHacks ON) | capture 2 (MonoHacks OFF) |
|---|---|---|---|
| r23 | R15 | `4` | `4` |
| r20 | R12 | `0` | `0` |
| r22 | R14 | `1` | `1` |
| r10 | RBX | `0xc6a99649c`, +4/iter | `0x4ffab9c0`, ≡0 mod 4 |

R15/R12/R14 are bit-identical across two independent runs; RBX differs in
magnitude but is again far past the `== 4` exit and again 4-aligned.

**Therefore: the mono backpatcher hook is not the cause** — disabling it
changes nothing about the wedge. The loop lives in the game's own text, runs
correctly, and is entered with an induction variable that already exceeds its
bound.

Also visible in capture 2's profile: `PPC64_SplitLockEmulate` at ~0.8%, and
the sample spread is flat (top entry 1.5%) rather than the concentrated
15/10/9% of capture 1 — i.e. this sample caught the process across many
blocks, so the concentrated spin is intermittent within the wedge rather than
the process's only activity.

## Workaround shipped: SpinLoopClamp (`37fd3ada8`)

`FEX_SPINLOOPCLAMP=0xBEGIN-0xEND:ind:bound` — for Ziggurat:
`FEX_SPINLOOPCLAMP=0x551330-0x5515e5:rbx:r15` (End = 0x551330 + guest_size
693). `fexplay-smc ziggurat` now exports this by default; set
`FEX_SPINLOOPCLAMP=disable` to turn it off.

Mechanism: every 64-bit reg-reg CMP of ind vs bound whose guest RIP falls in
the range is compiled (`OpDispatchBuilder::CMPOp`) with an overshoot clamp —
if ind is unsigned-above bound at the compare, both the flag input and the
architectural register are forced to the bound, so the `==` exit fires and
post-loop state equals a legitimate final iteration (`RBX == R15 == 4`). A
sane execution never trips it (legal values here are 0 and 4), and an empty
option emits nothing anywhere.

Verified on `repros/spinclamp_repro.s` (op4k) — the loop shape with RBX
pre-corrupted to `0x4ffab9c0`: spins forever without the clamp, exits 0 with
it, in both `cmp rbx,r15` and `cmp r15,rbx` encodings. Not yet observed
firing on a live wedge; the compile-time hit logs
`SpinLoopClamp: instrumented CMP at guest RIP 0x...`.

This is a workaround, not the fix: something (still suspected to be
signal-time resume skipping the loop init — see "Where to look next") hands
the loop a corrupted induction variable. The clamp makes the wedge survivable
while that hunt continues.

## 2026-08-04 CORRECTION: 0x551330 was a BAD DECODE — real block is 0x934a40

A live third capture (PID 339678, new build, clamp env confirmed present via
`/proc/PID/environ`) still wedged, and the clamp had **never instrumented
anything in any run** (no "instrumented CMP" line in any tmp/*.log; the lone
log line was the parse-time "SpinLoopClamp active"). Diagnosis by subagent:

- **The spin block's real guest RIP is `0x934a40`** (guest_size 4301,
  582 RIP entries); the spinning CMP itself maps to guest **`0x934d15`**,
  exit branch 0x934d2a, back edge 0x934d33, exit target 0x934e72. Still
  inside Ziggurat.x86_64's text. Same loop shape, same R15=4/R12=0/R14=1,
  RBX=0xab8107268 climbing.
- **Why capture 2 got 0x551330:** its perf offset was added to the FIRST
  16 MB FEXMemJIT mapping, which is *too small to contain the offset*;
  `jitrip.py` then accepted a plausible-looking false header (it takes the
  first self-consistent candidate within its scan window). The arithmetic
  proof this time: perf offset 0x5ab9e40 + third mapping base 0x1112beee000
  = live pc 0x111319a7e40. **Rule: reject any base where base+offset lands
  outside that same mapping.**
- The compare IS a 64-bit reg-reg CMP rbx,r15 (subfco. discards its result),
  so the clamp matches once aimed correctly.
- Tooling: `scratchpad/ripwalk.py` (also op4k:/tmp/ripwalk.py) walks the
  vl64pair RIP table exactly like `RestoreRIPFromHostPC` — use it to map
  host PC → guest RIP instead of trusting jitrip.py's header scan alone.

**Corrected spec: `FEX_SPINLOOPCLAMP=0x934a40-0x935b0d:rbx:r15`** — now the
fexplay-smc default. CMPOp additionally logs in-range-but-not-clamped CMPs so
a mis-aimed range can never again look identical to a working one.

## 2026-08-04 WEDGE CLEARED + SYSTEMIC DETECTION SHIPPED

With the corrected spec the user reached the dungeon **for the first time** —
the every-entry clamp succeeds where the 2026-07-31 one-shot gdb poke failed
(the outer structure re-enters, but each re-entry now exits immediately).

Systemic follow-up, `FEX_SPINLOOPCLAMPAUTO` (0 off / 1 Mono-detected,
default / 2 everywhere): `Decoder::DetectSpinLoops` (Frontend.cpp) runs after
multiblock decode and structurally recognizes equality-exit loops — backward
direct branch closing a contiguously-decoded body of ≤48 instructions,
containing a 64-bit reg-reg CMP whose equality edge exits (both shapes:
`cmp; jne head` and `cmp; je out ... jmp head`), where one compared register
takes exactly one positive-constant ADD step in the body and the other is
never written. The CMP gets FLAG_SPINCLAMP_{DEST,SRC}_IND and CMPOp emits the
same overshoot clamp with no configured RIPs. Calls/rets/indirect branches,
compare-skipping internal branches, or unclassifiable writes disqualify the
loop; only natively-non-terminating executions are altered.

Decode gotcha that cost an hour: group1 imm ALU ops carry the immediate in
**Src[1]**, and Src[0] holds a group-selector artifact that reads as a GPR
(RAX) — operand matching must accept the literal from either slot.

Verified (op4k, repros/): spinrepro, spinrepro2, spinrepro_b all exit 0 under
AUTO=2 with no RIPs; spinctl (induction also written by a mov) correctly
refused; Mono gating holds (no clamp for plain binaries at default 1);
manual range path unaffected. Commits 7df72dd17 + 5f040bd24.

## 2026-08-04 RimWorld audit → signed margin clamp (ed2b5766c)

Live-session audit of AUTO=1 on RimWorld: 1017 distinct flagged CMPs — 87%
in UnityPlayer.so native text, 123 in libc/ld.so/libX11, only 6 in libmono,
**zero** in Mono-JIT anon regions or game-executable text. Game healthy (no
E-lines, no Mono exceptions, no spin in perf; the paired startup
`Caught fatal signal` SIGSEGVs are baseline — present identically in the
pre-feature Player-prev.log). The "Mono gate" is a whole-process gate, not a
code-region gate — flags land in every library of a Mono title.

Audit found two real classifier holes, both fixed by changing WHAT the auto
clamp fires on (detection unchanged): auto sites now clamp only on **signed**
overshoot **> 2^30** past the bound. Negative inductions (unsigned-above for
their whole legit run) never fire; multi-exit scan loops (a second early-exit
edge is allowed — Ziggurat's own loop has one) can legitimately overshoot a
little but never by 1 GiB natively (fault first). All captured wedge RBX
values (1.3-53 GB past bound=4) clear the margin. Manual ranges keep the
exact immediate UGT clamp. Detection logging deduped per distinct CMP PC
(was 86% of the RimWorld log).

Gotcha: when a FEXServer is already running, one-off FEX runs route their
log lines to it (they appear in the live session's log) — an empty stderr
under FEX_SILENTLOG=0 is routing, not silence.

Still open (audit item D): the clamp emits Select+store on every execution
of each flagged compare — ~1000 sites including hot libc loops; worth a
benchmark A/B before calling the default final.

Intriguing lead for the ROOT CAUSE (from the user's "41 or 43" recollection
of the FEX arm64 talk): 0x41/0x43 are REX.B / REX.X|REX.B prefixes, and FEX
has release-note history of REX misapplication; the loop's invariant regs are
all REX-extended (R12/R14/R15) and the post-exit code indexes a load with RBX
via SIB (REX.X territory). A decode slip in the instruction that INITIALIZES
RBX would produce exactly "correct loop, garbage entry value". Check from the
FEX decoder side (dump decoded IR for [0x934a40, 0x934d15)) — the game binary
itself stays off-limits.
