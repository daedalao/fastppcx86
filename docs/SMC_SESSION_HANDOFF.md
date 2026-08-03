# SMC storm work — session handoff (2026-08-02/03)

Living document for continuing the SMC invalidation-storm work. Written at the end of
the session that brought Proton + Cyberpunk 2077 + Portal 2 up under FEX on op4k
(POWER8 — the "power9" branch name is the other dev's machine; **all codegen must stay
POWER8-legal**). Read this top to bottom before touching anything.

## Branch state

- `power9` (GitHub): upstream of record. NOTE: a local clone can silently be ~43
  commits stale — `git fetch` before reasoning about "unpushed" work. The atomics
  series (`atomics-C0/C1`, misaligned-CMPXCHG8B split-lock) IS on GitHub and was
  audited clean of POWER9-only instructions.
- `smc-store-emulation` (GitHub, commit 3cdb469bf + build fixes 19f3b3870): **v1** —
  per-store emulation via decode + pwrite(/proc/self/mem) when the write doesn't
  overlap compiled code. CORRECT (all smcstorm checksums OK) but a measured
  regression on bursts: every store faults, nothing amortizes. Keep for reference;
  do not enable in games.
- `smc-v2-deferred-reval` (LOCAL ONLY, workstation, commit ff8497b7d): **v2** —
  unprotect + queue page + invalidate-at-safepoint. **DO NOT BUILD — unsound.**
  No per-block content hashes exist in the tree, so "revalidate" degrades to
  invalidate-at-drain, and drains (next fault / next syscall) can happen after a
  same-thread patch-then-call has already executed stale code. Would fail
  smcstorm patchloop's checksum and would feed CP2077's runtime-codegen arena
  stale blocks. Its investigation notes (safepoint analysis, the
  MarkGuestExecutableRange lock hazard) are valid and worth reading in the commit.

## The design to implement next: v3 "soft-invalidate + validate-relink"

1. At compile time, hash each block's guest source bytes (xxhash is vendored in
   External/xxhash) — store in JITCodeTail or BlockEntry.
2. On SMC write fault: unprotect page, **soft-invalidate** its blocks = delink from
   L1/L2 lookup WITHOUT freeing the compiled code (BlockList entry stays).
3. Next execution misses fast lookup → slow path finds the retained block →
   compare stored hash vs current guest bytes → relink unchanged blocks (µs),
   recompile only genuinely modified ones.
4. Re-protect the page at relink/recompile time (code on page is live again).

Sound for same-thread SMC (visibility gated on dispatch, matching x86 branch
semantics), burst-amortized like legacy, recompiles only real changes. Fixes both
storm classes measured below.

## Measurements that anchor everything (op4k, POWER8, SMT4)

smcstorm suite (source: Proton-session scratchpad, binary at /tmp/smcstorm on op4k;
rebuild: gcc -O1 -pthread on any x86-64 box, it is a guest binary):

| scenario   | native x86 | FEX legacy | FEX v1 flag-on |
|------------|-----------:|-----------:|---------------:|
| falseshare | 16.2M/s    | 42K/s      | TIMEOUT (worse)|
| patchloop  | 55.1M/s    | 47K/s      | 47K/s (fallback)|
| crossthread| 327M/s     | 10.8M/s    | 392K/s (worse) |
| wxflip     | 363K/s     | 51K/s      | 51K/s          |

Storm cycle ≈22µs = fault + page-invalidate + recompile. Legacy amortizes bursts
via unprotect; that amortization must be preserved.

CP2077 audit histogram (FEX_SMC_AUDIT=<path>, runtime env, zero code needed):
55K invalidations spread ~uniformly (~90/page) over thousands of PRIVATE low-address
(0x08-0x0Axx_xxxx heap) pages = runtime-generated code arena churn, NOT single-page
ping-pong. v1's fast path fired 0 times (fallback reasons unlogged — an audit line
for fallback-reason is a wanted 3-line patch).

## Infrastructure on op4k

- Real git clone: ~/projects/fex-emu-ppc64le/src-smc (remote `booksmain` =
  ssh://booksmain/home/books/Projects/power8/fex-ppc64le). Build dir: ../build-smc
  (clang, RelWithDebInfo, ninja). **Build FEXServer + tools too, not just
  FEX/FEXBash** — missing FEXServer = silent "Expect errors!" launch failure.
  Submodules were copied from src/wt-power9 (workstation clone has them empty).
- Boot-test harness: /tmp/cp-boottest.sh (window-id-delta verdicts; kill patterns
  MUST live in script files, never in ssh command strings — self-kill hazard).
- Proton launcher: ~/fex-scripts/fexproton (FEX9_BIN_DIR selects build).
  CP2077 needs WINEDLLOVERRIDES="icuuc,icuin,icuio=n" and VKD3D/DXVK
  FILTER_DEVICE_NAME=V620.

## Open questions

1. Boot-crash (AV reading 0x300000073, pre-menu, once): nondeterministic; 3×
   flag-ON boot sampling was in flight when this session ended — rerun via
   `for n in 1 2 3; do /tmp/cp-boottest.sh ~/projects/fex-emu-ppc64le/build-smc/Bin FEX_SMCSTOREEMULATION=1; done`
   Suspects: atomics series first game exposure vs. coincidence. v1 code is
   read-only+fallback on that path and unlikely.
2. Audio corruption class (buzz→silence in CP2077, channel-drop/distortion in
   Portal 2, Stardew): NOT SMC. Untested lever: FEX_VECTORTSOENABLED=1
   FEX_MEMCPYSETTSOENABLED=1.
3. CP2077 lifepath-gate hang (the original storm livelock): expected fixed by v3;
   regression test = boot + character creation + lifepath transition.
