# Running on a 64K-page kernel: review findings and port design

Companion to [PAGE_SIZE_AUDIT.md](PAGE_SIZE_AUDIT.md) (a4b9668b9, 2026-08-16),
which classified all 245 `FEX_PAGE_SIZE` grep hits. This document is the result
of a second, independent read of the tree (2026-08-17, source-only — nothing
here was executed): first what that read confirmed, corrected, and found that
the audit missed; then the design that makes a 64K host actually work.

Why we want this at all: POWER8 has no radix MMU. Every page is a hash-table
entry, and a 4K kernel spends 16x the HPT slots and TLB entries that a 64K
kernel does for the same working set. 64K is the ppc64le distro default for a
reason; being 4K-only makes us the odd deployment out.

---

## Part 1 — review of the audit

### Confirmed (read at today's HEAD, line-exact)

- `InterruptFaultPage` layout trap and the five unchecked `mprotect` sites.
- The JIT pokes the fault page with a **D-form `stb` whose displacement is
  computed from `offsetof`** — `JIT.cpp:2963-2969` and
  `PPC64Dispatcher.cpp:465-470`, both guarded by `static_assert`s that document
  the layout dependence. A 16-bit signed displacement cannot reach a page-sized
  offset at 64K; this is an encoding failure before it is a layout failure.
- Call-ret shadow stack: `ThreadManager.cpp:354` (`+ 2 * FEX_PAGE_SIZE`) and
  `:378-379` — `CallRetStackBase = AllocBase + 4096` then an **unchecked**
  `mprotect`. First guest CALL faults. Confirmed verbatim.
- Code-buffer guard `CPUBackend.cpp:381-383`: confirmed, with one nuance the
  audit undersold in our favor — the failure *is* logged (`EFmt`), so unlike
  the callret site it is at least visible.
- `Source/Tools/FEXInterpreter/SignalDelegator.cpp` is dead code: confirmed,
  `FEXInterpreter/CMakeLists.txt` builds only `FEXInterpreter.cpp` and
  `AOT/AOTGenerator.cpp`.
- The allocator plumbing/policy split (`InitializeAllocator`/`SetupHooks`
  parameterised, both concrete allocators ignore it): confirmed.

### Corrections

1. **`SyscallsSMCTracking.cpp:460` (and the `UnprotectRegionCallback` uses at
   `:439-441`, `:506-508`) are misclassified as GUEST.** The *invalidation*
   argument is a guest quantity, but `UnprotectRegionCallback(FaultBase,
   FEX_PAGE_SIZE)` bottoms out in a host `mprotect` of 4096 bytes — HOST, and
   it fails on a 64K kernel. Worse, the fix is not mechanical: see the mtrack
   soundness rule in Part 2 §5. This is the one place where the audit's
   bucketing, taken literally, would produce a wrong port.

2. **The fault-page consumer list is incomplete.** Beyond the five `mprotect`
   sites, the fault page is a cross-thread *protocol*: `FEX_SMCLAZYLINK` arms
   the **writer's** fault page from another thread's SMC fault
   (`SMCLazyInvalidate.h:204-210`, `Syscalls.cpp:1176`), thread teardown
   triggers delivery through the refcount-destructor store
   (`Syscalls.cpp:1405-1411`), and the SIGSEGV handler *identifies* a
   fault-page fault by address comparison. Any layout change must update the
   identification predicate and every arming site together, not just the JIT
   stores.

### New findings (not in the audit)

3. **`ELFCodeLoader::MapFile` breaks on file *offsets*, not just addresses**
   (`ELFCodeLoader.h:84-86`). `off = p_offset - PAGE_OFFSET(p_vaddr)` is
   4K-congruent by construction; host `mmap` requires `offset % hostpage == 0`.
   x86-64 toolchains emit `p_align = 0x1000`, so **FEX's own loader — not
   guest ld.so — is the first casualty**: `execve` of anything dynamic fails at
   the first PT_LOAD with a nonzero offset. Every plan that starts with "the
   guest mmap path needs a shadow table" is missing that the loader runs first.
   Same class: `x32/Memory.cpp:43` — guest `mmap2`'s offset unit is 4096 **by
   x86 ABI** (that constant is GUEST and stays), but the product
   `pgoffset * 0x1000` becomes a host file offset with the same congruence
   problem.

4. **4K-granular ASLR feeds `MAP_FIXED_NOREPLACE`** (`ELFCodeLoader.h:587`
   computes the slide in FEX_PAGE units, `:479` maps the stack at the result).
   On a 64K host the slide must be host-granular; losing 4 bits of entropy is
   the whole cost.

5. **UNKNOWN #1 mostly resolves by reading the kernel's VA layout rules.**
   `DetermineVASize` (`Allocator.cpp:108-146`) probes `MAP_FIXED_NOREPLACE` at
   descending hint sizes; `Setup48BitAllocatorIfExists` engages at `>= 48`
   bits. On hash-MMU ppc64le the addressable ceiling depends on the page size:
   a 4K hash kernel tops out at 2^46, so **the 48-bit steal allocator never
   engages on op4k today** — which explains why its wholly-4K internals have
   never hurt us. A 64K hash kernel accepts high hints (128T default region,
   larger with an explicit hint), so on the 64K boot the probe at 2^48/2^52
   plausibly *succeeds* — i.e. the 4K-granular `OSAllocator_64Bit` engages
   **precisely and only on the host that cannot run it**. One `mmap` probe on
   op64k settles it; until then the port must treat 64BitAllocator as
   in-scope. (Also note the probe itself steps in `4096*i` decrements —
   15 of 16 iterations are spurious `EINVAL` on 64K, i=0 carries it.)

6. **The mtrack fault decoder's msync probes** — `SignalDelegator.cpp:928,949`
   `msync(page, 0x1000, MS_ASYNC)` with a 4K-masked address. Diagnostics-only
   (crash-dump code/stack excerpts) — on 64K they misreport "<unmapped>".
   Low severity, but it degrades exactly the diagnostics you need while
   bringing the port up, so fix it in phase 1 while touching the file.

7. **`CodeCache.cpp:1404-1405` uses literal `0x1000`** for the mapped-cursor
   alignment (the audit caught the `FEX_PAGE_SIZE` pad at `:1124-1131` but the
   literal escaped the grep). Same decision as the pad: on-disk format.

8. **Guest pthread stacks make sub-granule mprotect the COMMON case, not a
   corner.** Guest glibc sizes thread-stack guard pages from `AT_PAGESZ`
   (4096) and mprotects a 4K `PROT_NONE` guard at the low end of every thread
   stack. Under any threaded guest — i.e. every game — the shadow-table path
   in Part 2 is exercised at every `pthread_create`. Design for it as the hot
   path, not the fallback.

9. **Ungated binaries**, extending the audit's note: `TestHarnessRunner`,
   `FEXOfflineCompiler`, `FexBridge`, `Wow64Probe` (audit had these), plus
   `FastPPCx86Launcher` (reads `sysconf` correctly at `LaunchSpec.cpp:613`,
   host-side only — clean, listed for completeness).

### Verified-benign (so nobody re-litigates them)

- PPC64 JIT backend literals: `JIT.cpp:1048` `addi(r1, r1, -4096)` is a
  4096-**byte** scratch frame (stack arithmetic, not a page);
  `0x1000` thresholds at `:1932/2359/2385` are near-NULL guest sanity checks;
  `DISPATCHER_CODE_SIZE = 65536` is a buffer size. None are page-coupled.
- `Context.h:347` `SMCPageCounterSlots = 4096` — hash-table slot count.
- dcbz/`FEX_MEMCPYDCBZ` tiers operate on 128-byte cache lines — page-neutral.
- `PROT_SAO`/HWTSO: SAO is a per-PTE attribute on hash and works at 64K;
  the *paths* that apply it ride the guest-mprotect flow and inherit whatever
  Part 2 does; no SAO-specific work.

---

## Part 2 — the port design

The audit's option (b) — "shadow protection table" — is correct but is a
sentence standing in for the actual system. This is the system.

### 0. Two constants, one new module

Split `FEX_PAGE_SIZE` into:

- `FEX_GUEST_PAGE_SIZE` — `constexpr 4096`. Guest ABI. The GUEST bucket
  (53 sites) renames to this and never changes.
- `FEXCore::HostPage::Size()/Shift()/Mask()` — runtime, initialised once
  before any mapping (first line of `main`, before `DisableSBRKAllocations`,
  which itself must switch to it — audit break-order item 1).

The BOTH sites are then *forced* through a decision at the type level: every
use site names one or the other, and a grep for the old name reaching zero is
the completion criterion for the mechanical phase. No site keeps the old name.

### 1. `InterruptFaultPage` moves out of the struct

Replace the embedded array with an externally-allocated **host page** whose
address lives in `CpuStateFrame`:

```
CpuStateFrame {
  ...
  uint8_t* InterruptFaultPagePtr;   // one host page, mmap'd per thread
}
```

- JIT pokes become `ld TMP, faultptr_off(STATE); stb r0, 0(TMP)` — two
  instructions instead of one at the three emission sites
  (`JITClass.h:1081` helper, `PPC64Dispatcher.cpp:488`, `JIT.cpp:2969`).
  The D-form displacement problem disappears because the displacement is now
  a frame offset, not a page offset.
- The five arming/disarming `mprotect`s take the pointer and
  `HostPage::Size()`. They can finally *check the return value* by storing a
  result flag; the async-signal-safety constraint only forbids logging, not
  remembering.
- The SIGSEGV identification predicate compares against the stored pointer.
- SMC lazy-link arms the writer's page through the same pointer — the
  cross-thread protocol is unchanged, only the address source moves.
- `InternalThreadState` drops to whatever size it is; the
  `alignas`/`static_assert`s go. `BaseFrameState` reachability asserts stay,
  rewritten against the new layout.

Cost: one dependent load on the deferred-signal exit path (uncontended,
L1-resident — the frame line is already hot). This is the single structural
change that unblocks break-order items 2 and 3, and it is safe to land **now,
on the 4K build**, because it is page-size-neutral. Same treatment for the
call-ret guard: allocate `CALLRET_STACK_SIZE + 2*HostPage::Size()` and place
the base at `AllocBase + HostPage::Size()` — the bounds mirrors from
60afed914 already read the computed values, so only the allocation site
changes.

### 2. The granule table: extend VMATracking, don't build a parallel thing

FEX already tracks every guest VMA (`SyscallsVMATracking.h`) under the
VMATracking mutex, on every guest memory syscall. The shadow state is two
additions to that existing structure, not a new subsystem:

- per guest-4K-page **intended protection** (2 bits packed, R/W/X as the
  guest requested it),
- per host granule (64K = 16 guest pages) the **materialised host
  protection**.

Invariant: `host_prot(granule) = union of intended_prot over its 16 guest
pages, plus whatever SMC/mtrack has overlaid`. "Union" = most permissive:
nothing the guest believes writable may ever fault for granularity reasons.
The consequence — protections *stricter* than the granule union are tracked
but not enforced — is the soft-protection tier, and its correctness envelope
is stated in §6.

Guest syscall semantics on top:

- `mmap(NULL, ...)` (anon): pass through with host-granular length. Guest
  sees 64K-aligned result — legal, 64K is 4K-aligned. **No emulation.** This
  is most mmaps by count.
- `mmap(MAP_FIXED)` at host-aligned addr/offset: pass through.
- `mmap(MAP_FIXED)` at 4K-but-not-64K-aligned addr (guest ld.so, wine PE
  loader): the containing granules are (re)mapped anon-RW if not already
  private, file content `pread` into place, granule table updated. Private
  file mappings lose page-cache sharing; that is an RSS cost, not a
  semantics cost. `MAP_SHARED` at unrepresentable alignment cannot be
  emulated by copy — refuse with `EINVAL` and log loudly; survey says this
  is rare (X SHM segments and GL buffers arrive host-aligned because *we*
  allocate them).
- `munmap` of a sub-granule range: granule stays mapped if any sibling page
  is live; the unmapped pages' intended prot goes to NONE (soft), contents
  `madvise(MADV_DONTNEED)`-equivalent scrubbed only if the whole granule
  empties. `/proc` fiction (§7) hides the difference.
- `mprotect` sub-granule: update intended prot, rematerialise the union.
- `mremap` over mixed granules: decompose into (copy | remap) using the same
  primitives; the gvisor wart tests already document the kernel's own
  laxities here, so exotic corners may EINVAL with a clear conscience as
  long as plain grow/shrink/move works.
- `brk`: round the emulated break region to host granules internally; report
  4K-granular `brk` values to the guest (the audit's GUEST rounding at
  `Syscalls.cpp:1047,1061` stays).

### 3. The loader learns the same trick first

`MapFile` gets the identical fallback inline (it cannot use the guest-syscall
path — it runs before the syscall handler exists): if `addr | off` is not
host-aligned, anon-map the span and `pread`. BSS zeroing (`:167-187`) must
then zero `[filesz, page_end)` explicitly — the current code inherits the
kernel's zeroing of the mapped page tail, which the `pread` path does not
provide. ASLR slide generation moves to host-granular. `AT_PAGESZ` stays
4096 — that is the entire point.

### 4. Allocators

- `OSAllocator_64Bit`: parameterise `PageShift` throughout (it is a
  self-contained file; every listed line is `<<`/`>>`/`&` against the same
  constants). Its bitmap semantics survive intact at 64K granularity, and the
  region-header `static_assert(sizeof(LiveVMARegion) == page)` relaxes to
  `<=` with the header stride becoming `HostPage::Size()`.
- 32-bit `LinuxAllocator`: keep the 4K-granular *accounting* bitmap (guest
  addresses are a guest concept) but allocate/free against the kernel in
  host granules — i.e. it becomes the first client of the §2 table rather
  than a second implementation of it. Defer to phase 4; 64-bit guests first.
- Guard pages (`CPUBackend.cpp:381,:700`, `ThreadPoolAllocator.h:420`,
  altstack `SignalDelegator.cpp:1967`): host-granular length and alignment;
  buffer sizes grow by one granule where the guard was carved from the
  allocation. Mechanical.

### 5. SMC/mtrack on 64K granules — the soundness rule

mtrack write-protects guest code pages and invalidates on fault. At 64K the
protect/unprotect quantum is 16 guest pages, so:

> **Whatever range you unprotect, you must invalidate or re-arm every
> tracked guest page inside it.** Unprotecting a granule to service one 4K
> fault while leaving 15 sibling pages' JIT blocks live and their protection
> gone is silent SMC breakage — the exact class this port has spent a month
> exterminating.

Concretely `UnprotectRegionCallback` widens to the granule, and the fault
path iterates the granule's tracked pages: invalidate the faulting page,
*re-arm decision* per sibling (invalidate too, or re-protect the granule
after the write window — same choice mtrack already makes per page, just
batched). Expect real thrash on mixed code/data granules (Mono, wine PE
sections put both in 64K easily); mitigations in order of effort:
`FEX_SMCCHECKS=full` as the correctness fallback, the existing
soft-invalidate path (`SMCSoftInvalidate.h` hashes are guest-4K and stay),
and only then anything clever. The 08-16 aligned-tier/detector work is
granularity-independent (line-based), confirmed by reading.

### 6. What soft protection cannot do — the honest envelope

With union-permissive granules, a guest that *relies on receiving SIGSEGV*
from a protection it set on a sub-granule range will not get one:

- glibc pthread stack guards (finding 8): overflow sails through. Failure
  mode equals a wild overflow today; acceptable.
- **Wine's committed-stack guard-page growth and PE `PAGE_GUARD` semantics:
  not acceptable** — Windows code observes guard faults as API behaviour.
  This is the one consumer that forces the full-strength tier:
  **fault-reflection** — back guest anon memory with `memfd` so FEX can hold
  a second RW view; set the granule to the most *restrictive* union instead;
  on fault where the shadow says "guest allowed this access", perform the
  access through the mirror (or flip-protect under the VMATracking lock) and
  resume; where the shadow says "guest wanted a fault", deliver the guest
  SIGSEGV. Per-granule policy bit chooses permissive (fast, common) vs
  restrictive (correct for fault-consumers), flipped the first time a guest
  arms a fault-bearing protection in that granule.
- Phase it: permissive-only gets Linux-native games up; restrictive tier
  gates Wine/Proton titles.

### 7. Guest-visible reporting

- `AT_PAGESZ=4096` already correct by construction.
- `mincore`/`msync`/`madvise` grow shims that answer from the granule table
  at guest-4K granularity (mincore's vector is per-guest-page; today's raw
  passthrough at `Passthrough.cpp` both mis-sizes the vector and EINVALs on
  4K alignment).
- `/proc/self/maps`/`smaps` for the guest should be synthesized from
  VMATracking rather than passed through — this is the same fiction
  discipline as the dense-CPU-id work (getcpu remap, c6b0180d3): **every
  id/granularity the guest can observe must come from the fiction, not the
  host.** Today's host passthrough is already wrong on 4K (audit noted it);
  the 64K port makes it load-bearing because sub-granule munmap holes exist
  only in the table. Wine reads maps at startup.
- Code cache (NCS): pad sections to a fixed 64K worst case (≤60K/section,
  cheap) and fold the host page size into the cache identity hash — caches
  then stay portable in the only direction that matters (a 64K-padded cache
  loads fine on 4K).

### 8. Phasing, with completion criteria

| phase | contents | done when |
|---|---|---|
| **P0** (now, on 4K) | constant split; fault-page pointer redesign (§1); callret guard redesign; guard pages host-granular; msync-diag fix; `DetermineVASize` host-granular probe | 4K build byte-for-byte behaviourally unchanged; grep for unsplit constant = 0 |
| **P1** | loader pread fallback + host-granular ASLR + brk; SBRK site; 64BitAllocator parameterised; gate downgraded to warning behind `FEX_ALLOW_UNSUPPORTED_PAGE_SIZE` | static + dynamic hello-world and `nproc` run on op64k with `FEX_SMCCHECKS=full` |
| **P2** | §2 granule table in VMATracking; mmap/mprotect/munmap/mremap emulation (permissive tier); mincore/msync shims; maps synthesis | glibc test battery + a Linux-native title (Factorio-class) on op64k |
| **P3** | mtrack granule soundness (§5) | SMC titles (Mono/Unity) on op64k without `SMCCHECKS=full` |
| **P4** | restrictive tier + memfd mirrors (§6); 32-bit allocator; cache portability | Wine/Proton title boots on op64k |

P0 is the only phase that touches the shipping 4K build, is
page-size-neutral by construction, and removes the two structural items that
gate everything else — it is landable and gauntlet-verifiable this week.
Everything after P0 is additive behind the host-page check and cannot
regress op4k. Ordering within phases follows the audit's what-breaks-first
list, which this read confirms with one insertion: the loader file-offset
fallback (finding 3) belongs before any guest-syscall work, or nothing
dynamic ever loads to exercise it.

### Open questions for the first op64k session (one command each)

1. `FEXCore::Allocator::DetermineVASize()` equivalent probe — does a plain
   `mmap` hint at `1ULL<<48` succeed on the 64K hash kernel? (settles the
   64BitAllocator scope, finding 5).
2. `sbrk(0)` alignment at main (audit UNKNOWN #2).
3. `getauxval(AT_PAGESZ)` under the 64K kernel's own loader for FEX itself —
   confirms nothing in *our* host link assumes 4K (lds scripts don't; glibc
   handles it).
