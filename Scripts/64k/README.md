# `Scripts/64k` — tooling for the 64K-page port

Support for the effort described in `docs/PAGE_SIZE_64K_PLAN.md` (design) and
`docs/PAGE_SIZE_64K_EXECUTION.md` (schedule). The goal is one binary, built
once, that runs on the 4K kernel (op4k) and the 64K kernel (op64k) with the
host page size treated as a runtime quantity.

These notes live here rather than in `notes/64k/` because `notes/` is
gitignored (`.gitignore`) and this material has to travel with the branch.

## Contents

| file | what it is |
|---|---|
| `pageprobe.c` | host page-size facts: `AT_PAGESZ`, `sysconf`, `sbrk(0)` alignment, `MAP_FIXED_NOREPLACE` hints for 2^44..2^52, and whether 4K-granular `MAP_FIXED`/`mprotect`/`munmap` succeed. Build: `cc -O2 -o pageprobe Scripts/64k/pageprobe.c` |
| `governor-performance.sh` | sets the `performance` governor on all CPUs (needs root). op64k boots `ondemand`; run this before recording any number. `--show` just reports. |
| `kernel-ab.md` | written procedure for the kexec A/B between the 4K and 64K kernels on op64k, and the constraint (64K-block root) that limits what the 4K side can run. |

## S1: what landed and why

`External/jemalloc_glibc/pregen/include/jemalloc/internal/jemalloc_internal_defs.h`
baked `LG_PAGE 12`. jemalloc's `pages_boot()`
(`External/jemalloc_glibc/src/pages.c:765`) compares the detected `os_page`
against the compile-time `PAGE` and aborts when the host page is *larger*:

```
<jemalloc>: Unsupported system page size
terminate called without an active exception
```

That abort happens during static init, before `main`, so it is untouched by
`FEX_ALLOW_UNSUPPORTED_PAGE_SIZE` or any FEX config. It was the first thing
that died on op64k — before any FEX code ran.

A host page *smaller* than the compiled page is fine (only `os_page > PAGE` is
rejected), so `LG_PAGE 16` serves both kernels from one build. Fedora and Arch
ship jemalloc on aarch64 exactly this way. `LG_HUGEPAGE` is a separate,
unrelated knob and stays at 21.

`LG_PAGE` is the only compile-time page knob in the vendored tree; `PAGE`,
`SC_LARGE_MINCLASS`, `SC_LG_SLAB_MAXREGS`, the `sz_*` quantisation tables and
`RTREE_NLIB` are all derived from it. There is no CMake option or second
pregen header encoding a page size.

The 4K cost is RSS granularity inside the glibc-hook allocator, which every
host-native library uses (mesa, RADV, X client libs). Per
`PAGE_SIZE_64K_EXECUTION.md` §S1 this must be priced on op4k (microbench trio
plus a CP2077 nw lap set) before it ships to the gaming build. If it costs more
than noise the fallback is a runtime-`LG_PAGE` patch to `pages.c` that we would
carry, never a second build directory.

FEXCore's own allocator is rpmalloc and was never the problem: its config
defaults to a 64K page (`FEXCore/Source/Utils/AllocatorHooks.cpp:105-107`) and
every `InitializeAllocator`/`SetupHooks` caller feeds it `sysconf(_SC_PAGESIZE)`.

## S1 smoke result on op64k (2026-09-11)

```
FEX_ALLOW_UNSUPPORTED_PAGE_SIZE=1 FEX_SILENTLOG=0 FEX_OUTPUTLOG=stderr \
  Bin/FEX /usr/bin/true
```

The jemalloc abort is gone. FEX now reaches `CheckHostPageSize`
(`Source/Tools/FEXInterpreter/FEXInterpreter.cpp:319`), prints the WARNING form
of the gate, continues, and dies in FEX code — the S1 exit criterion.

It does **not** die first in the call-ret guard, as the plan predicted. It dies
earlier, in the 48-bit steal allocator, which the S0 probe warned would engage:

```
mmap(0x800000000000, 140737488355328, PROT_NONE, ...MAP_FIXED_NOREPLACE) = 0x800000000000
mmap(0x800000000000, 4096, PROT_READ|PROT_WRITE, ...MAP_FIXED) = 0x800000000000
mprotect(0x800000001000, 67108864, PROT_READ|PROT_WRITE) = -1 EINVAL   <- ignored
...
mprotect(0x800004001000, 4294971392, PROT_READ|PROT_WRITE) = -1 EINVAL <- ignored
--- SIGSEGV {si_code=SEGV_ACCERR, si_addr=0x800004001000} ---
```

Mechanism, for S2:

1. `make_alloc_unique` (`FEXCore/Source/Utils/Allocator/64BitAllocator.cpp:602-617`)
   carves a `FEX_PAGE_SIZE` (4096) page off the front of the stolen region for
   the allocator object and advances `Base.Ptr` by it. Every subsequent base in
   that region is therefore 4K-aligned but not 64K-aligned.
2. `OSAllocator_64Bit::MakeRegionActive` (`:167`) then calls
   `mprotect(ReservedRegion->Base, SizePlusManagedData, PROT_READ|PROT_WRITE)`
   on that misaligned base. On a 64K host the kernel returns EINVAL.
3. The result is only checked by `LOGMAN_THROW_A_FMT` (`:168`), which compiles
   out under `-DENABLE_ASSERTIONS=False` — the shipping configuration. The
   failure is silent.
4. The placement-new of `LiveVMARegion` at `:172` then writes to memory that is
   still `PROT_NONE`, and the process takes `SEGV_ACCERR`.

So this is the unchecked-mprotect class the plan describes, but the first
instance to fire is the allocator's, not the call-ret stack's
(`Source/Tools/LinuxEmulation/LinuxSyscalls/ThreadManager.cpp:379`), which is
never reached.

Two related observations from the same trace:

- `static_assert(sizeof(LiveVMARegion) == FEX_PAGE_SIZE)`
  (`64BitAllocator.cpp:143`) is the assert the plan's S2 item 5 relaxes to
  `<=`; the header stride also has to become the host page, otherwise step 1
  above keeps producing the misaligned base.
- `DetermineVASize` (`FEXCore/Source/Utils/Allocator.cpp:108`) probes
  `Size - FEX_PAGE_SIZE * i` for `i` in 0..63. On a 64K host all 63 non-zero
  `i` probes return EINVAL; only `i == 0` is host-aligned and can succeed. The
  function still returns the right answer here, but purely by luck of the
  first probe, and it no longer tolerates a host that has something mapped at
  exactly `1 << Bits`. Stepping in host pages is S2 item 6.
