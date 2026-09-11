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
