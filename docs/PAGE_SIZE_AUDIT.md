# Host page size audit (ppc64le port)

`FEXCore::Utils::FEX_PAGE_SIZE` is a `constexpr size_t = 4096` in
`FEXCore/include/FEXCore/Utils/TypeDefines.h:9`, with `FEX_PAGE_SHIFT = 12` and
`FEX_PAGE_MASK` derived from it. That one constant is doing **two unrelated
jobs**, and nothing in the tree distinguishes them:

| | job | correct value | changes on a 64K host? |
|---|---|---|---|
| **guest** | the page granularity the *x86 guest* sees | 4096, forever | no |
| **host** | the granularity real `mmap`/`mprotect` demand | host page size | **yes** |

The guest is x86 and is handed `AT_PAGESZ=4096`. That never changes. Everything
FEX hands to the *kernel*, however, has to be host-granular, and today it isn't.

> ⚠ **FEX currently refuses to start on a non-4K host.** The gate is
> `FEX::Kernel::PageSize::CheckHostPageSize` in
> `Source/Tools/FEXInterpreter/FEXInterpreter.cpp`, called first thing in
> `FEX::Kernel::Init` — before any `InternalThreadState` exists and before any
> guest mapping. `FEX_ALLOW_UNSUPPORTED_PAGE_SIZE=1` downgrades it to a warning
> and continues; expect a crash or a hang. This document is what makes the real
> port schedulable.
>
> **Gate coverage is the `FEX` binary only.** `TestHarnessRunner`
> (`Source/Tools/TestHarnessRunner/TestHarnessRunner.cpp:311`) and
> `FEXOfflineCompiler` build a `SyscallHandler` without ever calling
> `FEX::Kernel::Init`, so they are ungated and will still wedge. `FexBridge` and
> `Wow64Probe` likewise. Worth closing when someone touches those tools; not
> worth a cross-cutting change now, since none of them is a guest-hosting
> production path.

---

## Summary

| bucket | sites | meaning |
|---|---|---|
| **GUEST** | 53 | guest page granularity. Stays 4096. No work. |
| **HOST** | 119 | feeds a real `mmap`/`mprotect`/`munmap`/`madvise`/`mremap`. Must become runtime. |
| **BOTH** | 41 | conflated today. A 64K port has to split these, and each split needs a decision. |
| **STRUCTURAL** | 10 | baked into a layout, `alignas` or `static_assert`. Cannot be made runtime without changing the layout. |
| **already clean** | 8 | reads `sysconf(_SC_PAGESIZE)` and uses `FEX_PAGE_SIZE` only as a fallback. |
| | **231** | total classified use sites, across 39 files |

Plus 3 definition lines in `TypeDefines.h`, 2 comment-only mentions, and 9 lines
of the startup gate itself — 245 `grep` hits in total, all accounted for. Three
sites are additionally flagged **UNKNOWN**; they are counted in the buckets above
under a best guess and listed with their reason at the bottom.

The headline is the STRUCTURAL bucket. It is only 10 sites, but it is the reason
this is a port and not a search-and-replace: no amount of making constants
runtime fixes a `static_assert` on a struct's size.

---

## STRUCTURAL — the blocking ones

These cannot be fixed by making a constant runtime. Each one changes a layout.

| site | what it is | why it blocks |
|---|---|---|
| `FEXCore/include/FEXCore/Debug/InternalThreadState.h:130` | `alignas(FEX_PAGE_SIZE) uint8_t InterruptFaultPage[FEX_PAGE_SIZE]` | **the archetype.** See below. |
| `FEXCore/include/FEXCore/Debug/InternalThreadState.h:91` | `struct alignas(FEX_PAGE_SIZE) InternalThreadState` | the struct's own alignment is 4K, so `new` never returns a 64K-aligned object |
| `FEXCore/include/FEXCore/Debug/InternalThreadState.h:133-135` | `static_assert` that `InterruptFaultPage` is within `FEX_PAGE_SIZE` of `BaseFrameState` | **the sharpest edge.** The JIT pokes the page with `stb(r0, FaultOff, STATE)` (`JIT.cpp:2890`, and `PPC64Dispatcher.cpp:488` off the offset computed at `:465`), a D-form store whose displacement field is **signed 16-bit**. At `FEX_PAGE_SIZE = 4096` the offset fits easily; at 65536 it does not, so this is an *encoding* failure, not just an assert. |
| `FEXCore/include/FEXCore/Debug/InternalThreadState.h:136` | `static_assert(sizeof(InternalThreadState) == FEX_PAGE_SIZE * 2)` | pins the whole object to exactly two pages |
| `FEXCore/Source/Common/JitSymbols.h:16` | `BUFFER_SIZE = FEX_PAGE_SIZE - (8 * 2)` | buffer sized to fill exactly one page |
| `FEXCore/Source/Common/JitSymbols.h:31` | `static_assert(sizeof(JITSymbolBuffer) == FEX_PAGE_SIZE)` | ditto |
| `FEXCore/Source/Utils/Allocator/64BitAllocator.cpp:101` | `alignas(FEX_PAGE_SIZE) FlexBitSet<...> UsedPages` | region header alignment |
| `FEXCore/Source/Utils/Allocator/64BitAllocator.cpp:143` | `static_assert(sizeof(LiveVMARegion) == FEX_PAGE_SIZE)` | the VMA region header is exactly one page and is placed at the head of each slab |
| `FEXCore/Source/Interface/Core/CPUBackend.h:67` | `UsableSize() { return AllocatedSize - FEX_PAGE_SIZE; }` | the guard page is *one page* by contract; pairs with `CPUBackend.cpp:381` |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/ThreadManager.cpp:354` | `CALLRET_STACK_ALLOC_SIZE = CALLRET_STACK_SIZE + 2 * FEX_PAGE_SIZE` | guard pages either side of the call-ret stack, at 4K |

### The archetype: `InterruptFaultPage`

`InternalThreadState` is `alignas(4096)`, is exactly 8192 bytes, and puts
`InterruptFaultPage` in its second 4K — so `offsetof` is 4096. On a 64K host the
allocation is at best 4K-aligned, so `&Thread->InterruptFaultPage` is **4K-aligned
but not page-aligned** and every `mprotect` on it returns `EINVAL`:

- `Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.cpp:1032` — arm (`PROT_NONE`)
- `Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.cpp:1316` — disarm on fault
- `Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.cpp:1389` — re-arm
- `Source/Tools/LinuxEmulation/LinuxSyscalls/SyscallsSMCTracking.cpp:490` — arm from the SMC fault path
- `FEXCore/Source/Interface/Core/Core.cpp:599` — teardown, via `Allocator::VirtualProtect`

**None of these check the return value**, and none of them can: the first four run
on signal-delivery paths where `LogMan::Msg::*` is not async-signal-safe. The
deferred-signal fault page never arms, async signals never drain, and the guest
hangs with no diagnostic. That is the failure mode the startup gate exists to
replace.

It is **not fixable by rounding the length up.** A 64K-granular protection would
also cover `BaseFrameState` — the guest register file the JIT addresses through
r27/STATE — plus ~56K of whatever the allocator placed after the struct. The
layout has to change.

> ⚠ Stale copies at `Source/Tools/FEXInterpreter/SignalDelegator.cpp:464`, `:644`
> and `:701` mirror the live sites. **That file is in no `CMakeLists.txt` and is
> not built** — `Source/Tools/FEXInterpreter/CMakeLists.txt` builds only
> `FEXInterpreter.cpp` and `AOT/AOTGenerator.cpp`, and the only `SignalDelegator.cpp`
> any target compiles is `Source/Tools/LinuxEmulation/CMakeLists.txt:17`. Do not
> "fix" the dead copy and think you are done. (Two of the HOST sites counted
> above — `:622` and `:1064` — are in this unbuilt file.)

### The second one, which is just as bad

`Source/Tools/LinuxEmulation/LinuxSyscalls/ThreadManager.cpp:378-379`:

```cpp
ThreadStateObject->Thread->CallRetStackBase = reinterpret_cast<void*>(AllocBase + FEXCore::Utils::FEX_PAGE_SIZE);
::mprotect(ThreadStateObject->Thread->CallRetStackBase, FEXCore::Core::InternalThreadState::CALLRET_STACK_SIZE, PROT_READ | PROT_WRITE);
```

`AllocBase` comes from `FEXCore::Allocator::mmap(nullptr, ...)` and *is*
host-aligned. Adding a 4096-byte guard page makes `CallRetStackBase`
**not** host-aligned, so the `mprotect` that commits the call-ret shadow stack
returns `EINVAL` — **unchecked** — and the allocation stays `PROT_NONE`. The
JIT's shadow CALL push then faults on the *first guest CALL*. This one crashes
rather than hangs, and it is not SMC-related at all, which is why the old
"SMCChecks is not mtrack so the SMC path is not affected" message was actively
misleading. `ThreadManager.h:184` (`GetCallRetStackInfo`) encodes the same 4K
guard on both sides.

---

## HOST — must become the runtime host page size

Grouped by subsystem. These all bottom out in a real syscall.

### `FEXCore/Source/Utils/Allocator/64BitAllocator.cpp` (the 48-bit steal allocator)

The entire file is 4K-granular and it calls `::mmap` with **`MAP_FIXED`** at
addresses it computed itself, so on a 64K host it fails rather than degrades.

| lines | what |
|---|---|
| `70`, `71`, `196`, `199` | `UPPER_BOUND_PAGE` / `LOWER_BOUND_PAGE` in 4K units |
| `113`, `119`, `124`, `125`, `129`, `134`, `164` | region bookkeeping and `::madvise` of the used-page bitmap |
| `167` | `mprotect` of the reserved region header |
| `245`, `250`, `437`, `441` | request alignment checks (`Addr & ~FEX_PAGE_MASK` → `EINVAL`) |
| `260`, `263`, `285`, `289`, `290` | length/page-count conversion |
| `315`, `318` | **`AllocatedOffset = Base + AllocatedPage * FEX_PAGE_SIZE` then `::mmap(..., MAP_FIXED)`** — the core break |
| `345` | second `MAP_FIXED` path |
| `393`, `407`, `416` | live-region accounting |
| `452`, `465`, `466`, `477`, `478`, `481` | `Munmap` → `::madvise` + `::mmap(MAP_FIXED)` re-reservation |
| `508`, `511` | `mprotect` + `madvise(MADV_HUGEPAGE)` of slabs |
| `535`, `584`, `587`, `602`, `603`, `607` | small-allocation fast path, `::munmap`/`::mmap` at `MinPage` |

### `Source/Tools/LinuxEmulation/LinuxSyscalls/LinuxAllocator.cpp` (32-bit guest allocator)

Same shape: a 4K-granular bitmap over the low 4 GiB, then `::mmap` at
`Page << FEX_PAGE_SHIFT`.

| lines | what |
|---|---|
| `26`, `27` | `TOP_KEY` / `TOP_KEY32BIT` in 4K pages |
| `67`, `68`, `177`, `180`, `322`, `325` | address ↔ page-index conversion |
| `187`, `192`, `333` | alignment rejection |
| `245`, `251` | `::mmap(LowerPage << FEX_PAGE_SHIFT, ..., MAP_FIXED_NOREPLACE)` |
| `266` | `::mincore` probe at 4K granularity |
| `287`, `307`, `308` | `::mmap(PageAddr << FEX_PAGE_SHIFT, PagesLength << FEX_PAGE_SHIFT, ...)` |
| `368`, `369` | `::munmap` at 4K granularity |
| `387`, `388`, `394`, `396`, `407`, `412`, `418`, `425`, `426`, `448`, `450`, `482`, `486`, `488` | `mremap` bookkeeping |
| `510`, `522`, `538`, `560`, `599`, `610` | `shmat`/`shmdt` placement |

### Guard pages (all four are silently unarmed on a 64K host)

| site | what |
|---|---|
| `FEXCore/Source/Interface/Core/CPUBackend.cpp:381-383` | JIT code-buffer guard. `AlignDown(Ptr + Size - 1, 4096)` picks the last **4K sub-page** of a host-aligned buffer, so the `VirtualProtect` fails and the buffer-overrun detector stops working. |
| `FEXCore/Source/Interface/Core/CPUBackend.cpp:700` | same computation on the rotation path |
| `FEXCore/include/FEXCore/Utils/ThreadPoolAllocator.h:420-421` | identical pattern for pooled allocations |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/SignalDelegator.cpp:1967` | alt-stack overflow guard. Address *is* host-aligned so this one **succeeds**, but the kernel rounds the length up and it protects 64K instead of 4K, silently eating 60K of alt stack. |

### Allocator startup and misc

| site | what | note |
|---|---|---|
| `FEXCore/Source/Utils/Allocator.cpp:125-129` | `DetermineVASize` probes `::mmap(Size - 4096*i, ..., MAP_FIXED_NOREPLACE)` | on a 64K host 15 of every 16 probes spuriously `EINVAL`; `i=0` still works so VA detection limps |
| `FEXCore/Source/Utils/AllocatorHooks.cpp:60-61` | `constexpr size_t PageSize = 4096` in `GetInternalPlacementHint` | **benign** — it only rounds a placement *hint*, and Linux is free to ignore hints |
| `Source/Common/Linux/SBRKAllocations.cpp:30-32` | `AlignUp(sbrk(0), 4096)` then `::mmap(..., MAP_FIXED_NOREPLACE)` | see UNKNOWN #2 — this runs on the **first line of `main`**, before the gate |
| `Source/Common/Linux/SBRKAllocations.cpp:55` | matching `munmap` | |
| `FEXCore/Source/Interface/Core/CodeCache.cpp:1316` | aligns the mapped-cache cursor so the code buffer can be mapped | |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/Syscalls.cpp:125,136` | `PROT_SAO` probe `mmap`/`munmap` of one page | benign: `nullptr` hint, length rounds up |
| `FEXCore/include/FEXCore/fextl/memory_resource.h:48,54,98,112` | arena sizing for `VirtualAlloc`; `alignment <= FEX_PAGE_SIZE` assert | |
| `FEXCore/Source/Utils/Allocator/IntrusiveArenaAllocator.h:82,84,118,161,170,171` | 4K-granular arena bitmap | |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/ThreadManager.cpp:183` | stats-region sizing fallback | |
| `Source/Tools/CommonTools/HarnessHelpers.h:453,469,490` | test harness mapping sizes | already reads `sysconf(_SC_PAGESIZE)` with `FEX_PAGE_SIZE` only as fallback |

### Out-of-tree-ish tools (same bugs, separate binaries)

`Source/Tools/FexBridge/FexBridge.cpp:97,127,398,403,405,450,452,660,667,668,697`
and `Source/Tools/Wow64Probe/Wow64Probe.cpp:221,243,245,252` repeat the
call-ret-stack guard-page pattern and map 4K hlt/stack pages. Same fix, different
binary. `FexBridge.cpp:667` is a direct `::mprotect` at `StackBase + 4096`.

---

## BOTH — conflated; each needs a decision

These are the interesting ones. Every site here currently uses one constant for
a guest-facing quantity *and* a host syscall, and the port has to choose.

### Guest memory syscalls (`SyscallsSMCTracking.cpp`)

The guest `mmap`/`mprotect`/`munmap`/`mremap`/`madvise` entry points align the
**guest's** request with `FEX_PAGE_SIZE` and then hand the result to the **host**
kernel:

`1615`, `1705`, `1710`, `1715`, `1742`, `1780-1781`, `1786-1787`, `1792-1793`,
`1845-1848`, `1873-1876`, `1990-1991`, `2013-2014`, `2051-2052`, `2200`, `2355`,
`2360`, `2367-2368`, `2417`.

**The decision:** the guest legitimately asks for 4K granularity (it was told
`AT_PAGESZ=4096`) and the host cannot provide it. There is no way to satisfy
both. The options are (a) refuse — what the gate does today; (b) a shadow
protection table that tracks guest-visible protections at 4K while the real
mapping is host-granular, faulting on the difference; (c) lie to the guest about
`AT_PAGESZ`, which breaks any guest that computes `MAP_FIXED` addresses from
4K assumptions — i.e. most of them. **(b) is the only real answer, and it is the
bulk of the 64K project.** A `MAP_FIXED` at a 4K-aligned-but-not-host-aligned
address is unrepresentable and has to be emulated by remapping the containing
host page and copying.

### Host-owned range tracking

`Source/Tools/LinuxEmulation/LinuxSyscalls/HostOwnedRanges.cpp:229`, `238`, `239`
round guest requests to page granularity to test them against FEX's own host
mappings. Decision: this must round to the **host** page, because the thing it is
protecting is a host mapping — rounding to 4K would let a guest request that
lands in the same host page as FEX's own image slip through.

### Code cache file format

`FEXCore/Source/Interface/Core/CodeCache.cpp:1066-1067` pads the cache file to a
page boundary *so the code buffer can be `mmap`ed from it on load*. That is a
host requirement written into an **on-disk format**. Decision: either pad to the
host page (making caches non-portable between 4K and 64K hosts — the cache id
would need the host page size hashed in) or pad to a fixed 64K worst case.

### VDSO and vsyscall

| site | what | decision |
|---|---|---|
| `Source/Tools/LinuxEmulation/VDSO_Emulation.cpp:911` | `VDSOSize` aligned to 4K, then `GuestMmap(..., MAP_FIXED_NOREPLACE)` | host, but the guest sees the size |
| `Source/Tools/LinuxEmulation/VDSO_Emulation.cpp:138` | `size_of_opaque_state = FEX_PAGE_SIZE` for `getrandom` | guest-visible; glibc mmaps this. See UNKNOWN #3. |
| `Source/Tools/FEXInterpreter/ELFCodeLoader.h:657` | `GuestMmap` of a 4K vsyscall page | |
| `Source/Tools/FEXInterpreter/ELFCodeLoader.h:663` | **`mprotect(VSyscallPage, FEX_PAGE_SIZE, PROT_READ)`** — a raw host `mprotect` on a guest mapping | fails on a 64K host if `GuestMmap` returned a 4K-granular address |

`VDSO_Emulation.cpp:801`, `:928` and `ELFCodeLoader.h:474` already read
`sysconf(_SC_PAGESIZE)` and use `FEX_PAGE_SIZE` only as a fallback — **already
runtime-clean**.

### File-backed mapping identity

`Source/Common/FileMappingBaseAddress.h:41` compares
`(FileOffset & FEX_PAGE_MASK) == (phdr.p_offset & FEX_PAGE_MASK)` to decide
whether a host mapping corresponds to a guest ELF segment. Guest ELF offsets are
4K-granular; the host mapping is host-granular. Decision: this wants the **guest**
mask, but only if the host mapping is also tracked at 4K.

---

## GUEST — stays 4096, no work

Listed for completeness; a 64K port must **not** touch these.

| file | lines | what |
|---|---|---|
| `FEXCore/Source/Interface/Context/Context.cpp` | `103`, `180`, `181`, `183`, `184`, `205`, `206` | SMC page counters and the single-guest-page containment test for store patching |
| `FEXCore/Source/Interface/Core/LookupCache.cpp` | `42`, `65`, `73`, `107`, `133` | one L1 pointer **per guest page** of `VirtualMemSize` |
| `FEXCore/Source/Interface/Core/LookupCache.h` | `1189` | `SIZE_PER_PAGE` = guest page × entry size |
| `FEXCore/Source/Interface/Core/SMCSoftInvalidate.h` | `174` | guest code-page hashing |
| `FEXCore/Source/Interface/Core/Frontend.cpp` | `1247`, `1499`, `1546`, `1613`, `1614` | guest code page tracking, multiblock clamp, forward-branch limit |
| `FEXCore/Source/Interface/Core/Core.cpp` | `1325`, `1327`, `1476`, `1478` | `AddBlockExecutableRange` / `MarkGuestExecutableRange` — guest pages |
| `FEXCore/Source/Interface/Core/CodeCache.cpp` | `1564`, `1565` | same, on the cache-load path |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/SyscallsSMCTracking.cpp` | `230`, `439`, `441`, `460`, `506`, `508`, `530`, `542`, `622`, `623`, `642`, `867`, `870`, `1071` | SMC tracking **as a guest concept** — which guest page got dirtied |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/Syscalls.h` | `598`, `649` | SMC dirty/skipped guest-page sets |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/SyscallsVMATracking.h` | `258`, `266` | guest-page hash index and tag |
| `Source/Tools/FEXInterpreter/ELFCodeLoader.h` | `78`, `191`, `587`, `592` | guest ELF span, BRK base, ASLR offset shift, load-hint alignment |
| `Source/Tools/FEXInterpreter/ELFCodeLoader.h` | `636` | **`AT_PAGESZ`** — the definition of the guest contract |
| `Source/Tools/CommonTools/Linux/Utils/ELFContainer.cpp` | `212`, `347` | guest ELF BRK size and max phys addr |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/Syscalls.cpp` | `1047`, `1061` | guest `brk` rounding |
| `Source/Tools/LinuxEmulation/LinuxSyscalls/x32/Info.cpp` | `145` | `sysinfo` `mem_unit` floor — guest-visible |

---

## Guest-visible surface that must keep reporting 4K

Verified by reading where each is produced.

| surface | where | status |
|---|---|---|
| `AT_PAGESZ` | `Source/Tools/FEXInterpreter/ELFCodeLoader.h:636` — `auxv_t {6, FEX_PAGE_SIZE}` | ✅ **correct by construction.** Hard-coded to `FEX_PAGE_SIZE`, never to `sysconf`. |
| `/proc/self/maps` | **not emulated.** `HostOwnedRanges.cpp:83` and `GdbServer.cpp:342,572` read the *host's* real maps for FEX's own use; the guest's reads are not intercepted | ⚠ the guest sees host-granular mappings today, on a 4K host too. Not a regression, but a 64K port makes the discrepancy visible. |
| `smaps` | not emulated | ⚠ same |
| `mincore` | `Syscalls/Passthrough.cpp:839` — raw `SyscallPassthrough3` | ❌ **leaks the host page size.** The result vector is one byte per *host* page, and a 4K-aligned-but-not-host-aligned address returns `EINVAL`. Needs a shim. |
| `msync` | `Syscalls/Passthrough.cpp:838` — raw passthrough | ❌ same alignment exposure |
| `madvise` | `Syscalls/Memory.cpp:30-31` — `::madvise` directly | ❌ same; also `SyscallsSMCTracking.cpp:2417` aligns the length at 4K first |
| `mremap` | `x64/Memory.cpp:40`, `x32/Memory.cpp:55` → `GuestMremap` → `SyscallsSMCTracking.cpp:2360-2368` | ❌ 4K-aligned old/new sizes handed to host `mremap` |
| `mmap`/`mprotect`/`munmap` | `x64/Memory.cpp:35,44`, `x32/Memory.cpp:46,50` → `SyscallsSMCTracking.cpp` | ❌ see the BOTH section |

**Only `AT_PAGESZ` is already right.** Everything else in this table either
passes the host page size through to the guest or fails outright.

---

## Allocator: what is already runtime-clean

Genuinely useful scoping — the allocator is *partly* parameterised already.

| component | state |
|---|---|
| `InitializeAllocator(size_t PageSize)` (`AllocatorHooks.cpp:240-241`) | ✅ **clean.** Sets `global_config.page_size`, and rpmalloc's own default is already `64 * 1024` (`AllocatorHooks.cpp:107`). |
| `SetupHooks(size_t PageSize)` / `AssignHookOverrides` (`Allocator.cpp:94`, `:87`) | ✅ **clean.** Threads the value straight through. |
| `Setup48BitAllocatorIfExists(size_t PageSize)` (`Allocator.cpp:276-290`) | ⚠ **half.** The `PageSize` argument reaches rpmalloc, but the `OSAllocator_64Bit` it constructs on line 286 ignores it entirely and is 4K-granular throughout. |
| Callers (`FEXInterpreter.cpp:160,177,183`, `TestHarnessRunner.cpp:242`, `FEXOfflineCompiler/Main.cpp:170`) | ✅ **clean.** All already pass `sysconf(_SC_PAGESIZE)` with `FEX_PAGE_SIZE` only as a fallback. |
| `OSAllocator_64Bit` (`64BitAllocator.cpp`) | ❌ **not clean.** Wholly 4K. See the HOST table. |
| `MemAllocator` / 32-bit (`LinuxAllocator.cpp`) | ❌ **not clean.** Wholly 4K. |
| `GetInternalPlacementHint` (`AllocatorHooks.cpp:60`) | ⚠ hard-codes 4096, but only for a hint. Benign. |

So the *plumbing* exists and the *policy* is missing: the page size already
arrives at the allocator layer, and the two concrete allocators throw it away.

---

## What would break first

Ordered. Whoever picks this up should work down this list.

1. **`SBRKAllocations::DisableSBRKAllocations`** (`Source/Common/Linux/SBRKAllocations.cpp:30-38`)
   — runs on the *first line of `main`*, before logging, before config, before the
   page-size gate. If `sbrk(0)` is not host-aligned its `MAP_FIXED_NOREPLACE`
   fails and it calls `FEX_TRAP_EXECUTION` outright. Usually survives (see
   UNKNOWN #2), but it is genuinely first.
2. **The call-ret shadow stack** (`ThreadManager.cpp:378-379`) — first guest
   `CALL` faults. Crashes before anything interesting runs.
3. **`InterruptFaultPage`** (`SignalDelegator.cpp:1032`) — deferred signals never
   arm; the guest hangs the first time an async signal needs delivering. This is
   the one that costs a day, because there is no output at all.
4. **Guest `mmap`/`mprotect` with `MAP_FIXED`** (`SyscallsSMCTracking.cpp`) — the
   guest ELF loader itself uses `MAP_FIXED`, so most binaries die during load.
   Needs the shadow protection table; this is the bulk of the work.
5. **`OSAllocator_64Bit`** (`64BitAllocator.cpp:315-318`) — if it engages
   (UNKNOWN #1), every FEX-internal allocation goes through a `MAP_FIXED` at a
   4K-granular address.
6. **32-bit guests** (`LinuxAllocator.cpp`) — the whole low-4 GiB bitmap is
   4K-granular. Defer; 64-bit guests are the priority.
7. **SMC `mtrack`** (`SyscallsSMCTracking.cpp:490` and the protect paths) —
   needs guest-page protection state decoupled from host-page protection
   granularity. `FEX_SMCCHECKS=full` is the fallback while this is unfinished.
8. **Guard pages** (`CPUBackend.cpp:381`, `ThreadPoolAllocator.h:420`,
   `SignalDelegator.cpp:1967`) — safety nets, silently disarmed. Fix last, but do
   fix them: they are what turn a JIT buffer overrun into a clean abort.
9. **Code cache portability** (`CodeCache.cpp:1066`) — only matters once the
   above work.

Note that steps 2 and 3 both require the `InternalThreadState` layout change,
which is the single largest structural item and gates everything downstream.

---

## UNKNOWN

1. **Does `OSAllocator_64Bit` engage on a 64K ppc64le kernel?**
   `Setup48BitAllocatorIfExists` (`Allocator.cpp:276-280`) returns early unless
   `DetermineVASize() >= 48`. Whether a given ppc64le kernel reports ≥48 VA bits
   depends on the MMU mode (hash vs radix) and page size, and I could not probe
   it — this audit was done on an x86_64 workstation, and the tree does not build
   there. If it does engage, item 5 above moves up the list sharply.
2. **Is `sbrk(0)` host-page-aligned at the top of `main`?**
   `AlignUp(sbrk(0), 4096)` is a no-op when the break is already 64K-aligned,
   which is the normal case (the kernel page-aligns the initial break to the
   *host* page). If glibc has moved the break to a non-host-aligned value before
   `main`, FEX traps before the gate can print anything. Needs a real 64K host to
   settle.
3. **`VDSO_Emulation.cpp:138` `size_of_opaque_state = FEX_PAGE_SIZE`.**
   This is the size glibc's `getrandom` vDSO path uses to size an allocation it
   then `mmap`s. Whether the guest's allocation granularity or the host's governs
   depends on whether that mapping goes through `GuestMmap` — I traced it to the
   guest side but did not confirm the glibc behaviour end to end. Marked UNKNOWN
   rather than guessed.

---

## Scope note

Phase 0 (the startup gate) is deliberately *only* a guard rail. It adds no
shadow protection table, no granule manager, no `FEX_HOSTPAGESIZE` emulation
mode, and does **not** split `FEX_PAGE_SIZE` into two constants. That split is
the first commit of the real project, and this document is what scopes it.
