# Comprehensive Code Review: Mono Backpatcher and SMC Components

## Overview
This review covers the "mono backpatcher" logic, its associated SMC (Self-Modifying Code) systems, and general structural state of the codebase, evaluating progress against the `PLAN-mono-smc.md` document.

## 1. Mono Backpatcher Hook Porting (Linux)
**Status: Implemented / Functional**

The most critical problem described in the planning phase—that Linux missed the specialized hook for mono backpatching—has been successfully addressed.
- **Implementation**: `DetectMonoBackpatcherBlock` and `DisableSMCDetectionLocked` have been ported to the Linux emulation layer and reside in `Source/Tools/LinuxEmulation/LinuxSyscalls/SyscallsSMCTracking.cpp`.
- **Logic Correctness**: During an SMC page invalidation (in `HandleSegfault`), FEX checks if the fault originates within the mono runtime's mapped bounds and lands on an `XCHG (0x87)` instruction. If so, `MarkMonoBackpatcherBlock` is fired, skipping standard heavy invalidations.
- **PPC64LE JIT**: The lowering of `MonoBackpatcherWrite` in the PPC JIT (`FEXCore/Source/Interface/Core/JIT/PPC64LE/ALUOps.cpp`) is successfully present and emits a specialized mini-frame to handle these memory modifications efficiently. 

## 2. Mono Runtime Detection Path
**Status: Partially Implemented**

- **Implemented (Modern Unity)**: `libmonobdwgc-2.0.so` has successfully been added to the prefix check inside `Syscalls.cpp` (`IsMonoRuntimeLibraryPath`), which covers modern Unity (2017+) applications.
- **Missing (Stardew Valley / MonoKickstart)**: Workstream 2b from the plan highlights an issue where MonoKickstart statically links mono, bypassing the openat dynamic loading mechanisms. The proposed fallback mitigations—tracking `mscorlib.dll` data loads and environmental overrides (`FEX_FORCE_MONO_RANGE` / `FEX_FORCE_MONO_DETECT`)—are currently missing. Games utilizing static-linked mono runtimes will likely still fail to trigger the optimized backpatcher paths and hit SMC thrashing.

## 3. General Architecture & Structural Review
**Status: Evolving, Important Safeguards in Place**

- **Page Size Guardrails (AT_PAGESZ):** A strong safeguard check has been added to `Syscalls.cpp`. When FEX initializes, it warns loudly if the host system uses a page size other than 4KB (`sysconf(_SC_PAGESIZE) != 4096`) and `mtrack` is enabled. Since the SMC mechanism heavily relies on hardcoded 4KB page bounds (e.g. `FEX_PAGE_SIZE`), this acts as a critical protection on Power8/9 (which may run 64K pages) from cascading failures.
- **Block Linking / JIT Perf:** A minor review of `ExitFunctionLink` in `PPC64LE/JIT.cpp` confirms that direct branch backpatching (block linking) remains largely unimplemented. It simply falls back to the lookup cache. As correctly identified in the port plan's watch-list (WS6), this is a performance bottleneck rather than a correctness bug, but should be noted for future optimization sprints.
- **Logging Visibility:** Diagnostic logging has been implemented well, outputting via `LogMan::Msg::IFmt` when the Mono runtime is detected and the hook installs. 

## Recommendations
1. **Implement Fallback Mono Detection**: Address the Stardew/MonoKickstart static link bypass. Implement the data-file open detection (`mscorlib.dll` and `machine.config`) to flip the mono detected flag.
2. **Environmental Overrides**: Wire in the `FEX_FORCE_MONO_DETECT=1` flag to allow users to force the specialized SMC path manually.
