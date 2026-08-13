# FEX-2604-811-g211e31a74

## FEXCore
See [FEXCore/Readme.md](../FEXCore/Readme.md) for more details

### backend
IR to host code generation

#### ppc64le
- [JIT.cpp](../FEXCore/Source/Interface/Core/JIT/PPC64LE/JIT.cpp): Main glue logic for the PPC64LE (POWER8) JIT backend

#### shared
- [CPUBackend.h](../FEXCore/Source/Interface/Core/CPUBackend.h)



### frontend

#### x86-meta-blocks
- [Frontend.cpp](../FEXCore/Source/Interface/Core/Frontend.cpp): Extracts instruction & block meta info, frontend multiblock logic

#### x86-tables
- [BaseTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/BaseTables.cpp)
- [DDDTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/DDDTables.cpp)
- [H0F38Tables.cpp](../FEXCore/Source/Interface/Core/X86Tables/H0F38Tables.cpp)
- [H0F3ATables.cpp](../FEXCore/Source/Interface/Core/X86Tables/H0F3ATables.cpp)
- [PrimaryGroupTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/PrimaryGroupTables.cpp)
- [SecondaryGroupTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/SecondaryGroupTables.cpp)
- [SecondaryModRMTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/SecondaryModRMTables.cpp)
- [SecondaryTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/SecondaryTables.cpp)
- [VEXTables.cpp](../FEXCore/Source/Interface/Core/X86Tables/VEXTables.cpp)
- [X86Tables.h](../FEXCore/Source/Interface/Core/X86Tables/X86Tables.h)
- [X87Tables.cpp](../FEXCore/Source/Interface/Core/X86Tables/X87Tables.cpp)

#### x86-to-ir
- [AVX_128.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/AVX_128.cpp): Handles x86/64 AVX instructions to 128-bit IR
- [Crypto.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Crypto.cpp): Handles x86/64 Crypto instructions to IR
- [Flags.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Flags.cpp): Handles x86/64 flag generation
- [Vector.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Vector.cpp): Handles x86/64 Vector instructions to IR
- [X87.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/X87.cpp): Handles x86/64 x87 to IR
- [X87F64.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/X87F64.cpp): Handles x86/64 x87 to IR
- [OpcodeDispatcher.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp): Handles x86/64 ops to IR, no-pf opt, local-flags opt



### glue
Logic that binds various parts together

#### block-database
- [LookupCache.cpp](../FEXCore/Source/Interface/Core/LookupCache.cpp): Stores information about blocks, and provides C++ implementations to lookup the blocks

#### driver
Emulation mainloop related glue logic
- [Core.cpp](../FEXCore/Source/Interface/Core/Core.cpp): Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint

#### log-manager
- [LogManager.cpp](../FEXCore/Source/Utils/LogManager.cpp)

#### thunks
- [Thunks.h](../FEXCore/include/FEXCore/Core/Thunks.h)



### ir

#### debug
- [IRDumperPass.cpp](../FEXCore/Source/Interface/IR/Passes/IRDumperPass.cpp): Prints IR

#### dumper
IR -> Text
- [IRDumper.cpp](../FEXCore/Source/Interface/IR/IRDumper.cpp)

#### emitter
C++ Functions to generate IR. See IR.json for spec.
- [IREmitter.cpp](../FEXCore/Source/Interface/IR/IREmitter.cpp)

#### opts
IR to IR Optimization
- [PassManager.cpp](../FEXCore/Source/Interface/IR/PassManager.cpp): Defines which passes are run, and runs them
- [PassManager.h](../FEXCore/Source/Interface/IR/PassManager.h)
- [CompareBranchFusion.cpp](../FEXCore/Source/Interface/IR/Passes/CompareBranchFusion.cpp): Fuses a flag-setting SubWithFlags into the CondJump that consumes it
- [IRValidation.cpp](../FEXCore/Source/Interface/IR/Passes/IRValidation.cpp): Sanity checking pass
- [RedundantFlagCalculationElimination.cpp](../FEXCore/Source/Interface/IR/Passes/RedundantFlagCalculationElimination.cpp)
- [RegisterAllocationPass.cpp](../FEXCore/Source/Interface/IR/Passes/RegisterAllocationPass.cpp)
- [RegisterAllocationPass.h](../FEXCore/Source/Interface/IR/Passes/RegisterAllocationPass.h)
- [ScalarSplatChain.cpp](../FEXCore/Source/Interface/IR/Passes/ScalarSplatChain.cpp): Marks chained scalar-FP inserts whose upper elements nobody observes



### opcodes

#### cpuid
- [CPUID.cpp](../FEXCore/Source/Interface/Core/CPUID.cpp): Handles presented capability bits for guest cpu

#### dispatcher-implementations
- [AVX_128.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/AVX_128.cpp): Handles x86/64 AVX instructions to 128-bit IR
- [Crypto.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Crypto.cpp): Handles x86/64 Crypto instructions to IR
- [Flags.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Flags.cpp): Handles x86/64 flag generation
- [Vector.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/Vector.cpp): Handles x86/64 Vector instructions to IR
- [X87.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/X87.cpp): Handles x86/64 x87 to IR
- [X87F64.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher/X87F64.cpp): Handles x86/64 x87 to IR
- [OpcodeDispatcher.cpp](../FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp): Handles x86/64 ops to IR, no-pf opt, local-flags opt

## ThunkLibs
See [ThunkLibs/README.md](../ThunkLibs/README.md) for more details

### thunklibs
These are generated + glue logic 1:1 thunks unless noted otherwise

#### EGL
- [libEGL_Guest.cpp](../ThunkLibs/libEGL/libEGL_Guest.cpp): Depends on glXGetProcAddress thunk
- [libEGL_Host.cpp](../ThunkLibs/libEGL/libEGL_Host.cpp)

#### GL
- [libGL_Guest.cpp](../ThunkLibs/libGL/libGL_Guest.cpp): Handles glXGetProcAddress
- [libGL_Host.cpp](../ThunkLibs/libGL/libGL_Host.cpp): Uses glXGetProcAddress instead of dlsym

#### SDL2
- [libSDL2_Guest.cpp](../ThunkLibs/libSDL2/libSDL2_Guest.cpp): Handles sdlglproc, dload, stubs a few log fns
- [libSDL2_Host.cpp](../ThunkLibs/libSDL2/libSDL2_Host.cpp)

#### VDSO
- [libVDSO_Guest.cpp](../ThunkLibs/libVDSO/libVDSO_Guest.cpp): Linux VDSO thunking

#### Vulkan
- [Guest.cpp](../ThunkLibs/libvulkan/Guest.cpp)
- [Host.cpp](../ThunkLibs/libvulkan/Host.cpp)

#### asound
- [libasound_Guest.cpp](../ThunkLibs/libasound/libasound_Guest.cpp)
- [libasound_Host.cpp](../ThunkLibs/libasound/libasound_Host.cpp)

#### drm
- [Guest.cpp](../ThunkLibs/libdrm/Guest.cpp)
- [Host.cpp](../ThunkLibs/libdrm/Host.cpp)

#### fex_malloc
- [Guest.cpp](../ThunkLibs/libfex_malloc/Guest.cpp): Handles allocations between guest and host thunks
- [Host.cpp](../ThunkLibs/libfex_malloc/Host.cpp): Handles allocations between guest and host thunks

#### fex_malloc_loader
- [Guest.cpp](../ThunkLibs/libfex_malloc_loader/Guest.cpp): Delays malloc symbol replacement until it is safe to run constructors

#### fex_malloc_symbols
- [Host.cpp](../ThunkLibs/libfex_malloc_symbols/Host.cpp): Allows FEX to export allocation symbols

#### fex_thunk_test
- [Guest.cpp](../ThunkLibs/libfex_thunk_test/Guest.cpp)
- [Host.cpp](../ThunkLibs/libfex_thunk_test/Host.cpp)

#### wayland-client
- [Guest.cpp](../ThunkLibs/libwayland-client/Guest.cpp)
- [Host.cpp](../ThunkLibs/libwayland-client/Host.cpp)

#### xshmfence
- [Guest.cpp](../ThunkLibs/libxshmfence/Guest.cpp)
- [Host.cpp](../ThunkLibs/libxshmfence/Host.cpp)

## Source/Tests

## unittests
See [unittests/Readme.md](../unittests/Readme.md) for more details

