// SPDX-License-Identifier: MIT
#pragma once

#include <FEXCore/IR/IR.h>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <span>
#include <sys/time.h>

namespace FEXCore::Core {
struct InternalThreadState;
}

namespace FEX::HLE {
class SyscallHandler;
}

namespace FEX::VDSO {
struct VDSOMapping {
  void* VDSOBase {};
  size_t VDSOSize {};
  void* X86GeneratedCodePtr {};
  size_t X86GeneratedCodeSize {};
};

struct VDSOEntrypoints {
  void* VDSO_kernel_sigreturn;
  void* VDSO_kernel_rt_sigreturn;
  void* VDSO_FEX_CallbackRET;
};
VDSOMapping LoadVDSOThunks(FEXCore::Core::InternalThreadState* Thread, bool Is64Bit, FEX::HLE::SyscallHandler* const Handler);
void UnloadVDSOMapping(FEXCore::Core::InternalThreadState* Thread, FEX::HLE::SyscallHandler* const Handler, const VDSOMapping& Mapping);

uint64_t GetVSyscallEntry(const void* VDSOBase);

const std::span<FEXCore::IR::ThunkDefinition> GetVDSOThunkDefinitions(bool Is64Bit);
const VDSOEntrypoints& GetVDSOSymbols();

// Host vDSO clock entry points, for guests that bypass the guest vDSO and
// issue the raw syscall instead (Mono's mono_100ns_ticks, static binaries,
// anything calling syscall(2) directly). The raw-syscall passthrough handlers
// in LinuxSyscalls/Syscalls/Passthrough.cpp route through these to avoid a
// kernel entry per call.
//
// Each member is nullptr until LoadHostVDSO() resolves it, and stays nullptr
// forever if the host kernel exposes no vDSO or lacks that symbol; callers
// must null-check and fall back to the syscall.
//
// LIFECYCLE: written exactly once, by LoadHostVDSO(), which runs inside
// LoadVDSOThunks() on the main thread from FEXInterpreter.cpp before any guest
// instruction executes -- so no guest syscall can observe a partially
// initialised table, and every read afterwards is of immutable data. No
// synchronisation needed or wanted on the read path.
//
// CONVENTION: on ppc64le hosts these are the ppc_kernel_vdso::Shim* wrappers,
// not the bare kernel entry points -- the powerpc vDSO returns a positive
// errno with CR0.SO set rather than -1/errno, and the shims normalise that to
// the negative-errno form both FEX's VDSO handlers and the passthrough
// handlers expect. Do not bypass them.
struct HostVDSOClocks {
  decltype(::clock_gettime)* ClockGetTime {};
  decltype(::clock_getres)* ClockGetRes {};
  decltype(::gettimeofday)* GetTimeOfDay {};
  decltype(::time)* Time {};
};
const HostVDSOClocks& GetHostVDSOClocks();
} // namespace FEX::VDSO
