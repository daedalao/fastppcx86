// SPDX-License-Identifier: MIT
/*
$info$
meta: glue|thunks ~ FEXCore side of thunks: Registration, Lookup
tags: glue|thunks
$end_info$
*/

#include "Thunks.h"
#include "LinuxSyscalls/Syscalls.h"
#include "LinuxSyscalls/ThreadManager.h"

#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/X86Enums.h>
#include <FEXCore/Core/Thunks.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/Utils/LogManager.h>
#include <FEXCore/Utils/CompilerDefs.h>
#include <FEXCore/fextl/set.h>
#include <FEXCore/fextl/string.h>
#include <FEXCore/fextl/unordered_map.h>

#include <cstdint>
#include <dlfcn.h>

#include <malloc.h>
#include <mutex>
#include <shared_mutex>
#include <stdint.h>
#include <utility>

#ifdef ENABLE_JEMALLOC_GLIBC
extern "C" {
// jemalloc defines nothrow on its internal C function signatures.
#define JEMALLOC_NOTHROW __attribute__((nothrow))
// Forward declare jemalloc functions because we can't include the headers from the glibc jemalloc project.
// This is because we can't simultaneously set up include paths for both of our internal jemalloc modules.
FEX_DEFAULT_VISIBILITY JEMALLOC_NOTHROW extern int glibc_je_is_known_allocation(void* ptr);
}
#endif

static __attribute__((aligned(16), naked, section("HostToGuestTrampolineTemplate"))) void HostToGuestTrampolineTemplate() {
#if defined(ARCHITECTURE_x86_64)
  asm("lea 0f(%rip), %r11 \n"
      "jmpq *0f(%rip) \n"
      ".align 8 \n"
      "0: \n"
      ".quad 0, 0, 0, 0 \n" // TrampolineInstanceInfo
  );
#elif defined(ARCHITECTURE_arm64)
  asm(
    // x11 is part of the custom ABI and needs to point to the TrampolineInstanceInfo.
    "ldr x16, 0f \n"
    "adr x11, 0f \n"
    "br x16 \n"
    // Manually align to the next 8-byte boundary
    // NOTE: GCC over-aligns to a full page when using .align directives on ARM (last tested on GCC 11.2)
    "nop \n"
    "0: \n"
    ".quad 0, 0, 0, 0 \n" // TrampolineInstanceInfo
  );
#elif defined(ARCHITECTURE_ppc64le)
  // PPC64LE: pass TrampolineInstanceInfo via a thread-local variable.
  //
  // Why not r11 like x86/ARM: PPC64LE ELFv2 declares r11 as the "environment
  // pointer / static chain register," and the linker's PLT lazy-resolution
  // stubs are documented to clobber r11. The receiving CallGuestPtr also
  // calls into PLT-resolved external functions (GetGuestStack,
  // MoveGuestStack, etc.) before the inline asm has a chance to capture
  // r11, so the value gets corrupted in practice. Empirically observed as
  // "State.rip = low byte of (whatever was last at offset 16 of the
  // trampoline page)" across all libGL / libvulkan / libwayland host
  // thunks on POWER8.
  //
  // Replacement: the trampoline writes &TrampolineInstanceInfo into a
  // __thread variable defined in Bin/FEX, then bctr to HostPacker. The
  // LOAD_INTERNAL_GUESTPTR_VIA_CUSTOM_ABI macro (in ThunkLibs/include/
  // common/Host.h) reads the same TLS variable from the host thunk
  // libraries via the dynamic linker's Initial-Exec TLS model. r13 is the
  // PPC64LE thread pointer and is preserved across PLT stubs (kernel +
  // ABI invariant), so this is robust.
  //
  // Layout (12 insns = 48 bytes of code, then 32 bytes of InstanceInfo):
  //   +0:  mflr r0
  //   +4:  bl 1f
  //   +8:  [label1] mflr r12
  //   +12: mtlr r0
  //   +16: addi r11, r12, 32       r11 = &InstanceInfo (label1+32 = template+40)
  //   +20: addis r0, r13, var@tprel@ha
  //   +24: std r11, var@tprel@l(r0) write TLS
  //   +28: ld r12, 0(r11)           r12 = InstanceInfo.HostPacker
  //   +32: mtctr r12
  //   +36: bctr
  //   +40: .quad 0,0,0,0            TrampolineInstanceInfo (32 bytes)
  asm(
    "mflr %r0 \n"
    "bl 1f \n"
    "1: mflr %r12 \n"
    "mtlr %r0 \n"
    "addi %r11, %r12, 32 \n"
    "addis %r0, %r13, __fex_callback_guestcall_ptr@tprel@ha \n"
    "std %r11, __fex_callback_guestcall_ptr@tprel@l(%r0) \n"
    "ld %r12, 0(%r11) \n"
    "mtctr %r12 \n"
    "bctr \n"
    ".align 3 \n"
    ".quad 0, 0, 0, 0 \n"
  );
#else
#error Unsupported host architecture
#endif
}

extern char __start_HostToGuestTrampolineTemplate[];
extern char __stop_HostToGuestTrampolineTemplate[];

#if defined(ARCHITECTURE_ppc64le)
// Cross-arch callback side-channel for the PPC64LE trampoline. See the
// trampoline template comment above for why r11 doesn't work and TLS does.
//
// The TLS variable lives in Bin/FEX with Local-Exec model (cheap, just
// `addis/std OFFSET(r13)` in the trampoline asm). Host thunk libraries
// (libGL-host.so etc.) can't reach this TLS slot directly because of
// --no-undefined linker semantics on PPC64LE Initial-Exec relocations.
// Instead, Bin/FEX exports a default-visibility getter that the host
// libs call to read the value. The dynamic linker resolves the getter
// at dlopen time; cost is one PLT call per callback dispatch, which is
// negligible compared to the JIT re-entry that follows.
extern "C" __thread uintptr_t __fex_callback_guestcall_ptr;
// __attribute__((used)) prevents LTO from dropping the symbol because
// the only C++ reference is inside the trampoline's naked inline asm,
// which LTO treats as opaque.
__attribute__((used)) __thread uintptr_t __fex_callback_guestcall_ptr;

extern "C" FEX_DEFAULT_VISIBILITY uintptr_t FEX_GetCallbackGuestcallPtr() {
  return __fex_callback_guestcall_ptr;
}
#endif

namespace FEX::HLE {

static thread_local FEX::HLE::ThreadStateObject* ThreadObject {};

struct TrampolineInstanceInfo {
  void* HostPacker;
  uintptr_t CallCallback;
  uintptr_t GuestUnpacker;
  uintptr_t GuestTarget;
};

// Opaque type pointing to an instance of HostToGuestTrampolineTemplate and its
// embedded TrampolineInstanceInfo
struct HostToGuestTrampolinePtr;

static TrampolineInstanceInfo& GetInstanceInfo(HostToGuestTrampolinePtr* Trampoline) {
#if defined(ARCHITECTURE_ppc64le)
  // The PPC64LE trampoline reads its InstanceInfo via `addi r11, r12, 32`
  // where r12 holds the address of `label1` (template+8). That fixes the
  // InstanceInfo at exactly offset 40 from the trampoline start. (The
  // +32 is because we now have 3 extra instructions: addis + std for TLS
  // write — bumping the InstanceInfo's offset accordingly.)
  //
  // We cannot derive the offset from the section length on PPC64LE: the
  // assembler emits trailing padding after the embedded `.quad 0,0,0,0`,
  // so Length - sizeof(info) points past where the trampoline actually
  // reads. Hardcode it to match the asm above.
  constexpr auto InstanceInfoOffset = 40;
#else
  const auto Length = __stop_HostToGuestTrampolineTemplate - __start_HostToGuestTrampolineTemplate;
  const auto InstanceInfoOffset = Length - sizeof(TrampolineInstanceInfo);
#endif
  return *reinterpret_cast<TrampolineInstanceInfo*>(reinterpret_cast<char*>(Trampoline) + InstanceInfoOffset);
}

struct GuestcallInfo {
  uintptr_t GuestUnpacker;
  uintptr_t GuestTarget;

  bool operator==(const GuestcallInfo&) const noexcept = default;
};

struct GuestcallInfoHash {
  size_t operator()(const GuestcallInfo& x) const noexcept {
    // Hash only the target address, which is generally unique.
    // For the unlikely case of a hash collision, fextl::unordered_map still picks the correct bucket entry.
    return std::hash<uintptr_t> {}(x.GuestTarget);
  }
};

namespace ThunkFunctions {
  void LoadLib(void* ArgsV);
  void IsLibLoaded(void* ArgsRV);
  void IsHostHeapAllocation(void* ArgsRV);
  void LinkAddressToGuestFunction(void* argsv);
  void AllocateHostTrampolineForGuestFunction(void* ArgsRV);
  void RegisterCallbackUnpacker(void* argsv);
} // namespace ThunkFunctions

struct ThunkHandler_impl final : public FEX::HLE::ThunkHandler {
  std::shared_mutex ThunksMutex;

  // Can't be a string_view. We need to keep a copy of the library name in-case string_view pointer goes away.
  // Ideally we track when a library has been unloaded and remove it from this set before the memory backing goes away.
  fextl::set<fextl::string> Libs;

  fextl::unordered_map<GuestcallInfo, HostToGuestTrampolinePtr*, GuestcallInfoHash> GuestcallToHostTrampoline;

  uint8_t* HostTrampolineInstanceDataPtr;
  size_t HostTrampolineInstanceDataAvailable = 0;

  // 2026-05-15 cross-arch callback registry: signature_name (the C++ mangled
  // typeid().name() of a callback signature, e.g. "FvPjE" for VkResult(uint*))
  // -> guest VA of CallbackUnpack<F>::Unpack.  Populated by guest thunk OnInit
  // calls to RegisterCallbackUnpacker; consumed by libvulkan-host.so etc. via
  // the weak LookupGuestCallbackUnpacker entry below.
  std::shared_mutex CallbackUnpackerByNameMutex;
  fextl::unordered_map<fextl::string, uintptr_t> CallbackUnpackerByName;

  /*
      Set arg0/1 to arg regs, use CTX::HandleCallback to handle the callback
  */
  static void CallCallback(void* callback, void* arg0, void* arg1) {
    if (!ThreadObject) {
      ERROR_AND_DIE_FMT("Thunked library attempted to invoke guest callback asynchronously");
    }

    auto CTX = static_cast<FEXCore::Context::Context*>(ThreadObject->Thread->CTX);
    auto ThunkHandler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());

    if (ThunkHandler->Is64BitMode()) {
      ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDI] = (uintptr_t)arg0;
      ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSI] = (uintptr_t)arg1;
    } else {
      // 32-bit guest: both arg slots are 32-bit pointers. Guard both — a host
      // library returning a >4 GiB pointer in either slot would silently leak
      // the high bits into the guest GPR, undebuggable downstream.
      if ((reinterpret_cast<uintptr_t>(arg0) >> 32) != 0 ||
          (reinterpret_cast<uintptr_t>(arg1) >> 32) != 0) {
        ERROR_AND_DIE_FMT("Tried to call guest function with arguments packed to a 64-bit address");
      }
      ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RCX] = (uintptr_t)arg0;
      ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RDX] = (uintptr_t)arg1;
    }

    CTX->HandleCallback(ThreadObject->Thread, (uintptr_t)callback);
  }

  FEXCore::ThunkedFunction* LookupThunk(const FEXCore::IR::SHA256Sum& sha256) override {

    std::shared_lock lk(ThunksMutex);

    auto it = Thunks.find(sha256);

    if (it != Thunks.end()) {
      return it->second;
    } else {
      return nullptr;
    }
  }

  void RegisterTLSState(FEX::HLE::ThreadStateObject* _ThreadObject) override {
    ThreadObject = _ThreadObject;
  }

  void AppendThunkDefinitions(std::span<const FEXCore::IR::ThunkDefinition> Definitions) override {
    for (auto& Definition : Definitions) {
      Thunks.emplace(Definition.Sum, Definition.ThunkFunction);
    }
  }

  void LoadLib(std::string_view Name);

private:
  // Bits in a SHA256 sum are already randomly distributed, so truncation yields a suitable hash function
  struct TruncatingSHA256Hash {
    size_t operator()(const FEXCore::IR::SHA256Sum& SHA256Sum) const noexcept {
      return (const size_t&)SHA256Sum;
    }
  };

  fextl::unordered_map<FEXCore::IR::SHA256Sum, FEXCore::ThunkedFunction*, TruncatingSHA256Hash> Thunks = {
    {// sha256(fex:loadlib)
     {0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44,
      0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x80},
     &ThunkFunctions::LoadLib},
    {// sha256(fex:is_lib_loaded)
     {0xee, 0x57, 0xba, 0x0c, 0x5f, 0x6e, 0xef, 0x2a, 0x8c, 0xb5, 0x19, 0x81, 0xc9, 0x23, 0xe6, 0x51,
      0xae, 0x65, 0x02, 0x8f, 0x2b, 0x5d, 0x59, 0x90, 0x6a, 0x7e, 0xe2, 0xe7, 0x1c, 0x33, 0x8a, 0xff},
     &ThunkFunctions::IsLibLoaded},
    {// sha256(fex:is_host_heap_allocation)
     {0xf5, 0x77, 0x68, 0x43, 0xbb, 0x6b, 0x28, 0x18, 0x40, 0xb0, 0xdb, 0x8a, 0x66, 0xfb, 0x0e, 0x2d,
      0x98, 0xc2, 0xad, 0xe2, 0x5a, 0x18, 0x5a, 0x37, 0x2e, 0x13, 0xc9, 0xe7, 0xb9, 0x8c, 0xa9, 0x3e},
     &ThunkFunctions::IsHostHeapAllocation},
    {// sha256(fex:link_address_to_function)
     {0xe6, 0xa8, 0xec, 0x1c, 0x7b, 0x74, 0x35, 0x27, 0xe9, 0x4f, 0x5b, 0x6e, 0x2d, 0xc9, 0xa0, 0x27,
      0xd6, 0x1f, 0x2b, 0x87, 0x8f, 0x2d, 0x35, 0x50, 0xea, 0x16, 0xb8, 0xc4, 0x5e, 0x42, 0xfd, 0x77},
     &ThunkFunctions::LinkAddressToGuestFunction},
    {// sha256(fex:allocate_host_trampoline_for_guest_function)
     {0x9b, 0xb2, 0xf4, 0xb4, 0x83, 0x7d, 0x28, 0x93, 0x40, 0xcb, 0xf4, 0x7a, 0x0b, 0x47, 0x85, 0x87,
      0xf9, 0xbc, 0xb5, 0x27, 0xca, 0xa6, 0x93, 0xa5, 0xc0, 0x73, 0x27, 0x24, 0xae, 0xc8, 0xb8, 0x5a},
     &ThunkFunctions::AllocateHostTrampolineForGuestFunction},
    {// sha256(fex:register_callback_unpacker)
     {0x1b, 0xc2, 0x72, 0xb3, 0x65, 0xbe, 0x39, 0x15, 0xb0, 0xcb, 0xda, 0x79, 0xaf, 0xa2, 0x8c, 0x19,
      0x50, 0x2a, 0xbe, 0xc8, 0xd5, 0xbb, 0x64, 0x48, 0x2b, 0x87, 0x7f, 0xb6, 0xd6, 0xee, 0x3a, 0x86},
     &ThunkFunctions::RegisterCallbackUnpacker},
  };

  FEX_CONFIG_OPT(Is64BitMode, IS64BIT_MODE);
  FEX_CONFIG_OPT(ThunkHostLibsPath, THUNKHOSTLIBS);
};

void ThunkHandler_impl::LoadLib(std::string_view Name) {
  auto SOName = ThunkHostLibsPath();
  while (SOName.ends_with('/')) {
    SOName.pop_back();
  }
  SOName = fmt::format("{}{}/{}-host.so", SOName, (Is64BitMode() ? "" : "_32"), Name);

  LogMan::Msg::DFmt("LoadLib: {} -> {}", Name, SOName);

  auto Handle = dlopen(SOName.c_str(), RTLD_LOCAL | RTLD_NOW);
  if (!Handle) {
    ERROR_AND_DIE_FMT("LoadLib: Failed to dlopen thunk library {}: {}", SOName, dlerror());
  }

  // Library names often include dashes, which may not be used in C++ identifiers.
  // They are replaced with underscores hence.
  auto InitSym = "fexthunks_exports_" + fextl::string {Name};
  std::replace(InitSym.begin(), InitSym.end(), '-', '_');

  struct ExportEntry {
    uint8_t* sha256;
    FEXCore::ThunkedFunction* Fn;
  };

  ExportEntry* (*InitFN)();
  (void*&)InitFN = dlsym(Handle, InitSym.c_str());
  if (!InitFN) {
    ERROR_AND_DIE_FMT("LoadLib: Failed to find export {}", InitSym);
  }

  auto Exports = InitFN();
  if (!Exports) {
    ERROR_AND_DIE_FMT("LoadLib: Failed to initialize thunk library {}. "
                      "Check if the corresponding host library is installed "
                      "or disable thunking of this library.",
                      Name);
  }

  {
    std::lock_guard lk(ThunksMutex);

    Libs.insert(fextl::string {Name});

    int i;
    for (i = 0; Exports[i].sha256; i++) {
      Thunks[*reinterpret_cast<FEXCore::IR::SHA256Sum*>(Exports[i].sha256)] = Exports[i].Fn;
    }

    LogMan::Msg::DFmt("Loaded {} syms", i);
  }
}

/**
 * Generates a host-callable trampoline to call guest functions via the host ABI.
 *
 * This trampoline uses the same calling convention as the given HostPacker. Trampolines
 * are cached, so it's safe to call this function repeatedly on the same arguments without
 * leaking memory.
 *
 * Invoking the returned trampoline has the effect of:
 * - packing the arguments (using the HostPacker identified by its SHA256)
 * - performing a host->guest transition
 * - unpacking the arguments via GuestUnpacker
 * - calling the function at GuestTarget
 *
 * The primary use case of this is ensuring that guest function pointers ("callbacks")
 * passed to thunked APIs can safely be called by the native host library.
 *
 * Returns a pointer to the generated host trampoline and its TrampolineInstanceInfo.
 *
 * If HostPacker is zero, the trampoline will be partially initialized and needs to be
 * finalized with a call to FinalizeHostTrampolineForGuestFunction. A typical use case
 * is to allocate the trampoline for a given GuestTarget/GuestUnpacker on the guest-side,
 * and provide the HostPacker host-side.
 */
FEX_DEFAULT_VISIBILITY HostToGuestTrampolinePtr*
MakeHostTrampolineForGuestFunction(void* HostPacker, uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  LOGMAN_THROW_A_FMT(GuestTarget, "Tried to create host-trampoline to null pointer guest function");

  const auto ThunkHandler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());

  const GuestcallInfo gci = {GuestUnpacker, GuestTarget};

  // Try first with shared_lock
  {
    std::shared_lock lk(ThunkHandler->ThunksMutex);

    auto found = ThunkHandler->GuestcallToHostTrampoline.find(gci);
    if (found != ThunkHandler->GuestcallToHostTrampoline.end()) {
      return found->second;
    }
  }

  std::lock_guard lk(ThunkHandler->ThunksMutex);

  // Retry lookup with full lock before making a new trampoline to avoid double trampolines
  {
    auto found = ThunkHandler->GuestcallToHostTrampoline.find(gci);
    if (found != ThunkHandler->GuestcallToHostTrampoline.end()) {
      return found->second;
    }
  }

  LogMan::Msg::DFmt("Thunks: Adding host trampoline for guest function {:#x} via unpacker {:#x}", GuestTarget, GuestUnpacker);

  const auto HostToGuestTrampolineSize = __stop_HostToGuestTrampolineTemplate - __start_HostToGuestTrampolineTemplate;

  if (ThunkHandler->HostTrampolineInstanceDataAvailable < HostToGuestTrampolineSize) {
    const auto allocation_step = 16 * 1024;
    ThunkHandler->HostTrampolineInstanceDataAvailable = allocation_step;

    // For 32-bit guests the trampoline pointer is stored in guest function-pointer
    // slots, which are 32 bits wide. A naked mmap(0,...) lets the kernel pick any
    // host address; on PPC64LE that's typically a 64-bit address well above 4 GiB.
    // The guest truncates it to its low 32 bits, the host VK / GL library then
    // calls the truncated address as a host function pointer, and the host SEGVs
    // at the unmapped low-address (e.g. host PC 0x63315230 = a guest-space
    // address). Route through the guest's 32-bit allocator so the trampoline
    // lives in the low 4 GiB and 32-bit truncation is lossless.
    if (!FEX::HLE::_SyscallHandler->Is64BitMode()) {
      auto* Alloc = FEX::HLE::_SyscallHandler->Get32BitAllocator();
      auto* Result = Alloc->Mmap(nullptr, ThunkHandler->HostTrampolineInstanceDataAvailable,
                                 PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      LOGMAN_THROW_A_FMT(!FEX::HLE::HasSyscallError(reinterpret_cast<uint64_t>(Result)),
                         "Failed to allocate 32-bit host trampoline page (errno {})",
                         -static_cast<int64_t>(reinterpret_cast<intptr_t>(Result)));
      LOGMAN_THROW_A_FMT((reinterpret_cast<uintptr_t>(Result) >> 32) == 0,
                         "32-bit trampoline allocator returned a >4 GiB address {:#x}",
                         reinterpret_cast<uintptr_t>(Result));
      ThunkHandler->HostTrampolineInstanceDataPtr = static_cast<uint8_t*>(Result);
    } else {
      ThunkHandler->HostTrampolineInstanceDataPtr = (uint8_t*)mmap(0, ThunkHandler->HostTrampolineInstanceDataAvailable,
                                                                   PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      LOGMAN_THROW_A_FMT(ThunkHandler->HostTrampolineInstanceDataPtr != MAP_FAILED, "Failed to mmap HostTrampolineInstanceDataPtr");
    }
  }

  auto HostTrampoline = reinterpret_cast<HostToGuestTrampolinePtr*>(ThunkHandler->HostTrampolineInstanceDataPtr);
  ThunkHandler->HostTrampolineInstanceDataAvailable -= HostToGuestTrampolineSize;
  ThunkHandler->HostTrampolineInstanceDataPtr += HostToGuestTrampolineSize;
  memcpy(HostTrampoline, (void*)&HostToGuestTrampolineTemplate, HostToGuestTrampolineSize);
  GetInstanceInfo(HostTrampoline) = TrampolineInstanceInfo {
    .HostPacker = HostPacker, .CallCallback = (uintptr_t)&ThunkHandler_impl::CallCallback, .GuestUnpacker = GuestUnpacker, .GuestTarget = GuestTarget};

  ThunkHandler->GuestcallToHostTrampoline[gci] = HostTrampoline;
  return HostTrampoline;
}

FEX_DEFAULT_VISIBILITY void FinalizeHostTrampolineForGuestFunction(HostToGuestTrampolinePtr* TrampolineAddress, void* HostPacker) {
  if (TrampolineAddress == nullptr) {
    return;
  }

  auto& Trampoline = GetInstanceInfo(TrampolineAddress);

  LOGMAN_THROW_A_FMT(Trampoline.CallCallback == (uintptr_t)&ThunkHandler_impl::CallCallback, "Invalid trampoline at {} passed to {}",
                     fmt::ptr(TrampolineAddress), __FUNCTION__);

  if (!Trampoline.HostPacker) {
    LogMan::Msg::DFmt("Thunks: Finalizing trampoline at {} with host packer {}", fmt::ptr(TrampolineAddress), fmt::ptr(HostPacker));
    Trampoline.HostPacker = HostPacker;
  }
}

namespace ThunkFunctions {
  void LoadLib(void* ArgsV) {
    struct LoadlibArgs {
      const char* Name;
    };

    auto Args = reinterpret_cast<LoadlibArgs*>(ArgsV);
    auto ThunkHandler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());

    ThunkHandler->LoadLib(Args->Name);
  }

  void IsLibLoaded(void* ArgsRV) {
    struct ArgsRV_t {
      const char* Name;
      bool rv;
    };

    auto& [Name, rv] = *reinterpret_cast<ArgsRV_t*>(ArgsRV);
    auto ThunkHandler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());

    {
      std::shared_lock lk(ThunkHandler->ThunksMutex);
      rv = ThunkHandler->Libs.contains(Name);
    }
  }

  /**
   * Checks if the given pointer is allocated on the host heap.
   *
   * This is useful for thunking APIs that need to work with both guest
   * and host heap pointers.
   */
  void IsHostHeapAllocation(void* ArgsRV) {
#ifdef ENABLE_JEMALLOC_GLIBC
    struct ArgsRV_t {
      void* ptr;
      bool rv;
    }* args = reinterpret_cast<ArgsRV_t*>(ArgsRV);

    args->rv = glibc_je_is_known_allocation(args->ptr);
#else
    // Thunks usage without jemalloc isn't supported
    ERROR_AND_DIE_FMT("Unsupported: Thunks querying for host heap allocation information");
#endif
  }

  /**
   * Instructs the Core to redirect calls to functions at the given
   * address to another function. The original callee address is passed
   * to the target function through an implicit argument stored in r11.
   *
   * For 32-bit the implicit argument is stored in the lower 32-bits of mm0.
   *
   * The primary use case of this is ensuring that host function pointers
   * returned from thunked APIs can safely be called by the guest.
   */
  void LinkAddressToGuestFunction(void* argsv) {
    struct args_t {
      uintptr_t original_callee;
      uintptr_t target_addr; // Guest function to call when branching to original_callee
    };

    auto args = reinterpret_cast<args_t*>(argsv);
    auto CTX = static_cast<FEXCore::Context::Context*>(ThreadObject->Thread->CTX);
    CTX->AddThunkTrampolineIRHandler(args->original_callee, args->target_addr);
  }

  /**
   * Guest-side helper to initiate creation of a host trampoline for
   * calling guest functions. This must be followed by a host-side call
   * to FinalizeHostTrampolineForGuestFunction to make the trampoline
   * usable.
   *
   * This two-step initialization is equivalent to a host-side call to
   * MakeHostTrampolineForGuestFunction. The split is needed if the
   * host doesn't have all information needed to create the trampoline
   * on its own.
   */
  void AllocateHostTrampolineForGuestFunction(void* ArgsRV) {
    struct ArgsRV_t {
      uintptr_t GuestUnpacker;
      uintptr_t GuestTarget;
      uintptr_t rv; // Pointer to host trampoline + TrampolineInstanceInfo
    }* args = reinterpret_cast<ArgsRV_t*>(ArgsRV);

    args->rv = (uintptr_t)MakeHostTrampolineForGuestFunction(nullptr, args->GuestTarget, args->GuestUnpacker);
  }

  /**
   * 2026-05-15 cross-arch callback registry: guest pre-registers the address
   * of CallbackUnpack<F>::Unpack for each signature F so the host wrapper
   * can synthesise a HostToGuestTrampoline when thunkgen's callback annotation
   * was skipped for that signature.  Keyed by the C++ mangled typeid().name()
   * of the signature type, which is stable across guest/host compilation of
   * the same source.
   */
  void RegisterCallbackUnpacker(void* argsv) {
    // Args struct: both fields uint64_t so 32-bit and 64-bit guests have
    // identical layout (no padding hole).  Guest VA pointer fits in the low
    // 32 bits on i386.
    struct args_t {
      uint64_t signature_name;
      uint64_t guest_unpacker;
    }* args = reinterpret_cast<args_t*>(argsv);
    const char* name = reinterpret_cast<const char*>(static_cast<uintptr_t>(args->signature_name));
    if (!name || !args->guest_unpacker) {
      return;
    }
    auto* handler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());
    std::lock_guard lk(handler->CallbackUnpackerByNameMutex);
    // Insert or overwrite; if the guest re-registers, trust the latest value.
    handler->CallbackUnpackerByName.insert_or_assign(fextl::string {name}, static_cast<uintptr_t>(args->guest_unpacker));
  }
} // namespace ThunkFunctions

/**
 * Cross-arch callback registry lookup, weak-symbol exported for use by host
 * thunk libraries (libvulkan-host.so etc.).  Returns the guest VA of
 * CallbackUnpack<F>::Unpack registered for `signature_name`, or 0 if not
 * registered.  Called from GuestWrapperForHostFunction::Call in Host.h on
 * cross-arch builds when the wrapper sees an un-wrapped guest VA.
 */
FEX_DEFAULT_VISIBILITY uintptr_t LookupGuestCallbackUnpacker(const char* signature_name) {
  if (!signature_name || !FEX::HLE::_SyscallHandler) {
    return 0;
  }
  auto* handler = reinterpret_cast<ThunkHandler_impl*>(FEX::HLE::_SyscallHandler->GetThunkHandler());
  std::shared_lock lk(handler->CallbackUnpackerByNameMutex);
  auto it = handler->CallbackUnpackerByName.find(fextl::string {signature_name});
  return (it == handler->CallbackUnpackerByName.end()) ? 0 : it->second;
}

FEX_DEFAULT_VISIBILITY void* GetGuestStack() {
  if (!ThreadObject) {
    ERROR_AND_DIE_FMT("Thunked library attempted to query guest stack pointer asynchronously");
  }

  return (void*)(uintptr_t)((ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP]));
}

FEX_DEFAULT_VISIBILITY void MoveGuestStack(uintptr_t NewAddress) {
  if (!ThreadObject) {
    ERROR_AND_DIE_FMT("Thunked library attempted to query guest stack pointer asynchronously");
  }

  // 32-bit guest: RSP must fit in 32 bits. 64-bit guest: accept any address
  // the caller chose. The bump allocator on a cross-arch host (THUNK_HOST_NOT_X86_64)
  // derives Next from the current guest RSP, so values stay inside guest VA
  // space provided the guest didn't already have a stray RSP set.
  if (!FEX::HLE::_SyscallHandler->Is64BitMode() && (NewAddress >> 32)) {
    ERROR_AND_DIE_FMT("Tried to set stack pointer for 32-bit guest to a 64-bit address");
  }

  ThreadObject->Thread->CurrentFrame->State.gregs[FEXCore::X86State::REG_RSP] = NewAddress;
}

fextl::unique_ptr<ThunkHandler> CreateThunkHandler() {
  return fextl::make_unique<ThunkHandler_impl>();
}
} // namespace FEX::HLE
