/*
$info$
tags: thunklibs|Vulkan
$end_info$
*/

#define VK_USE_64_BIT_PTR_DEFINES 0

#define VK_USE_PLATFORM_XLIB_XRANDR_EXT
#define VK_USE_PLATFORM_XLIB_KHR
#define VK_USE_PLATFORM_XCB_KHR
#define VK_USE_PLATFORM_WAYLAND_KHR
#include <vulkan/vulkan.h>

#include "common/Guest.h"

#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "thunkgen_guest_libvulkan.inl"

extern "C" {

// Maps Vulkan API function names to the address of a guest function which is
// linked to the corresponding host function pointer
const std::unordered_map<std::string_view, uintptr_t /* guest function address */> HostPtrInvokers = std::invoke([]() {
#define PAIR(name, unused) Ret[#name] = reinterpret_cast<uintptr_t>(GetCallerForHostFunction(name));
  std::unordered_map<std::string_view, uintptr_t> Ret;
  FOREACH_internal_SYMBOL(PAIR);
  return Ret;
#undef PAIR
});

// This variable controls the behavior of vkGetDevice/InstanceProcAddr for functions we don't know the signature of:
// - if false (default), we return a nullptr (since the application might have a fallback code path)
// - if true, we return a stub function that fatally errors upon being called
//
// FEX_VK_TRAP_UNKNOWN=1 turns this on as a DIAGNOSTIC. The thunk covers only
// part of the API on 32-bit, so a client like DXVK gets null for hundreds of
// entry points. Most of those it merely probes and never calls - it has
// fallbacks - but the few it genuinely requires turn into a silent hang far
// from the cause (observed with Portal 2: every thread parked in futex_wait,
// no window, no further output).
//
// With this set, the first such call traps and names the function, which is
// what tells you which entry points actually need implementing rather than
// guessing among everything that came back null.
static const bool stub_unknown_functions = getenv("FEX_VK_TRAP_UNKNOWN") != nullptr;

// Names of the functions we handed back a trapping stub for, so the trap can
// report which one was called rather than a bare address.
static std::unordered_map<uintptr_t, std::string>& StubbedFunctionNames() {
  static std::unordered_map<uintptr_t, std::string> Map;
  return Map;
}
static std::mutex StubbedFunctionNamesMutex;

// Fatally erroring function with a thunk-like interface. This is used as a placeholder for unknown Vulkan functions
[[noreturn]]
static void FatalError(void* raw_args) {
  auto called_function = reinterpret_cast<PackedArguments<void, uintptr_t>*>(raw_args)->a0;
  const char* Name = "<unknown>";
  {
    std::lock_guard lk {StubbedFunctionNamesMutex};
    auto& Map = StubbedFunctionNames();
    if (auto It = Map.find(called_function); It != Map.end()) {
      Name = It->second.c_str();
    }
  }
  fprintf(stderr, "FATAL: Called unimplemented Vulkan function %s (address %p)\n", Name, reinterpret_cast<void*>(called_function));
  __builtin_trap();
}

static PFN_vkVoidFunction MakeGuestCallable(const char* origin, PFN_vkVoidFunction func, const char* name) {
  auto It = HostPtrInvokers.find(name);
  if (It == HostPtrInvokers.end()) {
    fprintf(stderr, "%s: Unknown Vulkan function at address %p: %s\n", origin, func, name);
    if (stub_unknown_functions) {
      {
        // Remember the name so the trap can report which function was called.
        std::lock_guard lk {StubbedFunctionNamesMutex};
        StubbedFunctionNames().emplace(reinterpret_cast<uintptr_t>(func), name);
      }
      const auto StubHostPtrInvoker = CallHostFunction<FatalError, void>;
      LinkAddressToFunction((uintptr_t)func, reinterpret_cast<uintptr_t>(StubHostPtrInvoker));
      return func;
    }
    return nullptr;
  }
  fprintf(stderr, "Linking address %p to host invoker %#zx\n", func, It->second);
  LinkAddressToFunction((uintptr_t)func, It->second);
  return func;
}

PFN_vkVoidFunction vkGetDeviceProcAddr(VkDevice a_0, const char* a_1) {
  // 2026-05-14: bootstrap self-return.  Loaders commonly call this with the
  // name "vkGetDeviceProcAddr" or "vkGetInstanceProcAddr" to populate their
  // dispatch tables.  Return our own thunk so subsequent dispatches go
  // through the guest_layout-marshalling shim that we ARE.
  if (a_1 == std::string_view {"vkGetDeviceProcAddr"}) {
    return (PFN_vkVoidFunction)vkGetDeviceProcAddr;
  }
  if (a_1 == std::string_view {"vkGetInstanceProcAddr"}) {
    return (PFN_vkVoidFunction)vkGetInstanceProcAddr;
  }
  auto Ret = fexfn_pack_vkGetDeviceProcAddr(a_0, a_1);
  if (!Ret) {
    return nullptr;
  }
  return MakeGuestCallable(__FUNCTION__, Ret, a_1);
}

PFN_vkVoidFunction vkGetInstanceProcAddr(VkInstance a_0, const char* a_1) {
  if (a_1 == std::string_view {"vkGetDeviceProcAddr"}) {
    return (PFN_vkVoidFunction)vkGetDeviceProcAddr;
  }
  // 2026-05-14: the Vulkan loader spec allows (and several loaders do) calling
  // vkGetInstanceProcAddr with the name "vkGetInstanceProcAddr" to fetch a
  // pointer to itself -- either with a NULL instance (early bootstrap) or a
  // real one.  Without this case, MakeGuestCallable() couldn't find the name
  // in HostPtrInvokers (vkGetInstanceProcAddr isn't in the thunkgen FOREACH
  // list -- it IS the thunkgen entry point) and returned nullptr.  Loaders
  // then retried via dlsym(libvulkan, "vkGetInstanceProcAddr"), which looped
  // back through us; with the Vulkan host thunk enabled the recursion
  // accreted guest-stack frames until exhaustion.  Symptom: Steam, FTL, and
  // Grimrock all crashed on the same `stdx r3, r11, r0` push at stack bottom
  // with r3=0x671903 (the bit-identical return-RIP of the looping caller).
  if (a_1 == std::string_view {"vkGetInstanceProcAddr"}) {
    return (PFN_vkVoidFunction)vkGetInstanceProcAddr;
  }
  auto Ret = fexfn_pack_vkGetInstanceProcAddr(a_0, a_1);
  if (!Ret) {
    return nullptr;
  }
  return MakeGuestCallable(__FUNCTION__, Ret, a_1);
}
}

void OnInit() {
  // TODO: Load libX11 on-demand instead
  void* libx11 = dlopen("libX11.so.6", RTLD_LAZY);
  fexfn_pack_Vulkan_SetGuestXSync((uintptr_t)dlsym(libx11, "XSync"), (uintptr_t)CallbackUnpack<decltype(XSync)>::Unpack);
  fexfn_pack_Vulkan_SetGuestXGetVisualInfo((uintptr_t)dlsym(libx11, "XGetVisualInfo"), (uintptr_t)CallbackUnpack<decltype(XGetVisualInfo)>::Unpack);
  fexfn_pack_Vulkan_SetGuestXDisplayString((uintptr_t)dlsym(libx11, "XDisplayString"), (uintptr_t)CallbackUnpack<decltype(XDisplayString)>::Unpack);

  // 2026-05-15 cross-arch callback registry: register CallbackUnpack<F>::Unpack
  // for every signature the host wrapper might see as an un-wrapped callback
  // (i.e. function pointers that flow through struct fields, ICD interface,
  // Vulkan layer chains, or any other path thunkgen doesn't annotate as a
  // callback parameter).  Steam (i686) hits VkResult(uint32_t*) first because
  // the Vulkan layer-chain dispatch table contains a PFN_vkEnumerateInstanceVersion
  // entry whose signature is exactly that.
  RegisterGuestCallbackUnpacker<VkResult(uint32_t*)>();
  RegisterGuestCallbackUnpacker<VkBool32(uint32_t*)>();
  RegisterGuestCallbackUnpacker<void(uint32_t*)>();

  // 2026-05-18 mirror libGL_Guest cross-arch registrations.  Mesa zink and
  // host-Vulkan-via-thunk paths pull these same generic signatures out of
  // Vulkan-side dispatch tables; without them the cross-arch fallback wrap
  // returns zero (FvjE/FvvE/FPKhjE patterns) and Mesa derefs the null
  // result.  Same set proven necessary for FTL libGL path; Grimrock zink
  // and Stardew .NET Core surface the same warnings.
  RegisterGuestCallbackUnpacker<void(unsigned int)>();
  RegisterGuestCallbackUnpacker<void()>();
  RegisterGuestCallbackUnpacker<const unsigned char*(unsigned int)>();
}

LOAD_LIB_INIT(libvulkan, OnInit)
