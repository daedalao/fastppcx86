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

#include "common/Host.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sys/mman.h>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
// The guest's Vulkan loader configuration must never reach the host loader.
//
// These variables name ICD/layer *manifests* and the shared objects they
// point at. Under a thunk those always describe guest-architecture files, so
// letting the host loader read them makes it try to load x86 objects into a
// PPC64LE process. It cannot, and reports the failure as though no usable
// driver existed at all.
//
// This was not hypothetical. Steam's pressure-vessel exports
//   VK_DRIVER_FILES=.../radeon_icd.i686.json:.../amd_icd32.json:...
// (i686 only, because those are the ICD manifests present in the FEX RootFS),
// the host loader found nothing loadable in that list, and every
// vkCreateInstance from inside the container returned -9
// VK_ERROR_INCOMPATIBLE_DRIVER — the Steam client's "CVulkanTopology: failed
// create vulkan instance: -9", and its GPU process aborting on startup.
// Outside the container, where these variables are unset, the very same thunk
// enumerated every GPU correctly.
//
// The host loader's own default search path is the right answer here: driver
// selection on the host side is precisely what the thunk exists to delegate.
// FEX_HOST_<VAR> is honoured first so a host ICD/layer set can still be aimed
// deliberately (e.g. to pick one of several host drivers for testing).
//
// Guest semantics are unaffected: the guest's environment block was
// materialised into guest memory at exec time, long before this host library
// is dlopen()ed, so the guest still sees its own values and passes them to
// any children it spawns.
__attribute__((constructor)) void SanitizeHostVulkanEnvironment() {
  for (const char* Var : {
         "VK_ICD_FILENAMES",
         "VK_DRIVER_FILES",
         "VK_ADD_DRIVER_FILES",
         "VK_LAYER_PATH",
         "VK_ADD_LAYER_PATH",
         "VK_IMPLICIT_LAYER_PATH",
         "VK_ADD_IMPLICIT_LAYER_PATH",
         "VK_INSTANCE_LAYERS",
       }) {
    const auto Override = std::string("FEX_HOST_") + Var;
    if (const char* Value = getenv(Override.c_str())) {
      setenv(Var, Value, 1);
    } else {
      unsetenv(Var);
    }
  }
}
} // namespace

#ifdef IS_32BIT_THUNK
// Union type embedded in VkDescriptorGetInfoEXT
template<>
struct guest_layout<VkDescriptorDataEXT> {
  char union_storage[8];
};

// Dispatchable Vulkan handles are real host pointers (VkInstance is
// VkInstance_T*, and so on), so a 32-bit guest cannot hold one. They are all
// annotated opaque_type in the interface, but that alone only stops the thunk
// generator from walking the pointee - the default conversion still narrows
// the pointer, and the truncation guard then aborts the process.
//
// Observed on Portal 2, a 32-bit title: DXVK calls vkCreateInstance, the host
// returns a VkInstance at 0x3fff'xxxx'xxxx, and FEX aborts with
//   "32-bit truncation of host pointer ... returned to guest"
// inside GuestWrapperForHostFunction<VkResult(const VkInstanceCreateInfo*...)>.
//
// Same treatment the GL handles got (GLXFBConfig, GLXContext, GLsync): hand the
// guest a stable token and translate back on the way in.
//
// Only the six DISPATCHABLE handle types need this. Non-dispatchable handles
// (VkImage, VkBuffer, VkDeviceMemory, ...) are already uint64_t by definition,
// so they survive the trip on their own.
#define FEX_VK_HANDLE_TOKEN(TYPE)                        \
  template<>                                             \
  struct host_layout<TYPE*> {                            \
    TYPE* data;                                          \
    host_layout(const guest_layout<TYPE*>&);             \
  };                                                     \
  guest_layout<TYPE*> to_guest(const host_layout<TYPE*>& from);

FEX_VK_HANDLE_TOKEN(VkInstance_T)
FEX_VK_HANDLE_TOKEN(VkPhysicalDevice_T)
FEX_VK_HANDLE_TOKEN(VkDevice_T)
FEX_VK_HANDLE_TOKEN(VkQueue_T)
FEX_VK_HANDLE_TOKEN(VkCommandBuffer_T)
FEX_VK_HANDLE_TOKEN(VkExternalComputeQueueNV_T)
#undef FEX_VK_HANDLE_TOKEN
#endif

#include "thunkgen_host_libvulkan.inl"

// FEX_VK_ARRAYTRACE=1 logs the count/array queries and the create-info repacks
// that this file implements by hand. Cheap enough to leave in: one cached
// lookup, no work when unset.
static bool VkArrayTrace() {
  static const bool Enabled = getenv("FEX_VK_ARRAYTRACE") != nullptr;
  return Enabled;
}

#include <common/X11Manager.h>

#ifdef IS_32BIT_THUNK
#include <common/OpaqueHandleRegistry.h>

// Backing registries for the handle tokens declared above. Each type gets its
// own token range so a handle passed where a different type is expected is
// rejected rather than silently reinterpreted. The bases sit high in the 32-bit
// range, clear of where a 32-bit guest's own mappings and FEX's low-4GB
// trampolines (0x7000'0000) live, and none of these values is ever
// dereferenced by either side.
//
// Handles are not retired. Instances, devices and physical devices are few and
// long-lived; queues and command buffers are owned by their device and die with
// it. Retiring on vkDestroy* would be tidier but risks resolving a token to
// null while the guest still legitimately holds it, and the registries are
// bounded in practice. glDeleteSync needed retirement because a title fences
// once per frame - nothing here has that shape.
namespace {
FEX::Thunks::OpaqueHandleRegistry<VkInstance_T, 0xE100'0000> InstanceRegistry;
FEX::Thunks::OpaqueHandleRegistry<VkPhysicalDevice_T, 0xE200'0000> PhysicalDeviceRegistry;
FEX::Thunks::OpaqueHandleRegistry<VkDevice_T, 0xE300'0000> DeviceRegistry;
FEX::Thunks::OpaqueHandleRegistry<VkQueue_T, 0xE400'0000> QueueRegistry;
FEX::Thunks::OpaqueHandleRegistry<VkCommandBuffer_T, 0xE500'0000> CommandBufferRegistry;
FEX::Thunks::OpaqueHandleRegistry<VkExternalComputeQueueNV_T, 0xE600'0000> ExternalComputeQueueRegistry;
} // namespace

#define FEX_VK_HANDLE_TOKEN_IMPL(TYPE, REGISTRY)                              \
  host_layout<TYPE*>::host_layout(const guest_layout<TYPE*>& guest)           \
    : data(REGISTRY.ForToken(static_cast<uint32_t>(guest.data))) {}           \
                                                                              \
  guest_layout<TYPE*> to_guest(const host_layout<TYPE*>& from) {              \
    guest_layout<TYPE*> Result {};                                            \
    Result.data = REGISTRY.TokenFor(from.data);                               \
    return Result;                                                            \
  }

FEX_VK_HANDLE_TOKEN_IMPL(VkInstance_T, InstanceRegistry)
FEX_VK_HANDLE_TOKEN_IMPL(VkPhysicalDevice_T, PhysicalDeviceRegistry)
FEX_VK_HANDLE_TOKEN_IMPL(VkDevice_T, DeviceRegistry)
FEX_VK_HANDLE_TOKEN_IMPL(VkQueue_T, QueueRegistry)
FEX_VK_HANDLE_TOKEN_IMPL(VkCommandBuffer_T, CommandBufferRegistry)
FEX_VK_HANDLE_TOKEN_IMPL(VkExternalComputeQueueNV_T, ExternalComputeQueueRegistry)
#undef FEX_VK_HANDLE_TOKEN_IMPL
#endif

static bool SetupInstance {};
static std::mutex SetupMutex {};

#define LDR_PTR(fn) fexldr_ptr_libvulkan_##fn

static void DoSetupWithInstance(VkInstance instance) {
  std::unique_lock lk {SetupMutex};

  // Needed since the Guest-endpoint calls without a function pointer
  // TODO: Support use of multiple instances
  (void*&)LDR_PTR(vkGetDeviceProcAddr) = (void*)LDR_PTR(vkGetInstanceProcAddr)(instance, "vkGetDeviceProcAddr");
  if (LDR_PTR(vkGetDeviceProcAddr) == nullptr) {
    std::abort();
  }

  // Query pointers for non-EXT functions customized below
  (void*&)LDR_PTR(vkCreateDevice) = (void*)LDR_PTR(vkGetInstanceProcAddr)(instance, "vkCreateDevice");

  // Only do this lookup once.
  // NOTE: If vkGetInstanceProcAddr was called with a null instance, only a few function pointers will be filled with non-null values, so we do repeat the lookup in that case
  if (instance) {
    SetupInstance = true;
  }
}

#define FEXFN_IMPL(fn) fexfn_impl_libvulkan_##fn

static X11Manager x11_manager;

static void fexfn_impl_libvulkan_Vulkan_SetGuestXGetVisualInfo(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &x11_manager.GuestXGetVisualInfo);
}

static void fexfn_impl_libvulkan_Vulkan_SetGuestXSync(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &x11_manager.GuestXSync);
}

static void fexfn_impl_libvulkan_Vulkan_SetGuestXDisplayString(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &x11_manager.GuestXDisplayString);
}

void fex_custom_repack_entry(host_layout<VkXcbSurfaceCreateInfoKHR>& to, const guest_layout<VkXcbSurfaceCreateInfoKHR>& from) {
  // TODO: xcb_aux_sync?
  to.data.connection = x11_manager.GuestToHostConnection(const_cast<xcb_connection_t*>(from.data.connection.force_get_host_pointer()));
}

bool fex_custom_repack_exit(guest_layout<VkXcbSurfaceCreateInfoKHR>&, const host_layout<VkXcbSurfaceCreateInfoKHR>&) {
  // TODO: xcb_sync?
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkXlibSurfaceCreateInfoKHR>& to, const guest_layout<VkXlibSurfaceCreateInfoKHR>& from) {
  to.data.dpy = x11_manager.GuestToHostDisplay(const_cast<Display*>(from.data.dpy.force_get_host_pointer()));
}

bool fex_custom_repack_exit(guest_layout<VkXlibSurfaceCreateInfoKHR>&, const host_layout<VkXlibSurfaceCreateInfoKHR>& from) {
  x11_manager.HostXFlush(from.data.dpy);
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

static VkResult fexfn_impl_libvulkan_vkAcquireXlibDisplayEXT(VkPhysicalDevice a_0, guest_layout<Display*> a_1, VkDisplayKHR a_2) {
  auto host_display = x11_manager.GuestToHostDisplay(a_1.force_get_host_pointer());
  auto ret = fexldr_ptr_libvulkan_vkAcquireXlibDisplayEXT(a_0, host_display, a_2);
  x11_manager.HostXFlush(host_display);
  return ret;
}

static VkResult fexfn_impl_libvulkan_vkGetRandROutputDisplayEXT(VkPhysicalDevice a_0, guest_layout<Display*> a_1, RROutput a_2, VkDisplayKHR* a_3) {
  auto host_display = x11_manager.GuestToHostDisplay(a_1.force_get_host_pointer());
  auto ret = fexldr_ptr_libvulkan_vkGetRandROutputDisplayEXT(a_0, host_display, a_2, a_3);
  x11_manager.HostXFlush(host_display);
  return ret;
}

static VkBool32 fexfn_impl_libvulkan_vkGetPhysicalDeviceXcbPresentationSupportKHR(VkPhysicalDevice a_0, uint32_t a_1,
                                                                                  guest_layout<xcb_connection_t*> a_2, xcb_visualid_t a_3) {
  auto host_connection = x11_manager.GuestToHostConnection(a_2.force_get_host_pointer());
  return fexldr_ptr_libvulkan_vkGetPhysicalDeviceXcbPresentationSupportKHR(a_0, a_1, host_connection, a_3);
}

static VkBool32 fexfn_impl_libvulkan_vkGetPhysicalDeviceXlibPresentationSupportKHR(VkPhysicalDevice a_0, uint32_t a_1,
                                                                                   guest_layout<Display*> a_2, VisualID a_3) {
  auto host_display = x11_manager.GuestToHostDisplay(a_2.force_get_host_pointer());
  auto ret = fexldr_ptr_libvulkan_vkGetPhysicalDeviceXlibPresentationSupportKHR(a_0, a_1, host_display, a_3);
  x11_manager.HostXFlush(host_display);
  return ret;
}

// Functions with callbacks are overridden to ignore the guest-side callbacks

static VkResult
FEXFN_IMPL(vkCreateShaderModule)(VkDevice a_0, const VkShaderModuleCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkShaderModule* a_3) {
  (void*&)LDR_PTR(vkCreateShaderModule) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateShaderModule");
  return LDR_PTR(vkCreateShaderModule)(a_0, a_1, nullptr, a_3);
}

static VkBool32
DummyVkDebugReportCallback(VkDebugReportFlagsEXT, VkDebugReportObjectTypeEXT, uint64_t, size_t, int32_t, const char*, const char*, void*) {
  return VK_FALSE;
}

static VkResult FEXFN_IMPL(vkCreateInstance)(const VkInstanceCreateInfo* a_0, const VkAllocationCallbacks* a_1, guest_layout<VkInstance*> a_2) {
  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: vkCreateInstance impl entered info=%p out=%p ldr=%p\n", (const void*)a_0, (void*)a_2.get_pointer(),
            (void*)LDR_PTR(vkCreateInstance));
    fflush(stderr);
  }
  const VkInstanceCreateInfo* vk_struct_base = a_0;
  for (const VkBaseInStructure* vk_struct = reinterpret_cast<const VkBaseInStructure*>(vk_struct_base); vk_struct->pNext;
       vk_struct = vk_struct->pNext) {
    // Override guest callbacks used for VK_EXT_debug_report AND
    // VK_EXT_debug_utils.  Both struct types embed a pfn*Callback that is
    // a guest VA — if native libvulkan invokes them, it runs guest code as
    // host code and SEGVs.  The standalone vkCreateDebugUtilsMessengerEXT
    // path replaces pfnUserCallback with DummyVkDebugUtilsMessengerCallback,
    // but the pNext-of-VkInstanceCreateInfo path was bypassing that
    // protection entirely — strip the messenger struct as well.
    const auto sType = reinterpret_cast<const VkBaseInStructure*>(vk_struct->pNext)->sType;
    if (sType == VK_STRUCTURE_TYPE_DEBUG_REPORT_CREATE_INFO_EXT ||
        sType == VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT) {
      // Overwrite the pNext pointer, ignoring its const-qualifier
      const_cast<VkBaseInStructure*>(vk_struct)->pNext = vk_struct->pNext->pNext;

      // If we copied over a nullptr for pNext then early exit
      if (!vk_struct->pNext) {
        break;
      }
    }
  }

  VkInstance out;
  auto ret = LDR_PTR(vkCreateInstance)(vk_struct_base, nullptr, &out);
  *a_2.get_pointer() = to_guest(to_host_layout(out));
  return ret;
}

#ifdef IS_32BIT_THUNK
static void EnablePlacedMapsForDevice(VkPhysicalDevice PhysicalDevice, VkDevice Device);
static bool DeviceSupportsPlacedMaps(VkPhysicalDevice PhysicalDevice);
#endif

static VkResult FEXFN_IMPL(vkCreateDevice)(VkPhysicalDevice a_0, const VkDeviceCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                           guest_layout<VkDevice*> a_3) {
  // Add VK_EXT_map_memory_placed (and the VK_KHR_map_memory2 it builds on) to
  // whatever the guest asked for. The guest will not request them - DXVK has no
  // reason to - but without them vkMapMemory cannot return an address a 32-bit
  // guest can hold. Same injection wine performs for wow64.
#ifdef IS_32BIT_THUNK
  VkDeviceCreateInfo PatchedInfo = *a_1;
  std::vector<const char*> PatchedExtensions;
  VkPhysicalDeviceMapMemoryPlacedFeaturesEXT PlacedFeatures {
    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAP_MEMORY_PLACED_FEATURES_EXT,
    .pNext = const_cast<void*>(a_1->pNext),
    .memoryMapPlaced = VK_TRUE,
    .memoryMapRangePlaced = VK_FALSE,
    .memoryUnmapReserve = VK_TRUE,
  };

  const bool WantPlaced = DeviceSupportsPlacedMaps(a_0);
  if (WantPlaced) {
    PatchedExtensions.assign(a_1->ppEnabledExtensionNames, a_1->ppEnabledExtensionNames + a_1->enabledExtensionCount);
    for (const char* Name : {VK_KHR_MAP_MEMORY_2_EXTENSION_NAME, VK_EXT_MAP_MEMORY_PLACED_EXTENSION_NAME}) {
      auto Already = std::any_of(PatchedExtensions.begin(), PatchedExtensions.end(),
                                 [&](const char* E) { return std::string_view {E} == Name; });
      if (!Already) {
        PatchedExtensions.push_back(Name);
      }
    }
    PatchedInfo.enabledExtensionCount = PatchedExtensions.size();
    PatchedInfo.ppEnabledExtensionNames = PatchedExtensions.data();
    PatchedInfo.pNext = &PlacedFeatures;
    a_1 = &PatchedInfo;
  }
#endif

  VkDevice out;
  auto ret = LDR_PTR(vkCreateDevice)(a_0, a_1, nullptr, &out);
#ifdef IS_32BIT_THUNK
  if (ret == VK_SUCCESS && WantPlaced) {
    EnablePlacedMapsForDevice(a_0, out);
  }
#endif
  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: vkCreateDevice ret=%d device=%p out_guest=%p\n", ret, (void*)out, (void*)a_3.get_pointer());
    fflush(stderr);
  }
  *a_3.get_pointer() = to_guest(to_host_layout(out));

  // Reload device-specific function pointers used in custom implementations.
  // This is only done in advance for functions that don't take a VkDevice
  // argument. Since this breaks multi-device scenarios, other functions reload
  // the function pointer on-demand.
  // NOTE: Running KHR-GLES31.core.compute_shader.simple-compute-shared_context with zink may trigger related issues
  // TODO: Support multi-device scenarios everywhere
#ifdef IS_32BIT_THUNK
  fexldr_ptr_libvulkan_vkCmdSetVertexInputEXT = (PFN_vkCmdSetVertexInputEXT)fexldr_ptr_libvulkan_vkGetDeviceProcAddr(out, "vkCmdSetVertexIn"
                                                                                                                          "putEXT");
  fexldr_ptr_libvulkan_vkQueueSubmit = (PFN_vkQueueSubmit)fexldr_ptr_libvulkan_vkGetDeviceProcAddr(out, "vkQueueSubmit");
#else
  // No functions affected on 64-bit
#endif

  return ret;
}

#ifdef IS_32BIT_THUNK
static void RecordPlacedAllocationSize(VkDeviceMemory Memory, VkDeviceSize Size);
static void ForgetPlacedAllocation(VkDeviceMemory Memory);
#endif

static VkResult FEXFN_IMPL(vkAllocateMemory)(VkDevice a_0, const VkMemoryAllocateInfo* a_1, const VkAllocationCallbacks* a_2, VkDeviceMemory* a_3) {
  (void*&)LDR_PTR(vkAllocateMemory) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkAllocateMemory");
  auto Ret = LDR_PTR(vkAllocateMemory)(a_0, a_1, nullptr, a_3);
#ifdef IS_32BIT_THUNK
  if (Ret == VK_SUCCESS) {
    // A VK_WHOLE_SIZE vkMapMemory has to be given a placed reservation covering
    // the whole allocation, and the size is not recoverable at map time.
    RecordPlacedAllocationSize(*a_3, a_1->allocationSize);
  }
#endif
  return Ret;
}

static void FEXFN_IMPL(vkFreeMemory)(VkDevice a_0, VkDeviceMemory a_1, const VkAllocationCallbacks* a_2) {
#ifdef IS_32BIT_THUNK
  ForgetPlacedAllocation(a_1);
#endif
  (void*&)LDR_PTR(vkFreeMemory) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkFreeMemory");
  LDR_PTR(vkFreeMemory)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateDebugReportCallbackEXT)(VkInstance a_0, guest_layout<const VkDebugReportCallbackCreateInfoEXT*> a_1,
                                                           const VkAllocationCallbacks* a_2, VkDebugReportCallbackEXT* a_3) {
  auto overridden_callback = host_layout<VkDebugReportCallbackCreateInfoEXT> {*a_1.get_pointer()}.data;
  overridden_callback.pfnCallback = DummyVkDebugReportCallback;
  (void*&)LDR_PTR(vkCreateDebugReportCallbackEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateDebugReportCallbackEXT");
  return LDR_PTR(vkCreateDebugReportCallbackEXT)(a_0, &overridden_callback, nullptr, a_3);
}

static void FEXFN_IMPL(vkDestroyDebugReportCallbackEXT)(VkInstance a_0, VkDebugReportCallbackEXT a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDebugReportCallbackEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkDestroyDebugReportCallbackEXT");
  LDR_PTR(vkDestroyDebugReportCallbackEXT)(a_0, a_1, nullptr);
}

extern "C" VkBool32 DummyVkDebugUtilsMessengerCallback(VkDebugUtilsMessageSeverityFlagBitsEXT, VkDebugUtilsMessageTypeFlagsEXT,
                                                       const VkDebugUtilsMessengerCallbackDataEXT*, void*) {
  return VK_FALSE;
}

static VkResult FEXFN_IMPL(vkCreateDebugUtilsMessengerEXT)(VkInstance_T* a_0, guest_layout<const VkDebugUtilsMessengerCreateInfoEXT*> a_1,
                                                           const VkAllocationCallbacks* a_2, VkDebugUtilsMessengerEXT* a_3) {
  auto overridden_callback = host_layout<VkDebugUtilsMessengerCreateInfoEXT> {*a_1.get_pointer()}.data;
  overridden_callback.pfnUserCallback = DummyVkDebugUtilsMessengerCallback;
  (void*&)LDR_PTR(vkCreateDebugUtilsMessengerEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateDebugUtilsMessengerEXT");
  return LDR_PTR(vkCreateDebugUtilsMessengerEXT)(a_0, &overridden_callback, nullptr, a_3);
}

// VkAllocationCallbacks embeds five guest function pointers (pfnAllocation,
// pfnReallocation, pfnFree, pfnInternalAllocation, pfnInternalFree).  Passing
// the struct through to native libvulkan causes it to interpret those guest
// VAs as host code pointers and SEGV the moment it tries to allocate.  Each
// FEXFN_IMPL wrapper below forces nullptr for pAllocator so the native loader
// uses its default allocator.  Device-level entrypoints look up their proc-
// addr lazily via vkGetDeviceProcAddr to remain multi-device-tolerant, matching
// the existing vkCreateShaderModule / vkAllocateMemory pattern.

static VkResult FEXFN_IMPL(vkCreateBuffer)(VkDevice a_0, const VkBufferCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkBuffer* a_3) {
  (void*&)LDR_PTR(vkCreateBuffer) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateBuffer");
  return LDR_PTR(vkCreateBuffer)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyBuffer)(VkDevice a_0, VkBuffer a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyBuffer) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyBuffer");
  LDR_PTR(vkDestroyBuffer)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateBufferView)(VkDevice a_0, const VkBufferViewCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkBufferView* a_3) {
  (void*&)LDR_PTR(vkCreateBufferView) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateBufferView");
  return LDR_PTR(vkCreateBufferView)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyBufferView)(VkDevice a_0, VkBufferView a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyBufferView) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyBufferView");
  LDR_PTR(vkDestroyBufferView)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateImage)(VkDevice a_0, const VkImageCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkImage* a_3) {
  (void*&)LDR_PTR(vkCreateImage) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateImage");
  return LDR_PTR(vkCreateImage)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyImage)(VkDevice a_0, VkImage a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyImage) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyImage");
  LDR_PTR(vkDestroyImage)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateImageView)(VkDevice a_0, const VkImageViewCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkImageView* a_3) {
  (void*&)LDR_PTR(vkCreateImageView) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateImageView");
  return LDR_PTR(vkCreateImageView)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyImageView)(VkDevice a_0, VkImageView a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyImageView) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyImageView");
  LDR_PTR(vkDestroyImageView)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreatePipelineCache)(VkDevice a_0, const VkPipelineCacheCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                                  VkPipelineCache* a_3) {
  (void*&)LDR_PTR(vkCreatePipelineCache) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreatePipelineCache");
  return LDR_PTR(vkCreatePipelineCache)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyPipelineCache)(VkDevice a_0, VkPipelineCache a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyPipelineCache) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyPipelineCache");
  LDR_PTR(vkDestroyPipelineCache)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateGraphicsPipelines)(VkDevice a_0, VkPipelineCache a_1, uint32_t a_2, const VkGraphicsPipelineCreateInfo* a_3,
                                                     const VkAllocationCallbacks* a_4, VkPipeline* a_5) {
  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: vkCreateGraphicsPipelines count=%u info=%p", a_2, (const void*)a_3);
    if (a_3) {
      fprintf(stderr, " stages=%u pStages=%p vi=%p ia=%p vp=%p rs=%p ms=%p ds=%p cb=%p dyn=%p layout=%p pNext=%p flags=%x",
              a_3->stageCount, (const void*)a_3->pStages, (const void*)a_3->pVertexInputState, (const void*)a_3->pInputAssemblyState,
              (const void*)a_3->pViewportState, (const void*)a_3->pRasterizationState, (const void*)a_3->pMultisampleState,
              (const void*)a_3->pDepthStencilState, (const void*)a_3->pColorBlendState, (const void*)a_3->pDynamicState,
              (const void*)a_3->layout, (const void*)a_3->pNext, a_3->flags);
    }
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  (void*&)LDR_PTR(vkCreateGraphicsPipelines) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateGraphicsPipelines");
  return LDR_PTR(vkCreateGraphicsPipelines)(a_0, a_1, a_2, a_3, nullptr, a_5);
}

#ifndef IS_32BIT_THUNK
static VkResult FEXFN_IMPL(vkCreateComputePipelines)(VkDevice a_0, VkPipelineCache a_1, uint32_t a_2, const VkComputePipelineCreateInfo* a_3,
                                                    const VkAllocationCallbacks* a_4, VkPipeline* a_5) {
  (void*&)LDR_PTR(vkCreateComputePipelines) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateComputePipelines");
  return LDR_PTR(vkCreateComputePipelines)(a_0, a_1, a_2, a_3, nullptr, a_5);
}
#endif

static void FEXFN_IMPL(vkDestroyPipeline)(VkDevice a_0, VkPipeline a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyPipeline) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyPipeline");
  LDR_PTR(vkDestroyPipeline)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreatePipelineLayout)(VkDevice a_0, const VkPipelineLayoutCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                                  VkPipelineLayout* a_3) {
  (void*&)LDR_PTR(vkCreatePipelineLayout) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreatePipelineLayout");
  return LDR_PTR(vkCreatePipelineLayout)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyPipelineLayout)(VkDevice a_0, VkPipelineLayout a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyPipelineLayout) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyPipelineLayout");
  LDR_PTR(vkDestroyPipelineLayout)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateSampler)(VkDevice a_0, const VkSamplerCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkSampler* a_3) {
  (void*&)LDR_PTR(vkCreateSampler) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateSampler");
  return LDR_PTR(vkCreateSampler)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroySampler)(VkDevice a_0, VkSampler a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySampler) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroySampler");
  LDR_PTR(vkDestroySampler)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateDescriptorSetLayout)(VkDevice a_0, const VkDescriptorSetLayoutCreateInfo* a_1,
                                                       const VkAllocationCallbacks* a_2, VkDescriptorSetLayout* a_3) {
  (void*&)LDR_PTR(vkCreateDescriptorSetLayout) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateDescriptorSetLayout");
  return LDR_PTR(vkCreateDescriptorSetLayout)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyDescriptorSetLayout)(VkDevice a_0, VkDescriptorSetLayout a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDescriptorSetLayout) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyDescriptorSetLayout");
  LDR_PTR(vkDestroyDescriptorSetLayout)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateDescriptorPool)(VkDevice a_0, const VkDescriptorPoolCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                                  VkDescriptorPool* a_3) {
  (void*&)LDR_PTR(vkCreateDescriptorPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateDescriptorPool");
  return LDR_PTR(vkCreateDescriptorPool)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyDescriptorPool)(VkDevice a_0, VkDescriptorPool a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDescriptorPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyDescriptorPool");
  LDR_PTR(vkDestroyDescriptorPool)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateSemaphore)(VkDevice a_0, const VkSemaphoreCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkSemaphore* a_3) {
  (void*&)LDR_PTR(vkCreateSemaphore) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateSemaphore");
  return LDR_PTR(vkCreateSemaphore)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroySemaphore)(VkDevice a_0, VkSemaphore a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySemaphore) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroySemaphore");
  LDR_PTR(vkDestroySemaphore)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateFence)(VkDevice a_0, const VkFenceCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkFence* a_3) {
  (void*&)LDR_PTR(vkCreateFence) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateFence");
  return LDR_PTR(vkCreateFence)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyFence)(VkDevice a_0, VkFence a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyFence) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyFence");
  LDR_PTR(vkDestroyFence)(a_0, a_1, nullptr);
}

#ifndef IS_32BIT_THUNK
static VkResult FEXFN_IMPL(vkCreateEvent)(VkDevice a_0, const VkEventCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkEvent* a_3) {
  (void*&)LDR_PTR(vkCreateEvent) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateEvent");
  return LDR_PTR(vkCreateEvent)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyEvent)(VkDevice a_0, VkEvent a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyEvent) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyEvent");
  LDR_PTR(vkDestroyEvent)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateQueryPool)(VkDevice a_0, const VkQueryPoolCreateInfo* a_1, const VkAllocationCallbacks* a_2, VkQueryPool* a_3) {
  (void*&)LDR_PTR(vkCreateQueryPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateQueryPool");
  return LDR_PTR(vkCreateQueryPool)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyQueryPool)(VkDevice a_0, VkQueryPool a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyQueryPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyQueryPool");
  LDR_PTR(vkDestroyQueryPool)(a_0, a_1, nullptr);
}
#endif

static VkResult FEXFN_IMPL(vkCreateFramebuffer)(VkDevice a_0, const VkFramebufferCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                               VkFramebuffer* a_3) {
  (void*&)LDR_PTR(vkCreateFramebuffer) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateFramebuffer");
  return LDR_PTR(vkCreateFramebuffer)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyFramebuffer)(VkDevice a_0, VkFramebuffer a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyFramebuffer) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyFramebuffer");
  LDR_PTR(vkDestroyFramebuffer)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateRenderPass)(VkDevice a_0, const VkRenderPassCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                              VkRenderPass* a_3) {
  (void*&)LDR_PTR(vkCreateRenderPass) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateRenderPass");
  return LDR_PTR(vkCreateRenderPass)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyRenderPass)(VkDevice a_0, VkRenderPass a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyRenderPass) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyRenderPass");
  LDR_PTR(vkDestroyRenderPass)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateRenderPass2)(VkDevice a_0, const VkRenderPassCreateInfo2* a_1, const VkAllocationCallbacks* a_2,
                                               VkRenderPass* a_3) {
  (void*&)LDR_PTR(vkCreateRenderPass2) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateRenderPass2");
  return LDR_PTR(vkCreateRenderPass2)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreateRenderPass2KHR)(VkDevice a_0, const VkRenderPassCreateInfo2* a_1, const VkAllocationCallbacks* a_2,
                                                  VkRenderPass* a_3) {
  (void*&)LDR_PTR(vkCreateRenderPass2KHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateRenderPass2KHR");
  return LDR_PTR(vkCreateRenderPass2KHR)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreateCommandPool)(VkDevice a_0, const VkCommandPoolCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                               VkCommandPool* a_3) {
  (void*&)LDR_PTR(vkCreateCommandPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateCommandPool");
  return LDR_PTR(vkCreateCommandPool)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyCommandPool)(VkDevice a_0, VkCommandPool a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyCommandPool) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyCommandPool");
  LDR_PTR(vkDestroyCommandPool)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateSwapchainKHR)(VkDevice a_0, const VkSwapchainCreateInfoKHR* a_1, const VkAllocationCallbacks* a_2,
                                                VkSwapchainKHR* a_3) {
  (void*&)LDR_PTR(vkCreateSwapchainKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateSwapchainKHR");
  return LDR_PTR(vkCreateSwapchainKHR)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroySwapchainKHR)(VkDevice a_0, VkSwapchainKHR a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySwapchainKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroySwapchainKHR");
  LDR_PTR(vkDestroySwapchainKHR)(a_0, a_1, nullptr);
}

// Follow-up wrappers covering instance/device shutdown plus surface creation
// and the Vulkan 1.1/1.2/1.3 + EXT/KHR descriptor-update-template /
// private-data-slot / sampler-ycbcr-conversion / validation-cache paths.
// Same nullptr-pAllocator rationale as the block above.

static void FEXFN_IMPL(vkDestroyInstance)(VkInstance a_0, const VkAllocationCallbacks* a_1) {
  (void*&)LDR_PTR(vkDestroyInstance) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkDestroyInstance");
  LDR_PTR(vkDestroyInstance)(a_0, nullptr);
}

static void FEXFN_IMPL(vkDestroyDevice)(VkDevice a_0, const VkAllocationCallbacks* a_1) {
  (void*&)LDR_PTR(vkDestroyDevice) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyDevice");
  LDR_PTR(vkDestroyDevice)(a_0, nullptr);
}

static void FEXFN_IMPL(vkDestroyShaderModule)(VkDevice a_0, VkShaderModule a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyShaderModule) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyShaderModule");
  LDR_PTR(vkDestroyShaderModule)(a_0, a_1, nullptr);
}

static void FEXFN_IMPL(vkDestroySurfaceKHR)(VkInstance a_0, VkSurfaceKHR a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySurfaceKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkDestroySurfaceKHR");
  LDR_PTR(vkDestroySurfaceKHR)(a_0, a_1, nullptr);
}

// WSI surface creators (vkCreateXlib/Xcb/WaylandSurfaceKHR).
//
// These were previously thunkgen-default because their Vk*SurfaceCreateInfoKHR
// embeds a Display*/xcb_connection_t* that must be translated via x11_manager
// (through the fex_custom_repack_entry hooks above).  But the auto-generated
// unpacker forwarded the guest pAllocator VERBATIM to the native driver.
// VkAllocationCallbacks is an opaque_type embedding five GUEST function
// pointers; if a guest supplies a custom allocator the native driver interprets
// those guest VAs as host code and SEGVs -- the same hazard class as the
// allocator-nulling family below.  (The WSI path rarely allocates through
// pAllocator today, which is why this was latent, but "rarely" is not "never":
// e.g. layered/driver-internal surface bookkeeping can honor it.)
//
// Convert them to custom_host_impl so pAllocator can be forced to nullptr.  The
// Display*/xcb_connection_t* translation is unaffected: the parameter is left
// non-passthrough, so the generated unpacker still wraps pCreateInfo in a
// repack_wrapper -- applying the custom entry-repack (dpy/connection + pNext)
// before this impl runs and the custom exit-repack (HostXFlush) after it
// returns -- and hands us the already-translated native host pointer.  The only
// deviation from the auto-generated path is substituting nullptr for the guest
// pAllocator, exactly like vkCreateDisplayPlaneSurfaceKHR / vkCreateHeadless-
// SurfaceEXT.  Defined unconditionally so 32-bit and 64-bit thunks both work.
static VkResult FEXFN_IMPL(vkCreateXlibSurfaceKHR)(VkInstance a_0, const VkXlibSurfaceCreateInfoKHR* a_1,
                                                   const VkAllocationCallbacks* a_2, VkSurfaceKHR* a_3) {
  (void*&)LDR_PTR(vkCreateXlibSurfaceKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateXlibSurfaceKHR");
  return LDR_PTR(vkCreateXlibSurfaceKHR)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreateXcbSurfaceKHR)(VkInstance a_0, const VkXcbSurfaceCreateInfoKHR* a_1,
                                                  const VkAllocationCallbacks* a_2, VkSurfaceKHR* a_3) {
  (void*&)LDR_PTR(vkCreateXcbSurfaceKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateXcbSurfaceKHR");
  return LDR_PTR(vkCreateXcbSurfaceKHR)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreateWaylandSurfaceKHR)(VkInstance a_0, const VkWaylandSurfaceCreateInfoKHR* a_1,
                                                      const VkAllocationCallbacks* a_2, VkSurfaceKHR* a_3) {
  (void*&)LDR_PTR(vkCreateWaylandSurfaceKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateWaylandSurfaceKHR");
  return LDR_PTR(vkCreateWaylandSurfaceKHR)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreateDescriptorUpdateTemplate)(VkDevice a_0, const VkDescriptorUpdateTemplateCreateInfo* a_1,
                                                             const VkAllocationCallbacks* a_2, VkDescriptorUpdateTemplate* a_3) {
  (void*&)LDR_PTR(vkCreateDescriptorUpdateTemplate) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateDescriptorUpdateTemplate");
  return LDR_PTR(vkCreateDescriptorUpdateTemplate)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyDescriptorUpdateTemplate)(VkDevice a_0, VkDescriptorUpdateTemplate a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDescriptorUpdateTemplate) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyDescriptorUpdateTemplate");
  LDR_PTR(vkDestroyDescriptorUpdateTemplate)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateDescriptorUpdateTemplateKHR)(VkDevice a_0, const VkDescriptorUpdateTemplateCreateInfo* a_1,
                                                                const VkAllocationCallbacks* a_2, VkDescriptorUpdateTemplate* a_3) {
  (void*&)LDR_PTR(vkCreateDescriptorUpdateTemplateKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateDescriptorUpdateTemplateKHR");
  return LDR_PTR(vkCreateDescriptorUpdateTemplateKHR)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyDescriptorUpdateTemplateKHR)(VkDevice a_0, VkDescriptorUpdateTemplate a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDescriptorUpdateTemplateKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyDescriptorUpdateTemplateKHR");
  LDR_PTR(vkDestroyDescriptorUpdateTemplateKHR)(a_0, a_1, nullptr);
}

static void FEXFN_IMPL(vkDestroyDebugUtilsMessengerEXT)(VkInstance a_0, VkDebugUtilsMessengerEXT a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyDebugUtilsMessengerEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkDestroyDebugUtilsMessengerEXT");
  LDR_PTR(vkDestroyDebugUtilsMessengerEXT)(a_0, a_1, nullptr);
}

#ifndef IS_32BIT_THUNK
static VkResult FEXFN_IMPL(vkCreateDisplayPlaneSurfaceKHR)(VkInstance a_0, const VkDisplaySurfaceCreateInfoKHR* a_1,
                                                           const VkAllocationCallbacks* a_2, VkSurfaceKHR* a_3) {
  (void*&)LDR_PTR(vkCreateDisplayPlaneSurfaceKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateDisplayPlaneSurfaceKHR");
  return LDR_PTR(vkCreateDisplayPlaneSurfaceKHR)(a_0, a_1, nullptr, a_3);
}

// vkCreateDisplayModeKHR takes VkPhysicalDevice; no owning VkInstance is in
// scope to refresh the proc-addr from, so reuse the pre-loaded dlsym pointer.
static VkResult FEXFN_IMPL(vkCreateDisplayModeKHR)(VkPhysicalDevice a_0, VkDisplayKHR a_1, const VkDisplayModeCreateInfoKHR* a_2,
                                                   const VkAllocationCallbacks* a_3, VkDisplayModeKHR* a_4) {
  return LDR_PTR(vkCreateDisplayModeKHR)(a_0, a_1, a_2, nullptr, a_4);
}

static VkResult FEXFN_IMPL(vkCreateHeadlessSurfaceEXT)(VkInstance a_0, const VkHeadlessSurfaceCreateInfoEXT* a_1,
                                                       const VkAllocationCallbacks* a_2, VkSurfaceKHR* a_3) {
  (void*&)LDR_PTR(vkCreateHeadlessSurfaceEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkCreateHeadlessSurfaceEXT");
  return LDR_PTR(vkCreateHeadlessSurfaceEXT)(a_0, a_1, nullptr, a_3);
}

static VkResult FEXFN_IMPL(vkCreatePrivateDataSlot)(VkDevice a_0, const VkPrivateDataSlotCreateInfo* a_1, const VkAllocationCallbacks* a_2,
                                                    VkPrivateDataSlot* a_3) {
  (void*&)LDR_PTR(vkCreatePrivateDataSlot) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreatePrivateDataSlot");
  return LDR_PTR(vkCreatePrivateDataSlot)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyPrivateDataSlot)(VkDevice a_0, VkPrivateDataSlot a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyPrivateDataSlot) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyPrivateDataSlot");
  LDR_PTR(vkDestroyPrivateDataSlot)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreatePrivateDataSlotEXT)(VkDevice a_0, const VkPrivateDataSlotCreateInfo* a_1,
                                                       const VkAllocationCallbacks* a_2, VkPrivateDataSlot* a_3) {
  (void*&)LDR_PTR(vkCreatePrivateDataSlotEXT) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreatePrivateDataSlotEXT");
  return LDR_PTR(vkCreatePrivateDataSlotEXT)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyPrivateDataSlotEXT)(VkDevice a_0, VkPrivateDataSlot a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyPrivateDataSlotEXT) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyPrivateDataSlotEXT");
  LDR_PTR(vkDestroyPrivateDataSlotEXT)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateSamplerYcbcrConversion)(VkDevice a_0, const VkSamplerYcbcrConversionCreateInfo* a_1,
                                                           const VkAllocationCallbacks* a_2, VkSamplerYcbcrConversion* a_3) {
  (void*&)LDR_PTR(vkCreateSamplerYcbcrConversion) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateSamplerYcbcrConversion");
  return LDR_PTR(vkCreateSamplerYcbcrConversion)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroySamplerYcbcrConversion)(VkDevice a_0, VkSamplerYcbcrConversion a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySamplerYcbcrConversion) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroySamplerYcbcrConversion");
  LDR_PTR(vkDestroySamplerYcbcrConversion)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateSamplerYcbcrConversionKHR)(VkDevice a_0, const VkSamplerYcbcrConversionCreateInfo* a_1,
                                                              const VkAllocationCallbacks* a_2, VkSamplerYcbcrConversion* a_3) {
  (void*&)LDR_PTR(vkCreateSamplerYcbcrConversionKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateSamplerYcbcrConversionKHR");
  return LDR_PTR(vkCreateSamplerYcbcrConversionKHR)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroySamplerYcbcrConversionKHR)(VkDevice a_0, VkSamplerYcbcrConversion a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroySamplerYcbcrConversionKHR) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroySamplerYcbcrConversionKHR");
  LDR_PTR(vkDestroySamplerYcbcrConversionKHR)(a_0, a_1, nullptr);
}

static VkResult FEXFN_IMPL(vkCreateValidationCacheEXT)(VkDevice a_0, const VkValidationCacheCreateInfoEXT* a_1,
                                                       const VkAllocationCallbacks* a_2, VkValidationCacheEXT* a_3) {
  (void*&)LDR_PTR(vkCreateValidationCacheEXT) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkCreateValidationCacheEXT");
  return LDR_PTR(vkCreateValidationCacheEXT)(a_0, a_1, nullptr, a_3);
}
static void FEXFN_IMPL(vkDestroyValidationCacheEXT)(VkDevice a_0, VkValidationCacheEXT a_1, const VkAllocationCallbacks* a_2) {
  (void*&)LDR_PTR(vkDestroyValidationCacheEXT) = (void*)LDR_PTR(vkGetDeviceProcAddr)(a_0, "vkDestroyValidationCacheEXT");
  LDR_PTR(vkDestroyValidationCacheEXT)(a_0, a_1, nullptr);
}
#endif

#ifdef IS_32BIT_THUNK
VkResult fexfn_impl_libvulkan_vkEnumeratePhysicalDevices(VkInstance instance, uint32_t* count, guest_layout<VkPhysicalDevice*> devices) {
  if (!devices.get_pointer()) {
    return fexldr_ptr_libvulkan_vkEnumeratePhysicalDevices(instance, count, nullptr);
  }

  auto input_count = *count;
  std::vector<VkPhysicalDevice> out(input_count);
  auto ret = fexldr_ptr_libvulkan_vkEnumeratePhysicalDevices(instance, count, out.data());
  for (size_t i = 0; i < std::min(input_count, *count); ++i) {
    devices.get_pointer()[i] = to_guest(to_host_layout(out[i]));
  }
  return ret;
}

void fexfn_impl_libvulkan_vkGetDeviceQueue(VkDevice device, uint32_t family_index, uint32_t queue_index, guest_layout<VkQueue*> queue) {
  VkQueue out;
  (void*&)fexldr_ptr_libvulkan_vkGetDeviceQueue = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkGetDeviceQueue");
  fexldr_ptr_libvulkan_vkGetDeviceQueue(device, family_index, queue_index, &out);
  *queue.get_pointer() = to_guest(to_host_layout(out));
}

VkResult fexfn_impl_libvulkan_vkAllocateCommandBuffers(VkDevice device, const VkCommandBufferAllocateInfo* info,
                                                       guest_layout<VkCommandBuffer*> buffers) {
  std::vector<VkCommandBuffer> out(info->commandBufferCount);
  (void*&)fexldr_ptr_libvulkan_vkAllocateCommandBuffers = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkAllocateCommandBuffers");
  auto ret = fexldr_ptr_libvulkan_vkAllocateCommandBuffers(device, info, out.data());
  if (ret == VK_SUCCESS) {
    for (size_t i = 0; i < info->commandBufferCount; ++i) {
      buffers.get_pointer()[i] = to_guest(to_host_layout(out[i]));
    }
  }
  return ret;
}

// ---------------------------------------------------------------------------
// Placed memory maps for 32-bit guests (VK_EXT_map_memory_placed).
//
// vkMapMemory hands back whatever address the driver picked, and on this host
// that is a 0x3fff'xxxx'xxxx mapping which cannot be represented in a 32-bit
// guest pointer at all. The old implementation narrowed it, which the guard in
// host_to_guest_convertible correctly turned into
//   FEX FATAL: 32-bit truncation of host pointer ... returned to guest
// and an abort, right as DXVK mapped its descriptor heap. No amount of
// repacking fixes that: the address itself has to be one the guest can hold.
//
// VK_EXT_map_memory_placed exists for exactly this problem (wine's wow64
// winevulkan uses it): vkMapMemory2 takes a VkMemoryMapPlacedInfoEXT naming the
// address the mapping must land on. So reserve a range down in the guest's own
// 4 GiB - where guest VA and host VA coincide - and place the mapping there.
//
// The device has to have the extension enabled for that to work, and DXVK will
// never ask for it, so vkCreateDevice below injects it.
// ---------------------------------------------------------------------------

// A reservation is a PROT_NONE mapping in the low 4 GiB, claimed in the guest's
// allocator so a later guest mmap cannot land on top of it. Reservations are
// kept and recycled rather than returned to the OS: with memoryUnmapReserve the
// driver leaves the address space intact on unmap, which is precisely so a
// caller can reuse it.
struct PlacedReservation {
  uintptr_t Base;
  size_t Size;
};

static std::mutex PlacedPoolMutex;
static std::multimap<size_t, uintptr_t> PlacedFreeRanges;    // size -> base
static std::unordered_map<uintptr_t, size_t> PlacedRangeSize; // base -> size

// Scans downward the same way MakeLow32HostTrampoline does, for the same
// reason: MAP_FIXED_NOREPLACE only loses to mappings that already exist, and
// ReserveLow32HostRange is what stops the guest allocator handing the range out
// later.
static uintptr_t ReserveGuestVisibleRange(size_t Size) {
  constexpr uintptr_t ScanTop = 0x7000'0000;
  constexpr uintptr_t ScanBottom = 0x1000'0000;
  const size_t Step = std::max<size_t>(Size, 0x10'0000);

  for (uintptr_t Addr = ScanTop - Size; Addr >= ScanBottom; Addr -= Step) {
    void* P = ::mmap(reinterpret_cast<void*>(Addr), Size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
    if (P == MAP_FAILED) {
      continue;
    }
    if (FEX::HLE::ReserveLow32HostRange) {
      FEX::HLE::ReserveLow32HostRange(reinterpret_cast<uintptr_t>(P), Size);
    }
    return reinterpret_cast<uintptr_t>(P);
  }
  return 0;
}

static uintptr_t AcquirePlacedRange(size_t Size, size_t Alignment) {
  const size_t Rounded = (Size + Alignment - 1) & ~(Alignment - 1);
  std::lock_guard lk {PlacedPoolMutex};

  // Smallest recycled range that fits.
  auto It = PlacedFreeRanges.lower_bound(Rounded);
  if (It != PlacedFreeRanges.end()) {
    auto Base = It->second;
    PlacedFreeRanges.erase(It);
    return Base;
  }

  auto Base = ReserveGuestVisibleRange(Rounded);
  if (Base) {
    PlacedRangeSize[Base] = Rounded;
  }
  return Base;
}

static void ReleasePlacedRange(uintptr_t Base) {
  std::lock_guard lk {PlacedPoolMutex};
  auto It = PlacedRangeSize.find(Base);
  if (It == PlacedRangeSize.end()) {
    return;
  }
  PlacedFreeRanges.emplace(It->second, Base);
}

// Per-device placed-mapping state. Empty means the device does not have the
// extension and vkMapMemory has nothing it can do.
struct PlacedDeviceInfo {
  PFN_vkMapMemory2KHR MapMemory2 {};
  PFN_vkUnmapMemory2KHR UnmapMemory2 {};
  size_t Alignment {4096};
  bool UnmapReserve {};
};

static std::mutex PlacedDeviceMutex;
static std::unordered_map<VkDevice, PlacedDeviceInfo> PlacedDevices;
// Allocation sizes, needed because a VK_WHOLE_SIZE map still has to be given a
// reservation big enough for the whole allocation.
static std::unordered_map<VkDeviceMemory, VkDeviceSize> PlacedAllocationSizes;
// Live placed mappings, so unmap can hand the reservation back.
static std::unordered_map<VkDeviceMemory, uintptr_t> PlacedMappings;

static void RecordPlacedAllocationSize(VkDeviceMemory Memory, VkDeviceSize Size) {
  std::lock_guard lk {PlacedDeviceMutex};
  PlacedAllocationSizes[Memory] = Size;
}

static void ForgetPlacedAllocation(VkDeviceMemory Memory) {
  std::lock_guard lk {PlacedDeviceMutex};
  PlacedAllocationSizes.erase(Memory);
  PlacedMappings.erase(Memory);
}

// Resolve the map/unmap entry points and the placement alignment once, at
// device creation, so vkMapMemory is a table lookup.
static void EnablePlacedMapsForDevice(VkPhysicalDevice PhysicalDevice, VkDevice Device) {
  PlacedDeviceInfo Info {};
  Info.MapMemory2 = (PFN_vkMapMemory2KHR)LDR_PTR(vkGetDeviceProcAddr)(Device, "vkMapMemory2KHR");
  Info.UnmapMemory2 = (PFN_vkUnmapMemory2KHR)LDR_PTR(vkGetDeviceProcAddr)(Device, "vkUnmapMemory2KHR");
  if (!Info.MapMemory2) {
    Info.MapMemory2 = (PFN_vkMapMemory2KHR)LDR_PTR(vkGetDeviceProcAddr)(Device, "vkMapMemory2");
    Info.UnmapMemory2 = (PFN_vkUnmapMemory2KHR)LDR_PTR(vkGetDeviceProcAddr)(Device, "vkUnmapMemory2");
  }
  if (!Info.MapMemory2 || !Info.UnmapMemory2) {
    fprintf(stderr, "ERROR: VK_EXT_map_memory_placed enabled but vkMapMemory2 is missing\n");
    fflush(stderr);
    return;
  }

  VkPhysicalDeviceMapMemoryPlacedPropertiesEXT PlacedProps {
    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAP_MEMORY_PLACED_PROPERTIES_EXT,
  };
  VkPhysicalDeviceProperties2 Props2 {
    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
    .pNext = &PlacedProps,
  };
  LDR_PTR(vkGetPhysicalDeviceProperties2)(PhysicalDevice, &Props2);
  // The placed address has to satisfy the driver's alignment, and the
  // reservation is an mmap, so never go below a page either.
  Info.Alignment = std::max<size_t>(PlacedProps.minPlacedMemoryMapAlignment, 4096);

  VkPhysicalDeviceMapMemoryPlacedFeaturesEXT PlacedFeatures {
    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAP_MEMORY_PLACED_FEATURES_EXT,
  };
  VkPhysicalDeviceFeatures2 Features2 {
    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
    .pNext = &PlacedFeatures,
  };
  LDR_PTR(vkGetPhysicalDeviceFeatures2)(PhysicalDevice, &Features2);
  Info.UnmapReserve = PlacedFeatures.memoryUnmapReserve == VK_TRUE;

  {
    std::lock_guard lk {PlacedDeviceMutex};
    PlacedDevices[Device] = Info;
  }
  fprintf(stderr, "Placed Vulkan memory maps enabled (alignment %zu, unmapReserve %d)\n", Info.Alignment, (int)Info.UnmapReserve);
  fflush(stderr);
}

static bool DeviceSupportsPlacedMaps(VkPhysicalDevice PhysicalDevice) {
  uint32_t Count = 0;
  if (LDR_PTR(vkEnumerateDeviceExtensionProperties)(PhysicalDevice, nullptr, &Count, nullptr) != VK_SUCCESS || !Count) {
    return false;
  }
  std::vector<VkExtensionProperties> Props(Count);
  if (LDR_PTR(vkEnumerateDeviceExtensionProperties)(PhysicalDevice, nullptr, &Count, Props.data()) != VK_SUCCESS) {
    return false;
  }
  bool HasPlaced = false;
  bool HasMapMemory2 = false;
  for (auto& P : Props) {
    std::string_view Name {P.extensionName};
    HasPlaced |= Name == VK_EXT_MAP_MEMORY_PLACED_EXTENSION_NAME;
    HasMapMemory2 |= Name == VK_KHR_MAP_MEMORY_2_EXTENSION_NAME;
  }
  return HasPlaced && HasMapMemory2;
}

VkResult fexfn_impl_libvulkan_vkMapMemory(VkDevice device, VkDeviceMemory memory, VkDeviceSize offset, VkDeviceSize size,
                                          VkMemoryMapFlags flags, guest_layout<void**> data) {
  PlacedDeviceInfo Placed;
  {
    std::lock_guard lk {PlacedDeviceMutex};
    auto It = PlacedDevices.find(device);
    if (It != PlacedDevices.end()) {
      Placed = It->second;
    }
  }

  if (!Placed.MapMemory2) {
    // No placed mapping on this device. Refusing is the only honest answer: the
    // driver would hand back an address the guest cannot hold, and narrowing it
    // silently corrupts. VK_ERROR_MEMORY_MAP_FAILED is a documented result that
    // callers already handle.
    static std::once_flag Warned;
    std::call_once(Warned, [] {
      fprintf(stderr, "ERROR: vkMapMemory on a device without VK_EXT_map_memory_placed; a 32-bit guest cannot hold the "
                      "host mapping address. Failing the map.\n");
      fflush(stderr);
    });
    return VK_ERROR_MEMORY_MAP_FAILED;
  }

  // A VK_WHOLE_SIZE map still needs a reservation covering the whole
  // allocation, so use the size recorded at vkAllocateMemory time.
  VkDeviceSize MapSize = size;
  if (MapSize == VK_WHOLE_SIZE) {
    std::lock_guard lk {PlacedDeviceMutex};
    auto It = PlacedAllocationSizes.find(memory);
    MapSize = It != PlacedAllocationSizes.end() ? It->second - offset : 0;
  }
  if (!MapSize) {
    return VK_ERROR_MEMORY_MAP_FAILED;
  }

  auto Base = AcquirePlacedRange(MapSize, Placed.Alignment);
  if (!Base) {
    fprintf(stderr, "ERROR: no free guest-visible address space for a %zu byte Vulkan mapping\n", (size_t)MapSize);
    fflush(stderr);
    return VK_ERROR_MEMORY_MAP_FAILED;
  }

  VkMemoryMapPlacedInfoEXT PlacedInfo {
    .sType = VK_STRUCTURE_TYPE_MEMORY_MAP_PLACED_INFO_EXT,
    .pNext = nullptr,
    .pPlacedAddress = reinterpret_cast<void*>(Base),
  };
  VkMemoryMapInfo MapInfo {
    .sType = VK_STRUCTURE_TYPE_MEMORY_MAP_INFO,
    .pNext = &PlacedInfo,
    .flags = flags | VK_MEMORY_MAP_PLACED_BIT_EXT,
    .memory = memory,
    .offset = offset,
    .size = size,
  };

  void* mapped {};
  auto ret = Placed.MapMemory2(device, &MapInfo, &mapped);
  if (ret != VK_SUCCESS) {
    ReleasePlacedRange(Base);
    return ret;
  }

  {
    std::lock_guard lk {PlacedDeviceMutex};
    PlacedMappings[memory] = Base;
  }

  host_layout<void*> host_data {};
  host_data.data = mapped;
  *data.get_pointer() = to_guest(host_data);
  return ret;
}

void fexfn_impl_libvulkan_vkUnmapMemory(VkDevice device, VkDeviceMemory memory) {
  PlacedDeviceInfo Placed;
  uintptr_t Base = 0;
  {
    std::lock_guard lk {PlacedDeviceMutex};
    auto It = PlacedDevices.find(device);
    if (It != PlacedDevices.end()) {
      Placed = It->second;
    }
    auto MapIt = PlacedMappings.find(memory);
    if (MapIt != PlacedMappings.end()) {
      Base = MapIt->second;
      PlacedMappings.erase(MapIt);
    }
  }

  if (!Base || !Placed.UnmapMemory2) {
    (void*&)LDR_PTR(vkUnmapMemory) = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkUnmapMemory");
    LDR_PTR(vkUnmapMemory)(device, memory);
    return;
  }

  // With memoryUnmapReserve the driver leaves the address space mapped
  // PROT_NONE instead of releasing it, which is what lets the range go back on
  // the free list. Without the feature the VA is gone, so put an equivalent
  // reservation back ourselves before recycling it.
  VkMemoryUnmapInfo UnmapInfo {
    .sType = VK_STRUCTURE_TYPE_MEMORY_UNMAP_INFO,
    .pNext = nullptr,
    .flags = Placed.UnmapReserve ? (VkMemoryUnmapFlags)VK_MEMORY_UNMAP_RESERVE_BIT_EXT : (VkMemoryUnmapFlags)0,
    .memory = memory,
  };
  Placed.UnmapMemory2(device, &UnmapInfo);

  if (!Placed.UnmapReserve) {
    size_t Size = 0;
    {
      std::lock_guard lk {PlacedPoolMutex};
      auto It = PlacedRangeSize.find(Base);
      Size = It != PlacedRangeSize.end() ? It->second : 0;
    }
    if (Size) {
      ::mmap(reinterpret_cast<void*>(Base), Size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1, 0);
    }
  }
  ReleasePlacedRange(Base);
}

// Allocates storage on the heap that must be de-allocated using delete[] or DeleteRepackedStructArray
template<bool NeedsRepack = true, typename T>
std::span<std::remove_cv_t<T>> RepackStructArray(uint32_t Count, const guest_layout<T*> GuestData) {
  if (!GuestData.get_pointer() || Count == 0) {
    return {};
  }

  auto HostData = new std::remove_cv_t<T>[Count];
  for (size_t i = 0; i < Count; ++i) {
    auto& GuestElement = (const guest_layout<std::remove_cv_t<T>>&)GuestData.get_pointer()[i];
    auto Element = host_layout<std::remove_cv_t<T>> {GuestElement};
    if constexpr (NeedsRepack) {
      fex_apply_custom_repacking_entry(Element, GuestElement);
    }
    HostData[i] = Element.data;
  }
  return {HostData, Count};
}

template<typename T>
void DeleteRepackedStructArray(uint32_t Count, T* HostData, guest_layout<T*>& GuestData) {
  for (uint32_t i = 0; i < Count; ++i) {
    fex_apply_custom_repacking_exit(GuestData.get_pointer()[i], to_host_layout(HostData[i]));
  }
  delete[] HostData;
}

void fexfn_impl_libvulkan_vkCmdSetVertexInputEXT(
  VkCommandBuffer Buffer, uint32_t BindingDescCount, guest_layout<const VkVertexInputBindingDescription2EXT*> GuestBindingDescs,
  uint32_t AttributeDescCount, guest_layout<const VkVertexInputAttributeDescription2EXT*> GuestAttributeDescs) {

  assert(GuestBindingDescs.get_pointer() && BindingDescCount > 0);
  assert(GuestAttributeDescs.get_pointer() && AttributeDescCount > 0);

  auto BindingDescs = RepackStructArray(BindingDescCount, GuestBindingDescs);
  auto AttributeDescs = RepackStructArray(AttributeDescCount, GuestAttributeDescs);

  fexldr_ptr_libvulkan_vkCmdSetVertexInputEXT(Buffer, BindingDescCount, BindingDescs.data(), AttributeDescCount, AttributeDescs.data());

  delete[] AttributeDescs.data();
  delete[] BindingDescs.data();
}

void fexfn_impl_libvulkan_vkUpdateDescriptorSets(VkDevice device, unsigned int descriptorWriteCount,
                                                 guest_layout<const VkWriteDescriptorSet*> pDescriptorWrites, unsigned int descriptorCopyCount,
                                                 guest_layout<const VkCopyDescriptorSet*> pDescriptorCopies) {

  auto HostDescriptorWrites = RepackStructArray(descriptorWriteCount, pDescriptorWrites);
  auto HostDescriptorCopies = RepackStructArray(descriptorCopyCount, pDescriptorCopies);

  (void*&)fexldr_ptr_libvulkan_vkUpdateDescriptorSets = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkUpdateDescriptorSets");
  fexldr_ptr_libvulkan_vkUpdateDescriptorSets(device, descriptorWriteCount, HostDescriptorWrites.data(), descriptorCopyCount,
                                              HostDescriptorCopies.data());

  delete[] HostDescriptorCopies.data();
  delete[] HostDescriptorWrites.data();
}

VkResult fexfn_impl_libvulkan_vkQueueSubmit(VkQueue queue, uint32_t submit_count, guest_layout<const VkSubmitInfo*> submit_infos, VkFence fence) {

  auto HostSubmitInfos = RepackStructArray(submit_count, submit_infos);
  auto ret = fexldr_ptr_libvulkan_vkQueueSubmit(queue, submit_count, HostSubmitInfos.data(), fence);
  delete[] HostSubmitInfos.data();
  return ret;
}

void fexfn_impl_libvulkan_vkFreeCommandBuffers(VkDevice device, VkCommandPool pool, uint32_t num_buffers,
                                               guest_layout<const VkCommandBuffer*> buffers) {

  auto HostBuffers = RepackStructArray<false>(num_buffers, buffers);
  (void*&)fexldr_ptr_libvulkan_vkFreeCommandBuffers = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkFreeCommandBuffers");
  fexldr_ptr_libvulkan_vkFreeCommandBuffers(device, pool, num_buffers, HostBuffers.data());
  delete[] HostBuffers.data();
}

VkResult fexfn_impl_libvulkan_vkGetPipelineCacheData(VkDevice device, VkPipelineCache cache, guest_layout<uint32_t*> guest_data_size, void* data) {
  size_t data_size = guest_data_size.get_pointer()->data;
  (void*&)fexldr_ptr_libvulkan_vkGetPipelineCacheData = (void*)LDR_PTR(vkGetDeviceProcAddr)(device, "vkGetPipelineCacheData");
  auto ret = fexldr_ptr_libvulkan_vkGetPipelineCacheData(device, cache, &data_size, data);
  *guest_data_size.get_pointer() = data_size;
  return ret;
}

#endif

// Single-source list of custom_host_impl functions whose ONLY safe caller is
// their fexfn_impl_* wrapper because the wrapper DEFUSES a guest function
// pointer the application always supplies (a debug-callback pointer inside the
// create-info struct).  A name resolved via vkGetInstanceProcAddr /
// vkGetDeviceProcAddr never reaches its fexfn_impl_* wrapper unless it is
// returned from LookupCustomVulkanFunction below: MakeGuestCallable (Guest.cpp)
// links the returned host address to a signature-generic invoker
// (GetCallerForHostFunction -> CallHostFunction<fexthunks_invoke_callback<Sig>>),
// which lands on the host at GuestWrapperForHostFunction<Sig>::Call and branches
// straight to whatever host address procaddr returned.  If that address is the
// raw driver entry (the default LDR_PTR return), the guest's pfn*Callback is
// passed through verbatim; native libvulkan then invokes a guest VA as host
// code and SEGVs the first time a debug message fires.  These two entry points
// are extension functions resolved exclusively via vkGetInstanceProcAddr, so
// the bypass is the common path, not the exception.  Same hazard class the
// vkCreateInstance impl already handles for the pNext-embedded callback.
//
// INVARIANT: every custom_host_impl that defuses or repacks a guest pointer the
// generic GuestWrapperForHostFunction path would pass verbatim MUST be listed
// here (or in the explicit branches below) or it is unreachable via GIPA/GDPA.
// This cannot be asserted at compile time from this translation unit (the set
// of custom_host_impl configs lives in libvulkan_interface.cpp / thunkgen and
// is not visible here), so it is enforced by review against that file.
#define FEX_VULKAN_CALLBACK_DEFUSING_IMPLS(X) \
  X(vkCreateDebugReportCallbackEXT)           \
  X(vkCreateDebugUtilsMessengerEXT)

// Second, larger member of the same hazard class as the callback-defusing list
// above: custom_host_impl functions whose fexfn_impl_* wrapper exists SOLELY to
// force pAllocator = nullptr before forwarding to native libvulkan.
//
// VkAllocationCallbacks is an opaque_type embedding five GUEST function pointers
// (pfnAllocation, pfnReallocation, pfnFree, pfnInternalAllocation,
// pfnInternalFree).  If the guest supplies a custom allocator and the struct is
// passed through verbatim, the native driver interprets those guest VAs as host
// code and SEGVs the instant it allocates.  The wrappers below defuse that by
// substituting nullptr (native default allocator).
//
// As with the callback-defusing list, a name resolved via
// vkGetInstanceProcAddr / vkGetDeviceProcAddr NEVER reaches its fexfn_impl_*
// wrapper unless LookupCustomVulkanFunction returns it (MakeGuestCallable links
// the returned host address to the signature-generic
// GuestWrapperForHostFunction<Sig>::Call, which branches straight to whatever
// host address procaddr returned -- the raw driver entry by default).  Since
// volk / layers / most engines resolve every entry point via GIPA/GDPA, that
// bypass is the COMMON path.  The bug is latent only because most applications
// pass pAllocator = nullptr, making both paths agree; any app with a custom
// allocator crashes.  Routing every wrapper through this table closes that.
//
// INVARIANT: every allocator-nulling custom_host_impl MUST appear here or it is
// unreachable via GIPA/GDPA.  This is the single source of truth for the family
// -- the plain-name branches in LookupCustomVulkanFunction below intentionally
// no longer duplicate any allocator-nulling entry.
//
// A generator-side auto-population was evaluated and rejected for the same
// reason documented in libGL_Host.cpp (FEX_LIBGL_RELOCATING_IMPLS): the thunk
// generator sees only the syntactic `custom_host_impl` flag, not the semantic
// reason a wrapper exists, so it cannot distinguish an allocator-nulling /
// pointer-defusing wrapper (which MUST be procaddr-routed) from a pure
// array-repacking wrapper or a custom_guest_entrypoint resolver such as
// vkGetInstanceProcAddr itself (which must NOT be).  The impl-body
// `#ifndef IS_32BIT_THUNK` guards further live in this .cpp, invisible to the
// generator's interface-only parse.  This X-macro coupling gives the same
// "cannot add the impl without registering it" guarantee locally.
//
// NOTE: the debug-callback creators are deliberately absent here -- they null
// pAllocator too, but are already covered by FEX_VULKAN_CALLBACK_DEFUSING_IMPLS
// above; listing them twice would be redundant (first match wins regardless).

// Wrappers defined unconditionally (both 32-bit and 64-bit thunk builds).
#define FEX_VULKAN_ALLOCATOR_NULLING_IMPLS(X) \
  X(vkCreateShaderModule)                     \
  X(vkCreateInstance)                         \
  X(vkCreateDevice)                           \
  X(vkAllocateMemory)                         \
  X(vkFreeMemory)                             \
  X(vkCreateBuffer)                           \
  X(vkDestroyBuffer)                          \
  X(vkCreateBufferView)                       \
  X(vkDestroyBufferView)                      \
  X(vkCreateImage)                            \
  X(vkDestroyImage)                           \
  X(vkCreateImageView)                        \
  X(vkDestroyImageView)                       \
  X(vkCreatePipelineCache)                    \
  X(vkDestroyPipelineCache)                   \
  X(vkCreateGraphicsPipelines)                \
  X(vkDestroyPipeline)                        \
  X(vkCreatePipelineLayout)                   \
  X(vkDestroyPipelineLayout)                  \
  X(vkCreateSampler)                          \
  X(vkDestroySampler)                         \
  X(vkCreateDescriptorSetLayout)              \
  X(vkDestroyDescriptorSetLayout)             \
  X(vkCreateDescriptorPool)                   \
  X(vkDestroyDescriptorPool)                  \
  X(vkCreateSemaphore)                        \
  X(vkDestroySemaphore)                       \
  X(vkCreateFence)                            \
  X(vkDestroyFence)                           \
  X(vkCreateFramebuffer)                      \
  X(vkDestroyFramebuffer)                     \
  X(vkCreateRenderPass)                       \
  X(vkDestroyRenderPass)                      \
  X(vkCreateRenderPass2)                      \
  X(vkCreateRenderPass2KHR)                   \
  X(vkCreateCommandPool)                      \
  X(vkDestroyCommandPool)                     \
  X(vkCreateSwapchainKHR)                     \
  X(vkDestroySwapchainKHR)                    \
  X(vkDestroyInstance)                        \
  X(vkDestroyDevice)                          \
  X(vkDestroyShaderModule)                    \
  X(vkDestroySurfaceKHR)                      \
  X(vkCreateDescriptorUpdateTemplate)         \
  X(vkDestroyDescriptorUpdateTemplate)        \
  X(vkCreateDescriptorUpdateTemplateKHR)      \
  X(vkDestroyDescriptorUpdateTemplateKHR)     \
  X(vkDestroyDebugReportCallbackEXT)          \
  X(vkDestroyDebugUtilsMessengerEXT)

// Wrappers whose fexfn_impl_* definitions are compiled only in the 64-bit thunk
// (their impl bodies sit inside `#ifndef IS_32BIT_THUNK` blocks in this file).
// Referencing them from a 32-bit build would be an undefined-symbol error, so
// they are expanded only under the same guard below.
#define FEX_VULKAN_ALLOCATOR_NULLING_IMPLS_64BIT(X) \
  X(vkCreateComputePipelines)                       \
  X(vkCreateEvent)                                  \
  X(vkDestroyEvent)                                 \
  X(vkCreateQueryPool)                              \
  X(vkDestroyQueryPool)                             \
  X(vkCreateDisplayPlaneSurfaceKHR)                 \
  X(vkCreateDisplayModeKHR)                         \
  X(vkCreateHeadlessSurfaceEXT)                     \
  X(vkCreatePrivateDataSlot)                        \
  X(vkDestroyPrivateDataSlot)                       \
  X(vkCreatePrivateDataSlotEXT)                     \
  X(vkDestroyPrivateDataSlotEXT)                    \
  X(vkCreateSamplerYcbcrConversion)                 \
  X(vkDestroySamplerYcbcrConversion)                \
  X(vkCreateSamplerYcbcrConversionKHR)              \
  X(vkDestroySamplerYcbcrConversionKHR)             \
  X(vkCreateValidationCacheEXT)                     \
  X(vkDestroyValidationCacheEXT)

// WSI surface creators.  Same procaddr-routing requirement as the
// allocator-nulling family: their custom_host_impl wrappers (which force
// pAllocator = nullptr while translating the embedded Display*/xcb_connection_t*
// via x11_manager) are only reached on the packed-thunk path.  A name resolved
// through vkGetInstanceProcAddr / vkGetDeviceProcAddr -- the path volk / layers /
// most engines actually take -- branches straight to the raw driver entry unless
// this table returns the wrapper, re-opening the exact pAllocator hole the
// wrapper closes.  Defined unconditionally (the impl bodies are not bitness-
// guarded), so this expands outside the IS_32BIT_THUNK guard below.
#define FEX_VULKAN_WSI_SURFACE_IMPLS(X) \
  X(vkCreateXlibSurfaceKHR)             \
  X(vkCreateXcbSurfaceKHR)              \
  X(vkCreateWaylandSurfaceKHR)

static PFN_vkVoidFunction LookupCustomVulkanFunction(const char* a_1) {
  using namespace std::string_view_literals;

#define FEX_VULKAN_PROCADDR_CASE(name)                      \
  if (a_1 == std::string_view {#name}) {                    \
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_##name; \
  }
  FEX_VULKAN_CALLBACK_DEFUSING_IMPLS(FEX_VULKAN_PROCADDR_CASE)
  FEX_VULKAN_ALLOCATOR_NULLING_IMPLS(FEX_VULKAN_PROCADDR_CASE)
  FEX_VULKAN_WSI_SURFACE_IMPLS(FEX_VULKAN_PROCADDR_CASE)
#ifndef IS_32BIT_THUNK
  FEX_VULKAN_ALLOCATOR_NULLING_IMPLS_64BIT(FEX_VULKAN_PROCADDR_CASE)
#endif
#undef FEX_VULKAN_PROCADDR_CASE

  if (a_1 == "vkAcquireXlibDisplayEXT"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkAcquireXlibDisplayEXT;
  } else if (a_1 == "vkGetRandROutputDisplayEXT"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkGetRandROutputDisplayEXT;
  } else if (a_1 == "vkGetPhysicalDeviceXcbPresentationSupportKHR"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkGetPhysicalDeviceXcbPresentationSupportKHR;
  } else if (a_1 == "vkGetPhysicalDeviceXlibPresentationSupportKHR"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkGetPhysicalDeviceXlibPresentationSupportKHR;
#ifdef IS_32BIT_THUNK
  } else if (a_1 == "vkAllocateCommandBuffers"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkAllocateCommandBuffers;
  } else if (a_1 == "vkEnumeratePhysicalDevices"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkEnumeratePhysicalDevices;
  } else if (a_1 == "vkFreeCommandBuffers"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkFreeCommandBuffers;
  } else if (a_1 == "vkGetDeviceQueue"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkGetDeviceQueue;
  } else if (a_1 == "vkGetPipelineCacheData"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkGetPipelineCacheData;
  } else if (a_1 == "vkMapMemory"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkMapMemory;
  } else if (a_1 == "vkQueueSubmit"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkQueueSubmit;
  } else if (a_1 == "vkCmdSetVertexInputEXT"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkCmdSetVertexInputEXT;
  } else if (a_1 == "vkUpdateDescriptorSets"sv) {
    return (PFN_vkVoidFunction)fexfn_impl_libvulkan_vkUpdateDescriptorSets;
#endif
  }
  return nullptr;
}

static PFN_vkVoidFunction FEXFN_IMPL(vkGetDeviceProcAddr)(VkDevice a_0, const char* a_1) {
  // Just return the host facing function pointer
  // The guest will handle mapping if this exists

  // Check for functions with custom implementations first
  if (auto ptr = LookupCustomVulkanFunction(a_1)) {
    return ptr;
  }

  return LDR_PTR(vkGetDeviceProcAddr)(a_0, a_1);
}

static PFN_vkVoidFunction FEXFN_IMPL(vkGetInstanceProcAddr)(VkInstance a_0, const char* a_1) {
  // Just return the host facing function pointer
  // The guest will handle mapping if it exists

  if (!SetupInstance && a_0) {
    DoSetupWithInstance(a_0);
  }

  // Check for functions with custom implementations first
  if (auto ptr = LookupCustomVulkanFunction(a_1)) {
    // If this function belongs to an instance extension, requery its address.
    // This ensures fexldr_ptr_* is valid if the application creates a minimal
    // VkInstance with no extensions before creating its actual instance.
    using namespace std::string_view_literals;
    if (a_1 == "vkGetRandROutputDisplayEXT"sv && !LDR_PTR(vkGetRandROutputDisplayEXT)) {
      (void*&)LDR_PTR(vkGetRandROutputDisplayEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkGetRandROutputDisplayEXT");
    }
    if (a_1 == "vkAcquireXlibDisplayEXT"sv && !LDR_PTR(vkAcquireXlibDisplayEXT)) {
      (void*&)LDR_PTR(vkAcquireXlibDisplayEXT) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, "vkAcquireXlibDisplayEXT");
    }
    const char* XcbPresent = "vkGetPhysicalDeviceXcbPresentationSupportKHR";
    if (a_1 == std::string_view {XcbPresent} && !LDR_PTR(vkGetPhysicalDeviceXcbPresentationSupportKHR)) {
      (void*&)LDR_PTR(vkGetPhysicalDeviceXcbPresentationSupportKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, XcbPresent);
    }
    const char* XlibPresent = "vkGetPhysicalDeviceXlibPresentationSupportKHR";
    if (a_1 == std::string_view {XlibPresent} && !LDR_PTR(vkGetPhysicalDeviceXlibPresentationSupportKHR)) {
      (void*&)LDR_PTR(vkGetPhysicalDeviceXlibPresentationSupportKHR) = (void*)LDR_PTR(vkGetInstanceProcAddr)(a_0, XlibPresent);
    }

    return ptr;
  }

  return LDR_PTR(vkGetInstanceProcAddr)(a_0, a_1);
}

#ifdef IS_32BIT_THUNK
template<VkStructureType TypeIndex, typename Type>
static VkBaseOutStructure* convert(const guest_layout<VkBaseOutStructure>* source) {
  // Using malloc here since no easily available type information is available at the time of destruction.
  auto typed_source = reinterpret_cast<const guest_layout<Type>*>(source);
  auto child_mem = (char*)aligned_alloc(alignof(host_layout<Type>), sizeof(host_layout<Type>));
  auto child = new (child_mem) host_layout<Type> {*typed_source};

  fex_custom_repack_entry(*child, *typed_source);

  return reinterpret_cast<VkBaseOutStructure*>(&child->data);
}

template<VkStructureType TypeIndex, typename Type>
static void convert_to_guest(void* into, const VkBaseOutStructure* from) {
  auto typed_into = reinterpret_cast<guest_layout<Type>*>(into);
  auto oldNext = typed_into->data.pNext; // TODO: This assumes Vulkan never modifies pNext internally
  *typed_into = to_guest(to_host_layout(*(Type*)from));
  typed_into->data.pNext = oldNext;

  fex_custom_repack_exit(*typed_into, to_host_layout(*(Type*)from));
}

template<VkStructureType TypeIndex, typename Type>
inline constexpr std::pair<VkStructureType, std::pair<VkBaseOutStructure* (*)(const guest_layout<VkBaseOutStructure>*), void (*)(void*, const VkBaseOutStructure*)>>
  converters = {TypeIndex, {convert<TypeIndex, Type>, convert_to_guest<TypeIndex, Type>}};

// NOTE: Not all Vulkan structures with pNext members are listed here. This is because excluding structs exclusively used as top-level entries is useful to detect repacking bugs.
static std::unordered_map<VkStructureType, std::pair<VkBaseOutStructure* (*)(const guest_layout<VkBaseOutStructure>*), void (*)(void*, const VkBaseOutStructure*)>> next_handlers {
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_MOTION_INFO_NV, VkAccelerationStructureMotionInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_AMIGO_PROFILING_SUBMIT_INFO_SEC, VkAmigoProfilingSubmitInfoSEC>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_DESCRIPTION_STENCIL_LAYOUT, VkAttachmentDescriptionStencilLayout>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_REFERENCE_STENCIL_LAYOUT, VkAttachmentReferenceStencilLayout>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_SAMPLE_COUNT_INFO_AMD, VkAttachmentSampleCountInfoAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_BUFFER_MEMORY_DEVICE_GROUP_INFO, VkBindBufferMemoryDeviceGroupInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_IMAGE_MEMORY_DEVICE_GROUP_INFO, VkBindImageMemoryDeviceGroupInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_IMAGE_MEMORY_SWAPCHAIN_INFO_KHR, VkBindImageMemorySwapchainInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_IMAGE_PLANE_MEMORY_INFO, VkBindImagePlaneMemoryInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_CREATE_INFO_EXT, VkBufferDeviceAddressCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_OPAQUE_CAPTURE_ADDRESS_CREATE_INFO, VkBufferOpaqueCaptureAddressCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_CONDITIONAL_RENDERING_INFO_EXT, VkCommandBufferInheritanceConditionalRenderingInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_RENDERING_INFO, VkCommandBufferInheritanceRenderingInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_RENDER_PASS_TRANSFORM_INFO_QCOM, VkCommandBufferInheritanceRenderPassTransformInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_VIEWPORT_SCISSOR_INFO_NV, VkCommandBufferInheritanceViewportScissorInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_COMMAND_TRANSFORM_INFO_QCOM, VkCopyCommandTransformInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_REPORT_CALLBACK_CREATE_INFO_EXT, VkDebugReportCallbackCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_UTILS_MESSENGER_CREATE_INFO_EXT, VkDebugUtilsMessengerCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_UTILS_OBJECT_NAME_INFO_EXT, VkDebugUtilsObjectNameInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEDICATED_ALLOCATION_BUFFER_CREATE_INFO_NV, VkDedicatedAllocationBufferCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEDICATED_ALLOCATION_IMAGE_CREATE_INFO_NV, VkDedicatedAllocationImageCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEDICATED_ALLOCATION_MEMORY_ALLOCATE_INFO_NV, VkDedicatedAllocationMemoryAllocateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEPTH_BIAS_REPRESENTATION_INFO_EXT, VkDepthBiasRepresentationInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_BUFFER_BINDING_PUSH_DESCRIPTOR_BUFFER_HANDLE_EXT, VkDescriptorBufferBindingPushDescriptorBufferHandleEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_INLINE_UNIFORM_BLOCK_CREATE_INFO, VkDescriptorPoolInlineUniformBlockCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_BINDING_FLAGS_CREATE_INFO, VkDescriptorSetLayoutBindingFlagsCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_ALLOCATE_INFO, VkDescriptorSetVariableDescriptorCountAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_VARIABLE_DESCRIPTOR_COUNT_LAYOUT_SUPPORT, VkDescriptorSetVariableDescriptorCountLayoutSupport>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_ADDRESS_BINDING_CALLBACK_DATA_EXT, VkDeviceAddressBindingCallbackDataEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_DIAGNOSTICS_CONFIG_CREATE_INFO_NV, VkDeviceDiagnosticsConfigCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_COMMAND_BUFFER_BEGIN_INFO, VkDeviceGroupCommandBufferBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_PRESENT_INFO_KHR, VkDeviceGroupPresentInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_RENDER_PASS_BEGIN_INFO, VkDeviceGroupRenderPassBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_SUBMIT_INFO, VkDeviceGroupSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_SWAPCHAIN_CREATE_INFO_KHR, VkDeviceGroupSwapchainCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_MEMORY_OVERALLOCATION_CREATE_INFO_AMD, VkDeviceMemoryOverallocationCreateInfoAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_PRIVATE_DATA_CREATE_INFO, VkDevicePrivateDataCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_NATIVE_HDR_SURFACE_CAPABILITIES_AMD, VkDisplayNativeHdrSurfaceCapabilitiesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_PRESENT_INFO_KHR, VkDisplayPresentInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXPORT_FENCE_CREATE_INFO, VkExportFenceCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO, VkExportMemoryAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO_NV, VkExportMemoryAllocateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXPORT_SEMAPHORE_CREATE_INFO, VkExportSemaphoreCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_IMAGE_FORMAT_PROPERTIES, VkExternalImageFormatProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_ACQUIRE_UNMODIFIED_EXT, VkExternalMemoryAcquireUnmodifiedEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO, VkExternalMemoryBufferCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO, VkExternalMemoryImageCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO_NV, VkExternalMemoryImageCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FILTER_CUBIC_IMAGE_VIEW_IMAGE_FORMAT_PROPERTIES_EXT, VkFilterCubicImageViewImageFormatPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_3, VkFormatProperties3>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_LIBRARY_CREATE_INFO_EXT, VkGraphicsPipelineLibraryCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_COMPRESSION_CONTROL_EXT, VkImageCompressionControlEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_COMPRESSION_PROPERTIES_EXT, VkImageCompressionPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_LIST_CREATE_INFO_EXT, VkImageDrmFormatModifierListCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_FORMAT_LIST_CREATE_INFO, VkImageFormatListCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_PLANE_MEMORY_REQUIREMENTS_INFO, VkImagePlaneMemoryRequirementsInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_STENCIL_USAGE_CREATE_INFO, VkImageStencilUsageCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_SWAPCHAIN_CREATE_INFO_KHR, VkImageSwapchainCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_ASTC_DECODE_MODE_EXT, VkImageViewASTCDecodeModeEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_MIN_LOD_CREATE_INFO_EXT, VkImageViewMinLodCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_SAMPLE_WEIGHT_CREATE_INFO_QCOM, VkImageViewSampleWeightCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_SLICED_CREATE_INFO_EXT, VkImageViewSlicedCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_USAGE_CREATE_INFO, VkImageViewUsageCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR, VkImportMemoryFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_FLAGS_INFO, VkMemoryAllocateFlagsInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_BARRIER_2, VkMemoryBarrier2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO, VkMemoryDedicatedAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_DEDICATED_REQUIREMENTS, VkMemoryDedicatedRequirements>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_OPAQUE_CAPTURE_ADDRESS_ALLOCATE_INFO, VkMemoryOpaqueCaptureAddressAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_PRIORITY_ALLOCATE_INFO_EXT, VkMemoryPriorityAllocateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MULTISAMPLED_RENDER_TO_SINGLE_SAMPLED_INFO_EXT, VkMultisampledRenderToSingleSampledInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MULTIVIEW_PER_VIEW_ATTRIBUTES_INFO_NVX, VkMultiviewPerViewAttributesInfoNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MULTIVIEW_PER_VIEW_RENDER_AREAS_RENDER_PASS_BEGIN_INFO_QCOM, VkMultiviewPerViewRenderAreasRenderPassBeginInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_OPTICAL_FLOW_IMAGE_FORMAT_INFO_NV, VkOpticalFlowImageFormatInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_QUERY_SUBMIT_INFO_KHR, VkPerformanceQuerySubmitInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_16BIT_STORAGE_FEATURES, VkPhysicalDevice16BitStorageFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_4444_FORMATS_FEATURES_EXT, VkPhysicalDevice4444FormatsFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_8BIT_STORAGE_FEATURES, VkPhysicalDevice8BitStorageFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_FEATURES_KHR, VkPhysicalDeviceAccelerationStructureFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ACCELERATION_STRUCTURE_PROPERTIES_KHR, VkPhysicalDeviceAccelerationStructurePropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ADDRESS_BINDING_REPORT_FEATURES_EXT, VkPhysicalDeviceAddressBindingReportFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_AMIGO_PROFILING_FEATURES_SEC, VkPhysicalDeviceAmigoProfilingFeaturesSEC>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ASTC_DECODE_FEATURES_EXT, VkPhysicalDeviceASTCDecodeFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ATTACHMENT_FEEDBACK_LOOP_DYNAMIC_STATE_FEATURES_EXT, VkPhysicalDeviceAttachmentFeedbackLoopDynamicStateFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ATTACHMENT_FEEDBACK_LOOP_LAYOUT_FEATURES_EXT, VkPhysicalDeviceAttachmentFeedbackLoopLayoutFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BLEND_OPERATION_ADVANCED_FEATURES_EXT, VkPhysicalDeviceBlendOperationAdvancedFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BLEND_OPERATION_ADVANCED_PROPERTIES_EXT, VkPhysicalDeviceBlendOperationAdvancedPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BORDER_COLOR_SWIZZLE_FEATURES_EXT, VkPhysicalDeviceBorderColorSwizzleFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES, VkPhysicalDeviceBufferDeviceAddressFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES_EXT, VkPhysicalDeviceBufferDeviceAddressFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CLUSTER_CULLING_SHADER_FEATURES_HUAWEI, VkPhysicalDeviceClusterCullingShaderFeaturesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CLUSTER_CULLING_SHADER_PROPERTIES_HUAWEI, VkPhysicalDeviceClusterCullingShaderPropertiesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COHERENT_MEMORY_FEATURES_AMD, VkPhysicalDeviceCoherentMemoryFeaturesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COLOR_WRITE_ENABLE_FEATURES_EXT, VkPhysicalDeviceColorWriteEnableFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CONDITIONAL_RENDERING_FEATURES_EXT, VkPhysicalDeviceConditionalRenderingFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CONSERVATIVE_RASTERIZATION_PROPERTIES_EXT, VkPhysicalDeviceConservativeRasterizationPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_FEATURES_KHR, VkPhysicalDeviceCooperativeMatrixFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_FEATURES_NV, VkPhysicalDeviceCooperativeMatrixFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_PROPERTIES_KHR, VkPhysicalDeviceCooperativeMatrixPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_PROPERTIES_NV, VkPhysicalDeviceCooperativeMatrixPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COPY_MEMORY_INDIRECT_FEATURES_NV, VkPhysicalDeviceCopyMemoryIndirectFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CORNER_SAMPLED_IMAGE_FEATURES_NV, VkPhysicalDeviceCornerSampledImageFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COVERAGE_REDUCTION_MODE_FEATURES_NV, VkPhysicalDeviceCoverageReductionModeFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CUSTOM_BORDER_COLOR_FEATURES_EXT, VkPhysicalDeviceCustomBorderColorFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CUSTOM_BORDER_COLOR_PROPERTIES_EXT, VkPhysicalDeviceCustomBorderColorPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEDICATED_ALLOCATION_IMAGE_ALIASING_FEATURES_NV, VkPhysicalDeviceDedicatedAllocationImageAliasingFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_BIAS_CONTROL_FEATURES_EXT, VkPhysicalDeviceDepthBiasControlFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_CLIP_CONTROL_FEATURES_EXT, VkPhysicalDeviceDepthClipControlFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_CLIP_ENABLE_FEATURES_EXT, VkPhysicalDeviceDepthClipEnableFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_STENCIL_RESOLVE_PROPERTIES, VkPhysicalDeviceDepthStencilResolveProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_DENSITY_MAP_PROPERTIES_EXT, VkPhysicalDeviceDescriptorBufferDensityMapPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_FEATURES_EXT, VkPhysicalDeviceDescriptorBufferFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_PROPERTIES_EXT, VkPhysicalDeviceDescriptorBufferPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_INDEXING_FEATURES, VkPhysicalDeviceDescriptorIndexingFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_INDEXING_PROPERTIES, VkPhysicalDeviceDescriptorIndexingProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_SET_HOST_MAPPING_FEATURES_VALVE, VkPhysicalDeviceDescriptorSetHostMappingFeaturesVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_GENERATED_COMMANDS_COMPUTE_FEATURES_NV, VkPhysicalDeviceDeviceGeneratedCommandsComputeFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_GENERATED_COMMANDS_FEATURES_NV, VkPhysicalDeviceDeviceGeneratedCommandsFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_GENERATED_COMMANDS_PROPERTIES_NV, VkPhysicalDeviceDeviceGeneratedCommandsPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_MEMORY_REPORT_FEATURES_EXT, VkPhysicalDeviceDeviceMemoryReportFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DIAGNOSTICS_CONFIG_FEATURES_NV, VkPhysicalDeviceDiagnosticsConfigFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DISCARD_RECTANGLE_PROPERTIES_EXT, VkPhysicalDeviceDiscardRectanglePropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES, VkPhysicalDeviceDriverProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRM_PROPERTIES_EXT, VkPhysicalDeviceDrmPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DYNAMIC_RENDERING_FEATURES, VkPhysicalDeviceDynamicRenderingFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DYNAMIC_RENDERING_UNUSED_ATTACHMENTS_FEATURES_EXT, VkPhysicalDeviceDynamicRenderingUnusedAttachmentsFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXCLUSIVE_SCISSOR_FEATURES_NV, VkPhysicalDeviceExclusiveScissorFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_DYNAMIC_STATE_2_FEATURES_EXT, VkPhysicalDeviceExtendedDynamicState2FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_DYNAMIC_STATE_3_FEATURES_EXT, VkPhysicalDeviceExtendedDynamicState3FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_DYNAMIC_STATE_3_PROPERTIES_EXT, VkPhysicalDeviceExtendedDynamicState3PropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_DYNAMIC_STATE_FEATURES_EXT, VkPhysicalDeviceExtendedDynamicStateFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_IMAGE_FORMAT_INFO, VkPhysicalDeviceExternalImageFormatInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_HOST_PROPERTIES_EXT, VkPhysicalDeviceExternalMemoryHostPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_RDMA_FEATURES_NV, VkPhysicalDeviceExternalMemoryRDMAFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FAULT_FEATURES_EXT, VkPhysicalDeviceFaultFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, VkPhysicalDeviceFeatures2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FLOAT_CONTROLS_PROPERTIES, VkPhysicalDeviceFloatControlsProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_2_FEATURES_EXT, VkPhysicalDeviceFragmentDensityMap2FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_2_PROPERTIES_EXT, VkPhysicalDeviceFragmentDensityMap2PropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_FEATURES_EXT, VkPhysicalDeviceFragmentDensityMapFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_PROPERTIES_EXT, VkPhysicalDeviceFragmentDensityMapPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADER_BARYCENTRIC_FEATURES_KHR, VkPhysicalDeviceFragmentShaderBarycentricFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADER_BARYCENTRIC_PROPERTIES_KHR, VkPhysicalDeviceFragmentShaderBarycentricPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADER_INTERLOCK_FEATURES_EXT, VkPhysicalDeviceFragmentShaderInterlockFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADING_RATE_ENUMS_FEATURES_NV, VkPhysicalDeviceFragmentShadingRateEnumsFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADING_RATE_ENUMS_PROPERTIES_NV, VkPhysicalDeviceFragmentShadingRateEnumsPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADING_RATE_FEATURES_KHR, VkPhysicalDeviceFragmentShadingRateFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADING_RATE_PROPERTIES_KHR, VkPhysicalDeviceFragmentShadingRatePropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GRAPHICS_PIPELINE_LIBRARY_FEATURES_EXT, VkPhysicalDeviceGraphicsPipelineLibraryFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GRAPHICS_PIPELINE_LIBRARY_PROPERTIES_EXT, VkPhysicalDeviceGraphicsPipelineLibraryPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_HOST_QUERY_RESET_FEATURES, VkPhysicalDeviceHostQueryResetFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES, VkPhysicalDeviceIDProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_2D_VIEW_OF_3D_FEATURES_EXT, VkPhysicalDeviceImage2DViewOf3DFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_FEATURES_EXT, VkPhysicalDeviceImageCompressionControlFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_COMPRESSION_CONTROL_SWAPCHAIN_FEATURES_EXT, VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_DRM_FORMAT_MODIFIER_INFO_EXT, VkPhysicalDeviceImageDrmFormatModifierInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGELESS_FRAMEBUFFER_FEATURES, VkPhysicalDeviceImagelessFramebufferFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_PROCESSING_FEATURES_QCOM, VkPhysicalDeviceImageProcessingFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_PROCESSING_PROPERTIES_QCOM, VkPhysicalDeviceImageProcessingPropertiesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_ROBUSTNESS_FEATURES, VkPhysicalDeviceImageRobustnessFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_SLICED_VIEW_OF_3D_FEATURES_EXT, VkPhysicalDeviceImageSlicedViewOf3DFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_VIEW_IMAGE_FORMAT_INFO_EXT, VkPhysicalDeviceImageViewImageFormatInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_VIEW_MIN_LOD_FEATURES_EXT, VkPhysicalDeviceImageViewMinLodFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INHERITED_VIEWPORT_SCISSOR_FEATURES_NV, VkPhysicalDeviceInheritedViewportScissorFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INLINE_UNIFORM_BLOCK_FEATURES, VkPhysicalDeviceInlineUniformBlockFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INLINE_UNIFORM_BLOCK_PROPERTIES, VkPhysicalDeviceInlineUniformBlockProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INVOCATION_MASK_FEATURES_HUAWEI, VkPhysicalDeviceInvocationMaskFeaturesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LEGACY_DITHERING_FEATURES_EXT, VkPhysicalDeviceLegacyDitheringFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LINEAR_COLOR_ATTACHMENT_FEATURES_NV, VkPhysicalDeviceLinearColorAttachmentFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_3_PROPERTIES, VkPhysicalDeviceMaintenance3Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_4_FEATURES, VkPhysicalDeviceMaintenance4Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_4_PROPERTIES, VkPhysicalDeviceMaintenance4Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT, VkPhysicalDeviceMemoryBudgetPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PRIORITY_FEATURES_EXT, VkPhysicalDeviceMemoryPriorityFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MESH_SHADER_FEATURES_EXT, VkPhysicalDeviceMeshShaderFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MESH_SHADER_FEATURES_NV, VkPhysicalDeviceMeshShaderFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MESH_SHADER_PROPERTIES_EXT, VkPhysicalDeviceMeshShaderPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MESH_SHADER_PROPERTIES_NV, VkPhysicalDeviceMeshShaderPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTI_DRAW_FEATURES_EXT, VkPhysicalDeviceMultiDrawFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTI_DRAW_PROPERTIES_EXT, VkPhysicalDeviceMultiDrawPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTISAMPLED_RENDER_TO_SINGLE_SAMPLED_FEATURES_EXT, VkPhysicalDeviceMultisampledRenderToSingleSampledFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_FEATURES, VkPhysicalDeviceMultiviewFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_PER_VIEW_ATTRIBUTES_PROPERTIES_NVX, VkPhysicalDeviceMultiviewPerViewAttributesPropertiesNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_PER_VIEW_RENDER_AREAS_FEATURES_QCOM, VkPhysicalDeviceMultiviewPerViewRenderAreasFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_PER_VIEW_VIEWPORTS_FEATURES_QCOM, VkPhysicalDeviceMultiviewPerViewViewportsFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MULTIVIEW_PROPERTIES, VkPhysicalDeviceMultiviewProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MUTABLE_DESCRIPTOR_TYPE_FEATURES_EXT, VkPhysicalDeviceMutableDescriptorTypeFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_NON_SEAMLESS_CUBE_MAP_FEATURES_EXT, VkPhysicalDeviceNonSeamlessCubeMapFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_OPACITY_MICROMAP_FEATURES_EXT, VkPhysicalDeviceOpacityMicromapFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_OPACITY_MICROMAP_PROPERTIES_EXT, VkPhysicalDeviceOpacityMicromapPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_OPTICAL_FLOW_FEATURES_NV, VkPhysicalDeviceOpticalFlowFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_OPTICAL_FLOW_PROPERTIES_NV, VkPhysicalDeviceOpticalFlowPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PAGEABLE_DEVICE_LOCAL_MEMORY_FEATURES_EXT, VkPhysicalDevicePageableDeviceLocalMemoryFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PCI_BUS_INFO_PROPERTIES_EXT, VkPhysicalDevicePCIBusInfoPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PERFORMANCE_QUERY_FEATURES_KHR, VkPhysicalDevicePerformanceQueryFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PERFORMANCE_QUERY_PROPERTIES_KHR, VkPhysicalDevicePerformanceQueryPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_CREATION_CACHE_CONTROL_FEATURES, VkPhysicalDevicePipelineCreationCacheControlFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_EXECUTABLE_PROPERTIES_FEATURES_KHR, VkPhysicalDevicePipelineExecutablePropertiesFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_LIBRARY_GROUP_HANDLES_FEATURES_EXT, VkPhysicalDevicePipelineLibraryGroupHandlesFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_PROPERTIES_FEATURES_EXT, VkPhysicalDevicePipelinePropertiesFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_POINT_CLIPPING_PROPERTIES, VkPhysicalDevicePointClippingProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_BARRIER_FEATURES_NV, VkPhysicalDevicePresentBarrierFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_ID_FEATURES_KHR, VkPhysicalDevicePresentIdFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_WAIT_FEATURES_KHR, VkPhysicalDevicePresentWaitFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRIMITIVES_GENERATED_QUERY_FEATURES_EXT, VkPhysicalDevicePrimitivesGeneratedQueryFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRIMITIVE_TOPOLOGY_LIST_RESTART_FEATURES_EXT, VkPhysicalDevicePrimitiveTopologyListRestartFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRIVATE_DATA_FEATURES, VkPhysicalDevicePrivateDataFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROTECTED_MEMORY_FEATURES, VkPhysicalDeviceProtectedMemoryFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROTECTED_MEMORY_PROPERTIES, VkPhysicalDeviceProtectedMemoryProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROVOKING_VERTEX_FEATURES_EXT, VkPhysicalDeviceProvokingVertexFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROVOKING_VERTEX_PROPERTIES_EXT, VkPhysicalDeviceProvokingVertexPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RASTERIZATION_ORDER_ATTACHMENT_ACCESS_FEATURES_EXT, VkPhysicalDeviceRasterizationOrderAttachmentAccessFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_QUERY_FEATURES_KHR, VkPhysicalDeviceRayQueryFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_INVOCATION_REORDER_FEATURES_NV, VkPhysicalDeviceRayTracingInvocationReorderFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_INVOCATION_REORDER_PROPERTIES_NV, VkPhysicalDeviceRayTracingInvocationReorderPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_MAINTENANCE_1_FEATURES_KHR, VkPhysicalDeviceRayTracingMaintenance1FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_MOTION_BLUR_FEATURES_NV, VkPhysicalDeviceRayTracingMotionBlurFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_FEATURES_KHR, VkPhysicalDeviceRayTracingPipelineFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PIPELINE_PROPERTIES_KHR, VkPhysicalDeviceRayTracingPipelinePropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_POSITION_FETCH_FEATURES_KHR, VkPhysicalDeviceRayTracingPositionFetchFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_PROPERTIES_NV, VkPhysicalDeviceRayTracingPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_REPRESENTATIVE_FRAGMENT_TEST_FEATURES_NV, VkPhysicalDeviceRepresentativeFragmentTestFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RGBA10X6_FORMATS_FEATURES_EXT, VkPhysicalDeviceRGBA10X6FormatsFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SAMPLE_LOCATIONS_PROPERTIES_EXT, VkPhysicalDeviceSampleLocationsPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SAMPLER_FILTER_MINMAX_PROPERTIES, VkPhysicalDeviceSamplerFilterMinmaxProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SAMPLER_YCBCR_CONVERSION_FEATURES, VkPhysicalDeviceSamplerYcbcrConversionFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SCALAR_BLOCK_LAYOUT_FEATURES, VkPhysicalDeviceScalarBlockLayoutFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SEPARATE_DEPTH_STENCIL_LAYOUTS_FEATURES, VkPhysicalDeviceSeparateDepthStencilLayoutsFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_ATOMIC_FLOAT_2_FEATURES_EXT, VkPhysicalDeviceShaderAtomicFloat2FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_ATOMIC_FLOAT_FEATURES_EXT, VkPhysicalDeviceShaderAtomicFloatFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_ATOMIC_INT64_FEATURES, VkPhysicalDeviceShaderAtomicInt64Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CLOCK_FEATURES_KHR, VkPhysicalDeviceShaderClockFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CORE_BUILTINS_FEATURES_ARM, VkPhysicalDeviceShaderCoreBuiltinsFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CORE_BUILTINS_PROPERTIES_ARM, VkPhysicalDeviceShaderCoreBuiltinsPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CORE_PROPERTIES_2_AMD, VkPhysicalDeviceShaderCoreProperties2AMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CORE_PROPERTIES_AMD, VkPhysicalDeviceShaderCorePropertiesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_CORE_PROPERTIES_ARM, VkPhysicalDeviceShaderCorePropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_DEMOTE_TO_HELPER_INVOCATION_FEATURES, VkPhysicalDeviceShaderDemoteToHelperInvocationFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_DRAW_PARAMETERS_FEATURES, VkPhysicalDeviceShaderDrawParametersFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_EARLY_AND_LATE_FRAGMENT_TESTS_FEATURES_AMD, VkPhysicalDeviceShaderEarlyAndLateFragmentTestsFeaturesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT16_INT8_FEATURES, VkPhysicalDeviceShaderFloat16Int8Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_IMAGE_ATOMIC_INT64_FEATURES_EXT, VkPhysicalDeviceShaderImageAtomicInt64FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_IMAGE_FOOTPRINT_FEATURES_NV, VkPhysicalDeviceShaderImageFootprintFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_INTEGER_DOT_PRODUCT_FEATURES, VkPhysicalDeviceShaderIntegerDotProductFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_INTEGER_DOT_PRODUCT_PROPERTIES, VkPhysicalDeviceShaderIntegerDotProductProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_INTEGER_FUNCTIONS_2_FEATURES_INTEL, VkPhysicalDeviceShaderIntegerFunctions2FeaturesINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_MODULE_IDENTIFIER_FEATURES_EXT, VkPhysicalDeviceShaderModuleIdentifierFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_MODULE_IDENTIFIER_PROPERTIES_EXT, VkPhysicalDeviceShaderModuleIdentifierPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_OBJECT_FEATURES_EXT, VkPhysicalDeviceShaderObjectFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_OBJECT_PROPERTIES_EXT, VkPhysicalDeviceShaderObjectPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SM_BUILTINS_FEATURES_NV, VkPhysicalDeviceShaderSMBuiltinsFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SM_BUILTINS_PROPERTIES_NV, VkPhysicalDeviceShaderSMBuiltinsPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SUBGROUP_EXTENDED_TYPES_FEATURES, VkPhysicalDeviceShaderSubgroupExtendedTypesFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SUBGROUP_UNIFORM_CONTROL_FLOW_FEATURES_KHR, VkPhysicalDeviceShaderSubgroupUniformControlFlowFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_UNTYPED_POINTERS_FEATURES_KHR, VkPhysicalDeviceShaderUntypedPointersFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_TERMINATE_INVOCATION_FEATURES, VkPhysicalDeviceShaderTerminateInvocationFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_TILE_IMAGE_FEATURES_EXT, VkPhysicalDeviceShaderTileImageFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_TILE_IMAGE_PROPERTIES_EXT, VkPhysicalDeviceShaderTileImagePropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADING_RATE_IMAGE_FEATURES_NV, VkPhysicalDeviceShadingRateImageFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADING_RATE_IMAGE_PROPERTIES_NV, VkPhysicalDeviceShadingRateImagePropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_PROPERTIES, VkPhysicalDeviceSubgroupProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_FEATURES, VkPhysicalDeviceSubgroupSizeControlFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_PROPERTIES, VkPhysicalDeviceSubgroupSizeControlProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBPASS_MERGE_FEEDBACK_FEATURES_EXT, VkPhysicalDeviceSubpassMergeFeedbackFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBPASS_SHADING_FEATURES_HUAWEI, VkPhysicalDeviceSubpassShadingFeaturesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBPASS_SHADING_PROPERTIES_HUAWEI, VkPhysicalDeviceSubpassShadingPropertiesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SYNCHRONIZATION_2_FEATURES, VkPhysicalDeviceSynchronization2Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TEXEL_BUFFER_ALIGNMENT_FEATURES_EXT, VkPhysicalDeviceTexelBufferAlignmentFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TEXEL_BUFFER_ALIGNMENT_PROPERTIES, VkPhysicalDeviceTexelBufferAlignmentProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TEXTURE_COMPRESSION_ASTC_HDR_FEATURES, VkPhysicalDeviceTextureCompressionASTCHDRFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TILE_PROPERTIES_FEATURES_QCOM, VkPhysicalDeviceTilePropertiesFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_FEATURES, VkPhysicalDeviceTimelineSemaphoreFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_PROPERTIES, VkPhysicalDeviceTimelineSemaphoreProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TRANSFORM_FEEDBACK_FEATURES_EXT, VkPhysicalDeviceTransformFeedbackFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TRANSFORM_FEEDBACK_PROPERTIES_EXT, VkPhysicalDeviceTransformFeedbackPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_UNIFORM_BUFFER_STANDARD_LAYOUT_FEATURES, VkPhysicalDeviceUniformBufferStandardLayoutFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VARIABLE_POINTERS_FEATURES, VkPhysicalDeviceVariablePointersFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VERTEX_ATTRIBUTE_DIVISOR_PROPERTIES_EXT, VkPhysicalDeviceVertexAttributeDivisorPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VERTEX_INPUT_DYNAMIC_STATE_FEATURES_EXT, VkPhysicalDeviceVertexInputDynamicStateFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES, VkPhysicalDeviceVulkan11Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_PROPERTIES, VkPhysicalDeviceVulkan11Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_FEATURES, VkPhysicalDeviceVulkan12Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_2_PROPERTIES, VkPhysicalDeviceVulkan12Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES, VkPhysicalDeviceVulkan13Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_PROPERTIES, VkPhysicalDeviceVulkan13Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_MEMORY_MODEL_FEATURES, VkPhysicalDeviceVulkanMemoryModelFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_WORKGROUP_MEMORY_EXPLICIT_LAYOUT_FEATURES_KHR, VkPhysicalDeviceWorkgroupMemoryExplicitLayoutFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_YCBCR_2_PLANE_444_FORMATS_FEATURES_EXT, VkPhysicalDeviceYcbcr2Plane444FormatsFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_YCBCR_IMAGE_ARRAYS_FEATURES_EXT, VkPhysicalDeviceYcbcrImageArraysFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ZERO_INITIALIZE_WORKGROUP_MEMORY_FEATURES, VkPhysicalDeviceZeroInitializeWorkgroupMemoryFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_ADVANCED_STATE_CREATE_INFO_EXT, VkPipelineColorBlendAdvancedStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COLOR_WRITE_CREATE_INFO_EXT, VkPipelineColorWriteCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COMPILER_CONTROL_CREATE_INFO_AMD, VkPipelineCompilerControlCreateInfoAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COVERAGE_MODULATION_STATE_CREATE_INFO_NV, VkPipelineCoverageModulationStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COVERAGE_REDUCTION_STATE_CREATE_INFO_NV, VkPipelineCoverageReductionStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COVERAGE_TO_COLOR_STATE_CREATE_INFO_NV, VkPipelineCoverageToColorStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_DISCARD_RECTANGLE_STATE_CREATE_INFO_EXT, VkPipelineDiscardRectangleStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_FRAGMENT_SHADING_RATE_ENUM_STATE_CREATE_INFO_NV, VkPipelineFragmentShadingRateEnumStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_FRAGMENT_SHADING_RATE_STATE_CREATE_INFO_KHR, VkPipelineFragmentShadingRateStateCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_LIBRARY_CREATE_INFO_KHR, VkPipelineLibraryCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_CONSERVATIVE_STATE_CREATE_INFO_EXT, VkPipelineRasterizationConservativeStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_DEPTH_CLIP_STATE_CREATE_INFO_EXT, VkPipelineRasterizationDepthClipStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_PROVOKING_VERTEX_STATE_CREATE_INFO_EXT, VkPipelineRasterizationProvokingVertexStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_RASTERIZATION_ORDER_AMD, VkPipelineRasterizationStateRasterizationOrderAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_STREAM_CREATE_INFO_EXT, VkPipelineRasterizationStateStreamCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO, VkPipelineRenderingCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_REPRESENTATIVE_FRAGMENT_TEST_STATE_CREATE_INFO_NV, VkPipelineRepresentativeFragmentTestStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_SAMPLE_LOCATIONS_STATE_CREATE_INFO_EXT, VkPipelineSampleLocationsStateCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_MODULE_IDENTIFIER_CREATE_INFO_EXT, VkPipelineShaderStageModuleIdentifierCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_REQUIRED_SUBGROUP_SIZE_CREATE_INFO, VkPipelineShaderStageRequiredSubgroupSizeCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_TESSELLATION_DOMAIN_ORIGIN_STATE_CREATE_INFO, VkPipelineTessellationDomainOriginStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_DEPTH_CLIP_CONTROL_CREATE_INFO_EXT, VkPipelineViewportDepthClipControlCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_EXCLUSIVE_SCISSOR_STATE_CREATE_INFO_NV, VkPipelineViewportExclusiveScissorStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_SWIZZLE_STATE_CREATE_INFO_NV, VkPipelineViewportSwizzleStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_W_SCALING_STATE_CREATE_INFO_NV, VkPipelineViewportWScalingStateCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_ID_KHR, VkPresentIdKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PROTECTED_SUBMIT_INFO, VkProtectedSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUERY_POOL_PERFORMANCE_CREATE_INFO_KHR, VkQueryPoolPerformanceCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUERY_POOL_PERFORMANCE_QUERY_CREATE_INFO_INTEL, VkQueryPoolPerformanceQueryCreateInfoINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_CHECKPOINT_PROPERTIES_2_NV, VkQueueFamilyCheckpointProperties2NV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_CHECKPOINT_PROPERTIES_NV, VkQueueFamilyCheckpointPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_QUERY_RESULT_STATUS_PROPERTIES_KHR, VkQueueFamilyQueryResultStatusPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_VIDEO_PROPERTIES_KHR, VkQueueFamilyVideoPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_FRAGMENT_DENSITY_MAP_ATTACHMENT_INFO_EXT, VkRenderingFragmentDensityMapAttachmentInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_FRAGMENT_SHADING_RATE_ATTACHMENT_INFO_KHR, VkRenderingFragmentShadingRateAttachmentInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_ATTACHMENT_BEGIN_INFO, VkRenderPassAttachmentBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_CREATION_CONTROL_EXT, VkRenderPassCreationControlEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_CREATION_FEEDBACK_CREATE_INFO_EXT, VkRenderPassCreationFeedbackCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_FRAGMENT_DENSITY_MAP_CREATE_INFO_EXT, VkRenderPassFragmentDensityMapCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_INPUT_ATTACHMENT_ASPECT_CREATE_INFO, VkRenderPassInputAttachmentAspectCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_MULTIVIEW_CREATE_INFO, VkRenderPassMultiviewCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_SUBPASS_FEEDBACK_CREATE_INFO_EXT, VkRenderPassSubpassFeedbackCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_TRANSFORM_BEGIN_INFO_QCOM, VkRenderPassTransformBeginInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLE_LOCATIONS_INFO_EXT, VkSampleLocationsInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_BORDER_COLOR_COMPONENT_MAPPING_CREATE_INFO_EXT, VkSamplerBorderColorComponentMappingCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_CUSTOM_BORDER_COLOR_CREATE_INFO_EXT, VkSamplerCustomBorderColorCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_REDUCTION_MODE_CREATE_INFO, VkSamplerReductionModeCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_YCBCR_CONVERSION_IMAGE_FORMAT_PROPERTIES, VkSamplerYcbcrConversionImageFormatProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_YCBCR_CONVERSION_INFO, VkSamplerYcbcrConversionInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO, VkSemaphoreTypeCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, VkShaderModuleCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SHADER_MODULE_VALIDATION_CACHE_CREATE_INFO_EXT, VkShaderModuleValidationCacheCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SHARED_PRESENT_SURFACE_CAPABILITIES_KHR, VkSharedPresentSurfaceCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_RESOLVE_PERFORMANCE_QUERY_EXT, VkSubpassResolvePerformanceQueryEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_SHADING_PIPELINE_CREATE_INFO_HUAWEI, VkSubpassShadingPipelineCreateInfoHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_PRESENT_BARRIER_NV, VkSurfaceCapabilitiesPresentBarrierNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_PROTECTED_CAPABILITIES_KHR, VkSurfaceProtectedCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_COUNTER_CREATE_INFO_EXT, VkSwapchainCounterCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_DISPLAY_NATIVE_HDR_CREATE_INFO_AMD, VkSwapchainDisplayNativeHdrCreateInfoAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_BARRIER_CREATE_INFO_NV, VkSwapchainPresentBarrierCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TEXTURE_LOD_GATHER_FORMAT_PROPERTIES_AMD, VkTextureLODGatherFormatPropertiesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO, VkTimelineSemaphoreSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VALIDATION_FEATURES_EXT, VkValidationFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VALIDATION_FLAGS_EXT, VkValidationFlagsEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_CAPABILITIES_KHR, VkVideoDecodeCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H264_CAPABILITIES_KHR, VkVideoDecodeH264CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H264_DPB_SLOT_INFO_KHR, VkVideoDecodeH264DpbSlotInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H264_PICTURE_INFO_KHR, VkVideoDecodeH264PictureInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H264_PROFILE_INFO_KHR, VkVideoDecodeH264ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H265_CAPABILITIES_KHR, VkVideoDecodeH265CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H265_DPB_SLOT_INFO_KHR, VkVideoDecodeH265DpbSlotInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H265_PICTURE_INFO_KHR, VkVideoDecodeH265PictureInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_H265_PROFILE_INFO_KHR, VkVideoDecodeH265ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_USAGE_INFO_KHR, VkVideoDecodeUsageInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_PROFILE_INFO_KHR, VkVideoProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_KHR, VkWriteDescriptorSetAccelerationStructureKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_ACCELERATION_STRUCTURE_NV, VkWriteDescriptorSetAccelerationStructureNV>,

  // Feature/property/capability structs an app or driver chains into a query.
  // These all had a VULKAN_*_CUSTOM_REPACK registration but no entry here, so
  // they were silently dropped from the chain and the guest read back zeroes.
  // DXVK reads that as "device lacks the feature" and skips the adapter
  // outright: with VkPhysicalDeviceMaintenance6Features missing it rejected
  // every GPU on the box with "Device does not support required feature
  // 'maintenance6'" and never created a device.
  //
  // Derived by matching each repack-registered struct name against the
  // VkStructureType enumerant it canonicalises to, so a pairing is only
  // emitted when the two agree exactly; anything irregular (VkPhysicalDevice-
  // Vulkan14Features, whose enum spells it VULKAN_1_4) is listed by hand below
  // rather than guessed at.
  converters<VkStructureType::VK_STRUCTURE_TYPE_COOPERATIVE_MATRIX_FLEXIBLE_DIMENSIONS_PROPERTIES_NV, VkCooperativeMatrixFlexibleDimensionsPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COOPERATIVE_MATRIX_PROPERTIES_KHR, VkCooperativeMatrixPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COOPERATIVE_MATRIX_PROPERTIES_NV, VkCooperativeMatrixPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COOPERATIVE_VECTOR_PROPERTIES_NV, VkCooperativeVectorPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_GROUP_PRESENT_CAPABILITIES_KHR, VkDeviceGroupPresentCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_MODE_PROPERTIES_2_KHR, VkDisplayModeProperties2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_MODE_STEREO_PROPERTIES_NV, VkDisplayModeStereoPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_PLANE_CAPABILITIES_2_KHR, VkDisplayPlaneCapabilities2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_PLANE_PROPERTIES_2_KHR, VkDisplayPlaneProperties2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_PROPERTIES_2_KHR, VkDisplayProperties2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_BUFFER_PROPERTIES, VkExternalBufferProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_FENCE_PROPERTIES, VkExternalFenceProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_SEMAPHORE_PROPERTIES, VkExternalSemaphoreProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_TENSOR_PROPERTIES_ARM, VkExternalTensorPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2, VkFormatProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_DRM_FORMAT_MODIFIER_PROPERTIES_EXT, VkImageDrmFormatModifierPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_FORMAT_PROPERTIES_2, VkImageFormatProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_ADDRESS_PROPERTIES_NVX, VkImageViewAddressPropertiesNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_LATENCY_SURFACE_CAPABILITIES_NV, VkLatencySurfaceCapabilitiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_FD_PROPERTIES_KHR, VkMemoryFdPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_HOST_POINTER_PROPERTIES_EXT, VkMemoryHostPointerPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MULTISAMPLE_PROPERTIES_EXT, VkMultisamplePropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_OPTICAL_FLOW_IMAGE_FORMAT_PROPERTIES_NV, VkOpticalFlowImageFormatPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ANTI_LAG_FEATURES_AMD, VkPhysicalDeviceAntiLagFeaturesAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CLUSTER_ACCELERATION_STRUCTURE_FEATURES_NV, VkPhysicalDeviceClusterAccelerationStructureFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CLUSTER_ACCELERATION_STRUCTURE_PROPERTIES_NV, VkPhysicalDeviceClusterAccelerationStructurePropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CLUSTER_CULLING_SHADER_VRS_FEATURES_HUAWEI, VkPhysicalDeviceClusterCullingShaderVrsFeaturesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COMMAND_BUFFER_INHERITANCE_FEATURES_NV, VkPhysicalDeviceCommandBufferInheritanceFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COMPUTE_OCCUPANCY_PRIORITY_FEATURES_NV, VkPhysicalDeviceComputeOccupancyPriorityFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COMPUTE_SHADER_DERIVATIVES_FEATURES_KHR, VkPhysicalDeviceComputeShaderDerivativesFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COMPUTE_SHADER_DERIVATIVES_PROPERTIES_KHR, VkPhysicalDeviceComputeShaderDerivativesPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_2_FEATURES_NV, VkPhysicalDeviceCooperativeMatrix2FeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_MATRIX_2_PROPERTIES_NV, VkPhysicalDeviceCooperativeMatrix2PropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_VECTOR_FEATURES_NV, VkPhysicalDeviceCooperativeVectorFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COOPERATIVE_VECTOR_PROPERTIES_NV, VkPhysicalDeviceCooperativeVectorPropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COPY_MEMORY_INDIRECT_FEATURES_KHR, VkPhysicalDeviceCopyMemoryIndirectFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_COPY_MEMORY_INDIRECT_PROPERTIES_KHR, VkPhysicalDeviceCopyMemoryIndirectPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CUBIC_CLAMP_FEATURES_QCOM, VkPhysicalDeviceCubicClampFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CUBIC_WEIGHTS_FEATURES_QCOM, VkPhysicalDeviceCubicWeightsFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_CUSTOM_RESOLVE_FEATURES_EXT, VkPhysicalDeviceCustomResolveFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DATA_GRAPH_FEATURES_ARM, VkPhysicalDeviceDataGraphFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DATA_GRAPH_MODEL_FEATURES_QCOM, VkPhysicalDeviceDataGraphModelFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_CLAMP_CONTROL_FEATURES_EXT, VkPhysicalDeviceDepthClampControlFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEPTH_CLAMP_ZERO_ONE_FEATURES_KHR, VkPhysicalDeviceDepthClampZeroOneFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_TENSOR_FEATURES_ARM, VkPhysicalDeviceDescriptorBufferTensorFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_BUFFER_TENSOR_PROPERTIES_ARM, VkPhysicalDeviceDescriptorBufferTensorPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_POOL_OVERALLOCATION_FEATURES_NV, VkPhysicalDeviceDescriptorPoolOverallocationFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_GENERATED_COMMANDS_FEATURES_EXT, VkPhysicalDeviceDeviceGeneratedCommandsFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DEVICE_GENERATED_COMMANDS_PROPERTIES_EXT, VkPhysicalDeviceDeviceGeneratedCommandsPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DYNAMIC_RENDERING_LOCAL_READ_FEATURES, VkPhysicalDeviceDynamicRenderingLocalReadFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_SPARSE_ADDRESS_SPACE_FEATURES_NV, VkPhysicalDeviceExtendedSparseAddressSpaceFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTENDED_SPARSE_ADDRESS_SPACE_PROPERTIES_NV, VkPhysicalDeviceExtendedSparseAddressSpacePropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_COMPUTE_QUEUE_PROPERTIES_NV, VkPhysicalDeviceExternalComputeQueuePropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FORMAT_PACK_FEATURES_ARM, VkPhysicalDeviceFormatPackFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_LAYERED_FEATURES_VALVE, VkPhysicalDeviceFragmentDensityMapLayeredFeaturesVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_LAYERED_PROPERTIES_VALVE, VkPhysicalDeviceFragmentDensityMapLayeredPropertiesVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_OFFSET_FEATURES_EXT, VkPhysicalDeviceFragmentDensityMapOffsetFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_DENSITY_MAP_OFFSET_PROPERTIES_EXT, VkPhysicalDeviceFragmentDensityMapOffsetPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAME_BOUNDARY_FEATURES_EXT, VkPhysicalDeviceFrameBoundaryFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_GLOBAL_PRIORITY_QUERY_FEATURES, VkPhysicalDeviceGlobalPriorityQueryFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_HDR_VIVID_FEATURES_HUAWEI, VkPhysicalDeviceHdrVividFeaturesHUAWEI>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_HOST_IMAGE_COPY_FEATURES, VkPhysicalDeviceHostImageCopyFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_HOST_IMAGE_COPY_PROPERTIES, VkPhysicalDeviceHostImageCopyProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_ALIGNMENT_CONTROL_FEATURES_MESA, VkPhysicalDeviceImageAlignmentControlFeaturesMESA>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_ALIGNMENT_CONTROL_PROPERTIES_MESA, VkPhysicalDeviceImageAlignmentControlPropertiesMESA>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_PROCESSING_2_FEATURES_QCOM, VkPhysicalDeviceImageProcessing2FeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_PROCESSING_2_PROPERTIES_QCOM, VkPhysicalDeviceImageProcessing2PropertiesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LAYERED_API_PROPERTIES_KHR, VkPhysicalDeviceLayeredApiPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LAYERED_API_VULKAN_PROPERTIES_KHR, VkPhysicalDeviceLayeredApiVulkanPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LAYERED_DRIVER_PROPERTIES_MSFT, VkPhysicalDeviceLayeredDriverPropertiesMSFT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LEGACY_VERTEX_ATTRIBUTES_FEATURES_EXT, VkPhysicalDeviceLegacyVertexAttributesFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LEGACY_VERTEX_ATTRIBUTES_PROPERTIES_EXT, VkPhysicalDeviceLegacyVertexAttributesPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LINE_RASTERIZATION_FEATURES, VkPhysicalDeviceLineRasterizationFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_LINE_RASTERIZATION_PROPERTIES, VkPhysicalDeviceLineRasterizationProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_10_FEATURES_KHR, VkPhysicalDeviceMaintenance10FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_10_PROPERTIES_KHR, VkPhysicalDeviceMaintenance10PropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_5_FEATURES, VkPhysicalDeviceMaintenance5Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_5_PROPERTIES, VkPhysicalDeviceMaintenance5Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_6_FEATURES, VkPhysicalDeviceMaintenance6Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_6_PROPERTIES, VkPhysicalDeviceMaintenance6Properties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_7_FEATURES_KHR, VkPhysicalDeviceMaintenance7FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_7_PROPERTIES_KHR, VkPhysicalDeviceMaintenance7PropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_8_FEATURES_KHR, VkPhysicalDeviceMaintenance8FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_9_FEATURES_KHR, VkPhysicalDeviceMaintenance9FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAINTENANCE_9_PROPERTIES_KHR, VkPhysicalDeviceMaintenance9PropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAP_MEMORY_PLACED_FEATURES_EXT, VkPhysicalDeviceMapMemoryPlacedFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MAP_MEMORY_PLACED_PROPERTIES_EXT, VkPhysicalDeviceMapMemoryPlacedPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_DECOMPRESSION_FEATURES_EXT, VkPhysicalDeviceMemoryDecompressionFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_DECOMPRESSION_PROPERTIES_EXT, VkPhysicalDeviceMemoryDecompressionPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2, VkPhysicalDeviceMemoryProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_NESTED_COMMAND_BUFFER_FEATURES_EXT, VkPhysicalDeviceNestedCommandBufferFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_NESTED_COMMAND_BUFFER_PROPERTIES_EXT, VkPhysicalDeviceNestedCommandBufferPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PARTITIONED_ACCELERATION_STRUCTURE_FEATURES_NV, VkPhysicalDevicePartitionedAccelerationStructureFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PARTITIONED_ACCELERATION_STRUCTURE_PROPERTIES_NV, VkPhysicalDevicePartitionedAccelerationStructurePropertiesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PER_STAGE_DESCRIPTOR_SET_FEATURES_NV, VkPhysicalDevicePerStageDescriptorSetFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PERFORMANCE_COUNTERS_BY_REGION_FEATURES_ARM, VkPhysicalDevicePerformanceCountersByRegionFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PERFORMANCE_COUNTERS_BY_REGION_PROPERTIES_ARM, VkPhysicalDevicePerformanceCountersByRegionPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_BINARY_FEATURES_KHR, VkPhysicalDevicePipelineBinaryFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_BINARY_PROPERTIES_KHR, VkPhysicalDevicePipelineBinaryPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_CACHE_INCREMENTAL_MODE_FEATURES_SEC, VkPhysicalDevicePipelineCacheIncrementalModeFeaturesSEC>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_OPACITY_MICROMAP_FEATURES_ARM, VkPhysicalDevicePipelineOpacityMicromapFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_PROTECTED_ACCESS_FEATURES, VkPhysicalDevicePipelineProtectedAccessFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_ROBUSTNESS_FEATURES, VkPhysicalDevicePipelineRobustnessFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_ROBUSTNESS_PROPERTIES, VkPhysicalDevicePipelineRobustnessProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_ID_2_FEATURES_KHR, VkPhysicalDevicePresentId2FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_MODE_FIFO_LATEST_READY_FEATURES_KHR, VkPhysicalDevicePresentModeFifoLatestReadyFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_TIMING_FEATURES_EXT, VkPhysicalDevicePresentTimingFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PRESENT_WAIT_2_FEATURES_KHR, VkPhysicalDevicePresentWait2FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, VkPhysicalDeviceProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PUSH_DESCRIPTOR_PROPERTIES, VkPhysicalDevicePushDescriptorProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAW_ACCESS_CHAINS_FEATURES_NV, VkPhysicalDeviceRawAccessChainsFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_INVOCATION_REORDER_FEATURES_EXT, VkPhysicalDeviceRayTracingInvocationReorderFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_INVOCATION_REORDER_PROPERTIES_EXT, VkPhysicalDeviceRayTracingInvocationReorderPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_LINEAR_SWEPT_SPHERES_FEATURES_NV, VkPhysicalDeviceRayTracingLinearSweptSpheresFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RAY_TRACING_VALIDATION_FEATURES_NV, VkPhysicalDeviceRayTracingValidationFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RELAXED_LINE_RASTERIZATION_FEATURES_IMG, VkPhysicalDeviceRelaxedLineRasterizationFeaturesIMG>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RENDER_PASS_STRIPED_FEATURES_ARM, VkPhysicalDeviceRenderPassStripedFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_RENDER_PASS_STRIPED_PROPERTIES_ARM, VkPhysicalDeviceRenderPassStripedPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ROBUSTNESS_2_FEATURES_KHR, VkPhysicalDeviceRobustness2FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ROBUSTNESS_2_PROPERTIES_KHR, VkPhysicalDeviceRobustness2PropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SCHEDULING_CONTROLS_FEATURES_ARM, VkPhysicalDeviceSchedulingControlsFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SCHEDULING_CONTROLS_PROPERTIES_ARM, VkPhysicalDeviceSchedulingControlsPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_64_BIT_INDEXING_FEATURES_EXT, VkPhysicalDeviceShader64BitIndexingFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_EXPECT_ASSUME_FEATURES, VkPhysicalDeviceShaderExpectAssumeFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT_CONTROLS_2_FEATURES, VkPhysicalDeviceShaderFloatControls2Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FMA_FEATURES_KHR, VkPhysicalDeviceShaderFmaFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_LONG_VECTOR_FEATURES_EXT, VkPhysicalDeviceShaderLongVectorFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_LONG_VECTOR_PROPERTIES_EXT, VkPhysicalDeviceShaderLongVectorPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_MAXIMAL_RECONVERGENCE_FEATURES_KHR, VkPhysicalDeviceShaderMaximalReconvergenceFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_QUAD_CONTROL_FEATURES_KHR, VkPhysicalDeviceShaderQuadControlFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_RELAXED_EXTENDED_INSTRUCTION_FEATURES_KHR, VkPhysicalDeviceShaderRelaxedExtendedInstructionFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_REPLICATED_COMPOSITES_FEATURES_EXT, VkPhysicalDeviceShaderReplicatedCompositesFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_SUBGROUP_ROTATE_FEATURES, VkPhysicalDeviceShaderSubgroupRotateFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_UNIFORM_BUFFER_UNSIZED_ARRAY_FEATURES_EXT, VkPhysicalDeviceShaderUniformBufferUnsizedArrayFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SWAPCHAIN_MAINTENANCE_1_FEATURES_KHR, VkPhysicalDeviceSwapchainMaintenance1FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TENSOR_FEATURES_ARM, VkPhysicalDeviceTensorFeaturesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TENSOR_PROPERTIES_ARM, VkPhysicalDeviceTensorPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TILE_MEMORY_HEAP_FEATURES_QCOM, VkPhysicalDeviceTileMemoryHeapFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TILE_MEMORY_HEAP_PROPERTIES_QCOM, VkPhysicalDeviceTileMemoryHeapPropertiesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TILE_SHADING_FEATURES_QCOM, VkPhysicalDeviceTileShadingFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TILE_SHADING_PROPERTIES_QCOM, VkPhysicalDeviceTileShadingPropertiesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TOOL_PROPERTIES, VkPhysicalDeviceToolProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_UNIFIED_IMAGE_LAYOUTS_FEATURES_KHR, VkPhysicalDeviceUnifiedImageLayoutsFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VERTEX_ATTRIBUTE_DIVISOR_FEATURES, VkPhysicalDeviceVertexAttributeDivisorFeatures>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VERTEX_ATTRIBUTE_DIVISOR_PROPERTIES, VkPhysicalDeviceVertexAttributeDivisorProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VERTEX_ATTRIBUTE_ROBUSTNESS_FEATURES_EXT, VkPhysicalDeviceVertexAttributeRobustnessFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_ENCODE_INTRA_REFRESH_FEATURES_KHR, VkPhysicalDeviceVideoEncodeIntraRefreshFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_ENCODE_QUANTIZATION_MAP_FEATURES_KHR, VkPhysicalDeviceVideoEncodeQuantizationMapFeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_ENCODE_RGB_CONVERSION_FEATURES_VALVE, VkPhysicalDeviceVideoEncodeRgbConversionFeaturesVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_MAINTENANCE_1_FEATURES_KHR, VkPhysicalDeviceVideoMaintenance1FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_MAINTENANCE_2_FEATURES_KHR, VkPhysicalDeviceVideoMaintenance2FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_YCBCR_DEGAMMA_FEATURES_QCOM, VkPhysicalDeviceYcbcrDegammaFeaturesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ZERO_INITIALIZE_DEVICE_MEMORY_FEATURES_EXT, VkPhysicalDeviceZeroInitializeDeviceMemoryFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_PROPERTIES_KHR, VkPipelineExecutablePropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_PROPERTIES_IDENTIFIER_EXT, VkPipelinePropertiesIdentifierEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_TIMING_SURFACE_CAPABILITIES_EXT, VkPresentTimingSurfaceCapabilitiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_DATA_GRAPH_PROCESSING_ENGINE_PROPERTIES_ARM, VkQueueFamilyDataGraphProcessingEnginePropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_DATA_GRAPH_PROPERTIES_ARM, VkQueueFamilyDataGraphPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_GLOBAL_PRIORITY_PROPERTIES, VkQueueFamilyGlobalPriorityProperties>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_OWNERSHIP_TRANSFER_PROPERTIES_KHR, VkQueueFamilyOwnershipTransferPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUEUE_FAMILY_PROPERTIES_2, VkQueueFamilyProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SPARSE_IMAGE_FORMAT_PROPERTIES_2, VkSparseImageFormatProperties2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_2_EXT, VkSurfaceCapabilities2EXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_2_KHR, VkSurfaceCapabilities2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_PRESENT_ID_2_KHR, VkSurfaceCapabilitiesPresentId2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_CAPABILITIES_PRESENT_WAIT_2_KHR, VkSurfaceCapabilitiesPresentWait2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_PRESENT_SCALING_CAPABILITIES_KHR, VkSurfacePresentScalingCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_TIMING_PROPERTIES_EXT, VkSwapchainTimingPropertiesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_FORMAT_PROPERTIES_ARM, VkTensorFormatPropertiesARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TILE_PROPERTIES_QCOM, VkTilePropertiesQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_CAPABILITIES_KHR, VkVideoCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_CAPABILITIES_KHR, VkVideoEncodeCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_INTRA_REFRESH_CAPABILITIES_KHR, VkVideoEncodeIntraRefreshCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_QUALITY_LEVEL_PROPERTIES_KHR, VkVideoEncodeQualityLevelPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_QUANTIZATION_MAP_CAPABILITIES_KHR, VkVideoEncodeQuantizationMapCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_RGB_CONVERSION_CAPABILITIES_VALVE, VkVideoEncodeRgbConversionCapabilitiesVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_FORMAT_PROPERTIES_KHR, VkVideoFormatPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_FORMAT_QUANTIZATION_MAP_PROPERTIES_KHR, VkVideoFormatQuantizationMapPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_4_FEATURES, VkPhysicalDeviceVulkan14Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_4_PROPERTIES, VkPhysicalDeviceVulkan14Properties>,

  // Everything else repack-registered that a driver or app can legally chain.
  // The earlier pass only added feature/property structs, which left the ones
  // that carry *behaviour* still being dropped -- and dropping those is worse
  // than dropping a query, because the call still happens, just without what
  // the app asked for. VkPipelineCreateFlags2CreateInfo is the case that bit:
  // DXVK puts VK_PIPELINE_CREATE_LIBRARY_BIT_KHR there under maintenance5, we
  // dropped it, and the driver then read a pipeline library as a complete
  // pipeline and dereferenced the state pointers it was entitled to assume
  // non-null.
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_BUILD_SIZES_INFO_KHR, VkAccelerationStructureBuildSizesInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CAPTURE_DESCRIPTOR_DATA_INFO_EXT, VkAccelerationStructureCaptureDescriptorDataInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_CREATE_INFO_KHR, VkAccelerationStructureCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_DEVICE_ADDRESS_INFO_KHR, VkAccelerationStructureDeviceAddressInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_MEMORY_REQUIREMENTS_INFO_NV, VkAccelerationStructureMemoryRequirementsInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACCELERATION_STRUCTURE_VERSION_INFO_KHR, VkAccelerationStructureVersionInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACQUIRE_NEXT_IMAGE_INFO_KHR, VkAcquireNextImageInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ACQUIRE_PROFILING_LOCK_INFO_KHR, VkAcquireProfilingLockInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ANTI_LAG_PRESENTATION_INFO_AMD, VkAntiLagPresentationInfoAMD>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_APPLICATION_INFO, VkApplicationInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_DESCRIPTION_2, VkAttachmentDescription2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_FEEDBACK_LOOP_INFO_EXT, VkAttachmentFeedbackLoopInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_ATTACHMENT_REFERENCE_2, VkAttachmentReference2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BEGIN_CUSTOM_RESOLVE_INFO_EXT, VkBeginCustomResolveInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_ACCELERATION_STRUCTURE_MEMORY_INFO_NV, VkBindAccelerationStructureMemoryInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_BUFFER_MEMORY_INFO, VkBindBufferMemoryInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_DATA_GRAPH_PIPELINE_SESSION_MEMORY_INFO_ARM, VkBindDataGraphPipelineSessionMemoryInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_DESCRIPTOR_BUFFER_EMBEDDED_SAMPLERS_INFO_EXT, VkBindDescriptorBufferEmbeddedSamplersInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_DESCRIPTOR_SETS_INFO, VkBindDescriptorSetsInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_IMAGE_MEMORY_INFO, VkBindImageMemoryInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_MEMORY_STATUS, VkBindMemoryStatus>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_TENSOR_MEMORY_INFO_ARM, VkBindTensorMemoryInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BIND_VIDEO_SESSION_MEMORY_INFO_KHR, VkBindVideoSessionMemoryInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BLIT_IMAGE_CUBIC_WEIGHTS_INFO_QCOM, VkBlitImageCubicWeightsInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BLIT_IMAGE_INFO_2, VkBlitImageInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_CAPTURE_DESCRIPTOR_DATA_INFO_EXT, VkBufferCaptureDescriptorDataInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_COPY_2, VkBufferCopy2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, VkBufferCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_DEVICE_ADDRESS_INFO, VkBufferDeviceAddressInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_IMAGE_COPY_2, VkBufferImageCopy2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER, VkBufferMemoryBarrier>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER_2, VkBufferMemoryBarrier2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_MEMORY_REQUIREMENTS_INFO_2, VkBufferMemoryRequirementsInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_USAGE_FLAGS_2_CREATE_INFO, VkBufferUsageFlags2CreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUFFER_VIEW_CREATE_INFO, VkBufferViewCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_BUILD_PARTITIONED_ACCELERATION_STRUCTURE_INFO_NV, VkBuildPartitionedAccelerationStructureInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_KHR, VkCalibratedTimestampInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CLUSTER_ACCELERATION_STRUCTURE_CLUSTERS_BOTTOM_LEVEL_INPUT_NV, VkClusterAccelerationStructureClustersBottomLevelInputNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CLUSTER_ACCELERATION_STRUCTURE_MOVE_OBJECTS_INPUT_NV, VkClusterAccelerationStructureMoveObjectsInputNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CLUSTER_ACCELERATION_STRUCTURE_TRIANGLE_CLUSTER_INPUT_NV, VkClusterAccelerationStructureTriangleClusterInputNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, VkCommandBufferAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, VkCommandBufferBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_INHERITANCE_INFO, VkCommandBufferInheritanceInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_BUFFER_SUBMIT_INFO, VkCommandBufferSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, VkCommandPoolCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMPUTE_OCCUPANCY_PRIORITY_PARAMETERS_NV, VkComputeOccupancyPriorityParametersNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, VkComputePipelineCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_INDIRECT_BUFFER_INFO_NV, VkComputePipelineIndirectBufferInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CONDITIONAL_RENDERING_BEGIN_INFO_EXT, VkConditionalRenderingBeginInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_ACCELERATION_STRUCTURE_INFO_KHR, VkCopyAccelerationStructureInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_BUFFER_INFO_2, VkCopyBufferInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_BUFFER_TO_IMAGE_INFO_2, VkCopyBufferToImageInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_DESCRIPTOR_SET, VkCopyDescriptorSet>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_IMAGE_INFO_2, VkCopyImageInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_IMAGE_TO_BUFFER_INFO_2, VkCopyImageToBufferInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_MEMORY_INDIRECT_INFO_KHR, VkCopyMemoryIndirectInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_MEMORY_TO_IMAGE_INDIRECT_INFO_KHR, VkCopyMemoryToImageIndirectInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_COPY_MICROMAP_INFO_EXT, VkCopyMicromapInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CU_FUNCTION_CREATE_INFO_NVX, VkCuFunctionCreateInfoNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CU_MODULE_TEXTURING_MODE_CREATE_INFO_NVX, VkCuModuleTexturingModeCreateInfoNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_CUSTOM_RESOLVE_CREATE_INFO_EXT, VkCustomResolveCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_BUILTIN_MODEL_CREATE_INFO_QCOM, VkDataGraphPipelineBuiltinModelCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_COMPILER_CONTROL_CREATE_INFO_ARM, VkDataGraphPipelineCompilerControlCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_CONSTANT_TENSOR_SEMI_STRUCTURED_SPARSITY_INFO_ARM, VkDataGraphPipelineConstantTensorSemiStructuredSparsityInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_DISPATCH_INFO_ARM, VkDataGraphPipelineDispatchInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_IDENTIFIER_CREATE_INFO_ARM, VkDataGraphPipelineIdentifierCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_INFO_ARM, VkDataGraphPipelineInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_RESOURCE_INFO_ARM, VkDataGraphPipelineResourceInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_SESSION_BIND_POINT_REQUIREMENT_ARM, VkDataGraphPipelineSessionBindPointRequirementARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_SESSION_BIND_POINT_REQUIREMENTS_INFO_ARM, VkDataGraphPipelineSessionBindPointRequirementsInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_SESSION_CREATE_INFO_ARM, VkDataGraphPipelineSessionCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PIPELINE_SESSION_MEMORY_REQUIREMENTS_INFO_ARM, VkDataGraphPipelineSessionMemoryRequirementsInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DATA_GRAPH_PROCESSING_ENGINE_CREATE_INFO_ARM, VkDataGraphProcessingEngineCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_MARKER_MARKER_INFO_EXT, VkDebugMarkerMarkerInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_MARKER_OBJECT_NAME_INFO_EXT, VkDebugMarkerObjectNameInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEBUG_UTILS_LABEL_EXT, VkDebugUtilsLabelEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEPENDENCY_INFO, VkDependencyInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEPTH_BIAS_INFO_EXT, VkDepthBiasInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_ADDRESS_INFO_EXT, VkDescriptorAddressInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_BUFFER_BINDING_INFO_EXT, VkDescriptorBufferBindingInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_GET_INFO_EXT, VkDescriptorGetInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_GET_TENSOR_INFO_ARM, VkDescriptorGetTensorInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, VkDescriptorPoolCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, VkDescriptorSetAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_BINDING_REFERENCE_VALVE, VkDescriptorSetBindingReferenceVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, VkDescriptorSetLayoutCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_HOST_MAPPING_INFO_VALVE, VkDescriptorSetLayoutHostMappingInfoVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_SUPPORT, VkDescriptorSetLayoutSupport>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DESCRIPTOR_UPDATE_TEMPLATE_CREATE_INFO, VkDescriptorUpdateTemplateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_BUFFER_MEMORY_REQUIREMENTS, VkDeviceBufferMemoryRequirements>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, VkDeviceCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_EVENT_INFO_EXT, VkDeviceEventInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_FAULT_COUNTS_EXT, VkDeviceFaultCountsEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_IMAGE_MEMORY_REQUIREMENTS, VkDeviceImageMemoryRequirements>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_MEMORY_OPAQUE_CAPTURE_ADDRESS_INFO, VkDeviceMemoryOpaqueCaptureAddressInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_MEMORY_REPORT_CALLBACK_DATA_EXT, VkDeviceMemoryReportCallbackDataEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_PIPELINE_BINARY_INTERNAL_CACHE_CONTROL_KHR, VkDevicePipelineBinaryInternalCacheControlKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, VkDeviceQueueCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_QUEUE_GLOBAL_PRIORITY_CREATE_INFO, VkDeviceQueueGlobalPriorityCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2, VkDeviceQueueInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DEVICE_QUEUE_SHADER_CORE_CONTROL_CREATE_INFO_ARM, VkDeviceQueueShaderCoreControlCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPATCH_TILE_INFO_QCOM, VkDispatchTileInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_EVENT_INFO_EXT, VkDisplayEventInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_MODE_CREATE_INFO_KHR, VkDisplayModeCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_PLANE_INFO_2_KHR, VkDisplayPlaneInfo2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_POWER_INFO_EXT, VkDisplayPowerInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_SURFACE_CREATE_INFO_KHR, VkDisplaySurfaceCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_DISPLAY_SURFACE_STEREO_CREATE_INFO_NV, VkDisplaySurfaceStereoCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EVENT_CREATE_INFO, VkEventCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_COMPUTE_QUEUE_CREATE_INFO_NV, VkExternalComputeQueueCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_COMPUTE_QUEUE_DATA_PARAMS_NV, VkExternalComputeQueueDataParamsNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_COMPUTE_QUEUE_DEVICE_CREATE_INFO_NV, VkExternalComputeQueueDeviceCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_TENSOR_CREATE_INFO_ARM, VkExternalMemoryTensorCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, VkFenceCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FENCE_GET_FD_INFO_KHR, VkFenceGetFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FRAME_BOUNDARY_TENSORS_ARM, VkFrameBoundaryTensorsARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FRAMEBUFFER_ATTACHMENT_IMAGE_INFO, VkFramebufferAttachmentImageInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO, VkFramebufferCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_FRAMEBUFFER_MIXED_SAMPLES_COMBINATION_NV, VkFramebufferMixedSamplesCombinationNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GENERATED_COMMANDS_INFO_EXT, VkGeneratedCommandsInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GENERATED_COMMANDS_MEMORY_REQUIREMENTS_INFO_EXT, VkGeneratedCommandsMemoryRequirementsInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GENERATED_COMMANDS_MEMORY_REQUIREMENTS_INFO_NV, VkGeneratedCommandsMemoryRequirementsInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GENERATED_COMMANDS_PIPELINE_INFO_EXT, VkGeneratedCommandsPipelineInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GENERATED_COMMANDS_SHADER_INFO_EXT, VkGeneratedCommandsShaderInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GEOMETRY_NV, VkGeometryNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GEOMETRY_TRIANGLES_NV, VkGeometryTrianglesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO, VkGraphicsPipelineCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_HEADLESS_SURFACE_CREATE_INFO_EXT, VkHeadlessSurfaceCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_HOST_IMAGE_COPY_DEVICE_PERFORMANCE_QUERY, VkHostImageCopyDevicePerformanceQuery>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_HOST_IMAGE_LAYOUT_TRANSITION_INFO, VkHostImageLayoutTransitionInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_ALIGNMENT_CONTROL_CREATE_INFO_MESA, VkImageAlignmentControlCreateInfoMESA>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_BLIT_2, VkImageBlit2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_CAPTURE_DESCRIPTOR_DATA_INFO_EXT, VkImageCaptureDescriptorDataInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_COPY_2, VkImageCopy2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO, VkImageCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, VkImageMemoryBarrier>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER_2, VkImageMemoryBarrier2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_MEMORY_REQUIREMENTS_INFO_2, VkImageMemoryRequirementsInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_RESOLVE_2, VkImageResolve2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_SPARSE_MEMORY_REQUIREMENTS_INFO_2, VkImageSparseMemoryRequirementsInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_SUBRESOURCE_2, VkImageSubresource2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_CAPTURE_DESCRIPTOR_DATA_INFO_EXT, VkImageViewCaptureDescriptorDataInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO, VkImageViewCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMAGE_VIEW_HANDLE_INFO_NVX, VkImageViewHandleInfoNVX>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMPORT_FENCE_FD_INFO_KHR, VkImportFenceFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR, VkImportSemaphoreFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_INDIRECT_COMMANDS_LAYOUT_TOKEN_NV, VkIndirectCommandsLayoutTokenNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_INDIRECT_EXECUTION_SET_PIPELINE_INFO_EXT, VkIndirectExecutionSetPipelineInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_INDIRECT_EXECUTION_SET_SHADER_LAYOUT_INFO_EXT, VkIndirectExecutionSetShaderLayoutInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, VkInstanceCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_LATENCY_SLEEP_INFO_NV, VkLatencySleepInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_LATENCY_SLEEP_MODE_INFO_NV, VkLatencySleepModeInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_LATENCY_SUBMISSION_PRESENT_ID_NV, VkLatencySubmissionPresentIdNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_LATENCY_TIMINGS_FRAME_REPORT_NV, VkLatencyTimingsFrameReportNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, VkMappedMemoryRange>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, VkMemoryAllocateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_BARRIER, VkMemoryBarrier>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_BARRIER_ACCESS_FLAGS_3_KHR, VkMemoryBarrierAccessFlags3KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO_TENSOR_ARM, VkMemoryDedicatedAllocateInfoTensorARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR, VkMemoryGetFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_GET_REMOTE_ADDRESS_INFO_NV, VkMemoryGetRemoteAddressInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_MAP_INFO, VkMemoryMapInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_REQUIREMENTS_2, VkMemoryRequirements2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_TO_IMAGE_COPY, VkMemoryToImageCopy>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MEMORY_UNMAP_INFO, VkMemoryUnmapInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MICROMAP_BUILD_SIZES_INFO_EXT, VkMicromapBuildSizesInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MICROMAP_CREATE_INFO_EXT, VkMicromapCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_MICROMAP_VERSION_INFO_EXT, VkMicromapVersionInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_OPTICAL_FLOW_EXECUTE_INFO_NV, VkOpticalFlowExecuteInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_OPTICAL_FLOW_SESSION_CREATE_INFO_NV, VkOpticalFlowSessionCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_OUT_OF_BAND_QUEUE_TYPE_INFO_NV, VkOutOfBandQueueTypeInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PARTITIONED_ACCELERATION_STRUCTURE_FLAGS_NV, VkPartitionedAccelerationStructureFlagsNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PARTITIONED_ACCELERATION_STRUCTURE_INSTANCES_INPUT_NV, VkPartitionedAccelerationStructureInstancesInputNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PAST_PRESENTATION_TIMING_INFO_EXT, VkPastPresentationTimingInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PER_TILE_BEGIN_INFO_QCOM, VkPerTileBeginInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PER_TILE_END_INFO_QCOM, VkPerTileEndInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_CONFIGURATION_ACQUIRE_INFO_INTEL, VkPerformanceConfigurationAcquireInfoINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_COUNTER_ARM, VkPerformanceCounterARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_COUNTER_DESCRIPTION_ARM, VkPerformanceCounterDescriptionARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_COUNTER_DESCRIPTION_KHR, VkPerformanceCounterDescriptionKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_COUNTER_KHR, VkPerformanceCounterKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_MARKER_INFO_INTEL, VkPerformanceMarkerInfoINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_OVERRIDE_INFO_INTEL, VkPerformanceOverrideInfoINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PERFORMANCE_STREAM_MARKER_INFO_INTEL, VkPerformanceStreamMarkerInfoINTEL>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_BUFFER_INFO, VkPhysicalDeviceExternalBufferInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_FENCE_INFO, VkPhysicalDeviceExternalFenceInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_SEMAPHORE_INFO, VkPhysicalDeviceExternalSemaphoreInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FRAGMENT_SHADING_RATE_KHR, VkPhysicalDeviceFragmentShadingRateKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_IMAGE_FORMAT_INFO_2, VkPhysicalDeviceImageFormatInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_QUEUE_FAMILY_DATA_GRAPH_PROCESSING_ENGINE_INFO_ARM, VkPhysicalDeviceQueueFamilyDataGraphProcessingEngineInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SPARSE_IMAGE_FORMAT_INFO_2, VkPhysicalDeviceSparseImageFormatInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SURFACE_INFO_2_KHR, VkPhysicalDeviceSurfaceInfo2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_FORMAT_INFO_KHR, VkPhysicalDeviceVideoFormatInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_BINARY_DATA_INFO_KHR, VkPipelineBinaryDataInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_BINARY_INFO_KHR, VkPipelineBinaryInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_BINARY_KEY_KHR, VkPipelineBinaryKeyKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO, VkPipelineCacheCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO, VkPipelineColorBlendStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_CREATE_FLAGS_2_CREATE_INFO, VkPipelineCreateFlags2CreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_CREATE_INFO_KHR, VkPipelineCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO, VkPipelineDepthStencilStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO, VkPipelineDynamicStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_INFO_KHR, VkPipelineExecutableInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_STATISTIC_KHR, VkPipelineExecutableStatisticKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_FRAGMENT_DENSITY_MAP_LAYERED_CREATE_INFO_VALVE, VkPipelineFragmentDensityMapLayeredCreateInfoVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_INDIRECT_DEVICE_ADDRESS_INFO_NV, VkPipelineIndirectDeviceAddressInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_INFO_KHR, VkPipelineInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO, VkPipelineInputAssemblyStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, VkPipelineLayoutCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO, VkPipelineMultisampleStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_LINE_STATE_CREATE_INFO, VkPipelineRasterizationLineStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO, VkPipelineRasterizationStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_ROBUSTNESS_CREATE_INFO, VkPipelineRobustnessCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, VkPipelineShaderStageCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_TESSELLATION_STATE_CREATE_INFO, VkPipelineTessellationStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO, VkPipelineVertexInputStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_DEPTH_CLAMP_CONTROL_CREATE_INFO_EXT, VkPipelineViewportDepthClampControlCreateInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO, VkPipelineViewportStateCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_ID_2_KHR, VkPresentId2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_INFO_KHR, VkPresentInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_TIMING_INFO_EXT, VkPresentTimingInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRESENT_WAIT_2_INFO_KHR, VkPresentWait2InfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PRIVATE_DATA_SLOT_CREATE_INFO, VkPrivateDataSlotCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO, VkQueryPoolCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_QUERY_POOL_VIDEO_ENCODE_FEEDBACK_CREATE_INFO_KHR, VkQueryPoolVideoEncodeFeedbackCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RAY_TRACING_PIPELINE_CLUSTER_ACCELERATION_STRUCTURE_CREATE_INFO_NV, VkRayTracingPipelineClusterAccelerationStructureCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RAY_TRACING_PIPELINE_INTERFACE_CREATE_INFO_KHR, VkRayTracingPipelineInterfaceCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RAY_TRACING_SHADER_GROUP_CREATE_INFO_NV, VkRayTracingShaderGroupCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RELEASE_CAPTURED_PIPELINE_DATA_INFO_KHR, VkReleaseCapturedPipelineDataInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RELEASE_SWAPCHAIN_IMAGES_INFO_KHR, VkReleaseSwapchainImagesInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO, VkRenderPassBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO, VkRenderPassCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO_2, VkRenderPassCreateInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_FRAGMENT_DENSITY_MAP_OFFSET_END_INFO_EXT, VkRenderPassFragmentDensityMapOffsetEndInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_PERFORMANCE_COUNTERS_BY_REGION_BEGIN_INFO_ARM, VkRenderPassPerformanceCountersByRegionBeginInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_STRIPE_INFO_ARM, VkRenderPassStripeInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDER_PASS_TILE_SHADING_CREATE_INFO_QCOM, VkRenderPassTileShadingCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_AREA_INFO, VkRenderingAreaInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_FLAGS_INFO_KHR, VkRenderingAttachmentFlagsInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_INFO, VkRenderingAttachmentInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_ATTACHMENT_LOCATION_INFO, VkRenderingAttachmentLocationInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_END_INFO_KHR, VkRenderingEndInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_INFO, VkRenderingInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RENDERING_INPUT_ATTACHMENT_INDEX_INFO, VkRenderingInputAttachmentIndexInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RESOLVE_IMAGE_INFO_2, VkResolveImageInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_RESOLVE_IMAGE_MODE_INFO_KHR, VkResolveImageModeInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_BLOCK_MATCH_WINDOW_CREATE_INFO_QCOM, VkSamplerBlockMatchWindowCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_CAPTURE_DESCRIPTOR_DATA_INFO_EXT, VkSamplerCaptureDescriptorDataInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO, VkSamplerCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_CUBIC_WEIGHTS_CREATE_INFO_QCOM, VkSamplerCubicWeightsCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_YCBCR_CONVERSION_CREATE_INFO, VkSamplerYcbcrConversionCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SAMPLER_YCBCR_CONVERSION_YCBCR_DEGAMMA_CREATE_INFO_QCOM, VkSamplerYcbcrConversionYcbcrDegammaCreateInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO, VkSemaphoreCreateInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_GET_FD_INFO_KHR, VkSemaphoreGetFdInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_SIGNAL_INFO, VkSemaphoreSignalInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO, VkSemaphoreSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SEMAPHORE_WAIT_INFO, VkSemaphoreWaitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SET_DESCRIPTOR_BUFFER_OFFSETS_INFO_EXT, VkSetDescriptorBufferOffsetsInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SET_LATENCY_MARKER_INFO_NV, VkSetLatencyMarkerInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SHADER_MODULE_IDENTIFIER_EXT, VkShaderModuleIdentifierEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SPARSE_IMAGE_MEMORY_REQUIREMENTS_2, VkSparseImageMemoryRequirements2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBMIT_INFO, VkSubmitInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBMIT_INFO_2, VkSubmitInfo2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_BEGIN_INFO, VkSubpassBeginInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_DEPENDENCY_2, VkSubpassDependency2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_DESCRIPTION_2, VkSubpassDescription2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBPASS_END_INFO, VkSubpassEndInfo>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBRESOURCE_HOST_MEMCPY_SIZE, VkSubresourceHostMemcpySize>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SUBRESOURCE_LAYOUT_2, VkSubresourceLayout2>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_FORMAT_2_KHR, VkSurfaceFormat2KHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_PRESENT_MODE_COMPATIBILITY_KHR, VkSurfacePresentModeCompatibilityKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SURFACE_PRESENT_MODE_KHR, VkSurfacePresentModeKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_CALIBRATED_TIMESTAMP_INFO_EXT, VkSwapchainCalibratedTimestampInfoEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR, VkSwapchainCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_LATENCY_CREATE_INFO_NV, VkSwapchainLatencyCreateInfoNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_FENCE_INFO_KHR, VkSwapchainPresentFenceInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_MODE_INFO_KHR, VkSwapchainPresentModeInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_MODES_CREATE_INFO_KHR, VkSwapchainPresentModesCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_SWAPCHAIN_PRESENT_SCALING_CREATE_INFO_KHR, VkSwapchainPresentScalingCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_CAPTURE_DESCRIPTOR_DATA_INFO_ARM, VkTensorCaptureDescriptorDataInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_MEMORY_BARRIER_ARM, VkTensorMemoryBarrierARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_MEMORY_REQUIREMENTS_INFO_ARM, VkTensorMemoryRequirementsInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_VIEW_CAPTURE_DESCRIPTOR_DATA_INFO_ARM, VkTensorViewCaptureDescriptorDataInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TENSOR_VIEW_CREATE_INFO_ARM, VkTensorViewCreateInfoARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TILE_MEMORY_BIND_INFO_QCOM, VkTileMemoryBindInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TILE_MEMORY_REQUIREMENTS_QCOM, VkTileMemoryRequirementsQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_TILE_MEMORY_SIZE_INFO_QCOM, VkTileMemorySizeInfoQCOM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VERTEX_INPUT_ATTRIBUTE_DESCRIPTION_2_EXT, VkVertexInputAttributeDescription2EXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VERTEX_INPUT_BINDING_DESCRIPTION_2_EXT, VkVertexInputBindingDescription2EXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_CODING_CONTROL_INFO_KHR, VkVideoCodingControlInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_INTRA_REFRESH_INFO_KHR, VkVideoEncodeIntraRefreshInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_PROFILE_RGB_CONVERSION_INFO_VALVE, VkVideoEncodeProfileRgbConversionInfoVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_QUALITY_LEVEL_INFO_KHR, VkVideoEncodeQualityLevelInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_QUANTIZATION_MAP_INFO_KHR, VkVideoEncodeQuantizationMapInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_QUANTIZATION_MAP_SESSION_PARAMETERS_CREATE_INFO_KHR, VkVideoEncodeQuantizationMapSessionParametersCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_RATE_CONTROL_LAYER_INFO_KHR, VkVideoEncodeRateControlLayerInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_SESSION_INTRA_REFRESH_CREATE_INFO_KHR, VkVideoEncodeSessionIntraRefreshCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_SESSION_PARAMETERS_FEEDBACK_INFO_KHR, VkVideoEncodeSessionParametersFeedbackInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_SESSION_PARAMETERS_GET_INFO_KHR, VkVideoEncodeSessionParametersGetInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_SESSION_RGB_CONVERSION_CREATE_INFO_VALVE, VkVideoEncodeSessionRgbConversionCreateInfoVALVE>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_USAGE_INFO_KHR, VkVideoEncodeUsageInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_END_CODING_INFO_KHR, VkVideoEndCodingInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_INLINE_QUERY_INFO_KHR, VkVideoInlineQueryInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_PICTURE_RESOURCE_INFO_KHR, VkVideoPictureResourceInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_REFERENCE_INTRA_REFRESH_INFO_KHR, VkVideoReferenceIntraRefreshInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_SESSION_MEMORY_REQUIREMENTS_KHR, VkVideoSessionMemoryRequirementsKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_SESSION_PARAMETERS_CREATE_INFO_KHR, VkVideoSessionParametersCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_SESSION_PARAMETERS_UPDATE_INFO_KHR, VkVideoSessionParametersUpdateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, VkWriteDescriptorSet>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_PARTITIONED_ACCELERATION_STRUCTURE_NV, VkWriteDescriptorSetPartitionedAccelerationStructureNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET_TENSOR_ARM, VkWriteDescriptorSetTensorARM>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_INDIRECT_EXECUTION_SET_PIPELINE_EXT, VkWriteIndirectExecutionSetPipelineEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_WRITE_INDIRECT_EXECUTION_SET_SHADER_EXT, VkWriteIndirectExecutionSetShaderEXT>,

  // Last of the chainable types. These were missed by the name-canonicalisation
  // pass because the enumerant groups digits differently from the struct name
  // (VkPhysicalDeviceIndexTypeUint8Features vs ..._INDEX_TYPE_UINT8_FEATURES),
  // so they are matched ignoring underscores instead, and only where exactly one
  // enumerant fits. IndexTypeUint8 is the one that mattered: DXVK asks for it,
  // and a dropped feature struct reads back as "unsupported".
  converters<VkStructureType::VK_STRUCTURE_TYPE_GEOMETRY_AABB_NV, VkGeometryAABBNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INDEX_TYPE_UINT8_FEATURES, VkPhysicalDeviceIndexTypeUint8Features>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_ATOMIC_FLOAT16_VECTOR_FEATURES_NV, VkPhysicalDeviceShaderAtomicFloat16VectorFeaturesNV>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_BFLOAT16_FEATURES_KHR, VkPhysicalDeviceShaderBfloat16FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SHADER_FLOAT8_FEATURES_EXT, VkPhysicalDeviceShaderFloat8FeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TEXTURE_COMPRESSION_ASTC_3D_FEATURES_EXT, VkPhysicalDeviceTextureCompressionASTC3DFeaturesEXT>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_DECODE_VP9_FEATURES_KHR, VkPhysicalDeviceVideoDecodeVP9FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VIDEO_ENCODE_AV1_FEATURES_KHR, VkPhysicalDeviceVideoEncodeAV1FeaturesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_AV1_CAPABILITIES_KHR, VkVideoDecodeAV1CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_AV1_PROFILE_INFO_KHR, VkVideoDecodeAV1ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_VP9_CAPABILITIES_KHR, VkVideoDecodeVP9CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_DECODE_VP9_PROFILE_INFO_KHR, VkVideoDecodeVP9ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_CAPABILITIES_KHR, VkVideoEncodeAV1CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_GOP_REMAINING_FRAME_INFO_KHR, VkVideoEncodeAV1GopRemainingFrameInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_PROFILE_INFO_KHR, VkVideoEncodeAV1ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_QUALITY_LEVEL_PROPERTIES_KHR, VkVideoEncodeAV1QualityLevelPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_QUANTIZATION_MAP_CAPABILITIES_KHR, VkVideoEncodeAV1QuantizationMapCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_RATE_CONTROL_INFO_KHR, VkVideoEncodeAV1RateControlInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_RATE_CONTROL_LAYER_INFO_KHR, VkVideoEncodeAV1RateControlLayerInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_AV1_SESSION_CREATE_INFO_KHR, VkVideoEncodeAV1SessionCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_CAPABILITIES_KHR, VkVideoEncodeH264CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_DPB_SLOT_INFO_KHR, VkVideoEncodeH264DpbSlotInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_GOP_REMAINING_FRAME_INFO_KHR, VkVideoEncodeH264GopRemainingFrameInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_PROFILE_INFO_KHR, VkVideoEncodeH264ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_QUALITY_LEVEL_PROPERTIES_KHR, VkVideoEncodeH264QualityLevelPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_QUANTIZATION_MAP_CAPABILITIES_KHR, VkVideoEncodeH264QuantizationMapCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_RATE_CONTROL_INFO_KHR, VkVideoEncodeH264RateControlInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_RATE_CONTROL_LAYER_INFO_KHR, VkVideoEncodeH264RateControlLayerInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_SESSION_CREATE_INFO_KHR, VkVideoEncodeH264SessionCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_SESSION_PARAMETERS_FEEDBACK_INFO_KHR, VkVideoEncodeH264SessionParametersFeedbackInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H264_SESSION_PARAMETERS_GET_INFO_KHR, VkVideoEncodeH264SessionParametersGetInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_CAPABILITIES_KHR, VkVideoEncodeH265CapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_DPB_SLOT_INFO_KHR, VkVideoEncodeH265DpbSlotInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_GOP_REMAINING_FRAME_INFO_KHR, VkVideoEncodeH265GopRemainingFrameInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_PROFILE_INFO_KHR, VkVideoEncodeH265ProfileInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_QUALITY_LEVEL_PROPERTIES_KHR, VkVideoEncodeH265QualityLevelPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_QUANTIZATION_MAP_CAPABILITIES_KHR, VkVideoEncodeH265QuantizationMapCapabilitiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_RATE_CONTROL_INFO_KHR, VkVideoEncodeH265RateControlInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_RATE_CONTROL_LAYER_INFO_KHR, VkVideoEncodeH265RateControlLayerInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_SESSION_CREATE_INFO_KHR, VkVideoEncodeH265SessionCreateInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_SESSION_PARAMETERS_FEEDBACK_INFO_KHR, VkVideoEncodeH265SessionParametersFeedbackInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_ENCODE_H265_SESSION_PARAMETERS_GET_INFO_KHR, VkVideoEncodeH265SessionParametersGetInfoKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_FORMAT_AV1_QUANTIZATION_MAP_PROPERTIES_KHR, VkVideoFormatAV1QuantizationMapPropertiesKHR>,
  converters<VkStructureType::VK_STRUCTURE_TYPE_VIDEO_FORMAT_H265_QUANTIZATION_MAP_PROPERTIES_KHR, VkVideoFormatH265QuantizationMapPropertiesKHR>,
};

// Walks a guest pNext chain to the first link next_handlers knows how to
// repack, skipping (and reporting, once per sType) any link it does not.
//
// Aborting here instead — which is what this used to do — turns every Vulkan
// extension newer than this table into a hard guest crash. That is not
// hypothetical: DXVK 3.0.2 on Mesa chains
// VkPhysicalDeviceShaderUntypedPointersFeaturesKHR into its
// vkGetPhysicalDeviceFeatures2 query, the abort fired inside the guest thunk,
// and wine turned it into an unwind through a smashed 32-bit stack frame —
// which is how Dex-Windows ended up branching to 0x0D000000 (2026-08-08).
//
// Dropping the link is the same thing a driver without that extension does:
// the host never sees the struct, so it never writes it, and the guest reads
// back whatever it initialized (zeroes, for a features query) and concludes
// the feature is unsupported. For an input chain we do lose the request, hence
// the warning naming the sType so it can be given a real converter.
//
// Both directions must skip by the same rule or the guest and host chains stop
// corresponding, so entry and reverse share this function.
static const guest_layout<VkBaseOutStructure>* find_repackable_link(const guest_layout<VkBaseOutStructure>* link) {
  static std::mutex ReportedMutex;
  static std::unordered_set<uint32_t> Reported;

  while (link) {
    const auto sType = static_cast<VkStructureType>(link->data.sType.data);
    if (next_handlers.contains(sType)) {
      return link;
    }
    {
      std::lock_guard lk {ReportedMutex};
      if (Reported.insert(link->data.sType.data).second) {
        fprintf(stderr, "WARNING: Unrecognized VkStructureType %u in a pNext chain; dropping it. Add it to next_handlers to repack it.\n",
                link->data.sType.data);
      }
    }
    link = reinterpret_cast<const guest_layout<VkBaseOutStructure>*>(link->data.pNext.get_pointer());
  }
  return nullptr;
}

static void default_fex_custom_repack_entry(VkBaseOutStructure& into, const guest_layout<VkBaseOutStructure>* from) {
  auto typed_source = find_repackable_link(reinterpret_cast<const guest_layout<VkBaseOutStructure>*>(from->data.pNext.get_pointer()));
  if (!typed_source) {
    into.pNext = nullptr;
    return;
  }

  auto next_handler = next_handlers.find(static_cast<VkStructureType>(typed_source->data.sType.data));
  into.pNext = next_handler->second.first(typed_source);
}

template<typename T>
void default_fex_custom_repack_entry(host_layout<T>& into, const guest_layout<T>& from) {
  default_fex_custom_repack_entry(*(VkBaseOutStructure*)&into.data, reinterpret_cast<const guest_layout<VkBaseOutStructure>*>(&from));
}

static void default_fex_custom_repack_reverse(guest_layout<VkBaseOutStructure>& into, const VkBaseOutStructure* from) {
  auto pNextHost = from->pNext;
  if (!pNextHost) {
    return;
  }

  // Same skip rule as the entry path, so this pairs with whichever guest link
  // actually got repacked into pNextHost.
  auto guest_link = find_repackable_link(reinterpret_cast<const guest_layout<VkBaseOutStructure>*>(into.data.pNext.get_pointer()));
  if (!guest_link) {
    free(pNextHost);
    return;
  }

  auto next_handler = next_handlers.find(static_cast<VkStructureType>(guest_link->data.sType.data));
  next_handler->second.second((void*)const_cast<guest_layout<VkBaseOutStructure>*>(guest_link), from->pNext);

  free(pNextHost);
}

// Default repacking functions that only traverses and repacks the pNext chain.
// If other members need to be repacked, use VULKAN_NONDEFAULT_CUSTOM_REPACK instead
#define VULKAN_DEFAULT_CUSTOM_REPACK(name)                                                             \
  void fex_custom_repack_entry(host_layout<name>& into, const guest_layout<name>& from) {              \
    default_fex_custom_repack_entry(reinterpret_cast<VkBaseOutStructure&>(into.data),                  \
                                    &reinterpret_cast<const guest_layout<VkBaseOutStructure>&>(from)); \
  }                                                                                                    \
                                                                                                       \
  bool fex_custom_repack_exit(guest_layout<name>& into, const host_layout<name>& from) {               \
    auto prev_next = into.data.pNext;                                                                  \
    default_fex_custom_repack_reverse(*reinterpret_cast<guest_layout<VkBaseOutStructure>*>(&into),     \
                                      &reinterpret_cast<const VkBaseOutStructure&>(from.data));        \
    into = to_guest(from);                                                                             \
    into.data.pNext = prev_next;                                                                       \
    return true;                                                                                       \
  }

// Intentionally left empty. This macro doesn't automate anything, but it
// helps ensure we don't forget any Vulkan types in the list. The actual
// repacking functions are defined manually later
#define VULKAN_NONDEFAULT_CUSTOM_REPACK(name)

// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureBuildGeometryInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureBuildSizesInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureCaptureDescriptorDataInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureDeviceAddressInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureGeometryAabbsDataKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureGeometryInstancesDataKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureGeometryKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureGeometryMotionTrianglesDataNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureGeometryTrianglesDataKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureMemoryRequirementsInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureMotionInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureTrianglesOpacityMicromapEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAccelerationStructureVersionInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAcquireNextImageInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAcquireProfilingLockInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAmigoProfilingSubmitInfoSEC)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkAntiLagDataAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAntiLagPresentationInfoAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkApplicationInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentDescription2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentDescriptionStencilLayout)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentFeedbackLoopInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentReference2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentReferenceStencilLayout)
VULKAN_DEFAULT_CUSTOM_REPACK(VkAttachmentSampleCountInfoAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBeginCustomResolveInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindAccelerationStructureMemoryInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindBufferMemoryDeviceGroupInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindBufferMemoryInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindDataGraphPipelineSessionMemoryInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindDescriptorBufferEmbeddedSamplersInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindDescriptorSetsInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindImageMemoryDeviceGroupInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindImageMemoryInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindImageMemorySwapchainInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindImagePlaneMemoryInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindMemoryStatus)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkBindSparseInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindTensorMemoryInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBindVideoSessionMemoryInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBlitImageCubicWeightsInfoQCOM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkBlitImageInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferCaptureDescriptorDataInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferCopy2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferDeviceAddressCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferDeviceAddressInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferImageCopy2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferMemoryBarrier)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferMemoryBarrier2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferMemoryRequirementsInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferOpaqueCaptureAddressCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferUsageFlags2CreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBufferViewCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkBuildPartitionedAccelerationStructureInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCalibratedTimestampInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCheckpointData2NV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCheckpointDataNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkClusterAccelerationStructureClustersBottomLevelInputNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkClusterAccelerationStructureMoveObjectsInputNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkClusterAccelerationStructureTriangleClusterInputNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferAllocateInfo)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkCommandBufferBeginInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferInheritanceConditionalRenderingInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferInheritanceInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferInheritanceRenderingInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferInheritanceRenderPassTransformInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferInheritanceViewportScissorInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandBufferSubmitInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCommandPoolCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkComputeOccupancyPriorityParametersNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkComputePipelineCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkComputePipelineIndirectBufferInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkConditionalRenderingBeginInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCooperativeMatrixFlexibleDimensionsPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCooperativeMatrixPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCooperativeMatrixPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCooperativeVectorPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyAccelerationStructureInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyAccelerationStructureToMemoryInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyBufferInfo2)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyBufferToImageInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyCommandTransformInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyDescriptorSet)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyImageInfo2)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyImageToBufferInfo2)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyImageToImageInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyImageToMemoryInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMemoryIndirectInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMemoryToAccelerationStructureInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMemoryToImageIndirectInfoKHR)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkCopyMemoryToImageInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMemoryToMicromapInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMicromapInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyMicromapToMemoryInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCopyTensorInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCuFunctionCreateInfoNVX)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCuLaunchInfoNVX)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkCuModuleCreateInfoNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCuModuleTexturingModeCreateInfoNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkCustomResolveCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineBuiltinModelCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineCompilerControlCreateInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineConstantARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineConstantTensorSemiStructuredSparsityInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineDispatchInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineIdentifierCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelinePropertyQueryResultARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineResourceInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineSessionBindPointRequirementARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineSessionBindPointRequirementsInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineSessionCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineSessionMemoryRequirementsInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphPipelineShaderModuleCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDataGraphProcessingEngineCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugMarkerMarkerInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugMarkerObjectNameInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugMarkerObjectTagInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugReportCallbackCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugUtilsLabelEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugUtilsMessengerCallbackDataEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugUtilsMessengerCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugUtilsObjectNameInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDebugUtilsObjectTagInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDecompressMemoryInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDedicatedAllocationBufferCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDedicatedAllocationImageCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDedicatedAllocationMemoryAllocateInfoNV)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkDependencyInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDepthBiasInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDepthBiasRepresentationInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorAddressInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorBufferBindingInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorBufferBindingPushDescriptorBufferHandleEXT)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkDescriptorGetInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorGetTensorInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorPoolCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorPoolInlineUniformBlockCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetBindingReferenceVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetLayoutBindingFlagsCreateInfo)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkDescriptorSetLayoutCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetLayoutHostMappingInfoVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetLayoutSupport)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetVariableDescriptorCountAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDescriptorSetVariableDescriptorCountLayoutSupport)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkDescriptorUpdateTemplateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceAddressBindingCallbackDataEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceBufferMemoryRequirements)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkDeviceCreateInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceDeviceMemoryReportCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceDiagnosticsConfigCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceEventInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceFaultCountsEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceFaultInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupBindSparseInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupCommandBufferBeginInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupDeviceCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupPresentCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupPresentInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupRenderPassBeginInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupSubmitInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceGroupSwapchainCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceImageMemoryRequirements)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceImageSubresourceInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceMemoryOpaqueCaptureAddressInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceMemoryOverallocationCreateInfoAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceMemoryReportCallbackDataEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDevicePipelineBinaryInternalCacheControlKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDevicePrivateDataCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceQueueCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceQueueGlobalPriorityCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceQueueInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceQueueShaderCoreControlCreateInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDeviceTensorMemoryRequirementsARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDirectDriverLoadingInfoLUNARG)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDirectDriverLoadingListLUNARG)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDispatchTileInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayEventInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayModeCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayModeProperties2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayModeStereoPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayNativeHdrSurfaceCapabilitiesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayPlaneCapabilities2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayPlaneInfo2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayPlaneProperties2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayPowerInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayPresentInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplayProperties2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplaySurfaceCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkDisplaySurfaceStereoCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDrmFormatModifierPropertiesList2EXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkDrmFormatModifierPropertiesListEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkEventCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExportFenceCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExportMemoryAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExportMemoryAllocateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExportSemaphoreCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalBufferProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalComputeQueueCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalComputeQueueDataParamsNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalComputeQueueDeviceCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalFenceProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalImageFormatProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalMemoryAcquireUnmodifiedEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalMemoryBufferCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalMemoryImageCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalMemoryImageCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalMemoryTensorCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalSemaphoreProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkExternalTensorPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFenceCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFenceGetFdInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFilterCubicImageViewImageFormatPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFormatProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFormatProperties3)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkFragmentShadingRateAttachmentInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkFrameBoundaryEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFrameBoundaryTensorsARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFramebufferAttachmentImageInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkFramebufferAttachmentsCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFramebufferCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkFramebufferMixedSamplesCombinationNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsMemoryRequirementsInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsMemoryRequirementsInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsPipelineInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeneratedCommandsShaderInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeometryAABBNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeometryNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGeometryTrianglesNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkGetLatencyMarkerInfoNV)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkGraphicsPipelineCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkGraphicsPipelineLibraryCreateInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkGraphicsPipelineShaderGroupsCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkGraphicsShaderGroupCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkHdrVividDynamicMetadataHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkHeadlessSurfaceCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkHostImageCopyDevicePerformanceQuery)
VULKAN_DEFAULT_CUSTOM_REPACK(VkHostImageLayoutTransitionInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageAlignmentControlCreateInfoMESA)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageBlit2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageCaptureDescriptorDataInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageCompressionControlEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageCompressionPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageCopy2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageCreateInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkImageDrmFormatModifierExplicitCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageDrmFormatModifierListCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageDrmFormatModifierPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageFormatListCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageFormatProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageMemoryBarrier)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageMemoryBarrier2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageMemoryRequirementsInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImagePlaneMemoryRequirementsInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageResolve2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageSparseMemoryRequirementsInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageStencilUsageCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageSubresource2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageSwapchainCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkImageToMemoryCopyEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewAddressPropertiesNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewASTCDecodeModeEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewCaptureDescriptorDataInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewHandleInfoNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewMinLodCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewSampleWeightCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewSlicedCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImageViewUsageCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImportFenceFdInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImportMemoryFdInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkImportMemoryHostPointerInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkImportSemaphoreFdInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkIndirectCommandsLayoutCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkIndirectCommandsLayoutTokenNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkIndirectExecutionSetPipelineInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkIndirectExecutionSetShaderInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkIndirectExecutionSetShaderLayoutInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkInitializePerformanceApiInfoINTEL)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkInstanceCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkLatencySleepInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkLatencySleepModeInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkLatencySubmissionPresentIdNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkLatencySurfaceCapabilitiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkLatencyTimingsFrameReportNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkLayerSettingsCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMappedMemoryRange)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryAllocateFlagsInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryBarrier)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryBarrier2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryBarrierAccessFlags3KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryDedicatedAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryDedicatedAllocateInfoTensorARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryDedicatedRequirements)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryFdPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryGetFdInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryGetRemoteAddressInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryHostPointerPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryMapInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryMapPlacedInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryOpaqueCaptureAddressAllocateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryPriorityAllocateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryRequirements2)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkMemoryToImageCopy)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMemoryUnmapInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkMicromapBuildInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMicromapBuildSizesInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMicromapCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMicromapVersionInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMultisampledRenderToSingleSampledInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMultisamplePropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMultiviewPerViewAttributesInfoNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkMultiviewPerViewRenderAreasRenderPassBeginInfoQCOM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkMutableDescriptorTypeCreateInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkOpaqueCaptureDescriptorDataCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkOpticalFlowExecuteInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkOpticalFlowImageFormatInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkOpticalFlowImageFormatPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkOpticalFlowSessionCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkOpticalFlowSessionCreatePrivateDataInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkOutOfBandQueueTypeInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPartitionedAccelerationStructureFlagsNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPartitionedAccelerationStructureInstancesInputNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPastPresentationTimingEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPastPresentationTimingInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPastPresentationTimingPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceConfigurationAcquireInfoINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceCounterARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceCounterDescriptionARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceCounterDescriptionKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceCounterKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceMarkerInfoINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceOverrideInfoINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceQuerySubmitInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerformanceStreamMarkerInfoINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerTileBeginInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPerTileEndInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevice16BitStorageFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevice4444FormatsFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevice8BitStorageFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAccelerationStructureFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAccelerationStructurePropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAddressBindingReportFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAmigoProfilingFeaturesSEC)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAntiLagFeaturesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceASTCDecodeFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAttachmentFeedbackLoopDynamicStateFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceAttachmentFeedbackLoopLayoutFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceBlendOperationAdvancedFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceBlendOperationAdvancedPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceBorderColorSwizzleFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceBufferDeviceAddressFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceBufferDeviceAddressFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceClusterAccelerationStructureFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceClusterAccelerationStructurePropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceClusterCullingShaderFeaturesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceClusterCullingShaderPropertiesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceClusterCullingShaderVrsFeaturesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCoherentMemoryFeaturesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceColorWriteEnableFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCommandBufferInheritanceFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceComputeOccupancyPriorityFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceComputeShaderDerivativesFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceComputeShaderDerivativesPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceConditionalRenderingFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceConservativeRasterizationPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrix2FeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrix2PropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrixFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrixFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrixPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeMatrixPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeVectorFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCooperativeVectorPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCopyMemoryIndirectFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCopyMemoryIndirectFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCopyMemoryIndirectPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCornerSampledImageFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCoverageReductionModeFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCubicClampFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCubicWeightsFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCustomBorderColorFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCustomBorderColorPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceCustomResolveFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDataGraphFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDataGraphModelFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDedicatedAllocationImageAliasingFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthBiasControlFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthClampControlFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthClampZeroOneFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthClipControlFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthClipEnableFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDepthStencilResolveProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorBufferDensityMapPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorBufferFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorBufferPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorBufferTensorFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorBufferTensorPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorIndexingFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorIndexingProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorPoolOverallocationFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDescriptorSetHostMappingFeaturesVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceGeneratedCommandsComputeFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceGeneratedCommandsFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceGeneratedCommandsFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceGeneratedCommandsPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceGeneratedCommandsPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDeviceMemoryReportFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDiagnosticsConfigFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDiscardRectanglePropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDriverProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDrmPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDynamicRenderingFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDynamicRenderingLocalReadFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceDynamicRenderingUnusedAttachmentsFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExclusiveScissorFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedDynamicState2FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedDynamicState3FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedDynamicState3PropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedDynamicStateFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedSparseAddressSpaceFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExtendedSparseAddressSpacePropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalBufferInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalComputeQueuePropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalFenceInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalImageFormatInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalMemoryHostPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalMemoryRDMAFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalSemaphoreInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceExternalTensorInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFaultFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFeatures2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFloatControlsProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFormatPackFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMap2FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMap2PropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapLayeredFeaturesVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapLayeredPropertiesVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapOffsetFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapOffsetPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentDensityMapPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShaderBarycentricFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShaderBarycentricPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShaderInterlockFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShadingRateEnumsFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShadingRateEnumsPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShadingRateFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShadingRateKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFragmentShadingRatePropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceFrameBoundaryFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceGlobalPriorityQueryFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceGraphicsPipelineLibraryFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceGraphicsPipelineLibraryPropertiesEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceGroupProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceHdrVividFeaturesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceHostImageCopyFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceHostImageCopyProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceHostQueryResetFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceIDProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImage2DViewOf3DFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageAlignmentControlFeaturesMESA)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageAlignmentControlPropertiesMESA)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageCompressionControlFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageCompressionControlSwapchainFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageDrmFormatModifierInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageFormatInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImagelessFramebufferFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageProcessing2FeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageProcessing2PropertiesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageProcessingFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageProcessingPropertiesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageRobustnessFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageSlicedViewOf3DFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageViewImageFormatInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceImageViewMinLodFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceIndexTypeUint8Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceInheritedViewportScissorFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceInlineUniformBlockFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceInlineUniformBlockProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceInvocationMaskFeaturesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLayeredApiPropertiesKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLayeredApiPropertiesListKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLayeredApiVulkanPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLayeredDriverPropertiesMSFT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLegacyDitheringFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLegacyVertexAttributesFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLegacyVertexAttributesPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLinearColorAttachmentFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLineRasterizationFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceLineRasterizationProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance10FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance10PropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance3Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance4Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance4Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance5Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance5Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance6Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance6Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance7FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance7PropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance8FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance9FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMaintenance9PropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMapMemoryPlacedFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMapMemoryPlacedPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMemoryBudgetPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMemoryDecompressionFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMemoryDecompressionPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMemoryPriorityFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMemoryProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMeshShaderFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMeshShaderFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMeshShaderPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMeshShaderPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiDrawFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiDrawPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultisampledRenderToSingleSampledFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiviewFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiviewPerViewAttributesPropertiesNVX)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiviewPerViewRenderAreasFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiviewPerViewViewportsFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMultiviewProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceMutableDescriptorTypeFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceNestedCommandBufferFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceNestedCommandBufferPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceNonSeamlessCubeMapFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceOpacityMicromapFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceOpacityMicromapPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceOpticalFlowFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceOpticalFlowPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePageableDeviceLocalMemoryFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePartitionedAccelerationStructureFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePartitionedAccelerationStructurePropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePCIBusInfoPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePerformanceCountersByRegionFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePerformanceCountersByRegionPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePerformanceQueryFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePerformanceQueryPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePerStageDescriptorSetFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineBinaryFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineBinaryPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineCacheIncrementalModeFeaturesSEC)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineCreationCacheControlFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineExecutablePropertiesFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineLibraryGroupHandlesFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineOpacityMicromapFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelinePropertiesFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineProtectedAccessFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineRobustnessFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePipelineRobustnessProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePointClippingProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentBarrierFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentId2FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentIdFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentMeteringFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentModeFifoLatestReadyFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentTimingFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentWait2FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePresentWaitFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePrimitivesGeneratedQueryFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePrimitiveTopologyListRestartFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePrivateDataFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceProtectedMemoryFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceProtectedMemoryProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceProvokingVertexFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceProvokingVertexPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDevicePushDescriptorProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceQueueFamilyDataGraphProcessingEngineInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRasterizationOrderAttachmentAccessFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRawAccessChainsFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayQueryFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingInvocationReorderFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingInvocationReorderFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingInvocationReorderPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingInvocationReorderPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingLinearSweptSpheresFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingMaintenance1FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingMotionBlurFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingPipelineFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingPipelinePropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingPositionFetchFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRayTracingValidationFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRelaxedLineRasterizationFeaturesIMG)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRenderPassStripedFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRenderPassStripedPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRepresentativeFragmentTestFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRGBA10X6FormatsFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRobustness2FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceRobustness2PropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSampleLocationsPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSamplerFilterMinmaxProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSamplerYcbcrConversionFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceScalarBlockLayoutFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSchedulingControlsFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSchedulingControlsPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSeparateDepthStencilLayoutsFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShader64BitIndexingFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderAtomicFloat16VectorFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderAtomicFloat2FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderAtomicFloatFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderAtomicInt64Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderBfloat16FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderClockFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderCoreBuiltinsFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderCoreBuiltinsPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderCoreProperties2AMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderCorePropertiesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderCorePropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderDemoteToHelperInvocationFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderDrawParametersFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderEarlyAndLateFragmentTestsFeaturesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderExpectAssumeFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderFloat16Int8Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderFloat8FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderFloatControls2Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderFmaFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderImageAtomicInt64FeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderImageFootprintFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderIntegerDotProductFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderIntegerDotProductProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderIntegerFunctions2FeaturesINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderLongVectorFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderLongVectorPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderMaximalReconvergenceFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderModuleIdentifierFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderModuleIdentifierPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderObjectFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderObjectPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderQuadControlFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderRelaxedExtendedInstructionFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderReplicatedCompositesFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderSMBuiltinsFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderSMBuiltinsPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderSubgroupExtendedTypesFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderSubgroupRotateFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderSubgroupUniformControlFlowFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderTerminateInvocationFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderTileImageFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderTileImagePropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderUniformBufferUnsizedArrayFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShaderUntypedPointersFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShadingRateImageFeaturesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceShadingRateImagePropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSparseImageFormatInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubgroupProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubgroupSizeControlFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubgroupSizeControlProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubpassMergeFeedbackFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubpassShadingFeaturesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSubpassShadingPropertiesHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSurfaceInfo2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSwapchainMaintenance1FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceSynchronization2Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTensorFeaturesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTensorPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTexelBufferAlignmentFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTexelBufferAlignmentProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTextureCompressionASTC3DFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTextureCompressionASTCHDRFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTileMemoryHeapFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTileMemoryHeapPropertiesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTilePropertiesFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTileShadingFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTileShadingPropertiesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTimelineSemaphoreFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTimelineSemaphoreProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceToolProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTransformFeedbackFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceTransformFeedbackPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceUnifiedImageLayoutsFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceUniformBufferStandardLayoutFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVariablePointersFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVertexAttributeDivisorFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVertexAttributeDivisorProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVertexAttributeDivisorPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVertexAttributeRobustnessFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVertexInputDynamicStateFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoDecodeVP9FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoEncodeAV1FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoEncodeIntraRefreshFeaturesKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoEncodeQualityLevelInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoEncodeQuantizationMapFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoEncodeRgbConversionFeaturesVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoFormatInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoMaintenance1FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVideoMaintenance2FeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan11Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan11Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan12Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan12Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan13Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan13Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan14Features)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkan14Properties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceVulkanMemoryModelFeatures)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceWorkgroupMemoryExplicitLayoutFeaturesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceYcbcr2Plane444FormatsFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceYcbcrDegammaFeaturesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceYcbcrImageArraysFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceZeroInitializeDeviceMemoryFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPhysicalDeviceZeroInitializeWorkgroupMemoryFeatures)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineBinaryCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineBinaryDataInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineBinaryHandlesInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineBinaryInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineBinaryKeyKHR)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkPipelineCacheCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineColorBlendAdvancedStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineColorBlendStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineColorWriteCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCompilerControlCreateInfoAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCoverageModulationStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCoverageReductionStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCoverageToColorStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCreateFlags2CreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineCreationFeedbackCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineDepthStencilStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineDiscardRectangleStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineDynamicStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineExecutableInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineExecutableInternalRepresentationKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineExecutablePropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineExecutableStatisticKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineFragmentDensityMapLayeredCreateInfoVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineFragmentShadingRateEnumStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineFragmentShadingRateStateCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineIndirectDeviceAddressInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineInputAssemblyStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineLayoutCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineLibraryCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineMultisampleStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelinePropertiesIdentifierEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationConservativeStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationDepthClipStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationLineStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationProvokingVertexStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationStateRasterizationOrderAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRasterizationStateStreamCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRenderingCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRepresentativeFragmentTestStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineRobustnessCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineSampleLocationsStateCreateInfoEXT)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkPipelineShaderStageCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineShaderStageModuleIdentifierCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineShaderStageRequiredSubgroupSizeCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineTessellationDomainOriginStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineTessellationStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineVertexInputDivisorStateCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineVertexInputStateCreateInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportCoarseSampleOrderStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportDepthClampControlCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportDepthClipControlCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportExclusiveScissorStateCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportShadingRateImageStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportStateCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportSwizzleStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPipelineViewportWScalingStateCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentId2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentIdKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentRegionsKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentTimesInfoGOOGLE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentTimingInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentTimingsInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentTimingSurfaceCapabilitiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPresentWait2InfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkPrivateDataSlotCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkProtectedSubmitInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPushConstantsInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPushDescriptorSetInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkPushDescriptorSetWithTemplateInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkQueryLowLatencySupportNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueryPoolCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueryPoolPerformanceCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueryPoolPerformanceQueryCreateInfoINTEL)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueryPoolVideoEncodeFeedbackCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyCheckpointProperties2NV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyCheckpointPropertiesNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyDataGraphProcessingEnginePropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyDataGraphPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyGlobalPriorityProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyOwnershipTransferPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyQueryResultStatusPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkQueueFamilyVideoPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingPipelineClusterAccelerationStructureCreateInfoNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingPipelineCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingPipelineCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingPipelineInterfaceCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingShaderGroupCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRayTracingShaderGroupCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkReleaseCapturedPipelineDataInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkReleaseSwapchainImagesInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingAreaInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingAttachmentFlagsInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingAttachmentInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingAttachmentLocationInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingEndInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingFragmentDensityMapAttachmentInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingFragmentShadingRateAttachmentInfoKHR)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkRenderingInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderingInputAttachmentIndexInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassAttachmentBeginInfo)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkRenderPassBeginInfo)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkRenderPassCreateInfo)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkRenderPassCreateInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassCreationControlEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassCreationFeedbackCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassFragmentDensityMapCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassFragmentDensityMapOffsetEndInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassInputAttachmentAspectCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassMultiviewCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassPerformanceCountersByRegionBeginInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassSampleLocationsBeginInfoEXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassStripeBeginInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassStripeInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassStripeSubmitInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassSubpassFeedbackCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassTileShadingCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkRenderPassTransformBeginInfoQCOM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkResolveImageInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkResolveImageModeInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSampleLocationsInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerBlockMatchWindowCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerBorderColorComponentMappingCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerCaptureDescriptorDataInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerCubicWeightsCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerCustomBorderColorCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerReductionModeCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerYcbcrConversionCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerYcbcrConversionImageFormatProperties)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerYcbcrConversionInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSamplerYcbcrConversionYcbcrDegammaCreateInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreGetFdInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreSignalInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreSubmitInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreTypeCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSemaphoreWaitInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSetDescriptorBufferOffsetsInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSetLatencyMarkerInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSetPresentConfigNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkShaderCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkShaderModuleCreateInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkShaderModuleIdentifierEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkShaderModuleValidationCacheCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSharedPresentSurfaceCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSparseImageFormatProperties2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSparseImageMemoryRequirements2)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkSubmitInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkSubmitInfo2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassBeginInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassDependency2)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkSubpassDescription2)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassDescriptionDepthStencilResolve)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassEndInfo)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassResolvePerformanceQueryEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubpassShadingPipelineCreateInfoHUAWEI)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubresourceHostMemcpySize)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSubresourceLayout2)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceCapabilities2EXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceCapabilities2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceCapabilitiesPresentBarrierNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceCapabilitiesPresentId2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceCapabilitiesPresentWait2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceFormat2KHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfacePresentModeCompatibilityKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfacePresentModeKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfacePresentScalingCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSurfaceProtectedCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainCalibratedTimestampInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainCounterCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainDisplayNativeHdrCreateInfoAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainLatencyCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainPresentBarrierCreateInfoNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainPresentFenceInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainPresentModeInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainPresentModesCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainPresentScalingCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainTimeDomainPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkSwapchainTimingPropertiesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorCaptureDescriptorDataInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorCopyARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorCreateInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorDependencyInfoARM)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorDescriptionARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorFormatPropertiesARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorMemoryBarrierARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorMemoryRequirementsInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorViewCaptureDescriptorDataInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTensorViewCreateInfoARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTextureLODGatherFormatPropertiesAMD)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTileMemoryBindInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTileMemoryRequirementsQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTileMemorySizeInfoQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTilePropertiesQCOM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkTimelineSemaphoreSubmitInfo)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkValidationCacheCreateInfoEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkValidationFeaturesEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkValidationFlagsEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVertexInputAttributeDescription2EXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVertexInputBindingDescription2EXT)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoBeginCodingInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoCodingControlInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeAV1CapabilitiesKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeAV1DpbSlotInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeAV1InlineSessionParametersInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeAV1ProfileInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeAV1SessionParametersCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264CapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264DpbSlotInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264PictureInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264ProfileInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264SessionParametersAddInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH264SessionParametersCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265CapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265DpbSlotInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265PictureInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265ProfileInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265SessionParametersAddInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeH265SessionParametersCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeUsageInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeVP9CapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoDecodeVP9ProfileInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1CapabilitiesKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1DpbSlotInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1GopRemainingFrameInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1ProfileInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1QualityLevelPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1QuantizationMapCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1RateControlInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1RateControlLayerInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1SessionCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeAV1SessionParametersCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264CapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264DpbSlotInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264GopRemainingFrameInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264ProfileInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264QualityLevelPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264QuantizationMapCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264RateControlInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264RateControlLayerInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264SessionCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264SessionParametersFeedbackInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH264SessionParametersGetInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265CapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265DpbSlotInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265GopRemainingFrameInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265ProfileInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265QualityLevelPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265QuantizationMapCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265RateControlInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265RateControlLayerInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265SessionCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265SessionParametersFeedbackInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeH265SessionParametersGetInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeIntraRefreshCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeIntraRefreshInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeProfileRgbConversionInfoVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeQualityLevelInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeQualityLevelPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeQuantizationMapCapabilitiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeQuantizationMapInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeQuantizationMapSessionParametersCreateInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeRateControlInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeRateControlLayerInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeRgbConversionCapabilitiesVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeSessionIntraRefreshCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeSessionParametersFeedbackInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeSessionParametersGetInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeSessionRgbConversionCreateInfoVALVE)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEncodeUsageInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoEndCodingInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoFormatAV1QuantizationMapPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoFormatH265QuantizationMapPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoFormatPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoFormatQuantizationMapPropertiesKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoInlineQueryInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoPictureResourceInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoProfileInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoProfileListInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoReferenceIntraRefreshInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoReferenceSlotInfoKHR)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoSessionCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoSessionMemoryRequirementsKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoSessionParametersCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkVideoSessionParametersUpdateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWaylandSurfaceCreateInfoKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSet) // TODO: This should be non-default instead
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSetAccelerationStructureKHR)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSetAccelerationStructureNV)
// VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSetInlineUniformBlock)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSetPartitionedAccelerationStructureNV)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteDescriptorSetTensorARM)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteIndirectExecutionSetPipelineEXT)
VULKAN_DEFAULT_CUSTOM_REPACK(VkWriteIndirectExecutionSetShaderEXT)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkXcbSurfaceCreateInfoKHR)
VULKAN_NONDEFAULT_CUSTOM_REPACK(VkXlibSurfaceCreateInfoKHR)


void fex_custom_repack_entry(host_layout<VkInstanceCreateInfo>& into, const guest_layout<VkInstanceCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  // pApplicationInfo is optional, and wine's own winex11 vulkan init omits it.
  // Dereferencing it unconditionally read address 0 inside the repack, before
  // the custom impl ran at all -- the 32-bit Dex process died there every run.
  // RepackStructArray already returns an empty span for a null pointer.
  into.data.pApplicationInfo = RepackStructArray(1u, from.data.pApplicationInfo).data();

  auto extension_count = from.data.enabledExtensionCount.data;
  into.data.ppEnabledExtensionNames = RepackStructArray<false>(extension_count, from.data.ppEnabledExtensionNames).data();

  auto layer_count = from.data.enabledLayerCount.data;
  into.data.ppEnabledLayerNames = RepackStructArray<false>(layer_count, from.data.ppEnabledLayerNames).data();
}

// Returning true suppresses the generic exit write-back in ~repack_wrapper.
//
// That write-back copies the *host* struct back over the guest's struct, and
// every one of these is a const input the guest still owns and reads after the
// call. Worse, it runs after this function has already freed the host arrays,
// so what lands in the guest is a set of dead host pointers narrowed to 32 bits
// -- or zero.
//
// ~repack_wrapper does have an `is_const_v` guard for exactly this, but the
// generator instantiates the wrapper through get_type_name_with_nonconst_pointee
// (Generator/gen.cpp), which strips the const, so the guard never fires and
// every input struct with a hand-written exit was being clobbered.
//
// Concretely: wine passes DXVK's VkDeviceCreateInfo straight through, we
// overwrote its pQueueCreateInfos with 0, and wine's init_device_queues then
// dereferenced null one instruction into the queue loop -- reported as
// "err:vulkan:vkCreateDevice Exception 0xc0000005 in Unix call", four calls
// deep and nowhere near the actual write.
bool fex_custom_repack_exit(guest_layout<VkInstanceCreateInfo>& into, const host_layout<VkInstanceCreateInfo>& from) {
  delete[] from.data.pApplicationInfo;
  delete[] from.data.ppEnabledExtensionNames;
  delete[] from.data.ppEnabledLayerNames;
  return true;
}

void fex_custom_repack_entry(host_layout<VkMemoryToImageCopyEXT>& into, const guest_layout<VkMemoryToImageCopyEXT>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pHostPointer = from.data.pHostPointer.get_pointer();
}

bool fex_custom_repack_exit(guest_layout<VkMemoryToImageCopyEXT>& into, const host_layout<VkMemoryToImageCopyEXT>& from) {
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkDeviceCreateInfo>& into, const guest_layout<VkDeviceCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  // queueCreateInfoCount is routinely >1 (DXVK asks for graphics + transfer +
  // sparse); only element 0 was being repacked, leaving the rest as guest
  // layout for the driver to read.
  into.data.pQueueCreateInfos = RepackStructArray(from.data.queueCreateInfoCount.data, from.data.pQueueCreateInfos).data();
  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: VkDeviceCreateInfo queueCount=%u guestQueues=%p hostQueues=%p layers=%u exts=%u\n",
            from.data.queueCreateInfoCount.data, (void*)from.data.pQueueCreateInfos.get_pointer(), (const void*)into.data.pQueueCreateInfos,
            from.data.enabledLayerCount.data, from.data.enabledExtensionCount.data);
    fflush(stderr);
  }

  // This used to read enabledExtensionCount, so a device asking for a
  // different number of layers than extensions repacked the wrong count.
  auto layer_count = from.data.enabledLayerCount.data;
  into.data.ppEnabledLayerNames = RepackStructArray<false>(layer_count, from.data.ppEnabledLayerNames).data();

  auto extension_count = from.data.enabledExtensionCount.data;
  into.data.ppEnabledExtensionNames = RepackStructArray<false>(extension_count, from.data.ppEnabledExtensionNames).data();
}

bool fex_custom_repack_exit(guest_layout<VkDeviceCreateInfo>& into, const host_layout<VkDeviceCreateInfo>& from) {
  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: VkDeviceCreateInfo exit guestQueues=%p count=%u guestPNext=%p\n",
            (void*)into.data.pQueueCreateInfos.get_pointer(), into.data.queueCreateInfoCount.data, (void*)into.data.pNext.get_pointer());
    fflush(stderr);
  }
  delete[] from.data.pQueueCreateInfos;
  delete[] from.data.ppEnabledExtensionNames;
  delete[] from.data.ppEnabledLayerNames;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkDescriptorSetLayoutCreateInfo>& into, const guest_layout<VkDescriptorSetLayoutCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pBindings = RepackStructArray(from.data.bindingCount.data, from.data.pBindings).data();
}

bool fex_custom_repack_exit(guest_layout<VkDescriptorSetLayoutCreateInfo>& into, const host_layout<VkDescriptorSetLayoutCreateInfo>& from) {
  delete[] from.data.pBindings;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkRenderPassCreateInfo>& into, const guest_layout<VkRenderPassCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pSubpasses = RepackStructArray(from.data.subpassCount.data, from.data.pSubpasses).data();
}

bool fex_custom_repack_exit(guest_layout<VkRenderPassCreateInfo>& into, const host_layout<VkRenderPassCreateInfo>& from) {
  delete[] from.data.pSubpasses;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkRenderPassCreateInfo2>& into, const guest_layout<VkRenderPassCreateInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pAttachments = RepackStructArray(from.data.attachmentCount.data, from.data.pAttachments).data();
  into.data.pSubpasses = RepackStructArray(from.data.subpassCount.data, from.data.pSubpasses).data();
  into.data.pDependencies = RepackStructArray(from.data.dependencyCount.data, from.data.pDependencies).data();
}

bool fex_custom_repack_exit(guest_layout<VkRenderPassCreateInfo2>& into, const host_layout<VkRenderPassCreateInfo2>& from) {
  DeleteRepackedStructArray(from.data.attachmentCount, from.data.pAttachments, into.data.pAttachments);
  DeleteRepackedStructArray(from.data.subpassCount, from.data.pSubpasses, into.data.pSubpasses);
  DeleteRepackedStructArray(from.data.dependencyCount, from.data.pDependencies, into.data.pDependencies);
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkSubpassDescription2>& into, const guest_layout<VkSubpassDescription2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pInputAttachments = RepackStructArray(from.data.inputAttachmentCount.data, from.data.pInputAttachments).data();
  into.data.pColorAttachments = RepackStructArray(from.data.colorAttachmentCount.data, from.data.pColorAttachments).data();
  into.data.pResolveAttachments = RepackStructArray(from.data.colorAttachmentCount.data, from.data.pResolveAttachments).data();

  if (from.data.pDepthStencilAttachment.data == 0) {
    into.data.pDepthStencilAttachment = nullptr;
  } else {
    into.data.pDepthStencilAttachment = new VkAttachmentReference2;
    auto in_data = host_layout<VkAttachmentReference2> {*from.data.pDepthStencilAttachment.get_pointer()};
    fex_apply_custom_repacking_entry(in_data, *from.data.pDepthStencilAttachment.get_pointer());
    memcpy((void*)into.data.pDepthStencilAttachment, &in_data.data, sizeof(VkAttachmentReference2));
  }
}

bool fex_custom_repack_exit(guest_layout<VkSubpassDescription2>& into, const host_layout<VkSubpassDescription2>& from) {
  DeleteRepackedStructArray(from.data.inputAttachmentCount, from.data.pInputAttachments, into.data.pInputAttachments);
  DeleteRepackedStructArray(from.data.colorAttachmentCount, from.data.pColorAttachments, into.data.pColorAttachments);
  DeleteRepackedStructArray(from.data.colorAttachmentCount, from.data.pResolveAttachments, into.data.pResolveAttachments);
  if (from.data.pDepthStencilAttachment) {
    fex_apply_custom_repacking_exit(*into.data.pDepthStencilAttachment.get_pointer(), to_host_layout(*from.data.pDepthStencilAttachment));
    delete from.data.pDepthStencilAttachment;
  }
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkRenderingInfo>& into, const guest_layout<VkRenderingInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  into.data.pColorAttachments = RepackStructArray(from.data.colorAttachmentCount.data, from.data.pColorAttachments).data();

  if (from.data.pDepthAttachment.get_pointer() == nullptr) {
    into.data.pDepthAttachment = nullptr;
  } else {
    into.data.pDepthAttachment = new VkRenderingAttachmentInfo;
    auto in_data = host_layout<VkRenderingAttachmentInfo> {*from.data.pDepthAttachment.get_pointer()};
    fex_apply_custom_repacking_entry(in_data, *from.data.pDepthAttachment.get_pointer());
    memcpy((void*)into.data.pDepthAttachment, &in_data.data, sizeof(VkRenderingAttachmentInfo));
  }

  if (from.data.pStencilAttachment.get_pointer() == nullptr) {
    into.data.pStencilAttachment = nullptr;
  } else {
    into.data.pStencilAttachment = new VkRenderingAttachmentInfo;
    auto in_data = host_layout<VkRenderingAttachmentInfo> {*from.data.pStencilAttachment.get_pointer()};
    fex_apply_custom_repacking_entry(in_data, *from.data.pStencilAttachment.get_pointer());
    memcpy((void*)into.data.pStencilAttachment, &in_data.data, sizeof(VkRenderingAttachmentInfo));
  }
}

bool fex_custom_repack_exit(guest_layout<VkRenderingInfo>& into, const host_layout<VkRenderingInfo>& from) {
  DeleteRepackedStructArray(from.data.colorAttachmentCount, from.data.pColorAttachments, into.data.pColorAttachments);
  if (from.data.pDepthAttachment) {
    fex_apply_custom_repacking_exit(*into.data.pDepthAttachment.get_pointer(), to_host_layout(*from.data.pDepthAttachment));
    delete from.data.pDepthAttachment;
  }
  if (from.data.pStencilAttachment) {
    fex_apply_custom_repacking_exit(*into.data.pStencilAttachment.get_pointer(), to_host_layout(*from.data.pStencilAttachment));
    delete from.data.pStencilAttachment;
  }
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkDescriptorGetInfoEXT>& into, const guest_layout<VkDescriptorGetInfoEXT>& from) {
  default_fex_custom_repack_entry(into, from);

  switch (into.data.type) {
  case VK_DESCRIPTOR_TYPE_SAMPLER:
  case VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER:
  case VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE:
  case VK_DESCRIPTOR_TYPE_STORAGE_IMAGE:
  case VK_DESCRIPTOR_TYPE_INPUT_ATTACHMENT: {
    // VkSampler* or VkDescriptorImageInfo*. Handle by zero-extending
    guest_layout<VkSampler*> guest_data;
    memcpy(&guest_data, from.data.data.union_storage, sizeof(guest_data));
    into.data.data.pSampler = host_layout<VkSampler*> {guest_data}.data;
    break;
  }

  case VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER:
  case VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER:
  case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
  case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER: {
    // VkDescriptorAddressInfoEXT*. Repacking required.
    //
    // The pointer is allowed to be null: with VK_EXT_robustness2's
    // nullDescriptor feature -- which DXVK enables, and radv supports -- a null
    // here means "write a null descriptor". Dereferencing it unconditionally
    // faulted inside the thunk, and wine turned that into
    // "nested exception on signal stack" while dispatching it, taking the crash
    // report with it.
    guest_layout<VkDescriptorAddressInfoEXT*> guest_ptr;
    memcpy(&guest_ptr, from.data.data.union_storage, sizeof(guest_ptr));
    if (!guest_ptr.get_pointer()) {
      into.data.data.pUniformBuffer = nullptr;
      break;
    }
    auto child_mem = (char*)aligned_alloc(alignof(host_layout<VkDescriptorAddressInfoEXT>), sizeof(host_layout<VkDescriptorAddressInfoEXT>));
    auto child = new (child_mem) host_layout<VkDescriptorAddressInfoEXT> {*guest_ptr.get_pointer()};

    default_fex_custom_repack_entry(*child, *guest_ptr.get_pointer());
    into.data.data.pUniformBuffer = &child->data;
    break;
  }

  case VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_KHR:
  case VK_DESCRIPTOR_TYPE_ACCELERATION_STRUCTURE_NV: {
    // Copy unmodified
    static_assert(sizeof(guest_layout<VkDeviceAddress>) == sizeof(uint64_t));
    memcpy(&into.data.data.accelerationStructure, &from.data.data, sizeof(uint64_t));
    break;
  }

  case VK_DESCRIPTOR_TYPE_SAMPLE_WEIGHT_IMAGE_QCOM:
  case VK_DESCRIPTOR_TYPE_BLOCK_MATCH_IMAGE_QCOM:
  case VK_DESCRIPTOR_TYPE_MUTABLE_EXT:
  case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER_DYNAMIC:
  case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER_DYNAMIC:
  case VK_DESCRIPTOR_TYPE_INLINE_UNIFORM_BLOCK:
  default:
    // This used to abort(). Two things were wrong with that. The message had no
    // newline and no flush, so it never reached the log and the abort looked
    // like a bare EXCEPTION_WINE_ASSERTION from inside libvulkan.so.1 -- which
    // wine then compounded into "nested exception on signal stack" while
    // dispatching it, losing the crash report entirely.
    //
    // And aborting is the wrong response: with VK_EXT_robustness2's
    // nullDescriptor enabled (DXVK does enable it), a zeroed descriptor is a
    // well-defined null descriptor. Degrade to that and name the type once, so
    // an unhandled case shows up as a rendering artifact plus a log line rather
    // than a dead process.
    {
      static std::mutex ReportedMutex;
      static std::unordered_set<uint32_t> Reported;
      std::lock_guard lk {ReportedMutex};
      if (Reported.insert(static_cast<uint32_t>(into.data.type)).second) {
        fprintf(stderr, "WARNING: Unhandled descriptor type %u in VkDescriptorGetInfoEXT; writing a null descriptor\n",
                static_cast<uint32_t>(into.data.type));
        fflush(stderr);
      }
    }
    memset(&into.data.data, 0, sizeof(into.data.data));
    break;
  }
}

bool fex_custom_repack_exit(guest_layout<VkDescriptorGetInfoEXT>& into, const host_layout<VkDescriptorGetInfoEXT>& from) {
  switch (from.data.type) {
  case VK_DESCRIPTOR_TYPE_UNIFORM_TEXEL_BUFFER:
  case VK_DESCRIPTOR_TYPE_STORAGE_TEXEL_BUFFER:
  case VK_DESCRIPTOR_TYPE_UNIFORM_BUFFER:
  case VK_DESCRIPTOR_TYPE_STORAGE_BUFFER:
    // Delete storage allocated on entry
    free((void*)from.data.data.pUniformBuffer);

  default:
    // Nothing to do for the rest
    break;
  }
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkCopyMemoryToImageInfoEXT>& into, const guest_layout<VkCopyMemoryToImageInfoEXT>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkCopyMemoryToImageInfoEXT>& into, const host_layout<VkCopyMemoryToImageInfoEXT>& from) {
  DeleteRepackedStructArray(from.data.regionCount, from.data.pRegions, into.data.pRegions);
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkDependencyInfo>& into, const guest_layout<VkDependencyInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pMemoryBarriers = RepackStructArray(from.data.memoryBarrierCount.data, from.data.pMemoryBarriers).data();
  into.data.pImageMemoryBarriers = RepackStructArray(from.data.imageMemoryBarrierCount.data, from.data.pImageMemoryBarriers).data();
  into.data.pBufferMemoryBarriers = RepackStructArray(from.data.bufferMemoryBarrierCount.data, from.data.pBufferMemoryBarriers).data();
}

bool fex_custom_repack_exit(guest_layout<VkDependencyInfo>& into, const host_layout<VkDependencyInfo>& from) {
  DeleteRepackedStructArray(from.data.memoryBarrierCount, from.data.pMemoryBarriers, into.data.pMemoryBarriers);
  DeleteRepackedStructArray(from.data.imageMemoryBarrierCount, from.data.pImageMemoryBarriers, into.data.pImageMemoryBarriers);
  DeleteRepackedStructArray(from.data.bufferMemoryBarrierCount, from.data.pBufferMemoryBarriers, into.data.pBufferMemoryBarriers);
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkDescriptorUpdateTemplateCreateInfo>& into,
                             const guest_layout<VkDescriptorUpdateTemplateCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pDescriptorUpdateEntries = RepackStructArray(from.data.descriptorUpdateEntryCount.data, from.data.pDescriptorUpdateEntries).data();
}

bool fex_custom_repack_exit(guest_layout<VkDescriptorUpdateTemplateCreateInfo>& into, const host_layout<VkDescriptorUpdateTemplateCreateInfo>& from) {
  DeleteRepackedStructArray(from.data.descriptorUpdateEntryCount, from.data.pDescriptorUpdateEntries, into.data.pDescriptorUpdateEntries);
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

// VkSpecializationInfo and VkSpecializationMapEntry both carry a size_t, so
// neither survives a straight copy from a 32-bit guest. This used to abort --
// with an fprintf that had no newline and no flush, so the message never even
// reached the log. DXVK attaches specialization constants to nearly every
// pipeline stage, so that abort was a wall.
void fex_custom_repack_entry(host_layout<VkSpecializationInfo>& into, const guest_layout<VkSpecializationInfo>& from) {
  into.data.pMapEntries = RepackStructArray(from.data.mapEntryCount.data, from.data.pMapEntries).data();
  // pData is an opaque blob of constant values; same bytes either side.
  into.data.pData = from.data.pData.get_pointer();
}

bool fex_custom_repack_exit(guest_layout<VkSpecializationInfo>& into, const host_layout<VkSpecializationInfo>& from) {
  delete[] from.data.pMapEntries;
  return true;
}

void fex_custom_repack_entry(host_layout<VkPipelineShaderStageCreateInfo>& into, const guest_layout<VkPipelineShaderStageCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  auto GuestSpec = from.data.pSpecializationInfo.get_pointer();
  if (!GuestSpec) {
    into.data.pSpecializationInfo = nullptr;
    return;
  }
  auto HostSpec = new host_layout<VkSpecializationInfo> {*GuestSpec};
  fex_custom_repack_entry(*HostSpec, *GuestSpec);
  into.data.pSpecializationInfo = &HostSpec->data;
}

bool fex_custom_repack_exit(guest_layout<VkPipelineShaderStageCreateInfo>& into, const host_layout<VkPipelineShaderStageCreateInfo>& from) {
  if (from.data.pSpecializationInfo) {
    delete[] from.data.pSpecializationInfo->pMapEntries;
    delete reinterpret_cast<const host_layout<VkSpecializationInfo>*>(from.data.pSpecializationInfo);
  }
  // TODO
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkGraphicsPipelineCreateInfo>& into, const guest_layout<VkGraphicsPipelineCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pStages = RepackStructArray(from.data.stageCount.data, from.data.pStages).data();

  if (!from.data.pVertexInputState.get_pointer()) {
    into.data.pVertexInputState = nullptr;
  } else {
    into.data.pVertexInputState = &(new host_layout<VkPipelineVertexInputStateCreateInfo> {*from.data.pVertexInputState.get_pointer()})->data;
  }

  if (!from.data.pInputAssemblyState.get_pointer()) {
    into.data.pInputAssemblyState = nullptr;
  } else {
    into.data.pInputAssemblyState =
      &(new host_layout<VkPipelineInputAssemblyStateCreateInfo> {*from.data.pInputAssemblyState.get_pointer()})->data;
  }

  if (!from.data.pTessellationState.get_pointer()) {
    into.data.pTessellationState = nullptr;
  } else {
    into.data.pTessellationState = &(new host_layout<VkPipelineTessellationStateCreateInfo> {*from.data.pTessellationState.get_pointer()})->data;
  }

  if (!from.data.pViewportState.get_pointer()) {
    into.data.pViewportState = nullptr;
  } else {
    into.data.pViewportState = &(new host_layout<VkPipelineViewportStateCreateInfo> {*from.data.pViewportState.get_pointer()})->data;
  }

  if (!from.data.pRasterizationState.get_pointer()) {
    into.data.pRasterizationState = nullptr;
  } else {
    into.data.pRasterizationState =
      &(new host_layout<VkPipelineRasterizationStateCreateInfo> {*from.data.pRasterizationState.get_pointer()})->data;
  }

  if (!from.data.pMultisampleState.get_pointer()) {
    into.data.pMultisampleState = nullptr;
  } else {
    into.data.pMultisampleState = &(new host_layout<VkPipelineMultisampleStateCreateInfo> {*from.data.pMultisampleState.get_pointer()})->data;
  }

  if (!from.data.pDepthStencilState.get_pointer()) {
    into.data.pDepthStencilState = nullptr;
  } else {
    into.data.pDepthStencilState = &(new host_layout<VkPipelineDepthStencilStateCreateInfo> {*from.data.pDepthStencilState.get_pointer()})->data;
  }

  if (!from.data.pColorBlendState.get_pointer()) {
    into.data.pColorBlendState = nullptr;
  } else {
    into.data.pColorBlendState = &(new host_layout<VkPipelineColorBlendStateCreateInfo> {*from.data.pColorBlendState.get_pointer()})->data;
  }

  if (!from.data.pDynamicState.get_pointer()) {
    into.data.pDynamicState = nullptr;
  } else {
    into.data.pDynamicState = &(new host_layout<VkPipelineDynamicStateCreateInfo> {*from.data.pDynamicState.get_pointer()})->data;
  }
}

bool fex_custom_repack_exit(guest_layout<VkGraphicsPipelineCreateInfo>& into, const host_layout<VkGraphicsPipelineCreateInfo>& from) {
  delete[] from.data.pStages;
  delete from.data.pVertexInputState;
  delete from.data.pInputAssemblyState;
  delete from.data.pTessellationState;
  delete from.data.pViewportState;
  delete from.data.pRasterizationState;
  delete from.data.pMultisampleState;
  delete from.data.pDepthStencilState;
  delete from.data.pColorBlendState;
  delete from.data.pDynamicState;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkSubmitInfo>& into, const guest_layout<VkSubmitInfo>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pCommandBuffers = RepackStructArray<false>(from.data.commandBufferCount.data, from.data.pCommandBuffers).data();
}

bool fex_custom_repack_exit(guest_layout<VkSubmitInfo>& into, const host_layout<VkSubmitInfo>& from) {
  delete[] from.data.pCommandBuffers;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkCommandBufferBeginInfo>& into, const guest_layout<VkCommandBufferBeginInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  if (!from.data.pInheritanceInfo.get_pointer() || !from.data.pInheritanceInfo.data) {
    into.data.pInheritanceInfo = nullptr;
    return;
  }
  into.data.pInheritanceInfo = new VkCommandBufferInheritanceInfo;
  auto src = host_layout<VkCommandBufferInheritanceInfo> {*from.data.pInheritanceInfo.get_pointer()}.data;
  static_assert(sizeof(src) == sizeof(*into.data.pInheritanceInfo));
  memcpy((void*)into.data.pInheritanceInfo, &src, sizeof(src));
}

bool fex_custom_repack_exit(guest_layout<VkCommandBufferBeginInfo>& into, const host_layout<VkCommandBufferBeginInfo>& from) {
  delete from.data.pInheritanceInfo;
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkPipelineCacheCreateInfo>& into, const guest_layout<VkPipelineCacheCreateInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  // Same underlying layout, so there's nothing to do
  into.data.pInitialData = from.data.pInitialData.get_pointer();
}

bool fex_custom_repack_exit(guest_layout<VkPipelineCacheCreateInfo>& into, const host_layout<VkPipelineCacheCreateInfo>& from) {
  // Nothing to do
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}

void fex_custom_repack_entry(host_layout<VkRenderPassBeginInfo>& into, const guest_layout<VkRenderPassBeginInfo>& from) {
  default_fex_custom_repack_entry(into, from);

  // Same underlying layout, so there's nothing to do
  into.data.pClearValues = reinterpret_cast<const VkClearValue*>(from.data.pClearValues.get_pointer());
}

bool fex_custom_repack_exit(guest_layout<VkRenderPassBeginInfo>& into, const host_layout<VkRenderPassBeginInfo>& from) {
  // Nothing to do
  // Input-only struct; see the note on fex_custom_repack_exit(VkInstanceCreateInfo).
  return true;
}


// ---------------------------------------------------------------------------
// Vulkan 1.3 info structs DXVK needs on 32-bit.
//
// Each wraps what used to be a flat argument list into a struct holding either
// a count/array pair or a pointer to another info struct, so the generator
// refuses the parameter outright ("Unsupported parameter type") until the
// member has a repack rule. Without them vkGetInstanceProcAddr returned null
// for vkQueueSubmit2, the copy_commands2 family and the maintenance4 memory
// queries, and Unity died with EIP=0 in "GfxDevice: creating device client".
//
// All are const inputs, so the exits return true: see the note on
// fex_custom_repack_exit(VkInstanceCreateInfo).
// ---------------------------------------------------------------------------
void fex_custom_repack_entry(host_layout<VkBlitImageInfo2>& into, const guest_layout<VkBlitImageInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkBlitImageInfo2>& into, const host_layout<VkBlitImageInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkCopyBufferInfo2>& into, const guest_layout<VkCopyBufferInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkCopyBufferInfo2>& into, const host_layout<VkCopyBufferInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkCopyImageInfo2>& into, const guest_layout<VkCopyImageInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkCopyImageInfo2>& into, const host_layout<VkCopyImageInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkCopyBufferToImageInfo2>& into, const guest_layout<VkCopyBufferToImageInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkCopyBufferToImageInfo2>& into, const host_layout<VkCopyBufferToImageInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkCopyImageToBufferInfo2>& into, const guest_layout<VkCopyImageToBufferInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkCopyImageToBufferInfo2>& into, const host_layout<VkCopyImageToBufferInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkResolveImageInfo2>& into, const guest_layout<VkResolveImageInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pRegions = RepackStructArray(from.data.regionCount.data, from.data.pRegions).data();
}

bool fex_custom_repack_exit(guest_layout<VkResolveImageInfo2>& into, const host_layout<VkResolveImageInfo2>& from) {
  delete[] from.data.pRegions;
  return true;
}

void fex_custom_repack_entry(host_layout<VkSubmitInfo2>& into, const guest_layout<VkSubmitInfo2>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pWaitSemaphoreInfos = RepackStructArray(from.data.waitSemaphoreInfoCount.data, from.data.pWaitSemaphoreInfos).data();
  into.data.pCommandBufferInfos = RepackStructArray(from.data.commandBufferInfoCount.data, from.data.pCommandBufferInfos).data();
  into.data.pSignalSemaphoreInfos = RepackStructArray(from.data.signalSemaphoreInfoCount.data, from.data.pSignalSemaphoreInfos).data();
}

bool fex_custom_repack_exit(guest_layout<VkSubmitInfo2>& into, const host_layout<VkSubmitInfo2>& from) {
  delete[] from.data.pWaitSemaphoreInfos;
  delete[] from.data.pCommandBufferInfos;
  delete[] from.data.pSignalSemaphoreInfos;
  return true;
}

void fex_custom_repack_entry(host_layout<VkDeviceBufferMemoryRequirements>& into, const guest_layout<VkDeviceBufferMemoryRequirements>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pCreateInfo = RepackStructArray(1u, from.data.pCreateInfo).data();
}

bool fex_custom_repack_exit(guest_layout<VkDeviceBufferMemoryRequirements>& into, const host_layout<VkDeviceBufferMemoryRequirements>& from) {
  delete[] from.data.pCreateInfo;
  return true;
}

void fex_custom_repack_entry(host_layout<VkDeviceImageMemoryRequirements>& into, const guest_layout<VkDeviceImageMemoryRequirements>& from) {
  default_fex_custom_repack_entry(into, from);
  into.data.pCreateInfo = RepackStructArray(1u, from.data.pCreateInfo).data();
}

bool fex_custom_repack_exit(guest_layout<VkDeviceImageMemoryRequirements>& into, const host_layout<VkDeviceImageMemoryRequirements>& from) {
  delete[] from.data.pCreateInfo;
  return true;
}

// ---------------------------------------------------------------------------
// Two-call array queries over extensible (sType/pNext) structs.
//
// The generator wraps an out-array parameter with make_repack_wrapper, which
// repacks exactly one element. For a count/array pair that is wrong twice over:
// elements past the first are never repacked, and on the counting call (array
// == nullptr) the wrapper still walks a struct that is not there. DXVK's first
// vkGetPhysicalDeviceQueueFamilyProperties2 call took the second path and
// faulted reading 0xFFFFFFFF inside the thunk.
//
// So these get a hand-written host impl, following the shape vkEnumerate-
// PhysicalDevices already uses: pass the count-probe straight through, and
// otherwise repack every element in and back out, carrying each element's own
// pNext chain across in both directions.
// ---------------------------------------------------------------------------
template<typename T, typename Fn>
static auto RepackedArrayQuery(uint32_t* count, guest_layout<T*> array, Fn&& call) {
  using RetType = decltype(call(std::declval<T*>()));

  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: array query enter count_ptr=%p count=%u array=%p\n", (void*)count, count ? *count : 0u,
            (void*)array.get_pointer());
  }
  if (!array.get_pointer()) {
    // Count probe: nothing to repack, and the guest may not have sized *count yet.
    return call(nullptr);
  }

  const uint32_t InputCount = *count;
  auto* Guest = array.get_pointer();

  // Hosts owns each element's repacked pNext chain until the exit pass frees it;
  // Plain is the contiguous T[] the driver actually writes through.
  std::vector<host_layout<T>> Hosts;
  Hosts.reserve(InputCount);
  std::vector<T> Plain(InputCount);
  for (uint32_t i = 0; i < InputCount; ++i) {
    Hosts.emplace_back(Guest[i]);
    fex_custom_repack_entry(Hosts[i], Guest[i]);
    Plain[i] = Hosts[i].data;
  }

  if (VkArrayTrace()) {
    fprintf(stderr, "FEXVKTRACE: array query repacked %u elements, calling driver\n", InputCount);
  }

  auto Finish = [&]() {
    // *count is what the driver actually filled, which may be below InputCount.
    for (uint32_t i = 0; i < std::min(InputCount, *count); ++i) {
      fex_custom_repack_exit(Guest[i], to_host_layout(Plain[i]));
    }
  };

  if constexpr (std::is_void_v<RetType>) {
    call(Plain.data());
    Finish();
  } else {
    auto Ret = call(Plain.data());
    Finish();
    return Ret;
  }
}

void fexfn_impl_libvulkan_vkGetPhysicalDeviceQueueFamilyProperties2(VkPhysicalDevice a_0, uint32_t* a_1,
                                                                    guest_layout<VkQueueFamilyProperties2*> a_2) {
  RepackedArrayQuery(a_1, a_2, [&](VkQueueFamilyProperties2* out) {
    fexldr_ptr_libvulkan_vkGetPhysicalDeviceQueueFamilyProperties2(a_0, a_1, out);
  });
}

void fexfn_impl_libvulkan_vkGetPhysicalDeviceQueueFamilyProperties2KHR(VkPhysicalDevice a_0, uint32_t* a_1,
                                                                       guest_layout<VkQueueFamilyProperties2*> a_2) {
  RepackedArrayQuery(a_1, a_2, [&](VkQueueFamilyProperties2* out) {
    fexldr_ptr_libvulkan_vkGetPhysicalDeviceQueueFamilyProperties2KHR(a_0, a_1, out);
  });
}

void fexfn_impl_libvulkan_vkGetPhysicalDeviceSparseImageFormatProperties2(VkPhysicalDevice a_0,
                                                                          const VkPhysicalDeviceSparseImageFormatInfo2* a_1, uint32_t* a_2,
                                                                          guest_layout<VkSparseImageFormatProperties2*> a_3) {
  RepackedArrayQuery(a_2, a_3, [&](VkSparseImageFormatProperties2* out) {
    fexldr_ptr_libvulkan_vkGetPhysicalDeviceSparseImageFormatProperties2(a_0, a_1, a_2, out);
  });
}

void fexfn_impl_libvulkan_vkGetPhysicalDeviceSparseImageFormatProperties2KHR(VkPhysicalDevice a_0,
                                                                             const VkPhysicalDeviceSparseImageFormatInfo2* a_1,
                                                                             uint32_t* a_2,
                                                                             guest_layout<VkSparseImageFormatProperties2*> a_3) {
  RepackedArrayQuery(a_2, a_3, [&](VkSparseImageFormatProperties2* out) {
    fexldr_ptr_libvulkan_vkGetPhysicalDeviceSparseImageFormatProperties2KHR(a_0, a_1, a_2, out);
  });
}

VkResult fexfn_impl_libvulkan_vkGetPhysicalDeviceSurfaceFormats2KHR(VkPhysicalDevice a_0, const VkPhysicalDeviceSurfaceInfo2KHR* a_1,
                                                                    uint32_t* a_2, guest_layout<VkSurfaceFormat2KHR*> a_3) {
  return RepackedArrayQuery(a_2, a_3, [&](VkSurfaceFormat2KHR* out) {
    return fexldr_ptr_libvulkan_vkGetPhysicalDeviceSurfaceFormats2KHR(a_0, a_1, a_2, out);
  });
}

VkResult fexfn_impl_libvulkan_vkGetPhysicalDeviceToolProperties(VkPhysicalDevice a_0, uint32_t* a_1,
                                                                 guest_layout<VkPhysicalDeviceToolProperties*> a_2) {
  return RepackedArrayQuery(a_1, a_2, [&](VkPhysicalDeviceToolProperties* out) {
    return fexldr_ptr_libvulkan_vkGetPhysicalDeviceToolProperties(a_0, a_1, out);
  });
}

VkResult fexfn_impl_libvulkan_vkGetPhysicalDeviceToolPropertiesEXT(VkPhysicalDevice a_0, uint32_t* a_1,
                                                                    guest_layout<VkPhysicalDeviceToolProperties*> a_2) {
  return RepackedArrayQuery(a_1, a_2, [&](VkPhysicalDeviceToolProperties* out) {
    return fexldr_ptr_libvulkan_vkGetPhysicalDeviceToolPropertiesEXT(a_0, a_1, out);
  });
}

VkResult fexfn_impl_libvulkan_vkGetPhysicalDeviceFragmentShadingRatesKHR(VkPhysicalDevice a_0, uint32_t* a_1,
                                                                         guest_layout<VkPhysicalDeviceFragmentShadingRateKHR*> a_2) {
  return RepackedArrayQuery(a_1, a_2, [&](VkPhysicalDeviceFragmentShadingRateKHR* out) {
    return fexldr_ptr_libvulkan_vkGetPhysicalDeviceFragmentShadingRatesKHR(a_0, a_1, out);
  });
}
#endif

EXPORTS(libvulkan)
