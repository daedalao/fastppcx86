/*
 * Guest-side Vulkan probe 1 — does the thunk chain reach the host driver?
 *
 * Built as an x86_64 GUEST binary and run under FEX on the POWER9 host. It answers exactly one
 * question, with no window, no surface and no WSI involved:
 *
 *     guest stub -> marshalling -> host thunk -> native ppc64le RADV -> GPU
 *
 * WHY THIS IS A CLEAN SIGNAL
 * --------------------------
 * The discrimination is unusually sharp, because the two outcomes cannot be confused:
 *
 *   * Thunk working    -> physical devices are enumerated and you see the real GPU, e.g.
 *                         "AMD Radeon RX 7900 XTX (RADV NAVI31)". Only the *host's* driver can
 *                         report that; there is no x86_64 driver on this machine to fake it.
 *   * Thunk NOT active -> the guest resolves the rootfs's own x86_64 libvulkan, which finds no
 *                         usable ICD, so vkCreateInstance fails with
 *                         VK_ERROR_INCOMPATIBLE_DRIVER or zero devices are enumerated.
 *
 * So a device name is proof of the whole chain, and its absence localises the failure without
 * needing a second experiment.
 *
 * Deliberately loads libvulkan by dlopen() rather than linking against it. That needs no link-time
 * library or dev package in the sysroot, and it exercises the same path a real application (and
 * DXVK) uses: FEX's ThunksDB overlays the guest's "libvulkan.so.1" with libvulkan-guest.so.
 *
 * BUILD (on the POWER9 host, with the crosstool-ng toolchain):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O1 -g \
 *       -I $HOME/Development/fex-ppc64le/External/Vulkan-Headers/include \
 *       -o probe_vk_enum probe_vk_enum.c -ldl
 *
 * RUN:
 *   FEX ./probe_vk_enum
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

static const char* res_str(VkResult r) {
    switch (r) {
    case VK_SUCCESS:                        return "VK_SUCCESS";
    case VK_INCOMPLETE:                     return "VK_INCOMPLETE";
    case VK_ERROR_OUT_OF_HOST_MEMORY:       return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:     return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_INITIALIZATION_FAILED:    return "VK_ERROR_INITIALIZATION_FAILED";
    case VK_ERROR_LAYER_NOT_PRESENT:        return "VK_ERROR_LAYER_NOT_PRESENT";
    case VK_ERROR_EXTENSION_NOT_PRESENT:    return "VK_ERROR_EXTENSION_NOT_PRESENT";
    case VK_ERROR_INCOMPATIBLE_DRIVER:      return "VK_ERROR_INCOMPATIBLE_DRIVER";
    default:                                return "VK_ERROR_<other>";
    }
}

static const char* dev_type_str(VkPhysicalDeviceType t) {
    switch (t) {
    case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU: return "integrated GPU";
    case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:   return "DISCRETE GPU";
    case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU:    return "virtual GPU";
    case VK_PHYSICAL_DEVICE_TYPE_CPU:            return "CPU (software)";
    default:                                     return "other";
    }
}

int main(void) {
    printf("probe_vk_enum — guest x86_64 Vulkan through the FEX thunk chain\n");
    printf("(no window, no surface, no WSI)\n\n");

    void* lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        fprintf(stderr, "FAIL: dlopen(\"libvulkan.so.1\"): %s\n", dlerror());
        fprintf(stderr, "  The guest could not load a Vulkan loader at all. Check that the rootfs\n"
                        "  has /usr/lib/x86_64-linux-gnu/libvulkan.so.1 and that ThunksDB has\n"
                        "  \"Vulkan\": 1.\n");
        return 1;
    }
    printf("dlopen(libvulkan.so.1)            OK\n");

    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
    if (!gipa) {
        fprintf(stderr, "FAIL: dlsym(vkGetInstanceProcAddr): %s\n", dlerror());
        return 1;
    }
    printf("dlsym(vkGetInstanceProcAddr)      OK  (%p)\n", (void*)gipa);

    /* Global-scope entry points are fetched with a NULL instance. */
    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)gipa(NULL, "vkCreateInstance");
    if (!create_instance) {
        fprintf(stderr, "FAIL: vkGetInstanceProcAddr(NULL, \"vkCreateInstance\") returned NULL\n");
        fprintf(stderr, "  The loader resolved but will not hand out entry points. Under a thunk\n"
                        "  this usually means the guest->host call returned without marshalling.\n");
        return 1;
    }
    printf("vkGetInstanceProcAddr(vkCreateInstance) OK\n");

    PFN_vkEnumerateInstanceVersion enum_ver =
        (PFN_vkEnumerateInstanceVersion)gipa(NULL, "vkEnumerateInstanceVersion");
    uint32_t inst_ver = VK_API_VERSION_1_0;
    if (enum_ver && enum_ver(&inst_ver) == VK_SUCCESS) {
        printf("instance API version              %u.%u.%u\n",
               VK_VERSION_MAJOR(inst_ver), VK_VERSION_MINOR(inst_ver), VK_VERSION_PATCH(inst_ver));
    }

    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "probe_vk_enum",
        .applicationVersion = 1,
        .pEngineName = "none",
        .engineVersion = 1,
        .apiVersion = VK_API_VERSION_1_0,
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app,
    };

    VkInstance instance = VK_NULL_HANDLE;
    VkResult r = create_instance(&ici, NULL, &instance);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "FAIL: vkCreateInstance -> %s (%d)\n", res_str(r), r);
        if (r == VK_ERROR_INCOMPATIBLE_DRIVER) {
            fprintf(stderr, "  INCOMPATIBLE_DRIVER is the signature of the thunk NOT being active:\n"
                            "  the guest reached a real x86_64 loader, which found no usable ICD\n"
                            "  because there is no x86_64 GPU driver on this machine. Check\n"
                            "  FEX_THUNKGUESTLIBS / FEX_THUNKHOSTLIBS and ThunksDB \"Vulkan\": 1.\n");
        }
        return 1;
    }
    printf("vkCreateInstance                  OK  (instance=%p)\n\n", (void*)instance);

    PFN_vkEnumeratePhysicalDevices enum_dev =
        (PFN_vkEnumeratePhysicalDevices)gipa(instance, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties get_props =
        (PFN_vkGetPhysicalDeviceProperties)gipa(instance, "vkGetPhysicalDeviceProperties");
    PFN_vkDestroyInstance destroy_instance =
        (PFN_vkDestroyInstance)gipa(instance, "vkDestroyInstance");

    if (!enum_dev || !get_props) {
        fprintf(stderr, "FAIL: instance-scope entry points not resolvable "
                        "(enum=%p props=%p)\n", (void*)enum_dev, (void*)get_props);
        return 1;
    }

    uint32_t count = 0;
    r = enum_dev(instance, &count, NULL);
    if (r != VK_SUCCESS && r != VK_INCOMPLETE) {
        fprintf(stderr, "FAIL: vkEnumeratePhysicalDevices(count) -> %s\n", res_str(r));
        return 1;
    }
    printf("physical device count             %u\n", count);
    if (count == 0) {
        fprintf(stderr, "\nFAIL: zero physical devices.\n"
                        "  The loader worked but no driver was reachable. Same meaning as\n"
                        "  INCOMPATIBLE_DRIVER above: most likely the thunk is not active and the\n"
                        "  guest is talking to a real x86_64 loader with no ICD to find.\n");
        return 1;
    }

    VkPhysicalDevice* devs = calloc(count, sizeof *devs);
    if (!devs) { fprintf(stderr, "FAIL: out of memory\n"); return 1; }
    r = enum_dev(instance, &count, devs);
    if (r != VK_SUCCESS && r != VK_INCOMPLETE) {
        fprintf(stderr, "FAIL: vkEnumeratePhysicalDevices(list) -> %s\n", res_str(r));
        return 1;
    }

    for (uint32_t i = 0; i < count; ++i) {
        VkPhysicalDeviceProperties p;
        memset(&p, 0, sizeof p);
        get_props(devs[i], &p);
        printf("\ndevice[%u]\n", i);
        printf("  name            %s\n", p.deviceName);
        printf("  type            %s\n", dev_type_str(p.deviceType));
        printf("  vendorID        0x%04x   deviceID 0x%04x\n", p.vendorID, p.deviceID);
        printf("  apiVersion      %u.%u.%u\n",
               VK_VERSION_MAJOR(p.apiVersion), VK_VERSION_MINOR(p.apiVersion),
               VK_VERSION_PATCH(p.apiVersion));
        printf("  driverVersion   0x%08x\n", p.driverVersion);
    }

    free(devs);
    if (destroy_instance) {
        destroy_instance(instance, NULL);
        printf("\nvkDestroyInstance                 OK\n");
    }

    printf("\nRESULT: PASS — the guest enumerated a real device through the thunk chain.\n"
           "  A device name here can only have come from the host's native driver; there is no\n"
           "  x86_64 driver on this machine that could have produced it. Guest stub, marshalling,\n"
           "  host thunk and native RADV are all working.\n");
    return 0;
}
