/*
 * Guest-side Vulkan probe 4 — vulkaninfo-breadth reproducer (props2 chains + the Wayland leg).
 *
 * WHY THIS PROBE EXISTS
 * ---------------------
 * vulkaninfo core-dumps where vkcube (xcb and Xlib WSI) works. Its last log lines are the Xlib
 * display translation succeeding:
 *
 *     Opening host-side X11 display: 0x32b0bde5880 -> 0x3fff96ba7000 (name=:1)
 *
 * Code reading (2026-07-29) establishes that on the 64-bit thunk build there is NO pNext walking
 * and NO struct repacking for the property/feature/enumeration surface: the entire next_handlers /
 * VULKAN_DEFAULT_CUSTOM_REPACK machinery in ThunkLibs/libvulkan/Host.cpp (lines 783-2693) is
 * compiled out (#ifdef IS_32BIT_THUNK), and the generated 64-bit unpackers pass guest pointers
 * straight to host RADV. So the popular hypotheses — unknown pNext sType, array-of-struct repack —
 * have no code to go wrong in. Stages P1-P4 below prove that at runtime.
 *
 * The leading candidate instead: vulkaninfo creates one surface per available WSI in source order
 * XCB -> XLIB -> WAYLAND. The last log line is mid-Xlib-surface-creation; the next thing vulkaninfo
 * does that emits no logging is the WAYLAND leg. This host runs a Wayland session (the Xlib probes
 * note "Xwayland is fine", DISPLAY=:1), so WAYLAND_DISPLAY is set and the leg is taken. The Wayland
 * WSI is a recorded-broken path on this branch: docs/POWER9_PORT_PLAN.md crash matrix has
 * "vkmark (auto -> wayland) | SEGV, PC=0 in wl_listener", and libvulkan_interface.cpp passes
 * wl_display/wl_surface as opaque_type — raw guest pointers into host RADV, whose wayland event
 * dispatch then jumps to non-host-executable listener addresses.
 *
 * Stage W reproduces exactly that leg in isolation. If this probe survives P1-P4 and dies in W,
 * the vulkaninfo core dump is the known Wayland WSI defect, not a thunk-coverage gap.
 *
 * CHEAP CROSS-CHECK WITHOUT THIS PROBE: run `WAYLAND_DISPLAY= vulkaninfo`. If it completes (or
 * gets much further), same conclusion.
 *
 * BUILD (on the POWER9 host, with the crosstool-ng toolchain):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O1 -g \
 *       -I $HOME/Development/fex-ppc64le/External/Vulkan-Headers/include \
 *       -o probe_vk_props2 probe_vk_props2.c -ldl
 *
 * RUN:
 *   FEX ./probe_vk_props2            # stages P1-P4 always; stage W only if WAYLAND_DISPLAY is set
 *   PROBE_SKIP_WAYLAND=1 FEX ./probe_vk_props2   # force-skip stage W
 *
 * No link-time libs: libvulkan and libwayland-client are dlopen'd, wayland protocol wrappers are
 * hand-rolled over dlsym'd wl_proxy_* symbols (the inline helpers in wayland-client.h are just
 * these calls with fixed opcodes; the opcodes are stable protocol ABI).
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

/* Progress markers are flushed immediately: if the process dies mid-call, the last line printed is
 * the diagnosis. */
#define STEP(fmt, ...) do { printf("[step] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)

/* ---- hand-rolled wayland-client declarations (no header dependency) ---- */
struct wl_display;
struct wl_proxy;
struct wl_interface;

typedef struct wl_display* (*pfn_wl_display_connect)(const char*);
typedef void (*pfn_wl_display_disconnect)(struct wl_display*);
typedef int (*pfn_wl_display_roundtrip)(struct wl_display*);
typedef struct wl_proxy* (*pfn_wl_proxy_marshal_constructor)(struct wl_proxy*, uint32_t, const struct wl_interface*, ...);
typedef struct wl_proxy* (*pfn_wl_proxy_marshal_constructor_versioned)(struct wl_proxy*, uint32_t, const struct wl_interface*, uint32_t, ...);
typedef int (*pfn_wl_proxy_add_listener)(struct wl_proxy*, void (**)(void), void*);

#define WL_DISPLAY_GET_REGISTRY 1  /* wl_display request opcode */
#define WL_REGISTRY_BIND 0         /* wl_registry request opcode */
#define WL_COMPOSITOR_CREATE_SURFACE 0

/* VkWaylandSurfaceCreateInfoKHR, declared manually so we don't need the platform header. */
typedef struct {
    VkStructureType sType;
    const void* pNext;
    VkFlags flags;
    struct wl_display* display;
    struct wl_proxy* surface;
} probe_VkWaylandSurfaceCreateInfoKHR;
#define PROBE_STYPE_WAYLAND_SURFACE_CREATE_INFO ((VkStructureType)1000006000)
typedef VkResult (*pfn_vkCreateWaylandSurfaceKHR)(VkInstance, const probe_VkWaylandSurfaceCreateInfoKHR*,
                                                  const VkAllocationCallbacks*, VkSurfaceKHR*);

/* Registry listener state. NOTE: when the WaylandClient thunk is active, these guest functions are
 * invoked THROUGH the cross-arch host->guest trampoline — this is the recorded PC=0 crash site. */
static uint32_t g_compositor_name = 0;
static uint32_t g_compositor_version = 0;
static void on_global(void* data, struct wl_proxy* registry, uint32_t name, const char* iface, uint32_t version) {
    (void)data; (void)registry;
    if (iface && strcmp(iface, "wl_compositor") == 0) {
        g_compositor_name = name;
        g_compositor_version = version < 4 ? version : 4;
    }
}
static void on_global_remove(void* data, struct wl_proxy* registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static void* g_registry_listener[2]; /* {global, global_remove} — layout of struct wl_registry_listener */

int main(void) {
    printf("probe_vk_props2 — vulkaninfo-breadth probe: pNext chains, two-call arrays, Wayland leg\n");
    printf("The last [step] line printed is the diagnosis.\n\n");

    STEP("dlopen libvulkan.so.1 + resolve loader");
    void* lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "FAIL: dlopen(libvulkan.so.1): %s\n", dlerror()); return 1; }
    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
    if (!gipa) { fprintf(stderr, "FAIL: dlsym(vkGetInstanceProcAddr)\n"); return 1; }

    STEP("vkCreateInstance (api 1.1, VK_KHR_surface + VK_KHR_wayland_surface if taken later)");
    const char* exts[3];
    uint32_t next = 0;
    exts[next++] = "VK_KHR_surface";
    int want_wayland = getenv("WAYLAND_DISPLAY") && !getenv("PROBE_SKIP_WAYLAND");
    if (want_wayland) { exts[next++] = "VK_KHR_wayland_surface"; }
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "probe_vk_props2",
        .apiVersion = VK_API_VERSION_1_1,
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app,
        .enabledExtensionCount = next,
        .ppEnabledExtensionNames = exts,
    };
    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)gipa(NULL, "vkCreateInstance");
    VkInstance instance = VK_NULL_HANDLE;
    VkResult r = create_instance(&ici, NULL, &instance);
    if (r != VK_SUCCESS && want_wayland) {
        /* Host may not advertise wayland WSI at all — retry without it. */
        printf("        (retrying without VK_KHR_wayland_surface, first attempt -> %d)\n", r);
        want_wayland = 0;
        ici.enabledExtensionCount = 1;
        r = create_instance(&ici, NULL, &instance);
    }
    if (r != VK_SUCCESS) { fprintf(stderr, "FAIL: vkCreateInstance -> %d\n", r); return 1; }
    printf("        instance=%p\n", (void*)instance);

    STEP("vkEnumeratePhysicalDevices");
    PFN_vkEnumeratePhysicalDevices enum_dev =
        (PFN_vkEnumeratePhysicalDevices)gipa(instance, "vkEnumeratePhysicalDevices");
    uint32_t dev_count = 0;
    enum_dev(instance, &dev_count, NULL);
    if (dev_count == 0) { fprintf(stderr, "FAIL: zero devices\n"); return 1; }
    VkPhysicalDevice devs[8];
    if (dev_count > 8) dev_count = 8;
    enum_dev(instance, &dev_count, devs);
    VkPhysicalDevice gpu = devs[0];
    printf("        %u device(s), gpu[0]=%p\n", dev_count, (void*)gpu);

    PFN_vkGetPhysicalDeviceProperties2 props2 =
        (PFN_vkGetPhysicalDeviceProperties2)gipa(instance, "vkGetPhysicalDeviceProperties2");
    if (!props2) {
        props2 = (PFN_vkGetPhysicalDeviceProperties2)gipa(instance, "vkGetPhysicalDeviceProperties2KHR");
    }
    if (!props2) { fprintf(stderr, "FAIL: vkGetPhysicalDeviceProperties2(KHR) not resolvable\n"); return 1; }

    STEP("P1: vkGetPhysicalDeviceProperties2, chain: DriverProperties -> IDProperties");
    VkPhysicalDeviceIDProperties id_props = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES };
    VkPhysicalDeviceDriverProperties drv_props = {
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DRIVER_PROPERTIES, .pNext = &id_props };
    VkPhysicalDeviceProperties2 p2 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &drv_props };
    props2(gpu, &p2);
    printf("        device=%s driver=%s (%s)\n", p2.properties.deviceName, drv_props.driverName, drv_props.driverInfo);

    STEP("P2: vkGetPhysicalDeviceProperties2 with an UNKNOWN sType (0x6ffff000) in the chain");
    /* Simulates a guest built against newer headers than the thunk/driver: drivers must skip
     * unknown sTypes; on the 64-bit passthrough path the thunk never inspects them. On a 32-bit
     * thunk this same chain would hit the next_handlers abort — the asymmetry this stage records. */
    struct { VkStructureType sType; void* pNext; char payload[64]; } unknown_node =
        { (VkStructureType)0x6ffff000, NULL, {0} };
    drv_props.pNext = &unknown_node;
    p2.pNext = &drv_props;
    props2(gpu, &p2);
    printf("        survived unknown sType\n");

    STEP("P3: vkGetPhysicalDeviceFeatures2, chain: Vulkan11Features");
    PFN_vkGetPhysicalDeviceFeatures2 feats2 =
        (PFN_vkGetPhysicalDeviceFeatures2)gipa(instance, "vkGetPhysicalDeviceFeatures2");
    if (!feats2) feats2 = (PFN_vkGetPhysicalDeviceFeatures2)gipa(instance, "vkGetPhysicalDeviceFeatures2KHR");
    if (feats2) {
        VkPhysicalDeviceVulkan11Features v11 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_1_FEATURES };
        VkPhysicalDeviceFeatures2 f2 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2, .pNext = &v11 };
        feats2(gpu, &f2);
        printf("        samplerAnisotropy=%u multiview=%u\n", f2.features.samplerAnisotropy, v11.multiview);
    }

    STEP("P4: two-call arrays: queue families (props2), memory props2, format props2");
    PFN_vkGetPhysicalDeviceQueueFamilyProperties2 qf2 =
        (PFN_vkGetPhysicalDeviceQueueFamilyProperties2)gipa(instance, "vkGetPhysicalDeviceQueueFamilyProperties2");
    if (qf2) {
        uint32_t qf_count = 0;
        qf2(gpu, &qf_count, NULL);
        VkQueueFamilyProperties2 qfp[16];
        if (qf_count > 16) qf_count = 16;
        for (uint32_t i = 0; i < qf_count; ++i) {
            memset(&qfp[i], 0, sizeof qfp[i]);
            qfp[i].sType = VK_STRUCTURE_TYPE_QUEUE_FAMILY_PROPERTIES_2;
        }
        qf2(gpu, &qf_count, qfp);
        printf("        %u queue families, qf0 flags=0x%x\n", qf_count, qf_count ? qfp[0].queueFamilyProperties.queueFlags : 0);
    }
    PFN_vkGetPhysicalDeviceMemoryProperties2 mem2 =
        (PFN_vkGetPhysicalDeviceMemoryProperties2)gipa(instance, "vkGetPhysicalDeviceMemoryProperties2");
    if (mem2) {
        VkPhysicalDeviceMemoryProperties2 mp2 = { .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2 };
        mem2(gpu, &mp2);
        printf("        %u memory types / %u heaps\n", mp2.memoryProperties.memoryTypeCount, mp2.memoryProperties.memoryHeapCount);
    }
    PFN_vkGetPhysicalDeviceFormatProperties2 fmt2 =
        (PFN_vkGetPhysicalDeviceFormatProperties2)gipa(instance, "vkGetPhysicalDeviceFormatProperties2");
    if (fmt2) {
        VkFormatProperties2 fp2 = { .sType = VK_STRUCTURE_TYPE_FORMAT_PROPERTIES_2 };
        fmt2(gpu, VK_FORMAT_B8G8R8A8_UNORM, &fp2);
        printf("        B8G8R8A8_UNORM optimal=0x%x\n", fp2.formatProperties.optimalTilingFeatures);
    }

    printf("\n[P-stages PASS] No pNext/array marshalling failure on the 64-bit passthrough path.\n\n");
    fflush(stdout);

    if (!want_wayland) {
        printf("RESULT: PASS (Wayland leg skipped: %s)\n",
               getenv("PROBE_SKIP_WAYLAND") ? "PROBE_SKIP_WAYLAND set" : "WAYLAND_DISPLAY unset or ext missing");
        return 0;
    }

    /* ---- Stage W: the leg vulkaninfo enters right after its last log line ---- */

    STEP("W1: dlopen libwayland-client.so.0");
    void* wl = dlopen("libwayland-client.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!wl) { printf("RESULT: PASS (no guest libwayland-client: %s)\n", dlerror()); return 0; }

    pfn_wl_display_connect wl_display_connect_ = (pfn_wl_display_connect)dlsym(wl, "wl_display_connect");
    pfn_wl_display_roundtrip wl_display_roundtrip_ = (pfn_wl_display_roundtrip)dlsym(wl, "wl_display_roundtrip");
    pfn_wl_display_disconnect wl_display_disconnect_ = (pfn_wl_display_disconnect)dlsym(wl, "wl_display_disconnect");
    pfn_wl_proxy_marshal_constructor wl_marshal_ctor_ =
        (pfn_wl_proxy_marshal_constructor)dlsym(wl, "wl_proxy_marshal_constructor");
    pfn_wl_proxy_marshal_constructor_versioned wl_marshal_ctor_ver_ =
        (pfn_wl_proxy_marshal_constructor_versioned)dlsym(wl, "wl_proxy_marshal_constructor_versioned");
    pfn_wl_proxy_add_listener wl_add_listener_ = (pfn_wl_proxy_add_listener)dlsym(wl, "wl_proxy_add_listener");
    const struct wl_interface* registry_iface = (const struct wl_interface*)dlsym(wl, "wl_registry_interface");
    const struct wl_interface* compositor_iface = (const struct wl_interface*)dlsym(wl, "wl_compositor_interface");
    const struct wl_interface* surface_iface = (const struct wl_interface*)dlsym(wl, "wl_surface_interface");
    if (!wl_display_connect_ || !wl_display_roundtrip_ || !wl_marshal_ctor_ || !wl_marshal_ctor_ver_ ||
        !wl_add_listener_ || !registry_iface || !compositor_iface || !surface_iface) {
        fprintf(stderr, "FAIL: missing libwayland-client symbols\n");
        return 1;
    }

    STEP("W2: wl_display_connect(NULL)  (WAYLAND_DISPLAY=%s)", getenv("WAYLAND_DISPLAY"));
    struct wl_display* wdpy = wl_display_connect_(NULL);
    if (!wdpy) { printf("RESULT: PASS (wayland connect failed; leg not reachable)\n"); return 0; }
    printf("        wl_display=%p  <-- host VA (0x3fff...) means WaylandClient thunk active; guest heap VA means raw guest object\n", (void*)wdpy);

    STEP("W3: get_registry + add_listener + roundtrip  <-- guest listener dispatch crossing");
    struct wl_proxy* registry = wl_marshal_ctor_((struct wl_proxy*)wdpy, WL_DISPLAY_GET_REGISTRY, registry_iface, NULL);
    g_registry_listener[0] = (void*)on_global;
    g_registry_listener[1] = (void*)on_global_remove;
    wl_add_listener_(registry, (void (**)(void))g_registry_listener, NULL);
    wl_display_roundtrip_(wdpy);
    printf("        wl_compositor global: name=%u version=%u\n", g_compositor_name, g_compositor_version);
    if (!g_compositor_name) { fprintf(stderr, "FAIL: no wl_compositor advertised\n"); return 1; }

    STEP("W4: bind wl_compositor + create wl_surface");
    struct wl_proxy* compositor = wl_marshal_ctor_ver_(registry, WL_REGISTRY_BIND, compositor_iface,
                                                       g_compositor_version, g_compositor_name,
                                                       "wl_compositor", g_compositor_version, NULL);
    if (!compositor) { fprintf(stderr, "FAIL: wl_registry.bind(wl_compositor)\n"); return 1; }
    struct wl_proxy* wsurf = wl_marshal_ctor_(compositor, WL_COMPOSITOR_CREATE_SURFACE, surface_iface, NULL);
    if (!wsurf) { fprintf(stderr, "FAIL: wl_compositor.create_surface\n"); return 1; }
    printf("        wl_surface=%p\n", (void*)wsurf);

    STEP("W5: vkCreateWaylandSurfaceKHR");
    pfn_vkCreateWaylandSurfaceKHR create_wsurface =
        (pfn_vkCreateWaylandSurfaceKHR)gipa(instance, "vkCreateWaylandSurfaceKHR");
    if (!create_wsurface) { fprintf(stderr, "FAIL: vkCreateWaylandSurfaceKHR not resolvable\n"); return 1; }
    probe_VkWaylandSurfaceCreateInfoKHR wci = {
        .sType = PROBE_STYPE_WAYLAND_SURFACE_CREATE_INFO,
        .display = wdpy,
        .surface = wsurf,
    };
    VkSurfaceKHR vksurf = VK_NULL_HANDLE;
    r = create_wsurface(instance, &wci, NULL, &vksurf);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "vkCreateWaylandSurfaceKHR -> %d (clean failure, not a crash — informative)\n", r);
        return 1;
    }
    printf("        surface=%p\n", (void*)vksurf);

    STEP("W6: vkGetPhysicalDeviceSurfaceSupportKHR  <-- host RADV walks the wl_display here. Expected failure point.");
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR surf_support =
        (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)gipa(instance, "vkGetPhysicalDeviceSurfaceSupportKHR");
    VkBool32 supported = VK_FALSE;
    r = surf_support(gpu, 0, vksurf, &supported);
    printf("        -> %d, supported=%u\n", r, supported);

    STEP("W7: vkGetPhysicalDeviceSurfaceFormatsKHR (two-call, on the wayland surface)");
    PFN_vkGetPhysicalDeviceSurfaceFormatsKHR surf_formats =
        (PFN_vkGetPhysicalDeviceSurfaceFormatsKHR)gipa(instance, "vkGetPhysicalDeviceSurfaceFormatsKHR");
    uint32_t fmt_count = 0;
    surf_formats(gpu, vksurf, &fmt_count, NULL);
    printf("        %u surface formats\n", fmt_count);

    printf("\nRESULT: PASS — including the full Wayland leg. If vulkaninfo still core dumps,\n"
           "the defect is NOT the wayland surface sweep; capture a backtrace from the core.\n");
    if (wl_display_disconnect_) wl_display_disconnect_(wdpy);
    return 0;
}
