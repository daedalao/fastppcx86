/*
 * Guest-side Vulkan probe 2 — does xcb WSI survive the cross-arch boundary?
 *
 * Run probe_vk_enum FIRST. This probe only adds the surface layer on top of it, so if that one
 * fails there is nothing to learn here.
 *
 * WHAT THIS TESTS THAT PROBE 1 DOES NOT
 * ------------------------------------
 * Probe 1 proves the guest can reach the host driver. This one adds the piece that has historically
 * broken on this port: window-system integration across the guest/host boundary. Per commit
 * d91959d2f, xcb is the *only* WSI that worked on POWER8, and it worked for a specific reason —
 *
 *   "vkcube/vkmark-xcb survive because XCB WSI never registers a guest callback through
 *    MakeHostTrampolineForGuestFunctionAt; its only cross-arch translation is
 *    GuestToHostConnection (xcb_connection_t*), which is opaque-pointer data, not a callable
 *    address."
 *
 * So this exercises opaque-handle translation (an xcb_connection_t* created in the guest being
 * usable by the host driver) while deliberately avoiding the guest-callback trampoline path that
 * SEGVs under Xlib and Wayland. A pass here reproduces the known-good POWER8 configuration on
 * POWER9. It does NOT say anything about the Xlib bug — that is a separate, expected failure.
 *
 * BUILD (on the POWER9 host):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O1 -g \
 *       -I $HOME/Development/fex-ppc64le/External/Vulkan-Headers/include \
 *       -idirafter /usr/include \
 *       -o probe_vk_xcb probe_vk_xcb.c -ldl
 *
 *   xcb headers are architecture-agnostic, hence -idirafter /usr/include, the same approach the
 *   thunk build uses. libxcb itself is dlopen'd, so no link-time library is needed.
 *
 * RUN (needs a display):
 *   DISPLAY=:0 FEX ./probe_vk_xcb
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <xcb/xcb.h>

#define VK_NO_PROTOTYPES
#define VK_USE_PLATFORM_XCB_KHR
#include <vulkan/vulkan.h>

/* xcb entry points resolved at runtime so no link-time libxcb is required. */
typedef xcb_connection_t* (*pfn_xcb_connect)(const char*, int*);
typedef int (*pfn_xcb_connection_has_error)(xcb_connection_t*);
typedef const struct xcb_setup_t* (*pfn_xcb_get_setup)(xcb_connection_t*);
typedef xcb_screen_iterator_t (*pfn_xcb_setup_roots_iterator)(const xcb_setup_t*);
typedef void (*pfn_xcb_screen_next)(xcb_screen_iterator_t*);
typedef uint32_t (*pfn_xcb_generate_id)(xcb_connection_t*);
typedef xcb_void_cookie_t (*pfn_xcb_create_window)(xcb_connection_t*, uint8_t, xcb_window_t,
                                                   xcb_window_t, int16_t, int16_t, uint16_t,
                                                   uint16_t, uint16_t, uint16_t, xcb_visualid_t,
                                                   uint32_t, const void*);
typedef xcb_void_cookie_t (*pfn_xcb_map_window)(xcb_connection_t*, xcb_window_t);
typedef int (*pfn_xcb_flush)(xcb_connection_t*);
typedef void (*pfn_xcb_disconnect)(xcb_connection_t*);

int main(void) {
    printf("probe_vk_xcb — guest x86_64 Vulkan + xcb WSI through the FEX thunk chain\n\n");

    /* ---- xcb side ---- */
    void* xcb = dlopen("libxcb.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!xcb) {
        fprintf(stderr, "FAIL: dlopen(libxcb.so.1): %s\n", dlerror());
        return 1;
    }
    pfn_xcb_connect              c_connect   = (pfn_xcb_connect)dlsym(xcb, "xcb_connect");
    pfn_xcb_connection_has_error c_haserr    = (pfn_xcb_connection_has_error)dlsym(xcb, "xcb_connection_has_error");
    pfn_xcb_get_setup            c_setup     = (pfn_xcb_get_setup)dlsym(xcb, "xcb_get_setup");
    pfn_xcb_setup_roots_iterator c_roots     = (pfn_xcb_setup_roots_iterator)dlsym(xcb, "xcb_setup_roots_iterator");
    pfn_xcb_screen_next          c_screennext= (pfn_xcb_screen_next)dlsym(xcb, "xcb_screen_next");
    pfn_xcb_generate_id          c_genid     = (pfn_xcb_generate_id)dlsym(xcb, "xcb_generate_id");
    pfn_xcb_create_window        c_createwin = (pfn_xcb_create_window)dlsym(xcb, "xcb_create_window");
    pfn_xcb_map_window           c_mapwin    = (pfn_xcb_map_window)dlsym(xcb, "xcb_map_window");
    pfn_xcb_flush                c_flush     = (pfn_xcb_flush)dlsym(xcb, "xcb_flush");
    pfn_xcb_disconnect           c_disc      = (pfn_xcb_disconnect)dlsym(xcb, "xcb_disconnect");
    if (!c_connect || !c_haserr || !c_setup || !c_roots || !c_screennext || !c_genid ||
        !c_createwin || !c_flush) {
        fprintf(stderr, "FAIL: could not resolve required xcb symbols\n");
        return 1;
    }

    int screen_num = 0;
    xcb_connection_t* conn = c_connect(NULL, &screen_num);
    if (!conn || c_haserr(conn)) {
        fprintf(stderr, "FAIL: xcb_connect failed (DISPLAY set? currently \"%s\")\n",
                getenv("DISPLAY") ? getenv("DISPLAY") : "(unset)");
        return 1;
    }
    printf("xcb_connect                       OK  (conn=%p, screen=%d)\n", (void*)conn, screen_num);

    /* Walk to the requested screen. xcb_screen_t is followed by a variable-length xcb_depth_t
     * array, so its stride is not sizeof(xcb_screen_t) — this is exactly why xcb ships
     * xcb_screen_next() and callers must not inline the advance. */
    xcb_screen_iterator_t it = c_roots(c_setup(conn));
    for (int i = 0; i < screen_num && it.rem > 1; ++i) {
        c_screennext(&it);
    }
    if (!it.data) { fprintf(stderr, "FAIL: no xcb screen\n"); return 1; }
    xcb_screen_t* screen = it.data;

    xcb_window_t win = c_genid(conn);
    uint32_t mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
    uint32_t values[2] = { screen->black_pixel, XCB_EVENT_MASK_EXPOSURE };
    c_createwin(conn, XCB_COPY_FROM_PARENT, win, screen->root, 0, 0, 320, 240, 0,
                XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual, mask, values);
    if (c_mapwin) { c_mapwin(conn, win); }
    c_flush(conn);
    printf("xcb window created + mapped       OK  (win=0x%x, 320x240)\n", win);

    /* ---- vulkan side ---- */
    void* lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "FAIL: dlopen(libvulkan.so.1): %s\n", dlerror()); return 1; }
    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
    if (!gipa) { fprintf(stderr, "FAIL: dlsym(vkGetInstanceProcAddr)\n"); return 1; }

    const char* exts[] = { VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_XCB_SURFACE_EXTENSION_NAME };
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "probe_vk_xcb",
        .apiVersion = VK_API_VERSION_1_0,
    };
    VkInstanceCreateInfo ici = {
        .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
        .pApplicationInfo = &app,
        .enabledExtensionCount = 2,
        .ppEnabledExtensionNames = exts,
    };

    PFN_vkCreateInstance create_instance = (PFN_vkCreateInstance)gipa(NULL, "vkCreateInstance");
    VkInstance instance = VK_NULL_HANDLE;
    VkResult r = create_instance(&ici, NULL, &instance);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "FAIL: vkCreateInstance with surface extensions -> %d\n", r);
        fprintf(stderr, "  If probe_vk_enum passed and this did not, the surface extensions are\n"
                        "  not being advertised across the thunk boundary.\n");
        return 1;
    }
    printf("vkCreateInstance (+surface exts)  OK\n");

    PFN_vkCreateXcbSurfaceKHR create_surface =
        (PFN_vkCreateXcbSurfaceKHR)gipa(instance, "vkCreateXcbSurfaceKHR");
    if (!create_surface) {
        fprintf(stderr, "FAIL: vkCreateXcbSurfaceKHR not resolvable\n");
        return 1;
    }

    VkXcbSurfaceCreateInfoKHR sci = {
        .sType = VK_STRUCTURE_TYPE_XCB_SURFACE_CREATE_INFO_KHR,
        .connection = conn,
        .window = win,
    };
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    r = create_surface(instance, &sci, NULL, &surface);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "\nFAIL: vkCreateXcbSurfaceKHR -> %d\n", r);
        fprintf(stderr, "  This is the cross-arch opaque-handle translation failing: the guest's\n"
                        "  xcb_connection_t* did not survive into the host driver. See\n"
                        "  fex_custom_repack_entry for VkXcbSurfaceCreateInfoKHR in\n"
                        "  ThunkLibs/libvulkan/Host.cpp, which calls x11_manager.GuestToHostConnection.\n");
        return 1;
    }
    printf("vkCreateXcbSurfaceKHR             OK  (surface=%p)\n", (void*)surface);
    printf("  ^ the guest's xcb_connection_t* was translated into a host connection\n");

    /* Confirm the driver will actually present to it. */
    PFN_vkEnumeratePhysicalDevices enum_dev =
        (PFN_vkEnumeratePhysicalDevices)gipa(instance, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceSurfaceSupportKHR surf_support =
        (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)gipa(instance, "vkGetPhysicalDeviceSurfaceSupportKHR");
    PFN_vkGetPhysicalDeviceProperties get_props =
        (PFN_vkGetPhysicalDeviceProperties)gipa(instance, "vkGetPhysicalDeviceProperties");

    uint32_t count = 0;
    if (enum_dev) { enum_dev(instance, &count, NULL); }
    if (count && surf_support && get_props) {
        VkPhysicalDevice* devs = calloc(count, sizeof *devs);
        enum_dev(instance, &count, devs);
        for (uint32_t i = 0; i < count; ++i) {
            VkPhysicalDeviceProperties p;
            memset(&p, 0, sizeof p);
            get_props(devs[i], &p);
            VkBool32 supported = VK_FALSE;
            /* queue family 0 is a reasonable probe for a graphics-capable device */
            surf_support(devs[i], 0, surface, &supported);
            printf("  device[%u] %-40s present-capable(qf0): %s\n",
                   i, p.deviceName, supported ? "YES" : "no");
        }
        free(devs);
    }

    printf("\nRESULT: PASS — xcb WSI works across the cross-arch boundary.\n"
           "  This reproduces the configuration d91959d2f recorded as working on POWER8.\n"
           "  It says nothing about Xlib or Wayland, which fail for a different reason\n"
           "  (guest-callback trampolines, not opaque-handle translation).\n");

    sleep(1); /* leave the window up briefly so it is visibly mapped */
    if (c_disc) { c_disc(conn); }
    return 0;
}
