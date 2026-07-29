/*
 * Guest-side Vulkan probe 3 — minimal reproducer for the Xlib WSI failure.
 *
 * THIS PROBE IS EXPECTED TO FAIL. That is the point.
 *
 * WHAT IT IS FOR
 * --------------
 * Commit d91959d2f records that on POWER8, Xlib and Wayland WSI both SEGV at PC=0 while xcb works,
 * and identifies the mechanism:
 *
 *   X11Manager::GuestToHostDisplay -> CallbackUnpack::CallGuestPtr
 *   -> dispatches to InstanceInfo.CallCallback (FEX::HLE::CallCallback)
 *   -> sets guest RIP = InstanceInfo.GuestUnpacker, which is a HOST VA
 *      (0x3fffxxxx_xxxx, inside libvulkan-host.so), not a guest x86_64 address;
 *      the JIT then fetches from unmapped memory and lands at PC=0.
 *
 * That is the highest-value open problem in this repository, because Wine's winex11 requests Xlib
 * surfaces for winevulkan — so it gates the entire Proton path. Until now it has only been
 * reproducible through SuperTuxKart, which is a poor debugging vehicle. This is the same failure in
 * ~150 lines of source we control, built with -g.
 *
 * WHAT A FAILURE HERE NOW MEANS (this has changed)
 * ------------------------------------------------
 * The leading hypothesis used to be a stale or ABI-mismatched libvulkan-guest.so, since the README
 * records guest stubs being built on a separate x86_64 machine and copied back. **That hypothesis is
 * now dead**: the guest and host thunks in use were built together, from the same commit, by the
 * crosstool-ng toolchain on this machine. If the bug still reproduces, staleness is not the cause.
 *
 * Remaining candidates, in order:
 *   1. The TLS side-channel. On PPC64LE the trampoline writes &InstanceInfo into
 *      __fex_callback_guestcall_ptr and the host thunk reads it back through an exported getter one
 *      PLT call later (Thunks.cpp, commit 62ea24ce4). x86 and ARM pass this in a register with no
 *      shared mutable state. Any nested or reentrant trampoline dispatch in that window would have
 *      the outer callback read the inner one's InstanceInfo.
 *   2. The values are already wrong when the host receives them, i.e. guest-side or in the
 *      generated unpacking.
 *
 * Three earlier hypotheses are already eliminated and should not be re-investigated: host_layout
 * does not transform these values; TrampolineInstanceInfo is populated with designated initialisers
 * so its fields cannot be transposed; and the hardcoded PPC64LE InstanceInfo offset of 40 is
 * correct. See docs/POWER9_PORT_PLAN.md, "The graphics path".
 *
 * HOW TO USE THE RESULT
 * ---------------------
 * The probe prints a progress marker before each step, so the last line printed localises the
 * failure without a debugger. Expected failure point is at or just after surface creation, when the
 * host driver first calls back into guest X11 code.
 *
 * If it does fail, the decisive next observation is a breakpoint on
 *   fexfn_impl_libvulkan_Vulkan_SetGuestXSync   (ThunkLibs/libvulkan/Host.cpp)
 * printing both uintptr_t arguments. Guest VAs at entry mean the corruption is downstream
 * (candidate 1); host VAs at entry mean it is upstream (candidate 2). That single observation
 * partitions the search.
 *
 * BUILD (on the POWER9 host):
 *   XT=$HOME/Development/fexrootfs/x-tools/x86_64-linux-gnu
 *   $XT/bin/x86_64-linux-gnu-gcc -O1 -g \
 *       -I $HOME/Development/fex-ppc64le/External/Vulkan-Headers/include \
 *       -idirafter /usr/include \
 *       -o probe_vk_xlib probe_vk_xlib.c -ldl
 *
 * RUN (needs a display; Xwayland is fine):
 *   DISPLAY=:1 FEX ./probe_vk_xlib
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <X11/Xlib.h>

#define VK_NO_PROTOTYPES
#define VK_USE_PLATFORM_XLIB_KHR
#include <vulkan/vulkan.h>

/* Progress markers are flushed immediately: if the process dies mid-call, the last line printed is
 * the diagnosis. */
#define STEP(fmt, ...) do { printf("[step] " fmt "\n", ##__VA_ARGS__); fflush(stdout); } while (0)

typedef Display* (*pfn_XOpenDisplay)(const char*);
typedef int (*pfn_XCloseDisplay)(Display*);
typedef Window (*pfn_XCreateSimpleWindow)(Display*, Window, int, int, unsigned, unsigned,
                                          unsigned, unsigned long, unsigned long);
typedef int (*pfn_XMapWindow)(Display*, Window);
typedef int (*pfn_XFlush)(Display*);
typedef int (*pfn_XSync)(Display*, Bool);
typedef Window (*pfn_XDefaultRootWindow)(Display*);
typedef int (*pfn_XDefaultScreen)(Display*);
typedef unsigned long (*pfn_XBlackPixel)(Display*, int);

int main(void) {
    printf("probe_vk_xlib — minimal reproducer for the Xlib WSI cross-arch failure\n");
    printf("EXPECTED TO FAIL. The last [step] line printed is the diagnosis.\n\n");

    STEP("dlopen libX11.so.6");
    void* x11 = dlopen("libX11.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!x11) { fprintf(stderr, "FAIL: dlopen(libX11.so.6): %s\n", dlerror()); return 1; }

    pfn_XOpenDisplay        XOpenDisplay_       = (pfn_XOpenDisplay)dlsym(x11, "XOpenDisplay");
    pfn_XCloseDisplay       XCloseDisplay_      = (pfn_XCloseDisplay)dlsym(x11, "XCloseDisplay");
    pfn_XCreateSimpleWindow XCreateSimpleWindow_= (pfn_XCreateSimpleWindow)dlsym(x11, "XCreateSimpleWindow");
    pfn_XMapWindow          XMapWindow_         = (pfn_XMapWindow)dlsym(x11, "XMapWindow");
    pfn_XFlush              XFlush_             = (pfn_XFlush)dlsym(x11, "XFlush");
    pfn_XSync               XSync_              = (pfn_XSync)dlsym(x11, "XSync");
    pfn_XDefaultRootWindow  XDefaultRootWindow_ = (pfn_XDefaultRootWindow)dlsym(x11, "XDefaultRootWindow");
    pfn_XDefaultScreen      XDefaultScreen_     = (pfn_XDefaultScreen)dlsym(x11, "XDefaultScreen");
    pfn_XBlackPixel         XBlackPixel_        = (pfn_XBlackPixel)dlsym(x11, "XBlackPixel");
    if (!XOpenDisplay_ || !XCreateSimpleWindow_ || !XMapWindow_ || !XFlush_ ||
        !XDefaultRootWindow_ || !XDefaultScreen_ || !XBlackPixel_) {
        fprintf(stderr, "FAIL: could not resolve required Xlib symbols\n");
        return 1;
    }

    STEP("XOpenDisplay(\"%s\")", getenv("DISPLAY") ? getenv("DISPLAY") : "(unset)");
    Display* dpy = XOpenDisplay_(NULL);
    if (!dpy) {
        fprintf(stderr, "FAIL: XOpenDisplay returned NULL (DISPLAY=%s)\n",
                getenv("DISPLAY") ? getenv("DISPLAY") : "(unset)");
        return 1;
    }
    printf("        display=%p\n", (void*)dpy);

    STEP("XCreateSimpleWindow + XMapWindow");
    int screen = XDefaultScreen_(dpy);
    Window root = XDefaultRootWindow_(dpy);
    Window win = XCreateSimpleWindow_(dpy, root, 0, 0, 320, 240, 0,
                                      XBlackPixel_(dpy, screen), XBlackPixel_(dpy, screen));
    XMapWindow_(dpy, win);
    XFlush_(dpy);
    printf("        window=0x%lx\n", (unsigned long)win);

    /* If the guest-callback registration is broken, an explicit XSync through the guest's own Xlib
     * is still fine — it never crosses the boundary. The crossing happens when the *host* driver
     * calls back into guest X11 code, below. */
    if (XSync_) { XSync_(dpy, False); }

    STEP("dlopen libvulkan.so.1 + resolve loader");
    void* lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "FAIL: dlopen(libvulkan.so.1): %s\n", dlerror()); return 1; }
    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
    if (!gipa) { fprintf(stderr, "FAIL: dlsym(vkGetInstanceProcAddr)\n"); return 1; }

    STEP("vkCreateInstance with VK_KHR_xlib_surface");
    const char* exts[] = { VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_XLIB_SURFACE_EXTENSION_NAME };
    VkApplicationInfo app = {
        .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
        .pApplicationName = "probe_vk_xlib",
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
        fprintf(stderr, "FAIL: vkCreateInstance -> %d\n", r);
        fprintf(stderr, "  If probe_vk_xcb passed and this did not, VK_KHR_xlib_surface is not\n"
                        "  being advertised across the thunk boundary — a different and more\n"
                        "  tractable problem than the callback bug.\n");
        return 1;
    }

    STEP("resolve vkCreateXlibSurfaceKHR");
    PFN_vkCreateXlibSurfaceKHR create_surface =
        (PFN_vkCreateXlibSurfaceKHR)gipa(instance, "vkCreateXlibSurfaceKHR");
    if (!create_surface) {
        fprintf(stderr, "FAIL: vkCreateXlibSurfaceKHR not resolvable\n");
        return 1;
    }

    STEP("vkCreateXlibSurfaceKHR  <-- the crossing. Expected failure point.");
    VkXlibSurfaceCreateInfoKHR sci = {
        .sType = VK_STRUCTURE_TYPE_XLIB_SURFACE_CREATE_INFO_KHR,
        .dpy = dpy,
        .window = win,
    };
    VkSurfaceKHR surface = VK_NULL_HANDLE;
    r = create_surface(instance, &sci, NULL, &surface);
    if (r != VK_SUCCESS) {
        fprintf(stderr, "\nvkCreateXlibSurfaceKHR -> %d (did not crash, but failed)\n", r);
        fprintf(stderr, "  A clean error rather than a SEGV is itself informative: the crossing was\n"
                        "  attempted and rejected rather than jumping to a bad address.\n");
        return 1;
    }
    printf("        surface=%p\n", (void*)surface);

    /* If we got here, the surface exists. Now force the host driver to actually use the guest's
     * Display*, which is where GuestToHostDisplay and the guest-callback trampolines get exercised
     * in earnest. */
    STEP("vkGetPhysicalDeviceSurfaceSupportKHR  <-- second crossing");
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
            surf_support(devs[i], 0, surface, &supported);
            printf("        device[%u] %-40s present-capable(qf0): %s\n",
                   i, p.deviceName, supported ? "YES" : "no");
        }
        free(devs);
    }

    printf("\nRESULT: UNEXPECTED PASS — Xlib WSI worked.\n"
           "  If this happens, it is a significant finding: either POWER9 behaves differently from\n"
           "  POWER8 here, or building both thunk halves together from one commit fixed what the\n"
           "  README attributed to a deeper callback bug. Either way, re-check SuperTuxKart, which\n"
           "  d91959d2f lists as failing on this exact path.\n");

    sleep(1);
    if (XCloseDisplay_) { XCloseDisplay_(dpy); }
    return 0;
}
