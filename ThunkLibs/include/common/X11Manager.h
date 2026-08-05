#include "Host.h"

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <mutex>
#include <unordered_map>

#include <X11/Xlib.h>
#include <xcb/xcb.h>

#ifdef IS_32BIT_THUNK
using guest_long = int32_t;
using guest_size_t = int32_t;
#else
using guest_long = long;
using guest_size_t = size_t;
#endif

/**
 * Guest X11 displays and xcb connections can't be used by the host, so
 * instead an intermediary object is created and mapped to the original
 * guest display/connection.
 */
struct X11Manager {
  std::mutex mutex;

  // Maps guest connection to intermediary host connection
  std::unordered_map<xcb_connection_t*, xcb_connection_t*> connections;

  xcb_connection_t* GuestToHostConnection(xcb_connection_t* GuestConnection) {
    std::unique_lock lock(mutex);
    // find-before-insert: libstdc++'s emplace allocates the node BEFORE probing
    // for an existing key and frees it again on a duplicate, so the old
    // emplace-always shape was a malloc/free pair on every repeat call.
    if (auto it = connections.find(GuestConnection); it != connections.end()) {
      return it->second;
    }
    auto [it, inserted] = connections.emplace(GuestConnection, nullptr);
    if (inserted) {
      // NOTE: There's no easy way to query the display name from the guest, so just connect to the default display.
      static void* libxcb = dlopen("libxcb.so.1", RTLD_LAZY);
      static auto ptr_xcb_connect = (decltype(&xcb_connect))dlsym(libxcb, "xcb_connect");
      static auto ptr_xcb_connection_has_error = (decltype(&xcb_connection_has_error))dlsym(libxcb, "xcb_connection_has_error");
      it->second = ptr_xcb_connect(nullptr, nullptr);
      if (ptr_xcb_connection_has_error(it->second)) {
        fprintf(stderr, "ERROR: Could not open xcb connection\n");
        std::abort();
      }
    }
    return it->second;
  }

  // Maps guest display to intermediary host display, plus the reverse index
  // for HostToGuestDisplay. Entries are only ever inserted, never erased (there
  // is no XCloseDisplay unmapping), which is what makes the lock-free memo in
  // GuestToHostDisplay safe: a cached pair can never refer to a dead mapping.
  std::unordered_map<_XDisplay*, _XDisplay*> displays;
  std::unordered_map<const _XDisplay*, _XDisplay*> displays_reverse;

  // Per-call guest sync is currently the DEFAULT; FEX_X11_SYNC_FIRST_ONLY=1
  // opts into syncing only on first mapping (plus the XID-taking entry
  // points' explicit syncs) and enables the lock-free memo below.
  //
  // The first-only mode is measurably the right thing — the per-call sync is
  // a host->guest trampoline + guest X round trip under every glXSwapBuffers.
  //
  // Grimrock used to break under it (GLXGetDrawableAttributes + GLXMakeCurrent
  // BadDrawable at bootstrap) because its GLX entry points were reached
  // through glXGetProcAddress, which bypasses the fexfn_impl_* wrappers
  // entirely: libGL_Guest.cpp links the returned *host* address to the generic
  // HostPtrInvokers entry, and the later guest call lands in
  // GuestWrapperForHostFunction<Sig>::Call (Host.h), which branches straight
  // at that address. So none of the impls' GuestSyncForHostDisplay calls ran.
  // Fixed by returning the impls from fexfn_impl_libGL_glXGetProcAddress for
  // the XID-taking entry points (libGL_Host.cpp). Any *new* custom_host_impl
  // whose extra work matters must be listed there too, or it is dead code for
  // procaddr-resolving callers.
  static bool SyncEveryCall() {
    static const bool FirstOnly = [] {
      const char* e = getenv("FEX_X11_SYNC_FIRST_ONLY");
      return e && *e == '1';
    }();
    return !FirstOnly;
  }

  _XDisplay* GuestToHostDisplay(_XDisplay* GuestDisplay) {
    // Hot path: one repeat display looked up per Display-taking GL call,
    // usually from a single render thread. The thread_local memo makes that
    // lock-free and allocation-free. Never invalidated — see the map comment.
    struct Memo {
      _XDisplay* guest = nullptr;
      _XDisplay* host = nullptr;
    };
    static thread_local Memo memo;
    if (GuestDisplay == memo.guest && !SyncEveryCall()) {
      return memo.host;
    }
    // Flush event queue to make effects of the guest-side connection visible.
    //
    // Both `GuestXSync` and `GuestXDisplayString` are populated when the
    // guest libGL (or libvulkan) thunk's OnInit runs and invokes the
    // corresponding `fexfn_pack_GL_SetGuestX*` host setter. If the guest
    // reaches a Display-taking API before that init has fired (Grimrock's
    // glewInit/GLX bootstrap is the documented case — see
    // project_grimrock_native_diff_2026-05-16 and the GLEW visual-picker
    // crash at libGL_Host.cpp:42 in PID 359285), these slots are still
    // nullptr from their declaration default. Previously this NULL-deref'd
    // with PC=0; now we degrade gracefully:
    //   - GuestXSync is an optimization (flush guest event queue); safe to skip
    //   - GuestXDisplayString returns the display name; absent it, pass nullptr
    //     to XOpenDisplay which uses $DISPLAY — usually the same target as
    //     the guest's connection (single-display systems are by far the norm
    //     for the game workloads this path serves)
    // Opt-in diagnostic: FEX_X11MANAGER_DEBUG=1.
    //
    // The nullptr guards below mean a *silent registration failure* and a *working callback* both
    // produce a successful call, which is exactly the ambiguity that matters when deciding whether
    // the cross-arch guest-callback path is genuinely working or merely being skipped. Log which
    // one actually happened. Costs one getenv on first use.
    {
      static const bool Debug = [] {
        const char* e = getenv("FEX_X11MANAGER_DEBUG");
        return e && *e == '1';
      }();
      if (Debug) {
        static thread_local unsigned Count = 0;
        fprintf(stderr, "[X11Manager] GuestToHostDisplay(%p) #%u  GuestXSync=%p  GuestXDisplayString=%p  GuestXGetVisualInfo=%p\n",
                (void*)GuestDisplay, ++Count, (void*)GuestXSync, (void*)GuestXDisplayString, (void*)GuestXGetVisualInfo);
        if (!GuestXSync) {
          fprintf(stderr, "[X11Manager]   GuestXSync is NULL — guest callback NOT registered; the "
                          "graceful-degradation path is being taken, so this call proves nothing "
                          "about cross-arch callback dispatch.\n");
        }
      }
    }

    // Sync the guest connection only around the FIRST mapping of a display
    // (or always, under the triage env above). The sync exists because guest
    // and host hold separate connections to the same server: an XID the guest
    // just created may still sit in the guest Xlib's request buffer, and a
    // host-side GLX request naming it would hit BadDrawable. But per call it
    // was a full host->guest trampoline (guest-stack bump, JIT re-entry) plus
    // a guest X round trip — hundreds of instructions under EVERY
    // glXSwapBuffers, for drawables that have existed for thousands of frames.
    // First-use covers the bootstrap case that motivated the sync; anything
    // that mints new XIDs mid-session (rare: a second GLX window) is what the
    // env lever and per-entry-point syncs are for.
    const bool KnownDisplay = [&] {
      std::unique_lock lock(mutex);
      return displays.find(GuestDisplay) != displays.end();
    }();
    if (GuestXSync && (!KnownDisplay || SyncEveryCall())) {
      GuestXSync(GuestDisplay, 0);
    }

    std::unique_lock lock(mutex);
    auto it = displays.find(GuestDisplay);
    if (it == displays.end()) {
      const char* display_name = GuestXDisplayString ? GuestXDisplayString(GuestDisplay) : nullptr;
      auto host_display = HostXOpenDisplay(display_name);
      fprintf(stderr, "Opening host-side X11 display: %p -> %p (name=%s)\n",
              GuestDisplay, host_display, display_name ? display_name : "<default>");
      if (!host_display) {
        fprintf(stderr, "ERROR: Could not open X display\n");
        std::abort();
      }
      it = displays.emplace(GuestDisplay, host_display).first;
      displays_reverse.emplace(host_display, GuestDisplay);
    }
    memo.guest = GuestDisplay;
    memo.host = it->second;
    return it->second;
  }

  // Sync the GUEST connection for a display we only know by its host handle.
  // For the XID-taking GLX entry points (glXMakeCurrent and friends): the
  // Window/Pixmap they name was created on the guest connection and may still
  // sit in the guest Xlib's request buffer — the host connection would hit
  // BadDrawable (Grimrock's bootstrap does exactly this: XCreateWindow lands
  // between the first Display-taking call and glXMakeCurrent, so the
  // first-mapping sync in GuestToHostDisplay has already come and gone).
  // These entry points are bootstrap/mode-change rare, so paying the guest
  // trampoline here costs nothing per-frame. Must NOT be called with `mutex`
  // held: GuestXSync re-enters the guest, which may call back into this
  // manager.
  void GuestSyncForHostDisplay(const _XDisplay* host) {
    if (!GuestXSync) {
      return;
    }
    _XDisplay* guest = nullptr;
    {
      std::unique_lock lock(mutex);
      if (auto it = displays_reverse.find(host); it != displays_reverse.end()) {
        guest = it->second;
      }
    }
    if (guest) {
      GuestXSync(guest, 0);
    }
  }

  guest_layout<_XDisplay*> HostToGuestDisplay(const _XDisplay* from) {
    if (from == nullptr) {
      return {.data = 0};
    }

    std::unique_lock lock(mutex);
    // O(1) via the reverse index kept in GuestToHostDisplay (this used to be a
    // linear scan of `displays` under the same lock, paid by every function
    // RETURNING a Display*).
    if (auto it = displays_reverse.find(from); it != displays_reverse.end()) {
      guest_layout<_XDisplay*> ret;
      ret.data = reinterpret_cast<uintptr_t>(it->second);
      return ret;
    }

    fprintf(stderr, "ERROR: Could not map host display %p back to guest\n", from);
    std::abort();
  }

  static void* GetLibX11() {
    static void* libx11 = dlopen("libX11.so.6", RTLD_LAZY);
    return libx11;
  }

  static int HostXFree(void* Ptr) {
    static auto func = reinterpret_cast<decltype(&XFree)>(dlsym(GetLibX11(), "XFree"));
    return func(Ptr);
  }

  static int HostXFlush(Display* Dis) {
    static auto func = reinterpret_cast<decltype(&XFlush)>(dlsym(GetLibX11(), "XFlush"));
    return func(Dis);
  }

  static Display* HostXOpenDisplay(const char* Name) {
    static auto func = reinterpret_cast<decltype(&XOpenDisplay)>(dlsym(GetLibX11(), "XOpenDisplay"));
    return func(Name);
  }

  static XVisualInfo* HostXGetVisualInfo(Display* a, long b, XVisualInfo* c, int* d) {
    static auto func = reinterpret_cast<decltype(&XGetVisualInfo)>(dlsym(GetLibX11(), "XGetVisualInfo"));
    return func(a, b, c, d);
  }

  // NOTE: Struct pointers are replaced by void* to avoid involving data layout conversion here.
  int (*GuestXSync)(void*, int) = nullptr;
  void* (*GuestXGetVisualInfo)(void*, guest_long, void*, int*) = nullptr;

  // XDisplayString internally just reads data from _XDisplay's internal struct definition.
  // This breaks when data layout is different, so allow reading from a guest context instead.
  char* (*GuestXDisplayString)(void*) = nullptr;
};
