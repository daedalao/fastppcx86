/*
$info$
tags: thunklibs|GL
desc: Uses glXGetProcAddress instead of dlsym
$end_info$
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <vector>

#define GL_GLEXT_PROTOTYPES 1
#define GLX_GLXEXT_PROTOTYPES 1

#include "glcorearb.h"

#include <GL/glx.h>
#include <GL/glxext.h>
#include <GL/gl.h>
#include <GL/glext.h>
#include <xcb/xcb.h>

#include "common/Host.h"
#include "common/X11Manager.h"

template<>
struct host_layout<_XDisplay*> {
  _XDisplay* data;
  _XDisplay* guest_display;

  host_layout(guest_layout<_XDisplay*>&);

  ~host_layout();
};

#if defined(IS_32BIT_THUNK)
// GLXFBConfig is an opaque handle that is really a host pointer
// (__GLXFBConfigRec* living at 0x3fff'xxxx'xxxx on ppc64le). Storing one in a
// 32-bit guest slot truncates it, and unlike a truncated string pointer the
// damage is silent and total: the guest hands the truncated value straight
// back to glXGetFBConfigAttrib, every attribute reads 0, and the config it
// then selects is rejected by the server with GLXBadFBConfig.
//
// Hand out a stable 32-bit token instead and translate back on the way in.
// The guest never dereferences these - GLX defines them as opaque - so the
// token only has to be unique, stable (applications compare handles for
// identity), and distinguishable from a real value.
//
// Hooking host_layout/to_guest rather than individual entry points means
// every generated wrapper that takes or returns a GLXFBConfig is covered,
// including ones reached through glXGetProcAddress.
template<>
struct host_layout<__GLXFBConfigRec*> {
  __GLXFBConfigRec* data;

  host_layout(const guest_layout<__GLXFBConfigRec*>&);
};

guest_layout<__GLXFBConfigRec*> to_guest(const host_layout<__GLXFBConfigRec*>& from);

// GLXContext (__GLXcontextRec*) is the same shape of problem: an opaque host
// pointer the guest stores and hands back. Truncated, the server rejects the
// context with GLXBadContext on X_GLXMakeCurrent, glGetString then returns
// NULL and a Unity title throws out of std::string construction.
template<>
struct host_layout<__GLXcontextRec*> {
  __GLXcontextRec* data;

  host_layout(const guest_layout<__GLXcontextRec*>&);
};

guest_layout<__GLXcontextRec*> to_guest(const host_layout<__GLXcontextRec*>& from);
#endif

static X11Manager x11_manager;

static void* (*GuestMalloc)(guest_size_t) = nullptr;

// Diagnostic X error handler. libX11's default handler prints and calls
// exit(1) on BadDrawable etc., which prevents seeing what came before and
// what request triggered it. Print extra context and let execution continue
// so we can characterize the call chain. Opt-in via FEX_LIBGL_DEBUG=1.
static int LoggingXErrorHandler(Display* d, XErrorEvent* ev) {
  fprintf(stderr, "[fex-libGL] X Error: code=%u request=%u.%u resource=0x%lx serial=%lu\n",
          (unsigned)ev->error_code, (unsigned)ev->request_code,
          (unsigned)ev->minor_code, (unsigned long)ev->resourceid,
          (unsigned long)ev->serial);
  return 0; // do not abort
}
static bool FexLibGLDebug() {
  static const bool enabled = (getenv("FEX_LIBGL_DEBUG") != nullptr);
  return enabled;
}
static void InstallLoggingXErrorHandler() {
  static bool installed = false;
  if (!installed && FexLibGLDebug()) {
    using XSetErrorHandler_t = int (*(*)(int (*)(Display*, XErrorEvent*)))(Display*, XErrorEvent*);
    auto setter = reinterpret_cast<XSetErrorHandler_t>(dlsym(X11Manager::GetLibX11(), "XSetErrorHandler"));
    if (setter) {
      setter(LoggingXErrorHandler);
    }
    installed = true;
  }
}

host_layout<_XDisplay*>::host_layout(guest_layout<_XDisplay*>& guest)
  : guest_display(guest.force_get_host_pointer()) {
  InstallLoggingXErrorHandler();
  data = x11_manager.GuestToHostDisplay(guest_display);
}

host_layout<_XDisplay*>::~host_layout() {
  // This used to XFlush the host connection unconditionally — a write(2) to
  // the X socket per Display-taking GL call, defeating Xlib request batching
  // entirely. It is not needed for rendering: glXSwapBuffers issues its own
  // flush as part of the swap protocol, and non-swap GLX requests that a guest
  // could observe cross-connection get pushed out by the server round trips
  // libX11 already performs for reply-carrying requests. Kept behind a triage
  // env: if a title's window updates lag or GLX state appears stale
  // cross-connection, set FEX_X11_FLUSH_EVERY_CALL=1 to confirm this elision
  // is the cause, then give the specific entry point its own flush.
  static const bool FlushEveryCall = [] {
    const char* e = getenv("FEX_X11_FLUSH_EVERY_CALL");
    return e && *e == '1';
  }();
  if (data && FlushEveryCall) {
    x11_manager.HostXFlush(data);
  }
}

// Functions returning _XDisplay* should be handled explicitly via ptr_passthrough
guest_layout<_XDisplay*> to_guest(host_layout<_XDisplay*>) = delete;

#if defined(IS_32BIT_THUNK)
// Token registry backing the GLXFBConfig handle translation declared above.
//
// Tokens are drawn from a range that cannot collide with a real 32-bit guest
// pointer value the guest might hand us: the guest's own address space is
// populated well below this, and these values are never dereferenced by
// either side. Entries are never retired - GLXFBConfigs are a small fixed
// per-screen set (a few hundred), the guest may hold one indefinitely, and
// reusing a token would alias two configs.
namespace {
// One registry per handle type, each with its own token range so a handle of
// the wrong type is caught rather than silently reinterpreted.
template<typename T, uint32_t TokenBase>
struct OpaqueHandleRegistry {
  std::mutex Mutex;
  // Index 0 is never handed out so that token 0 stays reserved for null.
  std::vector<T*> ByIndex {nullptr};
  std::unordered_map<T*, uint32_t> ToToken;

  uint32_t TokenFor(T* Host) {
    if (!Host) {
      return 0;
    }
    std::lock_guard lk {Mutex};
    if (auto It = ToToken.find(Host); It != ToToken.end()) {
      return It->second;
    }
    const uint32_t Token = TokenBase + static_cast<uint32_t>(ByIndex.size());
    ByIndex.push_back(Host);
    ToToken.emplace(Host, Token);
    return Token;
  }

  T* ForToken(uint32_t Token) {
    if (!Token) {
      return nullptr;
    }
    std::lock_guard lk {Mutex};
    // Token maps 1:1 onto an index. An earlier version spaced tokens 16 apart
    // while still dividing by that stride, so 15 of every 16 values in the
    // range resolved to a real-but-wrong handle instead of being rejected -
    // the opposite of the intent.
    const uint32_t Index = Token - TokenBase;
    if (Token < TokenBase || Index >= ByIndex.size()) {
      // Not one of ours. Pass it through rather than inventing a null: a guest
      // that obtained a handle by some path we do not model should fail in the
      // driver with its own diagnostics, not silently here.
      return reinterpret_cast<T*>(static_cast<uintptr_t>(Token));
    }
    // Null here means the handle was retired (see Retire) - the guest is using
    // it after destroying it. Returning null makes the driver reject it;
    // returning the old pointer would dereference freed memory.
    return ByIndex[Index];
  }

  // Drop a handle whose underlying object is being destroyed. The slot is
  // kept (so later tokens keep their meaning) but emptied, and the pointer is
  // un-interned so that an allocator reusing the address does not resurrect
  // the retired token for a different object.
  void Retire(T* Host) {
    if (!Host) {
      return;
    }
    std::lock_guard lk {Mutex};
    auto It = ToToken.find(Host);
    if (It == ToToken.end()) {
      return;
    }
    const uint32_t Index = It->second - TokenBase;
    if (Index < ByIndex.size()) {
      ByIndex[Index] = nullptr;
    }
    ToToken.erase(It);
  }
};

OpaqueHandleRegistry<__GLXFBConfigRec, 0xFBC0'0000> FBConfigRegistry;
OpaqueHandleRegistry<__GLXcontextRec, 0xC0C0'0000> ContextRegistry;
} // namespace

host_layout<__GLXFBConfigRec*>::host_layout(const guest_layout<__GLXFBConfigRec*>& guest)
  : data(FBConfigRegistry.ForToken(static_cast<uint32_t>(guest.data))) {}

guest_layout<__GLXFBConfigRec*> to_guest(const host_layout<__GLXFBConfigRec*>& from) {
  guest_layout<__GLXFBConfigRec*> Result {};
  Result.data = FBConfigRegistry.TokenFor(from.data);
  return Result;
}

host_layout<__GLXcontextRec*>::host_layout(const guest_layout<__GLXcontextRec*>& guest)
  : data(ContextRegistry.ForToken(static_cast<uint32_t>(guest.data))) {}

guest_layout<__GLXcontextRec*> to_guest(const host_layout<__GLXcontextRec*>& from) {
  guest_layout<__GLXcontextRec*> Result {};
  Result.data = ContextRegistry.TokenFor(from.data);
  return Result;
}
#endif

#if defined(IS_32BIT_THUNK)
// Same tripwire discipline for the GL/GLX string-return family. Any *future*
// function that returns a `const GLubyte*` / `const char*` without an
// explicit `ptr_passthrough` annotation becomes a compile error rather than
// silent 32-bit truncation of a host `.rodata` address.
guest_layout<const GLubyte*> to_guest(host_layout<const GLubyte*>) = delete;
#endif

static void fexfn_impl_libGL_GL_SetGuestMalloc(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &GuestMalloc);
}

static void fexfn_impl_libGL_GL_SetGuestXGetVisualInfo(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  // Build into a temporary and publish with a release store. Other threads
  // acquire-load this (MapToGuestVisualInfo); the trampoline body and its
  // GuestcallInfo must be visible before the pointer that reaches them is.
  decltype(x11_manager.GuestXGetVisualInfo) Fn {};
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &Fn);
  __atomic_store_n(&x11_manager.GuestXGetVisualInfo, Fn, __ATOMIC_RELEASE);
}

static void fexfn_impl_libGL_GL_SetGuestXSync(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &x11_manager.GuestXSync);
}

static void fexfn_impl_libGL_GL_SetGuestXDisplayString(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &x11_manager.GuestXDisplayString);
}

#include "thunkgen_host_libGL.inl"

#ifdef IS_32BIT_THUNK
// Single source of truth for the pointer-relocating custom_host_impl family.
//
// Each of these functions returns a host `.rodata` pointer (a GL/GLX driver
// string) that the custom impl copies into guest-addressable memory via
// RelocateStringToGuestHeap -- see the block near line ~350. The whole reason
// they exist is that the default `to_guest` truncates a 64-bit host pointer to
// 32 bits on an i386 guest (garbage that gldriverquery et al. read blindly).
//
// A procaddr-resolving i386 title (glXGetProcAddress("glGetString")) MUST land
// on the custom impl, never the raw host symbol -- otherwise it gets the
// truncating path the impl was written to avoid. The glXGetProcAddress table
// below therefore *must* contain every name in this list. To make that
// impossible to forget, the table branches are generated from this list: you
// cannot add a relocating impl to the list without also adding its table
// branch. (A generator-side check was considered but rejected: the generator
// has no visibility into this hand-written table -- see gen.cpp custom_host_impl
// handling -- so enforcing it there would mean teaching the generator to parse
// the impl .cpp. This X-macro coupling gives the same guarantee locally.)
#define FEX_LIBGL_RELOCATING_IMPLS(_) \
  _(glGetString)                      \
  _(glGetStringi)                     \
  _(glXGetClientString)               \
  _(glXQueryExtensionsString)         \
  _(glXQueryServerString)
#endif

auto fexfn_impl_libGL_glXGetProcAddress(const GLubyte* name) -> void (*)() {
  using VoidFn = void (*)();
  std::string_view name_sv {reinterpret_cast<const char*>(name)};
#ifdef IS_32BIT_THUNK
  // Pointer-relocating impls (see FEX_LIBGL_RELOCATING_IMPLS above). Kept as an
  // early-return block generated from the shared list so the "needs relocation"
  // set and the procaddr table are literally the same declaration.
#define FEX_LIBGL_PROCADDR_BRANCH(fn) \
  if (name_sv == #fn) {               \
    return (VoidFn)fexfn_impl_libGL_##fn; \
  }
  FEX_LIBGL_RELOCATING_IMPLS(FEX_LIBGL_PROCADDR_BRANCH)
#undef FEX_LIBGL_PROCADDR_BRANCH
#endif
  if (name_sv == "glCompileShaderIncludeARB") {
    return (VoidFn)fexfn_impl_libGL_glCompileShaderIncludeARB;
  } else if (name_sv == "glCreateShaderProgramv") {
    return (VoidFn)fexfn_impl_libGL_glCreateShaderProgramv;
  } else if (name_sv == "glGetBufferPointerv") {
    return (VoidFn)fexfn_impl_libGL_glGetBufferPointerv;
  } else if (name_sv == "glGetBufferPointervARB") {
    return (VoidFn)fexfn_impl_libGL_glGetBufferPointervARB;
  } else if (name_sv == "glGetNamedBufferPointerv") {
    return (VoidFn)fexfn_impl_libGL_glGetNamedBufferPointerv;
  } else if (name_sv == "glGetNamedBufferPointervEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetNamedBufferPointervEXT;
  } else if (name_sv == "glGetPointerv") {
    return (VoidFn)fexfn_impl_libGL_glGetPointerv;
  } else if (name_sv == "glGetPointervEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetPointervEXT;
  } else if (name_sv == "glGetPointeri_vEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetPointeri_vEXT;
  } else if (name_sv == "glGetPointerIndexedvEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetPointerIndexedvEXT;
  } else if (name_sv == "glGetVariantPointervEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetVariantPointervEXT;
  } else if (name_sv == "glGetVertexAttribPointervARB") {
    return (VoidFn)fexfn_impl_libGL_glGetVertexAttribPointervARB;
  } else if (name_sv == "glGetVertexAttribPointerv") {
    return (VoidFn)fexfn_impl_libGL_glGetVertexAttribPointerv;
  } else if (name_sv == "glGetVertexAttribPointervNV") {
    return (VoidFn)fexfn_impl_libGL_glGetVertexAttribPointervNV;
  } else if (name_sv == "glGetVertexArrayPointeri_vEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetVertexArrayPointeri_vEXT;
  } else if (name_sv == "glGetVertexArrayPointervEXT") {
    return (VoidFn)fexfn_impl_libGL_glGetVertexArrayPointervEXT;
  } else if (name_sv == "glShaderSource") {
    return (VoidFn)fexfn_impl_libGL_glShaderSource;
  } else if (name_sv == "glShaderSourceARB") {
    return (VoidFn)fexfn_impl_libGL_glShaderSourceARB;
#ifdef IS_32BIT_THUNK
  } else if (name_sv == "glBindBuffersRange") {
    return (VoidFn)fexfn_impl_libGL_glBindBuffersRange;
  } else if (name_sv == "glBindVertexBuffers") {
    return (VoidFn)fexfn_impl_libGL_glBindVertexBuffers;
  } else if (name_sv == "glGetUniformIndices") {
    return (VoidFn)fexfn_impl_libGL_glGetUniformIndices;
  } else if (name_sv == "glVertexArrayVertexBuffers") {
    return (VoidFn)fexfn_impl_libGL_glVertexArrayVertexBuffers;
#endif
  } else if (name_sv == "glXChooseFBConfig") {
    return (VoidFn)fexfn_impl_libGL_glXChooseFBConfig;
  } else if (name_sv == "glXChooseFBConfigSGIX") {
    return (VoidFn)fexfn_impl_libGL_glXChooseFBConfigSGIX;
  } else if (name_sv == "glXGetCurrentDisplay") {
    return (VoidFn)fexfn_impl_libGL_glXGetCurrentDisplay;
  } else if (name_sv == "glXGetCurrentDisplayEXT") {
    return (VoidFn)fexfn_impl_libGL_glXGetCurrentDisplayEXT;
  } else if (name_sv == "glXGetFBConfigs") {
    return (VoidFn)fexfn_impl_libGL_glXGetFBConfigs;
  } else if (name_sv == "glXGetFBConfigFromVisualSGIX") {
    return (VoidFn)fexfn_impl_libGL_glXGetFBConfigFromVisualSGIX;
  } else if (name_sv == "glXGetVisualFromFBConfigSGIX") {
    return (VoidFn)fexfn_impl_libGL_glXGetVisualFromFBConfigSGIX;
  } else if (name_sv == "glXChooseVisual") {
    return (VoidFn)fexfn_impl_libGL_glXChooseVisual;
    // The XID-taking GLX entry points MUST be listed here, not just annotated
    // custom_host_impl.
    //
    // A name resolved through glXGetProcAddress does NOT reach its
    // fexfn_impl_* wrapper. libGL_Guest.cpp:68 links the *returned host
    // address* to the generic HostPtrInvokers entry for that name, so a later
    // guest call lands in GuestWrapperForHostFunction<Sig>::Call (Host.h:913),
    // which repacks the arguments and then branches straight to whatever
    // address we returned here. Return the raw host symbol and the custom impl
    // is bypassed entirely — the guest_layout conversions still happen (that is
    // why this worked at all), but everything the impl adds around the call
    // does not. Confirmed by gdb: glXMakeCurrent in libGLX.so.0 called from
    // GuestWrapperForHostFunction<int (_XDisplay*, unsigned long,
    // __GLXcontextRec*), ...>::Call, never from fexfn_impl_libGL_glXMakeCurrent.
    //
    // For these four that missing extra is GuestSyncForHostDisplay: the
    // Window/Pixmap they name was minted on the guest connection and may still
    // sit in the guest Xlib request buffer. Without the sync the host
    // connection hits BadDrawable on GLXGetDrawableAttributes (Grimrock
    // bootstrap, serials ~28/30) whenever the per-call sync in
    // GuestToHostDisplay is not covering for it (FEX_X11_SYNC_FIRST_ONLY=1).
  } else if (name_sv == "glXMakeCurrent") {
    return (VoidFn)fexfn_impl_libGL_glXMakeCurrent;
  } else if (name_sv == "glXMakeContextCurrent") {
    return (VoidFn)fexfn_impl_libGL_glXMakeContextCurrent;
  } else if (name_sv == "glXCreateWindow") {
    return (VoidFn)fexfn_impl_libGL_glXCreateWindow;
  } else if (name_sv == "glXCreatePixmap") {
    return (VoidFn)fexfn_impl_libGL_glXCreatePixmap;
  } else if (name_sv == "glXCreateContext") {
    return (VoidFn)fexfn_impl_libGL_glXCreateContext;
  } else if (name_sv == "glXCreateGLXPixmap") {
    return (VoidFn)fexfn_impl_libGL_glXCreateGLXPixmap;
  } else if (name_sv == "glXCreateGLXPixmapMESA") {
    return (VoidFn)fexfn_impl_libGL_glXCreateGLXPixmapMESA;
  } else if (name_sv == "glXGetConfig") {
    return (VoidFn)fexfn_impl_libGL_glXGetConfig;
  } else if (name_sv == "glXGetVisualFromFBConfig") {
    return (VoidFn)fexfn_impl_libGL_glXGetVisualFromFBConfig;
#ifdef IS_32BIT_THUNK
  } else if (name_sv == "glXGetSelectedEvent") {
    return (VoidFn)fexfn_impl_libGL_glXGetSelectedEvent;
  } else if (name_sv == "glXGetSelectedEventSGIX") {
    return (VoidFn)fexfn_impl_libGL_glXGetSelectedEventSGIX;
#endif
  }
  return (VoidFn)glXGetProcAddress((const GLubyte*)name);
}

// TODO: unsigned int *glXEnumerateVideoDevicesNV (Display *dpy, int screen, int *nelements);


void fexfn_impl_libGL_glCompileShaderIncludeARB(GLuint a_0, GLsizei Count, guest_layout<const GLchar* const*> a_2, const GLint* a_3) {
#ifndef IS_32BIT_THUNK
  auto sources = a_2.force_get_host_pointer();
#else
  auto sources = (const char**)alloca(Count * sizeof(const char*));
  for (GLsizei i = 0; i < Count; ++i) {
    sources[i] = host_layout<const char* const> {a_2.get_pointer()[i]}.data;
  }
#endif
  return fexldr_ptr_libGL_glCompileShaderIncludeARB(a_0, Count, sources, a_3);
}

GLuint fexfn_impl_libGL_glCreateShaderProgramv(GLuint a_0, GLsizei count, guest_layout<const GLchar* const*> a_2) {
#ifndef IS_32BIT_THUNK
  auto sources = a_2.force_get_host_pointer();
#else
  auto sources = (const char**)alloca(count * sizeof(const char*));
  for (GLsizei i = 0; i < count; ++i) {
    sources[i] = host_layout<const char* const> {a_2.get_pointer()[i]}.data;
  }
#endif
  return fexldr_ptr_libGL_glCreateShaderProgramv(a_0, count, sources);
}

void fexfn_impl_libGL_glGetBufferPointerv(GLenum a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetBufferPointerv(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetBufferPointervARB(GLenum a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetBufferPointervARB(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetNamedBufferPointerv(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetNamedBufferPointerv(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetNamedBufferPointervEXT(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetNamedBufferPointervEXT(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetPointerv(GLenum a_0, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetPointerv(a_0, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetPointervEXT(GLenum a_0, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetPointervEXT(a_0, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetPointeri_vEXT(GLenum a_0, GLuint a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetPointeri_vEXT(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetPointerIndexedvEXT(GLenum a_0, GLuint a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetPointerIndexedvEXT(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVariantPointervEXT(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVariantPointervEXT(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVertexAttribPointervARB(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVertexAttribPointervARB(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVertexAttribPointerv(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVertexAttribPointerv(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVertexAttribPointervNV(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVertexAttribPointervNV(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVertexArrayPointeri_vEXT(GLuint a_0, GLuint a_1, GLenum a_2, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVertexArrayPointeri_vEXT(a_0, a_1, a_2, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glGetVertexArrayPointervEXT(GLuint a_0, GLenum a_1, guest_layout<void**> GuestOut) {
  void* HostOut;
  fexldr_ptr_libGL_glGetVertexArrayPointervEXT(a_0, a_1, &HostOut);
  *GuestOut.get_pointer() = to_guest(to_host_layout(HostOut));
}

void fexfn_impl_libGL_glShaderSource(GLuint a_0, GLsizei count, guest_layout<const GLchar* const*> a_2, const GLint* a_3) {
#ifndef IS_32BIT_THUNK
  auto sources = a_2.force_get_host_pointer();
#else
  auto sources = (const char**)alloca(count * sizeof(const char*));
  for (GLsizei i = 0; i < count; ++i) {
    sources[i] = host_layout<const char* const> {a_2.get_pointer()[i]}.data;
  }
#endif
  return fexldr_ptr_libGL_glShaderSource(a_0, count, sources, a_3);
}

void fexfn_impl_libGL_glShaderSourceARB(GLuint a_0, GLsizei count, guest_layout<const GLcharARB**> a_2, const GLint* a_3) {
#ifndef IS_32BIT_THUNK
  auto sources = a_2.force_get_host_pointer();
#else
  auto sources = (const char**)alloca(count * sizeof(const char*));
  for (GLsizei i = 0; i < count; ++i) {
    sources[i] = a_2.get_pointer()[i].force_get_host_pointer();
  }
#endif
  return fexldr_ptr_libGL_glShaderSourceARB(a_0, count, sources, a_3);
}

// Relocate data to guest heap so it can be called with XFree.
// The memory at the given host location will be de-allocated.
template<typename T>
guest_layout<T*> RelocateArrayToGuestHeap(T* Data, int NumItems) {
  if (!Data) {
    return guest_layout<T*> {.data = 0};
  }

  if (NumItems <= 0) {
    return guest_layout<T*> {.data = 0};
  }

  guest_layout<T*> GuestData;
  GuestData.data = reinterpret_cast<uintptr_t>(GuestMalloc(sizeof(guest_layout<T>) * NumItems));
  if (!GuestData.data) {
    // Guest heap exhausted. Without this check the loop below writes the
    // relocated array through a null guest pointer.
    return guest_layout<T*> {.data = 0};
  }
  for (int Index = 0; Index < NumItems; ++Index) {
    GuestData.get_pointer()[Index] = to_guest(to_host_layout(Data[Index]));
  }
  x11_manager.HostXFree(Data);
  return GuestData;
}

#if defined(IS_32BIT_THUNK)
// Copies a NUL-terminated host string onto the guest heap and returns a guest
// pointer to it. GL/GLX driver strings (`glGetString`, `glGetStringi`, and
// the `glX*String` trio) all return host `.rodata` pointers at
// `0x3fff'xxxx'xxxx`. The default `to_guest` on that pointer silently
// truncates to 32 bits on an i386 guest (`Host.h:551-557` -- upstream's own
// `// TODO: Assert upper 32 bits are zero`), producing garbage that
// `gldriverquery` and every driver-info consumer reads without noticing.
//
// Unlike `RelocateArrayToGuestHeap` this MUST NOT free the source. GL driver
// strings live in the driver's `.rodata` for the process lifetime; calling
// `HostXFree` on them would corrupt Mesa.
//
// Results are interned. GL strings are static, and applications compare
// returned pointers for identity (`s == prev_s` as a cheap "still the same
// driver?" check). Never freed by design -- the total is a small fixed set
// per process (VENDOR, RENDERER, VERSION, EXTENSIONS, one GLSL_VERSION,
// plus per-index EXTENSIONS strings, and a handful of GLX server/client
// strings). Under a busy application it stays well under 100 entries.
static guest_layout<const GLubyte*> RelocateStringToGuestHeap(const GLubyte* Str) {
  if (!Str) {
    return guest_layout<const GLubyte*> {.data = 0};
  }

  static std::mutex InternMutex;
  static std::unordered_map<const void*, uintptr_t> Interned;

  using GuestPtr = decltype(guest_layout<const GLubyte*>::data);

  {
    std::lock_guard<std::mutex> Lock(InternMutex);
    if (auto It = Interned.find(Str); It != Interned.end()) {
      return guest_layout<const GLubyte*> {.data = static_cast<GuestPtr>(It->second)};
    }
  }

  // Allocate OUTSIDE the lock. GuestMalloc is a host->guest trampoline: it
  // bumps the guest stack and re-enters the JIT to run the guest's malloc.
  // Holding a host lock across that is the hazard X11Manager documents for
  // GuestXSync - a guest allocator taking its own lock, or a signal landing on
  // another glGetString on this thread, deadlocks against us. glGetString sits
  // on the startup path, so this is not hypothetical.
  const size_t Size = std::strlen(reinterpret_cast<const char*>(Str)) + 1;
  void* GuestBuf = GuestMalloc(Size);
  if (!GuestBuf) {
    // Guest OOM. Returning null is honest -- the alternative is handing
    // back a truncated host pointer, which is the bug we are fixing.
    return guest_layout<const GLubyte*> {.data = 0};
  }
  std::memcpy(GuestBuf, Str, Size);

  // Re-check: another thread may have interned this string while we were in
  // the guest. Identity matters here (callers compare returned pointers), so
  // the first writer wins and our buffer is abandoned - a handful of bytes on
  // a rare race, against a fixed set of driver strings.
  std::lock_guard<std::mutex> Lock(InternMutex);
  auto [It, Inserted] = Interned.emplace(Str, reinterpret_cast<uintptr_t>(GuestBuf));
  return guest_layout<const GLubyte*> {.data = static_cast<GuestPtr>(It->second)};
}

guest_layout<const GLubyte*> fexfn_impl_libGL_glGetString(GLenum name) {
  return RelocateStringToGuestHeap(fexldr_ptr_libGL_glGetString(name));
}

guest_layout<const GLubyte*> fexfn_impl_libGL_glGetStringi(GLenum name, GLuint index) {
  return RelocateStringToGuestHeap(fexldr_ptr_libGL_glGetStringi(name, index));
}

// The glX*String trio's public signature is `const char*` (not `const
// GLubyte*` like the GL ones), and thunkgen declares the custom_host_impl
// forward with that type. The narrow char*/uint8_t* pointer-flavor interop
// on guest_layout<T*> (Host.h) bridges the assignment to the packed-args
// `rv` (which is `guest_layout<const uint8_t*>`).
static guest_layout<const char*> RelocateCharStringToGuestHeap(const char* Str) {
  auto Result = RelocateStringToGuestHeap(reinterpret_cast<const GLubyte*>(Str));
  return guest_layout<const char*> {.data = Result.data};
}

guest_layout<const char*> fexfn_impl_libGL_glXQueryExtensionsString(Display* dpy, int screen) {
  return RelocateCharStringToGuestHeap(fexldr_ptr_libGL_glXQueryExtensionsString(dpy, screen));
}

guest_layout<const char*> fexfn_impl_libGL_glXGetClientString(Display* dpy, int name) {
  return RelocateCharStringToGuestHeap(fexldr_ptr_libGL_glXGetClientString(dpy, name));
}

guest_layout<const char*> fexfn_impl_libGL_glXQueryServerString(Display* dpy, int screen, int name) {
  return RelocateCharStringToGuestHeap(fexldr_ptr_libGL_glXQueryServerString(dpy, screen, name));
}
#endif // IS_32BIT_THUNK

// Maps to a host-side XVisualInfo, which must be XFree'ed by the caller.
static XVisualInfo* LookupHostVisualInfo(Display* HostDisplay, guest_layout<XVisualInfo*> GuestInfo) {
  if (!GuestInfo.data) {
    return nullptr;
  }

  int num_matches;
  auto HostInfo = host_layout<XVisualInfo> {*GuestInfo.get_pointer()}.data;
  auto ret = x11_manager.HostXGetVisualInfo(HostDisplay, uint64_t {VisualScreenMask | VisualIDMask}, &HostInfo, &num_matches);
  if (num_matches != 1) {
    fprintf(stderr, "ERROR: Did not find unique host XVisualInfo\n");
    std::abort();
  }
  return ret;
}

// Maps to a guest-side XVisualInfo and destroys the host argument.
static guest_layout<XVisualInfo*> MapToGuestVisualInfo(Display* HostDisplay, XVisualInfo* HostInfo) {
  if (!HostInfo) {
    return guest_layout<XVisualInfo*> {.data = 0};
  }

  // This buffer must come from the *guest* heap.
  //
  // 41d9771a1 switched it to host std::malloc() on the reasoning that the
  // guest's XFree() would route back through the thunked XFree -> HostXFree ->
  // host free(). That is not what happens: libGL-guest.so has a DT_NEEDED on
  // the guest's own libX11.so.6, so XFree() is resolved inside the guest and
  // calls the *guest* allocator's free() on a host-heap pointer. Guest glibc
  // then walks a chunk header that was never its own and aborts with
  //   double free or corruption (out)
  // right after glXCreateContext. Whether it aborts at all depends only on
  // what the host pointer happens to alias, so it looked intermittent and got
  // misfiled as guest/host thunk interface drift.
  //
  // The guest-callback path that made GuestMalloc unusable back in May was
  // fixed afterwards (f34dbdb9d, 62ea24ce4, b21ee0205, 58973e69e), and
  // RelocateArrayToGuestHeap has been using GuestMalloc successfully since.
  // Use it here too - a single-element relocation is exactly what it does.
  //
  // ...but a byte-for-byte relocation is not enough, because XVisualInfo has a
  // `Visual* visual` member that points into the *host* Xlib's connection
  // state. Relocating the struct converts the layout and truncates that
  // member, and the guest then hands it to its own libX11: XCreateColormap
  // dereferences visual->visualid and segfaults. Dex died exactly there once
  // FBConfig selection started working.
  //
  // A Visual belongs to the connection that produced it, so the only correct
  // answer is one minted by the *guest's* Xlib. Re-query it there by screen +
  // visualid, which is the mirror of what LookupHostVisualInfo already does in
  // the other direction. GuestXGetVisualInfo has been registered for this
  // since the X11Manager was written but had no caller until now.
  //
  // The result is guest-allocated, so the guest's XFree owns it - which is
  // also what the caller of glXGetVisualFromFBConfig expects.
  // Acquire-load the callback pointer. It is published by a different thread
  // (whichever one ran the guest lib's OnInit) and publishing it also writes
  // trampoline bytes and a GuestcallInfo the callee dereferences. ppc64le is
  // weakly ordered, so without this a reader can observe a non-null pointer
  // while the memory behind it is not yet visible, and branch into garbage.
  auto* GuestGetVisualInfo = __atomic_load_n(&x11_manager.GuestXGetVisualInfo, __ATOMIC_ACQUIRE);
  auto* Malloc = __atomic_load_n(&GuestMalloc, __ATOMIC_ACQUIRE);

  if (GuestGetVisualInfo && Malloc) {
    auto GuestDisplay = x11_manager.HostToGuestDisplay(HostDisplay);
    if (GuestDisplay.data) {
      // Both the template and the out-count must live in guest memory: the
      // callback runs as guest code and cannot write to a host address.
      //
      // There is no guest free() registered here - only GuestMalloc - so a
      // per-call allocation would leak guest heap on every call, and a 32-bit
      // guest only has 4GiB of it. One buffer per thread, allocated once and
      // reused, keeps this bounded. It is thread_local because the callback
      // writes through it and concurrent callers must not share.
      constexpr size_t TemplateSize = sizeof(guest_layout<XVisualInfo>);
      static thread_local uint8_t* Scratch = nullptr;
      if (!Scratch) {
        Scratch = static_cast<uint8_t*>(Malloc(TemplateSize + sizeof(int)));
      }
      if (Scratch) {
        auto* Template = reinterpret_cast<guest_layout<XVisualInfo>*>(Scratch);
        auto* NumItems = reinterpret_cast<int*>(Scratch + TemplateSize);
        *Template = to_guest(to_host_layout(*HostInfo));
        *NumItems = 0;

        auto* Ret = GuestGetVisualInfo(reinterpret_cast<void*>(static_cast<uintptr_t>(GuestDisplay.data)),
                                       static_cast<guest_long>(VisualScreenMask | VisualIDMask), Template, NumItems);
        if (Ret && *NumItems >= 1) {
          x11_manager.HostXFree(HostInfo);
          return guest_layout<XVisualInfo*> {.data = static_cast<decltype(guest_layout<XVisualInfo*>::data)>(reinterpret_cast<uintptr_t>(Ret))};
        }
        // Fall through to the relocating path on a miss rather than failing
        // the call: a caller that only reads depth/class still works, and a
        // hard failure here would regress titles that never touch `visual`.
      }
    }
  }

  return RelocateArrayToGuestHeap(HostInfo, 1);
}

guest_layout<GLXFBConfig*> fexfn_impl_libGL_glXChooseFBConfig(Display* Display, int Screen, const int* Attributes, int* NumItems) {
  auto ret = fexldr_ptr_libGL_glXChooseFBConfig(Display, Screen, Attributes, NumItems);
  return RelocateArrayToGuestHeap(ret, *NumItems);
}

guest_layout<GLXFBConfigSGIX*> fexfn_impl_libGL_glXChooseFBConfigSGIX(Display* Display, int Screen, int* Attributes, int* NumItems) {
  auto ret = fexldr_ptr_libGL_glXChooseFBConfigSGIX(Display, Screen, Attributes, NumItems);
  return RelocateArrayToGuestHeap(ret, *NumItems);
}

guest_layout<_XDisplay*> fexfn_impl_libGL_glXGetCurrentDisplay() {
  auto ret = fexldr_ptr_libGL_glXGetCurrentDisplay();
  return x11_manager.HostToGuestDisplay(ret);
}

guest_layout<_XDisplay*> fexfn_impl_libGL_glXGetCurrentDisplayEXT() {
  auto ret = fexldr_ptr_libGL_glXGetCurrentDisplayEXT();
  return x11_manager.HostToGuestDisplay(ret);
}

guest_layout<GLXFBConfig*> fexfn_impl_libGL_glXGetFBConfigs(Display* Display, int Screen, int* NumItems) {
  auto ret = fexldr_ptr_libGL_glXGetFBConfigs(Display, Screen, NumItems);
  return RelocateArrayToGuestHeap(ret, *NumItems);
}

GLXFBConfigSGIX fexfn_impl_libGL_glXGetFBConfigFromVisualSGIX(Display* Display, guest_layout<XVisualInfo*> Info) {
  auto HostInfo = LookupHostVisualInfo(Display, Info);
  auto ret = fexldr_ptr_libGL_glXGetFBConfigFromVisualSGIX(Display, HostInfo);
  x11_manager.HostXFree(HostInfo);
  return ret;
}

guest_layout<XVisualInfo*> fexfn_impl_libGL_glXGetVisualFromFBConfigSGIX(Display* Display, GLXFBConfigSGIX Config) {
  return MapToGuestVisualInfo(Display, fexldr_ptr_libGL_glXGetVisualFromFBConfigSGIX(Display, Config));
}

guest_layout<XVisualInfo*> fexfn_impl_libGL_glXChooseVisual(Display* Display, int Screen, int* Attributes) {
  return MapToGuestVisualInfo(Display, fexldr_ptr_libGL_glXChooseVisual(Display, Screen, Attributes));
}

void fexfn_impl_libGL_glXDestroyContext(Display* Display, GLXContext Context) {
#if defined(IS_32BIT_THUNK)
  // Retire the token before the object goes away. Without this the registry
  // keeps handing out a pointer to freed memory, which Mesa will dereference -
  // strictly worse than the truncation this token map replaced, because a
  // truncated context was merely rejected with GLXBadContext. Un-interning also
  // stops an allocator that reuses the address from resurrecting the retired
  // token for a different context. SDL2 (hence Unity) creates a probe context,
  // destroys it and creates the real one during startup, so this path runs.
  ContextRegistry.Retire(Context);
#endif
  fexldr_ptr_libGL_glXDestroyContext(Display, Context);
}

GLXContext fexfn_impl_libGL_glXCreateContext(Display* Display, guest_layout<XVisualInfo*> Info, GLXContext ShareList, Bool Direct) {
  auto HostInfo = LookupHostVisualInfo(Display, Info);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXCreateContext: display=%p visualid=0x%lx screen=%d direct=%d\n",
            Display, (unsigned long)(HostInfo ? HostInfo->visualid : 0), HostInfo ? HostInfo->screen : -1, Direct);
  }
  auto ret = fexldr_ptr_libGL_glXCreateContext(Display, HostInfo, ShareList, Direct);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXCreateContext: returned ctx=%p\n", (void*)ret);
  }
  x11_manager.HostXFree(HostInfo);
  return ret;
}

Bool fexfn_impl_libGL_glXMakeCurrent(Display* Display, GLXDrawable Drawable, GLXContext Context) {
  // XID args may name a guest-created drawable the host connection has not
  // seen yet (see X11Manager::GuestSyncForHostDisplay). Rare call; cheap here.
  x11_manager.GuestSyncForHostDisplay(Display);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXMakeCurrent: display=%p drawable=0x%lx context=%p\n",
            Display, (unsigned long)Drawable, (void*)Context);
  }
  auto ret = fexldr_ptr_libGL_glXMakeCurrent(Display, Drawable, Context);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXMakeCurrent: returned %d\n", ret);
  }
  return ret;
}

Bool fexfn_impl_libGL_glXMakeContextCurrent(Display* Display, GLXDrawable Draw, GLXDrawable Read, GLXContext Context) {
  // XID args may name a guest-created drawable the host connection has not
  // seen yet (see X11Manager::GuestSyncForHostDisplay). Rare call; cheap here.
  x11_manager.GuestSyncForHostDisplay(Display);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXMakeContextCurrent: display=%p draw=0x%lx read=0x%lx context=%p\n",
            Display, (unsigned long)Draw, (unsigned long)Read, (void*)Context);
  }
  auto ret = fexldr_ptr_libGL_glXMakeContextCurrent(Display, Draw, Read, Context);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXMakeContextCurrent: returned %d\n", ret);
  }
  return ret;
}

GLXWindow fexfn_impl_libGL_glXCreateWindow(Display* Display, GLXFBConfig Config, Window Win, const int* AttribList) {
  // `Win` was created on the guest connection; sync it visible to the host
  // connection first. This is the path SDL2/GLX-1.3 titles take INSTEAD of
  // glXMakeCurrent-first (Grimrock: BadDrawable on GLXGetDrawableAttributes,
  // "failed to create drawable", before any MakeCurrent).
  x11_manager.GuestSyncForHostDisplay(Display);
  if (FexLibGLDebug()) {
    fprintf(stderr, "[fex-libGL] glXCreateWindow: display=%p win=0x%lx\n", Display, (unsigned long)Win);
  }
  return fexldr_ptr_libGL_glXCreateWindow(Display, Config, Win, AttribList);
}

GLXPixmap fexfn_impl_libGL_glXCreatePixmap(Display* Display, GLXFBConfig Config, Pixmap Pixmap, const int* AttribList) {
  x11_manager.GuestSyncForHostDisplay(Display);
  return fexldr_ptr_libGL_glXCreatePixmap(Display, Config, Pixmap, AttribList);
}

GLXPixmap fexfn_impl_libGL_glXCreateGLXPixmap(Display* Display, guest_layout<XVisualInfo*> Info, Pixmap Pixmap) {
  x11_manager.GuestSyncForHostDisplay(Display);
  auto HostInfo = LookupHostVisualInfo(Display, Info);
  auto ret = fexldr_ptr_libGL_glXCreateGLXPixmap(Display, HostInfo, Pixmap);
  x11_manager.HostXFree(HostInfo);
  return ret;
}

GLXPixmap fexfn_impl_libGL_glXCreateGLXPixmapMESA(Display* Display, guest_layout<XVisualInfo*> Info, Pixmap Pixmap, Colormap Colormap) {
  x11_manager.GuestSyncForHostDisplay(Display);
  auto HostInfo = LookupHostVisualInfo(Display, Info);
  auto ret = fexldr_ptr_libGL_glXCreateGLXPixmapMESA(Display, HostInfo, Pixmap, Colormap);
  x11_manager.HostXFree(HostInfo);
  return ret;
}

int fexfn_impl_libGL_glXGetConfig(Display* Display, guest_layout<XVisualInfo*> Info, int Attribute, int* Value) {
  auto HostInfo = LookupHostVisualInfo(Display, Info);
  auto ret = fexldr_ptr_libGL_glXGetConfig(Display, HostInfo, Attribute, Value);
  x11_manager.HostXFree(HostInfo);
  return ret;
}

guest_layout<XVisualInfo*> fexfn_impl_libGL_glXGetVisualFromFBConfig(Display* Display, GLXFBConfig Config) {
  return MapToGuestVisualInfo(Display, fexldr_ptr_libGL_glXGetVisualFromFBConfig(Display, Config));
}

#ifdef IS_32BIT_THUNK
void fexfn_impl_libGL_glBindBuffersRange(GLenum a_0, GLuint a_1, GLsizei Count, const GLuint* a_3, guest_layout<const int*> Offsets,
                                         guest_layout<const int*> Sizes) {
  auto HostOffsets = (GLintptr*)alloca(Count * sizeof(GLintptr));
  auto HostSizes = (GLsizeiptr*)alloca(Count * sizeof(GLsizeiptr));
  for (int i = 0; i < Count; ++i) {
    HostOffsets[i] = Offsets.get_pointer()[i].data;
    HostSizes[i] = Sizes.get_pointer()[i].data;
  }
  return fexldr_ptr_libGL_glBindBuffersRange(a_0, a_1, Count, a_3, HostOffsets, HostSizes);
}

void fexfn_impl_libGL_glBindVertexBuffers(GLuint a_0, GLsizei count, const GLuint* a_2, guest_layout<const int*> Offsets, const GLsizei* a_4) {
  auto HostOffsets = (GLintptr*)alloca(count * sizeof(GLintptr));
  for (int i = 0; i < count; ++i) {
    HostOffsets[i] = Offsets.get_pointer()[i].data;
  }
  fexldr_ptr_libGL_glBindVertexBuffers(a_0, count, a_2, HostOffsets, a_4);
}

void fexfn_impl_libGL_glGetUniformIndices(GLuint a_0, GLsizei Count, guest_layout<const GLchar* const*> Names, GLuint* a_3) {
  auto HostNames = (const GLchar**)alloca(Count * sizeof(GLintptr));
  for (int i = 0; i < Count; ++i) {
    HostNames[i] = host_layout<const char* const> {Names.get_pointer()[i]}.data;
  }
  fexldr_ptr_libGL_glGetUniformIndices(a_0, Count, HostNames, a_3);
}

void fexfn_impl_libGL_glVertexArrayVertexBuffers(GLuint a_0, GLuint a_1, GLsizei count, const GLuint* a_3, guest_layout<const int*> Offsets,
                                                 const GLsizei* a_5) {
  auto HostOffsets = (GLintptr*)alloca(count * sizeof(GLintptr));
  for (int i = 0; i < count; ++i) {
    HostOffsets[i] = Offsets.get_pointer()[i].data;
  }
  fexldr_ptr_libGL_glVertexArrayVertexBuffers(a_0, a_1, count, a_3, HostOffsets, a_5);
}

void fexfn_impl_libGL_glXGetSelectedEvent(Display* Display, GLXDrawable Drawable, guest_layout<uint32_t*> Mask) {
  unsigned long HostMask;
  fexldr_ptr_libGL_glXGetSelectedEvent(Display, Drawable, &HostMask);
  *Mask.get_pointer() = HostMask;
}
void fexfn_impl_libGL_glXGetSelectedEventSGIX(Display* Display, GLXDrawable Drawable, guest_layout<uint32_t*> Mask) {
  unsigned long HostMask;
  fexldr_ptr_libGL_glXGetSelectedEventSGIX(Display, Drawable, &HostMask);
  *Mask.get_pointer() = HostMask;
}
#endif

EXPORTS(libGL)
