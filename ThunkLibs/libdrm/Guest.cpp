/*
$info$
tags: thunklibs|drm
$end_info$
*/

#include <xf86drm.h>

#include <stdio.h>
#include <cstdlib>
#include <cstring>

#include "common/Guest.h"
#include <stdarg.h>

#include "thunkgen_guest_libdrm.inl"

extern "C" {

#ifndef IS_32BIT_THUNK
void FEX_malloc_free_on_host(void* Ptr) {
  struct {
    void* p;
  } args;
  args.p = Ptr;
  fexthunks_libdrm_FEX_free_on_host(&args);
}

size_t FEX_malloc_usable_size(void* Ptr) {
  struct {
    void* p;
    size_t rv;
  } args;
  args.p = Ptr;
  fexthunks_libdrm_FEX_usable_size(&args);
  return args.rv;
}
#endif

void drmMsg(const char* format, ...) {
  va_list ap;
  if (1) {
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
  }
}

#ifndef IS_32BIT_THUNK

// The caller-frees string family: the host hands back its own heap pointer.
// The guest's free() must own the result (that is the libdrm API contract for
// these), so copy it onto the guest heap and release the host allocation.
static char* RelocateToGuestHeap(char* ret) {
  if (ret) {
    // Usable size
    size_t Usable = FEX_malloc_usable_size(ret);

    // This will be a bit wasteful but this is an unsized pointer
    void* NewPtr = malloc(Usable);
    memcpy(NewPtr, ret, Usable);

    FEX_malloc_free_on_host(ret);
    ret = (char*)NewPtr;
  }

  return ret;
}

char* drmGetDeviceNameFromFd(int a_0) {
  return RelocateToGuestHeap(fexfn_pack_drmGetDeviceNameFromFd(a_0));
}

char* drmGetDeviceNameFromFd2(int a_0) {
  return RelocateToGuestHeap(fexfn_pack_drmGetDeviceNameFromFd2(a_0));
}

char* drmGetPrimaryDeviceNameFromFd(int a_0) {
  return RelocateToGuestHeap(fexfn_pack_drmGetPrimaryDeviceNameFromFd(a_0));
}

char* drmGetRenderDeviceNameFromFd(int a_0) {
  return RelocateToGuestHeap(fexfn_pack_drmGetRenderDeviceNameFromFd(a_0));
}

char* drmGetFormatModifierName(uint64_t a_0) {
  return RelocateToGuestHeap(fexfn_pack_drmGetFormatModifierName(a_0));
}

#else

// 32-bit lane: the custom host impls already materialize every one of these
// results on the *guest* heap (see Host.cpp), so the wrappers are plain pack
// calls and the guest's free() owns each result.
char* drmGetDeviceNameFromFd(int a_0) {
  return fexfn_pack_drmGetDeviceNameFromFd(a_0);
}

char* drmGetDeviceNameFromFd2(int a_0) {
  return fexfn_pack_drmGetDeviceNameFromFd2(a_0);
}

char* drmGetPrimaryDeviceNameFromFd(int a_0) {
  return fexfn_pack_drmGetPrimaryDeviceNameFromFd(a_0);
}

char* drmGetRenderDeviceNameFromFd(int a_0) {
  return fexfn_pack_drmGetRenderDeviceNameFromFd(a_0);
}

char* drmGetFormatModifierName(uint64_t a_0) {
  return fexfn_pack_drmGetFormatModifierName(a_0);
}

// The free half of the host-materialized objects. Each drmGetVersion/
// drmGetDevice*/drmGetBusid result is exactly one guest malloc block (strings
// and sub-structs live inside it), so freeing is exactly one free() -- no
// host call involved. These are excluded from the generated thunks on 32-bit
// (see libdrm_interface.cpp); the definitions here provide the exports.
void drmFreeVersion(drmVersionPtr v) {
  free(v);
}

void drmFreeDevice(drmDevicePtr* device) {
  if (!device || !*device) {
    return;
  }
  free(*device);
  *device = nullptr;
}

void drmFreeDevices(drmDevicePtr devices[], int count) {
  if (!devices) {
    return;
  }
  for (int i = 0; i < count; ++i) {
    if (devices[i]) {
      free(devices[i]);
      devices[i] = nullptr;
    }
  }
}

void drmFreeBusid(const char* busid) {
  free(const_cast<char*>(busid));
}

#endif
}

#ifdef IS_32BIT_THUNK
// Wrapper around malloc() without noexcept specifiers
static void* malloc_wrapper(size_t size) {
  return malloc(size);
}

static void OnInit() {
  // Hand the host our allocator so it can materialize host-allocated returns
  // (drmVersion/drmDevice/strings) in guest-addressable memory.
  fexfn_pack_DRM_SetGuestMalloc((uintptr_t)malloc_wrapper, (uintptr_t)CallbackUnpack<decltype(malloc_wrapper)>::Unpack);
}

LOAD_LIB_INIT(libdrm, OnInit)
#else
LOAD_LIB(libdrm)
#endif
