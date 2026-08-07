/*
$info$
tags: thunklibs|xshmfence
$end_info$
*/

#include <stdio.h>

#include <X11/xshmfence.h>

#include "common/Host.h"
#include <dlfcn.h>

#if defined(IS_32BIT_THUNK)
#include <mutex>
#include <unordered_map>
#include <vector>

// struct xshmfence* is a host pointer to an mmap'd fence page
// (xshmfence_map_shm), living at 0x3fff'xxxx'xxxx on ppc64le. A 32-bit guest
// slot can't hold that, and unlike a truncated string pointer the damage
// used to be silent: the guest stored the truncated value and handed it
// straight back to xshmfence_trigger/await/query/reset/unmap_shm, which
// would then operate on whatever unrelated low address happened to alias it.
// host_to_guest_convertible's pointer conversion now aborts instead of
// truncating (see Host.h), so this would otherwise be a hard abort on the
// first xshmfence_map_shm call from a 32-bit guest.
//
// xshmfence is declared fexgen::opaque_type and the guest never dereferences
// it (X11/xshmfence.h only ever passes it back into the API below), so - as
// with GLXFBConfig/GLXContext in libGL_Host.cpp - hand out a stable 32-bit
// token instead of the real pointer, and translate back on the way in. This
// reuses the exact OpaqueHandleRegistry shape from libGL_Host.cpp; see there
// for the reasoning behind the token layout and Retire semantics.
namespace {
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
    const uint32_t Index = Token - TokenBase;
    if (Token < TokenBase || Index >= ByIndex.size()) {
      // Not one of ours. Pass it through rather than inventing a null: a
      // guest that obtained a handle by some path we do not model should
      // fail in the driver with its own diagnostics, not silently here.
      return reinterpret_cast<T*>(static_cast<uintptr_t>(Token));
    }
    // Null here means the handle was retired (see Retire) - the guest is
    // using it after xshmfence_unmap_shm. Returning null makes the real
    // libxshmfence entry points fault predictably on a null pointer instead
    // of operating on an unmapped page that may since have been reused.
    return ByIndex[Index];
  }

  // Drop a handle whose backing mapping is being torn down
  // (xshmfence_unmap_shm). The slot is kept (so later tokens keep their
  // meaning) but emptied, and the pointer is un-interned so that an mmap
  // that reuses the address does not resurrect the retired token for an
  // unrelated fence.
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

// Single handle type here, so a single token range is enough - no risk of a
// handle of the wrong type resolving to a real-but-wrong pointer the way
// libGL's FBConfigRegistry/ContextRegistry needed to guard against.
OpaqueHandleRegistry<xshmfence, 0xFE00'0000> XshmfenceRegistry;
} // namespace

template<>
struct host_layout<xshmfence*> {
  xshmfence* data;

  explicit host_layout(const guest_layout<xshmfence*>& guest)
    : data(XshmfenceRegistry.ForToken(static_cast<uint32_t>(guest.data))) {}
};

guest_layout<xshmfence*> to_guest(const host_layout<xshmfence*>& from) {
  guest_layout<xshmfence*> Result {};
  Result.data = XshmfenceRegistry.TokenFor(from.data);
  return Result;
}
#endif

#include "thunkgen_host_libxshmfence.inl"

EXPORTS(libxshmfence)

// See the custom_host_impl comment on xshmfence_unmap_shm in
// libxshmfence_interface.cpp: on a 32-bit guest, retire the token before the
// mapping goes away so a stale guest-held token resolves to null (see
// OpaqueHandleRegistry::ForToken) instead of a freed/reused host pointer.
// On 64-bit there is no token registry - struct xshmfence* is a plain
// passthrough pointer - so this is identical to the pre-existing
// (non-custom) generated call.
static void fexfn_impl_libxshmfence_xshmfence_unmap_shm(struct xshmfence* f) {
#if defined(IS_32BIT_THUNK)
  XshmfenceRegistry.Retire(f);
#endif
  fexldr_ptr_libxshmfence_xshmfence_unmap_shm(f);
}
