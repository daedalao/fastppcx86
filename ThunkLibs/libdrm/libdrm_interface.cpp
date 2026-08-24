#include <common/GeneratorInterface.h>

#include <xf86drm.h>

template<auto>
struct fex_gen_config {
  unsigned version = 2;
};

template<typename>
struct fex_gen_type {};

// Function, parameter index, parameter type [optional]
template<auto, int, typename = void>
struct fex_gen_param {};

#ifndef IS_32BIT_THUNK
// On a 64-bit guest, pointers are the same width on both sides of the thunk and guest
// and host share the same virtual address space. That makes every one of the types
// below "bit compatible" as-is: no member needs repacking, and pointers found inside
// these structs can be dereferenced by the host directly without any translation.
// None of this holds on a 32-bit guest (4-byte guest pointers vs 8-byte host pointers,
// so the very shape of these structs differs) -- see the 32-bit-specific handling
// further down for each of these types.
template<>
struct fex_gen_type<drmDevice> : fexgen::assume_compatible_data_layout {};

// Anonymous sub-structs
template<>
struct fex_gen_type<drmStatsT> : fexgen::assume_compatible_data_layout {};

// TODO: Convert vtable
template<>
struct fex_gen_type<drmServerInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmEventContext> : fexgen::assume_compatible_data_layout {};
#else
// ---- 32-bit guest handling of the pointer-bearing structs ----
//
// None of the pointer-bearing libdrm structs go through the generator's layout
// wrappers on 32-bit. An earlier sketch annotated drmDevice with
// emit_layout_wrappers + custom_repack for nodes/businfo/deviceinfo, but that
// cannot work: businfo and deviceinfo are members of *anonymous union* type, and
// the generator names such types with an "unnamed_type_..." placeholder that is
// deliberately uncompilable when referenced (see get_type_name in
// Generator/analysis.h) -- guest_layout<drmDevice> would never build.
//
// Instead, every function that produces or consumes one of these structs is a
// custom_host_impl on 32-bit, with the drmDevicePtr/drmVersionPtr parameters and
// returns passed through raw (ptr_passthrough). Host.cpp defines hand-written
// i686 images of drmVersion and drmDevice (with static_asserts pinning the
// layout) and materializes each host-allocated return as a single guest-heap
// allocation -- the same GuestMalloc trampoline pattern libGL's
// RelocateArrayToGuestHeap uses. Because one returned object is exactly one
// guest malloc block, the matching guest-side drmFreeVersion/drmFreeDevice(s)
// (Guest.cpp) are plain free() and the free path unwinds per-call exactly.
//
// The structs behind businfo/deviceinfo's union arms (drmPciBusInfo,
// drmPciDeviceInfo, ...) contain only fixed-size integers and char arrays -- no
// pointers, no `long` -- so i686 and x86_64 lay them out identically and
// Host.cpp copies them bytewise. drmPlatformDeviceInfo/drmHost1xDeviceInfo's
// "char **compatible" string lists are rebuilt inside the same guest block.
//
// drmServerInfo and drmEventContext carry raw function pointers the host would
// have to call back through; their only consumers (drmSetServerInfo,
// drmHandleEvent) are excluded below, so the types need no handling at all.
#endif

#ifndef IS_32BIT_THUNK
// 64-bit only: the guest-side wrappers for the caller-frees string returns
// (drmGetDeviceNameFromFd & co) copy the host allocation onto the guest heap
// via its malloc_usable_size and then release it host-side. On 32-bit the
// host pointer cannot even reach the guest, so the relocation happens in the
// custom host impls instead and this pair is not needed.
size_t FEX_usable_size(void*);
void FEX_free_on_host(void*);

template<>
struct fex_gen_config<FEX_usable_size> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<FEX_free_on_host> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
#else
// 32-bit only: guest OnInit registers the guest allocator so the host impls
// can materialize host-allocated returns in guest-addressable memory. Same
// shape as libGL's GL_SetGuestMalloc.
void DRM_SetGuestMalloc(uintptr_t, uintptr_t);

template<>
struct fex_gen_config<DRM_SetGuestMalloc> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
#endif
// drmIoctl's payload crosses as-is (void*, shared address space). On a 32-bit
// guest this is sound for the ioctls Mesa actually issues directly -- the
// driver-specific amdgpu/radeon/GEM/syncobj/prime ioctls are fixed-width and
// 64-bit-aligned by kernel-ABI design, so i386 and x86_64 layouts agree. The
// legacy core ioctls whose structs genuinely differ (VERSION, GET_UNIQUE,
// MAP...) are reached through the libdrm wrappers thunked below, which the
// host rebuilds natively.
template<>
struct fex_gen_config<drmIoctl> {};
#ifndef IS_32BIT_THUNK
// The libdrm-internal hash table is a host-heap object: drmGetHashTable
// returns a raw host pointer and drmHashEntry carries a function pointer plus
// a tag-table pointer. A 32-bit guest slot cannot hold either, so both stay
// 64-bit only (nothing in the lib32 Mesa stack imports them).
template<>
struct fex_gen_config<drmGetHashTable> {};
template<>
struct fex_gen_config<drmGetEntry> {};
#endif
template<>
struct fex_gen_config<drmAvailable> {};
template<>
struct fex_gen_config<drmOpen> {};
template<>
struct fex_gen_config<drmOpenWithType> {};
template<>
struct fex_gen_config<drmOpenControl> {};
template<>
struct fex_gen_config<drmOpenRender> {};
template<>
struct fex_gen_config<drmClose> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetVersion> {};
template<>
struct fex_gen_config<drmGetLibVersion> {};
#else
// drmVersion is host-allocated and pointer-bearing: the custom impls rebuild
// it as a single i686-layout guest-heap block (see Host.cpp). drmFreeVersion
// is guest-local free() in Guest.cpp, so it must not be thunked here.
template<>
struct fex_gen_config<drmGetVersion> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetVersion, -1, drmVersionPtr> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetLibVersion> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetLibVersion, -1, drmVersionPtr> : fexgen::ptr_passthrough {};
#endif
template<>
struct fex_gen_config<drmGetCap> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmFreeVersion> {};
#endif
template<>
struct fex_gen_config<drmGetMagic> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetBusid> {};
#else
// Returns a host drmMalloc'd string; relocated onto the guest heap by the
// custom impl. The matching drmFreeBusid is guest-local free() in Guest.cpp.
template<>
struct fex_gen_config<drmGetBusid> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetBusid, -1, char*> : fexgen::ptr_passthrough {};
#endif
template<>
struct fex_gen_config<drmGetInterruptFromBusID> {};
template<>
struct fex_gen_config<drmGetMap> {};
template<>
struct fex_gen_config<drmGetClient> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetStats> {};
#else
// drmStatsT's data[] member is an array of *anonymous struct* type. The ABI
// mapper keys member types by name and anonymous types only get an
// uncompilable "unnamed_type_..." placeholder, so 32-bit generation cannot
// repack this struct (and it is genuinely not bit-compatible here: `unsigned
// long count`/`data[].value` are 4 guest bytes vs 8 host bytes). DRI1-era
// diagnostics API; nothing in the lib32 Mesa stack imports it. Excluded.
#endif
template<>
struct fex_gen_config<drmSetInterfaceVersion> {};
template<>
struct fex_gen_config<drmCommandNone> {};
template<>
struct fex_gen_config<drmCommandRead> {};
template<>
struct fex_gen_config<drmCommandWrite> {};
template<>
struct fex_gen_config<drmCommandWriteRead> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmFreeBusid> {};
#endif
template<>
struct fex_gen_config<drmSetBusid> {};
template<>
struct fex_gen_config<drmAuthMagic> {};
template<>
struct fex_gen_config<drmAddMap> {};
template<>
struct fex_gen_config<drmRmMap> {};
template<>
struct fex_gen_config<drmAddContextPrivateMapping> {};
template<>
struct fex_gen_config<drmAddBufs> {};
template<>
struct fex_gen_config<drmMarkBufs> {};
template<>
struct fex_gen_config<drmCreateContext> {};
template<>
struct fex_gen_config<drmSetContextFlags> {};
template<>
struct fex_gen_config<drmGetContextFlags> {};
template<>
struct fex_gen_config<drmAddContextTag> {};
template<>
struct fex_gen_config<drmDelContextTag> {};
#ifndef IS_32BIT_THUNK
// drmGetContextTag's void** out-parameter would have the host write an 8-byte
// pointer through a 4-byte guest slot; drmGetReservedContextList returns a
// host drmMalloc'd array its Free partner must see again. All DRI1
// master/X-server API, unreachable from the lib32 Mesa stack. Excluded on
// 32-bit (drmAddContextTag/drmDelContextTag above stay: they only store a
// value).
template<>
struct fex_gen_config<drmGetContextTag> {};
template<>
struct fex_gen_config<drmGetReservedContextList> {};
template<>
struct fex_gen_config<drmFreeReservedContextList> {};
#endif
template<>
struct fex_gen_config<drmSwitchToContext> {};
template<>
struct fex_gen_config<drmDestroyContext> {};
template<>
struct fex_gen_config<drmCreateDrawable> {};
template<>
struct fex_gen_config<drmDestroyDrawable> {};
template<>
struct fex_gen_config<drmUpdateDrawableInfo> {};
template<>
struct fex_gen_config<drmCtlInstHandler> {};
template<>
struct fex_gen_config<drmCtlUninstHandler> {};
template<>
struct fex_gen_config<drmSetClientCap> {};
template<>
struct fex_gen_config<drmCrtcGetSequence> {};
template<>
struct fex_gen_config<drmCrtcQueueSequence> {};
#ifndef IS_32BIT_THUNK
// The DRI1 mapping surface cannot cross the 32-bit boundary: drmMap writes a
// host mapping address through a void** out-parameter (8 bytes into a 4-byte
// guest slot, and the VA does not fit 32 bits anyway), and
// drmGetBufInfo/drmMapBufs return host-heap structs whose `list` members
// point at further host structs carrying mapped-buffer addresses. Nothing in
// the lib32 Mesa DRI3 stack imports any of these. Excluded on 32-bit; a
// missing symbol makes the one guest that wants it fail visibly at load
// instead of corrupting silently.
template<>
struct fex_gen_config<drmMap> {};
template<>
struct fex_gen_config<drmUnmap> {};
template<>
struct fex_gen_config<drmGetBufInfo> {};
template<>
struct fex_gen_config<drmMapBufs> {};
template<>
struct fex_gen_config<drmUnmapBufs> {};
#endif
template<>
struct fex_gen_config<drmDMA> {};
template<>
struct fex_gen_config<drmFreeBufs> {};
template<>
struct fex_gen_config<drmGetLock> {};
template<>
struct fex_gen_config<drmUnlock> {};
template<>
struct fex_gen_config<drmFinish> {};
template<>
struct fex_gen_config<drmGetContextPrivateMapping> {};
template<>
struct fex_gen_config<drmScatterGatherAlloc> {};
template<>
struct fex_gen_config<drmScatterGatherFree> {};
#ifdef IS_32BIT_THUNK
// drmVBlank is `union { drmVBlankReq request; drmVBlankReply reply; }`, and unlike
// drmDevice's unions this one isn't just a union-of-pointers problem: drmVBlankReq has
// an `unsigned long signal`, and drmVBlankReply has `long tval_sec`/`long tval_usec` --
// both 4 bytes on an i686 guest, 8 bytes on the x86_64 host, so the union genuinely has
// two different-sized/-offset layouts to repack, on top of needing a custom_repack to
// even pick which arm to look at (the two arms share a `type` field at the same offset
// as their discriminant, so it's doable). drmWaitVBlank is the legacy DRI1 vblank-wait
// ioctl wrapper, superseded by drmHandleEvent()/the DRI2+ present/vblank event path
// that our target Mesa DRI3 stack actually uses; it's also normally restricted to the
// active master. Given it isn't reachable from the consumer we're targeting, we exclude
// it here rather than build repacking for a union type nothing exercises. A real fix
// would add a custom_repack for drmVBlank keyed off request.type/reply.type, handling
// the `long`/`unsigned long` width difference member-by-member.
#else
template<>
struct fex_gen_config<drmWaitVBlank> {};
#endif

#ifdef IS_32BIT_THUNK
// See the drmServerInfo comment above the fex_gen_type block: X-server-only,
// unreachable from our target consumer, and would require real function-pointer
// vtable conversion rather than a data-layout fix. Excluded on 32-bit.
#else
template<>
struct fex_gen_config<drmSetServerInfo> {};
#endif
template<>
struct fex_gen_config<drmError> {};
#ifndef IS_32BIT_THUNK
// drmMalloc/drmHashCreate/drmRandomCreate/drmSLCreate all hand the guest a
// raw host-heap pointer (as void*), which does not fit a 32-bit guest slot;
// the rest of each family consumes those handles. Utility API for DDX
// drivers, unused by the lib32 Mesa stack. Excluded on 32-bit; if a consumer
// ever appears, the fix is an opaque-handle token registry as in
// libxshmfence/libGL, not a data-layout annotation.
template<>
struct fex_gen_config<drmMalloc> {};
template<>
struct fex_gen_config<drmFree> {};
template<>
struct fex_gen_config<drmHashCreate> {};
template<>
struct fex_gen_config<drmHashDestroy> {};
template<>
struct fex_gen_config<drmHashLookup> {};
template<>
struct fex_gen_config<drmHashInsert> {};
template<>
struct fex_gen_config<drmHashDelete> {};
template<>
struct fex_gen_config<drmHashFirst> {};
template<>
struct fex_gen_config<drmHashNext> {};
template<>
struct fex_gen_config<drmRandomCreate> {};
template<>
struct fex_gen_config<drmRandomDestroy> {};
template<>
struct fex_gen_config<drmRandom> {};
template<>
struct fex_gen_config<drmRandomDouble> {};
template<>
struct fex_gen_config<drmSLCreate> {};
template<>
struct fex_gen_config<drmSLDestroy> {};
template<>
struct fex_gen_config<drmSLLookup> {};
template<>
struct fex_gen_config<drmSLInsert> {};
template<>
struct fex_gen_config<drmSLDelete> {};
template<>
struct fex_gen_config<drmSLNext> {};
template<>
struct fex_gen_config<drmSLFirst> {};
template<>
struct fex_gen_config<drmSLDump> {};
template<>
struct fex_gen_config<drmSLLookupNeighbors> {};
#endif
template<>
struct fex_gen_config<drmOpenOnce> {};
template<>
struct fex_gen_config<drmOpenOnceWithType> {};
template<>
struct fex_gen_config<drmCloseOnce> {};
template<>
struct fex_gen_config<drmSetMaster> {};
template<>
struct fex_gen_config<drmDropMaster> {};
template<>
struct fex_gen_config<drmIsMaster> {};
#ifdef IS_32BIT_THUNK
// drmEventContext holds four raw handler function pointers (vblank_handler,
// page_flip_handler, page_flip_handler2, sequence_handler) that libdrm calls back
// into synchronously while decoding events off the DRM fd. Supporting that on a
// 32-bit guest means building a host trampoline per non-null handler and registering
// a guest unpacker for each signature — real callback-bridging work, not a
// data-layout annotation.
//
// Excluded for now because nothing in the target stack calls it. Measured against the
// 32-bit rootfs: neither libGLX_mesa.so.0 nor libEGL_mesa.so.0 imports drmHandleEvent,
// and neither does any of the 66 modules under lib32/dri. It is a KMS/display-server
// entry point (weston, kmscube, DDX drivers), not something a GLX/EGL client reaches.
//
// If a future consumer needs it, the fix is custom_host_impl + custom_guest_entrypoint
// plus AllocateHostTrampolineForGuestFunction for each non-null handler — see the
// callback handling in libwayland-client for the established shape.
#else
template<>
struct fex_gen_config<drmHandleEvent> {};
#endif
// The caller-frees string family. On 64-bit the guest wrapper copies the host
// allocation onto the guest heap (FEX_usable_size dance in Guest.cpp) so the
// guest's free() owns the result. On 32-bit the custom host impl relocates the
// string onto the guest heap directly -- the host pointer would not even fit
// the packed return slot -- and the guest wrapper is a plain pack call.
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<drmGetDeviceNameFromFd2> : fexgen::custom_guest_entrypoint {};
#else
template<>
struct fex_gen_config<drmGetDeviceNameFromFd> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDeviceNameFromFd, -1, char*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetDeviceNameFromFd2> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDeviceNameFromFd2, -1, char*> : fexgen::ptr_passthrough {};
#endif

template<>
struct fex_gen_config<drmGetNodeTypeFromFd> {};
template<>
struct fex_gen_config<drmPrimeHandleToFD> {};
template<>
struct fex_gen_config<drmPrimeFDToHandle> {};
// Modern GEM handle close; lib32/lib64 Mesa gallium binds it at load (BIND_NOW).
template<>
struct fex_gen_config<drmCloseBufferHandle> {};
#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetPrimaryDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<drmGetRenderDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};
// Returns a malloc'd string the caller frees with free(); same relocation
// pattern as drmGetDeviceNameFromFd. Mesa gallium binds it at load.
template<>
struct fex_gen_config<drmGetFormatModifierName> : fexgen::custom_guest_entrypoint {};
#else
template<>
struct fex_gen_config<drmGetPrimaryDeviceNameFromFd> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetPrimaryDeviceNameFromFd, -1, char*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetRenderDeviceNameFromFd> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetRenderDeviceNameFromFd, -1, char*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetFormatModifierName> : fexgen::custom_guest_entrypoint, fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetFormatModifierName, -1, char*> : fexgen::ptr_passthrough {};
#endif

#ifndef IS_32BIT_THUNK
template<>
struct fex_gen_config<drmGetDevice> {};
template<>
struct fex_gen_config<drmFreeDevice> {};
template<>
struct fex_gen_config<drmGetDevices> {};
template<>
struct fex_gen_config<drmFreeDevices> {};
template<>
struct fex_gen_config<drmGetDevice2> {};
template<>
struct fex_gen_config<drmGetDevices2> {};
// EGL and radv resolve device-by-dev_t through this at load.
template<>
struct fex_gen_config<drmGetDeviceFromDevId> {};
template<>
struct fex_gen_config<drmDevicesEqual> {};
#else
// See the 32-bit design note at the top: drmDevice returns are materialized
// as single guest-heap blocks by the custom impls, the drmDevicePtr
// parameters stay in guest layout end to end, and drmFreeDevice/
// drmFreeDevices are guest-local free() in Guest.cpp.
template<>
struct fex_gen_config<drmGetDevice> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDevice, 1, drmDevicePtr*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetDevices> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDevices, 0, drmDevicePtr*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetDevice2> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDevice2, 2, drmDevicePtr*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetDevices2> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDevices2, 1, drmDevicePtr*> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_config<drmGetDeviceFromDevId> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmGetDeviceFromDevId, 2, drmDevicePtr*> : fexgen::ptr_passthrough {};
// Pure businfo comparison; the custom impl reads the guest images directly,
// mirroring libdrm's bustype-keyed memcmp.
template<>
struct fex_gen_config<drmDevicesEqual> : fexgen::custom_host_impl {};
template<>
struct fex_gen_param<drmDevicesEqual, 0, drmDevicePtr> : fexgen::ptr_passthrough {};
template<>
struct fex_gen_param<drmDevicesEqual, 1, drmDevicePtr> : fexgen::ptr_passthrough {};
#endif
template<>
struct fex_gen_config<drmSyncobjCreate> {};
template<>
struct fex_gen_config<drmSyncobjDestroy> {};
template<>
struct fex_gen_config<drmSyncobjHandleToFD> {};
template<>
struct fex_gen_config<drmSyncobjFDToHandle> {};
template<>
struct fex_gen_config<drmSyncobjImportSyncFile> {};
template<>
struct fex_gen_config<drmSyncobjExportSyncFile> {};
template<>
struct fex_gen_config<drmSyncobjWait> {};
template<>
struct fex_gen_config<drmSyncobjReset> {};
template<>
struct fex_gen_config<drmSyncobjSignal> {};
template<>
struct fex_gen_config<drmSyncobjTimelineSignal> {};
template<>
struct fex_gen_config<drmSyncobjTimelineWait> {};
template<>
struct fex_gen_config<drmSyncobjQuery> {};
template<>
struct fex_gen_config<drmSyncobjQuery2> {};
template<>
struct fex_gen_config<drmSyncobjTransfer> {};
