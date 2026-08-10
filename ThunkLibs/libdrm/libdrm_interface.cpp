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
// ---- 32-bit guest struct repacking ----
//
// drmDevice contains two unions of pointers (businfo/deviceinfo, discriminated by
// bustype) plus a "char **nodes" array (DRM_NODE_MAX == 3 entries). All three are
// pointer-shaped members whose in-memory representation differs between a 32-bit
// guest (4-byte pointers) and the 64-bit host (8-byte pointers), so none of them can
// be treated as bit-compatible or repacked automatically -- automatic repacking can't
// know which arm of a union is active, and it only widens/narrows a *single* pointer
// value, it doesn't know to walk an array of guest-sized sub-pointers hiding behind a
// pointer-to-pointer member. All three are handled by one fex_custom_repack_entry/exit
// pair for drmDevice (see Host.cpp), keyed off the already-repacked "bustype" member
// (custom_repack entry runs *after* automatic repacking of plain members, so bustype
// is trustworthy by the time the custom code runs).
template<>
struct fex_gen_type<drmDevice> : fexgen::emit_layout_wrappers {};
template<>
struct fex_gen_config<&drmDevice::nodes> : fexgen::custom_repack {};
template<>
struct fex_gen_config<&drmDevice::businfo> : fexgen::custom_repack {};
template<>
struct fex_gen_config<&drmDevice::deviceinfo> : fexgen::custom_repack {};

// The structs pointed to by drmDevice::businfo's union arms contain only fixed-size
// integers and char arrays -- no pointers, no `long`/`unsigned long` -- so i686 and
// x86_64 lay them out identically and a plain bitwise copy (assume_compatible_data_layout)
// is correct.
template<>
struct fex_gen_type<drmPciBusInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmUsbBusInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmPlatformBusInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmHost1xBusInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmFauxBusInfo> : fexgen::assume_compatible_data_layout {};

// Likewise for most of deviceinfo's union arms...
template<>
struct fex_gen_type<drmPciDeviceInfo> : fexgen::assume_compatible_data_layout {};
template<>
struct fex_gen_type<drmUsbDeviceInfo> : fexgen::assume_compatible_data_layout {};

// ...except drmPlatformDeviceInfo and drmHost1xDeviceInfo, which each hold a single
// "char **compatible" member: a NULL-terminated list of strings. Same problem as
// drmDevice::nodes above (pointer-to-pointer, guest/host pointer width differs), so
// this needs its own custom_repack that walks the guest list until a NULL entry and
// builds an equivalent host-side NULL-terminated char** (and the reverse on exit, if
// these are ever guest-populated -- in practice libdrm only ever fills these itself).
template<>
struct fex_gen_type<drmPlatformDeviceInfo> : fexgen::emit_layout_wrappers {};
template<>
struct fex_gen_config<&drmPlatformDeviceInfo::compatible> : fexgen::custom_repack {};
template<>
struct fex_gen_type<drmHost1xDeviceInfo> : fexgen::emit_layout_wrappers {};
template<>
struct fex_gen_config<&drmHost1xDeviceInfo::compatible> : fexgen::custom_repack {};

// drmStatsT ("Anonymous sub-structs" above) has no unions and no pointers of its own
// (its `data[]` entries hold `unsigned long`/`const char *` members, both of which the
// automatic repacking machinery already understands: `unsigned long` is a plain builtin
// integer that gets width-converted like any other scalar, and `const char *` is a
// single-level pointer to opaque bytes shared between guest and host). What it does
// have is `unsigned long count` and `data[].value`, which are 4 bytes on an i686 guest
// and 8 bytes on the x86_64 host -- so, unlike on 64-bit, the struct is genuinely NOT
// bit-compatible here and assume_compatible_data_layout would silently corrupt it
// (misaligning every field after the first `unsigned long`). Leaving drmStatsT
// unannotated lets the generator fall back to normal member-wise repacking, which
// handles the width difference correctly.

// drmServerInfo's three members are raw function pointers (debug_print, load_module,
// get_perms) that the X server implements and libdrm's drmSetServerInfo() stashes away
// to call back into later. This is X-server (root-only) infrastructure: it exists to
// let the DDX driver hook into libdrm's internals and is never touched by an
// unprivileged client like a Mesa-based GLX/EGL application. Rather than build guest
// callback trampolines for an API our target consumer never calls, we exclude
// drmServerInfo/drmSetServerInfo from the 32-bit thunk entirely (see below); a guest
// that genuinely needs this (i.e. a 32-bit X server) would need real vtable/callback
// conversion, not a data-layout annotation.

// drmEventContext also carries raw function pointers (vblank_handler, page_flip_handler,
// page_flip_handler2, sequence_handler). Its only consumer is drmHandleEvent, which is
// excluded on 32-bit (see the comment there for the measurement showing nothing in the
// target Mesa stack imports it), so the type needs no layout wrappers at all here.
#endif

size_t FEX_usable_size(void*);
void FEX_free_on_host(void*);

template<>
struct fex_gen_config<FEX_usable_size> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<FEX_free_on_host> : fexgen::custom_host_impl, fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<drmIoctl> {};
template<>
struct fex_gen_config<drmGetHashTable> {};
template<>
struct fex_gen_config<drmGetEntry> {};
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
template<>
struct fex_gen_config<drmGetVersion> {};
template<>
struct fex_gen_config<drmGetLibVersion> {};
template<>
struct fex_gen_config<drmGetCap> {};
template<>
struct fex_gen_config<drmFreeVersion> {};
template<>
struct fex_gen_config<drmGetMagic> {};
template<>
struct fex_gen_config<drmGetBusid> {};
template<>
struct fex_gen_config<drmGetInterruptFromBusID> {};
template<>
struct fex_gen_config<drmGetMap> {};
template<>
struct fex_gen_config<drmGetClient> {};
template<>
struct fex_gen_config<drmGetStats> {};
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
template<>
struct fex_gen_config<drmFreeBusid> {};
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
template<>
struct fex_gen_config<drmGetContextTag> {};
template<>
struct fex_gen_config<drmGetReservedContextList> {};
template<>
struct fex_gen_config<drmFreeReservedContextList> {};
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
template<>
struct fex_gen_config<drmGetDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<drmGetDeviceNameFromFd2> : fexgen::custom_guest_entrypoint {};

template<>
struct fex_gen_config<drmGetNodeTypeFromFd> {};
template<>
struct fex_gen_config<drmPrimeHandleToFD> {};
template<>
struct fex_gen_config<drmPrimeFDToHandle> {};
template<>
struct fex_gen_config<drmGetPrimaryDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};
template<>
struct fex_gen_config<drmGetRenderDeviceNameFromFd> : fexgen::custom_guest_entrypoint {};

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
template<>
struct fex_gen_config<drmDevicesEqual> {};
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
