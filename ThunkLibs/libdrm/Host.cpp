/*
$info$
tags: thunklibs|drm
$end_info$
*/

#include <stdio.h>

#include <xf86drm.h>

#include "common/Host.h"
#include <dlfcn.h>
#include <malloc.h>

#ifdef IS_32BIT_THUNK
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <vector>
#endif

#include "thunkgen_host_libdrm.inl"

#ifndef IS_32BIT_THUNK

static size_t fexfn_impl_libdrm_FEX_usable_size(void* a_0) {
  return malloc_usable_size(a_0);
}

static void fexfn_impl_libdrm_FEX_free_on_host(void* a_0) {
  free(a_0);
}

#else

// ---- 32-bit guest lane -------------------------------------------------
//
// Host-allocated, pointer-bearing returns (drmVersion, drmDevice, the
// caller-frees strings) are rebuilt in *guest* heap memory with i686 layout.
// The allocator is the guest's own malloc, reached through a host->guest
// trampoline registered by the guest lib's OnInit (DRM_SetGuestMalloc) --
// the same pattern libGL's RelocateArrayToGuestHeap uses. Each returned
// object is exactly one guest allocation, so the guest-side drmFreeVersion/
// drmFreeDevice(s)/drmFreeBusid/free() unwind exactly what was allocated.

using guest_size_t = uint32_t;

static void* (*GuestMalloc)(guest_size_t) = nullptr;

static void fexfn_impl_libdrm_DRM_SetGuestMalloc(uintptr_t GuestTarget, uintptr_t GuestUnpacker) {
  // Build into a temporary and publish with a release store: the trampoline
  // bytes and GuestcallInfo must be visible to other threads before the
  // pointer that reaches them is (ppc64le is weakly ordered).
  decltype(GuestMalloc) Fn {};
  MakeHostTrampolineForGuestFunctionAt(GuestTarget, GuestUnpacker, &Fn);
  __atomic_store_n(&GuestMalloc, Fn, __ATOMIC_RELEASE);
}

// Allocate from the guest heap. Returns null before OnInit has registered the
// allocator (impossible for calls arriving through this library's own guest
// half) or on guest OOM.
static void* GuestMallocBytes(size_t Size) {
  auto* Malloc = __atomic_load_n(&GuestMalloc, __ATOMIC_ACQUIRE);
  if (!Malloc || Size > 0xFFFF'FFFFu) {
    return nullptr;
  }
  void* Ptr = Malloc(static_cast<guest_size_t>(Size));
  if (reinterpret_cast<uintptr_t>(Ptr) >> 32) {
    // A guest allocator can only ever return low-4GB memory; anything else
    // means the trampoline mis-fired. Dropping the block is safer than
    // handing out a truncated pointer.
    fprintf(stderr, "libdrm-host: guest malloc returned a non-guest address %p\n", Ptr);
    return nullptr;
  }
  return Ptr;
}

// i686 images of the pointer-bearing libdrm structs. Hand-built rather than
// generator-emitted: drmDevice's businfo/deviceinfo are members of anonymous
// union type, which the layout-wrapper generator cannot name (it emits an
// uncompilable "unnamed_type_..." placeholder), so these definitions are the
// ground truth for what the 32-bit guest sees. Every member is 4 bytes on
// i686, so the packed definitions below match the guest ABI exactly.
struct GuestDrmVersion {
  int32_t version_major;
  int32_t version_minor;
  int32_t version_patchlevel;
  int32_t name_len;
  uint32_t name; // char* in the guest
  int32_t date_len;
  uint32_t date; // char*
  int32_t desc_len;
  uint32_t desc; // char*
};
static_assert(sizeof(GuestDrmVersion) == 36, "i686 drmVersion: nine 4-byte members, no padding");

struct GuestDrmDevice {
  uint32_t nodes; // char** in the guest: DRM_NODE_MAX entries
  int32_t available_nodes;
  int32_t bustype;
  uint32_t businfo;    // union of pointers -> one 4-byte guest pointer
  uint32_t deviceinfo; // union of pointers -> one 4-byte guest pointer
};
static_assert(sizeof(GuestDrmDevice) == 20, "i686 drmDevice: five 4-byte members, no padding");

// The union arms' pointees carry only fixed-size integers and char arrays, so
// their layout is identical between i686 and the host and a bytewise copy is
// correct. Pin the sizes so a header change cannot silently break that.
static_assert(sizeof(drmPciBusInfo) == 6);
static_assert(sizeof(drmUsbBusInfo) == 2);
static_assert(sizeof(drmPlatformBusInfo) == DRM_PLATFORM_DEVICE_NAME_LEN);
static_assert(sizeof(drmHost1xBusInfo) == DRM_HOST1X_DEVICE_NAME_LEN);
static_assert(sizeof(drmPciDeviceInfo) == 10);
static_assert(sizeof(drmUsbDeviceInfo) == 4);
#ifdef DRM_BUS_FAUX
static_assert(sizeof(drmFauxBusInfo) == DRM_FAUX_DEVICE_NAME_LEN);
#endif

// Copies a NUL-terminated host string into a fresh guest-heap allocation the
// guest's free() owns. Returns 0 for null input or guest OOM.
static uint32_t RelocateStringToGuestHeap(const char* Str) {
  if (!Str) {
    return 0;
  }
  const size_t Bytes = strlen(Str) + 1;
  void* Guest = GuestMallocBytes(Bytes);
  if (!Guest) {
    return 0;
  }
  memcpy(Guest, Str, Bytes);
  return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Guest));
}

// Bump writer over one guest block. Run once with Block == nullptr to
// measure, then again against the real allocation -- the same code path
// computes the size and fills it, so the two cannot drift apart.
struct GuestBlockWriter {
  uint8_t* Block = nullptr;
  size_t Off = 0;

  void Align4() {
    Off = (Off + 3) & ~size_t {3};
  }

  // Reserves Bytes and returns the *guest* pointer to them (0 while
  // measuring). Copies Src if given.
  uint32_t Emit(const void* Src, size_t Bytes) {
    uint8_t* At = Block ? Block + Off : nullptr;
    if (At && Src) {
      memcpy(At, Src, Bytes);
    }
    const uint32_t GuestPtr = At ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(At)) : 0;
    Off += Bytes;
    return GuestPtr;
  }
};

static size_t BusInfoSize(int bustype) {
  switch (bustype) {
  case DRM_BUS_PCI: return sizeof(drmPciBusInfo);
  case DRM_BUS_USB: return sizeof(drmUsbBusInfo);
  case DRM_BUS_PLATFORM: return sizeof(drmPlatformBusInfo);
  case DRM_BUS_HOST1X: return sizeof(drmHost1xBusInfo);
#ifdef DRM_BUS_FAUX
  case DRM_BUS_FAUX: return sizeof(drmFauxBusInfo);
#endif
  default: return 0;
  }
}

// Lays one host drmVersion out as a single guest block:
//   [GuestDrmVersion][name\0][date\0][desc\0]
// Returns the guest pointer, or 0 on guest OOM.
static uint32_t MaterializeGuestVersion(const drmVersion* Host) {
  auto Build = [&](GuestBlockWriter& W) {
    GuestDrmVersion Out {};
    const uint32_t Base = W.Emit(nullptr, sizeof(GuestDrmVersion));
    Out.version_major = Host->version_major;
    Out.version_minor = Host->version_minor;
    Out.version_patchlevel = Host->version_patchlevel;
    Out.name_len = Host->name_len;
    Out.date_len = Host->date_len;
    Out.desc_len = Host->desc_len;
    Out.name = Host->name ? W.Emit(Host->name, strlen(Host->name) + 1) : 0;
    Out.date = Host->date ? W.Emit(Host->date, strlen(Host->date) + 1) : 0;
    Out.desc = Host->desc ? W.Emit(Host->desc, strlen(Host->desc) + 1) : 0;
    if (W.Block) {
      memcpy(W.Block, &Out, sizeof(Out));
    }
    return Base;
  };

  GuestBlockWriter Measure {};
  Build(Measure);
  GuestBlockWriter W {static_cast<uint8_t*>(GuestMallocBytes(Measure.Off))};
  if (!W.Block) {
    return 0;
  }
  return Build(W);
}

// Lays one host drmDevice out as a single guest block: the GuestDrmDevice
// header, the DRM_NODE_MAX node-pointer array, the bustype-selected businfo
// and deviceinfo copies (platform/host1x deviceinfo brings its NULL-terminated
// "compatible" string list along), then all strings. Returns the guest
// pointer, or 0 on guest OOM.
static uint32_t MaterializeGuestDevice(const drmDevice* Host) {
  // All union arms are pointers, so reading .pci merely reads the pointer bits
  // regardless of which arm is active -- same trick libdrm itself uses.
  const void* BusPtr = Host->businfo.pci;
  const void* DevPtr = Host->deviceinfo.pci;
  char* const* Compat = nullptr;
  if (DevPtr) {
    switch (Host->bustype) {
    case DRM_BUS_PLATFORM: Compat = Host->deviceinfo.platform->compatible; break;
    case DRM_BUS_HOST1X: Compat = Host->deviceinfo.host1x->compatible; break;
    default: break;
    }
  }

  auto Build = [&](GuestBlockWriter& W) {
    GuestDrmDevice Out {};
    const uint32_t Base = W.Emit(nullptr, sizeof(GuestDrmDevice));
    Out.available_nodes = Host->available_nodes;
    Out.bustype = Host->bustype;

    // Node pointer array; string bodies are emitted at the end of the block.
    uint32_t NodeSlots[DRM_NODE_MAX] = {};
    Out.nodes = W.Emit(nullptr, DRM_NODE_MAX * sizeof(uint32_t));
    const size_t NodesAt = W.Off - DRM_NODE_MAX * sizeof(uint32_t); // offset for the fill-in below

    if (BusPtr) {
      W.Align4();
      Out.businfo = W.Emit(BusPtr, BusInfoSize(Host->bustype));
    }

    if (DevPtr) {
      switch (Host->bustype) {
      case DRM_BUS_PCI:
        W.Align4();
        Out.deviceinfo = W.Emit(DevPtr, sizeof(drmPciDeviceInfo));
        break;
      case DRM_BUS_USB:
        W.Align4();
        Out.deviceinfo = W.Emit(DevPtr, sizeof(drmUsbDeviceInfo));
        break;
      case DRM_BUS_PLATFORM:
      case DRM_BUS_HOST1X: {
        // Guest image of {char** compatible}: a one-pointer struct, then the
        // NULL-terminated pointer array, then the strings.
        W.Align4();
        Out.deviceinfo = W.Emit(nullptr, sizeof(uint32_t));
        const size_t HolderOff = W.Off - sizeof(uint32_t);
        size_t Count = 0;
        while (Compat && Compat[Count]) {
          ++Count;
        }
        const uint32_t ArrayPtr = W.Emit(nullptr, (Count + 1) * sizeof(uint32_t));
        const size_t ArrayOff = W.Off - (Count + 1) * sizeof(uint32_t);
        for (size_t i = 0; i < Count; ++i) {
          const uint32_t StrPtr = W.Emit(Compat[i], strlen(Compat[i]) + 1);
          if (W.Block) {
            memcpy(W.Block + ArrayOff + i * sizeof(uint32_t), &StrPtr, sizeof(uint32_t));
          }
        }
        if (W.Block) {
          const uint32_t Null = 0;
          memcpy(W.Block + ArrayOff + Count * sizeof(uint32_t), &Null, sizeof(uint32_t));
          memcpy(W.Block + HolderOff, &ArrayPtr, sizeof(uint32_t));
        }
        break;
      }
      default:
        // Unknown bus type (e.g. a future addition): carry the identity
        // members and drop deviceinfo rather than guess at its shape.
        break;
      }
    }

    for (int i = 0; i < DRM_NODE_MAX; ++i) {
      const char* Node = Host->nodes ? Host->nodes[i] : nullptr;
      NodeSlots[i] = Node ? W.Emit(Node, strlen(Node) + 1) : 0;
    }

    if (W.Block) {
      memcpy(W.Block, &Out, sizeof(Out));
      memcpy(W.Block + NodesAt, NodeSlots, sizeof(NodeSlots));
    }
    return Base;
  };

  GuestBlockWriter Measure {};
  Build(Measure);
  GuestBlockWriter W {static_cast<uint8_t*>(GuestMallocBytes(Measure.Off))};
  if (!W.Block) {
    return 0;
  }
  return Build(W);
}

static auto fexfn_impl_libdrm_drmGetVersion(int a_0) -> guest_layout<drmVersionPtr> {
  guest_layout<drmVersionPtr> Result {.data = 0};
  drmVersionPtr Host = fexldr_ptr_libdrm_drmGetVersion(a_0);
  if (!Host) {
    return Result;
  }
  Result.data = MaterializeGuestVersion(Host);
  fexldr_ptr_libdrm_drmFreeVersion(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetLibVersion(int a_0) -> guest_layout<drmVersionPtr> {
  guest_layout<drmVersionPtr> Result {.data = 0};
  drmVersionPtr Host = fexldr_ptr_libdrm_drmGetLibVersion(a_0);
  if (!Host) {
    return Result;
  }
  Result.data = MaterializeGuestVersion(Host);
  fexldr_ptr_libdrm_drmFreeVersion(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetBusid(int a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetBusid(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  if (Host) {
    fexldr_ptr_libdrm_drmFreeBusid(Host);
  }
  return Result;
}

// The caller-frees string family: the host allocation is copied onto the
// guest heap (so the guest's free() owns the result, per the libdrm API
// contract) and released here.
static auto fexfn_impl_libdrm_drmGetDeviceNameFromFd(int a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetDeviceNameFromFd(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  free(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetDeviceNameFromFd2(int a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetDeviceNameFromFd2(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  free(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetPrimaryDeviceNameFromFd(int a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetPrimaryDeviceNameFromFd(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  free(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetRenderDeviceNameFromFd(int a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetRenderDeviceNameFromFd(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  free(Host);
  return Result;
}

static auto fexfn_impl_libdrm_drmGetFormatModifierName(uint64_t a_0) -> guest_layout<char*> {
  char* Host = fexldr_ptr_libdrm_drmGetFormatModifierName(a_0);
  guest_layout<char*> Result {.data = RelocateStringToGuestHeap(Host)};
  free(Host);
  return Result;
}

// Shared body of the drmGetDevice* single-device entry points.
static int GetOneGuestDevice(int HostRet, drmDevicePtr* Host, guest_layout<drmDevicePtr*> Out) {
  if (HostRet) {
    return HostRet;
  }
  if (!*Host) {
    return -ENODEV;
  }
  const uint32_t GuestDev = MaterializeGuestDevice(*Host);
  fexldr_ptr_libdrm_drmFreeDevice(Host);
  if (!GuestDev) {
    return -ENOMEM;
  }
  Out.get_pointer()->data = GuestDev;
  return 0;
}

static auto fexfn_impl_libdrm_drmGetDevice(int a_0, guest_layout<drmDevicePtr*> a_1) -> int {
  if (!a_1.data) {
    return -EINVAL;
  }
  drmDevicePtr Host = nullptr;
  return GetOneGuestDevice(fexldr_ptr_libdrm_drmGetDevice(a_0, &Host), &Host, a_1);
}

static auto fexfn_impl_libdrm_drmGetDevice2(int a_0, uint32_t a_1, guest_layout<drmDevicePtr*> a_2) -> int {
  if (!a_2.data) {
    return -EINVAL;
  }
  drmDevicePtr Host = nullptr;
  return GetOneGuestDevice(fexldr_ptr_libdrm_drmGetDevice2(a_0, a_1, &Host), &Host, a_2);
}

static auto fexfn_impl_libdrm_drmGetDeviceFromDevId(dev_t a_0, uint32_t a_1, guest_layout<drmDevicePtr*> a_2) -> int {
  if (!a_2.data) {
    return -EINVAL;
  }
  drmDevicePtr Host = nullptr;
  return GetOneGuestDevice(fexldr_ptr_libdrm_drmGetDeviceFromDevId(a_0, a_1, &Host), &Host, a_2);
}

// Shared body of drmGetDevices/drmGetDevices2. Fills the guest's
// drmDevicePtr[] with materialized guest blocks. On guest OOM the failed and
// remaining slots are left 0 and -ENOMEM is returned; blocks already
// materialized stay with the guest (it has no way to hand them back to us,
// and a guest whose heap is exhausted is past caring about the remainder).
template<typename CallFn>
static int GetGuestDeviceList(guest_layout<drmDevicePtr*> GuestArray, int MaxDevices, CallFn&& Call) {
  if (!GuestArray.data) {
    return Call(nullptr, MaxDevices);
  }
  if (MaxDevices < 0) {
    return -EINVAL;
  }
  std::vector<drmDevicePtr> Hosts(static_cast<size_t>(MaxDevices), nullptr);
  const int Ret = Call(Hosts.data(), MaxDevices);
  if (Ret <= 0) {
    return Ret;
  }
  const int Count = Ret < MaxDevices ? Ret : MaxDevices;
  auto* Slots = GuestArray.get_pointer();
  bool OOM = false;
  for (int i = 0; i < Count; ++i) {
    const uint32_t GuestDev = Hosts[i] ? MaterializeGuestDevice(Hosts[i]) : 0;
    OOM |= (Hosts[i] && !GuestDev);
    Slots[i].data = GuestDev;
  }
  fexldr_ptr_libdrm_drmFreeDevices(Hosts.data(), Count);
  return OOM ? -ENOMEM : Ret;
}

static auto fexfn_impl_libdrm_drmGetDevices(guest_layout<drmDevicePtr*> a_0, int a_1) -> int {
  return GetGuestDeviceList(a_0, a_1, [](drmDevicePtr* Devices, int Max) { return fexldr_ptr_libdrm_drmGetDevices(Devices, Max); });
}

static auto fexfn_impl_libdrm_drmGetDevices2(uint32_t a_0, guest_layout<drmDevicePtr*> a_1, int a_2) -> int {
  return GetGuestDeviceList(a_1, a_2, [a_0](drmDevicePtr* Devices, int Max) { return fexldr_ptr_libdrm_drmGetDevices2(a_0, Devices, Max); });
}

// Mirror of libdrm's drmDevicesEqual, evaluated directly on the guest images:
// same bustype, then bytewise-equal businfo (whose pointees are
// layout-identical across widths, see the static_asserts above).
static auto fexfn_impl_libdrm_drmDevicesEqual(guest_layout<drmDevicePtr> a_0, guest_layout<drmDevicePtr> a_1) -> int {
  const auto* A = reinterpret_cast<const GuestDrmDevice*>(uintptr_t {a_0.data});
  const auto* B = reinterpret_cast<const GuestDrmDevice*>(uintptr_t {a_1.data});
  if (!A || !B || A->bustype != B->bustype) {
    return 0;
  }
  const size_t Bytes = BusInfoSize(A->bustype);
  const void* BusA = reinterpret_cast<const void*>(uintptr_t {A->businfo});
  const void* BusB = reinterpret_cast<const void*>(uintptr_t {B->businfo});
  if (!Bytes || !BusA || !BusB) {
    return 0;
  }
  return memcmp(BusA, BusB, Bytes) == 0;
}

#endif // IS_32BIT_THUNK

EXPORTS(libdrm)
