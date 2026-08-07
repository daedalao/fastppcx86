/*
$info$
category: thunklibs ~ These are generated + glue logic 1:1 thunks unless noted otherwise
$end_info$
*/

#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <optional>
#include <typeinfo>

#include "PackedArguments.h"

// Import FEX::HLE functions for use in host thunk libraries.
//
// Note these are statically linked into the FEX executable. The linker hence
// doesn't know about them when linking thunk libraries. This issue is avoided
// by declaring the functions as weak symbols.
namespace FEX::HLE {
struct HostToGuestTrampolinePtr;

__attribute__((weak)) HostToGuestTrampolinePtr* MakeHostTrampolineForGuestFunction(void* HostPacker, uintptr_t GuestTarget, uintptr_t GuestUnpacker);

__attribute__((weak)) HostToGuestTrampolinePtr* FinalizeHostTrampolineForGuestFunction(HostToGuestTrampolinePtr*, void* HostPacker);

// 2026-05-15 cross-arch callback registry lookup (see Thunks.cpp).  Returns
// the guest VA of CallbackUnpack<F>::Unpack registered for the signature,
// or 0 if no registration exists.  Used by GuestWrapperForHostFunction::Call
// on cross-arch builds to bridge a guest VA into a host trampoline.
__attribute__((weak)) uintptr_t LookupGuestCallbackUnpacker(const char* signature_name);

__attribute__((weak)) void* GetGuestStack();

__attribute__((weak)) void MoveGuestStack(uintptr_t NewAddress);
} // namespace FEX::HLE

#ifdef IS_32BIT_THUNK
#include <mutex>
#include <sys/mman.h>
#include <unordered_map>
#include <utility>
#include <vector>

// Address ranges of the low-4GB trampoline pools allocated by
// MakeLow32HostTrampoline below. Kept separately from that function's own
// cache because the interesting query at the call site is the reverse one:
// "is this 32-bit value one of ours?" See IsLow32HostTrampoline.
struct Low32TrampolinePools {
  std::mutex Mutex;
  std::vector<std::pair<uintptr_t, uintptr_t>> Ranges; // [base, end)
};

inline Low32TrampolinePools& GetLow32TrampolinePools() {
  static Low32TrampolinePools Pools;
  return Pools;
}

/**
 * True if Addr points into a low-4GB host trampoline minted by
 * MakeLow32HostTrampoline - i.e. it is a *host*-executable stub that
 * tail-calls a real host function, not a guest function pointer.
 *
 * Both kinds of value are 32 bits wide and both arrive at the host wrapper
 * edge, so width alone cannot tell them apart. Getting this wrong is not
 * subtle: treating one of our own trampolines as a guest callback replaces a
 * working host call with a bounce into CallbackUnpack<Sig>::CallGuestPtr,
 * whose body the compiler emits as a trap for most signatures.
 */
inline bool IsLow32HostTrampoline(uintptr_t Addr) {
  auto& Pools = GetLow32TrampolinePools();
  std::lock_guard lk {Pools.Mutex};
  for (const auto& [Base, End] : Pools.Ranges) {
    if (Addr >= Base && Addr < End) {
      return true;
    }
  }
  return false;
}

// Host function pointers handed to a 32-bit guest must fit in 32 bits: the
// value doubles as the fake guest address the thunk machinery links
// (LinkAddressToFunction) and as the host callee the invoker calls back
// through (AddThunkTrampolineIRHandler forwards the linked address via mm0).
// Host VAs on ppc64le live at 0x3fff'xxxx'xxxx, so hand out a low-4GB
// executable host trampoline instead: `ld r0,16(r12); mtctr r0; mr r12,r0;
// bctr; .quad target` (ELFv2 indirect calls set r12 = entry, so the literal
// is reachable r12-relative and the real callee sees its own entry in r12).
// Cached per target so repeated queries return pointer-identical results.
// The pool page is invisible to MemAllocator32Bit's bitmap, but its
// MAP_FIXED_NOREPLACE + mincore-resync EEXIST path absorbs the collision if
// the guest allocator ever proposes this page.
inline void* MakeLow32HostTrampoline(void* Target) {
#ifdef __powerpc64__
  static std::mutex Mutex;
  static std::unordered_map<void*, void*> Cache;
  static uint8_t* Pool = nullptr;
  static size_t PoolOff = 0;
  constexpr size_t PoolSize = 0x10000;
  constexpr size_t TrampSize = 24;

  std::lock_guard lk {Mutex};
  if (auto It = Cache.find(Target); It != Cache.end()) {
    return It->second;
  }
  if (!Pool || PoolOff + TrampSize > PoolSize) {
    // Drop the exhausted pool before scanning. Without this, an exhausted pool
    // whose replacement mmap fails leaves Pool non-null, the `if (!Pool)` below
    // does not fire, and we carve trampolines past the end of the mapping into
    // whatever follows it - forever, with PoolOff growing unbounded.
    Pool = nullptr;
    PoolOff = 0;
    for (uintptr_t Addr = 0x7000'0000; Addr >= 0x1000'0000; Addr -= 0x100'0000) {
      void* P = ::mmap(reinterpret_cast<void*>(Addr), PoolSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (P != MAP_FAILED) {
        Pool = static_cast<uint8_t*>(P);
        PoolOff = 0;
        {
          // Record the range so IsLow32HostTrampoline can recognise these
          // addresses when they come back through a host wrapper.
          auto& Pools = GetLow32TrampolinePools();
          std::lock_guard pool_lk {Pools.Mutex};
          Pools.Ranges.emplace_back(reinterpret_cast<uintptr_t>(P), reinterpret_cast<uintptr_t>(P) + PoolSize);
        }
        break;
      }
    }
    if (!Pool) {
      return nullptr;
    }
  }
  uint8_t* Tramp = Pool + PoolOff;
  PoolOff += TrampSize;
  uint32_t* Insns = reinterpret_cast<uint32_t*>(Tramp);
  Insns[0] = 0xE80C0010; // ld    r0, 16(r12)
  Insns[1] = 0x7C0903A6; // mtctr r0
  Insns[2] = 0x7C0C0378; // mr    r12, r0   (or r12, r0, r0)
  Insns[3] = 0x4E800420; // bctr
  memcpy(Tramp + 16, &Target, 8);
  __builtin___clear_cache(reinterpret_cast<char*>(Tramp), reinterpret_cast<char*>(Tramp + 16));
  Cache.emplace(Target, Tramp);
  return Tramp;
#else
  return nullptr;
#endif
}
#endif

template<typename Fn>
struct function_traits;
template<typename Result, typename Arg>
struct function_traits<Result (*)(Arg)> {
  using result_t = Result;
  using arg_t = Arg;
};

template<auto Fn>
static typename function_traits<decltype(Fn)>::result_t fexfn_type_erased_unpack(void* argsv) {
  using args_t = typename function_traits<decltype(Fn)>::arg_t;
  return Fn(reinterpret_cast<args_t>(argsv));
}

struct ExportEntry {
  uint8_t* sha256;
  void (*fn)(void*);
};

typedef void fex_call_callback_t(uintptr_t callback, void* arg0, void* arg1);

#define EXPORTS(name)                       \
  extern "C" {                              \
  ExportEntry* fexthunks_exports_##name() { \
    if (!fexldr_init_##name()) {            \
      return nullptr;                       \
    }                                       \
    return exports;                         \
  }                                         \
  }

#define LOAD_LIB_INIT(init_fn)                         \
  __attribute__((constructor)) static void loadlib() { \
    init_fn();                                         \
  }

struct GuestcallInfo {
  uintptr_t HostPacker;
  void (*CallCallback)(uintptr_t GuestUnpacker, uintptr_t GuestTarget, void* argsrv);
  uintptr_t GuestUnpacker;
  uintptr_t GuestTarget;
};

// Helper macro for reading an internal argument passed through the host's
// callback custom-ABI. On x86/ARM this is the r11/x11 scratch register and
// the macro must be placed at the very beginning of the function it is
// used in. On PPC64LE r11 is the linker's environment-pointer register and
// gets clobbered by PLT stubs in the receiving function's prologue, so a
// thread-local variable is used instead — the trampoline writes it
// pre-bctr and the macro reads it back.
#if defined(ARCHITECTURE_x86_64)
#define LOAD_INTERNAL_GUESTPTR_VIA_CUSTOM_ABI(target_variable) asm volatile("mov %%r11, %0" : "=r"(target_variable))
#elif defined(ARCHITECTURE_arm64)
#define LOAD_INTERNAL_GUESTPTR_VIA_CUSTOM_ABI(target_variable) asm volatile("mov %0, x11" : "=r"(target_variable))
#elif defined(ARCHITECTURE_ppc64le)
// Bin/FEX exports this getter; host libs call it. The getter reads the TLS
// variable inside Bin/FEX's local-exec slot. Dynamic linker resolves at
// dlopen time (Bin/FEX is linked with --export-dynamic), so the cost is
// one PLT call per callback dispatch. Declared weak so the host libs link
// even with --no-undefined; missing at runtime would mean the lib was
// dlopened from a non-FEX process which would be a serious misuse.
extern "C" uintptr_t FEX_GetCallbackGuestcallPtr() __attribute__((weak));
#define LOAD_INTERNAL_GUESTPTR_VIA_CUSTOM_ABI(target_variable)                                                  \
  do {                                                                                                          \
    (target_variable) = reinterpret_cast<std::remove_reference_t<decltype(target_variable)>>(                   \
      FEX_GetCallbackGuestcallPtr());                                                                           \
  } while (0)
#endif

struct ParameterAnnotations {
  bool is_passthrough = false;
  bool assume_compatible = false;
};

// Generator emits specializations for this for each type that has compatible layout
template<typename T>
inline constexpr bool has_compatible_data_layout =
  std::is_integral_v<T> || std::is_enum_v<T> ||
  std::is_floating_point_v<T>
#ifndef IS_32BIT_THUNK
  // If none of the previous predicates matched, the thunk generator did *not* emit a specialization for T.
  // This should not happen on 64-bit with the currently thunked libraries, since their types
  // * either have fully consistent data layout across 64-bit architectures.
  // * or use custom repacking, in which case has_compatible_data_layout isn't used
  //
  // Throwing a fake exception here will trigger a build failure.
  || (throw "Instantiated on a type that was expected to be compatible", true)
#endif
  ;

#ifndef IS_32BIT_THUNK
// Pointers have the same size, hence data layout compatibility only depends on the pointee type
template<typename T>
inline constexpr bool has_compatible_data_layout<T*> = has_compatible_data_layout<std::remove_cv_t<T>>;
template<typename T>
inline constexpr bool has_compatible_data_layout<T* const> = has_compatible_data_layout<std::remove_cv_t<T>*>;

// void* and void** are assumed to be compatible to simplify handling of libraries that use them ubiquitously
template<>
inline constexpr bool has_compatible_data_layout<void*> = true;
template<>
inline constexpr bool has_compatible_data_layout<const void*> = true;
template<>
inline constexpr bool has_compatible_data_layout<void**> = true;
template<>
inline constexpr bool has_compatible_data_layout<const void**> = true;
#endif

// Placeholder type to indicate the given data is in guest-layout
template<typename T>
struct __attribute__((packed)) guest_layout {
  static_assert(!std::is_class_v<T>, "No guest layout defined for this non-opaque struct type. This may be a bug in the thunk generator.");
  static_assert(!std::is_union_v<T>, "No guest layout defined for this non-opaque union type. This may be a bug in the thunk generator.");
  static_assert(!std::is_enum_v<T>, "No guest layout defined for this enum type. This is a bug in the thunk generator.");
  static_assert(!std::is_void_v<T>, "Attempted to get guest layout of void. Missing annotation for void pointer?");

  static_assert(std::is_fundamental_v<T> || has_compatible_data_layout<T>, "Default guest_layout may not be used for non-compatible data");

  using type = std::enable_if_t<!std::is_pointer_v<T>, T>;
  type data;

  guest_layout& operator=(const T from) {
    data = from;
    return *this;
  }
};

template<typename T, std::size_t N>
struct __attribute__((packed)) guest_layout<T[N]> {
  using type = std::enable_if_t<!std::is_pointer_v<T>, T>;
  std::array<guest_layout<type>, N> data;
};

template<typename T>
struct guest_layout<T*> {
#ifdef IS_32BIT_THUNK
  using type = uint32_t;
#else
  using type = uint64_t;
#endif
  type data;

  // Allow implicit conversion for function pointers, since they disallow use of host_layout
  guest_layout& operator=(const T* from) requires (std::is_function_v<T>)
  {
#ifdef IS_32BIT_THUNK
    // guest_layout's data field is uint32_t here: the value must be
    // representable as a 32-bit guest address AND callable host-side (the
    // thunk trampoline machinery forwards it back as the host callee).
    // Host VAs sit above 4 GiB on ppc64le, so substitute a low-4GB host
    // trampoline that tail-calls the real function. Identity is preserved
    // per target, so guest-side pointer comparisons stay stable.
    if ((reinterpret_cast<uintptr_t>(from) >> 32) != 0) {
      void* Tramp = MakeLow32HostTrampoline(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(from)));
      if (!Tramp) {
        // Plain fprintf+abort because LOGMAN_THROW headers aren't in this
        // TU. Silent truncation produces undebuggable downstream crashes —
        // better to die at the obvious spot.
        fprintf(stderr, "FEX FATAL: guest_layout<T*> 32-bit truncation: host VA %p does not fit in 32 bits\n", (void*)from);
        std::abort();
      }
      data = static_cast<type>(reinterpret_cast<uintptr_t>(Tramp));
      return *this;
    }
#endif
    data = reinterpret_cast<uintptr_t>(from);
    return *this;
  }

  guest_layout<T>* get_pointer() {
    return reinterpret_cast<guest_layout<T>*>(uintptr_t {data});
  }

  const guest_layout<T>* get_pointer() const {
    return reinterpret_cast<const guest_layout<T>*>(uintptr_t {data});
  }

  T* force_get_host_pointer() {
    return reinterpret_cast<T*>(uintptr_t {data});
  }

  const T* force_get_host_pointer() const {
    return reinterpret_cast<const T*>(uintptr_t {data});
  }

  // char*/uint8_t* pointer-flavor interop for custom_host_impl functions.
  // Mirrors host_to_guest_convertible's operator guest_layout<const uint8_t*>()
  // (Host.h ~581). thunkgen declares impl returns as `guest_layout<const
  // char*>` (matching the source C signature) but declares the packed-args
  // `rv` field as `guest_layout<const uint8_t*>` (its canonicalised byte-ptr
  // form). Auto-generated unpackers bridge that via `to_guest(to_host_layout(...))`;
  // custom_host_impl assignments need this conversion instead.
  operator guest_layout<const uint8_t*>() const
    requires (std::is_same_v<T, const char>)
  {
    return guest_layout<const uint8_t*> {.data = data};
  }
  operator guest_layout<uint8_t*>() const
    requires (std::is_same_v<T, char>)
  {
    return guest_layout<uint8_t*> {.data = data};
  }
};

template<typename T>
struct guest_layout<T* const> {
#ifdef IS_32BIT_THUNK
  using type = uint32_t;
#else
  using type = uint64_t;
#endif
  type data;

  // Allow implicit conversion for function pointers, since they disallow use of host_layout
  guest_layout& operator=(const T* from) requires (std::is_function_v<T>)
  {
#ifdef IS_32BIT_THUNK
    // Same low-4GB host trampoline substitution as guest_layout<T*> above.
    if ((reinterpret_cast<uintptr_t>(from) >> 32) != 0) {
      void* Tramp = MakeLow32HostTrampoline(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(from)));
      if (!Tramp) {
        fprintf(stderr, "FEX FATAL: guest_layout<T* const> 32-bit truncation: host VA %p does not fit in 32 bits\n", (void*)from);
        std::abort();
      }
      data = static_cast<type>(reinterpret_cast<uintptr_t>(Tramp));
      return *this;
    }
#endif
    data = reinterpret_cast<uintptr_t>(from);
    return *this;
  }

  guest_layout<T>* get_pointer() {
    return reinterpret_cast<guest_layout<T>*>(uintptr_t {data});
  }

  const guest_layout<T>* get_pointer() const {
    return reinterpret_cast<const guest_layout<T>*>(uintptr_t {data});
  }
};

template<typename T>
struct host_layout;

template<typename T>
struct host_layout {
  static_assert(!std::is_class_v<T>, "No host_layout specialization generated for struct/class type");
  static_assert(!std::is_union_v<T>, "No host_layout specialization generated for union type");
  static_assert(!std::is_void_v<T>, "Attempted to get host layout of void. Missing annotation for void pointer?");

  // TODO: This generic implementation shouldn't be needed. Instead, auto-specialize host_layout for all types used as members.

  T data;

  explicit host_layout(const guest_layout<T>& from) requires (!std::is_enum_v<T>)
    : data {from.data} {
    // NOTE: This is not strictly neccessary since differently sized types may
    //       be used across architectures. It's important that the host type
    //       can represent all guest values without loss, however.
    static_assert(sizeof(data) == sizeof(from));
  }

  explicit host_layout(const guest_layout<T>& from) requires (std::is_enum_v<T>)
    : data {static_cast<T>(from.data)} {}

  // Allow conversion of integral types of smaller or equal size and same sign
  // to each other. Zero-extension is applied if needed.
  // Notably, this is useful for handling "long"/"long long" on 64-bit, as well
  // as uint8_t/char.
  template<typename U>
  explicit host_layout(const guest_layout<U>& from)
    requires (std::is_integral_v<U> && sizeof(U) <= sizeof(T) && std::is_convertible_v<T, U> && std::is_signed_v<T> == std::is_signed_v<U>)
    : data {static_cast<T>(from.data)} {}
};

// Explicitly turn a host type into its corresponding host_layout
template<typename T>
const host_layout<T>& to_host_layout(const T& t) {
  static_assert(std::is_same_v<decltype(host_layout<T>::data), T>);
  return reinterpret_cast<const host_layout<T>&>(t);
}

template<typename T, size_t N>
struct host_layout<T[N]> {
  std::array<T, N> data;

  explicit host_layout(const guest_layout<T[N]>& from) {
    for (size_t i = 0; i < N; ++i) {
      data[i] = host_layout<T> {from.data[i]}.data;
    }
  }
};

template<typename T>
constexpr bool is_long_or_longlong =
  std::is_same_v<T, long> || std::is_same_v<T, unsigned long> || std::is_same_v<T, long long> || std::is_same_v<T, unsigned long long>;

template<typename T>
struct host_layout<T*> {
  T* data;

  static_assert(!std::is_function_v<T>, "Function types must be handled separately");

  // Assume underlying data is compatible and just convert the guest-sized pointer to 64-bit
  explicit host_layout(const guest_layout<T*>& from)
    : data {(T*)(uintptr_t)from.data} {}

  host_layout() = default;

  // Allow conversion of pointers to 64-bit integer types to "(un)signed long (long)*".
  // This is useful for handling "long"/"long long" on 64-bit, which are distinct types
  // but have equal data layout.
  template<typename U>
  explicit host_layout(const guest_layout<U*>& from)
    requires (is_long_or_longlong<std::remove_cv_t<T>> && std::is_integral_v<U> && std::is_convertible_v<T, U> &&
              std::is_signed_v<T> == std::is_signed_v<U>
#if __clang_major__ >= 16
              // Old clang versions don't support using sizeof on incomplete types when evaluating requires()
              && sizeof(T) == sizeof(U)
#endif
                )
    : data {(T*)(uintptr_t)from.data} {
  }

  // Allow conversion of pointers to 8-bit integer types to "char*".
  // This is useful since "char"/"signed char"/"unsigned char"/"int8_t"/"uint8_t"
  // may all be distinct types but have equal data layout
  template<typename U>
  explicit host_layout(const guest_layout<U*>& from)
    requires (std::is_same_v<std::remove_cv_t<T>, char> && std::is_integral_v<U> && std::is_convertible_v<T, U> && sizeof(U) == 1)
    : data {(T*)(uintptr_t)from.data} {}

  // Allow conversion of pointers to 32-bit integer types to "wchar_t*".
  template<typename U>
  explicit host_layout(const guest_layout<U*>& from) requires (
    std::is_same_v<std::remove_cv_t<T>, wchar_t> && std::is_integral_v<U> && std::is_convertible_v<T, U> && sizeof(U) == sizeof(wchar_t))
    : data {(T*)(uintptr_t)from.data} {}
};

template<typename T>
struct host_layout<T* const> {
  T* data;

  static_assert(!std::is_function_v<T>, "Function types must be handled separately");

  // Assume underlying data is compatible and just convert the guest-sized pointer to 64-bit
  explicit host_layout(const guest_layout<T* const>& from)
    : data {(T*)(uintptr_t)from.data} {}
};

// Function-pointer specialization. Needed so CallbackUnpack<Sig>::CallGuestPtr
// can be instantiated for signatures whose argument list contains a callback
// type (e.g. `void(GLDEBUGPROC, void*)` for glDebugMessageCallbackARB). The
// body never executes at runtime for such signatures -- a host function whose
// own argument is itself a callback is never registered by the guest as a
// callback target -- but the address of CallGuestPtr is taken at the cross-arch
// wrap site (Host.h:702), forcing instantiation.
template<typename T>
  requires (std::is_function_v<T>)
struct host_layout<T*> {
  T* data;

  explicit host_layout(const guest_layout<T*>& from)
    : data {(T*)(uintptr_t)from.data} {}
  host_layout() = default;
};

template<typename T>
  requires (std::is_function_v<T>)
inline guest_layout<T*> to_guest(const host_layout<T*>& from) {
  guest_layout<T*> result {};
  result = from.data;
  return result;
}

// Wrapper around host_layout that repacks from a guest_layout on construction
// and exit-repacks on scope exit (if needed). The wrapper manages the storage
// needed for repacked data itself.
// This also implicitly converts to a pointer of the wrapped host type, since
// this conversion is required at all call sites anyway
template<typename T, typename GuestT>
struct repack_wrapper {
  static_assert(std::is_pointer_v<T>);

  // Strip "const" from pointee type in host_layout storage
  using PointeeT = std::remove_cv_t<std::remove_pointer_t<T>>;

  std::optional<host_layout<PointeeT>> data;
  guest_layout<GuestT>& orig_arg;

  repack_wrapper(guest_layout<GuestT>& orig_arg_)
    : orig_arg(orig_arg_) {
    if (orig_arg.get_pointer()) {
      data = {*orig_arg_.get_pointer()};

      if constexpr (!std::is_enum_v<T>) {
        constexpr bool is_compatible = has_compatible_data_layout<T> && std::is_same_v<T, GuestT>;
        if constexpr (!is_compatible && std::is_class_v<std::remove_pointer_t<T>>) {
          fex_apply_custom_repacking_entry(*data, *orig_arg_.get_pointer());
        }
      }
    }
  }

  ~repack_wrapper() {
    // TODO: Properly detect opaque types
    if constexpr (std::is_class_v<std::remove_pointer_t<T>> && requires(guest_layout<T> t, decltype(data) h) {
                    t.get_pointer();
                    (bool)h;
                    *data;
                  }) {
      if (data) {
        // NOTE: It's assumed that the native host library didn't modify any
        //       const-pointees, so we skip automatic exit repacking for them.
        //       However, *custom* repacking must still be applied since it
        //       might have unrelated side effects (such as deallocation of
        //       memory reserved on entry)
        if (!fex_apply_custom_repacking_exit(*orig_arg.get_pointer(), *data)) {
          if constexpr (!std::is_const_v<std::remove_pointer_t<T>>) { // Skip exit-repacking for const pointees
            if constexpr (!(has_compatible_data_layout<T> && std::is_same_v<T, GuestT>)) {
              *orig_arg.get_pointer() = to_guest(*data); // TODO: Only if annotated as out-parameter
            }
          }
        }
      }
    }
  }

  operator PointeeT*() {
    static_assert(sizeof(PointeeT) == sizeof(host_layout<PointeeT>));
    static_assert(alignof(PointeeT) == alignof(host_layout<PointeeT>));
    return data ? &data.value().data : nullptr;
  }
};

template<typename T, typename GuestT>
static repack_wrapper<T, GuestT> make_repack_wrapper(guest_layout<GuestT>& orig_arg) {
  return {orig_arg};
}

template<typename T>
T& unwrap_host(host_layout<T>& val) {
  return val.data;
}

template<typename T, typename T2>
T* unwrap_host(repack_wrapper<T*, T2>& val) {
  return val;
}

template<typename T>
struct host_to_guest_convertible {
  const host_layout<T>& from;

  // Conversion from host to guest layout for non-pointers
  operator guest_layout<T>() const requires (!std::is_pointer_v<T>)
  {
    if constexpr (std::is_enum_v<T>) {
      // enums are represented by fixed-size integers in guest_layout, so explicitly cast them
      return guest_layout<T> {static_cast<std::underlying_type_t<T>>(from.data)};
    } else {
      guest_layout<T> ret {.data = from.data};
      return ret;
    }
  }

  operator guest_layout<T>() const requires (std::is_pointer_v<T>)
  {
    // TODO: Assert upper 32 bits are zero
    guest_layout<T> ret;
    ret.data = reinterpret_cast<uintptr_t>(from.data);
    return ret;
  }

#if IS_32BIT_THUNK
  // Allow size_t -> uint32_t conversions, since they are so common on 32-bit
  operator guest_layout<uint32_t>() const requires (std::is_same_v<T, size_t>)
  {
    return {static_cast<uint32_t>(from.data)};
  }

  // libGL also needs to allow long->int conversions for return values...
  operator guest_layout<int32_t>() const requires (std::is_same_v<T, long>)
  {
    return {static_cast<int32_t>(from.data)};
  }
#endif

  // Make guest_layout of "long long" and "long" interoperable, since they are
  // the same type as far as data layout is concerned.
  operator guest_layout<const unsigned long long*>() const requires (std::is_same_v<T, const unsigned long*>)
  {
    return (guest_layout<const unsigned long long*>)reinterpret_cast<const host_to_guest_convertible<const unsigned long long*>&>(*this);
  }

  // Make guest_layout of "char" and "uint8_t" interoperable
  operator guest_layout<const uint8_t*>() const requires (std::is_same_v<T, const char*>)
  {
    return (guest_layout<const uint8_t*>)reinterpret_cast<const host_to_guest_convertible<const uint8_t*>&>(*this);
  }

  operator guest_layout<uint8_t*>() const requires (std::is_same_v<T, char*>)
  {
    return (guest_layout<uint8_t*>)reinterpret_cast<const host_to_guest_convertible<uint8_t*>&>(*this);
  }

  // Make guest_layout of "wchar_t" and "uint32_t" interoperable
  operator guest_layout<uint32_t*>() const requires (std::is_same_v<T, wchar_t*>)
  {
    return (guest_layout<uint32_t*>)reinterpret_cast<const host_to_guest_convertible<uint32_t*>&>(*this);
  }

  static_assert(sizeof(wchar_t) == 4);

  // Allow conversion of integral types of same size and sign to each other.
  // This is useful for handling "long"/"long long" on 64-bit, as well as uint8_t/char.
  template<typename U>
  operator guest_layout<U>() const
    requires (std::is_integral_v<U> && sizeof(U) == sizeof(T) && std::is_convertible_v<T, U> && std::is_signed_v<T> == std::is_signed_v<U>)
  {
    return guest_layout<U> {.data {static_cast<T>(from.data)}};
  }
};

template<typename T>
inline host_to_guest_convertible<T> to_guest(const host_layout<T>& from) {
  return {from};
}

// Cross-arch wrap helper: lets CallbackUnpack<Sig>::CallGuestPtr instantiate
// for signatures containing opaque types whose to_guest is intentionally
// `= delete`d (e.g. `_XDisplay*` at libGL_Host.cpp:51). Such signatures are
// never actually used as guest-passed callbacks -- they appear only as
// parameters of host functions called by guest -- but the cross-arch wrap
// at GuestWrapperForHostFunction::Call takes the address of CallGuestPtr at
// compile time, which forces the body to instantiate. Where to_guest is
// deleted, this branch substitutes an unreachable default-constructed
// guest_layout so the template instantiates; the runtime path is dead.
template<typename T>
auto pack_to_guest(const host_layout<T>& from) {
  if constexpr (requires { to_guest(from); }) {
    return to_guest(from);
  } else {
    __builtin_unreachable();
    return guest_layout<T> {};
  }
}

template<typename>
struct CallbackUnpack;

template<typename T, ParameterAnnotations Annotation>
constexpr bool IsCompatible() {
  if constexpr (Annotation.assume_compatible) {
    return true;
  } else if constexpr (has_compatible_data_layout<T>) {
    return true;
  } else {
    if constexpr (std::is_pointer_v<T>) {
      return has_compatible_data_layout<std::remove_cv_t<std::remove_pointer_t<T>>>;
    } else {
      return false;
    }
  }
}

template<typename T>
struct decaying_host_layout {
  host_layout<T> data;
  operator T() {
    return data.data;
  }
};

template<ParameterAnnotations Annotation, typename HostT, typename T>
auto Projection(guest_layout<T>& data) {
  if constexpr (Annotation.is_passthrough) {
    return data;
  } else if constexpr ((IsCompatible<T, Annotation>() && std::is_same_v<T, HostT>) || !std::is_pointer_v<T>) {
    // Instead of using host_layout<HostT> { data }.data, return a wrapper object.
    // This ensures that temporary lifetime extension can kick in at call-site.
    return decaying_host_layout<HostT> {.data {data}};
  } else {
    // This argument requires temporary storage for repacked data
    // *and* it needs to call custom repack functions (if any)
    return make_repack_wrapper<HostT>(data);
  }
}

#if defined(IS_32BIT_THUNK) || defined(THUNK_HOST_NOT_X86_64)
/**
 * Helper class to manage guest stack memory from a host function.
 *
 * The current guest stack position is saved upon construction and bumped
 * for each object construction. Upon destruction, the old guest stack is
 * restored.
 *
 * Needed whenever the guest will dereference a host-supplied pointer:
 *  - 32-bit guest on 64-bit host (original use): host stack lives above 4 GiB
 *    so a 64-bit host pointer cannot fit in a 32-bit guest slot.
 *  - 64-bit guest on non-x86_64 host (PPC64LE etc.): host stack lives in the
 *    host's VA region (e.g. 0x3fff... on PPC64LE), which is unmapped in the
 *    x86_64 guest's view. The guest-side unpacker would dereference a host
 *    VA and either fault or read garbage. Allocate on the guest stack instead.
 */
class GuestStackBumpAllocator final {
  uintptr_t Top = reinterpret_cast<uintptr_t>(FEX::HLE::GetGuestStack());
  uintptr_t Next = Top;

public:
  ~GuestStackBumpAllocator() {
    FEX::HLE::MoveGuestStack(Top);
  }

  template<typename T, typename... Args>
  T* New(Args&&... args) {
    Next -= sizeof(T);
    Next &= ~uintptr_t {alignof(T) - 1};
    FEX::HLE::MoveGuestStack(Next);
    return new (reinterpret_cast<void*>(Next)) T {std::forward<Args>(args)...};
  }
};
#endif

template<typename Result, typename... Args>
struct CallbackUnpack<Result(Args...)> {
  static Result CallGuestPtr(Args... args) {
    GuestcallInfo* guestcall;
    LOAD_INTERNAL_GUESTPTR_VIA_CUSTOM_ABI(guestcall);

#if defined(IS_32BIT_THUNK) || defined(THUNK_HOST_NOT_X86_64)
    GuestStackBumpAllocator GuestStack;
    auto& packed_args = *GuestStack.New<PackedArguments<Result, guest_layout<Args>...>>(pack_to_guest(to_host_layout(args))...);
#else
    PackedArguments<Result, guest_layout<Args>...> packed_args = {pack_to_guest(to_host_layout(args))...};
#endif
    guestcall->CallCallback(guestcall->GuestUnpacker, guestcall->GuestTarget, &packed_args);

    if constexpr (!std::is_void_v<Result>) {
      return packed_args.rv;
    }
  }
};

template<bool Cond, typename T, typename GuestT>
using as_guest_layout_if = std::conditional_t<Cond, guest_layout<GuestT>, T>;

template<typename, typename...>
struct GuestWrapperForHostFunction;

template<typename Result, typename... Args, typename... GuestArgs>
struct GuestWrapperForHostFunction<Result(Args...), GuestArgs...> {
  // Host functions called from Guest
  // NOTE: GuestArgs typically matches up with Args, however there may be exceptions (e.g. size_t)
  template<ParameterAnnotations RetAnnotations, ParameterAnnotations... Annotations>
  static void Call(void* argsv) {
    static_assert(sizeof...(Annotations) == sizeof...(Args));
    static_assert(sizeof...(GuestArgs) == sizeof...(Args));

    auto args =
      reinterpret_cast<PackedArguments<as_guest_layout_if<!std::is_void_v<Result>, Result, Result>, guest_layout<GuestArgs>..., uintptr_t>*>(argsv);
    constexpr auto CBIndex = sizeof...(GuestArgs);
    uintptr_t cb;
    static_assert(CBIndex <= 18 || CBIndex == 23);
    if constexpr (CBIndex == 0) {
      cb = args->a0;
    } else if constexpr (CBIndex == 1) {
      cb = args->a1;
    } else if constexpr (CBIndex == 2) {
      cb = args->a2;
    } else if constexpr (CBIndex == 3) {
      cb = args->a3;
    } else if constexpr (CBIndex == 4) {
      cb = args->a4;
    } else if constexpr (CBIndex == 5) {
      cb = args->a5;
    } else if constexpr (CBIndex == 6) {
      cb = args->a6;
    } else if constexpr (CBIndex == 7) {
      cb = args->a7;
    } else if constexpr (CBIndex == 8) {
      cb = args->a8;
    } else if constexpr (CBIndex == 9) {
      cb = args->a9;
    } else if constexpr (CBIndex == 10) {
      cb = args->a10;
    } else if constexpr (CBIndex == 11) {
      cb = args->a11;
    } else if constexpr (CBIndex == 12) {
      cb = args->a12;
    } else if constexpr (CBIndex == 13) {
      cb = args->a13;
    } else if constexpr (CBIndex == 14) {
      cb = args->a14;
    } else if constexpr (CBIndex == 15) {
      cb = args->a15;
    } else if constexpr (CBIndex == 16) {
      cb = args->a16;
    } else if constexpr (CBIndex == 17) {
      cb = args->a17;
    } else if constexpr (CBIndex == 18) {
      cb = args->a18;
    } else if constexpr (CBIndex == 23) {
      cb = args->a23;
    }

    // 2026-05-15 cross-arch callback bridging (PPC64LE host + i686 guest, or
    // any host whose code is not x86):
    //
    // `cb` is the function pointer the guest packed into args->aN.  In a
    // matched-architecture build (x86_64-host + x86_64-guest) the guest VA
    // IS host-executable, so the reinterpret_cast + bctrl that follows just
    // works.  Cross-arch builds rely on the GUEST having wrapped the function
    // pointer in `AllocateHostTrampolineForGuestFunction` (Guest.h:206) before
    // packing it: that returns a host-executable trampoline address whose
    // body bounces back into the guest dispatcher.  Thunkgen emits this
    // wrapping for parameters it classifies as callbacks
    // (ThunkLibs/Generator/gen.cpp:477), but it misses callbacks reached
    // through struct fields, layer chains, or other paths -- the host then
    // tries to call a raw guest VA and SIGSEGVs.
    //
    // For 32-bit thunk builds we synthesise the wrapping at the host wrapper
    // edge: if cb fits in 32 bits and we have a guest-side unpacker
    // registered for this template's signature, build a HostToGuestTrampoline
    // on the fly and call THROUGH it.
    static_assert(sizeof(void*) == 8, "host must be 64-bit; the cross-arch check assumes wide pointers");
#if defined(IS_32BIT_THUNK) || defined(THUNK_HOST_NOT_X86_64)
    // The `(cb >> 32) == 0` heuristic is only meaningful for 32-bit guests,
    // where a guest pointer must fit in 32 bits. For 64-bit cross-arch (e.g.
    // x86_64 guest on PPC64LE host), guest VAs are full 64 bits, and every
    // guest-passed `cb` requires wrapping since the host ISA cannot execute
    // guest x86 bytes directly.
    //
    // For 32-bit thunks this fallback is always on (upstream behaviour). For
    // 64-bit cross-arch hosts the fallback is OPT-IN via the
    // FEX_THUNK_FALLBACK_LOG_ONLY env var. When opted out, behaviour matches
    // upstream FEX (the wrap site is dead code); the proper fix for any given
    // API is to write a custom_guest_impl / custom_host_impl that pre-wraps
    // the callback via AllocateHostTrampolineForGuestFunction (the documented
    // FEX mechanism). The fallback exists for two reasons:
    //   1. catch the SIGSEGV class while custom impls are being written, and
    //   2. surface "no unpacker registered for signature X" to identify which
    //      APIs still need custom impls.
    // Opt-in on every configuration, including 32-bit.
    //
    // This block cannot be correct at this call site: CBIndex is
    // sizeof...(GuestArgs), which indexes the TRAILING uintptr_t of
    // PackedArguments - the dispatch target - and never a callback parameter.
    // GuestWrapperForHostFunction::Call is only ever emitted into the
    // host-funcptr invoker table (Generator/gen.cpp), i.e. the
    // glXGetProcAddress -> LinkAddressToFunction path, so that trailing value
    // is a host function pointer by construction. On a 32-bit guest it is a
    // low-4GB trampoline from MakeLow32HostTrampoline, which is already
    // directly callable.
    //
    // It used to be unconditionally on for IS_32BIT_THUNK, which meant every
    // condition ahead of the range check passed on every call - (cb >> 32) == 0
    // is always true precisely because we make these targets low - so a
    // process-global lock and a linear scan ran on every procaddr-dispatched
    // guest->host call on every thread. A thread preempted inside that critical
    // section stalls the rest; Unity's GC/job handshake then times out and
    // aborts. It reproduced under a 10-CPU taskset cage and not at 80.
    //
    // Keep it reachable for triage only: it is still the quickest way to
    // surface "no unpacker registered for signature X" while writing a
    // custom_host_impl.
    auto fallback_wrap_enabled = []() -> bool {
      static const bool enabled = (getenv("FEX_THUNK_FALLBACK_LOG_ONLY") != nullptr);
      return enabled;
    };

    // CBIndex is sizeof...(GuestArgs), which indexes the *trailing* uintptr_t
    // of PackedArguments - the dispatch target, not a callback parameter. For a
    // name resolved through glXGetProcAddress that target is the value the host
    // handed back, and on a 32-bit guest that is a low-4GB host trampoline
    // (MakeLow32HostTrampoline) which is already directly host-callable. Only
    // genuine guest function pointers need bridging; wrapping our own
    // trampoline swaps a working host call for a jump into a trap body, which
    // is a SIGILL at the first procaddr-dispatched GL call.
    //
    // 64-bit guests never hit this because fallback_wrap_enabled() is opt-in
    // there; for 32-bit it is always on, so the check has to be explicit.
    if (fallback_wrap_enabled() && cb && FEX::HLE::LookupGuestCallbackUnpacker
#ifdef IS_32BIT_THUNK
        && (cb >> 32) == 0 && !IsLow32HostTrampoline(cb)
#endif
    ) {
      using Sig = Result(Args...);
      // typeid(Sig).name() is the C++ compiler-mangled name of the signature
      // type; same source compiled with the same compiler on guest and host
      // produces the same string, so it's a stable cross-process key.
      uintptr_t guest_unpacker = FEX::HLE::LookupGuestCallbackUnpacker(typeid(Sig).name());
      if (guest_unpacker) {
        auto* trampoline = FEX::HLE::MakeHostTrampolineForGuestFunction(
          reinterpret_cast<void*>(&CallbackUnpack<Sig>::CallGuestPtr),
          /*GuestTarget=*/cb,
          /*GuestUnpacker=*/guest_unpacker);
        // Substitute cb with the host-callable trampoline address.  Everything
        // downstream (callback / lambda f / Invoke) treats cb as a host
        // function pointer of the right signature, which the trampoline now
        // satisfies.
        cb = reinterpret_cast<uintptr_t>(trampoline);
      } else {
        // No unpacker registered for this signature.  Log clearly so the
        // missing RegisterGuestCallbackUnpacker<Sig>() can be added in the
        // thunk lib's OnInit().  Return default Result so the caller's state
        // stays predictable instead of SIGSEGV.
        static thread_local bool warned = false;
        if (!warned) {
          warned = true;
          fprintf(stderr,
                  "FEX cross-arch thunk: no guest unpacker registered for signature %s "
                  "(callback at guest VA %p).  Add RegisterGuestCallbackUnpacker<Sig>() "
                  "in the thunk lib's OnInit to bridge this signature.\n",
                  typeid(Sig).name(), reinterpret_cast<void*>(cb));
          fflush(stderr);
        }
        if constexpr (!std::is_void_v<Result>) {
          args->rv = {};
        }
        return;
      }
    }
#endif

    // This is almost the same type as "Result func(Args..., uintptr_t)", but
    // individual types annotated as passthrough are wrapped in guest_layout<>
    auto callback = reinterpret_cast<as_guest_layout_if<RetAnnotations.is_passthrough, Result, Result> (*)(
      as_guest_layout_if<Annotations.is_passthrough, Args, GuestArgs>..., uintptr_t)>(cb);

    auto f = [&callback](guest_layout<GuestArgs>... args, uintptr_t target) {
      // Fold over each of Annotations, Args, and args. This will match up the elements in triplets.
      if constexpr (std::is_void_v<Result>) {
        callback(Projection<Annotations, Args>(args)..., target);
      } else if constexpr (!RetAnnotations.is_passthrough) {
        return (guest_layout<Result>)to_guest(to_host_layout(callback(Projection<Annotations, Args>(args)..., target)));
      } else {
        return callback(Projection<Annotations, Args>(args)..., target);
      }
    };
    Invoke(f, *args);
  }
};

template<typename FuncType>
void MakeHostTrampolineForGuestFunctionAt(uintptr_t GuestTarget, uintptr_t GuestUnpacker, FuncType** Func) {
  *Func = (FuncType*)FEX::HLE::MakeHostTrampolineForGuestFunction((void*)&CallbackUnpack<FuncType>::CallGuestPtr, GuestTarget, GuestUnpacker);
}

template<typename F>
void FinalizeHostTrampolineForGuestFunction(F* PreallocatedTrampolineForGuestFunction) {
  FEX::HLE::FinalizeHostTrampolineForGuestFunction((FEX::HLE::HostToGuestTrampolinePtr*)PreallocatedTrampolineForGuestFunction,
                                                   (void*)&CallbackUnpack<F>::CallGuestPtr);
}

template<typename F>
void FinalizeHostTrampolineForGuestFunction(guest_layout<F*> PreallocatedTrampolineForGuestFunction) {
  FEX::HLE::FinalizeHostTrampolineForGuestFunction((FEX::HLE::HostToGuestTrampolinePtr*)PreallocatedTrampolineForGuestFunction.data,
                                                   (void*)&CallbackUnpack<F>::CallGuestPtr);
}

// In the case of the thunk host_loader being the default, FEX need to use dlsym with RTLD_DEFAULT.
// If FEX queried the symbol object directly then it wouldn't follow symbol overriding rules.
//
// Common usecase is LD_PRELOAD with a library that defines some symbols.
// And then programs and libraries will pick up the preloaded symbols.
// ex: MangoHud overrides GLX and EGL symbols.
inline void* dlsym_default(void* handle, const char* symbol) {
  return dlsym(RTLD_DEFAULT, symbol);
}
