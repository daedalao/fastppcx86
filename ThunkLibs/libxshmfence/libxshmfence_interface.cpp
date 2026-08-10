#include <common/GeneratorInterface.h>

extern "C" {
#include <X11/xshmfence.h>
}

template<auto>
struct fex_gen_config {
  unsigned version = 1;
};

template<typename>
struct fex_gen_type {};

template<>
struct fex_gen_type<xshmfence> : fexgen::opaque_type {};

template<>
struct fex_gen_config<xshmfence_trigger> {};
template<>
struct fex_gen_config<xshmfence_await> {};
template<>
struct fex_gen_config<xshmfence_query> {};
template<>
struct fex_gen_config<xshmfence_reset> {};
template<>
struct fex_gen_config<xshmfence_alloc_shm> {};
template<>
struct fex_gen_config<xshmfence_map_shm> {};
// custom_host_impl so the 32-bit opaque-handle token registry (see
// XshmfenceRegistry in Host.cpp) can retire the handle before the underlying
// mapping goes away. Without this the registry keeps handing out a token that
// resolves to an unmapped page, which is worse than the truncation the
// registry itself replaced: a caller that mistakenly re-triggers/awaits a
// freed fence would fault on freed/unmapped memory instead of getting a
// well-defined rejection. Mirrors glXDestroyContext in libGL.
template<>
struct fex_gen_config<xshmfence_unmap_shm> : fexgen::custom_host_impl {};
