/* rpmalloc compiled for a dlopen()ed shared library.
 *
 * Stock rpmalloc declares its per-thread heap pointer with
 * __attribute__((tls_model("initial-exec"))).  That model stamps DF_STATIC_TLS
 * on any DSO the object is linked into, and glibc then refuses to dlopen() the
 * DSO whenever the process's static TLS surplus (~1.6KB by default) has been
 * spent: "cannot allocate memory in static TLS block".  An embedder cannot be
 * asked to launch with GLIBC_TUNABLES to make dlopen("libfexbridge.so") work,
 * so the bridge needs rpmalloc built with the compiler-default (dynamic) TLS
 * model instead.
 *
 * rpmalloc lives in a submodule of an upstream repo (FEX-Emu/rpmalloc), so the
 * model cannot be made configurable at the source.  Instead this wrapper
 * repaints the attribute: attribute arguments are macro-expanded, and a
 * function-like macro whose expansion contains its own name is not expanded
 * again (C11 6.10.3.4p2), so every tls_model("...") in rpmalloc.c becomes
 * tls_model("global-dynamic") and nothing else in the file is touched.
 *
 * fexbridge links this object instead of the static rpmalloc library the rest
 * of the tree uses; FEX and the other executables keep initial-exec, which is
 * both safe and faster for a main program.  See CMakeLists.txt here for how
 * the duplicate archive member is kept out of the link.
 */
#define tls_model(model) tls_model("global-dynamic")

#include "rpmalloc/rpmalloc.c"
