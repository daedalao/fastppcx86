option(ENABLE_CLANG_THUNKS "Enable building thunks with clang" FALSE)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR i686)

# Propagate through try_compile()'s inner CMake invocation, else the compiler-
# ABI probe re-loads this toolchain with the option defaulted to FALSE and the
# rebuild falls into the ct-ng -m32 branch that has no 32-bit multilib on this
# host and cannot link even a hello-world.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ENABLE_CLANG_THUNKS X86_DEV_ROOTFS)

if (ENABLE_CLANG_THUNKS)
  message(STATUS "Enabling thunk clang building. Force enabling LLD as well")

  set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_C_COMPILER clang)
  set(CMAKE_CXX_COMPILER clang++)
  set(CLANG_FLAGS "-target i686-linux-gnu -msse2 -mfpmath=sse")

  # Same sysroot logic as toolchain_x86_64.cmake: on non-Debian hosts clang has
  # no i386 crt/libc in its search path. Point --sysroot at the rootfs (which
  # is what the guest links against at runtime anyway); Arch's FEXRootFSFetcher
  # rootfs ships lib32-glibc / lib32-gcc-libs by default and provides both.
  if (X86_DEV_ROOTFS AND NOT X86_DEV_ROOTFS STREQUAL "/")
    set(CLANG_FLAGS "${CLANG_FLAGS} --sysroot=${X86_DEV_ROOTFS}")
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CLANG_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CLANG_FLAGS}")
else()
  set(CMAKE_C_COMPILER x86_64-linux-gnu-gcc -m32)
  set(CMAKE_CXX_COMPILER x86_64-linux-gnu-g++ -m32)
endif()
