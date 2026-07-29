option(ENABLE_CLANG_THUNKS "Enable building thunks with clang" FALSE)

set(CMAKE_SYSTEM_PROCESSOR x86_64)

if (ENABLE_CLANG_THUNKS)
  message(STATUS "Enabling thunk clang building. Force enabling LLD as well")

  set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_C_COMPILER clang)
  set(CMAKE_CXX_COMPILER clang++)
  set(CLANG_FLAGS "-target x86_64-linux-gnu")

  # Mirror of 711f640b4: when X86_DEV_ROOTFS and X86_DEV_GCC_TOOLCHAIN are supplied,
  # teach clang about them so crtbeginS.o and libgcc resolve. Without this, clang
  # falls through to the host's default search paths — which on non-Debian hosts
  # (e.g. Arch POWER) contain no x86_64 crt files.
  if (X86_DEV_ROOTFS AND NOT X86_DEV_ROOTFS STREQUAL "/")
    set(CLANG_FLAGS "${CLANG_FLAGS} --sysroot=${X86_DEV_ROOTFS}")
  endif()
  if (X86_DEV_GCC_TOOLCHAIN)
    set(CLANG_FLAGS "${CLANG_FLAGS} --gcc-toolchain=${X86_DEV_GCC_TOOLCHAIN}")
  endif()

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CLANG_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CLANG_FLAGS}")
else()
  set(CMAKE_C_COMPILER x86_64-linux-gnu-gcc)
  set(CMAKE_CXX_COMPILER x86_64-linux-gnu-g++)
endif()
