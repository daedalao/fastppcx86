option(ENABLE_CLANG_THUNKS "Enable building thunks with clang" FALSE)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Locate an x86_64 cross sysroot.
#
# On a non-x86 host (POWER8, aarch64) clang resolves Scrt1.o/crti.o/crtn.o
# through the gcc install dir's ../../../../lib64, which lands on the *native*
# /usr/lib64. The linker then latches onto the host ELF machine type from those
# first inputs and rejects every x86_64 object with
#   "... is incompatible with elf64-powerpcle"
# even though -m elf_x86_64 was passed. Pointing --sysroot at the real cross
# sysroot fixes it. On an x86_64 host there is nothing to do.
set(X86_64_CROSS_SYSROOT "" CACHE PATH "Sysroot containing x86_64 libc/CRT objects for cross-building thunks")
if (NOT X86_64_CROSS_SYSROOT AND NOT CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  foreach(_candidate /usr/x86_64-pc-linux-gnu /usr/x86_64-linux-gnu /usr/x86_64-unknown-linux-gnu)
    if (EXISTS "${_candidate}/lib/Scrt1.o" OR EXISTS "${_candidate}/usr/lib/Scrt1.o")
      set(X86_64_CROSS_SYSROOT "${_candidate}" CACHE PATH "" FORCE)
      break()
    endif()
  endforeach()
endif()
if (X86_64_CROSS_SYSROOT)
  message(STATUS "x86_64 thunk cross sysroot: ${X86_64_CROSS_SYSROOT}")
  set(CMAKE_SYSROOT "${X86_64_CROSS_SYSROOT}")
endif()

if (ENABLE_CLANG_THUNKS)
  message(STATUS "Enabling thunk clang building. Force enabling LLD as well")

  set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
  set(CMAKE_C_COMPILER clang)
  set(CMAKE_CXX_COMPILER clang++)
  set(CLANG_FLAGS "-target x86_64-linux-gnu")
  if (X86_64_CROSS_SYSROOT)
    string(APPEND CLANG_FLAGS " --sysroot=${X86_64_CROSS_SYSROOT}")
  endif()

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
  # Distros disagree on the cross triple: Debian/Ubuntu ship x86_64-linux-gnu-gcc,
  # Arch ships x86_64-pc-linux-gnu-gcc.
  find_program(X86_64_CROSS_GCC NAMES x86_64-linux-gnu-gcc x86_64-pc-linux-gnu-gcc x86_64-unknown-linux-gnu-gcc)
  find_program(X86_64_CROSS_GXX NAMES x86_64-linux-gnu-g++ x86_64-pc-linux-gnu-g++ x86_64-unknown-linux-gnu-g++)
  if (NOT X86_64_CROSS_GCC OR NOT X86_64_CROSS_GXX)
    message(FATAL_ERROR "No x86_64 cross gcc found. Install one, or configure with -DENABLE_CLANG_THUNKS=ON.")
  endif()
  set(CMAKE_C_COMPILER "${X86_64_CROSS_GCC}")
  set(CMAKE_CXX_COMPILER "${X86_64_CROSS_GXX}")
endif()
