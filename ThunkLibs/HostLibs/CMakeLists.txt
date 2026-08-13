cmake_minimum_required(VERSION 3.14)
project(host-thunks)
include(${FEX_PROJECT_SOURCE_DIR}/Data/CMake/version_to_variables.cmake)

set(CMAKE_CXX_STANDARD 20)
option(ENABLE_CLANG_THUNKS "Enable building thunks with clang" FALSE)

# Pre-generated thunkgen output. The generated .inl encodes GUEST data
# layouts, which thunkgen derives by parsing the interface with x86 targets
# against real x86 glibc/libstdc++ headers. Without those headers the parse is
# unsound -- against ppc64le glibc it produced silently different repack code
# for libwayland-client and refused valid Vulkan structs -- so builds on hosts
# without an x86 sysroot (i.e. end users) consume maintainer-generated .inl
# files instead of running the generator. Expects
# ${THUNKGEN_PREGEN_DIR}/gen_{32,64}/thunkgen_host_<name>.inl.
set(THUNKGEN_PREGEN_DIR "" CACHE PATH
    "Directory of pre-generated thunkgen host .inl files; skips the x86 interface parse")

if (ENABLE_CLANG_THUNKS)
  set(LD_OVERRIDE "-fuse-ld=lld")
  add_link_options(${LD_OVERRIDE})
endif()

set(PPC_THUNKGEN_EXTRA_FLAGS "")

# x86 cross toolchain detected at top level: its cross gcc supplies the
# libstdc++ headers for the x86-target parses (the cross-glibc sysroot in
# X86_DEV_ROOTFS has none of its own). The i686 parse additionally needs the
# stubs-32.h stand-in below: the cross glibc is 64-bit-only.
if (THUNKGEN_X86_CROSS_CXX_DIR)
  list(APPEND PPC_THUNKGEN_EXTRA_FLAGS
       "-isystem${THUNKGEN_X86_CROSS_CXX_DIR}"
       "-isystem${THUNKGEN_X86_CROSS_CXX_DIR}/x86_64-pc-linux-gnu")
endif()

# On PPC64LE (Arch) clang picks the Debian-style triple powerpc64le-linux-gnu
# for the GCC toolchain, but the platform-specific c++ headers live under
# powerpc64le-unknown-linux-gnu. The mismatch hides <bits/c++config.h>.
# Discover the real path once and add it to every thunkgen invocation.
# Skipped when the x86 cross toolchain supplies the c++ headers instead: two
# competing bits/c++config.h in the search path is how layouts go subtly
# wrong.
if (NOT THUNKGEN_X86_CROSS_CXX_DIR AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(ppc64|powerpc64)")
  set(_PPC_CXX_PLATFORM_INC "")
  file(GLOB _PPC_CXX_DIRS /usr/include/c++/*/powerpc64le-*linux-gnu)
  foreach(_d ${_PPC_CXX_DIRS})
    if (EXISTS "${_d}/bits/c++config.h")
      set(_PPC_CXX_PLATFORM_INC "${_d}")
      break()
    endif()
  endforeach()
  if (_PPC_CXX_PLATFORM_INC)
    message(STATUS "PPC64LE thunkgen: using platform c++ headers at ${_PPC_CXX_PLATFORM_INC}")
    list(APPEND PPC_THUNKGEN_EXTRA_FLAGS "-isystem${_PPC_CXX_PLATFORM_INC}")
  endif()
endif()

# Syntax: generate(libxyz libxyz-interface.cpp)
# This defines two targets and a custom command:
# - custom command: Main build step that runs the thunk generator on the given interface definition
# - libxyz-interface: Target for IDE integration (making sure libxyz-interface.cpp shows up as a source file in the project tree)
# - libxyz-deps: Interface target to read include directories from which are passed to libclang when parsing the interface definition
function(generate NAME SOURCE_FILE GUEST_BITNESS)
  # Interface target for the user to add include directories
  add_library(${NAME}-${GUEST_BITNESS}-deps INTERFACE)
  target_include_directories(${NAME}-${GUEST_BITNESS}-deps INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
  if (GUEST_BITNESS EQUAL 32)
    target_compile_definitions(${NAME}-${GUEST_BITNESS}-deps INTERFACE IS_32BIT_THUNK)
  endif()
  # Cross-arch host (non-x86_64): guest VAs cannot be bctrl'd into directly,
  # so callbacks passed by the guest must be wrapped in host trampolines just
  # like the 32-bit-on-64-bit case. Gates the cross-arch wrap path in
  # ThunkLibs/include/common/Host.h.
  if (NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    target_compile_definitions(${NAME}-${GUEST_BITNESS}-deps INTERFACE THUNK_HOST_NOT_X86_64)
  endif()
  # Shorthand for the include directories added after calling this function.
  # This is not evaluated directly, hence directories added after return are still picked up
  set(prop "$<TARGET_PROPERTY:${NAME}-${GUEST_BITNESS}-deps,INTERFACE_INCLUDE_DIRECTORIES>")
  set(compile_prop "$<TARGET_PROPERTY:${NAME}-${GUEST_BITNESS}-deps,INTERFACE_COMPILE_DEFINITIONS>")
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    list(APPEND compile_prop ARCHITECTURE_x86_64=1)
  elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    list(APPEND compile_prop ARCHITECTURE_arm64=1)
  elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^ppc64|^powerpc64")
    list(APPEND compile_prop ARCHITECTURE_ppc64le=1)
  endif()

  # Target for IDE integration
  add_library(${NAME}-${GUEST_BITNESS}-interface EXCLUDE_FROM_ALL ${SOURCE_FILE})
  target_link_libraries(${NAME}-${GUEST_BITNESS}-interface PRIVATE ${NAME}-${GUEST_BITNESS}-deps)

  # Run thunk generator for each of the given output files
  set(OUTFOLDER "${CMAKE_CURRENT_BINARY_DIR}/gen_${GUEST_BITNESS}")
  set(OUTFILE "${OUTFOLDER}/thunkgen_host_${NAME}.inl")

  file(MAKE_DIRECTORY "${OUTFOLDER}")

  set(BITNESS_FLAGS "")
  if (GUEST_BITNESS EQUAL 32)
    set(BITNESS_FLAGS "-for-32bit-guest")
  endif()

  # Without an X86_DEV_ROOTFS the x86-target interface parses run against the
  # host's glibc headers, and ppc64le glibc's <gnu/stubs.h> includes
  # <gnu/stubs-32.h> for ANY target that does not define __powerpc64__ -- so
  # both the x86_64 and the i686 parse die on a header only multilib glibc
  # ships. The parse never links, so an empty stand-in is sufficient;
  # -idirafter keeps it behind every real header, so a provided sysroot still
  # wins.
  set(THUNKGEN_COMPAT_DIR "${CMAKE_BINARY_DIR}/thunkgen-compat")
  file(WRITE "${THUNKGEN_COMPAT_DIR}/gnu/stubs-32.h"
    "/* Empty parse-only stand-in for the x86 multilib stubs header. */\n")
  set(BITNESS_COMPAT_FLAGS "-idirafter${THUNKGEN_COMPAT_DIR}")

  # Only pass X86_DEV_GCC_TOOLCHAIN for 64-bit guest thunks. For 32-bit the
  # ct-ng x86_64 crosstool has no i686 libstdc++, and pointing thunkgen's
  # clang at it forces the header search there and skips the perfectly good
  # i686-compatible headers inside X86_DEV_ROOTFS.
  set(THUNKGEN_GCC_TOOLCHAIN_ENV "")
  if (GUEST_BITNESS EQUAL 64)
    set(THUNKGEN_GCC_TOOLCHAIN_ENV "FEX_THUNKGEN_GCC_TOOLCHAIN=${X86_DEV_GCC_TOOLCHAIN}")
  endif()

  if (THUNKGEN_PREGEN_DIR)
    set(PREGEN_FILE "${THUNKGEN_PREGEN_DIR}/gen_${GUEST_BITNESS}/thunkgen_host_${NAME}.inl")
    if (NOT EXISTS "${PREGEN_FILE}")
      message(FATAL_ERROR "THUNKGEN_PREGEN_DIR is set but ${PREGEN_FILE} is missing")
    endif()
    add_custom_command(
      OUTPUT "${OUTFILE}"
      DEPENDS "${PREGEN_FILE}"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PREGEN_FILE}" "${OUTFILE}"
      VERBATIM)
  else()
  add_custom_command(
    OUTPUT "${OUTFILE}"
    DEPENDS "${SOURCE_FILE}"
    DEPENDS thunkgen
    COMMAND ${CMAKE_COMMAND} -E env ${THUNKGEN_GCC_TOOLCHAIN_ENV}
      "$<TARGET_FILE:thunkgen>" "${SOURCE_FILE}" "${NAME}" "-host" "${OUTFILE}" "${X86_DEV_ROOTFS}" ${BITNESS_FLAGS} -- -std=c++20
      # Expand compile definitions to space-separated list of -D parameters
      "$<$<BOOL:${compile_prop}>:;-D$<JOIN:${compile_prop},;-D>>"
      # Expand include directories to space-separated list of -isystem parameters
      "$<$<BOOL:${prop}>:;-isystem$<JOIN:${prop},;-isystem>>"
      ${PPC_THUNKGEN_EXTRA_FLAGS}
      ${BITNESS_COMPAT_FLAGS}
    VERBATIM
    COMMAND_EXPAND_LISTS)
  endif()

  list(APPEND OUTPUTS "${OUTFILE}")
  set(GEN_${NAME} ${OUTPUTS} PARENT_SCOPE)
endfunction()

function(add_host_lib NAME GUEST_BITNESS)
  set(SOURCE_FILE ../lib${NAME}/lib${NAME}_Host.cpp)
    get_filename_component(SOURCE_FILE_ABS "${SOURCE_FILE}" ABSOLUTE)
  if (NOT EXISTS "${SOURCE_FILE_ABS}")
    set(SOURCE_FILE ../lib${NAME}/Host.cpp)
    get_filename_component(SOURCE_FILE_ABS "${SOURCE_FILE}" ABSOLUTE)
    if (NOT EXISTS "${SOURCE_FILE_ABS}")
      message (FATAL_ERROR "Thunk source file for Host lib ${NAME} doesn't exist!")
    endif()
  endif()

  add_library(${NAME}-host-${GUEST_BITNESS} SHARED ${SOURCE_FILE} ${GEN_lib${NAME}})
  set_target_properties(${NAME}-host-${GUEST_BITNESS} PROPERTIES OUTPUT_NAME "${NAME}-host")
  set_target_properties(${NAME}-host-${GUEST_BITNESS} PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/HostLibs_${GUEST_BITNESS}")
  target_include_directories(${NAME}-host-${GUEST_BITNESS} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/gen_${GUEST_BITNESS}/")
  # For GUEST_BITNESS 32 on ppc64le, common/Host.h includes
  # <FEXCore/Utils/ArchHelpers/PPC64CacheFlush.h> for the low-32 trampoline's
  # I-cache publication. Stated explicitly rather than relying on the FEX
  # executable target below to propagate FEXCore's PUBLIC include dirs.
  # The include is confined to that one configuration inside Host.h: leaving it
  # unconditional at the top of the file broke every out-of-tree consumer of
  # ThunkLibs/include, which is a public include root with no other FEXCore
  # dependency and no way to know it had acquired one.
  target_include_directories(${NAME}-host-${GUEST_BITNESS} PRIVATE "${FEX_PROJECT_SOURCE_DIR}/FEXCore/include/")
  target_link_libraries(${NAME}-host-${GUEST_BITNESS} PRIVATE dl)
  target_link_libraries(${NAME}-host-${GUEST_BITNESS} PRIVATE lib${NAME}-${GUEST_BITNESS}-deps)
  target_link_libraries(${NAME}-host-${GUEST_BITNESS} PRIVATE FEX)
  ## Make signed overflow well defined 2's complement overflow
  target_compile_options(${NAME}-host-${GUEST_BITNESS} PRIVATE -fwrapv)

  if (NOT ENABLE_ASAN)
    # generated files forward-declare functions that need to be implemented manually, so pass --no-undefined to make sure errors are detected at compile-time rather than runtime
    # NOTE: ASan is not compatible with --no-undefined, see https://github.com/google/sanitizers/issues/380 for details
    target_link_options(${NAME}-host-${GUEST_BITNESS} PRIVATE "LINKER:--no-undefined")
  endif()

  if (${GUEST_BITNESS} EQUAL 32)
    install(TARGETS ${NAME}-host-${GUEST_BITNESS} COMPONENT Runtime DESTINATION ${HOSTLIBS_DATA_DIRECTORY}/HostThunks_32/)
  else()
    install(TARGETS ${NAME}-host-${GUEST_BITNESS} COMPONENT Runtime DESTINATION ${HOSTLIBS_DATA_DIRECTORY}/HostThunks/)
  endif()
endfunction()

set(BITNESS_LIST "64")
foreach(GUEST_BITNESS IN LISTS BITNESS_LIST)
  #add_host_lib(fex_malloc_symbols ${GUEST_BITNESS})

  #generate(libfex_malloc)
  #add_host_lib(fex_malloc ${GUEST_BITNESS})

  generate(libasound ${CMAKE_CURRENT_SOURCE_DIR}/../libasound/libasound_interface.cpp ${GUEST_BITNESS})
  add_host_lib(asound ${GUEST_BITNESS})

  # disabled for now, headers are platform specific
  # find_package(SDL2 REQUIRED)
  # generate(libSDL2)
  # add_host_lib(SDL2 ${GUEST_BITNESS})
  # target_include_directories(SDL2-host PRIVATE ${SDL2_INCLUDE_DIRS})

  # libdrm stays 64-bit-guest only until the 32-bit host-side work lands: the
  # interface carries the repacking annotations but the matching
  # fex_custom_repack_entry/exit and the guest-heap relocation for the
  # host-allocated drmDevice/drmVersion returns are not implemented yet.
  generate(libdrm ${CMAKE_CURRENT_SOURCE_DIR}/../libdrm/libdrm_interface.cpp ${GUEST_BITNESS})
  target_include_directories(libdrm-${GUEST_BITNESS}-deps INTERFACE /usr/include/drm/)
  target_include_directories(libdrm-${GUEST_BITNESS}-deps INTERFACE /usr/include/libdrm/)
  add_host_lib(drm ${GUEST_BITNESS})
endforeach()

# These libs support both guest bitnesses. Generating the 32-bit variants requires thunkgen to parse
# the interface headers as i686, which needs an i686 sysroot — hosts with only an x86_64
# cross-toolchain cannot do it, and nothing 64-bit-guest-only depends on the result.
if (BUILD_THUNKS_32BIT)
  set(BITNESS_LIST "32;64")
else()
  set(BITNESS_LIST "64")
endif()
foreach(GUEST_BITNESS IN LISTS BITNESS_LIST)
  if (BUILD_FEX_LINUX_TESTS)
    generate(libfex_thunk_test ${CMAKE_CURRENT_SOURCE_DIR}/../libfex_thunk_test/libfex_thunk_test_interface.cpp ${GUEST_BITNESS})
    add_host_lib(fex_thunk_test ${GUEST_BITNESS})
  endif()

  # libxshmfence: 32-bit support added 2026-08-07 for the guest Mesa/DRI3 stack
  # used by 32-bit Unity titles. Handles are translated through an opaque-handle
  # token registry on 32-bit; see ThunkLibs/libxshmfence/Host.cpp.
  generate(libxshmfence ${CMAKE_CURRENT_SOURCE_DIR}/../libxshmfence/libxshmfence_interface.cpp ${GUEST_BITNESS})
  add_host_lib(xshmfence ${GUEST_BITNESS})

  generate(libvulkan ${CMAKE_CURRENT_SOURCE_DIR}/../libvulkan/libvulkan_interface.cpp ${GUEST_BITNESS})
  target_include_directories(libvulkan-${GUEST_BITNESS}-deps INTERFACE ${FEX_PROJECT_SOURCE_DIR}/External/Vulkan-Headers/include/)
  add_host_lib(vulkan ${GUEST_BITNESS})

  generate(libwayland-client ${CMAKE_CURRENT_SOURCE_DIR}/../libwayland-client/libwayland-client_interface.cpp ${GUEST_BITNESS})
  add_host_lib(wayland-client ${GUEST_BITNESS})
  target_include_directories(libwayland-client-${GUEST_BITNESS}-deps INTERFACE /usr/include/wayland)

  generate(libEGL ${CMAKE_CURRENT_SOURCE_DIR}/../libEGL/libEGL_interface.cpp ${GUEST_BITNESS})
  add_host_lib(EGL ${GUEST_BITNESS})

  generate(libGL ${CMAKE_CURRENT_SOURCE_DIR}/../libGL/libGL_interface.cpp ${GUEST_BITNESS})
  add_host_lib(GL ${GUEST_BITNESS})

  find_package(OpenGL REQUIRED)
  target_link_libraries(GL-host-${GUEST_BITNESS} PRIVATE OpenGL::GL)
endforeach()

if (BUILD_FEX_LINUX_TESTS)
  add_library(fex_thunk_test SHARED ../libfex_thunk_test/lib.cpp)
  install(TARGETS fex_thunk_test LIBRARY DESTINATION lib COMPONENT TestLibraries)
endif()
