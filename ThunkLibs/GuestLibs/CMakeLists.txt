cmake_minimum_required(VERSION 3.14)
project(guest-thunks)
include(${FEX_PROJECT_SOURCE_DIR}/Data/CMake/version_to_variables.cmake)

option(ENABLE_CLANG_THUNKS "Enable building thunks with clang" FALSE)

if (ENABLE_CLANG_THUNKS)
  set(LD_OVERRIDE "-fuse-ld=lld")
  add_link_options(${LD_OVERRIDE})
endif()

if (NOT X86_DEV_ROOTFS)
  message(FATAL_ERROR "X86_DEV_ROOTFS must be set(use \"/\" to ignore)")
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  message(STATUS "CCache enabled for guest thunks")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  # We've been included using ExternalProject_add, so set up the actual thunk libraries to be cross-compiled
  set(CMAKE_CXX_STANDARD 20)

  # This gets passed in from the main cmake project
  set(DATA_DIRECTORY "" CACHE PATH "Global data directory (override)")
  if (NOT DATA_DIRECTORY)
    set(DATA_DIRECTORY "${CMAKE_INSTALL_PREFIX}/share/fex-emu")
  endif()

  set(TARGET_TYPE SHARED)
  set(GENERATE_GUEST_INSTALL_TARGETS TRUE)

  # Library headers (alsa, X11, libdrm, GL, wayland, ...) for the guest stubs.
  #
  # On an x86_64 host these come from the plain host /usr/include. Cross-building
  # from a non-x86 host we must not read the native ones, and CMAKE_SYSROOT
  # (the toolchain's libc/CRT sysroot) only carries libc and libstdc++. The dev
  # rootfs is the thing that has the actual library headers, so point compiles at
  # it as well -- thunkgen is already given it for parsing the interfaces.
  if (X86_DEV_ROOTFS AND NOT X86_DEV_ROOTFS STREQUAL "/")
    if (NOT EXISTS "${X86_DEV_ROOTFS}/usr/include")
      message(FATAL_ERROR "X86_DEV_ROOTFS '${X86_DEV_ROOTFS}' has no usr/include")
    endif()
    include_directories(SYSTEM "${X86_DEV_ROOTFS}/usr/include")
    foreach(_subdir drm libdrm wayland)
      if (EXISTS "${X86_DEV_ROOTFS}/usr/include/${_subdir}")
        include_directories(SYSTEM "${X86_DEV_ROOTFS}/usr/include/${_subdir}")
      endif()
    endforeach()
  endif()

  # uninstall target
  if(NOT TARGET uninstall)
    configure_file("${FEX_PROJECT_SOURCE_DIR}/Data/CMake/cmake_uninstall.cmake.in"
      "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cmake_uninstall.cmake"
      IMMEDIATE @ONLY)

    add_custom_target(uninstall
      COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cmake_uninstall.cmake)
  endif()
else()
  # We've been included using add_subdirectory, so set up targets for IDE integration using the host toolchain
  set(GENERATOR_EXE "$<TARGET_FILE:thunkgen>")
  set(TARGET_TYPE OBJECT)
  set(GENERATE_GUEST_INSTALL_TARGETS FALSE)
  set(BITNESS 64)
endif()

# Syntax: generate(libxyz libxyz-interface.cpp)
# This defines a target and a custom command:
# - custom command: Main build step that runs the thunk generator on the given interface definition
# - libxyz-guest-deps: Interface target to read include directories from which are passed to libclang when parsing the interface definition
function(generate NAME SOURCE_FILE)
  # Interface target for the user to add include directories
  add_library(${NAME}-guest-deps INTERFACE)
  target_include_directories(${NAME}-guest-deps INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../include")
  if (BITNESS EQUAL 32)
    target_compile_definitions(${NAME}-guest-deps INTERFACE IS_32BIT_THUNK)
  endif()
  # Shorthand for the include directories added after calling this function.
  # This is not evaluated directly, hence directories added after return are still picked up
  set(prop "$<TARGET_PROPERTY:${NAME}-guest-deps,INTERFACE_INCLUDE_DIRECTORIES>")
  set(compile_prop "$<TARGET_PROPERTY:${NAME}-guest-deps,INTERFACE_COMPILE_DEFINITIONS>")

  # Run thunk generator for each of the given output files
  set(OUTFOLDER "${CMAKE_CURRENT_BINARY_DIR}/gen")
  set(OUTFILE "${OUTFOLDER}/thunkgen_guest_${NAME}.inl")

  file(MAKE_DIRECTORY "${OUTFOLDER}")

  # Target selection for thunkgen's clang parse. The header search path is
  # supplied one of two ways:
  #
  #  * X86_DEV_ROOTFS == "/" (the default): fall back to Debian/Ubuntu's
  #    multilib convention, /usr/{i686,x86_64}-linux-gnu/include/. This is the
  #    historical behaviour and is preserved for hosts that provide it.
  #
  #  * X86_DEV_ROOTFS set to a real sysroot: pass --sysroot instead. Required on
  #    any host that does not ship Debian's multilib layout — e.g. Arch, and
  #    every non-x86 host cross-building these, where those paths simply do not
  #    exist and clang silently falls through to the *host* glibc's
  #    /usr/include/gnu/stubs.h, which then #includes a gnu/stubs-32.h that is
  #    not present. The resulting error names stubs-32.h and looks like a
  #    missing 32-bit package rather than a wrong search path.
  #
  # X86_DEV_GCC_TOOLCHAIN is separate and usually also needed with a sysroot: a
  # cross-toolchain keeps its libstdc++ headers beside the compiler rather than
  # inside the sysroot, so --sysroot alone finds libc but not <type_traits>.
  if (BITNESS EQUAL 32)
    set(BITNESS_FLAGS "-for-32bit-guest")
    set(BITNESS_FLAGS2 "-m32" "--target=i686-linux-gnu")
    set(_FALLBACK_ISYSTEM "/usr/i686-linux-gnu/include/")
  else()
    set(BITNESS_FLAGS "")
    set(BITNESS_FLAGS2 "--target=x86_64-linux-gnu")
    set(_FALLBACK_ISYSTEM "/usr/x86_64-linux-gnu/include/")
  endif()

  if (X86_DEV_ROOTFS AND NOT X86_DEV_ROOTFS STREQUAL "/")
    list(APPEND BITNESS_FLAGS2 "--sysroot=${X86_DEV_ROOTFS}")
  else()
    list(APPEND BITNESS_FLAGS2 "-isystem" "${_FALLBACK_ISYSTEM}")
  endif()

  # --gcc-toolchain wins over --sysroot for C++ header search. Only pass it
  # when it can genuinely serve the target: for 32-bit the ct-ng x86_64
  # crosstool at X86_DEV_GCC_TOOLCHAIN has no i686 libstdc++ headers (no
  # multilib on this host), and specifying it forces clang to look there and
  # miss the perfectly good headers inside the rootfs sysroot.
  if (X86_DEV_GCC_TOOLCHAIN AND BITNESS EQUAL 64)
    list(APPEND BITNESS_FLAGS2 "--gcc-toolchain=${X86_DEV_GCC_TOOLCHAIN}")
  endif()

  # Only pass X86_DEV_GCC_TOOLCHAIN for 64-bit guest thunks (see HostLibs
   # CMakeLists.txt for the same reasoning).
  set(THUNKGEN_GCC_TOOLCHAIN_ENV "")
  if (BITNESS EQUAL 64)
    set(THUNKGEN_GCC_TOOLCHAIN_ENV "FEX_THUNKGEN_GCC_TOOLCHAIN=${X86_DEV_GCC_TOOLCHAIN}")
  endif()

  add_custom_command(
    OUTPUT "${OUTFILE}"
    DEPENDS "${GENERATOR_EXE}"
    DEPENDS "${SOURCE_FILE}"
    COMMAND ${CMAKE_COMMAND} -E env ${THUNKGEN_GCC_TOOLCHAIN_ENV}
      "${GENERATOR_EXE}" "${SOURCE_FILE}" "${NAME}" "-guest" "${OUTFILE}" "${X86_DEV_ROOTFS}" ${BITNESS_FLAGS} -- -std=c++20 ${BITNESS_FLAGS2}
      # Expand compile definitions to space-separated list of -D parameters
      "$<$<BOOL:${compile_prop}>:;-D$<JOIN:${compile_prop},;-D>>"
      # Expand include directories to space-separated list of -isystem parameters
      "$<$<BOOL:${prop}>:;-isystem$<JOIN:${prop},;-isystem>>"
    VERBATIM
    COMMAND_EXPAND_LISTS)

  list(APPEND OUTPUTS "${OUTFILE}")
  set(GEN_${NAME} ${OUTPUTS} PARENT_SCOPE)
endfunction()

function(add_guest_lib NAME SONAME)
  set(SOURCE_FILE ../lib${NAME}/lib${NAME}_Guest.cpp)
  get_filename_component(SOURCE_FILE_ABS "${SOURCE_FILE}" ABSOLUTE)

  set(SOURCE_LDS_FILE ../lib${NAME}/lib${NAME}_Guest.lds)
  get_filename_component(SOURCE_LDS_FILE_ABS "${SOURCE_LDS_FILE}" ABSOLUTE)

  set(SOURCE_LDS_32_FILE ../lib${NAME}/lib${NAME}_Guest_32.lds)
  get_filename_component(SOURCE_LDS_32_FILE_ABS "${SOURCE_LDS_32_FILE}" ABSOLUTE)

  if (NOT EXISTS "${SOURCE_FILE_ABS}")
    set(SOURCE_FILE ../lib${NAME}/Guest.cpp)
    get_filename_component(SOURCE_FILE_ABS "${SOURCE_FILE}" ABSOLUTE)
    if (NOT EXISTS "${SOURCE_FILE_ABS}")
      message (FATAL_ERROR "Thunk source file for Guest lib ${NAME} doesn't exist!")
    endif()
  endif()

  add_library(${NAME}-guest ${TARGET_TYPE} ${SOURCE_FILE} ${GEN_lib${NAME}})
  target_include_directories(${NAME}-guest PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/gen/")
  target_compile_definitions(${NAME}-guest PRIVATE GUEST_THUNK_LIBRARY)
  target_link_libraries(${NAME}-guest PRIVATE lib${NAME}-guest-deps)

  ## Make signed overflow well defined 2's complement overflow
  target_compile_options(${NAME}-guest PRIVATE -fwrapv)
  if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    ## Compile for SSE2
    ## Compile with fpmath=sse to remove x87 usage
    target_compile_options(${NAME}-guest PRIVATE -msse2 -mfpmath=sse)

    # When cross-compiling against a dedicated sysroot, that sysroot generally contains only libc
    # and the C++ standard library. Thunk sources also include ordinary library headers — X11,
    # libdrm, alsa — which are architecture-agnostic and only exist under the host prefix. Search
    # there last, so the sysroot still wins for anything platform-specific. This mirrors what
    # thunkgen already does for its own parse (ThunkLibs/Generator/main.cpp).
    if (X86_DEV_ROOTFS AND NOT X86_DEV_ROOTFS STREQUAL "/")
      target_compile_options(${NAME}-guest PRIVATE -idirafter /usr/include)
    endif()
  endif()

  if (BITNESS EQUAL 32)
    # Makes the GOT/PLT lookups slightly less painful
    target_compile_options(${NAME}-guest PRIVATE -fno-plt -fno-stack-protector)
    target_link_options(${NAME}-guest PRIVATE "LINKER:-z,now" "LINKER:-z,relro" "LINKER:-z,notext")
  endif()

  # Add linker script if set
  if (BITNESS EQUAL 64 AND EXISTS "${SOURCE_LDS_FILE_ABS}")
    target_link_options(${NAME}-guest PRIVATE "-T" "${CMAKE_CURRENT_SOURCE_DIR}/../lib${NAME}/lib${NAME}_Guest.lds")
    set_property(TARGET ${NAME}-guest APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../lib${NAME}/lib${NAME}_Guest.lds")
  endif()

  if (BITNESS EQUAL 32 AND EXISTS "${SOURCE_LDS_32_FILE_ABS}")
    target_link_options(${NAME}-guest PRIVATE "-T" "${CMAKE_CURRENT_SOURCE_DIR}/../lib${NAME}/lib${NAME}_Guest_32.lds")
    set_property(TARGET ${NAME}-guest APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../lib${NAME}/lib${NAME}_Guest_32.lds")
  endif()

  # We need to override the soname for the linker.
  # Our guest thunk libraries are named `lib<Thunk>-guest`.
  # Once we override the loaded name, the guest is free to dlopen again by SONAME rather than filepath.
  # eg:
  # dlopen("libGL.so.1", RTLD_GLOBAL | RTLD_NOW); -> We override this `libGL.so.1` to `libGL-guest.so`
  # Later on in the program, it can do:
  # dlopen("libGL.so.1", RTLD_GLOBAL | RTLD_NOLOAD);
  # This second dlopen will only check to see if the previous load has made the library resident
  # Searching for SONAME in the process.
  #
  # Additionally, VDSO can only be opened by SONAME.
  # This means it will only ever open the handle with `dlopen("linux-vdso.so.1", RTLD_GLOBAL | RTLD_NOLOAD);
  # Note that this doesn't have a lib prefix, and also since it doesn't exist on the filesystem, it can never
  # Actually load from a path.
  target_link_options(${NAME}-guest PRIVATE "LINKER:-soname,${SONAME}")
  set_target_properties(${NAME}-guest PROPERTIES NO_SONAME ON)

  if (GENERATE_GUEST_INSTALL_TARGETS)
    if (BITNESS EQUAL 64)
      install(TARGETS ${NAME}-guest DESTINATION ${DATA_DIRECTORY}/GuestThunks/)
    else()
      install(TARGETS ${NAME}-guest DESTINATION ${DATA_DIRECTORY}/GuestThunks_32/)
    endif()
  endif()
endfunction()

# These thunks only support 64-bit (libvulkan is enabled for 32-bit too —
# Steam ubuntu12_32 needs it for zink/Vulkan rendering)
if (BITNESS EQUAL 32 OR BITNESS EQUAL 64)
  generate(libvulkan ${CMAKE_CURRENT_SOURCE_DIR}/../libvulkan/libvulkan_interface.cpp)
  target_include_directories(libvulkan-guest-deps INTERFACE ${FEX_PROJECT_SOURCE_DIR}/External/Vulkan-Headers/include/)
  add_guest_lib(vulkan "libvulkan.so.1")
endif()

if (BITNESS EQUAL 64)
  #add_guest_lib(fex_malloc_loader)
  #target_link_libraries(fex_malloc_loader-guest PRIVATE dl)

  #generate(libfex_malloc)
  #add_guest_lib(fex_malloc)

  generate(libasound ${CMAKE_CURRENT_SOURCE_DIR}/../libasound/libasound_interface.cpp)
  add_guest_lib(asound "libasound.so.2")

  # disabled for now, headers are platform specific
  # find_package(SDL2 REQUIRED)
  # generate(libSDL2)
  # add_guest_lib(SDL2)
  # target_include_directories(SDL2-guest PRIVATE ${SDL2_INCLUDE_DIRS})
  # target_link_libraries(SDL2-guest PRIVATE GL)
  # target_link_libraries(SDL2-guest PRIVATE dl)

  # libdrm stays 64-bit-guest only until its 32-bit host-side repacking and
  # guest-heap relocation land. See ThunkLibs/HostLibs/CMakeLists.txt.
  generate(libdrm ${CMAKE_CURRENT_SOURCE_DIR}/../libdrm/libdrm_interface.cpp)
  target_include_directories(libdrm-guest-deps INTERFACE /usr/include/drm/)
  target_include_directories(libdrm-guest-deps INTERFACE /usr/include/libdrm/)
  add_guest_lib(drm "libdrm.so.2")
endif()

# libxshmfence: 32-bit support added 2026-08-07 for the guest Mesa/DRI3 stack
# used by 32-bit Unity titles.
if (BITNESS EQUAL 32 OR BITNESS EQUAL 64)
  generate(libxshmfence ${CMAKE_CURRENT_SOURCE_DIR}/../libxshmfence/libxshmfence_interface.cpp)
  add_guest_lib(xshmfence "libxshmfence.so.1")
endif()

generate(libwayland-client ${CMAKE_CURRENT_SOURCE_DIR}/../libwayland-client/libwayland-client_interface.cpp)
add_guest_lib(wayland-client "libwayland-client.so.0.20.0")
target_include_directories(libwayland-client-guest-deps INTERFACE /usr/include/wayland)

generate(libVDSO ${CMAKE_CURRENT_SOURCE_DIR}/../libVDSO/libVDSO_interface.cpp)
add_guest_lib(VDSO "linux-vdso.so.1")
# Can't use a stack protector because otherwise cross-compiling fails
# Not necessary anyway because it only trampolines
target_compile_options(VDSO-guest PRIVATE "-fno-stack-protector")
target_link_options(VDSO-guest PRIVATE "-nostdlib" "LINKER:--no-undefined" "LINKER:-z,max-page-size=4096" "LINKER:--hash-style=both")

if (BITNESS EQUAL 32)
  # 32-bit entrypoint points to __kernel_vsyscall and needs to exist
  target_link_options(VDSO-guest PRIVATE "LINKER:-e,__kernel_vsyscall")
  # 32-bit VDSO needs to have PIC disabled.
  # Otherwise GCC/Clang generates GOT prologues on the functions that corrupt vsyscall.
  # Correct:
  # 00000350 <__kernel_vsyscall>:
  #  350:   cd 80                   int    0x80
  #  352:   c3                      ret
  #  353:   0f 0b                   ud2
  # Incorrect:
  # 0000032a <__kernel_vsyscall>:
  #  32a:   e8 0b 00 00 00          call   33a <__x86.get_pc_thunk.ax>
  #  32f:   05 79 03 00 00          add    eax,0x379
  #  334:   cd 80                   int    0x80
  #  336:   c3                      ret
  #  337:   90                      nop
  #  338:   0f 0b                   ud2
  target_compile_options(VDSO-guest PRIVATE "-fno-pic")
endif()

if (BUILD_FEX_LINUX_TESTS)
  generate(libfex_thunk_test ${CMAKE_CURRENT_SOURCE_DIR}/../libfex_thunk_test/libfex_thunk_test_interface.cpp)
  add_guest_lib(fex_thunk_test "libfex_thunk_test.so")
endif()

generate(libGL ${CMAKE_CURRENT_SOURCE_DIR}/../libGL/libGL_interface.cpp)
add_guest_lib(GL "libGL.so.1")

generate(libEGL ${CMAKE_CURRENT_SOURCE_DIR}/../libEGL/libEGL_interface.cpp)
add_guest_lib(EGL "libEGL.so.1")
target_link_libraries(EGL-guest PRIVATE GL-guest)

# libGL must pull in libX11.so, so generate a placeholder libX11.so to link against
add_library(PlaceholderX11 SHARED ../libX11/libX11_NativeGuest.cpp)
target_link_options(PlaceholderX11 PRIVATE "LINKER:-soname,libX11.so.6")
set_target_properties(PlaceholderX11 PROPERTIES NO_SONAME ON)
target_link_libraries(GL-guest PRIVATE PlaceholderX11)
