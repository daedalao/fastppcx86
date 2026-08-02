cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME FEXCore)
project(${PROJECT_NAME}
  VERSION 0.01
  LANGUAGES CXX)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  set(ARCHITECTURE_x86_64 1)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcx16")
endif()

if (CMAKE_SYSTEM_PROCESSOR MATCHES "^aarch64|^arm64|^armv8\.*")
  set(ARCHITECTURE_arm64 1)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
cmake_policy(SET CMP0083 NEW) # Follow new PIE policy
include(CheckPIESupported)
check_pie_supported()

set(CMAKE_INCLUDE_CURRENT_DIR ON)

include(CheckCXXCompilerFlag)
include(CheckIncludeFileCXX)
include(CheckCXXSourceCompiles)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# git_version.h is written once at configure time by the top-level CMakeLists
# (via Scripts/GenerateGitVersion.cmake), so it is guaranteed to exist before
# anything compiles. This target re-runs the same script on *every* build.
#
# Why: Interface/Core/CodeCache.cpp gates code cache loads on GIT_HASH and on
# nothing else that tracks the build -- the header check is Magic /
# FormatVersion / FEXVersion / non-zero block count, with no mtime, path or
# size. Configure-time-only detection means that after an incremental `ninja`
# following a JIT source edit, the freshly built binary happily loads caches
# emitted by the previous build. An A/B measurement across a codegen change
# then compares old code against old code and reads as "no regression".
# (EnableCodeCachingWIP defaults false, so this is a benchmarking gate rather
# than a live correctness bug.)
#
# The script ends in configure_file(), which does not rewrite the output when
# the rendered content is unchanged. Combined with Ninja's `restat` handling of
# custom-command byproducts, a no-op build leaves git_version.h's mtime alone
# and does not cascade a rebuild. When the hash *does* change, the nine
# translation units that include the header rebuild, plus the relink.
add_custom_target(git_version_header ALL
  COMMAND ${CMAKE_COMMAND}
    "-DGIT_EXECUTABLE=${GIT_EXECUTABLE}"
    "-DFEX_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "-DGIT_VERSION_INPUT=${CMAKE_CURRENT_SOURCE_DIR}/include/git_version.h.in"
    "-DGIT_VERSION_OUTPUT=${CMAKE_BINARY_DIR}/generated/git_version.h"
    "-DOVERRIDE_VERSION=${OVERRIDE_VERSION}"
    "-DOVERRIDE_HASH=${OVERRIDE_HASH}"
    -P "${CMAKE_SOURCE_DIR}/Scripts/GenerateGitVersion.cmake"
  BYPRODUCTS ${CMAKE_BINARY_DIR}/generated/git_version.h
  SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/git_version.h.in
    ${CMAKE_SOURCE_DIR}/Scripts/GenerateGitVersion.cmake
  COMMENT "Refreshing FEX build identity (git_version.h)"
  VERBATIM)

include_directories(${CMAKE_BINARY_DIR}/generated)

# Disable strict aliasing for all build modes
# See discussion in https://github.com/FEX-Emu/FEX/pull/4494#issuecomment-2800608944
# for background context.
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing> $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>)

add_subdirectory(Source/)

if (NOT BUILD_STEAM_SUPPORT)
  install (DIRECTORY include/FEXCore ${CMAKE_BINARY_DIR}/include/FEXCore
    DESTINATION include
    COMPONENT Development)
endif()

if (BUILD_TESTING)
  add_subdirectory(unittests/)
endif()
