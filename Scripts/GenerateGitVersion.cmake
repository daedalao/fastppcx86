# SPDX-License-Identifier: MIT
#
# Computes the FEX build identity (git describe string + 20-byte git hash) and
# writes FEXCore/include/git_version.h.in out to the build tree.
#
# This file is used two ways, and the two uses MUST produce byte-identical
# output or every build will look like the header changed:
#
#   1. include()d from the top-level CMakeLists.txt at configure time. This
#      guarantees the generated header exists before anything compiles, and
#      leaves GIT_DESCRIBE_STRING / GIT_HASH set in the caller's scope for
#      Source/Steam/VERSIONS.txt.in and the status messages.
#
#   2. Run via `cmake -P` from the `git_version_header` custom target
#      (FEXCore/CMakeLists.txt) on every build. Configure-time-only detection
#      is not enough: FEXCore/Source/Interface/Core/CodeCache.cpp gates code
#      cache loads on GIT_HASH and on nothing else that tracks the build (the
#      header check is Magic / FormatVersion / FEXVersion / non-zero block
#      count -- no mtime, no path, no size). So after an incremental `ninja`
#      following a JIT source edit, a binary built from new sources would load
#      caches emitted by the previous build, and an A/B measurement across a
#      codegen change silently compares old code against old code.
#
# configure_file() only rewrites its output when the rendered content differs,
# so a no-op build leaves git_version.h's mtime alone and does not cascade a
# rebuild of the nine translation units that include it.
#
# Variables (all optional; -D them in script mode):
#   GIT_EXECUTABLE       - path to git. Found here if not already set.
#   FEX_SOURCE_DIR       - top-level FEX source dir. Defaults to CMAKE_SOURCE_DIR.
#   GIT_VERSION_INPUT    - path to git_version.h.in
#   GIT_VERSION_OUTPUT   - path to the generated git_version.h
#   OVERRIDE_VERSION     - "detect", or a literal version string
#   OVERRIDE_HASH        - "detect", or a literal hash string
#
# Sets (in the caller's scope when include()d):
#   GIT_DESCRIBE_STRING, GIT_HASH, GIT_HASH_ARRAY, GIT_VERSION_DIRTY

if (CMAKE_SCRIPT_MODE_FILE)
  cmake_minimum_required(VERSION 3.14)
endif()

if (NOT DEFINED OVERRIDE_VERSION)
  set(OVERRIDE_VERSION "detect")
endif()
if (NOT DEFINED OVERRIDE_HASH)
  set(OVERRIDE_HASH "detect")
endif()
if (NOT FEX_SOURCE_DIR)
  set(FEX_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
endif()
if (NOT GIT_VERSION_INPUT)
  set(GIT_VERSION_INPUT "${FEX_SOURCE_DIR}/FEXCore/include/git_version.h.in")
endif()
if (NOT GIT_VERSION_OUTPUT)
  set(GIT_VERSION_OUTPUT "${CMAKE_BINARY_DIR}/generated/git_version.h")
endif()

# In script mode the caller passes -DGIT_EXECUTABLE so we don't re-search on
# every build; when include()d the top-level has already run find_package(Git).
if (NOT GIT_EXECUTABLE)
  # Clear a -DGIT_EXECUTABLE=GIT_EXECUTABLE-NOTFOUND passed through from a
  # configure where git was missing, so it can't shadow the cache entry
  # find_package() is about to write.
  unset(GIT_EXECUTABLE)
  unset(GIT_EXECUTABLE CACHE)
  find_package(Git QUIET)
endif()

set(GIT_DESCRIBE_STRING "FEX-Unknown")
set(GIT_HASH "Unknown")
set(GIT_VERSION_DIRTY FALSE)

if (OVERRIDE_VERSION STREQUAL "detect")
  if (GIT_EXECUTABLE)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" describe --abbrev=7
      WORKING_DIRECTORY "${FEX_SOURCE_DIR}"
      OUTPUT_VARIABLE GIT_DESCRIBE_STRING
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
else()
  set(GIT_DESCRIBE_STRING "${OVERRIDE_VERSION}")
endif()

if (OVERRIDE_HASH STREQUAL "detect")
  if (GIT_EXECUTABLE)
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
      WORKING_DIRECTORY "${FEX_SOURCE_DIR}"
      OUTPUT_VARIABLE GIT_HASH
      ERROR_QUIET
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    # Cache invalidation guard for uncommitted source changes: when the working
    # tree is dirty, derive a fresh hash by SHA1-mixing HEAD with the diff.
    #
    # ':!External' excludes the 16 git submodules under External/ (~554 MB),
    # which are essentially the entire cost of the diff and cannot change
    # without also changing the gitlink recorded in HEAD's tree -- which the
    # diff of the top-level tree does still see. Measured on an aarch64 host:
    # whole-tree `git diff HEAD --binary` was 76.6 s cold / ~2.1 s warm, the
    # same diff with ':!External' is ~0.7 s. Magic pathspecs need git >= 1.9.
    #
    # Everything else in the tree is still covered, deliberately: Source/ holds
    # volatile-metadata handling and Mono detection that affect codegen, and
    # Config.json.in's defaults compile into ConfigValues.inl. Narrowing this
    # to just FEXCore/ + CodeEmitter/ has been proposed and rejected.
    #
    # Not covered (same as before this was made build-time): untracked files,
    # since `git diff HEAD` does not see them, and submodule *working tree*
    # edits that have not been committed inside the submodule.
    execute_process(
      COMMAND "${GIT_EXECUTABLE}" diff HEAD --binary -- ":!External"
      WORKING_DIRECTORY "${FEX_SOURCE_DIR}"
      OUTPUT_VARIABLE GIT_DIRTY_DIFF
      ERROR_QUIET)
    if (NOT GIT_DIRTY_DIFF STREQUAL "")
      string(SHA1 GIT_HASH "${GIT_HASH}${GIT_DIRTY_DIFF}")
      set(GIT_VERSION_DIRTY TRUE)
    endif()
  endif()
else()
  set(GIT_HASH "${OVERRIDE_HASH}")
endif()

# Prepends 0x to every two-character sequence in the hash,
# OR the final character of the hash, to plumb it for C++ usage. e.g.:
# -DOVERRIDE_HASH=123456aa => 0x12, 0x34, 0x56, 0xaa,
# -DOVERRIDE_HASH=12345678a => 0x12, 0x34, 0x56, 0x78, 0xa,
string(REGEX
  REPLACE "(..|.$)" "0x\\1, "
  GIT_HASH_ARRAY "${GIT_HASH}")

get_filename_component(GIT_VERSION_OUTPUT_DIR "${GIT_VERSION_OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${GIT_VERSION_OUTPUT_DIR}")

# No-op when the rendered content is unchanged, which is what keeps a no-op
# build from cascading into a rebuild of the git_version.h consumers.
configure_file("${GIT_VERSION_INPUT}" "${GIT_VERSION_OUTPUT}")
