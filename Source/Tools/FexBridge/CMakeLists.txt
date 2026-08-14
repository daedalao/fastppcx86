# fexbridge: C-ABI shared library around frontend-free FEXCore, for a native
# ppc64le embedder (Wine). Same link list as Wow64Probe — FEXCore + Common +
# CommonTools, deliberately NOT LinuxEmulation — absorbed statically into one
# .so with only fexbridge_* exported (fexbridge.map).
#
# NOTE: building this target needs a tree configured with
#   -DCMAKE_POSITION_INDEPENDENT_CODE=ON
# (the static FEXCore objects must be PIC to enter a shared library).
list(APPEND LIBS FEXCore Common CommonTools JemallocLibs ${PTHREAD_LIB})

add_library(fexbridge SHARED FexBridge.cpp)
target_include_directories(fexbridge PRIVATE ${CMAKE_BINARY_DIR}/generated)
target_include_directories(fexbridge PRIVATE ${CMAKE_SOURCE_DIR}/Source/)
target_link_libraries(fexbridge PRIVATE ${LIBS})
target_link_options(fexbridge PRIVATE "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/fexbridge.map")
set_target_properties(fexbridge PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/fexbridge.map)

# The embedder-eye-view test: pure C, no C++ runtime, no FEXCore headers, not
# linked against fexbridge — dlopens it and drives the dlsym'd surface. This
# is the "an embedder can use this" proof, distinct from the probe.
add_executable(BridgeSmoke BridgeSmoke.c)
target_include_directories(BridgeSmoke PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(BridgeSmoke PRIVATE dl ${PTHREAD_LIB})
