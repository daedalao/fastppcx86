# Frontend-free FEXCore embedding probe.
# NOTE the link list: FEXCore + Common + CommonTools, and deliberately NOT
# LinuxEmulation. If this ever needs LinuxEmulation to link, the CPU-DLL shape
# is not actually frontend-free and that is a finding.
list(APPEND LIBS FEXCore Common CommonTools JemallocLibs ${PTHREAD_LIB})

add_executable(Wow64Probe Wow64Probe.cpp)

target_include_directories(Wow64Probe PRIVATE ${CMAKE_BINARY_DIR}/generated)
target_include_directories(Wow64Probe PRIVATE ${CMAKE_SOURCE_DIR}/Source/)

target_link_libraries(Wow64Probe PRIVATE ${LIBS})
