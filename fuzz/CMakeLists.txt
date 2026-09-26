# Mira/fuzz — protocol fuzzing, opt-in
#
# A parser's value is its negative space, and fuzzing explores that space
# faster than hand-written negative tests. The harnesses here are libFuzzer
# entry points over the library's public parsing surface; they assert the
# parser's own invariants and let ASan/UBSan catch everything else.
#
# Gated behind MIRA_BUILD_FUZZERS (and so is the fuzzer instrumentation):
# a consumer pulling Mira in via add_subdirectory() did not ask for our
# fuzzing binaries, and -fsanitize=fuzzer belongs to the fuzz build alone.

if(NOT MIRA_BUILD_FUZZERS)
    return()
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "MIRA_BUILD_FUZZERS requires clang (libFuzzer ships with it)")
endif()

add_executable(fuzz_http_parser http_parser.cpp)
target_link_libraries(fuzz_http_parser
    PRIVATE Mira::http Mira::warnings)
target_compile_features(fuzz_http_parser PRIVATE cxx_std_23)
target_compile_options(fuzz_http_parser PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_http_parser PRIVATE -fsanitize=fuzzer)

add_executable(fuzz_response_parser response_parser.cpp)
target_link_libraries(fuzz_response_parser
    PRIVATE Mira::http Mira::warnings)
target_compile_features(fuzz_response_parser PRIVATE cxx_std_23)
target_compile_options(fuzz_response_parser PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_response_parser PRIVATE -fsanitize=fuzzer)
