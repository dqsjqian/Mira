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

# Instrument the actual parsers, not only the harness. Ordinary test binaries
# retain their own entry points; installed consumers do not inherit these flags.
set(mira_fuzz_libraries mira_core mira_http mira_socks)
if(MIRA_ENABLE_WEBSOCKET)
    list(APPEND mira_fuzz_libraries mira_ws)
endif()
foreach(parser_target IN LISTS mira_fuzz_libraries)
    target_compile_options(${parser_target} PRIVATE -fsanitize=fuzzer-no-link)
    target_link_options(${parser_target} PUBLIC
        $<BUILD_INTERFACE:-fsanitize=fuzzer-no-link>)
endforeach()

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

foreach(harness IN ITEMS socks_handshake)
    add_executable(fuzz_${harness} ${harness}.cpp)
    target_link_libraries(fuzz_${harness} PRIVATE Mira::socks Mira::warnings)
    target_compile_features(fuzz_${harness} PRIVATE cxx_std_23)
    target_compile_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
endforeach()

if(MIRA_ENABLE_WEBSOCKET)
    foreach(harness IN ITEMS ws_parser ws_handshake ws_compression)
        add_executable(fuzz_${harness} ${harness}.cpp)
        target_link_libraries(fuzz_${harness} PRIVATE Mira::ws Mira::warnings)
        target_compile_features(fuzz_${harness} PRIVATE cxx_std_23)
        target_compile_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
        target_link_options(fuzz_${harness} PRIVATE -fsanitize=fuzzer)
    endforeach()
endif()
