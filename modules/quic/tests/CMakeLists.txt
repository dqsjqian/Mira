# Prefer a fully working openssl over a broken system one. On hosts where a
# Homebrew toolchain shadows system libraries, /bin/openssl can fail to even
# start (libssl version mismatch). find_program's prefix search can land on
# that broken binary before the toolchain's own, so the explicit paths come
# first. Note OPENSSL_ROOT_DIR may be empty on this host: a naive
# "${OPENSSL_ROOT_DIR}/bin" would collapse to "/bin" and re-select the broken
# binary, hence the guarded list assembly.
set(MIRA_QUIC_OPENSSL_HINTS "")
if(OPENSSL_ROOT_DIR)
    list(APPEND MIRA_QUIC_OPENSSL_HINTS "${OPENSSL_ROOT_DIR}/bin")
endif()
list(APPEND MIRA_QUIC_OPENSSL_HINTS
    /home/linuxbrew/.linuxbrew/bin
    /opt/homebrew/bin
)
find_program(MIRA_QUIC_OPENSSL_TOOL
    NAMES openssl
    HINTS ${MIRA_QUIC_OPENSSL_HINTS}
    PATHS /home/linuxbrew/.linuxbrew/bin /opt/homebrew/bin
    NO_DEFAULT_PATH
)
if(NOT MIRA_QUIC_OPENSSL_TOOL)
    find_program(MIRA_QUIC_OPENSSL_TOOL NAMES openssl REQUIRED)
endif()
set(MIRA_QUIC_TEST_CERT "${CMAKE_CURRENT_BINARY_DIR}/cert.pem" CACHE INTERNAL "QUIC test certificate")
set(MIRA_QUIC_TEST_KEY "${CMAKE_CURRENT_BINARY_DIR}/key.pem" CACHE INTERNAL "QUIC test private key")
execute_process(COMMAND "${MIRA_QUIC_OPENSSL_TOOL}" req -x509 -newkey rsa:2048 -nodes
    -keyout "${MIRA_QUIC_TEST_KEY}" -out "${MIRA_QUIC_TEST_CERT}" -days 2
    -subj /CN=localhost -addext subjectAltName=DNS:localhost
    RESULT_VARIABLE cert_result OUTPUT_QUIET ERROR_QUIET)
if(NOT cert_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate the local QUIC test certificate")
endif()
add_executable(test_quic_listener test_listener.cpp)
target_link_libraries(test_quic_listener PRIVATE Mira::quic Mira::warnings)
add_test(NAME quic_listener COMMAND test_quic_listener "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}")
set_tests_properties(quic_listener PROPERTIES TIMEOUT 30)
add_executable(test_quic_engine test_engine.cpp)
target_link_libraries(test_quic_engine PRIVATE Mira::quic)
# Asserting ngtcp2's native error codes requires its public headers; the quic
# engine keeps the dependency PRIVATE, so the tests carry their own include
# path rather than leaking it to the library's consumers.
target_include_directories(test_quic_engine PRIVATE "${MIRA_NGTCP2_INCLUDE_DIR}")
foreach(mode normal chaos bad-host untrusted bad-alpn stream-limit)
    add_test(NAME quic_${mode} COMMAND test_quic_engine "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}" ${mode})
    set_tests_properties(quic_${mode} PROPERTIES TIMEOUT 30)
endforeach()

# The engine's in-memory datagram tests prove the protocol state machine;
# this one proves the whole stack over the kernel's UDP.
# GCC 13 hits an internal compiler error (build_special_member_call) on the
# move-only connection coroutine tests; GCC 14+ and Clang compile cleanly.
# Skip on GCC 13 until the runner image moves on — the closing-exchange
# tests report expected failures there.
if(NOT (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 14))
    add_executable(test_quic_udp test_udp_transport.cpp)
    target_link_libraries(test_quic_udp PRIVATE Mira::quic Mira::warnings)
    target_include_directories(test_quic_udp PRIVATE "${CMAKE_SOURCE_DIR}/modules/core/tests")
    add_test(NAME quic_udp COMMAND test_quic_udp "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}")
    set_tests_properties(quic_udp PROPERTIES TIMEOUT 60)
endif()
