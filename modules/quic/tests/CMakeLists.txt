if(NOT OPENSSL_ROOT_DIR AND DEFINED ENV{OPENSSL_ROOT_DIR})
    set(OPENSSL_ROOT_DIR "$ENV{OPENSSL_ROOT_DIR}")
endif()
if(OPENSSL_ROOT_DIR)
    find_program(MIRA_QUIC_OPENSSL_TOOL NAMES openssl
        PATHS "${OPENSSL_ROOT_DIR}/tools/openssl" "${OPENSSL_ROOT_DIR}/bin"
        NO_DEFAULT_PATH)
endif()
if(NOT MIRA_QUIC_OPENSSL_TOOL)
    find_program(MIRA_QUIC_OPENSSL_TOOL NAMES openssl
        PATHS ENV PATH NO_DEFAULT_PATH REQUIRED)
endif()
set(MIRA_QUIC_TEST_CERT "${CMAKE_CURRENT_BINARY_DIR}/cert.pem" CACHE INTERNAL "QUIC test certificate")
set(MIRA_QUIC_TEST_KEY "${CMAKE_CURRENT_BINARY_DIR}/key.pem" CACHE INTERNAL "QUIC test private key")
# vcpkg's executable need not have a system openssl.cnf at its compiled-in
# location. Keep certificate generation independent of that host setting.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/openssl.cnf" "[req]\ndistinguished_name=dn\n[dn]\n")
execute_process(COMMAND "${MIRA_QUIC_OPENSSL_TOOL}" req -x509 -newkey rsa:2048 -nodes
    -config "${CMAKE_CURRENT_BINARY_DIR}/openssl.cnf"
    -keyout "${MIRA_QUIC_TEST_KEY}" -out "${MIRA_QUIC_TEST_CERT}" -days 2
    -subj /CN=localhost -addext subjectAltName=DNS:localhost
    RESULT_VARIABLE cert_result OUTPUT_QUIET ERROR_QUIET)
if(NOT cert_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate the local QUIC test certificate")
endif()
set(MIRA_QUIC_OTHER_CERT "${CMAKE_CURRENT_BINARY_DIR}/other-ca.pem")
execute_process(COMMAND "${MIRA_QUIC_OPENSSL_TOOL}" req -x509 -newkey rsa:2048 -nodes
    -config "${CMAKE_CURRENT_BINARY_DIR}/openssl.cnf"
    -keyout "${CMAKE_CURRENT_BINARY_DIR}/other-ca-key.pem" -out "${MIRA_QUIC_OTHER_CERT}" -days 2
    -subj /CN=unrelated-ca -addext basicConstraints=critical,CA:TRUE
    RESULT_VARIABLE other_cert_result OUTPUT_QUIET ERROR_QUIET)
if(NOT other_cert_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate the unrelated QUIC test CA")
endif()
add_executable(test_quic_retry test_retry.cpp)
target_link_libraries(test_quic_retry PRIVATE Mira::quic mira_ngtcp2_ossl Mira::warnings)
add_test(NAME quic_retry COMMAND test_quic_retry "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}")
set_tests_properties(quic_retry PROPERTIES TIMEOUT 60)
add_executable(test_quic_listener test_listener.cpp)
target_link_libraries(test_quic_listener PRIVATE Mira::quic Mira::warnings)
add_test(NAME quic_listener COMMAND test_quic_listener "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}")
set_tests_properties(quic_listener PROPERTIES TIMEOUT 30)
add_executable(test_quic_engine test_engine.cpp)
# The native error-code assertions include ngtcp2 directly; inherit its
# Windows static-library definition through the adapter. This also keeps the
# adapter before ngtcp2 in static link order without repeating ngtcp2.
target_link_libraries(test_quic_engine PRIVATE Mira::quic mira_ngtcp2_ossl)
foreach(mode normal chaos bad-host untrusted bad-alpn stream-limit)
    add_test(NAME quic_${mode} COMMAND test_quic_engine "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}" ${mode})
    set_tests_properties(quic_${mode} PROPERTIES TIMEOUT 30)
endforeach()

set(MIRA_QUIC_REJECTED_CERT "${CMAKE_CURRENT_BINARY_DIR}/rejected-ca.pem")
execute_process(COMMAND "${MIRA_QUIC_OPENSSL_TOOL}" x509 -in "${MIRA_QUIC_TEST_CERT}"
    -addreject serverAuth -trustout -out "${MIRA_QUIC_REJECTED_CERT}"
    RESULT_VARIABLE rejected_cert_result OUTPUT_QUIET ERROR_VARIABLE rejected_cert_error)
if(NOT rejected_cert_result EQUAL 0)
    message(FATAL_ERROR "Failed to generate the rejected-purpose QUIC test CA (${rejected_cert_result}): ${rejected_cert_error}")
endif()
add_test(NAME quic_ca-aux COMMAND test_quic_engine
    "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}" ca-aux "${MIRA_QUIC_REJECTED_CERT}")
set_tests_properties(quic_ca-aux PROPERTIES TIMEOUT 30)
foreach(mode ca-rotation ca-rotation-early system-cache)
    add_test(NAME quic_${mode} COMMAND test_quic_engine
        "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}" ${mode} "${MIRA_QUIC_OTHER_CERT}")
    set_tests_properties(quic_${mode} PROPERTIES TIMEOUT 30)
endforeach()
set_tests_properties(quic_system-cache PROPERTIES
    ENVIRONMENT "SSL_CERT_FILE=${MIRA_QUIC_TEST_CERT};SSL_CERT_DIR=${CMAKE_CURRENT_BINARY_DIR}/empty-ca-dir")

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
