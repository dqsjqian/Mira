add_executable(mira_tls_https_tests test_https.cpp)
target_link_libraries(mira_tls_https_tests PRIVATE
    Mira::tls
    Mira::http
    Mira::transport
    Mira::warnings
    OpenSSL::Crypto
)
target_include_directories(mira_tls_https_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/modules/core/tests
)
add_test(NAME tls_https COMMAND mira_tls_https_tests)
set_tests_properties(tls_https PROPERTIES TIMEOUT 60)

add_executable(mira_tcp_tls_early_peer ${PROJECT_SOURCE_DIR}/scripts/ci/tcp_tls_early_peer.cpp)
target_link_libraries(mira_tcp_tls_early_peer PRIVATE Mira::tls Mira::transport Mira::warnings)
find_package(Python3 QUIET COMPONENTS Interpreter)
find_program(MIRA_TLS_OPENSSL_PROGRAM openssl HINTS "${OPENSSL_ROOT_DIR}/bin")
if(Python3_Interpreter_FOUND AND MIRA_TLS_OPENSSL_PROGRAM)
    execute_process(COMMAND "${MIRA_TLS_OPENSSL_PROGRAM}" version
        OUTPUT_VARIABLE MIRA_TLS_OPENSSL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(MIRA_TLS_OPENSSL_VERSION MATCHES "^OpenSSL [34]\\.")
        add_test(NAME tls.early_data.openssl COMMAND ${Python3_EXECUTABLE}
            ${PROJECT_SOURCE_DIR}/scripts/ci/check_tcp_tls_early.py
            --peer $<TARGET_FILE:mira_tcp_tls_early_peer> --openssl ${MIRA_TLS_OPENSSL_PROGRAM})
        set_tests_properties(tls.early_data.openssl PROPERTIES TIMEOUT 60)
    endif()
endif()

foreach(mode IN ITEMS destroy-active move-active replace-active)
    add_test(NAME tls.contract.${mode}
        COMMAND ${CMAKE_COMMAND}
            -DPROGRAM=$<TARGET_FILE:mira_tls_https_tests>
            -DMODE=--${mode}
            -P ${PROJECT_SOURCE_DIR}/modules/core/tests/check_terminates.cmake)
    set_tests_properties(tls.contract.${mode} PROPERTIES TIMEOUT 15)
endforeach()
