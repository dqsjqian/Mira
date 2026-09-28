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
target_compile_definitions(mira_tls_https_tests PRIVATE
    MIRA_TLS_TEST_BINARY_DIR="${CMAKE_CURRENT_BINARY_DIR}"
)
add_test(NAME tls_https COMMAND mira_tls_https_tests)
set_tests_properties(tls_https PROPERTIES TIMEOUT 60)

foreach(mode IN ITEMS destroy-active move-active replace-active)
    add_test(NAME tls.contract.${mode}
        COMMAND ${CMAKE_COMMAND}
            -DPROGRAM=$<TARGET_FILE:mira_tls_https_tests>
            -DMODE=--${mode}
            -P ${PROJECT_SOURCE_DIR}/modules/core/tests/check_terminates.cmake)
    set_tests_properties(tls.contract.${mode} PROPERTIES TIMEOUT 15)
endforeach()
