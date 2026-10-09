if(TARGET mira_client_http2 OR TARGET mira_client_http3)
    find_program(MIRA_MULTIPLEX_OPENSSL openssl HINTS "${OPENSSL_ROOT_DIR}/bin" REQUIRED)
    set(MIRA_MULTIPLEX_CERT "${CMAKE_CURRENT_BINARY_DIR}/multiplex-cert.pem")
    set(MIRA_MULTIPLEX_KEY "${CMAKE_CURRENT_BINARY_DIR}/multiplex-key.pem")
    set(MIRA_MULTIPLEX_OTHER "${CMAKE_CURRENT_BINARY_DIR}/multiplex-other.pem")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/multiplex-openssl.cnf" "[req]\ndistinguished_name=dn\n[dn]\n")
    foreach(identity multiplex multiplex-other)
        if(identity STREQUAL "multiplex")
            set(cert "${MIRA_MULTIPLEX_CERT}")
            set(key "${MIRA_MULTIPLEX_KEY}")
        else()
            set(cert "${MIRA_MULTIPLEX_OTHER}")
            set(key "${CMAKE_CURRENT_BINARY_DIR}/multiplex-other-key.pem")
        endif()
        execute_process(COMMAND "${MIRA_MULTIPLEX_OPENSSL}" req -x509 -newkey rsa:2048 -nodes
            -config "${CMAKE_CURRENT_BINARY_DIR}/multiplex-openssl.cnf"
            -keyout "${key}" -out "${cert}" -days 2 -subj /CN=localhost
            -addext subjectAltName=DNS:localhost
            RESULT_VARIABLE generated OUTPUT_QUIET ERROR_QUIET)
        if(NOT generated EQUAL 0)
            message(FATAL_ERROR "Failed to generate multiplex client test certificates")
        endif()
    endforeach()
    foreach(protocol http2 http3)
        if(TARGET mira_client_${protocol})
            add_executable(mira_client_${protocol}_tests test_multiplex.cpp)
            target_link_libraries(mira_client_${protocol}_tests PRIVATE Mira::client_${protocol} Mira::warnings)
            if(protocol STREQUAL "http2")
                target_compile_definitions(mira_client_${protocol}_tests PRIVATE MIRA_TEST_H2=1)
            endif()
            add_test(NAME client_${protocol}_pool COMMAND mira_client_${protocol}_tests
                "${MIRA_MULTIPLEX_CERT}" "${MIRA_MULTIPLEX_KEY}" "${MIRA_MULTIPLEX_OTHER}")
            set_tests_properties(client_${protocol}_pool PROPERTIES TIMEOUT 45)
            add_test(NAME client_${protocol}_abandon COMMAND mira_client_${protocol}_tests
                "${MIRA_MULTIPLEX_CERT}" "${MIRA_MULTIPLEX_KEY}" "${MIRA_MULTIPLEX_OTHER}" --death)
            set_tests_properties(client_${protocol}_abandon PROPERTIES WILL_FAIL TRUE TIMEOUT 10
                FAIL_REGULAR_EXPRESSION "AddressSanitizer;runtime error:")
        endif()
    endforeach()
endif()

add_executable(mira_http_upload_tests ../../http/tests/test_client_upload.cpp)
target_link_libraries(mira_http_upload_tests PRIVATE Mira::http Mira::warnings)
target_include_directories(mira_http_upload_tests PRIVATE ${PROJECT_SOURCE_DIR}/modules/core/tests)
add_test(NAME http_client_upload COMMAND mira_http_upload_tests)
set_tests_properties(http_client_upload PROPERTIES TIMEOUT 30)

add_executable(mira_client_pool_tests test_pool.cpp)
target_link_libraries(mira_client_pool_tests PRIVATE Mira::client Mira::warnings)
target_include_directories(mira_client_pool_tests PRIVATE ${PROJECT_SOURCE_DIR}/modules/core/tests)
add_test(NAME client_pool COMMAND mira_client_pool_tests)
set_tests_properties(client_pool PROPERTIES TIMEOUT 60)

add_executable(mira_client_upload_peer upload_peer.cpp)
target_link_libraries(mira_client_upload_peer PRIVATE Mira::client Mira::warnings)
if(MIRA_ENABLE_TLS)
    target_link_libraries(mira_client_upload_peer PRIVATE Mira::client_tls)
    target_compile_definitions(mira_client_upload_peer PRIVATE MIRA_CLIENT_TEST_TLS=1)
endif()
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME client_stream_upload_interop
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/ci/check_http_stream_upload.py
            $<TARGET_FILE:mira_client_upload_peer>)
    set_tests_properties(client_stream_upload_interop PROPERTIES TIMEOUT 90)
    if(MIRA_ENABLE_TLS)
        find_program(MIRA_CLIENT_OPENSSL_EXECUTABLE openssl HINTS "${OPENSSL_ROOT_DIR}/bin")
        if(MIRA_CLIENT_OPENSSL_EXECUTABLE)
            add_test(NAME client_https_upload_interop
                COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/ci/check_http_stream_upload.py
                    $<TARGET_FILE:mira_client_upload_peer> --tls
                    --openssl ${MIRA_CLIENT_OPENSSL_EXECUTABLE})
            set_tests_properties(client_https_upload_interop PROPERTIES TIMEOUT 90)
        endif()
    endif()
endif()
