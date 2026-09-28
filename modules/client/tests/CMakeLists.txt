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
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/ci/check_http_stream_upload.py
            $<TARGET_FILE:mira_client_upload_peer>)
    set_tests_properties(client_stream_upload_interop PROPERTIES TIMEOUT 90)
    if(MIRA_ENABLE_TLS)
        find_program(MIRA_CLIENT_OPENSSL_EXECUTABLE openssl HINTS "${OPENSSL_ROOT_DIR}/bin")
        if(MIRA_CLIENT_OPENSSL_EXECUTABLE)
            add_test(NAME client_https_upload_interop
                COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/ci/check_http_stream_upload.py
                    $<TARGET_FILE:mira_client_upload_peer> --tls
                    --openssl ${MIRA_CLIENT_OPENSSL_EXECUTABLE})
            set_tests_properties(client_https_upload_interop PROPERTIES TIMEOUT 90)
        endif()
    endif()
endif()
