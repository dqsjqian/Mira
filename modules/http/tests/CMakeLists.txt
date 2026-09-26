add_executable(mira_http_tests test_parser.cpp)
add_executable(mira_http_server_tests test_server.cpp)
add_executable(mira_http_response_tests test_response_parser.cpp)
add_executable(mira_http_client_tests test_client.cpp)
target_link_libraries(mira_http_client_tests PRIVATE Mira::transport)

# The only binary that links both http and transport. The *library* keeps its
# boundary (Mira::http depends on core alone); a test that runs the whole
# stack over a real socket is exactly where the layers should be checked
# against each other.
add_executable(mira_http_e2e_tests test_end_to_end.cpp)
target_link_libraries(mira_http_e2e_tests PRIVATE Mira::transport)

add_executable(mira_http_streaming_tests test_streaming.cpp)
foreach(target mira_http_tests mira_http_server_tests mira_http_e2e_tests
               mira_http_response_tests mira_http_client_tests
               mira_http_streaming_tests)
    target_link_libraries(${target} PRIVATE
        Mira::http
        Mira::warnings
    )
    # Reuse the core test harness rather than duplicating it.
    target_include_directories(${target} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/modules/core/tests
    )
endforeach()

add_test(NAME http_parser COMMAND mira_http_tests)
add_test(NAME http_server COMMAND mira_http_server_tests)
add_test(NAME http_end_to_end COMMAND mira_http_e2e_tests)

# A connection-loop bug hangs rather than fails; a timeout makes it red.
add_test(NAME http_response_parser COMMAND mira_http_response_tests)
add_test(NAME http_client COMMAND mira_http_client_tests)
add_test(NAME http_streaming COMMAND mira_http_streaming_tests)
set_tests_properties(http_server http_end_to_end http_response_parser http_client http_streaming PROPERTIES TIMEOUT 60)
