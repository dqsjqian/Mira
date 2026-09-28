add_executable(mira_dial test_dial.cpp)
target_link_libraries(mira_dial PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_dial PRIVATE ${PROJECT_SOURCE_DIR}/modules/core/tests)
add_test(NAME dial COMMAND mira_dial)
set_tests_properties(dial PROPERTIES TIMEOUT 30)

add_executable(mira_server_shutdown_tests test_server_shutdown.cpp)
target_link_libraries(mira_server_shutdown_tests PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_server_shutdown_tests PRIVATE ${PROJECT_SOURCE_DIR}/modules/core/tests)
add_test(NAME server_shutdown COMMAND mira_server_shutdown_tests)
set_tests_properties(server_shutdown PROPERTIES TIMEOUT 30)

add_executable(mira_transport_tests test_tcp.cpp)

target_link_libraries(mira_transport_tests PRIVATE
    Mira::transport
    Mira::warnings
)

target_include_directories(mira_transport_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/modules/core/tests
)

add_test(NAME transport COMMAND mira_transport_tests)

add_executable(mira_local_tests test_local.cpp)
target_link_libraries(mira_local_tests PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_local_tests PRIVATE ${CMAKE_SOURCE_DIR}/modules/core/tests)
add_test(NAME local_transport COMMAND mira_local_tests)
set_tests_properties(local_transport PROPERTIES TIMEOUT 30)

add_executable(mira_connection_pool_tests test_connection_pool.cpp)
target_link_libraries(mira_connection_pool_tests PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_connection_pool_tests PRIVATE ${CMAKE_SOURCE_DIR}/modules/core/tests)
add_test(NAME connection_pool COMMAND mira_connection_pool_tests)
set_tests_properties(connection_pool PROPERTIES TIMEOUT 30)

# A transport bug hangs rather than fails; a timeout makes it red instead.
set_tests_properties(transport PROPERTIES TIMEOUT 60)

add_executable(mira_udp_tests test_udp.cpp)
target_link_libraries(mira_udp_tests PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_udp_tests PRIVATE ${CMAKE_SOURCE_DIR}/modules/core/tests)
add_test(NAME udp COMMAND mira_udp_tests)

# Concept conformance is compile-time only; the binary exists so ctest can
# witness it building and linking against the installed shapes.
add_executable(mira_datagram_concept_tests test_datagram_concept.cpp)
target_link_libraries(mira_datagram_concept_tests PRIVATE Mira::transport Mira::warnings)
add_test(NAME datagram_concept COMMAND mira_datagram_concept_tests)
set_tests_properties(udp PROPERTIES TIMEOUT 60)

add_executable(mira_resolver_tests test_resolver.cpp)
target_link_libraries(mira_resolver_tests PRIVATE Mira::transport Mira::warnings)
target_include_directories(mira_resolver_tests PRIVATE ${CMAKE_SOURCE_DIR}/modules/core/tests)
add_test(NAME resolver COMMAND mira_resolver_tests)
set_tests_properties(resolver PROPERTIES TIMEOUT 60)
