cmake_minimum_required(VERSION 3.21)

project(Mira
    VERSION 1.0.0
    DESCRIPTION "Coroutine-native C++23 networking library — transport, protocols, and nothing else"
    LANGUAGES CXX
)

# ── Standard ────────────────────────────────────────────────────────────────
#
# C++23 is the baseline. Use std::expected directly rather than maintaining a
# second, subtly different error model for an older standard.
set(CMAKE_CXX_STANDARD 23 CACHE STRING "C++ standard used to build Mira")
if(CMAKE_CXX_STANDARD LESS 23)
    message(FATAL_ERROR "Mira requires C++23 or newer; use -DCMAKE_CXX_STANDARD=23")
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(PROJECT_IS_TOP_LEVEL)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

option(MIRA_BUILD_TESTS "Build Mira tests" ${PROJECT_IS_TOP_LEVEL})

# Mobile/cross builds should not produce a host-style server unless requested.
set(MIRA_BUILD_EXAMPLES_DEFAULT OFF)
if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(MIRA_BUILD_EXAMPLES_DEFAULT ON)
endif()
option(MIRA_BUILD_EXAMPLES "Build Mira examples" ${MIRA_BUILD_EXAMPLES_DEFAULT})

option(MIRA_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(MIRA_ENABLE_TLS "Build the optional OpenSSL 3 TLS stream module" OFF)
option(MIRA_ENABLE_WEBSOCKET "Build WebSocket (OpenSSL Crypto and zlib for optional compression)" OFF)
option(MIRA_ENABLE_HTTP2 "Build the optional nghttp2 HTTP/2 module" OFF)
option(MIRA_ENABLE_HTTP3 "Build the optional QUIC and HTTP/3 modules (experimental)" OFF)

# Off by default when embedded: a project that pulls Mira in via
# add_subdirectory() has not asked to install our headers alongside its own.
option(MIRA_INSTALL "Generate install and package-config rules"
       ${PROJECT_IS_TOP_LEVEL})

# ── Warning policy ──────────────────────────────────────────────────────────
#
# Applied through an interface target rather than global flags so that a
# consumer pulling Mira in via add_subdirectory() does not inherit our
# warning policy for their own sources.

add_library(mira_warnings INTERFACE)
add_library(Mira::warnings ALIAS mira_warnings)

if(MSVC)
    # Sources are UTF-8. Without /utf-8, MSVC assumes the active code page
    # and C4819 (a hard error under /WX) fires on CJK-locale Windows hosts.
    target_compile_options(mira_warnings INTERFACE /W4 /permissive- /utf-8)
    if(MIRA_WARNINGS_AS_ERRORS)
        target_compile_options(mira_warnings INTERFACE /WX)
    endif()
else()
    target_compile_options(mira_warnings INTERFACE
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast
    )
    if(MIRA_WARNINGS_AS_ERRORS)
        target_compile_options(mira_warnings INTERFACE -Werror)
    endif()
endif()

# ── Installation ────────────────────────────────────────────────────────────
#
# One export set for every module, so that a consumer gets a single
# `find_package(Mira)` rather than one per layer.
#
# Each module calls this rather than repeating four near-identical blocks,
# which is also what keeps a new module from being installed slightly
# differently to the others.

include(GNUInstallDirs)

function(mira_install_module target)
    if(NOT MIRA_INSTALL)
        return()
    endif()

    # Export-set names map one-to-one to targets via a lookup table rather
    # than an if/elseif ladder: a new module joins with one "target=exportSet"
    # line, not one more branch.
    set(export_set miraTargets)
    foreach(entry
            "mira_tls=miraTlsTargets"
            "mira_client_tls=miraClientTlsTargets"
            "mira_client_http2=miraClientHttp2Targets"
            "mira_client_http3=miraClientHttp3Targets"
            "mira_crypto=miraCryptoTargets"
            "mira_ws=miraWsTargets"
            "mira_http2=miraHttp2Targets"
            "mira_quic=miraQuicTargets"
            "mira_http3=miraHttp3Targets")
        string(REPLACE "=" ";" pair "${entry}")
        list(GET pair 0 mapped_target)
        list(GET pair 1 mapped_set)
        if(target STREQUAL "${mapped_target}")
            set(export_set "${mapped_set}")
        endif()
    endforeach()
    install(TARGETS ${target}
        EXPORT ${export_set}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endfunction()

# ── Modules ─────────────────────────────────────────────────────────────────
#
# Dependency direction is one-way and enforced by tools/ci/check_layering.py:
#
#   http and tls consume core's AsyncStream seam; transport implements it.
#   Applications compose the modules, rather than http depending on sockets.
#
# TLS is optional: the core/plain TCP/HTTP build has no OpenSSL dependency.

if(MIRA_BUILD_TESTS)
    enable_testing()
endif()

# Each module registers its own tests and install rules.
add_subdirectory(modules/core)
add_subdirectory(modules/http_common)
add_subdirectory(modules/transport)
add_subdirectory(modules/http)
add_subdirectory(modules/socks)
add_subdirectory(modules/dns)
add_subdirectory(modules/mqtt)

if(MIRA_ENABLE_TLS)
    add_subdirectory(modules/tls)
endif()
if(MIRA_ENABLE_WEBSOCKET)
    add_subdirectory(modules/crypto)
    add_subdirectory(modules/ws)
endif()
if(MIRA_ENABLE_HTTP2)
    add_subdirectory(modules/http2)
endif()
if(MIRA_ENABLE_HTTP3)
    add_subdirectory(modules/quic)
    add_subdirectory(modules/http3)
endif()

add_subdirectory(modules/client)

if(MIRA_BUILD_TESTS AND MIRA_ENABLE_WEBSOCKET AND MIRA_ENABLE_HTTP2 AND MIRA_ENABLE_HTTP3)
    add_executable(mira_ws_connect_network modules/ws/tests/test_connect_network.cpp)
    target_link_libraries(mira_ws_connect_network PRIVATE
        Mira::ws Mira::http2 Mira::http3 Mira::warnings)
    add_test(NAME ws.connect_network COMMAND mira_ws_connect_network
        "${MIRA_QUIC_TEST_CERT}" "${MIRA_QUIC_TEST_KEY}")
    set_tests_properties(ws.connect_network PROPERTIES TIMEOUT 90)
endif()

if(MIRA_BUILD_TESTS AND MIRA_ENABLE_HTTP3 AND MIRA_ENABLE_WEBSOCKET)
    add_executable(mira_h3_advanced_peer tools/ci/h3_advanced_peer.cpp)
    target_link_libraries(mira_h3_advanced_peer PRIVATE Mira::http3 Mira::ws Mira::warnings)
endif()

# ── Benchmarks ──────────────────────────────────────────────────────────────
# The bench gate lives in bench/CMakeLists.txt; it needs the option declared
# here so `cmake -DMIRA_BUILD_BENCH=ON` is visible before the subdirectory.
option(MIRA_BUILD_BENCH "Build Mira's in-process benchmarks" OFF)
option(MIRA_BUILD_FUZZERS "Build Mira's libFuzzer harnesses (clang only)" OFF)
if(MIRA_BUILD_BENCH)
    add_subdirectory(bench)
endif()
if(MIRA_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# ── Examples ────────────────────────────────────────────────────────────────

if(MIRA_BUILD_EXAMPLES)
    add_executable(mira_loop_group_server examples/loop_group_server.cpp)
    target_link_libraries(mira_loop_group_server PRIVATE Mira::transport Mira::warnings)

    add_executable(mira_echo_server examples/echo_server.cpp)
    target_link_libraries(mira_echo_server PRIVATE Mira::transport Mira::warnings)

    add_executable(mira_hello_world_server examples/hello_world_server.cpp)
    target_link_libraries(mira_hello_world_server PRIVATE Mira::http Mira::transport Mira::warnings)

    add_executable(mira_tiny_file_server examples/tiny_file_server.cpp)
    target_link_libraries(mira_tiny_file_server PRIVATE Mira::http Mira::transport Mira::warnings)

    foreach(example IN ITEMS tcp_client udp_server udp_client managed_echo_server)
        add_executable(mira_${example} examples/${example}.cpp)
        target_link_libraries(mira_${example} PRIVATE Mira::transport Mira::warnings)
    endforeach()
    add_executable(mira_http1_client examples/http1_client.cpp)
    target_link_libraries(mira_http1_client PRIVATE Mira::http Mira::transport Mira::warnings)
    add_executable(mira_sse_server examples/sse_server.cpp)
    target_link_libraries(mira_sse_server PRIVATE Mira::http Mira::transport Mira::warnings)
    add_executable(mira_socks5_server examples/socks5_server.cpp)
    target_link_libraries(mira_socks5_server PRIVATE Mira::socks Mira::transport Mira::warnings)
    add_executable(mira_socks5_client examples/socks5_client.cpp)
    target_link_libraries(mira_socks5_client PRIVATE Mira::client Mira::warnings)
    add_executable(mira_doh_server examples/doh_server.cpp)
    target_link_libraries(mira_doh_server PRIVATE Mira::dns Mira::socks Mira::transport Mira::warnings)
    add_executable(mira_doh_client examples/doh_client.cpp)
    target_link_libraries(mira_doh_client PRIVATE Mira::dns Mira::transport Mira::warnings)
    add_executable(mira_mqtt_client examples/mqtt_client.cpp)
    target_link_libraries(mira_mqtt_client PRIVATE Mira::mqtt Mira::transport Mira::warnings)
    if(MIRA_ENABLE_TLS)
        foreach(example IN ITEMS mira_doh_server mira_doh_client mira_mqtt_client)
            target_link_libraries(${example} PRIVATE Mira::tls)
            target_compile_definitions(${example} PRIVATE MIRA_EXAMPLE_TLS=1)
        endforeach()
    endif()

    if(MIRA_ENABLE_WEBSOCKET)
        foreach(example IN ITEMS ws_server ws_client ws_autobahn_server ws_autobahn_client ws_extensions_peer)
            add_executable(mira_${example} examples/${example}.cpp)
            target_link_libraries(mira_${example} PRIVATE Mira::ws Mira::transport Mira::warnings)
        endforeach()
    endif()
    if(MIRA_ENABLE_TLS AND MIRA_ENABLE_HTTP2)
        add_executable(mira_https_managed_server examples/https_managed_server.cpp)
        target_link_libraries(mira_https_managed_server PRIVATE
            Mira::tls Mira::http Mira::http2 Mira::transport Mira::warnings)
    endif()
    if(MIRA_ENABLE_HTTP2)
        add_executable(mira_h2_prior_knowledge_server examples/h2_prior_knowledge_server.cpp)
        target_link_libraries(mira_h2_prior_knowledge_server PRIVATE Mira::http2 Mira::transport Mira::warnings)
        add_executable(mira_h2_client examples/h2_client.cpp)
        target_link_libraries(mira_h2_client PRIVATE Mira::http2 Mira::transport Mira::warnings)
    endif()
    if(MIRA_ENABLE_HTTP3)
        add_executable(mira_h3_server examples/h3_server.cpp)
        target_link_libraries(mira_h3_server PRIVATE Mira::http3 Mira::warnings)
        add_executable(mira_h3_client examples/h3_client.cpp)
        target_link_libraries(mira_h3_client PRIVATE Mira::http3 Mira::warnings)
        add_executable(mira_h3_multi_server examples/h3_multi_server.cpp)
        target_link_libraries(mira_h3_multi_server PRIVATE Mira::http3 Mira::warnings)
    endif()

    if(MIRA_BUILD_TESTS)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            add_test(NAME mira_managed_server
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_managed_server.py
                    $<TARGET_FILE:mira_managed_echo_server>)
            set_tests_properties(mira_managed_server PROPERTIES TIMEOUT 30)
            add_test(NAME mira_sse_example
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_sse_example.py
                    $<TARGET_FILE:mira_sse_server>)
            set_tests_properties(mira_sse_example PROPERTIES TIMEOUT 30)
            add_test(NAME mira_client_server_examples
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_client_server_examples.py
                    --tcp-server $<TARGET_FILE:mira_echo_server>
                    --tcp-client $<TARGET_FILE:mira_tcp_client>
                    --udp-server $<TARGET_FILE:mira_udp_server>
                    --udp-client $<TARGET_FILE:mira_udp_client>
                    --http-server $<TARGET_FILE:mira_hello_world_server>
                    --http-client $<TARGET_FILE:mira_http1_client>)
            set_tests_properties(mira_client_server_examples PROPERTIES TIMEOUT 90)
            add_test(NAME mira_echo_example
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_echo_example.py
                    $<TARGET_FILE:mira_echo_server>
            )
            set_tests_properties(mira_echo_example PROPERTIES TIMEOUT 90)
            add_test(NAME mira_hello_world_example
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_hello_world_example.py
                    $<TARGET_FILE:mira_hello_world_server>
            )
            set_tests_properties(mira_hello_world_example PROPERTIES TIMEOUT 90)
            add_test(NAME mira_tiny_file_server_example
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_tiny_file_server.py
                    $<TARGET_FILE:mira_tiny_file_server>
            )
            set_tests_properties(mira_tiny_file_server_example PROPERTIES TIMEOUT 120)
            add_test(NAME socks.interop
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_socks5.py
                    --proxy $<TARGET_FILE:mira_socks5_server>
                    --client $<TARGET_FILE:mira_socks5_client>
                    --http-server $<TARGET_FILE:mira_hello_world_server>)
            set_tests_properties(socks.interop PROPERTIES TIMEOUT 90)
            set(mira_doh_tls_flag "")
            if(MIRA_ENABLE_TLS)
                find_program(MIRA_DOH_OPENSSL openssl HINTS "${OPENSSL_ROOT_DIR}/bin")
                set(mira_doh_tls_flag --tls)
                if(MIRA_DOH_OPENSSL)
                    list(APPEND mira_doh_tls_flag --openssl "${MIRA_DOH_OPENSSL}")
                endif()
            endif()
            add_test(NAME dns.interop
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_doh.py
                    --server $<TARGET_FILE:mira_doh_server>
                    --client $<TARGET_FILE:mira_doh_client>
                    --http-server $<TARGET_FILE:mira_hello_world_server> ${mira_doh_tls_flag})
            set_tests_properties(dns.interop PROPERTIES TIMEOUT 120)
            add_test(NAME mqtt.interop
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_mqtt.py
                    --client $<TARGET_FILE:mira_mqtt_client>)
            set_tests_properties(mqtt.interop PROPERTIES TIMEOUT 180)
            if(TARGET mira_https_managed_server)
                add_test(NAME mira_managed_https
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_managed_https.py
                        $<TARGET_FILE:mira_https_managed_server>)
                set_tests_properties(mira_managed_https PROPERTIES TIMEOUT 45 SKIP_RETURN_CODE 77)
            endif()
            if(TARGET mira_ws_server)
                add_test(NAME mira_ws_interop
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_ws_interop.py
                        --server $<TARGET_FILE:mira_ws_server> --client $<TARGET_FILE:mira_ws_client>)
                set_tests_properties(mira_ws_interop PROPERTIES TIMEOUT 60)
                add_test(NAME mira_ws_extensions_interop
                    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_ws_interop.py
                        --extensions-peer $<TARGET_FILE:mira_ws_extensions_peer>)
                set_tests_properties(mira_ws_extensions_interop PROPERTIES TIMEOUT 120)
            endif()
            if(TARGET mira_h2_prior_knowledge_server)
                add_test(NAME mira_h2_pair
                    COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_h2_pair.py
                        --server $<TARGET_FILE:mira_h2_prior_knowledge_server>
                        --client $<TARGET_FILE:mira_h2_client>)
                set_tests_properties(mira_h2_pair PROPERTIES TIMEOUT 60)
                add_test(NAME mira_h2_interop
                    COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_h2_interop.py
                        $<TARGET_FILE:mira_h2_prior_knowledge_server>
                )
                set_tests_properties(mira_h2_interop PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
            endif()
            if(TARGET mira_h3_server)
                add_test(NAME mira_h3_pair
                    COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_h3_pair.py
                        $<TARGET_FILE:mira_h3_server> $<TARGET_FILE:mira_h3_client>
                        ${MIRA_QUIC_TEST_CERT} ${MIRA_QUIC_TEST_KEY})
                set_tests_properties(mira_h3_pair PROPERTIES TIMEOUT 120)
                add_test(NAME mira_h3_interop
                    COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_h3_interop.py
                        $<TARGET_FILE:mira_h3_server>
                        --openssl ${MIRA_QUIC_OPENSSL_TOOL}
                )
                set_tests_properties(mira_h3_interop PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
                add_test(NAME mira_h3_retry_interop
                    COMMAND ${Python3_EXECUTABLE}
                        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_h3_interop.py
                        $<TARGET_FILE:mira_h3_multi_server> --multi-retry
                        --openssl ${MIRA_QUIC_OPENSSL_TOOL})
                set_tests_properties(mira_h3_retry_interop PROPERTIES TIMEOUT 120 SKIP_RETURN_CODE 77)
            endif()
        endif()
    endif()
endif()

# ── Package config ──────────────────────────────────────────────────────────
#
# Written after the modules so that the export set is complete.

if(MIRA_INSTALL)
    include(CMakePackageConfigHelpers)

    set(MIRA_CMAKE_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Mira)
    install(FILES LICENSE THIRD_PARTY_NOTICES.md DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/Mira)

    install(EXPORT miraTargets
        FILE miraTargets.cmake
        NAMESPACE Mira::
        DESTINATION ${MIRA_CMAKE_DESTINATION}
    )

    foreach(optional_module IN ITEMS Tls ClientTls ClientHttp2 ClientHttp3 Crypto Ws Http2 Quic Http3)
        if(((optional_module STREQUAL "Tls" OR optional_module STREQUAL "ClientTls") AND MIRA_ENABLE_TLS)
           OR ((optional_module STREQUAL "Crypto" OR optional_module STREQUAL "Ws") AND MIRA_ENABLE_WEBSOCKET)
           OR (optional_module STREQUAL "Http2" AND MIRA_ENABLE_HTTP2)
           OR (optional_module STREQUAL "ClientHttp2" AND MIRA_ENABLE_HTTP2 AND MIRA_ENABLE_TLS)
           OR (optional_module STREQUAL "ClientHttp3" AND MIRA_ENABLE_HTTP3)
           OR ((optional_module STREQUAL "Quic" OR optional_module STREQUAL "Http3") AND MIRA_ENABLE_HTTP3))
            install(EXPORT mira${optional_module}Targets
                FILE mira${optional_module}Targets.cmake
                NAMESPACE Mira::
                DESTINATION ${MIRA_CMAKE_DESTINATION}
            )
        endif()
    endforeach()

    if(MIRA_ENABLE_HTTP3)
        install(FILES cmake/mira-quic-dependencies.cmake cmake/mira-http3-dependencies.cmake
            DESTINATION ${MIRA_CMAKE_DESTINATION})
    endif()

    configure_package_config_file(
        cmake/mira-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfig.cmake
        INSTALL_DESTINATION ${MIRA_CMAKE_DESTINATION}
    )

    # Stable releases preserve source compatibility within a major version.
    # Consumers needing an exact SDK can use find_package(... EXACT).
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfigVersion.cmake
        COMPATIBILITY SameMajorVersion
    )

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfigVersion.cmake
        DESTINATION ${MIRA_CMAKE_DESTINATION}
    )
endif()
