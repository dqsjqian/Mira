cmake_minimum_required(VERSION 3.20)

project(Mira
    VERSION 0.3.0
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

    # Export-set 名字与目标一一对应，用映射表而非 if/elseif 阶梯：
    # 新模块接入只需加一行 "target=exportSet"，不再多一条分支。
    set(export_set miraTargets)
    foreach(entry
            "mira_tls=miraTlsTargets"
            "mira_http2=miraHttp2Targets"
            "mira_quic=miraHttp3Targets"
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
add_subdirectory(modules/transport)
add_subdirectory(modules/http)

if(MIRA_ENABLE_TLS)
    add_subdirectory(modules/tls)
endif()
if(MIRA_ENABLE_HTTP2)
    add_subdirectory(modules/http2)
endif()
if(MIRA_ENABLE_HTTP3)
    add_subdirectory(modules/quic)
    add_subdirectory(modules/http3)
endif()

# ── Benchmarks ──────────────────────────────────────────────────────────────
# The bench gate lives in bench/CMakeLists.txt; it needs the option declared
# here so `cmake -DMIRA_BUILD_BENCH=ON` is visible before the subdirectory.
option(MIRA_BUILD_BENCH "Build Mira's in-process benchmarks" OFF)
if(MIRA_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# ── Examples ────────────────────────────────────────────────────────────────

if(MIRA_BUILD_EXAMPLES)
    add_executable(mira_echo_server examples/echo_server.cpp)
    target_link_libraries(mira_echo_server PRIVATE Mira::transport Mira::warnings)

    if(MIRA_BUILD_TESTS)
        find_package(Python3 COMPONENTS Interpreter QUIET)
        if(Python3_Interpreter_FOUND)
            add_test(NAME mira_echo_example
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/tools/ci/check_echo_example.py
                    $<TARGET_FILE:mira_echo_server>
            )
            set_tests_properties(mira_echo_example PROPERTIES TIMEOUT 90)
        endif()
    endif()
endif()

# ── Package config ──────────────────────────────────────────────────────────
#
# Written after the modules so that the export set is complete.

if(MIRA_INSTALL)
    include(CMakePackageConfigHelpers)

    set(MIRA_CMAKE_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Mira)

    install(EXPORT miraTargets
        FILE miraTargets.cmake
        NAMESPACE Mira::
        DESTINATION ${MIRA_CMAKE_DESTINATION}
    )

    foreach(optional_module IN ITEMS Tls Http2 Http3)
        if((optional_module STREQUAL "Tls" AND MIRA_ENABLE_TLS)
           OR (optional_module STREQUAL "Http2" AND MIRA_ENABLE_HTTP2)
           OR (optional_module STREQUAL "Http3" AND MIRA_ENABLE_HTTP3))
            install(EXPORT mira${optional_module}Targets
                FILE mira${optional_module}Targets.cmake
                NAMESPACE Mira::
                DESTINATION ${MIRA_CMAKE_DESTINATION}
            )
        endif()
    endforeach()

    if(MIRA_ENABLE_HTTP3)
        install(FILES cmake/mira-http3-dependencies.cmake
            DESTINATION ${MIRA_CMAKE_DESTINATION})
    endif()

    configure_package_config_file(
        cmake/mira-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfig.cmake
        INSTALL_DESTINATION ${MIRA_CMAKE_DESTINATION}
    )

    # SameMinorVersion, not SameMajorVersion: while the major version is 0 the
    # minor one is where breaking changes land, so 0.2 must not satisfy a
    # request for 0.3. See CHANGELOG.md for the policy this encodes.
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfigVersion.cmake
        COMPATIBILITY SameMinorVersion
    )

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/MiraConfigVersion.cmake
        DESTINATION ${MIRA_CMAKE_DESTINATION}
    )
endif()
