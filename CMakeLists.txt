cmake_minimum_required(VERSION 3.20)

project(Mira
    VERSION 2.0.0
    DESCRIPTION "A modern C++23 thread pool"
    HOMEPAGE_URL "https://github.com/dqsjqian/Mira"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Library: header only, C++23, nothing beyond the standard library.
# ---------------------------------------------------------------------------

add_library(mira INTERFACE)
add_library(mira::mira ALIAS mira)

target_include_directories(mira INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# C++23 is the minimum, not a ceiling. On MSVC this CMake maps cxx_std_23 to
# /std:c++latest, which enables the C++26 preview on top of the C++23 features
# Mira actually uses. Pass -DCMAKE_CXX_STANDARD=26 to ask for C++26 explicitly
# on toolchains that support it.
target_compile_features(mira INTERFACE cxx_std_23)

find_package(Threads REQUIRED)
target_link_libraries(mira INTERFACE Threads::Threads)

# Warnings are applied to Mira's own targets only. A library should not force
# its warning policy onto the projects that consume it.
if(MSVC)
    set(MIRA_WARNING_FLAGS /W4 /permissive- /utf-8)
else()
    set(MIRA_WARNING_FLAGS -Wall -Wextra -Wpedantic)
endif()

option(MIRA_WERROR "Treat warnings in Mira's own targets as errors" OFF)
if(MIRA_WERROR)
    if(MSVC)
        list(APPEND MIRA_WARNING_FLAGS /WX)
    else()
        list(APPEND MIRA_WARNING_FLAGS -Werror)
    endif()
endif()

# ---------------------------------------------------------------------------
# Standard library side libraries
#
# Two C++23 library features Mira uses do not always live in the main runtime
# library: on GCC 14, <stacktrace> needs libstdc++_libbacktrace and <print>
# needs libstdc++exp. Hardcoding that would break toolchains that keep both in
# the main runtime (MSVC, libc++, newer libstdc++), so probe for it instead.
# ---------------------------------------------------------------------------

include(CheckCXXSourceCompiles)

set(MIRA_STACKTRACE_PROBE "
#include <stacktrace>
int main() {
    const std::stacktrace trace = std::stacktrace::current();
    return trace.empty() ? 0 : 1;
}")

set(MIRA_PRINT_PROBE "
#include <print>
int main() {
    std::println(\"mira\");
    return 0;
}")

# The probes must compile as C++23 themselves; check_cxx_source_compiles does
# not inherit the standard requirement from target_compile_features, and
# without it <stacktrace> and <print> do not exist at all. Appending rather
# than overwriting lets a caller inject extra flags through
# -DCMAKE_REQUIRED_FLAGS (needed when the standard library has to be selected
# explicitly, e.g. Clang with --gcc-install-dir).
if(MSVC)
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} /std:c++latest")
else()
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -std=c++23")
endif()

check_cxx_source_compiles("${MIRA_STACKTRACE_PROBE}" MIRA_STACKTRACE_LINKS_UNAIDED)

if(MIRA_STACKTRACE_LINKS_UNAIDED)
    message(STATUS "Mira: std::stacktrace links against the standard library")
else()
    set(CMAKE_REQUIRED_LIBRARIES stdc++_libbacktrace)
    check_cxx_source_compiles("${MIRA_STACKTRACE_PROBE}" MIRA_STACKTRACE_LINKS_WITH_LIBBACKTRACE)
    unset(CMAKE_REQUIRED_LIBRARIES)
    if(MIRA_STACKTRACE_LINKS_WITH_LIBBACKTRACE)
        message(STATUS "Mira: std::stacktrace needs -lstdc++_libbacktrace")
        target_link_libraries(mira INTERFACE stdc++_libbacktrace)
    else()
        message(FATAL_ERROR
            "Mira needs C++23 and a linkable std::stacktrace. This probe failed "
            "both with and without -lstdc++_libbacktrace, which usually means the "
            "compiler does not support C++23 at all (Mira needs GCC 14+, "
            "Clang 18+ or MSVC 19.40+).")
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

option(MIRA_BUILD_TESTS "Build the Mira test suite" ON)

if(MIRA_BUILD_TESTS)
    enable_testing()

    add_executable(mira_tests tests/thread_pool_test.cpp)
    target_link_libraries(mira_tests PRIVATE mira::mira)
    target_compile_options(mira_tests PRIVATE ${MIRA_WARNING_FLAGS})

    add_test(NAME mira_tests COMMAND mira_tests)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

option(MIRA_BUILD_EXAMPLES "Build the Mira examples" ON)

if(MIRA_BUILD_EXAMPLES)
    add_executable(mira_example examples/basic_usage.cpp)
    target_link_libraries(mira_example PRIVATE mira::mira)
    target_compile_options(mira_example PRIVATE ${MIRA_WARNING_FLAGS})

    # std::print is the one side library Mira's own headers do not pull in, so
    # the probe result is attached to the example rather than to the interface.
    check_cxx_source_compiles("${MIRA_PRINT_PROBE}" MIRA_PRINT_LINKS_UNAIDED)
    if(NOT MIRA_PRINT_LINKS_UNAIDED)
        set(CMAKE_REQUIRED_LIBRARIES stdc++exp)
        check_cxx_source_compiles("${MIRA_PRINT_PROBE}" MIRA_PRINT_LINKS_WITH_STDCXXEXP)
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(MIRA_PRINT_LINKS_WITH_STDCXXEXP)
            message(STATUS "Mira: std::print needs -lstdc++exp")
            target_link_libraries(mira_example PRIVATE stdc++exp)
        else()
            message(FATAL_ERROR
                "This toolchain ships <print> but cannot link std::print, which "
                "the Mira example uses for its output.")
        endif()
    endif()
endif()

unset(CMAKE_REQUIRED_FLAGS)

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS mira EXPORT MiraTargets INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT MiraTargets
    NAMESPACE mira::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Mira)
