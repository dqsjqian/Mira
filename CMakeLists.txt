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
# Two of the C++23 library features Mira uses are not always part of the main
# runtime library:
#
#   * libc++ has no <stacktrace> header at all, Apple's included, so there is
#     nothing to link against there.
#   * libstdc++ keeps the experimental C++23 library, which includes both
#     std::stacktrace and std::print, in libstdc++exp. GCC 13 put the
#     std::stacktrace symbols in a separate libstdc++_libbacktrace instead.
#   * MSVC and newer libstdc++ need nothing extra.
#
# So probe rather than hardcode: link the snippet on its own, then against each
# candidate library in turn.
# ---------------------------------------------------------------------------

include(CheckCXXSourceCompiles)

set(MIRA_EXPERIMENTAL_LIBRARIES stdc++exp stdc++_libbacktrace)

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

# Sets <prefix>_OK, and <prefix>_LIBRARIES to whatever had to be linked.
function(mira_resolve_side_libraries prefix snippet)
    check_cxx_source_compiles("${snippet}" "${prefix}_LINKS_UNAIDED")
    if(${prefix}_LINKS_UNAIDED)
        set(${prefix}_OK TRUE PARENT_SCOPE)
        set(${prefix}_LIBRARIES "" PARENT_SCOPE)
        return()
    endif()

    set(index 0)
    foreach(candidate IN LISTS ARGN)
        math(EXPR index "${index} + 1")
        set(CMAKE_REQUIRED_LIBRARIES "${candidate}")
        check_cxx_source_compiles("${snippet}" "${prefix}_LINKS_WITH_${index}")
        unset(CMAKE_REQUIRED_LIBRARIES)
        if(${prefix}_LINKS_WITH_${index})
            set(${prefix}_OK TRUE PARENT_SCOPE)
            set(${prefix}_LIBRARIES "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()

    set(${prefix}_OK FALSE PARENT_SCOPE)
    set(${prefix}_LIBRARIES "" PARENT_SCOPE)
endfunction()

mira_resolve_side_libraries(MIRA_STACKTRACE "${MIRA_STACKTRACE_PROBE}"
    ${MIRA_EXPERIMENTAL_LIBRARIES})

if(MIRA_STACKTRACE_OK)
    if(MIRA_STACKTRACE_LIBRARIES)
        message(STATUS "Mira: std::stacktrace needs -l${MIRA_STACKTRACE_LIBRARIES}")
        target_link_libraries(mira INTERFACE ${MIRA_STACKTRACE_LIBRARIES})
    else()
        message(STATUS "Mira: std::stacktrace links against the standard library")
    endif()
else()
    # Not fatal: the header falls back to an empty trace so that the pool still
    # builds and runs, it just cannot say where a task came from.
    message(STATUS "Mira: no usable <stacktrace> here, task provenance is disabled")
    target_compile_definitions(mira INTERFACE MIRA_NO_STACKTRACE=1)
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
    # std::print is the one side library Mira's own headers do not pull in, so
    # the probe result is attached to the example rather than to the interface.
    mira_resolve_side_libraries(MIRA_PRINT "${MIRA_PRINT_PROBE}"
        ${MIRA_EXPERIMENTAL_LIBRARIES})

    if(MIRA_PRINT_OK)
        add_executable(mira_example examples/basic_usage.cpp)
        target_link_libraries(mira_example PRIVATE mira::mira)
        target_compile_options(mira_example PRIVATE ${MIRA_WARNING_FLAGS})
        if(MIRA_PRINT_LIBRARIES)
            message(STATUS "Mira: std::print needs -l${MIRA_PRINT_LIBRARIES}")
            target_link_libraries(mira_example PRIVATE ${MIRA_PRINT_LIBRARIES})
        endif()
    else()
        message(STATUS "Mira: no usable <print> here, skipping the example")
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
