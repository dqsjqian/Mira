cmake_minimum_required(VERSION 3.16)

project(Mira
    VERSION 1.0.0
    DESCRIPTION "A small, modern C++20 thread pool"
    HOMEPAGE_URL "https://github.com/dqsjqian/Mira"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Library: header only, C++20, nothing beyond the standard library.
# ---------------------------------------------------------------------------

add_library(mira INTERFACE)
add_library(mira::mira ALIAS mira)

target_include_directories(mira INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_compile_features(mira INTERFACE cxx_std_20)

find_package(Threads REQUIRED)
target_link_libraries(mira INTERFACE Threads::Threads)

# Warnings are applied to Mira's own targets only. A library should not force
# its warning policy onto the projects that consume it.
if(MSVC)
    set(MIRA_WARNING_FLAGS /W4 /permissive- /utf-8)
else()
    set(MIRA_WARNING_FLAGS -Wall -Wextra -Wpedantic)
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
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

include(GNUInstallDirs)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS mira EXPORT MiraTargets INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT MiraTargets
    NAMESPACE mira::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Mira)
