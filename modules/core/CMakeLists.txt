# Mira::core — event loop, buffers, coroutine plumbing, error model.
#
# A compiled library, not header-only. Header-only was considered and rejected:
# the reference point for this project ships 22k lines in one header, and the
# compile-time cost of that lands on every translation unit of every consumer.
# A compiled target also gives Mira somewhere to put a real ABI policy.

add_library(mira_core
    src/error.cpp
    src/event_loop_common.cpp
)

add_library(Mira::core ALIAS mira_core)

# ── Platform backends ───────────────────────────────────────────────────────
#
# Each backend file also guards itself with the macros from platform.hpp, so
# compiling the wrong one yields an empty object rather than a broken build.
# Selecting here as well keeps the build output honest about what is compiled.

if(WIN32)
    target_sources(mira_core PRIVATE src/event_loop_iocp.cpp)
    target_link_libraries(mira_core PUBLIC ws2_32 mswsock)
    # Keep <windows.h> from defining min/max macros and the kitchen sink.
    target_compile_definitions(mira_core PUBLIC WIN32_LEAN_AND_MEAN NOMINMAX)
    set(MIRA_IO_BACKEND "iocp")
elseif(APPLE OR CMAKE_SYSTEM_NAME MATCHES "BSD|DragonFly")
    target_sources(mira_core PRIVATE
        src/event_loop_posix.cpp
        src/poller_kqueue.cpp
    )
    set(MIRA_IO_BACKEND "kqueue")
elseif(UNIX)
    target_sources(mira_core PRIVATE
        src/event_loop_posix.cpp
        src/poller_epoll.cpp
    )
    set(MIRA_IO_BACKEND "epoll")
else()
    message(FATAL_ERROR
        "Mira: no I/O backend for ${CMAKE_SYSTEM_NAME}. "
        "Add a readiness or completion backend before building here.")
endif()

message(STATUS "Mira: I/O backend = ${MIRA_IO_BACKEND} (${CMAKE_SYSTEM_NAME})")

# ── Generated version header ────────────────────────────────────────────────
#
# Generated into the build tree and installed alongside the hand-written
# headers, so there is exactly one place the version is stated.

set(MIRA_GENERATED_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/generated)

configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/version.hpp.in
    ${MIRA_GENERATED_INCLUDE}/mira/core/version.hpp
    @ONLY
)

target_include_directories(mira_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${MIRA_GENERATED_INCLUDE}>
    $<INSTALL_INTERFACE:include>
)

# Internal headers (poller.hpp, loop_common.hpp) are visible to this target
# only — implementation detail, not part of the installed surface.
target_include_directories(mira_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(mira_core PUBLIC cxx_std_23)

# Wrapped in BUILD_INTERFACE because a PRIVATE dependency of a static library
# is still recorded in INTERFACE_LINK_LIBRARIES as $<LINK_ONLY:...>, which
# makes install(EXPORT) demand that mira_warnings be exported too — and
# exporting it would push our warning policy onto every consumer, which is the
# thing the interface target exists to avoid.
target_link_libraries(mira_core PRIVATE $<BUILD_INTERFACE:Mira::warnings>)

find_package(Threads REQUIRED)
target_link_libraries(mira_core PUBLIC Threads::Threads)

set_target_properties(mira_core PROPERTIES
    OUTPUT_NAME Mira-core
    VERSION ${PROJECT_VERSION}
    # The build-tree ALIAS is Mira::core; without EXPORT_NAME the export
    # uses the real target name and installs Mira::mira_core instead,
    # so a consumer's link line would differ from an embedder's for no reason.
    EXPORT_NAME core
)

mira_install_module(mira_core)

if(MIRA_INSTALL)
    install(DIRECTORY ${MIRA_GENERATED_INCLUDE}/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif()

# Registered here rather than from the root, so that every module owns its own
# test registration and a new module cannot be added without one.
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
