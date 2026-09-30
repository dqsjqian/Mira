# Mira::transport — TCP listeners, connections, and endpoints.
#
# The only module besides core/ that touches OS networking headers, and it
# confines them to src/socket_compat.hpp. Protocols never link against this:
# they take an AsyncStream, and tcp::Socket happens to model it.

add_library(mira_transport
    src/endpoint.cpp
    src/tcp.cpp
    src/udp.cpp
    src/local.cpp
    src/resolver.cpp
)

add_library(Mira::transport ALIAS mira_transport)

target_include_directories(mira_transport PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_include_directories(mira_transport PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(mira_transport PUBLIC cxx_std_23)
target_link_libraries(mira_transport
    PUBLIC Mira::core
    # See modules/core/CMakeLists.txt for why this is wrapped.
    PRIVATE $<BUILD_INTERFACE:Mira::warnings>
)

if(WIN32)
    target_link_libraries(mira_transport PUBLIC ws2_32 mswsock)
endif()

set_target_properties(mira_transport PROPERTIES
    OUTPUT_NAME Mira-transport
    VERSION ${PROJECT_VERSION}
    # The build-tree ALIAS is Mira::transport; without EXPORT_NAME the export
    # uses the real target name and installs Mira::mira_transport instead,
    # so a consumer's link line would differ from an embedder's for no reason.
    EXPORT_NAME transport
)

mira_install_module(mira_transport)

if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
