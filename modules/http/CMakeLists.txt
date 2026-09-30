# Mira::http — HTTP/1.1 message parsing and serialisation.
#
# Links only against Mira::core. No OS headers, no socket types: the
# layering check fails the build on either. That is what keeps the parser
# testable over an in-memory buffer and reusable over TLS later.

add_library(mira_http
    src/message.cpp
    src/parser.cpp
    src/response_parser.cpp
    src/serializer.cpp
)

add_library(Mira::http ALIAS mira_http)

target_include_directories(mira_http PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(mira_http PUBLIC cxx_std_23)
target_link_libraries(mira_http
    PUBLIC Mira::core
    # See modules/core/CMakeLists.txt for why this is wrapped.
    PRIVATE $<BUILD_INTERFACE:Mira::warnings>
)

set_target_properties(mira_http PROPERTIES
    OUTPUT_NAME Mira-http
    VERSION ${PROJECT_VERSION}
    # The build-tree ALIAS is Mira::http; without EXPORT_NAME the export
    # uses the real target name and installs Mira::mira_http instead,
    # so a consumer's link line would differ from an embedder's for no reason.
    EXPORT_NAME http
)

mira_install_module(mira_http)

if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
