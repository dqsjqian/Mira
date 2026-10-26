# Protocol library versions, revisions and hashes are pinned in
# scripts/protocol-dependencies.json; see docs/PROTOCOL-DEPENDENCIES.md.
# No dependency downloads occur during CMake configuration.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(NGHTTP2 1.61 REQUIRED)

add_library(mira_http2 src/session.cpp)
add_library(Mira::http2 ALIAS mira_http2)
target_include_directories(mira_http2 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_http2 PUBLIC cxx_std_23)
target_link_libraries(mira_http2 PUBLIC Mira::core Mira::http_common
    PRIVATE NGHTTP2::NGHTTP2 $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_http2 PROPERTIES OUTPUT_NAME Mira-http2
    VERSION ${PROJECT_VERSION} EXPORT_NAME http2)
mira_install_module(mira_http2)
if(MIRA_INSTALL)
    install(FILES cmake/FindNGHTTP2.cmake cmake/mira-http2-dependencies.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Mira)
endif()
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
