# Protocol library versions, revisions and hashes are pinned in
# scripts/protocol-dependencies.json; see docs/PROTOCOL-DEPENDENCIES.md.
# No dependency downloads occur during CMake configuration.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(NGHTTP2 1.61 REQUIRED)

# The HTTP/2 module must link the nghttp2 from the ForgeDeps recipe graph
# (1.70.0-mira.1), never a host/toolchain copy: the recipe carries
# Mira-specific behavior the stock library lacks, and a silent downgrade
# used to surface only as mira_http2 test failures. Fail at configure
# time, naming both sides of the mismatch. The check is path-based so a
# future recipe version bump does not need a CMake edit; it only applies
# when the ForgeDeps dependency prefixes are known.
if(DEFINED _mira_dependency_prefixes)
    set(_mira_nghttp2_from_recipe FALSE)
    foreach(_mira_prefix IN LISTS _mira_dependency_prefixes)
        string(FIND "${NGHTTP2_LIBRARY}" "${_mira_prefix}/" _mira_nghttp2_prefix_pos)
        if(_mira_nghttp2_prefix_pos EQUAL 0)
            set(_mira_nghttp2_from_recipe TRUE)
        endif()
    endforeach()
    if(NOT _mira_nghttp2_from_recipe)
        message(FATAL_ERROR
            "Mira HTTP/2 requires nghttp2 from the ForgeDeps recipe graph (1.70.0-mira.1), "
            "but found ${NGHTTP2_LIBRARY} (version ${NGHTTP2_VERSION}). "
            "Check that the ForgeDeps dependency prefixes come before any toolchain paths.")
    endif()
    unset(_mira_nghttp2_from_recipe)
    unset(_mira_nghttp2_prefix_pos)
    unset(_mira_prefix)
endif()

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
