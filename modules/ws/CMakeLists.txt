find_package(ZLIB REQUIRED)
# An explicit SDK /usr/include can precede libc++'s C-header wrappers with
# non-Apple Clang. The sysroot already supplies that directory; retain custom
# zlib prefixes while removing only the same canonical system include root.
if(APPLE AND IS_DIRECTORY "${CMAKE_OSX_SYSROOT}")
    file(REAL_PATH "${CMAKE_OSX_SYSROOT}/usr/include" _mira_sdk_include)
    get_target_property(_mira_zlib_includes ZLIB::ZLIB INTERFACE_INCLUDE_DIRECTORIES)
    set(_mira_zlib_filtered "")
    foreach(_include IN LISTS _mira_zlib_includes)
        if(IS_DIRECTORY "${_include}")
            file(REAL_PATH "${_include}" _real_include)
        else()
            set(_real_include "${_include}")
        endif()
        if(NOT _real_include STREQUAL _mira_sdk_include)
            list(APPEND _mira_zlib_filtered "${_include}")
        endif()
    endforeach()
    set_property(TARGET ZLIB::ZLIB PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${_mira_zlib_filtered}")
endif()
add_library(mira_ws src/frame.cpp src/handshake.cpp src/compression.cpp)
add_library(Mira::ws ALIAS mira_ws)
target_include_directories(mira_ws PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_ws PUBLIC cxx_std_23)
target_link_libraries(mira_ws PUBLIC Mira::core Mira::crypto Mira::http_common ZLIB::ZLIB
    PRIVATE $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_ws PROPERTIES OUTPUT_NAME Mira-ws
    VERSION ${PROJECT_VERSION} EXPORT_NAME ws)
mira_install_module(mira_ws)
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
