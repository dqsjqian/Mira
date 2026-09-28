find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_NGHTTP2 QUIET libnghttp2)
endif()
find_path(NGHTTP2_INCLUDE_DIR nghttp2/nghttp2.h HINTS ${PC_NGHTTP2_INCLUDE_DIRS})
find_library(NGHTTP2_LIBRARY NAMES nghttp2 nghttp2_static HINTS ${PC_NGHTTP2_LIBRARY_DIRS})
if(NGHTTP2_INCLUDE_DIR)
    file(STRINGS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2ver.h" _nghttp2_version_line
         REGEX "^#define NGHTTP2_VERSION +\"")
    string(REGEX REPLACE ".*\"([^\"]+)\".*" "\\1" NGHTTP2_VERSION "${_nghttp2_version_line}")
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NGHTTP2 REQUIRED_VARS NGHTTP2_LIBRARY NGHTTP2_INCLUDE_DIR
                                  VERSION_VAR NGHTTP2_VERSION)
if(NGHTTP2_FOUND AND NOT TARGET NGHTTP2::NGHTTP2)
    add_library(NGHTTP2::NGHTTP2 UNKNOWN IMPORTED)
    set_target_properties(NGHTTP2::NGHTTP2 PROPERTIES
        IMPORTED_LOCATION "${NGHTTP2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP2_INCLUDE_DIR}"
        INTERFACE_COMPILE_DEFINITIONS NGHTTP2_NO_SSIZE_T)
    if(WIN32 AND NGHTTP2_LIBRARY MATCHES "(_static|\\.a$)")
        set_property(TARGET NGHTTP2::NGHTTP2 APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS NGHTTP2_STATICLIB)
    endif()
endif()
mark_as_advanced(NGHTTP2_INCLUDE_DIR NGHTTP2_LIBRARY)
