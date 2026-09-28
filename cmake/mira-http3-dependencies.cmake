# QUIC is loaded first by MiraConfig; HTTP/3 adds only its framing engine.
find_path(MIRA_NGHTTP3_INCLUDE_DIR nghttp3/nghttp3.h REQUIRED)
find_library(MIRA_NGHTTP3_LIBRARY NAMES nghttp3 nghttp3_static NAMES_PER_DIR REQUIRED)
if(NOT TARGET mira_nghttp3)
    add_library(mira_nghttp3 UNKNOWN IMPORTED)
    set_target_properties(mira_nghttp3 PROPERTIES
        IMPORTED_LOCATION "${MIRA_NGHTTP3_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MIRA_NGHTTP3_INCLUDE_DIR}")
    if(WIN32 AND MIRA_NGHTTP3_LIBRARY MATCHES "(_static[.]lib|[.]a)$")
        set_property(TARGET mira_nghttp3 APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS NGHTTP3_STATICLIB)
    endif()
endif()
