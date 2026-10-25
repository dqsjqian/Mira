add_library(mira_client INTERFACE)
add_library(Mira::client ALIAS mira_client)
target_include_directories(mira_client INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_client INTERFACE cxx_std_23)
target_link_libraries(mira_client INTERFACE Mira::http Mira::socks Mira::transport)
# Content-Encoding decoding (client/decompress.hpp) needs zlib, but only
# when the client actually decodes: without zlib the header still compiles
# and identity still works, while real codings fail with not_supported.
# http itself stays zlib-free by design, so the dependency lives here, at
# the composition layer that owns the convenience APIs.
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
    # A sysroot toolchain (e.g. conda gcc) leaves
    # CMAKE_LIBRARY_ARCHITECTURE empty, so find_library never looks in
    # the multiarch directory where the system libz actually lives
    # (/usr/lib/x86_64-linux-gnu, not /usr/lib). Retry against the
    # multiarch paths explicitly; this never fires on a normal system
    # compiler, and it only affects this target.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
        set(_mira_multiarch "x86_64-linux-gnu")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
        set(_mira_multiarch "aarch64-linux-gnu")
    endif()
    if(_mira_multiarch)
        # Prefer the static archive: linking the shared system libz would
        # put its directory first in the build RPATH, and under a sysroot
        # compiler that shadows the toolchain's libstdc++ with the older
        # system one (missing newer GLIBCXX symbols). The static archive
        # adds no runtime dependency and no RPATH entry at all.
        # Unset first: an earlier configure may have cached the shared
        # library, and find_library would otherwise keep it.
        unset(MIRA_CLIENT_ZLIB_LIBRARY CACHE)
        find_library(MIRA_CLIENT_ZLIB_LIBRARY NAMES libz.a NO_CMAKE_FIND_ROOT_PATH
            PATHS "/usr/lib/${_mira_multiarch}" "/usr/local/lib/${_mira_multiarch}")
    endif()
    if(NOT MIRA_CLIENT_ZLIB_LIBRARY AND _mira_multiarch)
        find_library(MIRA_CLIENT_ZLIB_LIBRARY NAMES z NO_CMAKE_FIND_ROOT_PATH
            PATHS "/usr/lib/${_mira_multiarch}" "/usr/local/lib/${_mira_multiarch}")
    endif()
    if(NOT MIRA_CLIENT_ZLIB_LIBRARY)
        find_library(MIRA_CLIENT_ZLIB_LIBRARY NAMES z NO_CMAKE_FIND_ROOT_PATH)
    endif()
    if(NOT ZLIB_INCLUDE_DIR)
        find_path(ZLIB_INCLUDE_DIR NAMES zlib.h NO_CMAKE_FIND_ROOT_PATH)
    endif()
    if(MIRA_CLIENT_ZLIB_LIBRARY AND ZLIB_INCLUDE_DIR)
        add_library(ZLIB::ZLIB UNKNOWN IMPORTED)
        set_target_properties(ZLIB::ZLIB PROPERTIES
            IMPORTED_LOCATION "${MIRA_CLIENT_ZLIB_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${ZLIB_INCLUDE_DIR}")
        # CMake never emits -I for /usr/include (it treats that path as an
        # implicit system directory), but a sysroot compiler does not search
        # the host /usr/include by default — so the include dir must also
        # travel as a raw compile option, which CMake does not filter.
        # -isystem (not -I) keeps the headers' system-header warning
        # exemption under this repo's -Werror build. Build-tree only, like
        # the link and the define below.
        target_compile_options(mira_client INTERFACE "$<BUILD_INTERFACE:-isystem${ZLIB_INCLUDE_DIR}>")
        set(ZLIB_FOUND TRUE)
    endif()
endif()
if(ZLIB_FOUND)
    # Build-tree only. The installed client must stay consumable without
    # zlib — the install-consumer script disables ZLIB lookup for the
    # client case — so neither the link nor the define may leak into the
    # exported target. Installed consumers that want gzip/deflate define
    # MIRA_CLIENT_HAS_ZLIB themselves and link ZLIB::ZLIB (see
    # decompress.hpp); without that, the header compiles in no-zlib mode
    # and real codings fail with not_supported, exactly as here.
    target_link_libraries(mira_client INTERFACE $<BUILD_INTERFACE:ZLIB::ZLIB>)
    target_compile_definitions(mira_client INTERFACE $<BUILD_INTERFACE:MIRA_CLIENT_HAS_ZLIB=1>)
endif()
set_target_properties(mira_client PROPERTIES EXPORT_NAME client)
mira_install_module(mira_client)

if(MIRA_ENABLE_TLS)
    add_library(mira_client_tls INTERFACE)
    add_library(Mira::client_tls ALIAS mira_client_tls)
    target_link_libraries(mira_client_tls INTERFACE Mira::client Mira::tls)
    set_target_properties(mira_client_tls PROPERTIES EXPORT_NAME client_tls)
    mira_install_module(mira_client_tls)
endif()

if(MIRA_ENABLE_HTTP2 AND MIRA_ENABLE_TLS)
    add_library(mira_client_http2 INTERFACE)
    add_library(Mira::client_http2 ALIAS mira_client_http2)
    target_link_libraries(mira_client_http2 INTERFACE Mira::client Mira::http2 Mira::tls)
    set_target_properties(mira_client_http2 PROPERTIES EXPORT_NAME client_http2)
    mira_install_module(mira_client_http2)
endif()
if(MIRA_ENABLE_HTTP3)
    add_library(mira_client_http3 INTERFACE)
    add_library(Mira::client_http3 ALIAS mira_client_http3)
    target_link_libraries(mira_client_http3 INTERFACE Mira::client Mira::http3)
    set_target_properties(mira_client_http3 PROPERTIES EXPORT_NAME client_http3)
    mira_install_module(mira_client_http3)
endif()

if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
