# Shared field vocabulary and core-only session scheduling, without an HTTP/1
# or compression-engine dependency.
add_library(mira_http_common INTERFACE)
add_library(Mira::http_common ALIAS mira_http_common)
target_include_directories(mira_http_common INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_http_common INTERFACE cxx_std_23)
target_link_libraries(mira_http_common INTERFACE Mira::core)
set_target_properties(mira_http_common PROPERTIES EXPORT_NAME http_common)
mira_install_module(mira_http_common)
