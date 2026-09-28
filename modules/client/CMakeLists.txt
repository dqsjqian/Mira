add_library(mira_client INTERFACE)
add_library(Mira::client ALIAS mira_client)
target_include_directories(mira_client INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(mira_client INTERFACE cxx_std_23)
target_link_libraries(mira_client INTERFACE Mira::http Mira::transport)
set_target_properties(mira_client PROPERTIES EXPORT_NAME client)
mira_install_module(mira_client)

if(MIRA_ENABLE_TLS)
    add_library(mira_client_tls INTERFACE)
    add_library(Mira::client_tls ALIAS mira_client_tls)
    target_link_libraries(mira_client_tls INTERFACE Mira::client Mira::tls)
    set_target_properties(mira_client_tls PROPERTIES EXPORT_NAME client_tls)
    mira_install_module(mira_client_tls)
endif()

if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
