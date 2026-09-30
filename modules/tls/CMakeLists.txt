find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)

add_library(mira_tls
    src/context.cpp
    src/engine.cpp
    src/error.cpp
)
add_library(Mira::tls ALIAS mira_tls)

target_include_directories(mira_tls PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_features(mira_tls PUBLIC cxx_std_23)
target_link_libraries(mira_tls
    PUBLIC Mira::core OpenSSL::SSL OpenSSL::Crypto
    # See modules/core/CMakeLists.txt for why this is wrapped.
    PRIVATE $<BUILD_INTERFACE:Mira::warnings>
)
set_target_properties(mira_tls PROPERTIES
    OUTPUT_NAME Mira-tls
    VERSION ${PROJECT_VERSION}
    # The build-tree ALIAS is Mira::tls; without EXPORT_NAME the export
    # uses the real target name and installs Mira::mira_tls instead,
    # so a consumer's link line would differ from an embedder's for no reason.
    EXPORT_NAME tls
)

mira_install_module(mira_tls)

if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
