find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(mira_crypto src/crypto.cpp)
add_library(Mira::crypto ALIAS mira_crypto)
target_include_directories(mira_crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_crypto PUBLIC cxx_std_23)
target_link_libraries(mira_crypto PUBLIC Mira::core
    PRIVATE OpenSSL::Crypto $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_crypto PROPERTIES OUTPUT_NAME Mira-crypto EXPORT_NAME crypto)
mira_install_module(mira_crypto)
