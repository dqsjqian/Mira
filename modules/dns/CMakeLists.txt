# Mira::dns — DNS message codec (RFC 1035/6891) and DoH mapping (RFC 8484).
add_library(mira_dns src/message.cpp src/doh.cpp)
add_library(Mira::dns ALIAS mira_dns)
target_include_directories(mira_dns PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(mira_dns PUBLIC cxx_std_23)
target_link_libraries(mira_dns PUBLIC Mira::core Mira::http Mira::http_common PRIVATE $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_dns PROPERTIES OUTPUT_NAME Mira-dns
    VERSION ${PROJECT_VERSION} EXPORT_NAME dns)
mira_install_module(mira_dns)
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
