# Mira::socks — SOCKS5 (RFC 1928/1929) over core's bounded stream seam.
add_library(mira_socks src/socks5.cpp)
add_library(Mira::socks ALIAS mira_socks)
target_include_directories(mira_socks PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(mira_socks PUBLIC cxx_std_23)
target_link_libraries(mira_socks PUBLIC Mira::core PRIVATE $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_socks PROPERTIES OUTPUT_NAME Mira-socks
    VERSION ${PROJECT_VERSION} EXPORT_NAME socks)
mira_install_module(mira_socks)
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
