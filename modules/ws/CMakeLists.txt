find_package(ZLIB REQUIRED)
add_library(mira_ws src/frame.cpp src/handshake.cpp src/compression.cpp)
add_library(Mira::ws ALIAS mira_ws)
target_include_directories(mira_ws PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(mira_ws PUBLIC cxx_std_23)
target_link_libraries(mira_ws PUBLIC Mira::core Mira::crypto ZLIB::ZLIB
    PRIVATE $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_ws PROPERTIES OUTPUT_NAME Mira-ws
    VERSION ${PROJECT_VERSION} EXPORT_NAME ws)
mira_install_module(mira_ws)
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
