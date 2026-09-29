# Mira::mqtt — MQTT 3.1.1/5.0 codec, socket-free client session, stream client.
add_library(mira_mqtt src/packet.cpp src/session.cpp)
add_library(Mira::mqtt ALIAS mira_mqtt)
target_include_directories(mira_mqtt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(mira_mqtt PUBLIC cxx_std_23)
target_link_libraries(mira_mqtt PUBLIC Mira::core PRIVATE $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_mqtt PROPERTIES OUTPUT_NAME Mira-mqtt
    VERSION ${PROJECT_VERSION} EXPORT_NAME mqtt)
mira_install_module(mira_mqtt)
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
