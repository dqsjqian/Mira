cmake_minimum_required(VERSION 3.25)
project(MiraDeviceSmoke LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(MIRA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(MIRA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(MIRA_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(MIRA_BUILD_FUZZERS OFF CACHE BOOL "" FORCE)
set(MIRA_INSTALL OFF CACHE BOOL "" FORCE)
set(MIRA_ENABLE_TLS OFF CACHE BOOL "" FORCE)
set(MIRA_ENABLE_WEBSOCKET OFF CACHE BOOL "" FORCE)
set(MIRA_ENABLE_HTTP2 OFF CACHE BOOL "" FORCE)
set(MIRA_ENABLE_HTTP3 OFF CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

get_filename_component(MIRA_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
add_subdirectory("${MIRA_SOURCE}" "${CMAKE_CURRENT_BINARY_DIR}/mira")

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
    if(NOT CMAKE_OSX_SYSROOT MATCHES "iphoneos|iPhoneOS" OR
       NOT CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        message(FATAL_ERROR "This target requires the physical iPhoneOS SDK and arm64")
    endif()
    if(NOT MIRA_SMOKE_BUNDLE_ID MATCHES "^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")
        message(FATAL_ERROR "Provide -DMIRA_SMOKE_BUNDLE_ID=<your.test.bundle.id>")
    endif()
    enable_language(OBJCXX)
    add_executable(mira_device_smoke MACOSX_BUNDLE
        App.mm "${MIRA_SOURCE}/examples/device_smoke.cpp")
    target_compile_definitions(mira_device_smoke PRIVATE MIRA_DEVICE_SMOKE_EMBEDDED=1)
    target_compile_options(mira_device_smoke PRIVATE "$<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>")
    target_link_libraries(mira_device_smoke PRIVATE "-framework UIKit" "-framework Foundation")
    set_target_properties(mira_device_smoke PROPERTIES
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
        MACOSX_BUNDLE_GUI_IDENTIFIER "${MIRA_SMOKE_BUNDLE_ID}"
        XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${MIRA_SMOKE_BUNDLE_ID}"
        XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2"
        XCODE_ATTRIBUTE_CODE_SIGN_STYLE "Manual"
        XCODE_ATTRIBUTE_ENABLE_BITCODE "NO")
    if(MIRA_SMOKE_TEAM AND MIRA_SMOKE_IDENTITY AND MIRA_SMOKE_PROFILE)
        set_target_properties(mira_device_smoke PROPERTIES
            XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "YES"
            XCODE_ATTRIBUTE_DEVELOPMENT_TEAM "${MIRA_SMOKE_TEAM}"
            XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "${MIRA_SMOKE_IDENTITY}"
            XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "${MIRA_SMOKE_PROFILE}")
    elseif(MIRA_SMOKE_TEAM OR MIRA_SMOKE_IDENTITY OR MIRA_SMOKE_PROFILE)
        message(FATAL_ERROR "Signing requires MIRA_SMOKE_TEAM, MIRA_SMOKE_IDENTITY and MIRA_SMOKE_PROFILE")
    endif()
else()
    add_executable(mira_device_smoke "${MIRA_SOURCE}/examples/device_smoke.cpp")
    enable_testing()
    add_test(NAME mira_device_smoke_host COMMAND mira_device_smoke)
    set_tests_properties(mira_device_smoke_host PROPERTIES TIMEOUT 30)
endif()

target_link_libraries(mira_device_smoke PRIVATE Mira::http Mira::transport Mira::warnings)
