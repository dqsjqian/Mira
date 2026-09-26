# 已验证依赖：nghttp3 1.15.0（MIT），不自动下载依赖。
# nghttp3-1.15.0.tar.xz SHA256:
# 6da0cd06b428d32a54c58137838505d9dc0371a900bb8070a46b29e1ceaf2e0f
# 官方源码：https://github.com/ngtcp2/nghttp3/releases/download/v1.15.0/nghttp3-1.15.0.tar.xz
find_path(MIRA_NGHTTP3_INCLUDE_DIR nghttp3/nghttp3.h REQUIRED)
find_library(MIRA_NGHTTP3_LIBRARY NAMES nghttp3 REQUIRED)
if(NOT TARGET mira_nghttp3)
    add_library(mira_nghttp3 UNKNOWN IMPORTED GLOBAL)
    set_target_properties(mira_nghttp3 PROPERTIES IMPORTED_LOCATION "${MIRA_NGHTTP3_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${MIRA_NGHTTP3_INCLUDE_DIR}")
endif()
add_library(mira_http3 src/engine.cpp)
add_library(Mira::http3 ALIAS mira_http3)
target_include_directories(mira_http3 PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(mira_http3 PUBLIC cxx_std_23)
# 加密随机源由 Mira::quic 提供；本模块不直接依赖 TLS 后端。
# 公共头部类型（http2/headers.hpp 的 Header/Headers）：HPACK 与 QPACK 的
# 字段区块语义相同，http3 直接复用同一类型，故此处是 PUBLIC 依赖。
target_link_libraries(mira_http3 PUBLIC Mira::quic Mira::http2
    PRIVATE mira_nghttp3 $<BUILD_INTERFACE:Mira::warnings>)
set_target_properties(mira_http3 PROPERTIES OUTPUT_NAME Mira-http3 EXPORT_NAME http3)
if(COMMAND mira_install_module)
    mira_install_module(mira_http3)
endif()
if(MIRA_BUILD_TESTS)
    add_subdirectory(tests)
endif()
