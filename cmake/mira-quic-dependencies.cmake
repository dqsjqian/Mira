include(CMakeFindDependencyMacro)
find_dependency(OpenSSL 3.5 COMPONENTS SSL Crypto)
find_path(MIRA_NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2_crypto_ossl.h REQUIRED)
find_library(MIRA_NGTCP2_LIBRARY NAMES ngtcp2 ngtcp2_static NAMES_PER_DIR REQUIRED)
find_library(MIRA_NGTCP2_OSSL_LIBRARY NAMES ngtcp2_crypto_ossl ngtcp2_crypto_ossl_static NAMES_PER_DIR REQUIRED)
if(NOT TARGET mira_ngtcp2)
    add_library(mira_ngtcp2 UNKNOWN IMPORTED)
    set_target_properties(mira_ngtcp2 PROPERTIES
        IMPORTED_LOCATION "${MIRA_NGTCP2_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MIRA_NGTCP2_INCLUDE_DIR}")
    if(WIN32)
        set_property(TARGET mira_ngtcp2 APPEND PROPERTY INTERFACE_LINK_LIBRARIES ws2_32)
        if(MIRA_NGTCP2_LIBRARY MATCHES "(_static[.]lib|[.]a)$")
            set_property(TARGET mira_ngtcp2 APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS NGTCP2_STATICLIB)
        endif()
    endif()
endif()
if(NOT TARGET mira_ngtcp2_ossl)
    add_library(mira_ngtcp2_ossl UNKNOWN IMPORTED)
    set_target_properties(mira_ngtcp2_ossl PROPERTIES
        IMPORTED_LOCATION "${MIRA_NGTCP2_OSSL_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MIRA_NGTCP2_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "mira_ngtcp2;OpenSSL::SSL;OpenSSL::Crypto")
    if(WIN32 AND MIRA_NGTCP2_OSSL_LIBRARY MATCHES "(_static[.]lib|[.]a)$")
        set_property(TARGET mira_ngtcp2_ossl APPEND PROPERTY INTERFACE_COMPILE_DEFINITIONS NGTCP2_STATICLIB)
    endif()
endif()
