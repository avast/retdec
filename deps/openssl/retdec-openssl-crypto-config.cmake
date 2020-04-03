@PACKAGE_INIT@

find_package(Threads REQUIRED)

if(NOT TARGET retdec::openssl-crypto-libs)
    add_library(retdec::openssl-crypto-libs STATIC IMPORTED)
    set_target_properties(retdec::openssl-crypto-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_OPENSSL_CRYPTO_LIB_INSTALLED@
    )
endif()

if(NOT TARGET retdec::openssl-crypto)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-openssl-crypto-targets.cmake)
endif()
