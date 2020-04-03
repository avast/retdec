@PACKAGE_INIT@

if(NOT TARGET retdec::deps::openssl-crypto-libs)
    add_library(retdec::deps::openssl-crypto-libs STATIC IMPORTED)
    set_target_properties(retdec::deps::openssl-crypto-libs PROPERTIES
        IMPORTED_LOCATION @PACKAGE_OPENSSL_CRYPTO_LIB_INSTALLED@
    )
endif()

if(NOT TARGET retdec::deps::openssl-crypto)
    find_package(Threads REQUIRED)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-openssl-crypto-targets.cmake)
endif()
