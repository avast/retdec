
find_package(Threads REQUIRED)
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        utils
        openssl-crypto
)

if(NOT TARGET retdec::crypto)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-crypto-targets.cmake)
endif()
