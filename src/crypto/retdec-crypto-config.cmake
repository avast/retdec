
if(NOT TARGET retdec::crypto)
    find_package(Threads REQUIRED)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            utils
            openssl-crypto
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-crypto-targets.cmake)
endif()
