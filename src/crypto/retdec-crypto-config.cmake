
include(CMakeFindDependencyMacro)
find_dependency(Threads REQUIRED)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        utils
        openssl-crypto
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-crypto-targets.cmake)
