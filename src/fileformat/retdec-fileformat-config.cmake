
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        crypto
        common
        utils
        pelib
        elfio
        llvm
        openssl-crypto
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-fileformat-targets.cmake)
