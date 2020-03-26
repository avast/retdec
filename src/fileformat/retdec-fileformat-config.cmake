
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
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-fileformat-targets.cmake)
