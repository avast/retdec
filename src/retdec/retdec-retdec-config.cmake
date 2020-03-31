
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        bin2llvmir
        config
        common
        capstone
        llvm
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-targets.cmake)
