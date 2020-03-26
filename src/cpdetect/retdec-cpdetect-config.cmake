
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        fileformat
        utils
        yaracpp
        llvm
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-cpdetect-targets.cmake)
