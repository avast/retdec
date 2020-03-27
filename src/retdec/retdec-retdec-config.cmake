
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        config
        utils
        llvm-support
        rapidjson
        llvm
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-targets.cmake)
