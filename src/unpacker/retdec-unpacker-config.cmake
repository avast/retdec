
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        loader
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-unpacker-targets.cmake)
