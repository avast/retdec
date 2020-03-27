
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        config
        common
        loader
        utils
        yaracpp
        capstone
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-stacofin-targets.cmake)
