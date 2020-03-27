
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        loader
        common
        utils
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-rtti-finder-targets.cmake)
