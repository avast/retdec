
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        libyara
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-targets.cmake)
