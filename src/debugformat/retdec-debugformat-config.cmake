
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        demangler
        pdbparser
        fileformat
        loader
        common
        llvm
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-debugformat-targets.cmake)
