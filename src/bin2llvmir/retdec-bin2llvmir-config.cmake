
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0
    REQUIRED
    COMPONENTS
        ctypesparser
        rtti-finder
        loader
        fileformat
        debugformat
        config
        demangler
        capstone2llvmir
        stacofin
        llvm-support
        common
        utils
        llvm
)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-bin2llvmir-targets.cmake)
