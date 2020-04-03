
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        rtti-finder
        capstone2llvmir
        debugformat
        demangler
        stacofin
        loader
        fileformat
        config
        ctypesparser
        common
        utils
        llvm-support
        llvm
)

if(NOT TARGET retdec::bin2llvmir)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-bin2llvmir-targets.cmake)
endif()
