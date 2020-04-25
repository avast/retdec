
if(NOT TARGET retdec::bin2llvmir)
    find_package(retdec @PROJECT_VERSION@
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

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-bin2llvmir-targets.cmake)
endif()
