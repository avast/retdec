
if(NOT TARGET retdec::retdec)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            bin2llvmir
            llvmir2hll
            config
            common
            capstone
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-targets.cmake)
endif()
