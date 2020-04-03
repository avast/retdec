
if(NOT TARGET retdec::capstone2llvmir)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            common
            capstone
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone2llvmir-targets.cmake)
endif()
