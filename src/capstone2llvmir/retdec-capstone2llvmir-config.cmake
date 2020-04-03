
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        common
        capstone
        llvm
)

if(NOT TARGET retdec::capstone2llvmir)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone2llvmir-targets.cmake)
endif()
