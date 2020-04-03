
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        common
        capstone
        llvm
)

if(NOT TARGET retdec::capstone2llvmir)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-capstone2llvmir-targets.cmake)
endif()
