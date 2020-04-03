
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        bin2llvmir
        config
        common
        capstone
        llvm
)

if(NOT TARGET retdec::retdec)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-targets.cmake)
endif()
