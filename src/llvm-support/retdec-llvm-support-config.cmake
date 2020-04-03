
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        utils
        llvm
)

if(NOT TARGET retdec::llvm-support)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvm-support-targets.cmake)
endif()
