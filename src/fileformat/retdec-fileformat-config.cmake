
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        crypto
        common
        utils
        pelib
        elfio
        llvm
)

if(NOT TARGET retdec::fileformat)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-fileformat-targets.cmake)
endif()
