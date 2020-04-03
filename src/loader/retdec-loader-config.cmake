
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        fileformat
        common
        utils
)

if(NOT TARGET retdec::loader)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-loader-targets.cmake)
endif()
