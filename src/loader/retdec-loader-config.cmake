
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        fileformat
        common
        utils
)

if(NOT TARGET retdec::loader)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-loader-targets.cmake)
endif()
