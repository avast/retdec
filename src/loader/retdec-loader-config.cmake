
if(NOT TARGET retdec::loader)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            fileformat
            common
            utils
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-loader-targets.cmake)
endif()
