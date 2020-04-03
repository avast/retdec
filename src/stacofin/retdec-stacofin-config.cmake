
if(NOT TARGET retdec::stacofin)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            loader
            config
            common
            yaracpp
            utils
            capstone
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-stacofin-targets.cmake)
endif()
