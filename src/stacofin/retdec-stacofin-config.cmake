
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

if(NOT TARGET retdec::stacofin)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-stacofin-targets.cmake)
endif()
