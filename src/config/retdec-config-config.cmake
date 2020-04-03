
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        serdes
        common
        utils
        rapidjson
)

if(NOT TARGET retdec::config)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-config-targets.cmake)
endif()