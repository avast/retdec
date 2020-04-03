
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        common
        rapidjson
)

if(NOT TARGET retdec::serdes)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-serdes-targets.cmake)
endif()
