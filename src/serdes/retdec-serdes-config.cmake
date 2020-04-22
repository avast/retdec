
if(NOT TARGET retdec::serdes)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            common
            rapidjson
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-serdes-targets.cmake)
endif()
