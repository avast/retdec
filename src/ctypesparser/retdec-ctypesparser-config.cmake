
if(NOT TARGET retdec::ctypesparser)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            ctypes
            utils
            rapidjson
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypesparser-targets.cmake)
endif()
