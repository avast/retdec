
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        ctypes
        utils
        rapidjson
)

if(NOT TARGET retdec::ctypesparser)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypesparser-targets.cmake)
endif()
