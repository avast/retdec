
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        ctypes
        utils
        rapidjson
)

if(NOT TARGET retdec::ctypesparser)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypesparser-targets.cmake)
endif()
