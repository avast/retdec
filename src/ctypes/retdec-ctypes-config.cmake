
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        utils
)

if(NOT TARGET retdec::ctypes)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypes-targets.cmake)
endif()
