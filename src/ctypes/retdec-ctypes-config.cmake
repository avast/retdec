
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        utils
)

if(NOT TARGET retdec::ctypes)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypes-targets.cmake)
endif()
