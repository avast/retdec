
find_package(retdec @PROJECT_VERSION@ REQUIRED
    COMPONENTS
        utils
)

if(NOT TARGET retdec::common)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-common-targets.cmake)
endif()
