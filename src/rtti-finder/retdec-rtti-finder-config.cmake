
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        loader
        common
        utils
)

if(NOT TARGET retdec::rtti-finder)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-rtti-finder-targets.cmake)
endif()
