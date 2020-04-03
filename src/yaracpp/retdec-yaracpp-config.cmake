
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        libyara
)

if(NOT TARGET retdec::yaracpp)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-targets.cmake)
endif()
