
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        libyara
)

if(NOT TARGET retdec::yaracpp)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-targets.cmake)
endif()
