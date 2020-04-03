
if(NOT TARGET retdec::yaracpp)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            libyara
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-targets.cmake)
endif()
