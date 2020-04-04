
if(NOT TARGET retdec::utils)
    find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        whereami
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-utils-targets.cmake)
endif()
