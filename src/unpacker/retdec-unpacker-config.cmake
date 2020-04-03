
if(NOT TARGET retdec::unpacker)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            loader
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-unpacker-targets.cmake)
endif()
