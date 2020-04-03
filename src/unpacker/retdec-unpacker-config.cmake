
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        loader
)

if(NOT TARGET retdec::unpacker)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-unpacker-targets.cmake)
endif()
