
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        fileformat
        utils
        yaramod
)

if(NOT TARGET retdec::patterngen)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-patterngen-targets.cmake)
endif()
