
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        fileformat
        yaracpp
        utils
        tinyxml2
        llvm
)

if(NOT TARGET retdec::cpdetect)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-cpdetect-targets.cmake)
endif()
