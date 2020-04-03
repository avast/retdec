
if(NOT TARGET retdec::cpdetect)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            fileformat
            yaracpp
            utils
            tinyxml2
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-cpdetect-targets.cmake)
endif()
