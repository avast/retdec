
if(NOT TARGET retdec::fileformat)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            crypto
            common
            utils
            pelib
            elfio
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-fileformat-targets.cmake)
endif()
