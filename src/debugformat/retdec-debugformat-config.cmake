
if(NOT TARGET retdec::debugformat)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            demangler
            loader
            fileformat
            common
            pdbparser
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-debugformat-targets.cmake)
endif()
