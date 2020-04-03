
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

if(NOT TARGET retdec::debugformat)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-debugformat-targets.cmake)
endif()
