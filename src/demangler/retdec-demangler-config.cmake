
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        ctypesparser
        llvm
)

if(NOT TARGET retdec::demangler)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-demangler-targets.cmake)
endif()
