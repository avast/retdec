
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        ctypesparser
        llvm
)

if(NOT TARGET retdec::demangler)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-demangler-targets.cmake)
endif()
