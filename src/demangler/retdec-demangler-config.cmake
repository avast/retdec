
if(NOT TARGET retdec::demangler)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            ctypesparser
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-demangler-targets.cmake)
endif()
