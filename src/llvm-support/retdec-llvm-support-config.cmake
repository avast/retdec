
if(NOT TARGET retdec::llvm-support)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            utils
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvm-support-targets.cmake)
endif()
