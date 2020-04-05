
if(NOT TARGET retdec::llvmir-emul)
    find_package(retdec @PROJECT_VERSION@
        REQUIRED
        COMPONENTS
            llvm
    )

    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvmir-emul-targets.cmake)
endif()
