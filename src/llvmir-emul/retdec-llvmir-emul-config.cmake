
find_package(retdec @PROJECT_VERSION@
    REQUIRED
    COMPONENTS
        llvm
)

if(NOT TARGET retdec::llvmir-emul)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvmir-emul-targets.cmake)
endif()
