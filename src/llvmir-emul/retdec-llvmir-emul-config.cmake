
find_package(retdec 4.0
    REQUIRED
    COMPONENTS
        llvm
)

if(NOT TARGET retdec::llvmir-emul)
    include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvmir-emul-targets.cmake)
endif()
