
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS llvm)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvmir-emul-targets.cmake)
