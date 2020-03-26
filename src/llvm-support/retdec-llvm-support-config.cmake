
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS utils llvm)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvm-support-targets.cmake)
