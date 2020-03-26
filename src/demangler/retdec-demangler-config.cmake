
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS ctypesparser llvm)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-demangler-targets.cmake)
