
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS common)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-serdes-targets.cmake)
