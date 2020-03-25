
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS common serdes utils)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-config-targets.cmake)
