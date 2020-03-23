
#include(${CMAKE_CURRENT_LIST_DIR}/retdec-common-targets.cmake)
#find_package(retdec 4.0 REQUIRED COMPONENTS utils)

get_filename_component(KURVA_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)
include(CMakeFindDependencyMacro)
list(APPEND CMAKE_MODULE_PATH ${KURVA_CMAKE_DIR})
find_dependency(retdec 4.0 REQUIRED COMPONENTS utils)
#find_package(retdec 4.0 REQUIRED COMPONENTS utils)
list(REMOVE_AT CMAKE_MODULE_PATH -1)
include(${CMAKE_CURRENT_LIST_DIR}/retdec-common-targets.cmake)
