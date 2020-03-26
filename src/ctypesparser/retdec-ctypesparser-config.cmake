
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS ctypes utils rapidjson)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-ctypesparser-targets.cmake)
