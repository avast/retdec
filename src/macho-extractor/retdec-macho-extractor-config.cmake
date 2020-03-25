
include(CMakeFindDependencyMacro)
find_dependency(retdec 4.0 REQUIRED COMPONENTS utils rapidjson llvm)

include(${CMAKE_CURRENT_LIST_DIR}/retdec-macho-extractor-targets.cmake)
