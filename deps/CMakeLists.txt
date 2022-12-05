
include(ExternalProject)

include(ProcessorCount)
ProcessorCount(CPUS)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

set(MSVC_GE $<BOOL:${MSVC}>)
set(MSVC_CONFIG $<${MSVC_GE}:$<CONFIG>/>)

cond_add_subdirectory(stb RETDEC_ENABLE_STB)
cond_add_subdirectory(authenticode-parser RETDEC_ENABLE_AUTHENTICODE_PARSER)
cond_add_subdirectory(capstone RETDEC_ENABLE_CAPSTONE)
cond_add_subdirectory(elfio RETDEC_ENABLE_ELFIO)
cond_add_subdirectory(googletest RETDEC_ENABLE_GOOGLETEST)
cond_add_subdirectory(keystone RETDEC_ENABLE_KEYSTONE)
cond_add_subdirectory(llvm RETDEC_ENABLE_LLVM)
cond_add_subdirectory(rapidjson RETDEC_ENABLE_RAPIDJSON)
cond_add_subdirectory(tinyxml2 RETDEC_ENABLE_TINYXML2)
cond_add_subdirectory(yara RETDEC_ENABLE_YARA)
cond_add_subdirectory(yaramod RETDEC_ENABLE_YARAMOD)
cond_add_subdirectory(tlsh RETDEC_ENABLE_TLSH)
