
find_package(Threads REQUIRED)
if(UNIX OR MINGW)
	find_package(ZLIB REQUIRED)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/retdec-llvm-targets.cmake)
