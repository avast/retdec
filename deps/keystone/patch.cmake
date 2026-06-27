file(GLOB_RECURSE KEYSTONE_CMAKE_LISTS "${keystone_path}/CMakeLists.txt")

foreach(cmake_list ${KEYSTONE_CMAKE_LISTS})
	file(READ "${cmake_list}" KEYSTONE_CMAKE)
	string(REPLACE
		"cmake_minimum_required(VERSION 2.8.7)"
		"cmake_minimum_required(VERSION 3.10)"
		KEYSTONE_CMAKE
		"${KEYSTONE_CMAKE}"
	)
	string(REPLACE
		"cmake_policy(SET CMP0051 OLD)"
		"cmake_policy(SET CMP0051 NEW)"
		KEYSTONE_CMAKE
		"${KEYSTONE_CMAKE}"
	)
	if(NOT KEYSTONE_CMAKE MATCHES "CMP0148")
		string(REGEX REPLACE
			"(cmake_minimum_required\\([^)]*\\)\n)"
			"\\1if(POLICY CMP0148)\n  cmake_policy(SET CMP0148 OLD)\nendif()\n"
			KEYSTONE_CMAKE
			"${KEYSTONE_CMAKE}"
		)
	endif()
	file(WRITE "${cmake_list}" "${KEYSTONE_CMAKE}")
endforeach()

file(READ "${keystone_path}/llvm/include/llvm/ADT/STLExtras.h" KEYSTONE_STL_EXTRAS)

if(NOT KEYSTONE_STL_EXTRAS MATCHES "#[ \t]*include[ \t]*<cstdint>")
	string(REGEX REPLACE
		"(#include <utility>[^\n]*\n)"
		"\\1#include <cstdint>\n"
		KEYSTONE_STL_EXTRAS
		"${KEYSTONE_STL_EXTRAS}"
	)
	file(WRITE "${keystone_path}/llvm/include/llvm/ADT/STLExtras.h" "${KEYSTONE_STL_EXTRAS}")
endif()
