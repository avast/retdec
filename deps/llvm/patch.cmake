file(GLOB_RECURSE LLVM_CMAKE_LISTS "${llvm_path}/CMakeLists.txt")

foreach(cmake_list ${LLVM_CMAKE_LISTS})
	file(READ "${cmake_list}" LLVM_CMAKE)
	string(REPLACE
		"cmake_minimum_required(VERSION 3.4.3)"
		"cmake_minimum_required(VERSION 3.10)"
		LLVM_CMAKE
		"${LLVM_CMAKE}"
	)
	string(REPLACE
		"cmake_minimum_required (VERSION 2.8.12)"
		"cmake_minimum_required(VERSION 3.10)"
		LLVM_CMAKE
		"${LLVM_CMAKE}"
	)
	if(NOT LLVM_CMAKE MATCHES "CMP0148")
		string(REGEX REPLACE
			"(cmake_minimum_required\\([^)]*\\)\n)"
			"\\1if(POLICY CMP0148)\n  cmake_policy(SET CMP0148 OLD)\nendif()\n"
			LLVM_CMAKE
			"${LLVM_CMAKE}"
		)
	endif()
	file(WRITE "${cmake_list}" "${LLVM_CMAKE}")
endforeach()
