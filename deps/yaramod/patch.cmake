file(GLOB_RECURSE YARAMOD_CMAKE_LISTS "${yaramod_path}/CMakeLists.txt")

foreach(cmake_list ${YARAMOD_CMAKE_LISTS})
	file(READ "${cmake_list}" YARAMOD_CMAKE)
	string(REGEX REPLACE
		"cmake_minimum_required[ \t]*\\([ \t]*VERSION[ \t]+3\\.[0-9.]+[ \t]*\\)"
		"cmake_minimum_required(VERSION 3.10)"
		YARAMOD_CMAKE
		"${YARAMOD_CMAKE}"
	)
	file(WRITE "${cmake_list}" "${YARAMOD_CMAKE}")
endforeach()
