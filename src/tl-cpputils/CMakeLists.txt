
set(TL_CPPUTILS_SOURCES
	address.cpp
	alignment.cpp
	byte_value_storage.cpp
	conversion.cpp
	file_io.cpp
	filesystem_path.cpp
	math.cpp
	string.cpp
	system.cpp
	time.cpp
)

if(NOT TARGET tl-cpputils)

	add_library(tl-cpputils STATIC ${TL_CPPUTILS_SOURCES})
	if(MSVC)
		target_link_libraries(tl-cpputils shlwapi) # shlwapi.dll for PathRemoveFileSpec()
	endif()
	target_include_directories(tl-cpputils PUBLIC ${PROJECT_SOURCE_DIR}/include/)

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	# Any target that includes "windows.h" needs to define this.
	if(MSVC)
		target_compile_definitions(tl-cpputils PUBLIC NOMINMAX)
	endif()

endif()
