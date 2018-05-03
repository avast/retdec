include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(pelib-project
	URL https://github.com/avast-tl/pelib/archive/9ccd3943c1a0917ffdaff5ab983fa7cdbb6dc5a2.zip
	URL_HASH SHA256=a502c9023a52b3f248b331ce3a12a04c1b668a1d077dc69e03ea86aa9b0543df
	DOWNLOAD_NAME pelib.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

ExternalProject_Get_Property(pelib-project source_dir)
ExternalProject_Get_Property(pelib-project binary_dir)

# Add libraries.
add_library(pelib INTERFACE)
add_dependencies(pelib pelib-project)
target_include_directories(pelib SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(pelib INTERFACE debug     ${binary_dir}/src/pelib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pelib INTERFACE optimized ${binary_dir}/src/pelib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
