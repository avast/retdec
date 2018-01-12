cmake_minimum_required(VERSION 3.6)

include(ExternalProject)

ExternalProject_Add(pelib-project
	URL https://github.com/avast-tl/pelib/archive/e93eaa7c150f4608a5d02a67f5edc9e54456fe24.zip
	URL_HASH SHA256=2ffd7e89451c980a1af6d24d4f6dfbb69a660b06ad5de44c481f6431e21de394
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
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
target_link_libraries(pelib INTERFACE debug     ${binary_dir}/src/pelib/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pelib INTERFACE optimized ${binary_dir}/src/pelib/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
