
cmake_minimum_required(VERSION 3.6)

# Requirements.
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

include(ExternalProject)

ExternalProject_Add(yaramod-project
	URL https://github.com/avast-tl/yaramod/archive/122610928203f4606276e1cb2552f04f6dd33c32.zip
	URL_HASH SHA256=7fac768ccc8699fc44c1bac1e9ebea8ab57654f34a53ff772b025e50fa66c760
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

ExternalProject_Get_Property(yaramod-project source_dir)
ExternalProject_Get_Property(yaramod-project binary_dir)

# Add libraries.
add_library(yaramod INTERFACE)
add_dependencies(yaramod yaramod-project)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/deps)
target_include_directories(yaramod SYSTEM INTERFACE ${binary_dir}/src)
target_include_directories(yaramod SYSTEM INTERFACE "${FLEX_INCLUDE_DIRS}")
target_link_libraries(yaramod INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaramod INTERFACE debug     ${binary_dir}/deps/tl-cpputils/src/tl-cpputils/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tl-cpputils${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaramod INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaramod INTERFACE optimized ${binary_dir}/deps/tl-cpputils/src/tl-cpputils/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tl-cpputils${CMAKE_STATIC_LIBRARY_SUFFIX})
