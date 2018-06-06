# Requirements.
find_package(FLEX REQUIRED)
find_package(BISON REQUIRED)

include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(yaramod-project
	URL https://github.com/avast-tl/yaramod/archive/v2.1.2.zip
	URL_HASH SHA256=85ff3fb144f1baa1321258852929ffe7a11db3dbb12ef95b8b5aa7fd9ff9bd9e
	DOWNLOAD_NAME yaramod.zip
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

ExternalProject_Get_Property(yaramod-project source_dir)
ExternalProject_Get_Property(yaramod-project binary_dir)

# Add libraries.
add_library(yaramod INTERFACE)
add_dependencies(yaramod yaramod-project)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/include)
target_include_directories(yaramod SYSTEM INTERFACE ${source_dir}/deps)
target_include_directories(yaramod SYSTEM INTERFACE ${binary_dir}/src)
target_include_directories(yaramod SYSTEM INTERFACE "${FLEX_INCLUDE_DIRS}")
target_link_libraries(yaramod INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(yaramod INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
