include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(tinyxml2-project
	URL https://github.com/leethomason/tinyxml2/archive/cc1745b552dd12bb1297a99f82044f83b06729e0.zip
	URL_HASH SHA256=de255ce39ba1efe20cbffdebd3eea2d08f1269d03440a4fd60e142b0481c3f00
	DOWNLOAD_NAME tinyxml2.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Build only static library.
		-DBUILD_STATIC_LIBS:BOOL=ON
		-DBUILD_SHARED_LIBS:BOOL=OFF
		# Do not build tests.
		-DBUILD_TESTS:BOOL=OFF
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

# Set include directories.
ExternalProject_Get_Property(tinyxml2-project source_dir)
set(TINYXML2_INCLUDE_DIR ${source_dir})

# Add libraries.
ExternalProject_Get_Property(tinyxml2-project binary_dir)

if(MSVC)
	set(DEBUG_DIR "Debug/")
	set(RELEASE_DIR "Release/")
	set(DEBUG_LIB_SUFFIX "d")
endif()

add_library(tinyxml2 INTERFACE)
target_link_libraries(tinyxml2 INTERFACE debug ${binary_dir}/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}tinyxml2${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(tinyxml2 INTERFACE optimized ${binary_dir}/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}tinyxml2${CMAKE_STATIC_LIBRARY_SUFFIX})
target_include_directories(tinyxml2 SYSTEM INTERFACE ${TINYXML2_INCLUDE_DIR})
add_dependencies(tinyxml2 tinyxml2-project)
