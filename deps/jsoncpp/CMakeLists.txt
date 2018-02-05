include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(jsoncpp-project
	URL https://github.com/open-source-parsers/jsoncpp/archive/1.8.4.zip
	URL_HASH SHA256=2979436dbd4c48a3284dca9fa8f212298425ba3920ed6bacdda8905a94b111a8
	DOWNLOAD_NAME jsoncpp.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
		# Disable unused options.
		-DJSONCPP_WITH_TESTS=OFF
		-DJSONCPP_WITH_POST_BUILD_UNITTEST=OFF
		-DJSONCPP_WITH_PKGCONFIG_SUPPORT=OFF
		-DBUILD_SHARED_LIBS=OFF
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(jsoncpp-project source_dir)
set(JSONCPP_INCLUDE_DIR ${source_dir}/include)

# Add libraries.
ExternalProject_Get_Property(jsoncpp-project binary_dir)

if(MSVC)
	set(DEBUG_DIR "Debug/")
	set(RELEASE_DIR "Release/")
endif()

add_library(jsoncpp INTERFACE)
target_link_libraries(jsoncpp INTERFACE debug ${binary_dir}/src/lib_json/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}jsoncpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(jsoncpp INTERFACE optimized ${binary_dir}/src/lib_json/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}jsoncpp${CMAKE_STATIC_LIBRARY_SUFFIX})
target_include_directories(jsoncpp SYSTEM INTERFACE ${JSONCPP_INCLUDE_DIR})
add_dependencies(jsoncpp jsoncpp-project)
