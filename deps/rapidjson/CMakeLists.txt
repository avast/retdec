include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(rapidjson-project
	URL https://github.com/Tencent/rapidjson/archive/v1.1.0.zip
	URL_HASH SHA256=8e00c38829d6785a2dfb951bb87c6974fa07dfe488aa5b25deec4b8bc0f6a3ab
	DOWNLOAD_NAME rapidjson.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DRAPIDJSON_BUILD_DOC=OFF
		-DRAPIDJSON_BUILD_EXAMPLES=OFF
		-DRAPIDJSON_BUILD_TESTS=OFF
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the build step.
	BUILD_COMMAND ""
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

ExternalProject_Get_Property(rapidjson-project source_dir)

# Add libraries.
add_library(rapidjson INTERFACE)
add_dependencies(rapidjson rapidjson-project)
target_include_directories(rapidjson SYSTEM INTERFACE ${source_dir}/include)
