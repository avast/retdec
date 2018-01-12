cmake_minimum_required(VERSION 3.6)

include(ExternalProject)

ExternalProject_Add(rapidjson-project
	URL https://github.com/Tencent/rapidjson/archive/v1.1.0.zip
	URL_HASH SHA256=8e00c38829d6785a2dfb951bb87c6974fa07dfe488aa5b25deec4b8bc0f6a3ab
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DRAPIDJSON_BUILD_DOC=OFF
		-DRAPIDJSON_BUILD_EXAMPLES=OFF
		-DRAPIDJSON_BUILD_TESTS=OFF
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
