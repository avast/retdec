
cmake_minimum_required(VERSION 3.6)

if (NOT TARGET rapidjson-project)

	include(ExternalProject)
	
	ExternalProject_Add(rapidjson-project
		GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
		GIT_TAG v1.1.0
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

endif()
