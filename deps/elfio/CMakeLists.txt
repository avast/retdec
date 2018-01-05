
cmake_minimum_required(VERSION 3.6)

if (NOT TARGET elfio-project)

	include(ExternalProject)
	
	ExternalProject_Add(elfio-project
		GIT_REPOSITORY https://github.com/avast-tl/elfio
		GIT_TAG v1.0
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
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
	
	ExternalProject_Get_Property(elfio-project source_dir)
	
	# Add libraries.
	add_library(elfio INTERFACE)
	add_dependencies(elfio elfio-project)
	target_include_directories(elfio SYSTEM INTERFACE ${source_dir}/include)

endif()
