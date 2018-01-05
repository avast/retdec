
cmake_minimum_required(VERSION 3.6)

if (NOT TARGET capstone-project)

	include(ExternalProject)
	
	ExternalProject_Add(capstone-project
		GIT_REPOSITORY https://github.com/avast-tl/capstone.git
		GIT_TAG retdec-v1.0
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			-DCAPSTONE_BUILD_SHARED=OFF
			-DCAPSTONE_BUILD_STATIC_RUNTIME=OFF
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
		LOG_DOWNLOAD ON
		LOG_CONFIGURE ON
		LOG_BUILD ON
	)
	
	# Set include directories.
	ExternalProject_Get_Property(capstone-project source_dir)
	ExternalProject_Get_Property(capstone-project binary_dir)
	
	# Add libraries.
	add_library(capstone INTERFACE)
	add_dependencies(capstone capstone-project)
	target_include_directories(capstone SYSTEM INTERFACE ${source_dir}/include)
	target_link_libraries(capstone INTERFACE debug ${binary_dir}/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(capstone INTERFACE optimized ${binary_dir}/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})

endif()
