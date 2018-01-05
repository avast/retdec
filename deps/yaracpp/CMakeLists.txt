
cmake_minimum_required(VERSION 3.6)

if (NOT TARGET yaracpp-project)

	include(ExternalProject)
	
	ExternalProject_Add(yaracpp-project
		GIT_REPOSITORY https://github.com/avast-tl/yaracpp.git
		GIT_TAG v1.0
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
	
	ExternalProject_Get_Property(yaracpp-project source_dir)
	ExternalProject_Get_Property(yaracpp-project binary_dir)
	
	# Add libraries.
	add_library(yaracpp INTERFACE)
	add_dependencies(yaracpp yaracpp-project)
	target_include_directories(yaracpp SYSTEM INTERFACE ${source_dir}/include)
	target_link_libraries(yaracpp INTERFACE debug     ${binary_dir}/src/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(yaracpp INTERFACE debug     ${binary_dir}/deps/yara/src/yara/libyara/.libs/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yara${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(yaracpp INTERFACE optimized ${binary_dir}/src/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yaracpp${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(yaracpp INTERFACE optimized ${binary_dir}/deps/yara/src/yara/libyara/.libs/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}yara${CMAKE_STATIC_LIBRARY_SUFFIX})

endif()
