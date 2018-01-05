
cmake_minimum_required(VERSION 3.6)

if (NOT TARGET tinyxml2-project)

	include(ExternalProject)

	if(MSVC)
		set(PATCH_COMMAND patch < "${CMAKE_CURRENT_SOURCE_DIR}/tinyxml2-msvc.patch")
	endif()

	ExternalProject_Add(tinyxml2-project
		GIT_REPOSITORY https://github.com/leethomason/tinyxml2.git
		GIT_TAG 5.0.1
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Build only static library.
			-DBUILD_STATIC_LIBS:BOOL=ON
			-DBUILD_SHARED_LIBS:BOOL=OFF
			# Do not build tests.
			-DBUILD_TESTS:BOOL=OFF
		# We need to patch the source files because of the following reasons:
		# - Rename the DEBUG symbolic constant to TINYXML2_DEBUG to prevent
		#   name clashes.
		PATCH_COMMAND ${PATCH_COMMAND}
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
	target_link_libraries(tinyxml2 INTERFACE debug ${binary_dir}/${DEBUG_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tinyxml2${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_link_libraries(tinyxml2 INTERFACE optimized ${binary_dir}/${RELEASE_DIR}${CMAKE_FIND_LIBRARY_PREFIXES}tinyxml2${CMAKE_STATIC_LIBRARY_SUFFIX})
	target_include_directories(tinyxml2 SYSTEM INTERFACE ${TINYXML2_INCLUDE_DIR})
	add_dependencies(tinyxml2 tinyxml2-project)

endif()
