include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if(PELIB_LOCAL_DIR)
	message(STATUS "PeLib: using local PeLib directory.")

	ExternalProject_Add(pelib-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${PELIB_LOCAL_DIR}"
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
	)
	force_configure_step(pelib-project)
else()
	message(STATUS "PeLib: using remote PeLib revision.")

	ExternalProject_Add(pelib-project
		URL https://github.com/avast-tl/pelib/archive/d6965e6d78eb37409e940e11dbc1298443cdbe49.zip
		URL_HASH SHA256=0771016fedeb820ab23daee3532bfc831604656479e10915f60cf36c628ae350
		DOWNLOAD_NAME pelib.zip
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
		# Force rebuild if switch happened.
		# Seems like this is not needed on Linux, and not working on Windows :-(
		BUILD_ALWAYS ${CHANGED}
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
		LOG_DOWNLOAD ON
		LOG_CONFIGURE ON
		LOG_BUILD ON
	)
endif()

check_if_variable_changed(PELIB_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(pelib-project binary_dir)
	message(STATUS "PeLib: path to PeLib directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(pelib-project source_dir)
ExternalProject_Get_Property(pelib-project binary_dir)

# Add libraries.
add_library(pelib INTERFACE)
add_dependencies(pelib pelib-project)
target_include_directories(pelib SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(pelib INTERFACE debug     ${binary_dir}/src/pelib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pelib INTERFACE optimized ${binary_dir}/src/pelib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}pelib${CMAKE_STATIC_LIBRARY_SUFFIX})
