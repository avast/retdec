include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if(ELFIO_LOCAL_DIR)
	message(STATUS "ELFIO: using local ELFIO directory.")

	ExternalProject_Add(elfio-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${ELFIO_LOCAL_DIR}"
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
		# Disable the configure step - header only.
		CONFIGURE_COMMAND ""
		# Disable the build step.
		BUILD_COMMAND ""
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
	)
	force_configure_step(elfio-project)
else()
	message(STATUS "ELFIO: using remote ELFIO revision.")

	ExternalProject_Add(elfio-project
		URL https://github.com/avast/elfio/archive/f85f07390b756fee61408dfe0b04ae4fb86c5477.zip
		URL_HASH SHA256=bc821b602cad22de1d671f0314b1171e4bca7ca1aabc85eb2d32945ed8dfcc66
		DOWNLOAD_NAME elfio.zip
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			# Force the use of the same compiler as used to build the top-level
			# project. Otherwise, the external project may pick up a different
			# compiler, which may result in link errors.
			"${CMAKE_C_COMPILER_OPTION}"
			"${CMAKE_CXX_COMPILER_OPTION}"
		# Disable the configure step - header only.
		CONFIGURE_COMMAND ""
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
endif()

check_if_variable_changed(ELFIO_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(elfio-project binary_dir)
	message(STATUS "ELFIO: path to ELFIO directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(elfio-project source_dir)

# Add libraries.
add_library(elfio INTERFACE)
add_dependencies(elfio elfio-project)
target_include_directories(elfio SYSTEM INTERFACE ${source_dir}/include)
