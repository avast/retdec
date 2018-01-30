include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

# Keystone requires python3, so we first check whether python3 is installed as
# "python3", and if not, we suppose that `python` runs python3.
# Python is used to generate LLVMBuild.cmake file. Python2 generates this file
# with UNIX paths, which do not work. Python3 generates proper Windows paths.
find_program(PYTHON_EXECUTABLE "python3")
if(NOT PYTHON_EXECUTABLE)
	find_program(PYTHON_EXECUTABLE "python")
endif()

ExternalProject_Add(keystone-project
	URL https://github.com/avast-tl/keystone/archive/4722974f58dbe878c805ce2b7c0a41cf6153903c.zip
	URL_HASH SHA256=145c8bb836d2f06f845b5015b3eab350ae59d35a54052f00f5d26445172415fd
	DOWNLOAD_NAME keystone.zip
	CMAKE_ARGS
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Force python version set in this cmake file.
		-DPYTHON_EXECUTABLE=${PYTHON_EXECUTABLE}
		-DKEYSTONE_BUILD_STATIC_RUNTIME=OFF
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
	# Disable the update step.
	UPDATE_COMMAND ""
	# Disable the install step.
	INSTALL_COMMAND ""
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
)

# Set include directories.
ExternalProject_Get_Property(keystone-project source_dir)
ExternalProject_Get_Property(keystone-project binary_dir)

# Add libraries.
add_library(keystone INTERFACE)
add_dependencies(keystone keystone-project)
target_include_directories(keystone SYSTEM INTERFACE ${source_dir}/include)
target_link_libraries(keystone INTERFACE debug ${binary_dir}/llvm/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}keystone${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(keystone INTERFACE optimized ${binary_dir}/llvm/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}keystone${CMAKE_STATIC_LIBRARY_SUFFIX})
