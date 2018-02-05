include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

ExternalProject_Add(elfio-project
	URL https://github.com/avast-tl/elfio/archive/1677a88d902d0fa6a5a7a31dc4da45748bba0bde.zip
	URL_HASH SHA256=a446b2751b177bde6c5bff5a3716a978918daba6f4953aeef3850036cb43fde7
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

ExternalProject_Get_Property(elfio-project source_dir)

# Add libraries.
add_library(elfio INTERFACE)
add_dependencies(elfio elfio-project)
target_include_directories(elfio SYSTEM INTERFACE ${source_dir}/include)
