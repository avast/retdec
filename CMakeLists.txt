
cmake_minimum_required(VERSION 3.6)

project(retdec CXX)

# Set the default build type to 'Release'
if (NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

option(RETDEC_DOC "Build public API documentation (requires Doxygen)." OFF)
option(RETDEC_TESTS "Build tests." OFF)

# Build all external projects in the same directory that is directly inside the
# build directory. This reduces path lengths, which is important on Windows as
# there is a limit on how long a path can be.
set_directory_properties(PROPERTIES EP_PREFIX "${PROJECT_BINARY_DIR}/external")

set(DEPS_TESTS ${RETDEC_TESTS})
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/deps-config.cmake)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/install-external.cmake)

add_subdirectory(deps)
if(RETDEC_DOC)
	add_subdirectory(doc)
endif()
add_subdirectory(scripts)
add_subdirectory(src)
if(RETDEC_TESTS)
	add_subdirectory(tests)
endif()
