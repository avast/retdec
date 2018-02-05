cmake_minimum_required(VERSION 3.6)
project(retdec C CXX)

# Set the default build type to 'Release'.
if(NOT CMAKE_BUILD_TYPE)
	set(default_build_type "Release")
	message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
	set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
endif()

option(RETDEC_DOC "Build public API documentation (requires Doxygen)." OFF)
option(RETDEC_TESTS "Build tests." OFF)
option(RETDEC_DEV_TOOLS "Build dev tools." OFF)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# On Linux and macOS, set RPATH relative to the origin of the installed
# executables (i.e. relative to the bin directory). This allows us to move the
# installation directory into a different location after installation, which is
# useful e.g. when the installation is performed on one machine but we want to
# run the executables on a different machine.
#
# On Windows, there is no need to set anything as DLLs are installed into the
# bin directory, where they are automatically picked up by executables.
#
# For more details, see
#  - https://github.com/avast-tl/retdec/issues/77
#  - https://cmake.org/Wiki/CMake_RPATH_handling
if(APPLE)
	set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
elseif(UNIX)
	set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()

# Build all external projects in the same directory that is directly inside the
# build directory. This reduces path lengths, which is important on Windows as
# there is a limit on how long a path can be.
set(EP_PREFIX "${PROJECT_BINARY_DIR}/external")
set_directory_properties(PROPERTIES EP_PREFIX "${EP_PREFIX}")

# Compilation warnings.
if(MSVC)
	# For the moment, suppress all warnings when building with MSVC on Windows
	# because there are too many warnings that clutter the build output (#106).
	# We should investigate the warnings, fix them, and then enable their
	# emission (e.g. by replacing /W0 with /W3 in the code below).
	if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W0" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	else()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")
	endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR
		CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR
		CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
	# Enable standard warnings.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

	# Enable additional warnings that are not included in -Wall and -Wextra.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wcast-align")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wcast-qual")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wswitch-default")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wuninitialized")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wold-style-cast")

	# Disable warnings that produce more headaches than use.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter")
endif()

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
