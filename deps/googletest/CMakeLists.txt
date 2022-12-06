
find_package(Threads REQUIRED)

if(RETDEC_MSVC_STATIC_RUNTIME)
	set(FORCE_SHARED_RUNTIME OFF)
else()
	set(FORCE_SHARED_RUNTIME ON)
endif()

set(GOOGLETEST_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps/install/googletest)

if (MSVC)
	# Generator expressions screw up Ninja build, use them only for MSVC.
	# Googletest adds "d" suffix for MSVC debug build.
	# It does not seem this can be controlled from the outside.
	set(MSVC_DEBUG_LIB_SUFFIX $<$<AND:${MSVC_GE},$<CONFIG:Debug>>:d>)
else()
	set(MSVC_DEBUG_LIB_SUFFIX "")
endif()
set(GTEST_LIB      ${GOOGLETEST_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gtest${MSVC_DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})
set(GTEST_MAIN_LIB ${GOOGLETEST_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${MSVC_DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})
set(GMOCK_LIB      ${GOOGLETEST_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gmock${MSVC_DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})
set(GMOCK_MAIN_LIB ${GOOGLETEST_INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}gmock_main${MSVC_DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX})

# Generator expressions (possibly in MSVC_DEBUG_LIB_SUFFIX)
# cannot be in BUILD_BYPRODUCTS, do not set byproducts in MSVC
# (it is good only for Ninja build).
if (MSVC)
	set(GTEST_BYPRODUCTS "")
else()
	set(GTEST_BYPRODUCTS
		${GTEST_LIB}
		${GTEST_MAIN_LIB}
		${GMOCK_LIB}
		${GMOCK_MAIN_LIB}
	)
endif()

if(GOOGLETEST_LOCAL_DIR)
	message(STATUS "Googletest: using local Googletest directory.")
	set(GOOGLETEST_SOURCE_DIR "${GOOGLETEST_LOCAL_DIR}")
	set(_GOOGLETEST_URL "")
else()
	message(STATUS "Googletest: using remote Googletest revision.")
	set(GOOGLETEST_SOURCE_DIR "")
	set(_GOOGLETEST_URL "${GOOGLETEST_URL}")
endif()

ExternalProject_Add(googletest
	SOURCE_DIR ${GOOGLETEST_SOURCE_DIR}
	URL ${_GOOGLETEST_URL}
	URL_HASH SHA256=${GOOGLETEST_ARCHIVE_SHA256}
	DOWNLOAD_NAME googletest.zip
	CMAKE_ARGS
		-DCMAKE_INSTALL_PREFIX=${GOOGLETEST_INSTALL_DIR}
		# This does not work on MSVC, but is useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		# Without this, googletest's CMakeLists.txt replaces "/MD" (dynamic run-time) with "-MT" (static runtime).
		# Default config for most applications is "/MD", so this will cause problems if linked with "-MT" googletest.
		# https://msdn.microsoft.com/en-us/library/2kzt1wy3.aspx
		-Dgtest_force_shared_crt=${FORCE_SHARED_RUNTIME}
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
		-DCMAKE_POSITION_INDEPENDENT_CODE=${CMAKE_POSITION_INDEPENDENT_CODE}
		-DCMAKE_LIBTOOL=${CMAKE_LIBTOOL}
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
	BUILD_BYPRODUCTS
		${GTEST_BYPRODUCTS}
)
if(GOOGLETEST_LOCAL_DIR)
	force_configure_step(googletest)
endif()

check_if_variable_changed(GOOGLETEST_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(googletest binary_dir)
	message(STATUS "Googletest: path to Googletest directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

set(GTEST_INCLUDE_DIR ${GOOGLETEST_INSTALL_DIR}/include)
set(GMOCK_INCLUDE_DIR ${GOOGLETEST_INSTALL_DIR}/include)

# Create targets.

# gtest
add_library(gtest INTERFACE)
add_library(retdec::deps::gtest ALIAS gtest)
add_dependencies(gtest googletest)
target_link_libraries(gtest INTERFACE
	${GTEST_LIB}
	Threads::Threads
)
target_include_directories(gtest
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${GTEST_INCLUDE_DIR}>
)

# gtest_main
add_library(gtest_main INTERFACE)
add_library(retdec::deps::gtest_main ALIAS gtest_main)
target_link_libraries(gtest_main INTERFACE
	${GTEST_MAIN_LIB}
	gtest
)

# gmock
add_library(gmock INTERFACE)
add_library(retdec::deps::gmock ALIAS gmock)
target_link_libraries(gmock INTERFACE
	${GMOCK_LIB}
	gtest
)
target_include_directories(gmock
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${GMOCK_INCLUDE_DIR}>
)

# gmock_main
add_library(gmock_main INTERFACE)
add_library(retdec::deps::gmock_main ALIAS gmock_main)
target_link_libraries(gmock_main INTERFACE
	${GMOCK_MAIN_LIB}
	gmock
)
