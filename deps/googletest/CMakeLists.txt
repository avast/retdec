
find_package(Threads REQUIRED)

if(RETDEC_MSVC_STATIC_RUNTIME)
	set(FORCE_SHARED_RUNTIME OFF)
else()
	set(FORCE_SHARED_RUNTIME ON)
endif()

if(GOOGLETEST_LOCAL_DIR)
	message(STATUS "Googletest: using local Googletest directory.")

	ExternalProject_Add(googletest
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${GOOGLETEST_LOCAL_DIR}"
		CMAKE_ARGS
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
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
	)
	force_configure_step(googletest)
else()
	message(STATUS "Googletest: using remote Googletest revision.")

	ExternalProject_Add(googletest
		URL ${GOOGLETEST_URL}
		URL_HASH SHA256=${GOOGLETEST_ARCHIVE_SHA256}
		DOWNLOAD_NAME googletest.zip
		CMAKE_ARGS
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
		# Disable the update step.
		UPDATE_COMMAND ""
		# Disable the install step.
		INSTALL_COMMAND ""
		LOG_DOWNLOAD ON
		LOG_CONFIGURE ON
		LOG_BUILD ON
	)
endif()

check_if_variable_changed(GOOGLETEST_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(googletest binary_dir)
	message(STATUS "Googletest: path to Googletest directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(googletest source_dir)
ExternalProject_Get_Property(googletest binary_dir)

set(GTEST_INCLUDE_DIR ${source_dir}/googletest/include)
set(GMOCK_INCLUDE_DIR ${source_dir}/googlemock/include)

# Create targets.

# gtest
add_library(gtest INTERFACE)
add_library(retdec::deps::gtest ALIAS gtest)
add_dependencies(gtest googletest)
target_link_libraries(gtest INTERFACE
	debug
		${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}
	optimized
		${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX}
	general
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
	debug
		${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}
	optimized
		${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${CMAKE_STATIC_LIBRARY_SUFFIX}
	general
		gtest
)

# gmock
add_library(gmock INTERFACE)
add_library(retdec::deps::gmock ALIAS gmock)
target_link_libraries(gmock INTERFACE
	debug
		${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}
	optimized
		${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock${CMAKE_STATIC_LIBRARY_SUFFIX}
	general
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
	debug
		${binary_dir}/lib/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock_main${DEBUG_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}
	optimized
		${binary_dir}/lib/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}gmock_main${CMAKE_STATIC_LIBRARY_SUFFIX}
	general
		gmock
)
