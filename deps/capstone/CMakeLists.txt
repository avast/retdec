
if(RETDEC_USE_SYSTEM_CAPSTONE)
	message(STATUS "Capstone: using system Capstone.")

	include(FindPkgConfig)
	pkg_check_modules(CAPSTONE REQUIRED capstone>=5.0)

	add_library(capstone INTERFACE)
	add_library(retdec::deps::capstone ALIAS capstone)

	target_include_directories(capstone
		SYSTEM INTERFACE
			$<BUILD_INTERFACE:${CAPSTONE_INCLUDE_DIRS}>
			$<INSTALL_INTERFACE:${CAPSTONE_INCLUDE_DIRS}>
	)

	target_link_libraries(capstone INTERFACE
		$<BUILD_INTERFACE:${CAPSTONE_LINK_LIBRARIES}>
		$<INSTALL_INTERFACE:${CAPSTONE_LINK_LIBRARIES}>
	)

	# Install targets.
	install(TARGETS capstone
		EXPORT capstone-targets
	)

	# Export targets.
	install(EXPORT capstone-targets
		FILE "retdec-capstone-targets.cmake"
		NAMESPACE retdec::deps::
		DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	)

	# Install CMake files.
	install(
		FILES
			"${CMAKE_CURRENT_LIST_DIR}/retdec-system-capstone-config.cmake"
		DESTINATION
			"${RETDEC_INSTALL_CMAKE_DIR}"
		RENAME
			"retdec-capstone-config.cmake"
	)

	return()
endif()

set(CAPSTONE_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps/install/capstone)

set(CAPSTONE_LIB_NAME  ${CMAKE_STATIC_LIBRARY_PREFIX}capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
set(CAPSTONE_LIB_PNAME ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-capstone${CMAKE_STATIC_LIBRARY_SUFFIX})
set(CAPSTONE_LIB       ${CAPSTONE_INSTALL_DIR}/lib/${CAPSTONE_LIB_NAME})

if(CAPSTONE_LOCAL_DIR)
	message(STATUS "Capstone: using local Capstone directory.")
	set(CAPSTONE_SOURCE_DIR "${CAPSTONE_LOCAL_DIR}")
	set(_CAPSTONE_URL "")
else()
	message(STATUS "Capstone: using remote Capstone revision.")
	set(CAPSTONE_SOURCE_DIR "")
	set(_CAPSTONE_URL "${CAPSTONE_URL}")
endif()

ExternalProject_Add(capstone-project
	SOURCE_DIR ${CAPSTONE_SOURCE_DIR}
	URL ${_CAPSTONE_URL}
	URL_HASH SHA256=${CAPSTONE_ARCHIVE_SHA256}
	DOWNLOAD_NAME capstone.zip
	CMAKE_ARGS
		-DCMAKE_INSTALL_PREFIX=${CAPSTONE_INSTALL_DIR}
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCAPSTONE_BUILD_STATIC=ON
		-DCAPSTONE_BUILD_SHARED=OFF
		-DCAPSTONE_BUILD_STATIC_RUNTIME=${RETDEC_MSVC_STATIC_RUNTIME}
		-DCAPSTONE_BUILD_TESTS=OFF
		-DCAPSTONE_X86_ATT_DISABLE=OFF
		# Enabled architectures.
		-DCAPSTONE_ARM_SUPPORT=ON
		-DCAPSTONE_MIPS_SUPPORT=ON
		-DCAPSTONE_PPC_SUPPORT=ON
		-DCAPSTONE_X86_SUPPORT=ON
		-DCAPSTONE_ARM64_SUPPORT=ON
		# Disabled architectures.
		-DCAPSTONE_M68K_SUPPORT=OFF
		-DCAPSTONE_SPARC_SUPPORT=OFF
		-DCAPSTONE_SYSZ_SUPPORT=OFF
		-DCAPSTONE_XCORE_SUPPORT=OFF
		-DCAPSTONE_TMS320C64X_SUPPORT=OFF
		-DCAPSTONE_M680X_SUPPORT=OFF
		# Force the use of the same compiler as used to build the top-level
		# project. Otherwise, the external project may pick up a different
		# compiler, which may result in link errors.
		"${CMAKE_C_COMPILER_OPTION}"
		"${CMAKE_CXX_COMPILER_OPTION}"
		-DCMAKE_POSITION_INDEPENDENT_CODE=${CMAKE_POSITION_INDEPENDENT_CODE}
		-DCAPSTONE_INSTALL=ON
		-DCMAKE_LIBTOOL=${CMAKE_LIBTOOL}
	LOG_DOWNLOAD ON
	LOG_CONFIGURE ON
	LOG_BUILD ON
	BUILD_BYPRODUCTS
		${CAPSTONE_LIB}
)
if(CAPSTONE_LOCAL_DIR)
	force_configure_step(capstone-project)
endif()
ExternalProject_Add_Step(capstone-project movelib64
	WORKING_DIRECTORY ${CAPSTONE_INSTALL_DIR}
	DEPENDEES install
	# We cannot copy non-existing directory - it fails.
	# So we try to create it, if it already does exist, nothing happens.
	COMMAND ${CMAKE_COMMAND} -E make_directory lib64
	# If lib was created by Capstone install, and lib64 by us, lib64 is empty
	# and this should not replace lib content (i.e. capstone lib).
	COMMAND ${CMAKE_COMMAND} -E copy_directory lib64 lib
)

check_if_variable_changed(CAPSTONE_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(capstone-project binary_dir)
	message(STATUS "Capstone: path to Capstone directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(capstone-project source_dir)

# Create target.
add_library(capstone INTERFACE)
add_library(retdec::deps::capstone ALIAS capstone)
add_dependencies(capstone capstone-project)

target_include_directories(capstone
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${source_dir}/arch>
		$<BUILD_INTERFACE:${CAPSTONE_INSTALL_DIR}/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
)

target_link_libraries(capstone INTERFACE
		$<BUILD_INTERFACE:${CAPSTONE_LIB}>
		$<INSTALL_INTERFACE:retdec::deps::capstone-libs>
)

# Install includes.
install(
	DIRECTORY   ${CAPSTONE_INSTALL_DIR}/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(
	FILES       ${CAPSTONE_LIB}
	DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	RENAME      ${CAPSTONE_LIB_PNAME}
	OPTIONAL
)

# Install targets.
install(TARGETS capstone
	EXPORT capstone-targets
)

# Export targets.
install(EXPORT capstone-targets
	FILE "retdec-capstone-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Configure config file.
set(CAPSTONE_LIB_INSTALLED "${RETDEC_INSTALL_LIB_DIR_ABS}/${CAPSTONE_LIB_PNAME}")
configure_package_config_file(
	"retdec-capstone-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-capstone-config.cmake"
	INSTALL_DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	PATH_VARS
		CAPSTONE_LIB_INSTALLED
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-capstone-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
