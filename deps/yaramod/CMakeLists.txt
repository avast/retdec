
if(YARAMOD_LOCAL_DIR)
	message(STATUS "YaraMod: using local YaraMod directory.")

	ExternalProject_Add(yaramod-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${YARAMOD_LOCAL_DIR}"
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
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
	force_configure_step(yaramod-project)
else()
	message(STATUS "YaraMod: using remote YaraMod revision.")

	ExternalProject_Add(yaramod-project
		URL ${YARAMOD_URL}
		URL_HASH SHA256=${YARAMOD_ARCHIVE_SHA256}
		DOWNLOAD_NAME yaramod.zip
		CMAKE_ARGS
			# This does not work on MSVC, but may be useful on Linux.
			-DCMAKE_BUILD_TYPE=Release
			-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
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

check_if_variable_changed(YARAMOD_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(yaramod-project binary_dir)
	message(STATUS "YaraMod: path to YaraMod directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

ExternalProject_Get_Property(yaramod-project source_dir)
ExternalProject_Get_Property(yaramod-project binary_dir)

set(YARAMOD_LIB_NAME  ${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
set(YARAMOD_LIB_PNAME ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
set(YARAMOD_LIB_OPT   ${binary_dir}/src/${RELEASE_DIR}${YARAMOD_LIB_NAME})
set(YARAMOD_LIB_DEBUG ${binary_dir}/src/${DEBUG_DIR}${YARAMOD_LIB_NAME})

set(FMT_LIB_NAME      ${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX})
set(FMT_LIB_PNAME     ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX})
set(FMT_LIB           ${binary_dir}/deps/pog/deps/fmt/fmt/${CMAKE_INSTALL_LIBDIR}/${FMT_LIB_NAME})

set(RE2_LIB_NAME      ${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX})
set(RE2_LIB_PNAME     ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX})
set(RE2_LIB           ${binary_dir}/deps/pog/deps/re2/re2/${CMAKE_INSTALL_LIBDIR}/${RE2_LIB_NAME})

# Create target.
add_library(yaramod INTERFACE)
add_library(retdec::deps::yaramod ALIAS yaramod)
add_dependencies(yaramod yaramod-project)

target_include_directories(yaramod
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${source_dir}/include>
		$<BUILD_INTERFACE:${source_dir}/deps>
		$<BUILD_INTERFACE:${source_dir}/deps/pog/include>
		$<BUILD_INTERFACE:${source_dir}/deps/pog/include/pog>
		$<BUILD_INTERFACE:${source_dir}/deps/pog/deps/fmt/fmt/include>
		$<BUILD_INTERFACE:${source_dir}/deps/pog/deps/re2/re2>
		$<BUILD_INTERFACE:${binary_dir}/src>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
)

target_link_libraries(yaramod INTERFACE
	debug
		$<BUILD_INTERFACE:${YARAMOD_LIB_DEBUG}>
	optimized
		$<BUILD_INTERFACE:${YARAMOD_LIB_OPT}>
	general
		$<BUILD_INTERFACE:${FMT_LIB}>
		$<BUILD_INTERFACE:${RE2_LIB}>
		$<INSTALL_INTERFACE:retdec::deps::yaramod-libs>
)
if(WIN32)
	target_link_libraries(yaramod INTERFACE shlwapi)
endif()

# Install includes.
install(
	DIRECTORY   ${source_dir}/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
# Install both Release and Debug variant to the same location.
# We assume that only one variant will be present at the time.
install(
    FILES       ${YARAMOD_LIB_DEBUG}
    DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	RENAME      ${YARAMOD_LIB_PNAME}
	OPTIONAL
)
install(
    FILES       ${YARAMOD_LIB_OPT}
	DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	RENAME      ${YARAMOD_LIB_PNAME}
	OPTIONAL
)
install(
    FILES       ${FMT_LIB}
    DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	RENAME      ${FMT_LIB_PNAME}
	OPTIONAL
)
install(
    FILES       ${RE2_LIB}
	DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	RENAME      ${RE2_LIB_PNAME}
	OPTIONAL
)


# Install targets.
install(TARGETS yaramod
	EXPORT yaramod-targets
)

# Export targets.
install(EXPORT yaramod-targets
	FILE "retdec-yaramod-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Configure config file.
list(APPEND YARAMOD_LIBS_INSTALLED "${RETDEC_INSTALL_LIB_DIR_ABS}/${YARAMOD_LIB_PNAME}")
list(APPEND YARAMOD_LIBS_INSTALLED "${RETDEC_INSTALL_LIB_DIR_ABS}/${FMT_LIB_PNAME}")
list(APPEND YARAMOD_LIBS_INSTALLED "${RETDEC_INSTALL_LIB_DIR_ABS}/${RE2_LIB_PNAME}")
configure_package_config_file(
	"retdec-yaramod-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-yaramod-config.cmake"
	INSTALL_DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	PATH_VARS
		YARAMOD_LIBS_INSTALLED
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-yaramod-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
