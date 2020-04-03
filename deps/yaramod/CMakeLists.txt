include(ExternalProject)

if(CMAKE_C_COMPILER)
	set(CMAKE_C_COMPILER_OPTION "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}")
endif()
if(CMAKE_CXX_COMPILER)
	set(CMAKE_CXX_COMPILER_OPTION "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}")
endif()

if(YARAMOD_LOCAL_DIR)
	message(STATUS "YaraMod: using local YaraMod directory.")

	ExternalProject_Add(yaramod-project
		DOWNLOAD_COMMAND ""
		SOURCE_DIR "${YARAMOD_LOCAL_DIR}"
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

# Add libraries.
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
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps>
)

target_link_libraries(yaramod INTERFACE
	debug
		$<BUILD_INTERFACE:${binary_dir}/src/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX}>
	optimized
		$<BUILD_INTERFACE:${binary_dir}/src/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX}>
	general
		$<BUILD_INTERFACE:${binary_dir}/deps/pog/deps/fmt/fmt/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX}>
		$<BUILD_INTERFACE:${binary_dir}/deps/pog/deps/re2/re2/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX}>
		$<INSTALL_INTERFACE:retdec::deps::yaramod-libs>
)

# Install libs.
# Install both Release and Debug variant to the same location.
# We assume that only one variant will be present at the time.
install(
    FILES
		${binary_dir}/src/${DEBUG_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/src/${RELEASE_DIR}${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/deps/pog/deps/fmt/fmt/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX}
		${binary_dir}/deps/pog/deps/re2/re2/${CMAKE_INSTALL_LIBDIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX}
    DESTINATION
		${RETDEC_INSTALL_LIB_DIR}
	OPTIONAL
)

list(APPEND YARAMOD_LIBS_INSTALLED "${CMAKE_INSTALL_PREFIX}/${RETDEC_INSTALL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX}")
list(APPEND YARAMOD_LIBS_INSTALLED "${CMAKE_INSTALL_PREFIX}/${RETDEC_INSTALL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX}")
list(APPEND YARAMOD_LIBS_INSTALLED "${CMAKE_INSTALL_PREFIX}/${RETDEC_INSTALL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX}")

# Configure config file.
configure_package_config_file(
	"retdec-yaramod-config.cmake"
	"${RETDEC_BINARY_SHARE_DIR}/retdec-yaramod-config.cmake"
	INSTALL_DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	PATH_VARS
		YARAMOD_LIBS_INSTALLED
)

# Install includes.
install(
	DIRECTORY
		${source_dir}/include/yaramod
	DESTINATION
		${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps
)

install(TARGETS yaramod
	EXPORT yaramod-targets
)

# Export targets.
install(EXPORT yaramod-targets
	FILE "retdec-yaramod-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${RETDEC_BINARY_SHARE_DIR}/retdec-yaramod-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
