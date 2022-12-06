
set(YARAMOD_INSTALL_DIR ${CMAKE_BINARY_DIR}/deps/install/yaramod)

set(YARAMOD_LIB_NAME  ${CMAKE_STATIC_LIBRARY_PREFIX}yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
set(YARAMOD_LIB_PNAME ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-yaramod${CMAKE_STATIC_LIBRARY_SUFFIX})
set(YARAMOD_LIB       ${YARAMOD_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${YARAMOD_LIB_NAME})

set(FMT_LIB_NAME      ${CMAKE_STATIC_LIBRARY_PREFIX}pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX})
set(FMT_LIB_PNAME     ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-pog_fmt${CMAKE_STATIC_LIBRARY_SUFFIX})
set(FMT_LIB           ${YARAMOD_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${FMT_LIB_NAME})

set(RE2_LIB_NAME      ${CMAKE_STATIC_LIBRARY_PREFIX}pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX})
set(RE2_LIB_PNAME     ${CMAKE_STATIC_LIBRARY_PREFIX}retdec-pog_re2${CMAKE_STATIC_LIBRARY_SUFFIX})
set(RE2_LIB           ${YARAMOD_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${RE2_LIB_NAME})

if(YARAMOD_LOCAL_DIR)
	message(STATUS "YaraMod: using local YaraMod directory.")
	set(YARAMOD_SOURCE_DIR "${YARAMOD_LOCAL_DIR}")
	set(_YARAMOD_URL "")
else()
	message(STATUS "YaraMod: using remote YaraMod revision.")
	set(YARAMOD_SOURCE_DIR "")
	set(_YARAMOD_URL "${YARAMOD_URL}")
endif()

ExternalProject_Add(yaramod-project
	SOURCE_DIR ${YARAMOD_SOURCE_DIR}
	URL ${_YARAMOD_URL}
	URL_HASH SHA256=${YARAMOD_ARCHIVE_SHA256}
	DOWNLOAD_NAME yaramod.zip
	CMAKE_ARGS
		-DCMAKE_INSTALL_PREFIX=${YARAMOD_INSTALL_DIR}
		# This does not work on MSVC, but may be useful on Linux.
		-DCMAKE_BUILD_TYPE=Release
		-DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
		-DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
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
		${YARAMOD_LIB}
		${FMT_LIB}
		${RE2_LIB}
)
if(YARAMOD_LOCAL_DIR)
	force_configure_step(yaramod-project)
endif()

check_if_variable_changed(YARAMOD_LOCAL_DIR CHANGED)
if(CHANGED)
	ExternalProject_Get_Property(yaramod-project binary_dir)
	message(STATUS "YaraMod: path to YaraMod directory changed -> cleaning CMake files in ${binary_dir}.")
	clean_cmake_files(${binary_dir})
endif()

# Create target.
add_library(yaramod INTERFACE)
add_library(retdec::deps::yaramod ALIAS yaramod)
add_dependencies(yaramod yaramod-project)

target_include_directories(yaramod
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${YARAMOD_INSTALL_DIR}/include>
		$<BUILD_INTERFACE:${YARAMOD_INSTALL_DIR}/include/pog>
		$<BUILD_INTERFACE:${YARAMOD_INSTALL_DIR}/include/yaramod>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
)

target_link_libraries(yaramod
	INTERFACE
		$<BUILD_INTERFACE:${YARAMOD_LIB}>
		$<BUILD_INTERFACE:${FMT_LIB}>
		$<BUILD_INTERFACE:${RE2_LIB}>
		$<INSTALL_INTERFACE:retdec::deps::yaramod-libs>
)
if(WIN32)
	target_link_libraries(yaramod INTERFACE shlwapi)
endif()

# Install includes.
install(
	DIRECTORY   ${YARAMOD_INSTALL_DIR}/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(
    FILES       ${YARAMOD_LIB}
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
