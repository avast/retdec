
add_library(utils STATIC
	io/log.cpp
	io/logger.cpp
	alignment.cpp
	byte_value_storage.cpp
	binary_path.cpp
	conversion.cpp
	crc32.cpp
	dynamic_buffer.cpp
	file_io.cpp
	math.cpp
	memory.cpp
	ord_lookup.cpp
	string.cpp
	system.cpp
	time.cpp
	version.cpp
	${RETDEC_DEPS_DIR}/whereami/whereami/whereami.c
)
add_library(retdec::utils ALIAS utils)

target_compile_features(utils PUBLIC cxx_std_17)

target_compile_definitions(utils PRIVATE
	RETDEC_GIT_COMMIT_HASH="${RETDEC_GIT_COMMIT_HASH}"
	RETDEC_BUILD_DATE="${RETDEC_BUILD_DATE}"
	RETDEC_GIT_VERSION_TAG="${RETDEC_GIT_VERSION_TAG}"
)

target_include_directories(utils
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/whereami>
)

# We may need to link filesystem library manually.
find_library(STD_CPP_FS stdc++fs)
# Library found -> link against it.
if (STD_CPP_FS)
	message(STATUS "-- Library stdc++fs found -> Linking with ${STD_CPP_FS}")
	target_link_libraries(utils
		PRIVATE
			stdc++fs
	)
# Library not found & (Linux, BSD, Solaris, Minix) & GCC
elseif(UNIX AND (NOT APPLE) AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	message(STATUS "-- Library stdc++fs NOT found & Linux+GCC -> Linking with stdc++fs")
	target_link_libraries(utils
		PRIVATE
			stdc++fs
	)
# Library not found -> hope compiler does not need it.
elseif(NOT APPLE)
	message(STATUS "-- Library stdc++fs NOT found -> linking utils without stdc++fs library")
endif()

# Disable the min() and max() macros to prevent errors when using e.g.
# std::numeric_limits<...>::max()
# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
# Any target that includes "windows.h" needs to define this.
if(MSVC)
	target_compile_definitions(utils PUBLIC NOMINMAX)
endif()

set_target_properties(utils
	PROPERTIES
		OUTPUT_NAME "retdec-utils"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/utils
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS utils
	EXPORT utils-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT utils-targets
	FILE "retdec-utils-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-utils-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-utils-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-utils-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
