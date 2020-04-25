
add_library(utils STATIC
	alignment.cpp
	byte_value_storage.cpp
	binary_path.cpp
	conversion.cpp
	dynamic_buffer.cpp
	file_io.cpp
	filesystem_path.cpp
	math.cpp
	memory.cpp
	string.cpp
	system.cpp
	time.cpp
)
add_library(retdec::utils ALIAS utils)

target_compile_features(utils PUBLIC cxx_std_17)

target_include_directories(utils
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(utils
	PRIVATE
		retdec::deps::whereami
)

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
