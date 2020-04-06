
add_library(common STATIC
	address.cpp
	architecture.cpp
	basic_block.cpp
	calling_convention.cpp
	class.cpp
	file_format.cpp
	file_type.cpp
	function.cpp
	language.cpp
	object.cpp
	pattern.cpp
	storage.cpp
	tool_info.cpp
	type.cpp
	vtable.cpp
)
add_library(retdec::common ALIAS common)

target_compile_features(common PUBLIC cxx_std_17)

target_include_directories(common
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(common
	PRIVATE
		retdec::utils
)

set_target_properties(common
	PROPERTIES
		OUTPUT_NAME "retdec-common"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/common
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS common
	EXPORT common-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT common-targets
	FILE "retdec-common-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-common-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-common-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-common-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
