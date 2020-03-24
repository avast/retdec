
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

target_include_directories(common
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(common
	PRIVATE retdec::utils
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/common/retdec-common-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/common
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT common
)

# Install libs.
install(TARGETS common
	EXPORT common-targets
	COMPONENT common
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT common-targets
	FILE "retdec-common-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT common
)

# Install CMake files.
install(
	FILES
		"${RETDEC_SHARE_DIR}/common/retdec-common-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/common/retdec-common-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT common
)
