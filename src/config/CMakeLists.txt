
add_library(config STATIC
	config.cpp
	parameters.cpp
)
add_library(retdec::config ALIAS config)

target_compile_features(config PUBLIC cxx_std_17)

target_include_directories(config PUBLIC
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(config
	PUBLIC
		retdec::common
		retdec::rapidjson
	PRIVATE
		retdec::serdes
		retdec::utils
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-config-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/config
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT config
)

# Install libs.
install(TARGETS config
	EXPORT config-targets
	COMPONENT config
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT config-targets
	FILE "retdec-config-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT config
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-config-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-config-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT config
)
