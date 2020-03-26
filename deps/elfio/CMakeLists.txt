
add_library(elfio INTERFACE)
add_library(retdec::elfio ALIAS elfio)

target_include_directories(elfio
    SYSTEM INTERFACE
        $<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/elfio/include>
        $<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>/retdec/deps
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-elfio-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/elfio/include/elfio
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps
	COMPONENT elfio
)

# Install libs.
install(TARGETS elfio
	EXPORT elfio-targets
	COMPONENT elfio
	# Header only -> there are no actual libs to install to destination.
	# But this block is still needed to get proper config.
)

# Export targets.
install(EXPORT elfio-targets
	FILE "retdec-elfio-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT elfio
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-elfio-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-elfio-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT elfio
)
