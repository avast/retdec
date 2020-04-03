
add_library(elfio INTERFACE)
add_library(retdec::deps::elfio ALIAS elfio)

target_include_directories(elfio
    SYSTEM INTERFACE
        $<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/elfio/include>
        $<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>/retdec/deps
)

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/elfio/include/elfio
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps
)

# Install libs.
install(TARGETS elfio
	EXPORT elfio-targets
	# Header only -> there are no actual libs to install to destination.
	# But this block is still needed to get proper config.
)

# Export targets.
install(EXPORT elfio-targets
	FILE "retdec-elfio-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-elfio-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
