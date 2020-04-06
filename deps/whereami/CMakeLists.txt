
add_library(whereami STATIC
	whereami.c
)
add_library(retdec::deps::whereami ALIAS whereami)

target_include_directories(whereami
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/whereami/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/whereami>
)

set_target_properties(whereami
	PROPERTIES
		OUTPUT_NAME "retdec-whereami"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/whereami/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(TARGETS whereami
	EXPORT whereami-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT whereami-targets
	FILE "retdec-whereami-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-whereami-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
