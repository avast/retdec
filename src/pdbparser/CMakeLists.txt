
add_library(pdbparser STATIC
	pdb_file.cpp
	pdb_symbols.cpp
	pdb_types.cpp
	pdb_utils.cpp
)
add_library(retdec::pdbparser ALIAS pdbparser)

target_include_directories(pdbparser
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-pdbparser-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/pdbparser
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT pdbparser
)

# Install libs.
install(TARGETS pdbparser
	EXPORT pdbparser-targets
	COMPONENT pdbparser
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT pdbparser-targets
	FILE "retdec-pdbparser-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT pdbparser
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-pdbparser-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-pdbparser-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT pdbparser
)
