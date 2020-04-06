
add_library(pdbparser STATIC
	pdb_file.cpp
	pdb_symbols.cpp
	pdb_types.cpp
	pdb_utils.cpp
)
add_library(retdec::pdbparser ALIAS pdbparser)

target_compile_features(pdbparser PUBLIC cxx_std_17)

target_include_directories(pdbparser
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

set_target_properties(pdbparser
	PROPERTIES
		OUTPUT_NAME "retdec-pdbparser"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/pdbparser
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS pdbparser
	EXPORT pdbparser-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT pdbparser-targets
	FILE "retdec-pdbparser-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-pdbparser-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
