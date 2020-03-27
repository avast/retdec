
add_library(patterngen STATIC
	pattern_extractor/pattern_extractor.cpp
	pattern_extractor/types/symbol_pattern.cpp
)
add_library(retdec::patterngen ALIAS patterngen)

target_compile_features(patterngen PUBLIC cxx_std_17)

target_include_directories(patterngen
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(patterngen
	PUBLIC
		retdec::yaramod
	PRIVATE
		retdec::fileformat
		retdec::utils
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-patterngen-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/patterngen
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT patterngen
)

# Install libs.
install(TARGETS patterngen
	EXPORT patterngen-targets
	COMPONENT patterngen
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT patterngen-targets
	FILE "retdec-patterngen-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT patterngen
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-patterngen-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-patterngen-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT patterngen
)
