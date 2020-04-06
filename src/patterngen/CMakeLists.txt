
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
		retdec::deps::yaramod
	PRIVATE
		retdec::fileformat
		retdec::utils
)

set_target_properties(patterngen
	PROPERTIES
		OUTPUT_NAME "retdec-patterngen"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/patterngen
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS patterngen
	EXPORT patterngen-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT patterngen-targets
	FILE "retdec-patterngen-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-patterngen-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-patterngen-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-patterngen-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
