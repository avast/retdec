
add_library(stacofin STATIC
	stacofin.cpp
)
add_library(retdec::stacofin ALIAS stacofin)

target_compile_features(stacofin PUBLIC cxx_std_17)

target_include_directories(stacofin
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(stacofin
	PUBLIC
		retdec::config
		retdec::common
		retdec::deps::capstone
	PRIVATE
		retdec::loader
		retdec::yaracpp
		retdec::utils
)

set_target_properties(stacofin
	PROPERTIES
		OUTPUT_NAME "retdec-stacofin"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/stacofin
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS stacofin
	EXPORT stacofin-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT stacofin-targets
	FILE "retdec-stacofin-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-stacofin-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-stacofin-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-stacofin-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
