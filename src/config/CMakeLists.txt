
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
		retdec::deps::rapidjson
	PRIVATE
		retdec::serdes
		retdec::utils
)

set_target_properties(config
	PROPERTIES
		OUTPUT_NAME "retdec-config"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/config
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS config
	EXPORT config-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT config-targets
	FILE "retdec-config-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-config-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-config-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-config-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
