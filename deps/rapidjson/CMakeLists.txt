
add_library(rapidjson INTERFACE)
add_library(retdec::deps::rapidjson ALIAS rapidjson)

target_compile_definitions(rapidjson
	INTERFACE
		RAPIDJSON_HAS_STDSTRING=1
		RAPIDJSON_HAS_CXX11_RVALUE_REFS=1
)

target_include_directories(rapidjson
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/rapidjson/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
)

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/rapidjson/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install targets.
install(TARGETS rapidjson
	EXPORT rapidjson-targets
	# Header only -> there are no actual libs to install to destination.
)

# Export targets.
install(EXPORT rapidjson-targets
	FILE "retdec-rapidjson-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-rapidjson-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
