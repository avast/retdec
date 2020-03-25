
add_library(rapidjson INTERFACE)
add_library(retdec::rapidjson ALIAS rapidjson)

target_compile_definitions(rapidjson
	INTERFACE
		RAPIDJSON_HAS_STDSTRING=1
		RAPIDJSON_HAS_CXX11_RVALUE_REFS=1
)

target_include_directories(rapidjson
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/rapidjson/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>/retdec/deps
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-rapidjson-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/rapidjson/include/rapidjson
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps
	COMPONENT rapidjson
)

# Install libs.
install(TARGETS rapidjson
	EXPORT rapidjson-targets
	COMPONENT rapidjson
	# Header only -> there are no actual libs to install to destination.
	# But this block is still needed to get proper config.
)

# Export targets.
install(EXPORT rapidjson-targets
	FILE "retdec-rapidjson-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT rapidjson
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-rapidjson-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-rapidjson-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT rapidjson
)
