
add_library(rapidjson INTERFACE)

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

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/rapidjson/include/rapidjson
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec/deps
)
