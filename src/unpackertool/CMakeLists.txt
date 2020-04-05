
add_executable(unpackertool
	arg_handler.cpp
	unpacker.cpp
	plugin_mgr.cpp
)

target_compile_features(unpackertool PUBLIC cxx_std_17)

target_include_directories(unpackertool
	PRIVATE
		${RETDEC_SOURCE_DIR}
)

target_link_libraries(unpackertool
	retdec::unpacker
	retdec::unpacker-upx
	retdec::unpacker-mpress
	retdec::loader
	retdec::cpdetect
	retdec::utils
	retdec::pelib)

set_target_properties(unpackertool
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker"
)

install(TARGETS unpackertool
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)

# Plugins.
add_subdirectory(plugins)
