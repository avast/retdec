
add_executable(unpackertool
	arg_handler.cpp
	unpacker.cpp
	plugin_mgr.cpp
)

target_include_directories(unpackertool
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
		# not installed
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
	RUNTIME DESTINATION bin
)

# Plugins.
add_subdirectory(plugins)
