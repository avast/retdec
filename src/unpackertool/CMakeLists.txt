set(UNPACKERTOOL_SOURCES
	arg_handler.cpp
	unpacker.cpp
	plugin_mgr.cpp
)

add_executable(retdec-unpackertool ${UNPACKERTOOL_SOURCES})
set_target_properties(retdec-unpackertool PROPERTIES OUTPUT_NAME "retdec-unpacker")

target_link_libraries(retdec-unpackertool retdec-unpacker retdec-loader retdec-cpdetect retdec-utils pelib)
target_link_libraries(retdec-unpackertool retdec-unpacker-upx retdec-unpacker-mpress)

install(TARGETS retdec-unpackertool RUNTIME DESTINATION bin)

# Plugins.
add_subdirectory(plugins)
