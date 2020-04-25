
add_library(unpacker-example STATIC
	example.cpp
)
add_library(retdec::unpacker-example ALIAS unpacker-example)

target_compile_features(unpacker-example PUBLIC cxx_std_17)

target_include_directories(unpacker-example
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
		# not installed
)

target_link_libraries(unpacker-example
	PUBLIC
		retdec::unpacker
		retdec::fileformat
)

set_target_properties(unpacker-example
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker-example"
)
