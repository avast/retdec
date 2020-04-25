
add_library(unpacker-mpress STATIC
	mpress.cpp
)
add_library(retdec::unpacker-mpress ALIAS unpacker-mpress)

target_compile_features(unpacker-mpress PUBLIC cxx_std_17)

target_include_directories(unpacker-mpress
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
		# not installed
)

target_link_libraries(unpacker-mpress
	PUBLIC
		retdec::unpacker
		retdec::fileformat
)

set_target_properties(unpacker-mpress
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker-mpress"
)
