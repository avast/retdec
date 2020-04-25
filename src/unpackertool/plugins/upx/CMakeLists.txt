
add_library(unpacker-upx STATIC
	upx_stub_signatures.cpp
	upx.cpp
	pe/pe_upx_stub.cpp
	unfilter.cpp
	upx_stub.cpp
	macho/macho_upx_stub.cpp
	decompressors/decompressor_direct_jump.cpp
	decompressors/decompressor_scrambler.cpp
	decompressors/decompressor_upxshit.cpp
	decompressors/decompressor_nrv.cpp
	decompressors/decompressor_lzma.cpp
	decompressors/decompressor.cpp
	elf/elf_upx_stub.cpp
)
add_library(retdec::unpacker-upx ALIAS unpacker-upx)

target_compile_features(unpacker-upx PUBLIC cxx_std_17)

target_include_directories(unpacker-upx
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
		# not installed
)

target_link_libraries(unpacker-upx
	PUBLIC
		retdec::unpacker
		retdec::fileformat
		retdec::utils
)

set_target_properties(unpacker-upx
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker-upx"
)
