set(UPX_SOURCES
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

add_library(retdec-unpacker-upx STATIC ${UPX_SOURCES})
target_link_libraries(retdec-unpacker-upx retdec-unpacker retdec-fileformat retdec-utils)
target_include_directories(retdec-unpacker-upx PUBLIC ${PROJECT_SOURCE_DIR}/src/)
