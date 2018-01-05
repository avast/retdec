
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

add_library(upx SHARED ${UPX_SOURCES})
target_link_libraries(upx fileformat-headers)
target_include_directories(upx PUBLIC ${PROJECT_SOURCE_DIR}/src/)
# Plugin related libraries are linked to the plugin on Windows
if(MSVC OR APPLE)
	target_link_libraries(upx tl-cpputils unpacker)
endif()
install(TARGETS upx
	LIBRARY DESTINATION bin/unpacker-plugins
	RUNTIME DESTINATION bin/unpacker-plugins
)
