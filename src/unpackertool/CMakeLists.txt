
add_library(unpackertool STATIC
	plugins/mpress/mpress.cpp
	plugins/upx/upx_stub_signatures.cpp
	plugins/upx/upx.cpp
	plugins/upx/pe/pe_upx_stub.cpp
	plugins/upx/unfilter.cpp
	plugins/upx/upx_stub.cpp
	plugins/upx/macho/macho_upx_stub.cpp
	plugins/upx/decompressors/decompressor_direct_jump.cpp
	plugins/upx/decompressors/decompressor_scrambler.cpp
	plugins/upx/decompressors/decompressor_upxshit.cpp
	plugins/upx/decompressors/decompressor_nrv.cpp
	plugins/upx/decompressors/decompressor_lzma.cpp
	plugins/upx/decompressors/decompressor.cpp
	plugins/upx/elf/elf_upx_stub.cpp
	arg_handler.cpp
	unpacker.cpp
	plugin_mgr.cpp
)
add_library(retdec::unpackertool ALIAS unpackertool)

target_compile_features(unpackertool PUBLIC cxx_std_17)

target_include_directories(unpackertool
	PRIVATE
		$<BUILD_INTERFACE:${RETDEC_SOURCE_DIR}>
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(unpackertool
	PUBLIC
		retdec::unpacker
		retdec::loader
		retdec::cpdetect
		retdec::utils
		retdec::pelib
)

set_target_properties(unpackertool
	PROPERTIES
		OUTPUT_NAME "retdec-unpackertool"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/unpackertool
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS unpackertool
	EXPORT unpackertool-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT unpackertool-targets
	FILE "retdec-unpackertool-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-unpackertool-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-unpackertool-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-unpackertool-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)

##########################################################################

add_executable(main
	main.cpp
)

target_compile_features(main PUBLIC cxx_std_17)

target_include_directories(main
	PRIVATE
		${RETDEC_SOURCE_DIR}
)

target_link_libraries(main
	retdec::unpackertool
)

set_target_properties(main
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker"
)

install(TARGETS main
	RUNTIME DESTINATION ${RETDEC_INSTALL_BIN_DIR}
)
