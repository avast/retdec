
add_library(unpacker STATIC
	decompression/lzma/lzma_data.cpp
	decompression/nrv/nrv2d_data.cpp
	decompression/nrv/nrv2b_data.cpp
	decompression/nrv/nrv2e_data.cpp
	decompression/lzmat/lzmat_data.cpp
	signature.cpp
)
add_library(retdec::unpacker ALIAS unpacker)

target_compile_features(unpacker PUBLIC cxx_std_17)

target_include_directories(unpacker
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(unpacker
	PUBLIC
		retdec::loader
)

set_target_properties(unpacker
	PROPERTIES
		OUTPUT_NAME "retdec-unpacker"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/unpacker
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS unpacker
	EXPORT unpacker-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT unpacker-targets
	FILE "retdec-unpacker-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-unpacker-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-unpacker-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-unpacker-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
