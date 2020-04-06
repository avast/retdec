
add_library(crypto STATIC
	crc32.cpp
	crypto.cpp
	hash_context.cpp
)
add_library(retdec::crypto ALIAS crypto)

target_compile_features(crypto PUBLIC cxx_std_17)

target_include_directories(crypto
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(crypto
	PUBLIC
		retdec::deps::openssl-crypto
	PRIVATE
		retdec::utils
)

set_target_properties(crypto
	PROPERTIES
		OUTPUT_NAME "retdec-crypto"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/crypto
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS crypto
	EXPORT crypto-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT crypto-targets
	FILE "retdec-crypto-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-crypto-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-crypto-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-crypto-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
