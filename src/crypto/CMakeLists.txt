
add_library(crypto STATIC
	crc32.cpp
	crypto.cpp
	hash_context.cpp
)
add_library(retdec::crypto ALIAS crypto)

target_include_directories(crypto
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(crypto
	PRIVATE
		retdec::utils
		openssl-crypto
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/crypto/retdec-crypto-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/crypto
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT crypto
)

# Install libs.
install(TARGETS crypto openssl-crypto
	EXPORT crypto-targets
	COMPONENT crypto
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT crypto-targets
	FILE "retdec-crypto-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT crypto
)

# Install CMake files.
install(
	FILES
		"${RETDEC_SHARE_DIR}/crypto/retdec-crypto-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/crypto/retdec-crypto-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT crypto
)
