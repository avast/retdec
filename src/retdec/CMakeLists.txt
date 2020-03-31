
add_library(retdec STATIC
    retdec.cpp
)
add_library(retdec::retdec ALIAS retdec)

target_compile_features(retdec PUBLIC cxx_std_17)

target_include_directories(retdec
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(retdec
	PUBLIC
		retdec::common
		retdec::capstone
		retdec::llvm
	PRIVATE
		retdec::bin2llvmir
		retdec::config
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-retdec-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/retdec
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT retdec
)

# Install libs.
install(TARGETS retdec
	EXPORT retdec-targets
	COMPONENT retdec
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT retdec-targets
	FILE "retdec-retdec-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT retdec
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-retdec-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-retdec-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT retdec
)
