
add_library(macho-extractor STATIC
	break_fat.cpp
)
add_library(retdec::macho-extractor ALIAS macho-extractor)

target_include_directories(macho-extractor
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(macho-extractor
	PUBLIC
		retdec::llvm
	PRIVATE
		retdec::utils
		retdec::rapidjson
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-macho-extractor-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/macho-extractor
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT macho-extractor
)

# Install libs.
install(TARGETS macho-extractor
	EXPORT macho-extractor-targets
	COMPONENT macho-extractor
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT macho-extractor-targets
	FILE "retdec-macho-extractor-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT macho-extractor
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-macho-extractor-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-macho-extractor-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT macho-extractor
)

