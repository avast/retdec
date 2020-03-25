
add_library(yaracpp STATIC
	types/yara_match.cpp
	types/yara_meta.cpp
	types/yara_rule.cpp
	yara_detector/yara_detector.cpp
)
add_library(retdec::yaracpp ALIAS yaracpp)

target_include_directories(yaracpp
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(yaracpp
	PRIVATE libyara
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-yaracpp-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/yaracpp
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT yaracpp
)

# Install libs.
install(TARGETS yaracpp libyara
	EXPORT yaracpp-targets
	COMPONENT yaracpp
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT yaracpp-targets
	FILE "retdec-yaracpp-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT yaracpp
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-yaracpp-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-yaracpp-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT yaracpp
)
