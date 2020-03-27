
add_library(stacofin STATIC
	stacofin.cpp
)
add_library(retdec::stacofin ALIAS stacofin)

target_compile_features(stacofin PUBLIC cxx_std_17)

target_include_directories(stacofin
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(stacofin
	PUBLIC
		retdec::config
		retdec::common
		retdec::capstone
	PRIVATE
		retdec::loader
		retdec::yaracpp
		retdec::utils
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-stacofin-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/stacofin
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT stacofin
)

# Install libs.
install(TARGETS stacofin
	EXPORT stacofin-targets
	COMPONENT stacofin
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT stacofin-targets
	FILE "retdec-stacofin-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT stacofin
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-stacofin-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-stacofin-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT stacofin
)
