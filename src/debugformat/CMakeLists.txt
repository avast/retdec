
add_library(debugformat STATIC
	debugformat.cpp
	dwarf.cpp
	pdb.cpp
)
add_library(retdec::debugformat ALIAS debugformat)

target_compile_features(debugformat PUBLIC cxx_std_17)

target_include_directories(debugformat
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(debugformat
	PUBLIC
		retdec::loader
		retdec::fileformat
		retdec::demangler
		retdec::common
		retdec::pdbparser
		retdec::llvm
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-debugformat-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/debugformat
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT debugformat
)

# Install libs.
install(TARGETS debugformat
	EXPORT debugformat-targets
	COMPONENT debugformat
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT debugformat-targets
	FILE "retdec-debugformat-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT debugformat
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-debugformat-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-debugformat-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT debugformat
)
