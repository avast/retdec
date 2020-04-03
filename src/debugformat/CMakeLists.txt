
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
		retdec::demangler
		retdec::loader
		retdec::fileformat
		retdec::common
		retdec::pdbparser
		retdec::llvm
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
configure_file(
	"retdec-debugformat-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-debugformat-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-debugformat-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT debugformat
)
