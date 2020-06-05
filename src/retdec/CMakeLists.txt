
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
		retdec::deps::capstone
		retdec::deps::llvm
	PRIVATE
		retdec::bin2llvmir
		retdec::llvmir2hll
		retdec::config
)

set_target_properties(retdec
	PROPERTIES
		OUTPUT_NAME "retdec-retdec"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/retdec
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS retdec
	EXPORT retdec-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT retdec-targets
	FILE "retdec-retdec-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-retdec-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-retdec-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-retdec-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
