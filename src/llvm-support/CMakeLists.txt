
add_library(llvm-support STATIC
	diagnostics.cpp
)
add_library(retdec::llvm-support ALIAS llvm-support)

target_compile_features(llvm-support PUBLIC cxx_std_17)

target_include_directories(llvm-support
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(llvm-support
	PUBLIC
		retdec::deps::llvm
	PRIVATE
		retdec::utils
)

set_target_properties(llvm-support
	PROPERTIES
		OUTPUT_NAME "retdec-llvm-support"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/llvm-support
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS llvm-support
	EXPORT llvm-support-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT llvm-support-targets
	FILE "retdec-llvm-support-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-llvm-support-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-llvm-support-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-llvm-support-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
