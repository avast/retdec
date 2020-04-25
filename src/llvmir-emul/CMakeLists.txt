
add_library(llvmir-emul STATIC
	llvmir_emul.cpp
)
add_library(retdec::llvmir-emul ALIAS llvmir-emul)

target_compile_features(llvmir-emul PUBLIC cxx_std_17)

target_include_directories(llvmir-emul
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(llvmir-emul
	PUBLIC
		retdec::deps::llvm
)

set_target_properties(llvmir-emul
	PROPERTIES
		OUTPUT_NAME "retdec-llvmir-emul"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/llvmir-emul
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS llvmir-emul
	EXPORT llvmir-emul-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT llvmir-emul-targets
	FILE "retdec-llvmir-emul-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-llvmir-emul-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-llvmir-emul-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-llvmir-emul-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
