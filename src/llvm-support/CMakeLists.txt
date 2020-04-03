
add_library(llvm-support STATIC
	diagnostics.cpp
)
add_library(retdec::llvm-support ALIAS llvm-support)

target_include_directories(llvm-support
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(llvm-support
	PUBLIC
		retdec::llvm
	PRIVATE
		retdec::utils
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/llvm-support
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT llvm-support
)

# Install libs.
install(TARGETS llvm-support
	EXPORT llvm-support-targets
	COMPONENT llvm-support
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT llvm-support-targets
	FILE "retdec-llvm-support-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT llvm-support
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-llvm-support-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT llvm-support
)
