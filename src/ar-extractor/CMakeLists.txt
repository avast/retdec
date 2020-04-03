
add_library(ar-extractor STATIC
	archive_wrapper.cpp
	detection.cpp
)
add_library(retdec::ar-extractor ALIAS ar-extractor)

target_include_directories(ar-extractor
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(ar-extractor
	PUBLIC
		retdec::utils
		retdec::llvm
	PRIVATE
		retdec::rapidjson
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/ar-extractor
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT ar-extractor
)

# Install libs.
install(TARGETS ar-extractor
	EXPORT ar-extractor-targets
	COMPONENT ar-extractor
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT ar-extractor-targets
	FILE "retdec-ar-extractor-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT ar-extractor
)

# Install CMake files.
configure_file(
	"retdec-ar-extractor-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-ar-extractor-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-ar-extractor-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT ar-extractor
)
