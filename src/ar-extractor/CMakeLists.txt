
add_library(ar-extractor STATIC
	archive_wrapper.cpp
	detection.cpp
)
add_library(retdec::ar-extractor ALIAS ar-extractor)

target_compile_features(ar-extractor PUBLIC cxx_std_17)

target_include_directories(ar-extractor
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(ar-extractor
	PUBLIC
		retdec::utils
		retdec::deps::llvm
	PRIVATE
		retdec::deps::rapidjson
)

set_target_properties(ar-extractor
	PROPERTIES
		OUTPUT_NAME "retdec-ar-extractor"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/ar-extractor
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS ar-extractor
	EXPORT ar-extractor-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT ar-extractor-targets
	FILE "retdec-ar-extractor-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
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
)
