
add_library(macho-extractor STATIC
	break_fat.cpp
)
add_library(retdec::macho-extractor ALIAS macho-extractor)

target_compile_features(macho-extractor PUBLIC cxx_std_17)

target_include_directories(macho-extractor
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(macho-extractor
	PUBLIC
		retdec::deps::llvm
	PRIVATE
		retdec::utils
		retdec::deps::rapidjson
)

set_target_properties(macho-extractor
	PROPERTIES
		OUTPUT_NAME "retdec-macho-extractor"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/macho-extractor
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS macho-extractor
	EXPORT macho-extractor-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT macho-extractor-targets
	FILE "retdec-macho-extractor-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-macho-extractor-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-macho-extractor-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-macho-extractor-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
