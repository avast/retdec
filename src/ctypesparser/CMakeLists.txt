
add_library(ctypesparser STATIC
	ctypes_parser.cpp
	json_ctypes_parser.cpp
	type_config.cpp
)
add_library(retdec::ctypesparser ALIAS ctypesparser)

target_compile_features(ctypesparser PUBLIC cxx_std_17)

target_include_directories(ctypesparser
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(ctypesparser
	PUBLIC
		retdec::ctypes
		retdec::deps::rapidjson
	PRIVATE
		retdec::utils
)

set_target_properties(ctypesparser
	PROPERTIES
		OUTPUT_NAME "retdec-ctypesparser"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/ctypesparser
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS ctypesparser
	EXPORT ctypesparser-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT ctypesparser-targets
	FILE "retdec-ctypesparser-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-ctypesparser-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-ctypesparser-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-ctypesparser-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
