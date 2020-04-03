
add_library(ctypesparser STATIC
	ctypes_parser.cpp
	json_ctypes_parser.cpp
	type_config.cpp
)
add_library(retdec::ctypesparser ALIAS ctypesparser)

target_include_directories(ctypesparser
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(ctypesparser
	PUBLIC
		retdec::ctypes
		retdec::rapidjson
	PRIVATE
		retdec::utils
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/ctypesparser
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT ctypesparser
)

# Install libs.
install(TARGETS ctypesparser
	EXPORT ctypesparser-targets
	COMPONENT ctypesparser
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT ctypesparser-targets
	FILE "retdec-ctypesparser-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT ctypesparser
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-ctypesparser-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT ctypesparser
)
