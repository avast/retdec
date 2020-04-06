
add_library(serdes STATIC
	address.cpp
	architecture.cpp
	basic_block.cpp
	calling_convention.cpp
	class.cpp
	file_format.cpp
	file_type.cpp
	function.cpp
	language.cpp
	object.cpp
	pattern.cpp
	std.cpp
	storage.cpp
	tool_info.cpp
	type.cpp
	vtable.cpp
)
add_library(retdec::serdes ALIAS serdes)

target_compile_features(serdes PUBLIC cxx_std_17)

target_include_directories(serdes
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(serdes
	PUBLIC
		retdec::common
		retdec::deps::rapidjson
)

set_target_properties(serdes
	PROPERTIES
		OUTPUT_NAME "retdec-serdes"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/serdes
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS serdes
	EXPORT serdes-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT serdes-targets
	FILE "retdec-serdes-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-serdes-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-serdes-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-serdes-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
