
add_library(ctypes STATIC
	annotation.cpp
	annotation_in.cpp
	annotation_inout.cpp
	annotation_optional.cpp
	annotation_out.cpp
	array_type.cpp
	call_convention.cpp
	composite_type.cpp
	context.cpp
	enum_type.cpp
	floating_point_type.cpp
	function.cpp
	function_declaration.cpp
	function_type.cpp
	header_file.cpp
	integral_type.cpp
	member.cpp
	module.cpp
	named_type.cpp
	parameter.cpp
	pointer_type.cpp
	reference_type.cpp
	struct_type.cpp
	type.cpp
	typedefed_type.cpp
	union_type.cpp
	unknown_type.cpp
	visit_all_visitor.cpp
	visitor.cpp
	void_type.cpp
)
add_library(retdec::ctypes ALIAS ctypes)

target_compile_features(ctypes PUBLIC cxx_std_17)

target_link_libraries(ctypes
	PRIVATE
		retdec::utils
)

target_include_directories(ctypes
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

set_target_properties(ctypes
	PROPERTIES
		OUTPUT_NAME "retdec-ctypes"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/ctypes
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS ctypes
	EXPORT ctypes-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT ctypes-targets
	FILE "retdec-ctypes-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-ctypes-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-ctypes-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-ctypes-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
