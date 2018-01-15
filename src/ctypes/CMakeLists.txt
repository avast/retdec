set(CTYPES_SOURCES
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
	parameter.cpp
	pointer_type.cpp
	struct_type.cpp
	type.cpp
	typedefed_type.cpp
	union_type.cpp
	unknown_type.cpp
	visit_all_visitor.cpp
	visitor.cpp
	void_type.cpp
)

add_library(retdec-ctypes STATIC ${CTYPES_SOURCES})
target_link_libraries(retdec-ctypes retdec-utils)
target_include_directories(retdec-ctypes PUBLIC ${PROJECT_SOURCE_DIR}/include/)
