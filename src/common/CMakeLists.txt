
add_library(retdec-common STATIC
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
	storage.cpp
	tool_info.cpp
	type.cpp
	vtable.cpp
)
target_link_libraries(retdec-common
	retdec-utils
)
target_include_directories(retdec-common PUBLIC ${PROJECT_SOURCE_DIR}/include/)
