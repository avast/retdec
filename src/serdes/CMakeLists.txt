
add_library(retdec-serdes STATIC
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
	utils.cpp
	vtable.cpp
)
target_link_libraries(retdec-serdes
	retdec-common
	jsoncpp
)
target_include_directories(retdec-serdes
	PUBLIC ${PROJECT_SOURCE_DIR}/include/
)
target_include_directories(retdec-serdes
	PUBLIC ${PROJECT_SOURCE_DIR}/src/
)
