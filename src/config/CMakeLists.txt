
add_library(retdec-config STATIC
	architecture.cpp
	base.cpp
	calling_convention.cpp
	classes.cpp
	config.cpp
	file_format.cpp
	file_type.cpp
	functions.cpp
	language.cpp
	objects.cpp
	parameters.cpp
	patterns.cpp
	segments.cpp
	storage.cpp
	tool_info.cpp
	types.cpp
	vtables.cpp
)
target_link_libraries(retdec-config
	retdec-common
	retdec-utils
	jsoncpp
)
target_include_directories(retdec-config PUBLIC ${PROJECT_SOURCE_DIR}/include/)
