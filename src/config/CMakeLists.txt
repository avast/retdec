
add_library(retdec-config STATIC
	base.cpp
	classes.cpp
	config.cpp
	file_format.cpp
	file_type.cpp
	functions.cpp
	language.cpp
	objects.cpp
	parameters.cpp
	patterns.cpp
	storage.cpp
	tool_info.cpp
	types.cpp
	vtables.cpp
)
target_link_libraries(retdec-config
	retdec-serdes
	retdec-common
	retdec-utils
	jsoncpp
)
target_include_directories(retdec-config PUBLIC ${PROJECT_SOURCE_DIR}/include/)
