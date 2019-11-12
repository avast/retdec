
add_library(retdec-config STATIC
	base.cpp
	config.cpp
	functions.cpp
	objects.cpp
	parameters.cpp
	types.cpp
)
target_link_libraries(retdec-config
	retdec-serdes
	retdec-common
	retdec-utils
	jsoncpp
)
target_include_directories(retdec-config PUBLIC ${PROJECT_SOURCE_DIR}/include/)
