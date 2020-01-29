
add_library(retdec-config STATIC
	config.cpp
	parameters.cpp
)
target_link_libraries(retdec-config
	retdec-serdes
	retdec-common
	retdec-utils
	rapidjson
)
target_include_directories(retdec-config PUBLIC ${PROJECT_SOURCE_DIR}/include/)
