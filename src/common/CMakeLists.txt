
add_library(retdec-common STATIC
	address.cpp
	architecture.cpp
	calling_convention.cpp
)
target_link_libraries(retdec-common
	retdec-utils
)
target_include_directories(retdec-common PUBLIC ${PROJECT_SOURCE_DIR}/include/)
