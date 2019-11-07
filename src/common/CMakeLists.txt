
add_library(retdec-common STATIC
	address.cpp
	calling_convention.cpp
)
target_include_directories(retdec-common PUBLIC ${PROJECT_SOURCE_DIR}/include/)
