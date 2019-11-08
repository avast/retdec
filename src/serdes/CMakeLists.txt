
add_library(retdec-serdes STATIC
	address.cpp
	architecture.cpp
	calling_convention.cpp
	file_format.cpp
	utils.cpp
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
