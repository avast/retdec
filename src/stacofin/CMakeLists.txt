
add_library(retdec-stacofin STATIC
	stacofin.cpp
)
target_link_libraries(retdec-stacofin
	retdec-loader
	retdec-config
	retdec-common
	retdec-utils
	yaracpp
	capstone
)
target_include_directories(retdec-stacofin PUBLIC ${PROJECT_SOURCE_DIR}/include/)
