set(STACOFIN_SOURCES
	stacofin.cpp
)

add_library(retdec-stacofin STATIC ${STACOFIN_SOURCES})
target_link_libraries(retdec-stacofin retdec-loader retdec-utils yaracpp)
target_include_directories(retdec-stacofin PUBLIC ${PROJECT_SOURCE_DIR}/include/)
