set(MPRESS_SOURCES
	mpress.cpp
)

add_library(retdec-unpacker-mpress STATIC ${MPRESS_SOURCES})
target_link_libraries(retdec-unpacker-mpress retdec-unpacker retdec-fileformat)
target_include_directories(retdec-unpacker-mpress PUBLIC ${PROJECT_SOURCE_DIR}/src/)
