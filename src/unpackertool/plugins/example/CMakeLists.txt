set(EXAMPLE_SOURCES
	example.cpp
)

add_library(retdec-unpacker-example STATIC ${EXAMPLE_SOURCES})
target_link_libraries(retdec-unpacker-example retdec-unpacker retdec-fileformat)
target_include_directories(retdec-unpacker-example PUBLIC ${PROJECT_SOURCE_DIR}/src/)
