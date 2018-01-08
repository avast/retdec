
set(EXAMPLE_SOURCES
	example.cpp
)

add_library(retdec-example SHARED ${EXAMPLE_SOURCES})
target_link_libraries(retdec-example retdec-fileformat-headers)
install(TARGETS retdec-example
	LIBRARY DESTINATION bin/unpacker-plugins
	RUNTIME DESTINATION bin/unpacker-plugins
)
