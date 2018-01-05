
set(EXAMPLE_SOURCES
	example.cpp
)

add_library(example SHARED ${EXAMPLE_SOURCES})
target_link_libraries(example fileformat-headers)
install(TARGETS example
	LIBRARY DESTINATION bin/unpacker-plugins
	RUNTIME DESTINATION bin/unpacker-plugins
)
