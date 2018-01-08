
set(MPRESS_SOURCES
	mpress.cpp
)

add_library(retdec-mpress SHARED ${MPRESS_SOURCES})
target_link_libraries(retdec-mpress retdec-fileformat-headers)
target_include_directories(retdec-mpress PUBLIC ${PROJECT_SOURCE_DIR}/src/)
# Plugin related libraries are linked to the plugin on Windows
if(MSVC OR APPLE)
	target_link_libraries(retdec-mpress retdec-unpacker)
endif()
install(TARGETS retdec-mpress
	LIBRARY DESTINATION bin/unpacker-plugins
	RUNTIME DESTINATION bin/unpacker-plugins
)
