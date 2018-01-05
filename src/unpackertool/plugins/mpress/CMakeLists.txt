
set(MPRESS_SOURCES
	mpress.cpp
)

add_library(mpress SHARED ${MPRESS_SOURCES})
target_link_libraries(mpress fileformat-headers)
target_include_directories(mpress PUBLIC ${PROJECT_SOURCE_DIR}/src/)
# Plugin related libraries are linked to the plugin on Windows
if(MSVC OR APPLE)
	target_link_libraries(mpress unpacker)
endif()
install(TARGETS mpress
	LIBRARY DESTINATION bin/unpacker-plugins
	RUNTIME DESTINATION bin/unpacker-plugins
)
