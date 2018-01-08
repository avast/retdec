
set(UNPACKERTOOL_SOURCES
	arg_handler.cpp
	unpacker.cpp
	plugin_mgr.cpp
)

add_executable(retdec-unpackertool ${UNPACKERTOOL_SOURCES})
set_target_properties(retdec-unpackertool PROPERTIES OUTPUT_NAME "retdec-unpacker")

# There are multiple cases for linking because of the plugin model and different behavior under Windows and Linux
# 1. The libraries that are used only in the unpacker core are linked standardly
# 2. The libraries that are used in plugins under Linux are linked as whole-archives
# 3. The libraries that are used in plugins under Windows/macOS are linked to plugins themselves in plugins/*/CMakeLists.txt
# 4. The libraries that are used both by core and plugins need to be linked as whole-archive under Linux, and under Windows/macOS like in 1 and 3 simultaneously
target_link_libraries(retdec-unpackertool retdec-cpdetect)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	target_link_libraries(retdec-unpackertool -rdynamic
		-Wl,-force_load retdec-utils
		-Wl,-force_load retdec-unpacker
		-Wl,-force_load retdec-loader
		-Wl,-force_load retdec-pelib
		dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	target_link_libraries(retdec-unpackertool -rdynamic -Wl,-whole-archive retdec-utils retdec-unpacker retdec-loader pelib -Wl,-no-whole-archive dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(retdec-unpackertool shlwapi)
endif()

install(TARGETS retdec-unpackertool RUNTIME DESTINATION bin)

# Plugins.
add_subdirectory(plugins)
