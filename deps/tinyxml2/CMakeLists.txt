
add_library(tinyxml2 tinyxml2.cpp)
target_include_directories(tinyxml2 SYSTEM PUBLIC ${CMAKE_CURRENT_LIST_DIR})

# Disable all warnings from this 3rd party project.
if(MSVC)
	target_compile_options(tinyxml2 PRIVATE "/w")
else()
	target_compile_options(tinyxml2 PRIVATE "-w")
endif()
