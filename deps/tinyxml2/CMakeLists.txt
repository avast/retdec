
add_library(tinyxml2 STATIC
	tinyxml2.cpp
)
add_library(retdec::tinyxml2 ALIAS tinyxml2)

target_include_directories(tinyxml2
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/tinyxml2/include>
		# nothing for install because this does not need to be installed
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include/tinyxml2
)

# Disable all warnings from this 3rd party project.
if(MSVC)
	target_compile_options(tinyxml2 PRIVATE "/w")
else()
	target_compile_options(tinyxml2 PRIVATE "-w")
endif()
