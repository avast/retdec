
add_library(tinyxml2 STATIC
	tinyxml2.cpp
)
add_library(retdec::deps::tinyxml2 ALIAS tinyxml2)

target_include_directories(tinyxml2
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/tinyxml2/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/tinyxml2>
)

set_target_properties(tinyxml2
	PROPERTIES
		OUTPUT_NAME "retdec-tinyxml2"
)

# Disable all warnings from this 3rd party project.
if(MSVC)
	target_compile_options(tinyxml2 PRIVATE "/w")
else()
	target_compile_options(tinyxml2 PRIVATE "-w")
endif()

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/tinyxml2/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(TARGETS tinyxml2
	EXPORT tinyxml2-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT tinyxml2-targets
	FILE "retdec-tinyxml2-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-tinyxml2-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
