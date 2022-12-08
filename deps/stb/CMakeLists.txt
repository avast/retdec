
add_library(stb STATIC
    stb_image.c
)

add_library(retdec::deps::stb ALIAS stb)

target_include_directories(stb
    SYSTEM INTERFACE
        $<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/stb/include>
        $<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/stb>
)

set_target_properties(stb
	PROPERTIES
		OUTPUT_NAME "retdec-stb"
)

# Disable all warnings from this 3rd party project.
if(MSVC)
	target_compile_options(stb PRIVATE "/w")
else()
	target_compile_options(stb PRIVATE "-w")
endif()

# Install includes.
install(
    DIRECTORY ${RETDEC_DEPS_DIR}/stb/include/
    DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(TARGETS stb
    EXPORT stb-targets
    ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
    LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT stb-targets
    FILE "retdec-stb-targets.cmake"
    NAMESPACE retdec::deps::
    DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
    FILES
        "${CMAKE_CURRENT_LIST_DIR}/retdec-stb-config.cmake"
    DESTINATION
        "${RETDEC_INSTALL_CMAKE_DIR}"
)
