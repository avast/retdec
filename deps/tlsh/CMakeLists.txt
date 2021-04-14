
add_library(tlsh STATIC
	tlsh.cpp
	tlsh_impl.cpp
	tlsh_util.cpp
)
add_library(retdec::deps::tlsh ALIAS tlsh)

target_include_directories(tlsh
	SYSTEM INTERFACE
		$<BUILD_INTERFACE:${RETDEC_DEPS_DIR}/tlsh/include>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_DEPS_INCLUDE_DIR}>
	PRIVATE
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/tlsh>
)

set_target_properties(tlsh
	PROPERTIES
		OUTPUT_NAME "retdec-tlsh"
)

if(MSVC)
	target_compile_definitions(tlsh PUBLIC WINDOWS TLSH_EXPORTS TLSH_LIB)
endif()

# Install includes.
install(
	DIRECTORY ${RETDEC_DEPS_DIR}/tlsh/include/
	DESTINATION ${RETDEC_INSTALL_DEPS_INCLUDE_DIR}
)

# Install libs.
install(TARGETS tlsh
	EXPORT tlsh-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT tlsh-targets
	FILE "retdec-tlsh-targets.cmake"
	NAMESPACE retdec::deps::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-tlsh-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
