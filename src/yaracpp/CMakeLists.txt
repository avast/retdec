
add_library(yaracpp STATIC
	yara_match.cpp
	yara_meta.cpp
	yara_rule.cpp
	yara_detector.cpp
)
add_library(retdec::yaracpp ALIAS yaracpp)

target_compile_features(yaracpp PUBLIC cxx_std_17)

target_include_directories(yaracpp
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(yaracpp
	PRIVATE
		retdec::deps::libyara
)

set_target_properties(yaracpp
	PROPERTIES
		OUTPUT_NAME "retdec-yaracpp"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/yaracpp
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS yaracpp
	EXPORT yaracpp-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT yaracpp-targets
	FILE "retdec-yaracpp-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-yaracpp-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-yaracpp-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-yaracpp-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
