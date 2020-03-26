
add_library(cpdetect STATIC
	compiler_detector/coff_compiler.cpp
	compiler_detector/compiler_detector.cpp
	compiler_detector/elf_compiler.cpp
	compiler_detector/heuristics/elf_heuristics.cpp
	compiler_detector/heuristics/heuristics.cpp
	compiler_detector/heuristics/macho_heuristics.cpp
	compiler_detector/heuristics/pe_heuristics.cpp
	compiler_detector/intel_hex_compiler.cpp
	compiler_detector/macho_compiler.cpp
	compiler_detector/pe_compiler.cpp
	compiler_detector/raw_data_compiler.cpp
	compiler_detector/search/search.cpp
	compiler_factory.cpp
	cptypes.cpp
	errors.cpp
	signatures/avg/signature.cpp
	signatures/avg/signature_checker.cpp
	utils/version_solver.cpp
)
add_library(retdec::cpdetect ALIAS cpdetect)

target_compile_features(cpdetect PUBLIC cxx_std_17)

target_include_directories(cpdetect
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(cpdetect
	PUBLIC
		retdec::fileformat
		retdec::utils
	PRIVATE
		retdec::yaracpp
		retdec::tinyxml2
		retdec::llvm
)

# Create config version file.
write_basic_package_version_file(
	"${RETDEC_BINARY_SHARE_DIR}/retdec-cpdetect-config-version.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY AnyNewerVersion
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/cpdetect
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT cpdetect
)

# Install libs.
install(TARGETS cpdetect tinyxml2
	EXPORT cpdetect-targets
	COMPONENT cpdetect
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT cpdetect-targets
	FILE "retdec-cpdetect-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT cpdetect
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-cpdetect-config.cmake"
		"${RETDEC_BINARY_SHARE_DIR}/retdec-cpdetect-config-version.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT cpdetect
)
