
add_library(loader STATIC
	utils/range.cpp
	utils/overlap_resolver.cpp
	utils/name_generator.cpp
	image_factory.cpp
	loader/pe/pe_image.cpp
	loader/image.cpp
	loader/coff/coff_image.cpp
	loader/segment.cpp
	loader/intel_hex/intel_hex_image.cpp
	loader/macho/macho_image.cpp
	loader/raw_data/raw_data_image.cpp
	loader/segment_data_source.cpp
	loader/elf/elf_image.cpp
)
add_library(retdec::loader ALIAS loader)

target_compile_features(loader PUBLIC cxx_std_17)

target_include_directories(loader
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(loader
	PUBLIC
		retdec::fileformat
		retdec::common
		retdec::utils
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/loader
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
	COMPONENT loader
)

# Install libs.
install(TARGETS loader
	EXPORT loader-targets
	COMPONENT loader
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT loader-targets
	FILE "retdec-loader-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
	COMPONENT loader
)

# Install CMake files.
install(
	FILES
		"${CMAKE_CURRENT_LIST_DIR}/retdec-loader-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
	COMPONENT loader
)
