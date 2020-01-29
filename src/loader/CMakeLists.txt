
add_library(retdec-loader STATIC
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
target_link_libraries(retdec-loader
	retdec-fileformat
	retdec-common
	retdec-utils
)
target_include_directories(retdec-loader PUBLIC ${PROJECT_SOURCE_DIR}/include/)
