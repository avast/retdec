
set(LOADER_SOURCES
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

if(NOT TARGET loader)

	add_library(loader STATIC ${LOADER_SOURCES})
	target_link_libraries(loader fileformat tl-cpputils)
	target_include_directories(loader PUBLIC ${PROJECT_SOURCE_DIR}/include/)

endif()
