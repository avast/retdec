
if(WIN32)
	set(OPENSSL_USE_STATIC_LIBS TRUE)
	set(OPENSSL_MSVC_STATIC_RT ${RETDEC_MSVC_STATIC_RUNTIME})
endif()
find_package(OpenSSL 1.0.1 REQUIRED)

add_library(fileformat STATIC
	utils/format_detection.cpp
	utils/byte_array_buffer.cpp
	utils/conversions.cpp
	utils/crypto.cpp
	utils/other.cpp
	utils/asn1.cpp
	utils/file_io.cpp
	format_factory.cpp
	types/dotnet_headers/blob_stream.cpp
	types/dotnet_headers/user_string_stream.cpp
	types/dotnet_headers/guid_stream.cpp
	types/dotnet_headers/clr_header.cpp
	types/dotnet_headers/string_stream.cpp
	types/dotnet_headers/metadata_stream.cpp
	types/dotnet_headers/metadata_tables.cpp
	types/dotnet_headers/metadata_header.cpp
	types/pdb_info/pdb_info.cpp
	types/symbol_table/symbol_table.cpp
	types/symbol_table/macho_symbol.cpp
	types/symbol_table/symbol.cpp
	types/symbol_table/elf_symbol.cpp
	types/rich_header/rich_header.cpp
	types/rich_header/linker_info.cpp
	types/visual_basic/visual_basic_info.cpp
	types/visual_basic/visual_basic_object.cpp
	types/visual_basic/visual_basic_extern.cpp
	types/import_table/import.cpp
	types/import_table/import_table.cpp
	types/import_table/elf_import_table.cpp
	types/import_table/pe_import.cpp
	types/export_table/export.cpp
	types/export_table/export_table.cpp
	types/relocation_table/relocation_table.cpp
	types/relocation_table/relocation.cpp
	types/resource_table/resource.cpp
	types/resource_table/resource_icon.cpp
	types/resource_table/resource_icon_group.cpp
	types/resource_table/resource_table.cpp
	types/resource_table/resource_tree.cpp
	types/resource_table/bitmap_image.cpp
	types/certificate_table/certificate.cpp
	types/certificate_table/certificate_table.cpp
	types/dotnet_types/dotnet_type_reconstructor.cpp
	types/dotnet_types/dotnet_class.cpp
	types/dotnet_types/dotnet_property.cpp
	types/dotnet_types/dotnet_field.cpp
	types/dotnet_types/dotnet_type.cpp
	types/dotnet_types/dotnet_data_types.cpp
	types/dotnet_types/dotnet_parameter.cpp
	types/dotnet_types/dotnet_method.cpp
	types/sec_seg/elf_section.cpp
	types/sec_seg/elf_segment.cpp
	types/sec_seg/segment.cpp
	types/sec_seg/pe_coff_section.cpp
	types/sec_seg/sec_seg.cpp
	types/sec_seg/section.cpp
	types/sec_seg/macho_section.cpp
	types/dynamic_table/dynamic_entry.cpp
	types/dynamic_table/dynamic_table.cpp
	types/strings/string.cpp
	types/note_section/elf_notes.cpp
	types/note_section/elf_core.cpp
	types/tls_info/tls_info.cpp
	file_format/pe/pe_format.cpp
	file_format/pe/pe_dll_list.cpp
	file_format/pe/authenticode/authenticode.cpp
	file_format/pe/authenticode/pkcs9_counter_signature.cpp
	file_format/pe/authenticode/ms_counter_signature.cpp
	file_format/pe/authenticode/pkcs7_signature.cpp
	file_format/pe/authenticode/x509_certificate.cpp
	file_format/pe/authenticode/helper.cpp
	file_format/pe/authenticode/authenticode_structs.cpp
	file_format/coff/coff_format.cpp
	file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.cpp
	file_format/intel_hex/intel_hex_parser/intel_hex_parser.cpp
	file_format/intel_hex/intel_hex_format.cpp
	file_format/macho/macho_format.cpp
	file_format/raw_data/raw_data_format.cpp
	file_format/file_format.cpp
	file_format/elf/elf_format.cpp
)
add_library(retdec::fileformat ALIAS fileformat)

target_compile_features(fileformat PUBLIC cxx_std_17)

target_include_directories(fileformat
	PUBLIC
		$<BUILD_INTERFACE:${RETDEC_INCLUDE_DIR}>
		$<INSTALL_INTERFACE:${RETDEC_INSTALL_INCLUDE_DIR}>
)

target_link_libraries(fileformat
	PUBLIC
		retdec::common
		retdec::utils
		retdec::pelib
		retdec::deps::elfio
		retdec::deps::llvm
	PRIVATE
		retdec::deps::tlsh
		OpenSSL::Crypto
)

# Needed when OpenSSL is linked statically on Windows.
if(WIN32)
	target_link_libraries(fileformat
		PRIVATE
			Crypt32
			ws2_32
	)
endif()

set_target_properties(fileformat
	PROPERTIES
		OUTPUT_NAME "retdec-fileformat"
)

# Install includes.
install(
	DIRECTORY ${RETDEC_INCLUDE_DIR}/retdec/fileformat
	DESTINATION ${RETDEC_INSTALL_INCLUDE_DIR}/retdec
)

# Install libs.
install(TARGETS fileformat
	EXPORT fileformat-targets
	ARCHIVE DESTINATION ${RETDEC_INSTALL_LIB_DIR}
	LIBRARY DESTINATION ${RETDEC_INSTALL_LIB_DIR}
)

# Export targets.
install(EXPORT fileformat-targets
	FILE "retdec-fileformat-targets.cmake"
	NAMESPACE retdec::
	DESTINATION ${RETDEC_INSTALL_CMAKE_DIR}
)

# Install CMake files.
configure_file(
	"retdec-fileformat-config.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/retdec-fileformat-config.cmake"
	@ONLY
)
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/retdec-fileformat-config.cmake"
	DESTINATION
		"${RETDEC_INSTALL_CMAKE_DIR}"
)
