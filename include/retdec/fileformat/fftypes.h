/**
 * @file include/retdec/fileformat/fftypes.h
 * @brief Header file for fileformat types and structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FFTYPES_H
#define RETDEC_FILEFORMAT_FFTYPES_H

#include "retdec/fileformat/types/certificate_table/certificate_table.h"
#include "retdec/fileformat/types/dotnet_headers/clr_header.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_header.h"
#include "retdec/fileformat/types/dotnet_headers/stream.h"
#include "retdec/fileformat/types/dynamic_table/dynamic_table.h"
#include "retdec/fileformat/types/export_table/export_table.h"
#include "retdec/fileformat/types/import_table/import_table.h"
#include "retdec/fileformat/types/import_table/pe_import.h"
#include "retdec/fileformat/types/note_section/elf_notes.h"
#include "retdec/fileformat/types/note_section/elf_core.h"
#include "retdec/fileformat/types/pdb_info/pdb_info.h"
#include "retdec/fileformat/types/relocation_table/relocation_table.h"
#include "retdec/fileformat/types/resource_table/resource_table.h"
#include "retdec/fileformat/types/resource_table/resource_tree.h"
#include "retdec/fileformat/types/rich_header/rich_header.h"
#include "retdec/fileformat/types/sec_seg/elf_section.h"
#include "retdec/fileformat/types/sec_seg/elf_segment.h"
#include "retdec/fileformat/types/sec_seg/macho_section.h"
#include "retdec/fileformat/types/sec_seg/pe_coff_section.h"
#include "retdec/fileformat/types/sec_seg/segment.h"
#include "retdec/fileformat/types/strings/string.h"
#include "retdec/fileformat/types/symbol_table/macho_symbol.h"
#include "retdec/fileformat/types/symbol_table/symbol_table.h"

namespace retdec {
namespace fileformat {

/**
 * Supported file-format types
 */
enum class Format
{
	UNDETECTABLE,
	UNKNOWN,
	PE,
	ELF,
	COFF,
	MACHO,
	INTEL_HEX,
	RAW_DATA
};

/**
 * Supported architectures
 */
enum class Architecture
{
	UNKNOWN,
	X86,
	X86_64,
	ARM,
	POWERPC,
	MIPS
};

enum LoadFlags
{
	NONE              = 0,
	NO_FILE_HASHES    = 1,
	NO_VERBOSE_HASHES = 2,
	DETECT_STRINGS    = 4
};

} // namespace fileformat
} // namespace retdec

#endif
