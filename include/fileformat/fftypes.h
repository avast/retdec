/**
 * @file include/fileformat/fftypes.h
 * @brief Header file for fileformat types and structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_FFTYPES_H
#define FILEFORMAT_FFTYPES_H

#include "fileformat/types/certificate_table/certificate_table.h"
#include "fileformat/types/dotnet_headers/clr_header.h"
#include "fileformat/types/dotnet_headers/metadata_header.h"
#include "fileformat/types/dotnet_headers/stream.h"
#include "fileformat/types/dynamic_table/dynamic_table.h"
#include "fileformat/types/export_table/export_table.h"
#include "fileformat/types/import_table/import_table.h"
#include "fileformat/types/pdb_info/pdb_info.h"
#include "fileformat/types/relocation_table/relocation_table.h"
#include "fileformat/types/resource_table/resource_table.h"
#include "fileformat/types/resource_table/resource_tree.h"
#include "fileformat/types/rich_header/rich_header.h"
#include "fileformat/types/sec_seg/elf_section.h"
#include "fileformat/types/sec_seg/elf_segment.h"
#include "fileformat/types/sec_seg/macho_section.h"
#include "fileformat/types/sec_seg/pe_coff_section.h"
#include "fileformat/types/sec_seg/segment.h"
#include "fileformat/types/strings/string.h"
#include "fileformat/types/symbol_table/macho_symbol.h"
#include "fileformat/types/symbol_table/symbol_table.h"

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

#endif
