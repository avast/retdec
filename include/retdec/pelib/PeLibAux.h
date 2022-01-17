/*
* PeLibAux.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_PELIBAUX_H
#define RETDEC_PELIB_PELIBAUX_H

#include <cstdint>
#include <ios>
#include <numeric>
#include <string.h>
#include <string>
#include <vector>
#include <fstream>

#ifdef _MSC_VER						// Reduces number of warnings under MS Visual Studio from ~100000 to zero
#pragma warning(disable:4267)		// C4267: 'initializing': conversion from 'size_t' to '_Ty2', possible loss of data
#pragma warning(disable:4244)		// C4244: 'argument': conversion from 'uint64_t' to 'unsigned int', possible loss of data
#endif

//get rid of duplicate windows.h definitions
#ifdef ERROR_NONE
#undef ERROR_NONE
#endif

namespace PeLib
{
	enum errorCodes
	{
		ERROR_NONE = 0,
		ERROR_OPENING_FILE = -1,
		ERROR_INVALID_FILE = -2,
		ERROR_TOO_MANY_SECTIONS = -3,
		ERROR_NOT_ENOUGH_SPACE = -4,
		ERROR_NO_FILE_ALIGNMENT = -5,
		ERROR_NO_SECTION_ALIGNMENT = -6,
		ERROR_ENTRY_NOT_FOUND = -7,
		ERROR_DUPLICATE_ENTRY = -8,
		ERROR_DIRECTORY_DOES_NOT_EXIST = -9,
		ERROR_COFF_SYMBOL_TABLE_DOES_NOT_EXIST = -10,
		ERROR_SKIP_RESOURCE = -11
	};

	enum LoaderError
	{
		LDR_ERROR_NONE = 0,                         // No error
		LDR_ERROR_FILE_TOO_BIG,                     // The file is larger than 0xFFFFFFFF bytes
		LDR_ERROR_E_LFANEW_UNALIGNED,               // The IMAGE_DOS_HEADER::e_lfanew is not aligned to 4
		LDR_ERROR_E_LFANEW_OUT_OF_FILE,             // The IMAGE_DOS_HEADER::e_lfanew is out of (lower 4 GB of) the file
		LDR_ERROR_NTHEADER_OFFSET_OVERFLOW,         // NT header offset + sizeof(IMAGE_NT_HEADERS) overflow
		LDR_ERROR_NTHEADER_OUT_OF_FILE,             // NT header offset + sizeof(IMAGE_NT_HEADERS) is greater than filesize
		LDR_ERROR_NO_NT_SIGNATURE,                  // Missing IMAGE_NT_SIGNATURE in the NT headers
		LDR_ERROR_FILE_HEADER_INVALID,              // Invalid IMAGE_FILE_HEADER::Machine or IMAGE_FILE_HEADER::SizeOfOptionalHeader
		LDR_ERROR_IMAGE_NON_EXECUTABLE,             // Missing IMAGE_FILE_EXECUTABLE_IMAGE in IMAGE_FILE_HEADER::Characteristics
		LDR_ERROR_NO_OPTHDR_MAGIC,                  // Invalid IMAGE_OPTIONAL_HEADER::Magic
		LDR_ERROR_SIZE_OF_HEADERS_ZERO,             // IMAGE_OPTIONAL_HEADER::SizeOfHeaders is zero
		LDR_ERROR_FILE_ALIGNMENT_ZERO,              // IMAGE_OPTIONAL_HEADER::FileAlignment is zero
		LDR_ERROR_FILE_ALIGNMENT_NOT_POW2,          // IMAGE_OPTIONAL_HEADER::FileAlignment is not power of two
		LDR_ERROR_SECTION_ALIGNMENT_ZERO,           // IMAGE_OPTIONAL_HEADER::SectionAlignment is zero
		LDR_ERROR_SECTION_ALIGNMENT_NOT_POW2,       // IMAGE_OPTIONAL_HEADER::SectionAlignment is not power of two
		LDR_ERROR_SECTION_ALIGNMENT_TOO_SMALL,      // IMAGE_OPTIONAL_HEADER::SectionAlignment is less than IMAGE_OPTIONAL_HEADER::FileAlignment
		LDR_ERROR_SECTION_ALIGNMENT_INVALID,        // IMAGE_OPTIONAL_HEADER::SectionAlignment must be equal to IMAGE_OPTIONAL_HEADER::FileAlignment if (FileAlignment < 512)
		LDR_ERROR_SIZE_OF_IMAGE_TOO_BIG,            // IMAGE_OPTIONAL_HEADER::SizeOfImage is too big
		LDR_ERROR_INVALID_MACHINE32,                // IMAGE_FILE_HEADER::Machine is invalid for IMAGE_OPTIONAL_HEADER::Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
		LDR_ERROR_INVALID_MACHINE64,                // IMAGE_FILE_HEADER::Machine is invalid for IMAGE_OPTIONAL_HEADER::Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
		LDR_ERROR_SIZE_OF_HEADERS_INVALID,          // IMAGE_OPTIONAL_HEADER::SizeOfHeaders is greater than IMAGE_OPTIONAL_HEADER::SizeOfImage
		LDR_ERROR_SIZE_OF_OPTHDR_NOT_ALIGNED,       // IMAGE_OPTIONAL_HEADER::SizeOfHeaders is not aligned to 8 (64-bit Windows only)
		LDR_ERROR_SIZE_OF_IMAGE_ZERO,               // Number of PTEs for the entire image is zero
		LDR_ERROR_IMAGE_BASE_NOT_ALIGNED,           // IMAGE_OPTIONAL_HEADER::ImageBase is not aligned to 64KB
		LDR_ERROR_SIZE_OF_IMAGE_PTES_ZERO,          // Number of Page Table Entries for the image is zero
		LDR_ERROR_RAW_DATA_OVERFLOW,                // Overflow in section's raw data size
		LDR_ERROR_SECTION_HEADERS_OUT_OF_IMAGE,     // Section headers are out of the image
		LDR_ERROR_SECTION_HEADERS_OVERFLOW,         // Image with single subsection: size of headers is near the end of range
		LDR_ERROR_SECTION_SIZE_MISMATCH,            // Image with single subsection: virtual values with rawdata values don't match
		LDR_ERROR_INVALID_SECTION_VA,               // Images with normal sections: invalid virtual address of a section
		LDR_ERROR_INVALID_SECTION_VSIZE,            // Images with normal sections: invalid virtual size of a section
		LDR_ERROR_INVALID_SECTION_RAWSIZE,          // Images with normal sections: invalid raw data size
		LDR_ERROR_INVALID_SIZE_OF_IMAGE,            // IMAGE_OPTIONAL_HEADER::SizeOfImage doesn't match the (header+sections)
		LDR_ERROR_FILE_IS_CUT,                      // The PE file is cut
		LDR_ERROR_FILE_IS_CUT_LOADABLE,             // The PE file is cut, but loadable

		// Errors from Import Table parser
		LDR_ERROR_IMPDIR_OUT_OF_FILE,               // Offset of the import directory is out of the file
		LDR_ERROR_IMPDIR_CUT,                       // Import directory is cut
		LDR_ERROR_IMPDIR_COUNT_EXCEEDED,            // Number of import descriptors exceeds maximum
		LDR_ERROR_IMPDIR_NAME_RVA_INVALID,          // RVA of the import name is invalid
		LDR_ERROR_IMPDIR_THUNK_RVA_INVALID,         // RVA of the import thunk is invalid
		LDR_ERROR_IMPDIR_IMPORT_COUNT_EXCEEDED,     // Number of imported functions exceeds maximum

		// Errors from resource parser
		LDR_ERROR_RSRC_OVER_END_OF_IMAGE,           // Array of resource directory entries goes beyond end of the image
		LDR_ERROR_RSRC_NAME_OUT_OF_IMAGE,           // One of the resource names points out of the image
		LDR_ERROR_RSRC_DATA_OUT_OF_IMAGE,           // One of the resource data points out of the image
		LDR_ERROR_RSRC_SUBDIR_OUT_OF_IMAGE,         // One of the resource subdirectories points out of the image

		// Errors from entry point checker
		LDR_ERROR_ENTRY_POINT_OUT_OF_IMAGE,         // The entry point is out of the image
		LDR_ERROR_ENTRY_POINT_ZEROED,               // The entry point is zeroed

		// Errors from signature parser
		LDR_ERROR_DIGITAL_SIGNATURE_CUT,            // The file signature is out of the file
		LDR_ERROR_DIGITAL_SIGNATURE_ZEROED,         // The file signature is zeroed

		// Errors from relocations
		LDR_ERROR_RELOCATIONS_OUT_OF_IMAGE,         // The relocation directory points out of the image
		LDR_ERROR_RELOC_BLOCK_INVALID_VA,           // A relocation block has invalid virtual address
		LDR_ERROR_RELOC_BLOCK_INVALID_LENGTH,       // A relocation block has invalid length
		LDR_ERROR_RELOC_ENTRY_BAD_TYPE,             // A relocation entry has invalid type

		// Other errors
		LDR_ERROR_INMEMORY_IMAGE,                   // The file is a 1:1 in-memory image

		LDR_ERROR_MAX

	};

	struct LoaderErrorInfo
	{
		const char * loaderErrorString;
		const char * loaderErrorUserFriendly;
		bool loadableAnyway;
	};

	class PeFile;

	typedef std::vector<std::uint8_t> ByteBuffer;

	enum
	{
		PEFILE32 = 32,
		PEFILE64 = 64,
		PEFILE_UNKNOWN = 0
	};

	const std::uint16_t PELIB_IMAGE_DOS_SIGNATURE = 0x5A4D;

	const std::uint32_t PELIB_PAGE_SIZE = 0x1000;

	const std::uint32_t PELIB_PAGE_SIZE_SHIFT = 12;

	const std::uint32_t PELIB_SIZE_64KB = 0x10000;

	const std::uint32_t PELIB_SIZE_10MB = 0xA00000;

	const std::uint32_t PELIB_IMAGE_NT_SIGNATURE = 0x00004550;

	const std::uint32_t PELIB_MM_SIZE_OF_LARGEST_IMAGE = 0x77000000;

	const std::uint32_t PELIB_MAX_TLS_CALLBACKS      = 0x100;           // Maximum number of processed TLS callbacks
	const std::uint32_t PELIB_MAX_IMPORT_DLLS        = 0x100;           // Maximum number of imported DLLs we consider OK
	const std::uint32_t PELIB_MAX_IMPORTED_FUNCTIONS = 0x1000;          // Maximum number of exported functions (per DLL) that we support
	const std::uint32_t PELIB_MAX_EXPORTED_FUNCTIONS = 0x1000;          // Maximum number of exported functions that we support
	const std::uint32_t PE_MAX_SECTION_COUNT_XP = 96;
	const std::uint32_t PE_MAX_SECTION_COUNT_7 = 192;

	const std::uint32_t PELIB_IMAGE_DEBUG_INFO_CODEVIEW = 2;

	const std::uint32_t PELIB_SECTOR_SIZE = 0x200;

	const std::uint32_t PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

	const std::uint32_t PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000;
	const std::uint32_t PELIB_IMAGE_RESOURCE_NAME_IS_STRING = 0x80000000;
	const std::uint32_t PELIB_IMAGE_RESOURCE_RVA_MASK = 0x7FFFFFFF;
	const std::uint16_t PELIB_MAX_RESOURCE_ENTRIES = 0x8000;            // Maximum number of resource directory entries we consider OK

	enum : std::uint32_t
	{
		PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT,		// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT,		// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE,		// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_EXCEPTION,
		PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY,
		PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC,	// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG,
		PELIB_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
		PELIB_IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
		PELIB_IMAGE_DIRECTORY_ENTRY_TLS,
		PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
		PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,	// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_IAT,		// OK
		PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
		PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	};

	enum : std::uint32_t
	{
		PELIB_PAGE_NOACCESS          = 0x01,
		PELIB_PAGE_READONLY          = 0x02,
		PELIB_PAGE_READWRITE         = 0x04,
		PELIB_PAGE_WRITECOPY         = 0x08,
		PELIB_PAGE_EXECUTE           = 0x10,
		PELIB_PAGE_EXECUTE_READ      = 0x20,
		PELIB_PAGE_EXECUTE_READWRITE = 0x40,
		PELIB_PAGE_EXECUTE_WRITECOPY = 0x80,
	};

	enum : std::uint32_t
	{
		PELIB_IMAGE_SCN_TYPE_NO_PAD		= 0x00000008,
		PELIB_IMAGE_SCN_CNT_CODE		   = 0x00000020,
		PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA	   = 0x00000040,
		PELIB_IMAGE_SCN_CNT_UNINITIALIZED_DATA     = 0x00000080,
		PELIB_IMAGE_SCN_LNK_OTHER		  = 0x00000100,
		PELIB_IMAGE_SCN_LNK_INFO		   = 0x00000200,
		PELIB_IMAGE_SCN_LNK_REMOVE		 = 0x00000800,
		PELIB_IMAGE_SCN_LNK_COMDAT		 = 0x00001000,
		PELIB_IMAGE_SCN_NO_DEFER_SPEC_EXC	  = 0x00004000,
		PELIB_IMAGE_SCN_GPREL		      = 0x00008000,
		PELIB_IMAGE_SCN_MEM_FARDATA		= 0x00008000,
		PELIB_IMAGE_SCN_MEM_PURGEABLE	      = 0x00020000,
		PELIB_IMAGE_SCN_MEM_16BIT		  = 0x00020000,
		PELIB_IMAGE_SCN_MEM_LOCKED		 = 0x00040000,
		PELIB_IMAGE_SCN_MEM_PRELOAD		= 0x00080000,
		PELIB_IMAGE_SCN_ALIGN_1BYTES	       = 0x00100000,
		PELIB_IMAGE_SCN_ALIGN_2BYTES	       = 0x00200000,
		PELIB_IMAGE_SCN_ALIGN_4BYTES	       = 0x00300000,
		PELIB_IMAGE_SCN_ALIGN_8BYTES	       = 0x00400000,
		PELIB_IMAGE_SCN_ALIGN_16BYTES	      = 0x00500000,
		PELIB_IMAGE_SCN_ALIGN_BYTES		= 0x00600000,
		PELIB_IMAGE_SCN_ALIGN_64BYTES	      = 0x00700000,
		PELIB_IMAGE_SCN_ALIGN_128BYTES	     = 0x00800000,
		PELIB_IMAGE_SCN_ALIGN_256BYTES	     = 0x00900000,
		PELIB_IMAGE_SCN_ALIGN_512BYTES	     = 0x00A00000,
		PELIB_IMAGE_SCN_ALIGN_1024BYTES	    = 0x00B00000,
		PELIB_IMAGE_SCN_ALIGN_2048BYTES	    = 0x00C00000,
		PELIB_IMAGE_SCN_ALIGN_4096BYTES	    = 0x00D00000,
		PELIB_IMAGE_SCN_ALIGN_8192BYTES	    = 0x00E00000,
		PELIB_IMAGE_SCN_LNK_NRELOC_OVFL	    = 0x01000000,
		PELIB_IMAGE_SCN_MEM_DISCARDABLE	    = 0x02000000,
		PELIB_IMAGE_SCN_MEM_NOT_CACHED	     = 0x04000000,
		PELIB_IMAGE_SCN_MEM_NOT_PAGED	      = 0x08000000,
		PELIB_IMAGE_SCN_MEM_SHARED		 = 0x10000000,
		PELIB_IMAGE_SCN_MEM_EXECUTE		= 0x20000000,
		PELIB_IMAGE_SCN_MEM_READ		   = 0x40000000,
		PELIB_IMAGE_SCN_MEM_WRITE		  = 0x80000000U
	};

	enum PELIB_IMAGE_FILE_MACHINE : std::uint16_t
	{
		PELIB_IMAGE_FILE_MACHINE_UNKNOWN		= 0,
		PELIB_IMAGE_FILE_MACHINE_I386			= 0x014C,
		PELIB_IMAGE_FILE_MACHINE_I486			= 0x014D,	// https://corkami.googlecode.com/svn/wiki/PE.wiki
		PELIB_IMAGE_FILE_MACHINE_PENTIUM		= 0x014E,	// https://corkami.googlecode.com/svn/wiki/PE.wiki
		PELIB_IMAGE_FILE_MACHINE_R3000_BIG		= 0x0160,
		PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE	= 0x0162,
		PELIB_IMAGE_FILE_MACHINE_R4000			= 0x0166,
		PELIB_IMAGE_FILE_MACHINE_R10000			= 0x0168,
		PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2		= 0x0169,
		PELIB_IMAGE_FILE_MACHINE_ALPHA			= 0x0184,
		PELIB_IMAGE_FILE_MACHINE_SH3			= 0x01A2,
		PELIB_IMAGE_FILE_MACHINE_SH3DSP			= 0x01A3,
		PELIB_IMAGE_FILE_MACHINE_SH3E			= 0x01A4,
		PELIB_IMAGE_FILE_MACHINE_SH4			= 0x01A6,
		PELIB_IMAGE_FILE_MACHINE_SH5			= 0x01A8,
		PELIB_IMAGE_FILE_MACHINE_ARM			= 0x01C0,
		PELIB_IMAGE_FILE_MACHINE_THUMB			= 0x01C2,
		PELIB_IMAGE_FILE_MACHINE_ARMNT			= 0x01C4,
		PELIB_IMAGE_FILE_MACHINE_AM33			= 0x01D3,
		PELIB_IMAGE_FILE_MACHINE_POWERPC		= 0x01F0,
		PELIB_IMAGE_FILE_MACHINE_POWERPCFP		= 0x01F1,
		PELIB_IMAGE_FILE_MACHINE_IA64			= 0x0200,
		PELIB_IMAGE_FILE_MACHINE_MIPS16			= 0x0266,
		PELIB_IMAGE_FILE_MACHINE_MOTOROLA68000	= 0x0268,
		PELIB_IMAGE_FILE_MACHINE_PARISC			= 0x0290,
		PELIB_IMAGE_FILE_MACHINE_ALPHA64		= 0x0284,
		PELIB_IMAGE_FILE_MACHINE_AXP64			= PELIB_IMAGE_FILE_MACHINE_ALPHA64,
		PELIB_IMAGE_FILE_MACHINE_MIPSFPU		= 0x0366,
		PELIB_IMAGE_FILE_MACHINE_MIPSFPU16		= 0x0466,
		PELIB_IMAGE_FILE_MACHINE_TRICORE		= 0x0520,
		PELIB_IMAGE_FILE_MACHINE_EBC			= 0x0EBC,
		PELIB_IMAGE_FILE_MACHINE_AMD64			= 0x8664,
		PELIB_IMAGE_FILE_MACHINE_M32R			= 0x9041,
		PELIB_IMAGE_FILE_MACHINE_ARM64			= 0xAA64,
		PELIB_IMAGE_FILE_MACHINE_MSIL			= 0xC0EE
	};

	enum : std::uint32_t
	{
		PELIB_IMAGE_FILE_RELOCS_STRIPPED	   = 0x0001,
		PELIB_IMAGE_FILE_EXECUTABLE_IMAGE	  = 0x0002,
		PELIB_IMAGE_FILE_LINE_NUMS_STRIPPED	= 0x0004,
		PELIB_IMAGE_FILE_LOCAL_SYMS_STRIPPED       = 0x0008,
		PELIB_IMAGE_FILE_AGGRESSIVE_WS_TRIM	 = 0x0010,
		PELIB_IMAGE_FILE_LARGE_ADDRESS_AWARE       = 0x0020,
		PELIB_IMAGE_FILE_BYTES_REVERSED_LO	 = 0x0080,
		PELIB_IMAGE_FILE_32BIT_MACHINE	     = 0x0100,
		PELIB_IMAGE_FILE_DEBUG_STRIPPED	    = 0x0200,
		PELIB_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   = 0x0400,
		PELIB_IMAGE_FILE_NET_RUN_FROM_SWAP	 = 0x0800,
		PELIB_IMAGE_FILE_SYSTEM		    = 0x1000,
		PELIB_IMAGE_FILE_DLL		       = 0x2000,
		PELIB_IMAGE_FILE_UP_SYSTEM_ONLY	    = 0x4000,
		PELIB_IMAGE_FILE_BYTES_REVERSED_HI	 = 0x8000
	};

	enum : std::uint16_t
	{
		PELIB_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE            = 0x0040,
		PELIB_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY         = 0x0080,
		PELIB_IMAGE_DLLCHARACTERISTICS_NX_COMPAT               = 0x0100,
		PELIB_IMAGE_DLLCHARACTERISTICS_NO_ISOLATION            = 0x0200,
		PELIB_IMAGE_DLLCHARACTERISTICS_NO_SEH                  = 0x0400,
		PELIB_IMAGE_DLLCHARACTERISTICS_NO_BIND                 = 0x0800,
		PELIB_IMAGE_DLLCHARACTERISTICS_APPCONTAINER            = 0x1000,
		PELIB_IMAGE_DLLCHARACTERISTICS_WDM_DRIVER              = 0x2000,
		PELIB_IMAGE_DLLCHARACTERISTICS_GUARD_CF                = 0x4000,
		PELIB_IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE   = 0x8000
	};

	enum : std::uint16_t
	{
		PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC      = 0x10b,
		PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC      = 0x20b,
		PELIB_IMAGE_ROM_OPTIONAL_HDR_MAGIC       = 0x107
	};

	enum : std::uint16_t
	{
		PELIB_IMAGE_SUBSYSTEM_UNKNOWN	      = 0,
		PELIB_IMAGE_SUBSYSTEM_NATIVE	       = 1,
		PELIB_IMAGE_SUBSYSTEM_WINDOWS_GUI	  = 2,
		PELIB_IMAGE_SUBSYSTEM_WINDOWS_CUI	  = 3,
		PELIB_IMAGE_SUBSYSTEM_OS2_CUI	      = 5,
		PELIB_IMAGE_SUBSYSTEM_POSIX_CUI	    = 7,
		PELIB_IMAGE_SUBSYSTEM_NATIVE_WINDOWS       = 8,
		PELIB_IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       = 9
	};

	enum : uint16_t
	{
		PELIB_IMAGE_REL_BASED_ABSOLUTE        = 0,
		PELIB_IMAGE_REL_BASED_HIGH            = 1,
		PELIB_IMAGE_REL_BASED_LOW             = 2,
		PELIB_IMAGE_REL_BASED_HIGHLOW         = 3,
		PELIB_IMAGE_REL_BASED_HIGHADJ         = 4,
		PELIB_IMAGE_REL_BASED_MIPS_JMPADDR    = 5,
		PELIB_IMAGE_REL_BASED_IA64_IMM64      = 9,
		PELIB_IMAGE_REL_BASED_DIR64           = 10
	};

	enum : std::uint32_t
	{
		PELIB_RT_CURSOR = 1,		// 1
		PELIB_RT_BITMAP,			// 2
		PELIB_RT_ICON,			// 3
		PELIB_RT_MENU,			// 4
		PELIB_RT_DIALOG,			// 5
		PELIB_RT_STRING,			// 6
		PELIB_RT_FONTDIR,			// 7
		PELIB_RT_FONT,			// 8
		PELIB_RT_ACCELERATOR,		// 9
		PELIB_RT_RCDATA,			// 10
		PELIB_RT_MESSAGETABLE,	// 11
		PELIB_RT_GROUP_CURSOR,	// 12
		PELIB_RT_GROUP_ICON = 14,	// 14
		PELIB_RT_VERSION = 16,
		PELIB_RT_DLGINCLUDE,
		PELIB_RT_PLUGPLAY = 19,
		PELIB_RT_VXD,
		PELIB_RT_ANICURSOR,
		PELIB_RT_ANIICON,
		PELIB_RT_HTML,
		PELIB_RT_MANIFEST,
		PELIB_RT_DLGINIT = 240,
		PELIB_RT_TOOLBAR
	};

	enum : std::uint16_t
	{
		PELIB_LANG_NEUTRAL = 0x00,
		PELIB_LANG_ARABIC = 0x01,
		PELIB_LANG_BULGARIAN = 0x02,
		PELIB_LANG_CATALAN = 0x03,
		PELIB_LANG_CHINESE = 0x04,
		PELIB_LANG_CZECH = 0x05,
		PELIB_LANG_DANISH = 0x06,
		PELIB_LANG_GERMAN = 0x07,
		PELIB_LANG_GREEK = 0x08,
		PELIB_LANG_ENGLISH = 0x09,
		PELIB_LANG_SPANISH = 0x0A,
		PELIB_LANG_FINNISH = 0x0B,
		PELIB_LANG_FRENCH = 0x0C,
		PELIB_LANG_HEBREW = 0x0D,
		PELIB_LANG_HUNGARIAN = 0x0E,
		PELIB_LANG_ICELANDIC = 0x0F,
		PELIB_LANG_ITALIAN = 0x10,
		PELIB_LANG_JAPANESE = 0x11,
		PELIB_LANG_KOREAN = 0x12,
		PELIB_LANG_DUTCH = 0x13,
		PELIB_LANG_NORWEGIAN = 0x14,
		PELIB_LANG_POLISH = 0x15,
		PELIB_LANG_PORTUGUESE = 0x16,
		PELIB_LANG_ROMANSH = 0x17,
		PELIB_LANG_ROMANIAN = 0x18,
		PELIB_LANG_RUSSIAN = 0x19,
		PELIB_LANG_CROATIAN = 0x1A,
		PELIB_LANG_SERBIAN_NEUTRAL = 0x7C1A,
		PELIB_LANG_BOSNIAN_NEUTRAL = 0x781A,
		PELIB_LANG_SLOVAK = 0x1B,
		PELIB_LANG_ALBANIAN = 0x1C,
		PELIB_LANG_SWEDISH = 0x1D,
		PELIB_LANG_THAI = 0x1E,
		PELIB_LANG_TURKISH = 0x1F,
		PELIB_LANG_URDU = 0x20,
		PELIB_LANG_INDONESIAN = 0x21,
		PELIB_LANG_UKRAINIAN = 0x22,
		PELIB_LANG_BELARUSIAN = 0x23,
		PELIB_LANG_SLOVENIAN = 0x24,
		PELIB_LANG_ESTONIAN = 0x25,
		PELIB_LANG_LATVIAN = 0x26,
		PELIB_LANG_LITHUANIAN = 0x27,
		PELIB_LANG_TAJIK = 0x28,
		PELIB_LANG_PERSIAN = 0x29,
		PELIB_LANG_VIETNAMESE = 0x2A,
		PELIB_LANG_ARMENIAN = 0x2B,
		PELIB_LANG_AZERI = 0x2C,
		PELIB_LANG_BASQUE = 0x2D,
		PELIB_LANG_SORBIAN = 0x2E,
		PELIB_LANG_LOWER_SORBIAN = 0x2E,
		PELIB_LANG_UPPER_SORBIAN = 0x2E,
		PELIB_LANG_MACEDONIAN = 0x2F,
		PELIB_LANG_SOTHO = 0x30,
		PELIB_LANG_TSONGA = 0x31,
		PELIB_LANG_TSWANA = 0x32,
		PELIB_LANG_VENDA = 0x33,
		PELIB_LANG_XHOSA = 0x34,
		PELIB_LANG_ZULU = 0x35,
		PELIB_LANG_AFRIKAANS = 0x36,
		PELIB_LANG_GEORGIAN = 0x37,
		PELIB_LANG_FAEROESE = 0x38,
		PELIB_LANG_HINDI = 0x39,
		PELIB_LANG_MALTESE = 0x3A,
		PELIB_LANG_SAMI = 0x3B,
		PELIB_LANG_IRISH = 0x3C,
		PELIB_LANG_MALAY = 0x3E,
		PELIB_LANG_KAZAK = 0x3F,
		PELIB_LANG_KYRGYZ = 0x40,
		PELIB_LANG_SWAHILI = 0x41,
		PELIB_LANG_TURKMEN = 0x42,
		PELIB_LANG_UZBEK = 0x43,
		PELIB_LANG_TATAR = 0x44,
		PELIB_LANG_BENGALI = 0x45,
		PELIB_LANG_PUNJABI = 0x46,
		PELIB_LANG_GUJARATI = 0x47,
		PELIB_LANG_ORIYA = 0x48,
		PELIB_LANG_TAMIL = 0x49,
		PELIB_LANG_TELUGU = 0x4A,
		PELIB_LANG_KANNADA = 0x4B,
		PELIB_LANG_MALAYALAM = 0x4C,
		PELIB_LANG_ASSAMESE = 0x4D,
		PELIB_LANG_MARATHI = 0x4E,
		PELIB_LANG_SANSKRIT = 0x4F,
		PELIB_LANG_MONGOLIAN = 0x50,
		PELIB_LANG_TIBETAN = 0x51,
		PELIB_LANG_WELSH = 0x52,
		PELIB_LANG_KHMER = 0x53,
		PELIB_LANG_LAO = 0x54,
		PELIB_LANG_BURMESE = 0x55,
		PELIB_LANG_GALICIAN = 0x56,
		PELIB_LANG_KONKANI = 0x57,
		PELIB_LANG_MANIPURI = 0x58,
		PELIB_LANG_SINDHI = 0x59,
		PELIB_LANG_SYRIAC = 0x5A,
		PELIB_LANG_SINHALESE = 0x5B,
		PELIB_LANG_CHEROKEE = 0x5C,
		PELIB_LANG_INUKTITUT = 0x5D,
		PELIB_LANG_AMHARIC = 0x5E,
		PELIB_LANG_TAMAZIGHT = 0x5F,
		PELIB_LANG_KASHMIRI = 0x60,
		PELIB_LANG_NEPALI = 0x61,
		PELIB_LANG_FRISIAN = 0x62,
		PELIB_LANG_PASHTO = 0x63,
		PELIB_LANG_FILIPINO = 0x64,
		PELIB_LANG_DIVEHI = 0x65,
		PELIB_LANG_FULAH = 0x67,
		PELIB_LANG_HAUSA = 0x68,
		PELIB_LANG_YORUBA = 0x6A,
		PELIB_LANG_QUECHUA = 0x6B,
		PELIB_LANG_NORTHERN_SOTHO = 0x6C,
		PELIB_LANG_BASHKIR = 0x6D,
		PELIB_LANG_LUXEMBOURGISH = 0x6E,
		PELIB_LANG_GREENLANDIC = 0x6F,
		PELIB_LANG_IGBO = 0x70,
		PELIB_LANG_OROMO = 0x72,
		PELIB_LANG_TIGRIGNA = 0x73,
		PELIB_LANG_GUARANI = 0x74,
		PELIB_LANG_HAWAIIAN = 0x75,
		PELIB_LANG_SOMALI = 0x77,
		PELIB_LANG_YI = 0x78,
		PELIB_LANG_MAPUDUNGUN = 0x7A,
		PELIB_LANG_MOHAWK = 0x7C,
		PELIB_LANG_BRETON = 0x7E,
		PELIB_LANG_INVARIANT = 0x7F,
		PELIB_LANG_UIGHUR = 0x80,
		PELIB_LANG_MAORI = 0x81,
		PELIB_LANG_OCCITAN = 0x82,
		PELIB_LANG_CORSICAN = 0x83,
		PELIB_LANG_ALSATIAN = 0x84,
		PELIB_LANG_YAKUT = 0x85,
		PELIB_LANG_KICHE = 0x86,
		PELIB_LANG_KINYARWANDA = 0x87,
		PELIB_LANG_WOLOF = 0x88,
		PELIB_LANG_DARI = 0x8C,
		PELIB_LANG_SCOTTISH = 0x91,
		PELIB_LANG_KURDISH = 0x92,
	};

	template<typename T>
	unsigned int accumulate(unsigned int size, const T& v)
	{
		return size + v.size();
	}

	class PELIB_IMAGE_FILE_MACHINE_ITERATOR
	{
		public:
		typedef std::vector<PELIB_IMAGE_FILE_MACHINE>::const_iterator imageFileMachineIterator;
		private:
		const std::vector<PELIB_IMAGE_FILE_MACHINE> all =
		{
			PELIB_IMAGE_FILE_MACHINE_UNKNOWN,
			PELIB_IMAGE_FILE_MACHINE_I386,
			PELIB_IMAGE_FILE_MACHINE_I486,
			PELIB_IMAGE_FILE_MACHINE_PENTIUM,
			PELIB_IMAGE_FILE_MACHINE_R3000_BIG,
			PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE,
			PELIB_IMAGE_FILE_MACHINE_R4000,
			PELIB_IMAGE_FILE_MACHINE_R10000,
			PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2,
			PELIB_IMAGE_FILE_MACHINE_ALPHA,
			PELIB_IMAGE_FILE_MACHINE_SH3,
			PELIB_IMAGE_FILE_MACHINE_SH3DSP,
			PELIB_IMAGE_FILE_MACHINE_SH3E,
			PELIB_IMAGE_FILE_MACHINE_SH4,
			PELIB_IMAGE_FILE_MACHINE_SH5,
			PELIB_IMAGE_FILE_MACHINE_ARM,
			PELIB_IMAGE_FILE_MACHINE_THUMB,
			PELIB_IMAGE_FILE_MACHINE_ARMNT,
			PELIB_IMAGE_FILE_MACHINE_AM33,
			PELIB_IMAGE_FILE_MACHINE_POWERPC,
			PELIB_IMAGE_FILE_MACHINE_POWERPCFP,
			PELIB_IMAGE_FILE_MACHINE_IA64,
			PELIB_IMAGE_FILE_MACHINE_MIPS16,
			PELIB_IMAGE_FILE_MACHINE_MOTOROLA68000,
			PELIB_IMAGE_FILE_MACHINE_PARISC,
			PELIB_IMAGE_FILE_MACHINE_ALPHA64,
			PELIB_IMAGE_FILE_MACHINE_AXP64,
			PELIB_IMAGE_FILE_MACHINE_MIPSFPU,
			PELIB_IMAGE_FILE_MACHINE_MIPSFPU16,
			PELIB_IMAGE_FILE_MACHINE_TRICORE,
			PELIB_IMAGE_FILE_MACHINE_EBC,
			PELIB_IMAGE_FILE_MACHINE_AMD64,
			PELIB_IMAGE_FILE_MACHINE_M32R,
			PELIB_IMAGE_FILE_MACHINE_ARM64,
			PELIB_IMAGE_FILE_MACHINE_MSIL
		};
		public:
		PELIB_IMAGE_FILE_MACHINE_ITERATOR();
		~PELIB_IMAGE_FILE_MACHINE_ITERATOR();

		bool isValidMachineCode(PELIB_IMAGE_FILE_MACHINE value) const;
		imageFileMachineIterator begin() const;
		imageFileMachineIterator end() const;
	};

	struct PELIB_IMAGE_DOS_HEADER
	{
		std::uint16_t e_magic;
		std::uint16_t e_cblp;
		std::uint16_t e_cp;
		std::uint16_t e_crlc;
		std::uint16_t e_cparhdr;
		std::uint16_t e_minalloc;
		std::uint16_t e_maxalloc;
		std::uint16_t e_ss;
		std::uint16_t e_sp;
		std::uint16_t e_csum;
		std::uint16_t e_ip;
		std::uint16_t e_cs;
		std::uint16_t e_lfarlc;
		std::uint16_t e_ovno;
		std::uint16_t e_res[4];
		std::uint16_t e_oemid;
		std::uint16_t e_oeminfo;
		std::uint16_t e_res2[10];
		std::uint32_t e_lfanew;

		PELIB_IMAGE_DOS_HEADER()
		{
			memset(this, 0, sizeof(PELIB_IMAGE_DOS_HEADER));
		}

		static inline std::size_t size()
		{
			return 64;
		}
	};

	struct PELIB_IMAGE_FILE_HEADER
	{
		std::uint16_t Machine;
		std::uint16_t NumberOfSections;
		std::uint32_t TimeDateStamp;
		std::uint32_t PointerToSymbolTable;
		std::uint32_t NumberOfSymbols;
		std::uint16_t SizeOfOptionalHeader;
		std::uint16_t Characteristics;

		PELIB_IMAGE_FILE_HEADER()
		{
			Machine = 0;
			NumberOfSections = 0;
			TimeDateStamp = 0;
			PointerToSymbolTable = 0;
			NumberOfSymbols = 0;
			SizeOfOptionalHeader = 0;
			Characteristics = 0;
		}

		static inline std::size_t size()
		{
			return 20;
		}
	};

	struct PELIB_IMAGE_DATA_DIRECTORY
	{
		std::uint32_t VirtualAddress;
		std::uint32_t Size;

		PELIB_IMAGE_DATA_DIRECTORY()
		{
			VirtualAddress = 0;
			Size = 0;
		}

		static inline std::size_t size() {return 8;}
	};

	struct PELIB_IMAGE_OPTIONAL_HEADER32
	{
		std::uint16_t Magic;
		std::uint8_t  MajorLinkerVersion;
		std::uint8_t  MinorLinkerVersion;
		std::uint32_t SizeOfCode;
		std::uint32_t SizeOfInitializedData;
		std::uint32_t SizeOfUninitializedData;
		std::uint32_t AddressOfEntryPoint;
		std::uint32_t BaseOfCode;
		std::uint32_t BaseOfData;
		std::uint32_t ImageBase;
		std::uint32_t SectionAlignment;
		std::uint32_t FileAlignment;
		std::uint16_t MajorOperatingSystemVersion;
		std::uint16_t MinorOperatingSystemVersion;
		std::uint16_t MajorImageVersion;
		std::uint16_t MinorImageVersion;
		std::uint16_t MajorSubsystemVersion;
		std::uint16_t MinorSubsystemVersion;
		std::uint32_t Win32VersionValue;
		std::uint32_t SizeOfImage;
		std::uint32_t SizeOfHeaders;
		std::uint32_t CheckSum;
		std::uint16_t Subsystem;
		std::uint16_t DllCharacteristics;
		std::uint32_t SizeOfStackReserve;
		std::uint32_t SizeOfStackCommit;
		std::uint32_t SizeOfHeapReserve;
		std::uint32_t SizeOfHeapCommit;
		std::uint32_t LoaderFlags;
		std::uint32_t NumberOfRvaAndSizes;

		PELIB_IMAGE_DATA_DIRECTORY DataDirectory[PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	struct PELIB_IMAGE_OPTIONAL_HEADER64
	{
		std::uint16_t Magic;
		std::uint8_t  MajorLinkerVersion;
		std::uint8_t  MinorLinkerVersion;
		std::uint32_t SizeOfCode;
		std::uint32_t SizeOfInitializedData;
		std::uint32_t SizeOfUninitializedData;
		std::uint32_t AddressOfEntryPoint;
		std::uint32_t BaseOfCode;
		std::uint64_t ImageBase;
		std::uint32_t SectionAlignment;
		std::uint32_t FileAlignment;
		std::uint16_t MajorOperatingSystemVersion;
		std::uint16_t MinorOperatingSystemVersion;
		std::uint16_t MajorImageVersion;
		std::uint16_t MinorImageVersion;
		std::uint16_t MajorSubsystemVersion;
		std::uint16_t MinorSubsystemVersion;
		std::uint32_t Win32VersionValue;
		std::uint32_t SizeOfImage;
		std::uint32_t SizeOfHeaders;
		std::uint32_t CheckSum;
		std::uint16_t Subsystem;
		std::uint16_t DllCharacteristics;
		std::uint64_t SizeOfStackReserve;
		std::uint64_t SizeOfStackCommit;
		std::uint64_t SizeOfHeapReserve;
		std::uint64_t SizeOfHeapCommit;
		std::uint32_t LoaderFlags;
		std::uint32_t NumberOfRvaAndSizes;

		PELIB_IMAGE_DATA_DIRECTORY DataDirectory[PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	// Common structure for both 32-bit and 64-bit PE files
	struct PELIB_IMAGE_OPTIONAL_HEADER
	{
		std::uint16_t Magic;
		std::uint8_t  MajorLinkerVersion;
		std::uint8_t  MinorLinkerVersion;
		std::uint32_t SizeOfCode;
		std::uint32_t SizeOfInitializedData;
		std::uint32_t SizeOfUninitializedData;
		std::uint32_t AddressOfEntryPoint;
		std::uint32_t BaseOfCode;
		std::uint32_t BaseOfData;
		std::uint64_t ImageBase;
		std::uint32_t SectionAlignment;
		std::uint32_t FileAlignment;
		std::uint16_t MajorOperatingSystemVersion;
		std::uint16_t MinorOperatingSystemVersion;
		std::uint16_t MajorImageVersion;
		std::uint16_t MinorImageVersion;
		std::uint16_t MajorSubsystemVersion;
		std::uint16_t MinorSubsystemVersion;
		std::uint32_t Win32VersionValue;
		std::uint32_t SizeOfImage;
		std::uint32_t SizeOfHeaders;
		std::uint32_t CheckSum;
		std::uint16_t Subsystem;
		std::uint16_t DllCharacteristics;
		std::uint64_t SizeOfStackReserve;
		std::uint64_t SizeOfStackCommit;
		std::uint64_t SizeOfHeapReserve;
		std::uint64_t SizeOfHeapCommit;
		std::uint32_t LoaderFlags;
		std::uint32_t NumberOfRvaAndSizes;

		PELIB_IMAGE_DATA_DIRECTORY DataDirectory[PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	template<int x>
	struct PELIB_IMAGE_NT_HEADERS_EX
	{
		std::uint32_t Signature;
		PELIB_IMAGE_FILE_HEADER FileHeader;
		PELIB_IMAGE_OPTIONAL_HEADER OptionalHeader;
		std::vector<PELIB_IMAGE_DATA_DIRECTORY> dataDirectories;
		bool lastDirectoryIsIncomplete;

		unsigned int sizeOfSignature() const
		{
			return sizeof(std::uint32_t);
		}

		unsigned int size() const
		{
			return sizeOfSignature()
				+ PELIB_IMAGE_FILE_HEADER::size()
				+ sizeof(PELIB_IMAGE_OPTIONAL_HEADER)
				+ static_cast<unsigned int>(dataDirectories.size()) * PELIB_IMAGE_DATA_DIRECTORY::size();
		}

		unsigned int loadedSize() const
		{
			auto res = size();
			if (lastDirectoryIsIncomplete && !dataDirectories.empty())
			{
				res -= sizeof(dataDirectories[0].Size);
			}

			return res;
		}

		PELIB_IMAGE_NT_HEADERS_EX()
		{
			Signature = 0;
			lastDirectoryIsIncomplete = false;
		}
	};

	const unsigned int PELIB_IMAGE_SIZEOF_SHORT_NAME  = 8;
	const unsigned int PELIB_IMAGE_SIZEOF_MAX_NAME    = 1024;

	struct PELIB_IMAGE_SECTION_HEADER
	{
		PELIB_IMAGE_SECTION_HEADER()
		{
			memset(Name, 0, sizeof(Name));
			VirtualSize = 0;
			VirtualAddress = 0;
			SizeOfRawData = 0;
			PointerToRawData = 0;
			PointerToRelocations = 0;
			PointerToLinenumbers = 0;
			NumberOfRelocations = 0;
			NumberOfLinenumbers = 0;
			Characteristics = 0;
		}

		std::uint8_t  Name[PELIB_IMAGE_SIZEOF_SHORT_NAME];
		std::uint32_t VirtualSize;
		std::uint32_t VirtualAddress;
		std::uint32_t SizeOfRawData;
		std::uint32_t PointerToRawData;
		std::uint32_t PointerToRelocations;
		std::uint32_t PointerToLinenumbers;
		std::uint16_t NumberOfRelocations;
		std::uint16_t NumberOfLinenumbers;
		std::uint32_t Characteristics;
	};

	struct PELIB_SECTION_HEADER : public PELIB_IMAGE_SECTION_HEADER
	{
		void setName(const char * newName)
		{
			// Copy the name to the fixed_length name
			memset(Name, 0, PELIB_IMAGE_SIZEOF_SHORT_NAME);
			for(std::size_t i = 0; i < PELIB_IMAGE_SIZEOF_SHORT_NAME; i++)
			{
				if(newName[i] == 0)
					break;
				Name[i] = newName[i];
			}

			// Also put it to the string
			sectionName = newName;
		}

		const std::string & getName() const
		{
			return sectionName;
		}

		void setVirtualRange(std::uint32_t newVirtualAddress, std::uint32_t newVirtualSize)
		{
			if(newVirtualAddress != UINT32_MAX)
				VirtualAddress = newVirtualAddress;
			if(newVirtualSize != UINT32_MAX)
				VirtualSize = newVirtualSize;
		}

		void setRawDataRange(std::uint32_t newPointerToRawData, std::uint32_t newSizeOfRawData)
		{
			if(newPointerToRawData != UINT32_MAX)
				PointerToRawData = newPointerToRawData;
			if(newSizeOfRawData != UINT32_MAX)
				SizeOfRawData = newSizeOfRawData;
		}

		static const std::size_t size()
		{
			return sizeof(PELIB_IMAGE_SECTION_HEADER);
		}

		std::string sectionName;
	};

	struct PELIB_IMAGE_THUNK_DATA
	{
		std::uint64_t Ordinal;

		PELIB_IMAGE_THUNK_DATA()
		{
			Ordinal = 0;
		}
	};

	struct PELIB_IMAGE_IMPORT_DESCRIPTOR
	{
		std::uint32_t	OriginalFirstThunk;
		std::uint32_t	TimeDateStamp;
		std::uint32_t	ForwarderChain;
		std::uint32_t	Name;
		std::uint32_t	FirstThunk;

		PELIB_IMAGE_IMPORT_DESCRIPTOR()
		{
			OriginalFirstThunk = 0;
			TimeDateStamp = 0;
			ForwarderChain = 0;
			Name = 0;
			FirstThunk = 0;
		}

		static inline std::size_t size() {return 20;}
	};

	struct PELIB_IMAGE_EXPORT_DIRECTORY
	{
		std::uint32_t	Characteristics;
		std::uint32_t	TimeDateStamp;
		std::uint16_t	MajorVersion;
		std::uint16_t	MinorVersion;
		std::uint32_t	Name;
		std::uint32_t	Base;
		std::uint32_t	NumberOfFunctions;
		std::uint32_t	NumberOfNames;
		std::uint32_t	AddressOfFunctions;
		std::uint32_t	AddressOfNames;
		std::uint32_t	AddressOfNameOrdinals;

		PELIB_IMAGE_EXPORT_DIRECTORY()
		{
			Characteristics = 0;
			TimeDateStamp = 0;
			MajorVersion = 0;
			MinorVersion = 0;
			Name = 0;
			Base = 0;
			NumberOfFunctions = 0;
			NumberOfNames = 0;
			AddressOfFunctions = 0;
			AddressOfNames = 0;
			AddressOfNameOrdinals = 0;
		}

		static inline std::size_t size()
		{
			return sizeof(PELIB_IMAGE_EXPORT_DIRECTORY);
		}
	};

	struct PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR
	{
		std::uint32_t	TimeDateStamp;
		std::uint16_t	OffsetModuleName;
		std::uint16_t	NumberOfModuleForwarderRefs;

		PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR()
		{
			TimeDateStamp = 0;
			OffsetModuleName = 0;
			NumberOfModuleForwarderRefs = 0;
		}

		static inline std::size_t size()
		{
			return 8;
		}
	};

	// Stores all necessary information about a BoundImport field.
	struct PELIB_IMAGE_BOUND_DIRECTORY
	{
		PELIB_IMAGE_BOUND_IMPORT_DESCRIPTOR ibdDescriptor; ///< Information about the imported file.
		std::string strModuleName; ///< Name of the imported file.
		std::vector<PELIB_IMAGE_BOUND_DIRECTORY> moduleForwarders;

		// Will be used in std::find_if
		// Passing by-reference not possible (see C++ Standard Core Language Defect Reports, Revision 29, Issue 106)
		/// Compares the passed filename to the struct's filename.
		bool equal(const std::string strModuleName2) const;

		std::size_t size() const;
	};

	struct PELIB_EXP_FUNC_INFORMATION
	{
		std::uint32_t addroffunc;
		std::uint32_t addrofname;
		std::uint16_t ordinal;
		std::string funcname;

		PELIB_EXP_FUNC_INFORMATION();

		bool equal(const std::string strFunctionName) const;
		inline unsigned int size() const
		{
			unsigned int uiSize = 4;
			if (addroffunc) uiSize += 2;// + 4;
			if (!funcname.empty())
				uiSize = (unsigned int)(uiSize + 4 + funcname.size() + 1);
			return uiSize;
		}
	};

	struct PELIB_IMAGE_RESOURCE_DIRECTORY
	{
		std::uint32_t	Characteristics;
		std::uint32_t	TimeDateStamp;
		std::uint16_t	MajorVersion;
		std::uint16_t	MinorVersion;
		std::uint16_t	NumberOfNamedEntries;
		std::uint16_t	NumberOfIdEntries;

		PELIB_IMAGE_RESOURCE_DIRECTORY();

		static inline std::size_t size() {return 16;}
	};

	struct PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY
	{
		std::uint32_t	Name;
		std::uint32_t	OffsetToData;

		PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY();

		static inline std::size_t size() {return 8;}
	};

	const unsigned int PELIB_IMAGE_SIZEOF_BASE_RELOCATION = 8;

	struct PELIB_IMG_RES_DIR_ENTRY
	{
		PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY irde;
		std::string wstrName;

		bool operator<(const PELIB_IMG_RES_DIR_ENTRY& first) const;

	};

	struct PELIB_IMAGE_BASE_RELOCATION
	{
		std::uint32_t	VirtualAddress;
		std::uint32_t	SizeOfBlock;

		PELIB_IMAGE_BASE_RELOCATION()
		{
			VirtualAddress = 0;
			SizeOfBlock = 0;
		}

		static inline std::size_t size() {return 72;}
	};

	struct PELIB_IMAGE_COR20_HEADER
	{
		std::uint32_t	cb;
		std::uint16_t	MajorRuntimeVersion;
		std::uint16_t	MinorRuntimeVersion;
		PELIB_IMAGE_DATA_DIRECTORY MetaData;
		std::uint32_t	Flags;
		std::uint32_t	EntryPointToken;
		PELIB_IMAGE_DATA_DIRECTORY Resources;
		PELIB_IMAGE_DATA_DIRECTORY StrongNameSignature;
		PELIB_IMAGE_DATA_DIRECTORY CodeManagerTable;
		PELIB_IMAGE_DATA_DIRECTORY VTableFixups;
		PELIB_IMAGE_DATA_DIRECTORY ExportAddressTableJumps;
		PELIB_IMAGE_DATA_DIRECTORY ManagedNativeHeader;

		PELIB_IMAGE_COR20_HEADER();
		static inline std::size_t size() {return 72;}
	};

	// Used to store a file's export table.
	struct PELIB_IMAGE_EXP_DIRECTORY
	{
		/// The IMAGE_EXPORTED_DIRECTORY of a file's export table.
		PELIB_IMAGE_EXPORT_DIRECTORY ied;
		/// The original filename of current file.
		std::string name;
		std::vector<PELIB_EXP_FUNC_INFORMATION> functions;

		inline std::size_t size() const
		{
			return (PELIB_IMAGE_EXPORT_DIRECTORY::size() + name.size() + 1 +
			std::accumulate(functions.begin(), functions.end(), 0, accumulate<PELIB_EXP_FUNC_INFORMATION>));
		}
	};

	bool isEqualNc(const std::string& s1, const std::string& s2);

	// Used for parsing a file's import table. It combines the function name, the hint
	// and the IMAGE_THUNK_DATA of an imported function.
	struct PELIB_THUNK_DATA
	{
		/// The IMAGE_THUNK_DATA struct of an imported function.
		PELIB_IMAGE_THUNK_DATA itd;
		/// The function name of an imported function.
		std::string fname;
		/// The RVA of the patched address (from the FirstThunk)
		std::uint32_t patchRva;
		/// The hint of an imported function (only if imported by name)
		std::uint16_t hint;

		PELIB_THUNK_DATA()
		{
			patchRva = 0;
			hint = 0;
		}

		bool equalHint(std::uint16_t wHint) const
		{
			return hint == wHint;
//			return itd.Ordinal == (wHint | PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG);
		}

		bool equalFunctionName(std::string strFunctionName) const
		{
			return isEqualNc(fname, strFunctionName);
		}

		std::uint32_t calculateSize(std::uint32_t pointerSize) const
		{
			return pointerSize + fname.size() + 1 + sizeof(hint);
		}
	};

	struct PELIB_DELAY_IMPORT
	{
		std::uint64_t address;
		std::uint16_t hint;
		std::string fname;

		PELIB_DELAY_IMPORT() : hint(0)
		{

		}
	};

	// Used to store a file's import table. Every struct of this sort
	// can store import information of one DLL.
	struct PELIB_IMAGE_IMPORT_DIRECTORY
	{
		/// The IMAGE_IMPORT_DESCRIPTOR of an imported DLL.
		PELIB_IMAGE_IMPORT_DESCRIPTOR impdesc;
		/// The name of an imported DLL.
		std::string name;
		/// The list of functions imported from the DLL
		//std::vector<PELIB_THUNK_DATA> originalfirstthunk;
		//std::vector<PELIB_THUNK_DATA> firstthunk;
		std::vector<PELIB_THUNK_DATA> thunk_data;

		inline std::uint32_t calculateSize(std::uint32_t pointerSize) const
		{
			std::uint32_t totalSize = sizeof(PELIB_IMAGE_IMPORT_DESCRIPTOR) + name.size() + 1;  // descriptor + dllname

			for(const auto & element : thunk_data)
				totalSize += element.calculateSize(pointerSize);
			return totalSize + pointerSize;                            // Add zero-termination
		}

		bool operator==(std::string strFilename) const
		{
			return isEqualNc(this->name, strFilename);
		}
	};

	const std::size_t IMPORT_LIBRARY_MAX_LENGTH = 256;
	const std::size_t IMPORT_SYMBOL_MAX_LENGTH = 256;

	struct PELIB_IMAGE_RESOURCE_DATA_ENTRY
	{
		std::uint32_t	OffsetToData;
		std::uint32_t	Size;
		std::uint32_t	CodePage;
		std::uint32_t	Reserved;

		static inline unsigned int size() {return 16;}

		PELIB_IMAGE_RESOURCE_DATA_ENTRY();
	};

	struct PELIB_IMAGE_RESOURCE_DATA
	{
		PELIB_IMAGE_RESOURCE_DATA_ENTRY irdEntry;
		std::vector<std::uint8_t> vData;
	};

	struct IMG_BASE_RELOC
	{
		PELIB_IMAGE_BASE_RELOCATION ibrRelocation;
		std::vector<std::uint16_t> vRelocData;
	};

	struct PELIB_IMAGE_DEBUG_DIRECTORY
	{
		std::uint32_t	Characteristics;
		std::uint32_t	TimeDateStamp;
		std::uint16_t	MajorVersion;
		std::uint16_t	MinorVersion;
		std::uint32_t	Type;
		std::uint32_t	SizeOfData;
		std::uint32_t	AddressOfRawData;
		std::uint32_t	PointerToRawData;

		static std::size_t size() {return 28;}

		PELIB_IMAGE_DEBUG_DIRECTORY();
	};

	struct PELIB_IMG_DEBUG_DIRECTORY
	{
		PELIB_IMAGE_DEBUG_DIRECTORY idd;
		std::vector<std::uint8_t> data;
	};

	struct PELIB_IMAGE_TLS_DIRECTORY32
	{
		std::uint32_t StartAddressOfRawData;
		std::uint32_t EndAddressOfRawData;
		std::uint32_t AddressOfIndex;
		std::uint32_t AddressOfCallBacks;
		std::uint32_t SizeOfZeroFill;
		std::uint32_t Characteristics;
	};

	struct PELIB_IMAGE_TLS_DIRECTORY
	{
		std::uint64_t StartAddressOfRawData;
		std::uint64_t EndAddressOfRawData;
		std::uint64_t AddressOfIndex;
		std::uint64_t AddressOfCallBacks;
		std::uint32_t SizeOfZeroFill;
		std::uint32_t Characteristics;

		PELIB_IMAGE_TLS_DIRECTORY()
		{
			StartAddressOfRawData = 0;
			EndAddressOfRawData = 0;
			AddressOfIndex = 0;
			AddressOfCallBacks = 0;
			SizeOfZeroFill = 0;
			Characteristics = 0;
		}
	};

	std::uint32_t BytesToPages(std::uint32_t ByteSize);
	std::uint32_t AlignToSize(std::uint32_t ByteSize, std::uint32_t AlignSize);

	std::uint64_t fileSize(const std::string& filename);
	std::uint64_t fileSize(std::istream& stream);
	std::uint64_t fileSize(std::ofstream& file);
	std::uint64_t fileSize(std::fstream& file);
	unsigned int alignOffset(unsigned int uiOffset, unsigned int uiAlignment);
	std::size_t getStringFromFileOffset(
			std::istream &stream,
			std::string &result,
			std::size_t fileOffset,
			std::size_t maxLength = 0,
			bool isPrintable = false,
			bool isNotTooLong = false);

	const char * getLoaderErrorString(LoaderError ldrError, bool userFriendly = false);
	bool getLoaderErrorLoadableAnyway(LoaderError ldrError);

  /*  enum MzHeader_Field {e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc,
						e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid,
						e_oeminfo, e_res2, e_lfanew};
	enum PeHeader_Field {NtSignature, Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable,
						NumberOfSymbols, SizeOfOptionalHeader, Characteristics, Magic,
						MajorLinkerVersion, MinorLinkerVersion, SizeOfCode, SizeOfInitializedData,
						SizeOfUninitializedData, AddressOfEntryPoint, BaseOfCode, BaseOfData, ImageBase,
						SectionAlignment, FileAlignment, MajorOperatingSystemVersion, MinorOperatingSystemVersion,
						MajorImageVersion, MinorImageVersion, MajorSubsystemVersion, MinorSubsystemVersion,
						Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum, Subsystem, DllCharacteristics,
						SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit,
						LoaderFlags, NumberOfRvaAndSizes, DataDirectoryRva, DataDirectorySize};
	enum Section_Field {SectionName, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations,
						PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers, SectionCharacteristics};
*/

	const unsigned int PELIB_IMAGE_SIZEOF_COFF_SYMBOL = 18;
	const std::size_t COFF_SYMBOL_NAME_MAX_LENGTH = 256;

	struct PELIB_IMAGE_COFF_SYMBOL
	{
		std::uint32_t Index;
		std::string Name;
		std::uint32_t Value;
		std::uint16_t SectionNumber;
		std::uint8_t TypeComplex;
		std::uint8_t TypeSimple;
		std::uint8_t StorageClass;
		std::uint8_t NumberOfAuxSymbols;

		PELIB_IMAGE_COFF_SYMBOL() : Index(0), Value(0), SectionNumber(0),
			TypeComplex(0), TypeSimple(0), StorageClass(0), NumberOfAuxSymbols(0)
		{

		}
	};

	struct PELIB_IMAGE_RICH_HEADER_RECORD
	{
		std::string Signature;
		std::uint16_t ProductId;
		std::uint16_t ProductBuild;
		std::uint32_t Count;
		std::string ProductName;
		std::string VisualStudioName;

		PELIB_IMAGE_RICH_HEADER_RECORD() : ProductId(0), ProductBuild(0), Count(0)
		{

		}
	};

	struct PELIB_IMAGE_LOAD_CONFIG_CODE_INTEGRITY
	{
		std::uint16_t Flags;                         // Flags to indicate if CI information is available, etc.
		std::uint16_t Catalog;                       // 0xFFFF means not available
		std::uint32_t CatalogOffset;
		std::uint32_t Reserved;                      // Additional bitmask to be defined later
	};

	// Load config directory
	struct PELIB_IMAGE_LOAD_CONFIG_DIRECTORY32
	{
		std::uint32_t Size;
		std::uint32_t TimeDateStamp;
		std::uint16_t MajorVersion;
		std::uint16_t MinorVersion;
		std::uint32_t GlobalFlagsClear;
		std::uint32_t GlobalFlagsSet;
		std::uint32_t CriticalSectionDefaultTimeout;
		std::uint32_t DeCommitFreeBlockThreshold;
		std::uint32_t DeCommitTotalFreeThreshold;
		std::uint32_t LockPrefixTable;
		std::uint32_t MaximumAllocationSize;
		std::uint32_t VirtualMemoryThreshold;
		std::uint32_t ProcessHeapFlags;
		std::uint32_t ProcessAffinityMask;
		std::uint16_t CSDVersion;
		std::uint16_t DependentLoadFlags;
		std::uint32_t EditList;
		std::uint32_t SecurityCookie;
		std::uint32_t SEHandlerTable;
		std::uint32_t SEHandlerCount;
		std::uint32_t GuardCFCheckFunctionPointer;
		std::uint32_t GuardCFDispatchFunctionPointer;
		std::uint32_t GuardCFFunctionTable;
		std::uint32_t GuardCFFunctionCount;
		std::uint32_t GuardFlags;
		PELIB_IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		std::uint32_t GuardAddressTakenIatEntryTable;
		std::uint32_t GuardAddressTakenIatEntryCount;
		std::uint32_t GuardLongJumpTargetTable;
		std::uint32_t GuardLongJumpTargetCount;
		std::uint32_t DynamicValueRelocTable;
		std::uint32_t CHPEMetadataPointer;
		std::uint32_t GuardRFFailureRoutine;
		std::uint32_t GuardRFFailureRoutineFunctionPointer;
		std::uint32_t DynamicValueRelocTableOffset;
		std::uint16_t DynamicValueRelocTableSection;
		std::uint16_t Reserved2;
		std::uint32_t GuardRFVerifyStackPointerFunctionPointer;
		std::uint32_t HotPatchTableOffset;
		std::uint32_t Reserved3;
		std::uint32_t EnclaveConfigurationPointer;
		std::uint32_t VolatileMetadataPointer;
		std::uint32_t GuardEHContinuationTable;
		std::uint32_t GuardEHContinuationCount;
	};

	struct PELIB_IMAGE_LOAD_CONFIG_DIRECTORY64
	{
		std::uint32_t Size;
		std::uint32_t TimeDateStamp;
		std::uint16_t MajorVersion;
		std::uint16_t MinorVersion;
		std::uint32_t GlobalFlagsClear;
		std::uint32_t GlobalFlagsSet;
		std::uint32_t CriticalSectionDefaultTimeout;
		std::uint64_t DeCommitFreeBlockThreshold;
		std::uint64_t DeCommitTotalFreeThreshold;
		std::uint64_t LockPrefixTable;
		std::uint64_t MaximumAllocationSize;
		std::uint64_t VirtualMemoryThreshold;
		std::uint64_t ProcessAffinityMask;
		std::uint32_t ProcessHeapFlags;
		std::uint16_t CSDVersion;
		std::uint16_t DependentLoadFlags;
		std::uint64_t EditList;
		std::uint64_t SecurityCookie;
		std::uint64_t SEHandlerTable;
		std::uint64_t SEHandlerCount;
		std::uint64_t GuardCFCheckFunctionPointer;
		std::uint64_t GuardCFDispatchFunctionPointer;
		std::uint64_t GuardCFFunctionTable;
		std::uint64_t GuardCFFunctionCount;
		std::uint32_t GuardFlags;
		PELIB_IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
		std::uint64_t GuardAddressTakenIatEntryTable;
		std::uint64_t GuardAddressTakenIatEntryCount;
		std::uint64_t GuardLongJumpTargetTable;
		std::uint64_t GuardLongJumpTargetCount;
		std::uint64_t DynamicValueRelocTable;
		std::uint64_t CHPEMetadataPointer;
		std::uint64_t GuardRFFailureRoutine;
		std::uint64_t GuardRFFailureRoutineFunctionPointer;
		std::uint32_t DynamicValueRelocTableOffset;
		std::uint16_t DynamicValueRelocTableSection;
		std::uint16_t Reserved2;
		std::uint64_t GuardRFVerifyStackPointerFunctionPointer;
		std::uint32_t HotPatchTableOffset;
		std::uint32_t Reserved3;
		std::uint64_t EnclaveConfigurationPointer;
		std::uint64_t VolatileMetadataPointer;
		std::uint64_t GuardEHContinuationTable;
		std::uint64_t GuardEHContinuationCount;
	};

	// This structure is defined in the "delayimp.h" header file as ImgDelayDescrV1 or ImgDelayDescrV2.
	// Fields suffixed with "Rva" are direct virtual addresses in the "V1" version of the structure.
	struct PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR
	{
		std::uint32_t Attributes;                           // Attributes. See PELIB_DELAY_ATTRIBUTE_XXX for more info
		std::uint32_t NameRva;                              // RVA to dll name
		std::uint32_t ModuleHandleRva;                      // RVA of module handle
		std::uint32_t DelayImportAddressTableRva;           // RVA of the IAT
		std::uint32_t DelayImportNameTableRva;              // RVA of the INT
		std::uint32_t BoundDelayImportTableRva;             // RVA of the optional bound IAT
		std::uint32_t UnloadDelayImportTableRva;            // RVA of optional copy of original IAT
		std::uint32_t TimeStamp;                            // 0 if not bound, O.W. date/time stamp of DLL bound to (Old BIND)
	};

	const std::uint32_t PELIB_DELAY_ATTRIBUTE_V2 = 0x01;	// If this bit is set, then the structure is version 2

	struct PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD
	{
		private:
			typedef typename std::vector<PELIB_DELAY_IMPORT>::const_iterator DelayImportIterator;
			bool hasOrdinalNumbers;
			std::vector<PELIB_DELAY_IMPORT> Functions;

		public:
			PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR delayedImport;
			std::string Name;

			PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD()
			{
				init();
			}

			~PELIB_IMAGE_DELAY_IMPORT_DIRECTORY_RECORD()
			{

			}

			void init()
			{
				memset(&delayedImport, 0, sizeof(PELIB_IMAGE_DELAY_LOAD_DESCRIPTOR));
				hasOrdinalNumbers = false;
				Functions.clear();
				Name.clear();
			}

			void addFunction(const PELIB_DELAY_IMPORT &function)
			{
				Functions.push_back(function);
				if(function.hint)
				{
					hasOrdinalNumbers = true;
				}
			}

			auto ordinalNumbersAreValid() const
			{
				return hasOrdinalNumbers;
			}

			auto getNumberOfFunctions() const
			{
				return Functions.size();
			}

			const PELIB_DELAY_IMPORT *getFunction(std::size_t index) const
			{
				return index < getNumberOfFunctions() ? &Functions[index] : nullptr;
			}

			PELIB_DELAY_IMPORT *getFunction(std::size_t index)
			{
				return index < getNumberOfFunctions() ? &Functions[index] : nullptr;
			}

			const DelayImportIterator begin() const
			{
				return Functions.begin();
			}

			DelayImportIterator begin()
			{
				return Functions.begin();
			}

			const DelayImportIterator end() const
			{
				return Functions.end();
			}

			DelayImportIterator end()
			{
				return Functions.end();
			}
	};

	enum
	{
		PELIB_WIN_CERT_REVISION_1_0 = 0x100,
		PELIB_WIN_CERT_REVISION_2_0 = 0x200
	};

	enum
	{
		PELIB_WIN_CERT_TYPE_X509 = 1,
		PELIB_WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2,
		PELIB_WIN_CERT_TYPE_RESERVED_1 = 3,
		PELIB_WIN_CERT_TYPE_TS_STACK_SIGNED = 4
	};

	struct PELIB_IMAGE_CERTIFICATE_ENTRY
	{
		std::uint32_t Length;
		std::uint16_t Revision;
		std::uint16_t CertificateType;
		std::vector<unsigned char> Certificate;

		static inline unsigned int size() { return 8; }
	};
}

class IStreamWrapper
{
	public:
		IStreamWrapper(std::istream& stream) :
				_stream(stream)
		{
			_pos = _stream.tellg();
			_state = _stream.rdstate();
			_stream.clear();
		}

		~IStreamWrapper()
		{
			_stream.setstate(_state);
			_stream.seekg(_pos, std::ios::beg);
		}

		operator std::istream&() const
		{
			return _stream;
		}
		std::istream& getIstream()
		{
			return _stream;
		}

		// Needed wrapped methods.
		//
		explicit operator bool() const
		{
			return static_cast<bool>(_stream);
		}

		IStreamWrapper& seekg(std::streampos pos)
		{
			_stream.seekg(pos);
			return *this;
		}

		IStreamWrapper& seekg(std::streamoff off, std::ios_base::seekdir way)
		{
			_stream.seekg(off, way);
			return *this;
		}

		std::streampos tellg()
		{
			return _stream.tellg();
		}

		IStreamWrapper& read(char* s, std::streamsize n)
		{
			_stream.read(s, n);
			return *this;
		}

		std::streamsize gcount() const
		{
			return _stream.gcount();
		}

		void clear(std::ios_base::iostate state = std::ios_base::goodbit)
		{
			return _stream.clear(state);
		}

	private:
		std::istream& _stream;
		std::streampos _pos;
		std::ios::iostate _state;
};

#endif
