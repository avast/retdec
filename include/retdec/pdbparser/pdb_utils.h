/**
 * @file include/retdec/pdbparser/pdb_utils.h
 * @brief Utils
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PDBPARSER_PDB_UTILS_H
#define RETDEC_PDBPARSER_PDB_UTILS_H

#include <map>
#include <string>
#include <vector>

namespace retdec {
namespace pdbparser {

// =================================================================
// VISUAL C++ TYPES AND SCRUCTURES
// =================================================================

typedef unsigned int PDB_DWORD;
typedef PDB_DWORD * PDB_PDWORD;
typedef char * PDB_DWORD_PTR;
typedef int PDB_LONG;
typedef PDB_LONG * PDB_PLONG;
typedef unsigned int PDB_ULONG;
typedef PDB_ULONG * PDB_PULONG;
typedef char * PDB_ULONG_PTR;
typedef char PDB_CHAR;
typedef PDB_CHAR * PDB_PCHAR;
typedef unsigned char PDB_UCHAR;
typedef PDB_UCHAR * PDB_PUCHAR;
typedef unsigned char PDB_BYTE;
typedef PDB_BYTE * PDB_PBYTE;
typedef unsigned short PDB_WORD;
typedef PDB_WORD * PDB_PWORD;
typedef short PDB_SHORT;
typedef PDB_SHORT * PDB_PSHORT;
typedef unsigned short PDB_USHORT;
typedef PDB_USHORT * PDB_PUSHORT;
typedef PDB_BYTE PDB_BOOLEAN;
typedef void PDB_VOID;
typedef void * PDB_PVOID;
typedef size_t PDB_SIZE_T;

#define TRUE true
#define FALSE false

#define CHAR_ sizeof(PDB_CHAR)
#define WORD_ sizeof(PDB_WORD)
#define SHORT_ sizeof(PDB_SHORT)
#define USHORT_ sizeof(PDB_USHORT)
#define LONG_ sizeof(PDB_LONG)
#define ULONG_ sizeof(PDB_ULONG)
#define DWORD_ sizeof(PDB_DWORD)

typedef struct PDB__GUID
{
		unsigned long Data1;
		unsigned short Data2;
		unsigned short Data3;
		unsigned char Data4[8];
} PDB_GUID;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct PDB__IMAGE_SECTION_HEADER
{
		PDB_BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
		union
		{
				PDB_DWORD PhysicalAddress;
				PDB_DWORD VirtualSize;
		} Misc;
		PDB_DWORD VirtualAddress;
		PDB_DWORD SizeOfRawData;
		PDB_DWORD PointerToRawData;
		PDB_DWORD PointerToRelocations;
		PDB_DWORD PointerToLinenumbers;
		PDB_WORD NumberOfRelocations;
		PDB_WORD NumberOfLinenumbers;
		PDB_DWORD Characteristics;
} PDB_IMAGE_SECTION_HEADER, *PDB_PIMAGE_SECTION_HEADER;

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// =================================================================
// PDB PARSER TYPES AND STRUCTURES
// =================================================================

// PDB Stream
typedef struct _PDBStream
{
		char * data;  // stream data pointer
		int size;  // stream size in bytes
		bool unused;  // indicates unused stream
		bool linear;  // stream is linear in PDB file
} PDBStream;

// PDB Modules vector
typedef std::vector<PDBStream> PDBStreamsVec;

// PDB Module
typedef struct _PDBModule
{
		const char * name;  // module name
		int stream_num;  // number of stream with module symbols
		PDBStream * stream;  // stream with module symbols
} PDBModule;

// PDB Modules vector
typedef std::vector<PDBModule> PDBModulesVec;

// PDB PE Section
typedef struct _PDBPESection
{
		const char * name;  // section name
		PDB_DWORD virtual_address;  // virtual address
		PDB_DWORD file_address;  // address in file
} PDBPESection;

// PDB PE sections vector
typedef std::vector<PDBPESection> PDBSectionsVec;

// General PDB symbol structure
typedef struct _PDBGeneralSymbol
{
		PDB_WORD size;  // symbol data size
		PDB_WORD type;  // symbol type
		PDB_BYTE data[];  // symbol data
} PDBGeneralSymbol;

// Big PDB symbol structure
typedef struct _PDBBigSymbol
{
		PDB_DWORD type;  // symbol type
		PDB_DWORD size;  // symbol data size
		PDB_BYTE data[];  // symbol data
} PDBBigSymbol;

// =================================================================
// UTILITY FUNCTIONS
// =================================================================

PDB_PBYTE RecordValue(PDB_PBYTE pbData, PDB_PDWORD pdValue);  // Get numeric value followed by string from PDB record
void print_dwords(PDB_DWORD *data, int len);  // Print list of dwords (hexadecomally)
void print_bytes(PDB_BYTE *data, int len);  // Print list of bytes (hexadecomally)

} // namespace pdbparser
} // namespace retdec

#endif
