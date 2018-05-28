/**
 * @file include/retdec/pdbparser/pdb_file.h
 * @brief PDB file
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PDBPARSER_PDB_FILE_H
#define RETDEC_PDBPARSER_PDB_FILE_H

#include "retdec/pdbparser/pdb_info.h"
#include "retdec/pdbparser/pdb_symbols.h"
#include "retdec/pdbparser/pdb_types.h"
#include "retdec/pdbparser/pdb_utils.h"

namespace retdec {
namespace pdbparser {

// =================================================================
// STATES
// =================================================================

enum PDBFileState
{
	PDB_STATE_OK,
	PDB_STATE_ALREADY_LOADED,
	PDB_STATE_ERR_FILE_OPEN,
	PDB_STATE_INVALID_FILE,
	PDB_STATE_UNSUPPORTED_VERSION
};

// =================================================================
// PDB_VERSIONS
// =================================================================

#define PDB_VERSION_200         0x200  // binary version number
#define PDB_SIGNATURE_200_SIZE  0x2C   // signature size (bytes)
#define PDB_SIGNATURE_200 "Microsoft C/C++ program database 2.00\r\n\032JG\0"

#define PDB_VERSION_700         0x700  // binary version number
#define PDB_SIGNATURE_700_SIZE  0x20   // signature size (bytes)
#define PDB_SIGNATURE_700 "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0"

// some arbitrary, hopefully big enough, signature size
#define PDB_VERSION_INDEPENDENT_SIGNATURE_SIZE 0x100

// =================================================================
// STREAM IDS
// =================================================================

#define PDB_STREAM_ROOT     0 // PDB root directory
#define PDB_STREAM_PDB      1 // PDB stream info
#define PDB_STREAM_TPI      2 // type info
#define PDB_STREAM_DBI      3 // debug info

// =================================================================
// PDB 2.00 STRUCTURES
// =================================================================

typedef struct _PDB_STREAM_200
{
		PDB_DWORD dStreamBytes;  // stream size (-1 = unused)
		PDB_PVOID pReserved;  // implementation dependent
} PDB_STREAM_200;

// -----------------------------------------------------------------

typedef struct _PDB_HEADER_200
{
		PDB_BYTE abSignature[PDB_SIGNATURE_200_SIZE];  // version ID
		PDB_DWORD dPageBytes;  // 0x0400, 0x0800, 0x1000
		PDB_WORD wStartPage;  // 0x0009, 0x0005, 0x0002
		PDB_WORD wFilePages;  // file size / dPageBytes
		PDB_STREAM_200 RootStream;  // stream directory
		PDB_WORD awRootPages[];  // pages containing PDB_ROOT_200
} PDB_HEADER_200;

// -----------------------------------------------------------------

typedef struct _PDB_ROOT_200
{
		PDB_WORD wStreams;  // number of streams
		PDB_WORD wReserved;  // not used
		PDB_STREAM_200 aStreams[];  // stream size list
} PDB_ROOT_200;

// =================================================================
// PDB 7.00 STRUCTURES
// =================================================================

typedef struct _PDB_HEADER_700
{
		PDB_BYTE abSignature[PDB_SIGNATURE_700_SIZE];  // version ID
		PDB_DWORD dBytesPerPage;  // 0x0400
		PDB_DWORD dFlagPage;  // 0x0002
		PDB_DWORD dNumPages;  // number of pages in file
		PDB_DWORD dRootSize;  // stream directory size
		PDB_DWORD dReserved;  // 0
		PDB_DWORD dRootIndexesPage;  // root page index
} PDB_HEADER_700;

// -----------------------------------------------------------------

typedef struct _PDB_ROOT_700
{
		PDB_DWORD dNumStreams;  // number of streams
		PDB_DWORD adStreamSizes[];  // stream size list
} PDB_ROOT_700;

// =================================================================
// VERSION-INDEPENDENT PDB STRUCTURES
// =================================================================

typedef union _PDB_HEADER
{
		PDB_BYTE abSignature[PDB_VERSION_INDEPENDENT_SIGNATURE_SIZE];  // version signature
		PDB_HEADER_200 V200;  // version 2.00 header
		PDB_HEADER_700 V700;  // version 7.00 header
} PDB_HEADER;

// -----------------------------------------------------------------

typedef union _PDB_ROOT
{
		PDB_ROOT_200 V200;  // version 2.00 root directory
		PDB_ROOT_700 V700;  // version 7.00 root directory
} PDB_ROOT;

// =================================================================
// CLASS PDBFile
// =================================================================

class PDBFile
{
	public:
		PDBFile(void) :
				pdb_loaded(false), pdb_initialized(false), pdb_filename(nullptr), pdb_version(0), page_size(0), pdb_file_size(
				        0), pdb_file_data(
				nullptr), num_streams(0), pdb_fpo_num(0), pdb_newfpo_num(0), pdb_sec_num(0), pdb_header(nullptr), pdb_root_dir(
				nullptr), pdb_info_v700(nullptr), dbi_header_v700(nullptr), pdb_types(nullptr), pdb_symbols(nullptr)
		{
		}
		;
		~PDBFile(void);

		// Action methods
		PDBFileState load_pdb_file(const char *filename);
		void initialize(int image_base = 0);
		bool save_streams_to_files(void);

		// Getting methods
		unsigned int get_version(void)
		{
			return pdb_version;
		}
		PDBStream * get_stream(unsigned int num)
		{
			if (num < num_streams)
				return &streams[num];
			else
				return nullptr;
		}
		const char * get_module_name(unsigned int num)
		{
			if (num < modules.size())
				return modules[num].name;
			else
				return nullptr;
		}
		PDBTypes * get_types_container(void)
		{
			return pdb_types;
		}
		PDBSymbols * get_symbols_container(void)
		{
			return pdb_symbols;
		}
		PDBFunctionAddressMap * get_functions(void)
		{
			if (pdb_symbols != nullptr)
				return &pdb_symbols->get_functions();
			else
				return nullptr;
		}
		PDBGlobalVarAddressMap * get_global_variables(void)
		{
			if (pdb_symbols != nullptr)
				return &pdb_symbols->get_global_variables();
			else
				return nullptr;
		}

		// Printing methods
		void print_pdb_file_info(void);
		void print_modules(void);
		void dump_FPO(void);
		void dump_PE_sections(void);

	private:
		// Internal functions
		bool stream_is_linear(PDB_DWORD *pages, int num_pages);
		char * extract_stream(PDB_DWORD *pages, int num_pages);
		PDBFileState load_pdb_v200(void);
		PDBFileState load_pdb_v700(void);
		void parse_modules(void);
		void parse_sections(int image_base);

		// Variables
		bool pdb_loaded;
		bool pdb_initialized;
		const char * pdb_filename;
		unsigned int pdb_version;
		unsigned int page_size;
		unsigned int pdb_file_size;
		char * pdb_file_data;
		unsigned int num_streams;
		int pdb_fpo_num;
		int pdb_newfpo_num;
		int pdb_sec_num;

		// Data structure pointers
		PDB_HEADER * pdb_header;
		PDB_ROOT * pdb_root_dir;
		PDBInfo70 * pdb_info_v700;
		NewDBIHdr * dbi_header_v700;

		// Child objects
		PDBTypes * pdb_types;
		PDBSymbols * pdb_symbols;

		// Data containers
		PDBStreamsVec streams;
		PDBModulesVec modules;
		PDBSectionsVec sections;

};

} // namespace pdbparser
} // namespace retdec

#endif
