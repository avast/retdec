/**
 * @file src/pdbparser/pdb_file.cpp
 * @brief PDB file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "retdec/pdbparser/pdb_file.h"

using namespace std;

namespace retdec {
namespace pdbparser {

// =================================================================
// PUBLIC METHODS
// =================================================================

/**
 * Loads PDB file into memory and separates all streams.
 * Must be called before using of any method.
 * Can be called only once.
 * @param filename Name of PDB file to load.
 * @return Loading status
 */
PDBFileState PDBFile::load_pdb_file(const char *filename)
{
	if (pdb_loaded)
		return PDB_STATE_ALREADY_LOADED;

	// Load PDB file into memory
	pdb_filename = filename;
	FILE *fp = fopen(filename,"rb");
	if (fp == nullptr)
	{
		return PDB_STATE_ERR_FILE_OPEN;
	}
	fseek(fp, 0, SEEK_END);  // Determine file size
	pdb_file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	pdb_file_data = new char[pdb_file_size]; // Allocate memory
	size_t result = fread(pdb_file_data,1,pdb_file_size,fp); // Read the file
	fclose(fp);
	if (result != pdb_file_size)
	{
		return PDB_STATE_ERR_FILE_OPEN;
	}

	// Get the version of PDB file and parse it
	pdb_header = reinterpret_cast<PDB_HEADER *>(pdb_file_data);
	PDBFileState state;
	// Version is 2.00
	if (strcmp(reinterpret_cast<const char*>(pdb_header->abSignature), PDB_SIGNATURE_200) == 0)
	{
		pdb_version = PDB_VERSION_200;
		state = load_pdb_v200();
	}
	// Version is 7.00
	else if (strcmp(reinterpret_cast<const char*>(pdb_header->abSignature), PDB_SIGNATURE_700) == 0)
	{
		pdb_version = PDB_VERSION_700;
		state = load_pdb_v700();
		// Get pointer to PDB info header
		if (streams.size() > PDB_STREAM_PDB)
		{
			pdb_info_v700 = reinterpret_cast<PDBInfo70 *>(streams[PDB_STREAM_PDB].data);
		}
		else
		{
			return PDB_STATE_INVALID_FILE;
		}
	}
	else // Invalid file
	{
		return PDB_STATE_INVALID_FILE;
	}
	if (state == PDB_STATE_OK)
		pdb_loaded = true;
	return state;
}

/**
 * Processes all PDB file streams and fills data containers.
 * Must be called after load_pdb_file() and before any getting and printing or dumping method.
 * Can be called only once.
 * @param image_base Base address of program's virtual memory.
 */
void PDBFile::initialize(int image_base)
{
	if (!pdb_loaded || streams.size() <= PDB_STREAM_TPI || pdb_initialized || streams.size() <= PDB_STREAM_DBI)
	{
		return;
	}

	// Initialize types
	pdb_types = new PDBTypes(&streams[PDB_STREAM_TPI]);
	pdb_types->parse_types();

	// Check if DBI stream is present
	bool dbi_present = (num_streams > PDB_STREAM_DBI && streams[PDB_STREAM_DBI].unused == false);

	if (dbi_present)
	{
		// Get DBI stream
		unsigned int pdb_dbi_size = streams[PDB_STREAM_DBI].size;
		char * pdb_dbi_data = streams[PDB_STREAM_DBI].data;

		// Get pointer to DBI header
		dbi_header_v700 = reinterpret_cast<NewDBIHdr *>(pdb_dbi_data);

		// Get debug stream numbers
		PDB_SHORT *dbg_numbers = reinterpret_cast<PDB_SHORT *>(pdb_dbi_data + pdb_dbi_size - dbi_header_v700->cbDbgHdr);
		pdb_fpo_num = dbg_numbers[0];
		pdb_sec_num = dbg_numbers[5];
		pdb_newfpo_num = dbg_numbers[9];

		// Initialize modules
		parse_modules();

		// Intialize sections
		if (image_base == 0)
			image_base = 0x400000; // Default image base
		parse_sections(image_base);

		// Initialize symbols
		int pdb_gsi_num = dbi_header_v700->snGSSyms;
		int pdb_psi_num = dbi_header_v700->snPSSyms;
		int pdb_sym_num = dbi_header_v700->snSymRecs;
		pdb_symbols = new PDBSymbols(&streams[pdb_gsi_num],&streams[pdb_psi_num],&streams[pdb_sym_num],modules,sections,pdb_types);
		pdb_symbols->parse_symbols();
	}
	pdb_initialized = true;
}

/**
 * Saves all streams into separate files.
 * File names consist of input PDB file name and extension .xxx as stream number
 * Can be called after load_pdb_file() was executed
 * @return Operation was successful
 */
bool PDBFile::save_streams_to_files(void)
{
	if (!pdb_loaded || num_streams == 0)
		return false;
	// Save each stream to file
	for (unsigned int i = 0; i < num_streams;i++)
	{
		char stream_filename[MAX_PATH+4];
		sprintf(stream_filename,"%s.%03d",pdb_filename,i);
		FILE *fs = fopen(stream_filename,"wb");
		if (fs == nullptr)
			return false;
		if (!streams[i].unused)
			fwrite(streams[i].data,1,streams[i].size,fs);
		fclose(fs);
	}
	return true;
}

/**
 * Prints basic PDB file information and list of streams
 * Can be called after load_pdb_file() was executed
 */
void PDBFile::print_pdb_file_info(void)
{
	puts("******* PDB file info *******");
	if (!pdb_loaded)
	{
		puts("PDB file not properly loaded yet!\n");
		return;
	}
	printf("File name: %s\n", pdb_filename);
	printf("File size: %d bytes \n", pdb_file_size);
	printf("PDB version: ");
	if (pdb_version == PDB_VERSION_200)
		printf("2.00\n");
	else if (pdb_version == PDB_VERSION_700)
		printf("7.00\n");
	if (pdb_info_v700 != nullptr)
	{
		printf("Age: %d\n", pdb_info_v700->pdbinfo.age);
		printf("GUID: ");
		print_bytes(reinterpret_cast<PDB_BYTE *>(&pdb_info_v700->sig70), sizeof(PDB_GUID));
		puts("");
	}
	printf("Page size: 0x%x bytes\n", page_size);
	printf("Number of streams: %d\n", num_streams);
	for (unsigned int i = 0;i < num_streams;i++)
		printf("Stream %02d size: %7d unused: %d linear: %d\n", i, streams[i].size,  streams[i].unused, streams[i].linear);

	puts("");
}

/**
 * Prints all modules names and their stream numbers
 * Can be called after initialize() was executed
 */
void PDBFile::print_modules(void)
{
	puts("******* PDB list of modules *******");
	if (!pdb_initialized)
	{
		puts("PDB file not initialized yet!\n");
		return;
	}
	if (modules.size() == 0)
	{
		puts("PDB file doesn't contain module list!\n");
		return;
	}
	printf("Symbol streams:\n");
	printf("  GSI stream: %d\n", dbi_header_v700->snGSSyms);
	printf("  PSGSI stream: %d\n", dbi_header_v700->snPSSyms);
	printf("  SYM stream: %d\n", dbi_header_v700->snSymRecs);
	puts("");
	printf("List of modules:\n");
	for (unsigned int i = 0; i < modules.size(); i++)
		printf("  Stream number: %d Module name: %s\n",modules[i].stream_num,modules[i].name);
	puts("");
}

/**
 * Dumps FPO stream.
 * Can be called after initialize() was executed.
 */
void PDBFile::dump_FPO(void)
{
	puts("******* FPO dump *******");
	if (!pdb_initialized)
	{
		puts("PDB file not initialized yet!\n");
		return;
	}
	if (pdb_fpo_num <= 0)
	{
		puts("FPO information not present in PDB file!\n");
		return;
	}

	PDBStream *pdb_fpo_stream = &streams[pdb_fpo_num];
	int fpoSize = pdb_fpo_stream->size;
	PDB_FPO_DATA *fpo = reinterpret_cast<PDB_FPO_DATA *>(pdb_fpo_stream->data);

	int fpoCount = fpoSize / sizeof(PDB_FPO_DATA);
	for (int i=0; i<fpoCount; i++)
	{
		printf(
			"start %08x size %08x locals %08x params %04x "
			"prolog %02x regs %x SEH? %x EBP? %x rsvd %x frameType %x\n",
			fpo[i].ulOffStart,
			fpo[i].cbProcSize,
			fpo[i].cdwLocals,
			fpo[i].cdwParams,
			fpo[i].cbProlog,
			fpo[i].cbRegs,
			fpo[i].fHasSEH,
			fpo[i].fUseBP,
			fpo[i].reserved,
			fpo[i].cbFrame);
	}
	puts("");
}

/**
 * Dumps PE Sections stream.
 * Can be called after initialize() was executed.
 */
void PDBFile::dump_PE_sections(void)
{
	puts("******* PE sections dump *******");
	if (!pdb_initialized)
	{
		puts("PDB file not initialized yet!\n");
		return;
	}
	if (pdb_sec_num <= 0)
	{
		puts("PE sections information not present in PDB file!\n");
		return;
	}

	PDBStream *pdb_sect_stream = &streams[pdb_sec_num];
	PDB_PVOID pSect = pdb_sect_stream->data;
	unsigned long sectSize = pdb_sect_stream->size;

	int nSect = sectSize / sizeof (PDB_IMAGE_SECTION_HEADER);
	PDB_PIMAGE_SECTION_HEADER Sections = reinterpret_cast<PDB_PIMAGE_SECTION_HEADER>(pSect);
	for (int i=0; i<nSect; i++)
	{
		printf("%s (VA %08x * %08x RawSize %08x Misc %08x)\n",
			Sections[i].Name,
			Sections[i].VirtualAddress,
			Sections[i].PointerToRawData,
			Sections[i].SizeOfRawData,
			Sections[i].Misc.VirtualSize);
	}
	puts("");
}

/**
 * Destructor
 */
PDBFile::~PDBFile()
{
	if (pdb_file_data)
		delete [] pdb_file_data;
	// Delete all non-linear (copied) streams
	for (unsigned int i = 0; i < num_streams;i++)
		if (!streams[i].unused && !streams[i].linear)
			delete [] streams[i].data;
	if (pdb_types)
		delete pdb_types;
	if (pdb_symbols)
		delete pdb_symbols;
}

// =================================================================
// PRIVATE METHODS
// =================================================================

/**
 * Determines whether stream is stored linear in PDB file or not
 * @param pages Index of pages used by stream
 * @param num_pages Number of pages used by stream
 * @return Stream is linear
 */
bool PDBFile::stream_is_linear(PDB_DWORD *pages, int num_pages)
{
	PDB_DWORD cur_page = pages[0];
	for (int i = 1;i < num_pages;i++)
		if (pages[i] != ++cur_page)
			return false;
	return true;
}

/**
 * Extracts non-linear stream into linear memory.
 * @param pages Index of pages used by stream
 * @param num_pages Number of pages used by stream
 * @return Stream data in linear memory
 */
char *PDBFile::extract_stream(PDB_DWORD *pages, int num_pages)
{
	// Copy data from each page
	char *stream_data = new char[num_pages * page_size];
	for (int i = 0;i < num_pages;i++)
	{
		memcpy(stream_data + page_size * i, pdb_file_data + pages[i] * page_size, page_size);
	}
	return stream_data;
}

/**
 * Separates all streams from PDB file version 2.00.
 * Vector "streams" is filled here.
 * @return State (OK or Invalid file)
 */
PDBFileState PDBFile::load_pdb_v200(void)
{
	//TODO - add support for PDB version 2.00
	return PDB_STATE_UNSUPPORTED_VERSION;
}

/**
 * Separates all streams from PDB file version 7.00.
 * Vector "streams" is filled here.
 * @return State (OK or Invalid file)
 */
PDBFileState PDBFile::load_pdb_v700(void)
{
	// Get page size
	page_size = pdb_header->V700.dBytesPerPage;
	if (!(page_size == 0x200 || page_size == 0x400 || page_size == 0x800 || page_size == 0x1000))
		return PDB_STATE_INVALID_FILE;

	// Check file size
	if (pdb_file_size != page_size * pdb_header->V700.dNumPages)
		return PDB_STATE_INVALID_FILE;

	// Get root directory
	int pages_per_root = (pdb_header->V700.dRootSize + page_size - 1) / page_size;
	PDB_DWORD *root_dir_indexes = reinterpret_cast<PDB_DWORD *>(pdb_file_data + (pdb_header->V700.dRootIndexesPage) * page_size);
	if (stream_is_linear(root_dir_indexes, pages_per_root))
		pdb_root_dir = reinterpret_cast<PDB_ROOT *>(pdb_file_data + root_dir_indexes[0] * page_size);
	else
		pdb_root_dir = reinterpret_cast<PDB_ROOT *>(extract_stream(root_dir_indexes, pages_per_root));

	// Get streams
	num_streams = pdb_root_dir->V700.dNumStreams;
	// Allocate memory for streams. We need to use resize() instead of
	// reserve() because reserve() does not increases the size of the
	// container. That would make accesses to it in the following loop invalid.
	streams.resize(num_streams);
	int cur_pagedir_index = num_streams + 0;  // Skip dwords with stream sizes

	// Extract each stream
	for (unsigned int i = 0; i < num_streams;i++)
	{
		streams[i].size = pdb_root_dir->V700.adStreamSizes[i];
		// Stream is empty
		if (streams[i].size <= 0)
		{
			streams[i].unused = true;
			streams[i].linear = false;
			streams[i].data = nullptr;
		}
		// Stream is not empty
		else
		{
			streams[i].unused = false;
			int pages_per_stream = (streams[i].size + page_size - 1) / page_size;
			// Stream is linear in pdb file, we just get a pointer to it
			if (stream_is_linear(&pdb_root_dir->V700.adStreamSizes[cur_pagedir_index], pages_per_stream))
			{
				streams[i].data = pdb_file_data + pdb_root_dir->V700.adStreamSizes[cur_pagedir_index] * page_size;
				streams[i].linear = true;
			}
			// Stream is not linear in pdb file, we must copy it to linear memory
			else
			{
				streams[i].data = extract_stream(&pdb_root_dir->V700.adStreamSizes[cur_pagedir_index], pages_per_stream);
				streams[i].linear = false;
			}
			cur_pagedir_index += pages_per_stream;  // Increase index to next stream
		}
	}
	return PDB_STATE_OK;
}

/**
 * Parses DBI stream and gets names of modules and their streams.
 * Vector "modules" is filled here.
 */
void PDBFile::parse_modules(void)
{
	// Get DBI stream size and data
	PDBStream * pdb_dbi_stream = &streams[PDB_STREAM_DBI];
	unsigned int pdb_dbi_size = pdb_dbi_stream->size;
	char * pdb_dbi_data = pdb_dbi_stream->data;

	if (pdb_dbi_size < sizeof(NewDBIHdr))  // DBI stream is empty
		return;

	unsigned int position = sizeof(NewDBIHdr);  //0x40
	unsigned int limit = sizeof(NewDBIHdr) + dbi_header_v700->cbGpModi;
	int cnt = 0;
	MODI * entry;

	while (position < limit)
	{
		// Parse entries with module information
		entry = reinterpret_cast<MODI *>(pdb_dbi_data + position);

		// Determine the end of entry
		int len = 0;
		bool ended = false;  // String already ended
		int second_len = 0;  // Length of second string
		while (1)
		{
			if (entry->rgch[len] == 0)
			{
				if (ended && second_len > 1 && (len & 3) == 0)
					break;
				ended = true;
				second_len++;
			}
			else
				ended = false;
			len++;
		}

		// Add module into vector
		PDBStream *s = (entry->sn == 0xffff)?nullptr:&streams[entry->sn]; // Get module stream
		PDBModule new_module =
		{
			reinterpret_cast<char *>(entry->rgch),  // name
			entry->sn,  // stream_num
			s  // stream
		};
		modules.push_back(new_module);
		cnt++;
		// Go to next entry
		position += sizeof(MODI) + len;
	}
}

/**
 * Parses PE Sections stream and gets section name, virtual address and file address
 * Vector "sections" is filled here.
 */
void PDBFile::parse_sections(int image_base)
{
	if (pdb_sec_num <= 0)  // Sections stream not present
		return;

	// Get stream with section info
	PDBStream * pdb_sect_stream = &streams[pdb_sec_num];
	unsigned int pdb_sect_size = pdb_sect_stream->size;
	char * pdb_sect_data = pdb_sect_stream->data;

	// Get number of sections and array of section headers
	int num_sects = pdb_sect_size / sizeof(PDB_IMAGE_SECTION_HEADER);
	PDB_IMAGE_SECTION_HEADER * sects = reinterpret_cast<PDB_IMAGE_SECTION_HEADER *>(pdb_sect_data);

	// Create dummy zero-number section
	PDBPESection zero_sect = {"",0,0};
	sections.push_back(zero_sect);

	int max_code_sect = 1;  // Maximum number of code section
	// Parse all sections
	for(int i = 0; i < num_sects;i++)
	{
		PDBPESection new_sect =
		{
			reinterpret_cast<char *>(sects[i].Name),  // name
			sects[i].VirtualAddress + image_base,  // virtual_address
			sects[i].PointerToRawData  // file_address
		};
		sections.push_back(new_sect);
		// Check if section is code section
		if (strncmp(reinterpret_cast<const char *>(sects[i].Name), ".text", 5) == 0)
			max_code_sect = i+1;
	}
	sections[0].file_address = max_code_sect;
}

} // namespace pdbparser
} // namespace retdec
