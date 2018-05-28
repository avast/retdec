/**
 * @file include/retdec/pdbparser/pdb_symbols.h
 * @brief Symbols
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_PDBPARSER_PDB_SYMBOLS_H
#define RETDEC_PDBPARSER_PDB_SYMBOLS_H

#include "retdec/pdbparser/pdb_info.h"
#include "retdec/pdbparser/pdb_types.h"
#include "retdec/pdbparser/pdb_utils.h"

namespace retdec {
namespace pdbparser {

class PDBSymbols;

// =================================================================
// LOCAL VARIABLE STRUCTURES
// =================================================================

// Local variable location
enum ePDBLocVarLocation
{
	PDBLVLOC_REGISTER, PDBLVLOC_BPREL32, PDBLVLOC_REGREL32
};

// PDB local variable
typedef struct _PDBLocalVariable
{
		char * name;  // Name
		ePDBLocVarLocation location;  // Location
		int block;  // Function block
		int offset;  // Offset (ignored for register)
		int register_num;  // Register number (ignored for bprel32)
		unsigned int type_index;  // Type index
		PDBTypeDef * type_def;  // Type definition
} PDBLocalVariable;

// =================================================================
// CLASS PDBFunction
// =================================================================

// PDB data inside function's code
typedef struct _PDBFunctionData
{
		char * name;  // Name
		int address;  // Virtual address (image base + section address + offset)
		int offset;  // Offset
		int section;  // Segment
		unsigned int type_index;  // Type index
		PDBTypeDef * type_def;  // Type definition
} PDBFunctionData;

// PDB line number information
typedef struct _PDBLineInfo
{
		int line;
		unsigned int offset;
} PDBLineInfo;

class PDBFunction
{
	public:
		char * name;  // Function name
		int overload_index;  // Function is overloaded (number of function's occurrence)
		int address;  // Virtual address (image base + section address + offset)
		int offset;  // Function offset
		int section;  // And section
		int module_index;  // In which module the function is
		int length;  // Function length
		unsigned int type_index;  // Type index
		PDBTypeFunction * type_def;  // Type definition
		std::vector<PDBLocalVariable> arguments;  // List of function arguments
		std::vector<PDBLocalVariable> loc_variables;  // List of local variables
		std::vector<int> blocks;  // List of code blocks (value is offset)
		std::vector<PDBFunctionData> data;  // List of data objects stored in function's code
		std::vector<PDBLineInfo> lines;  // Line number information

		PDBFunction(int cur_module) :
				name(nullptr), overload_index(0), address(0), offset(0), section(0), module_index(cur_module), length(0), type_index(
				        0), type_def(nullptr), args_remain(0), cur_block(0), depth(0)
		{
		}
		;  // Constructor
		void dump(void);  // Dump function
		bool parse_symbol(PDBGeneralSymbol *symbol, PDBTypes *types, PDBSymbols *pdbsyms);  // Parse given symbol
		void parse_line_info(LineInfoHeader *hdr);  // Parse line information
		std::string getNameWithOverloadIndex() const;
	private:
		int args_remain;  // Number of arguments remaining to add
		int cur_block;  // Number of current block
		int depth;  // Depth of blocks
};

// PDB function map (key is address)
typedef std::map<int, PDBFunction *> PDBFunctionAddressMap;

// =================================================================
// GLOBAL VARIABLE STRUCTURES
// =================================================================

// PDB global variable
typedef struct _PDBGlobalVariable
{
		char * name;  // Name
		int address;  // Virtual address (image base + section address + offset)
		int offset;  // Offset (ignored for register)
		int section;  // Segment
		int module_index;  // In which module the variable is
		unsigned int type_index;  // Type index
		PDBTypeDef * type_def;  // Type definition
} PDBGlobalVariable;

// PDB global variable map (key is segment+offset (in int32 : SSOOOOOO))
typedef std::map<int, PDBGlobalVariable> PDBGlobalVarAddressMap;

// =================================================================
// MAIN CLASS PDBSymbols
// =================================================================

class PDBSymbols
{
	public:
		// Constructor and destructor
		PDBSymbols(PDBStream *gsi, PDBStream *psi, PDBStream *sym, PDBModulesVec & m, PDBSectionsVec & s,
		        PDBTypes * tps) :
//		pdb_gsi_size(gsi->size),
//		pdb_gsi_data(gsi->data),
//		pdb_psi_size(psi->size),
//		pdb_psi_data(psi->data),
				pdb_sym_size(sym->size), pdb_sym_data(sym->data), modules(m), sections(s), types(tps), parsed(false)
		{
		}
		;
		~PDBSymbols(void);

		// Action methods
		void parse_symbols(void);

		// Getting methods
		PDBFunctionAddressMap & get_functions(void)
		{
			return functions;
		}
		;
		PDBGlobalVarAddressMap & get_global_variables(void)
		{
			return global_variables;
		}
		;

		/**
		 * Get virtual address from section index and offset of symbol
		 */
		int get_virtual_address(unsigned int section, unsigned int offset)
		{
			if (sections.size() > section)
				return sections[section].virtual_address + offset;
			else
				return -1;
		}
		;

		/**
		 *
		 */
		int get_file_address(unsigned int section, unsigned int offset)
		{
			if (sections.size() > section)
				return sections[section].file_address + offset;
			else
				return -1;
		}
		;

		// Printing methods
		void dump_global_symbols(void);
		void dump_module_symbols(int index);
		void dump_all_modules(void);
		void print_functions(void);
		void print_global_variables(void);

	private:
		// Internal functions
		static void dump_symbol(PSYM Sym);

		// Variables
//	unsigned int		pdb_gsi_size;	// size of GSI stream
//	char *				pdb_gsi_data;	// data from GSI stream
//	unsigned int		pdb_psi_size;	// size of PSI stream
//	char *				pdb_psi_data;	// data from PSI stream
		unsigned int pdb_sym_size;  // size of SYM stream
		char * pdb_sym_data;  // data from SYM stream
		PDBModulesVec & modules;  // modules
		PDBSectionsVec & sections;  // sections
		PDBTypes * types;  // types
		bool parsed;  // modules are parsed

		// Data containers
		PDBFunctionAddressMap functions;  // Map of functions (key is address)
		PDBGlobalVarAddressMap global_variables;  // Map of global variables (key is address)
};

}  // namespace pdbparser
} // namespace retdec

#endif
