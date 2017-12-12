/**
 * @file include/debugformat/debugformat.h
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef DEBUGFORMAT_DEBUGFORMAT_H
#define DEBUGFORMAT_DEBUGFORMAT_H

#include <pdbparser/pdb_file.h>

#include "retdec-config/functions.h"
#include "retdec-config/objects.h"
#include "retdec-config/types.h"
#include "demangler/demangler.h"
#include "dwarfparser/dwarf_file.h"
#include "fileformat/fileformat.h"
#include "loader/loader.h"

namespace debugformat {

/**
 * Common (PDB and DWARF) debug information representation.
 */
class DebugFormat
{
	public:
		using SymbolTable = std::map<tl_cpputils::Address, const fileformat::Symbol*>;

	public:
		DebugFormat();
		DebugFormat(
				loader::Image* inFile,
				const std::string& pdbFile,
				SymbolTable* symtab,
				demangler::CDemangler* demangler,
				unsigned long long imageBase = 0);

		retdec_config::Function* getFunction(tl_cpputils::Address a);
		const retdec_config::Object* getGlobalVar(tl_cpputils::Address a);

		bool hasInformation() const;

	private:
		void loadPdb();
		void loadPdbTypes();
		void loadPdbGlobalVariables();
		void loadPdbFunctions();
		retdec_config::Type loadPdbType(pdbparser::PDBTypeDef* type);

		void loadDwarf();
		void loadDwarfTypes();
		void loadDwarfGlobalVariables();
		void loadDwarfFunctions();
		retdec_config::Type loadDwarfType(dwarfparser::DwarfType* type);

		void loadSymtab();

	private:
		/// Input file used to initialize this debug information.
		std::string _inputFile;
		/// Symbol table to read symbols from.
		SymbolTable* _symtab = nullptr;
		/// Underlying binary file representation.
		loader::Image* _inFile = nullptr;
		/// Underlying PDB representation.
		pdbparser::PDBFile* _pdbFile = nullptr;
		/// Underlying DWARF representation.
		dwarfparser::DwarfFile* _dwarfFile = nullptr;
		/// Demangler.
		demangler::CDemangler* _demangler = nullptr;

	public:
		retdec_config::GlobalVarContainer globals;
		retdec_config::TypeContainer types;

		std::map<tl_cpputils::Address, retdec_config::Function> functions;
};

} // namespace debugformat

#endif
