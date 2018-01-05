/**
 * @file include/retdec/debugformat/debugformat.h
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DEBUGFORMAT_DEBUGFORMAT_H
#define RETDEC_DEBUGFORMAT_DEBUGFORMAT_H

#include "retdec/pdbparser/pdb_file.h"
#include "retdec/config/functions.h"
#include "retdec/config/objects.h"
#include "retdec/config/types.h"

#include "retdec/demangler/demangler.h"
#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader.h"

namespace debugformat {

/**
 * Common (PDB and DWARF) debug information representation.
 */
class DebugFormat
{
	public:
		using SymbolTable = std::map<retdec::utils::Address, const fileformat::Symbol*>;

	public:
		DebugFormat();
		DebugFormat(
				loader::Image* inFile,
				const std::string& pdbFile,
				SymbolTable* symtab,
				demangler::CDemangler* demangler,
				unsigned long long imageBase = 0);

		retdec::config::Function* getFunction(retdec::utils::Address a);
		const retdec::config::Object* getGlobalVar(retdec::utils::Address a);

		bool hasInformation() const;

	private:
		void loadPdb();
		void loadPdbTypes();
		void loadPdbGlobalVariables();
		void loadPdbFunctions();
		retdec::config::Type loadPdbType(pdbparser::PDBTypeDef* type);

		void loadDwarf();
		void loadDwarfTypes();
		void loadDwarfGlobalVariables();
		void loadDwarfFunctions();
		retdec::config::Type loadDwarfType(dwarfparser::DwarfType* type);

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
		retdec::config::GlobalVarContainer globals;
		retdec::config::TypeContainer types;

		std::map<retdec::utils::Address, retdec::config::Function> functions;
};

} // namespace debugformat

#endif
