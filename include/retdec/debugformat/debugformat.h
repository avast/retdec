/**
 * @file include/retdec/debugformat/debugformat.h
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DEBUGFORMAT_DEBUGFORMAT_H
#define RETDEC_DEBUGFORMAT_DEBUGFORMAT_H

#include "retdec/common/function.h"
#include "retdec/common/object.h"
#include "retdec/common/type.h"
#include "retdec/pdbparser/pdb_file.h"

#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/dwarfparser/dwarf_file.h"
#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader.h"

namespace retdec {
namespace debugformat {

/**
 * Common (PDB and DWARF) debug information representation.
 */
class DebugFormat
{
	public:
		using SymbolTable = std::map<retdec::common::Address, const retdec::fileformat::Symbol*>;

	public:
		DebugFormat();
		DebugFormat(
				retdec::loader::Image* inFile,
				const std::string& pdbFile,
				SymbolTable* symtab,
				retdec::bin2llvmir::Demangler* demangler,
				unsigned long long imageBase = 0);

		retdec::common::Function* getFunction(retdec::common::Address a);
		const retdec::common::Object* getGlobalVar(retdec::common::Address a);

		bool hasInformation() const;

	private:
		void loadPdb();
		void loadPdbTypes();
		void loadPdbGlobalVariables();
		void loadPdbFunctions();
		retdec::common::Type loadPdbType(retdec::pdbparser::PDBTypeDef* type);

		void loadDwarf();
		void loadDwarfTypes();
		void loadDwarfGlobalVariables();
		void loadDwarfFunctions();
		retdec::common::Type loadDwarfType(retdec::dwarfparser::DwarfType* type);

		void loadSymtab();

	private:
		/// Input file used to initialize this debug information.
		std::string _inputFile;
		/// Symbol table to read symbols from.
		SymbolTable* _symtab = nullptr;
		/// Underlying binary file representation.
		retdec::loader::Image* _inFile = nullptr;
		/// Underlying PDB representation.
		retdec::pdbparser::PDBFile* _pdbFile = nullptr;
		/// Underlying DWARF representation.
		retdec::dwarfparser::DwarfFile* _dwarfFile = nullptr;
		/// Demangler.
		retdec::bin2llvmir::Demangler* _demangler = nullptr;

	public:
		retdec::common::GlobalVarContainer globals;
		retdec::common::TypeContainer types;

		std::map<retdec::common::Address, retdec::common::Function> functions;
};

} // namespace debugformat
} // namespace retdec

#endif
