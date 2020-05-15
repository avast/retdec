/**
 * @file include/retdec/debugformat/debugformat.h
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DEBUGFORMAT_DEBUGFORMAT_H
#define RETDEC_DEBUGFORMAT_DEBUGFORMAT_H

#include <llvm/DebugInfo/DIContext.h>
#include <llvm/DebugInfo/DWARF/DWARFContext.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/MemoryBuffer.h>

#include "retdec/common/function.h"
#include "retdec/common/object.h"
#include "retdec/common/type.h"
#include "retdec/pdbparser/pdb_file.h"

#include "retdec/demangler/demangler.h"
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
				retdec::demangler::Demangler* demangler
		);

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
		void loadDwarf_CU(llvm::DWARFDie die);
		retdec::common::Function loadDwarf_subprogram(llvm::DWARFDie die);
		std::string loadDwarf_type(llvm::DWARFDie die);
		std::string _loadDwarf_type(llvm::DWARFDie die);
		retdec::common::Object loadDwarf_formal_parameter(
				llvm::DWARFDie die,
				unsigned argCntr);
		retdec::common::Object loadDwarf_variable(llvm::DWARFDie die);

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
		/// Demangler.
		retdec::demangler::Demangler* _demangler = nullptr;

		/// Dwarf named types cache.
		std::map<std::pair<llvm::DWARFUnit*, uint32_t>, std::string> dieOff2type;

	public:
		retdec::common::GlobalVarContainer globals;
		retdec::common::TypeContainer types;

		std::map<retdec::common::Address, retdec::common::Function> functions;
};

} // namespace debugformat
} // namespace retdec

#endif
