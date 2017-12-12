/**
 * @file src/debugformat/debugformat.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <iostream>
#include <sstream>

#include "tl-cpputils/debug.h"
#include "debugformat/debugformat.h"

namespace debugformat {

DebugFormat::DebugFormat()
{

}

/**
 * @param inFile    Parsed file format representation of @p inputFile.
 * @param pdbFile   Input PDB file to load debugging information from.
 * @param symtab    Symbol table.
 * @param demangler Demangled instance used for this input file.
 * @param imageBase Image base used in PDB initialization.
 */
DebugFormat::DebugFormat(
		loader::Image* inFile,
		const std::string& pdbFile,
		SymbolTable* symtab,
		demangler::CDemangler* demangler,
		unsigned long long imageBase)
		:
		_symtab(symtab),
		_inFile(inFile),
		_demangler(demangler)
{
	_pdbFile = new pdbparser::PDBFile();
	auto s = _pdbFile->load_pdb_file(pdbFile.c_str());
	_dwarfFile = new dwarfparser::DwarfFile(_inFile->getFileFormat()->getPathToFile(), _inFile->getFileFormat());

	if (s == pdbparser::PDB_STATE_OK)
	{
		LOG << "\n*** DebugFormat::DebugFormat(): PDB" << std::endl;
		_pdbFile->initialize(imageBase);
		loadPdb();
	}
	else if (_dwarfFile->hasDwarfInfo())
	{
		LOG << "\n*** DebugFormat::DebugFormat(): DWARF" << std::endl;
		loadDwarf();
	}

	loadSymtab();
}

/**
 * @return @c True if debug info was loaded successfully from PDB or DWARF.
 *         @c False otherwise.
 */
bool DebugFormat::hasInformation() const
{
	return !functions.empty();
}

/**
 * TODO: move to own module.
 */
void DebugFormat::loadSymtab()
{
	if (!_symtab)
		return;

	for (auto it = _symtab->begin(); it != _symtab->end(); ++it)
	{
		std::string funcName = it->second->getNormalizedName();

		retdec_config::Function nf(funcName);

		nf.setDemangledName(_demangler->demangleToString(funcName));

		tl_cpputils::Address addr = it->first;
		if (_inFile->getFileFormat()->isArm() && addr % 2 != 0)
		{
			addr -= 1;
		}
		nf.setStart(addr);

		unsigned long long symbolSize = 0;
		if (it->second->getSize(symbolSize))
		{
			nf.setEnd(nf.getStart() + symbolSize);
		}
		else
		{
			auto itNext = it;
			++itNext;
			if (itNext != _symtab->end())
			{
				nf.setEnd(itNext->first - 1);
			}
			else
			{
				for (const auto &seg : _inFile->getSegments())
				{
					if (seg->containsAddress(nf.getStart()))
					{
						nf.setEnd(seg->getEndAddress() + 1);
						break;
					}
				}
			}
		}

		nf.returnType.setLlvmIr("void");
		nf.setIsFromDebug(false);
		nf.setIsThumb(it->second->isThumbSymbol());
		functions.insert( {nf.getStart(), nf} );
	}
}

retdec_config::Function* DebugFormat::getFunction(tl_cpputils::Address a)
{
	auto fIt = functions.find(a);
	return fIt != functions.end() ? &fIt->second : nullptr;
}

const retdec_config::Object* DebugFormat::getGlobalVar(
		tl_cpputils::Address a)
{
	return globals.getObjectByAddress(a);
}

} // namespace debugformat
