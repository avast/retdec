/**
 * @file src/debugformat/debugformat.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <sstream>

#include "retdec/utils/debug.h"
#include "retdec/debugformat/debugformat.h"

namespace retdec {
namespace debugformat {

DebugFormat::DebugFormat()
{

}

/**
 * @param inFile    Parsed file format representation of @p inputFile.
 * @param pdbFile   Input PDB file to load debugging information from.
 * @param symtab    Symbol table.
 * @param demangler Demangled instance used for this input file.
 */
DebugFormat::DebugFormat(
		retdec::loader::Image* inFile,
		const std::string& pdbFile,
		SymbolTable* symtab,
		retdec::demangler::Demangler* demangler)
		:
		_symtab(symtab),
		_inFile(inFile),
		_demangler(demangler)
{
	_pdbFile = new retdec::pdbparser::PDBFile();
	auto s = _pdbFile->load_pdb_file(pdbFile.c_str());

	if (s == retdec::pdbparser::PDB_STATE_OK)
	{
		LOG << "\n*** DebugFormat::DebugFormat(): PDB" << std::endl;

		std::uint64_t imageBase = 0;
		if (auto* pe = dynamic_cast<const fileformat::PeFormat*>(
				inFile->getFileFormat()))
		{
			pe->getImageBaseAddress(imageBase);
		}

		_pdbFile->initialize(imageBase);
		loadPdb();
	}

	loadDwarf();

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

		retdec::common::Function nf(funcName);

		nf.setDemangledName(_demangler->demangleToString(funcName));

		retdec::common::Address addr = it->first;
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
				nf.setEnd(itNext->first);
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

retdec::common::Function* DebugFormat::getFunction(retdec::common::Address a)
{
	auto fIt = functions.find(a);
	return fIt != functions.end() ? &fIt->second : nullptr;
}

const retdec::common::Object* DebugFormat::getGlobalVar(
		retdec::common::Address a)
{
	return globals.getObjectByAddress(a);
}

} // namespace debugformat
} // namespace retdec
