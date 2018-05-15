/**
 * @file src/fileformat/types/symbol_table/macho_symbol.cpp
 * @brief Class for one Mach-O symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/types/symbol_table/macho_symbol.h"

using namespace retdec::utils;
using namespace llvm::MachO;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
MachOSymbol::MachOSymbol()
{

}

/**
 * Destructor
 */
MachOSymbol::~MachOSymbol()
{

}

/**
 * Makes symbol a function if conditions are met (call only after setAllValues)
 * @param fileParser Pointer to FileFormat parser
 */
void MachOSymbol::makeFunction(FileFormat *fileParser)
{
	if(!(type & N_STAB))
	{
		if ((type & N_TYPE) == N_SECT)
		{
			// Mach-O sections are indexed by 1
			auto *sectionPtr = fileParser->getSection(section - 1);
			if (sectionPtr && sectionPtr->isCode())
			{
				isFunction = true;
				return;
			}
		}
	}

	// Else
	isFunction = false;
}

/**
 * Get symbol type
 * @return Symbol type
 */
Symbol::Type MachOSymbol::getSymbolType() const
{
	if(type & N_STAB)
	{
		return Symbol::Type::UNDEFINED_SYM;
	}

	switch(type & N_TYPE)
	{
		case N_SECT:
			if((description & REFERENCE_TYPE) == REFERENCE_FLAG_PRIVATE_DEFINED)
			{
				return Symbol::Type::PRIVATE;
			}
			else
			{
				return Symbol::Type::PUBLIC;
			}
		case N_UNDF:
			if((type & N_EXT) && value)
			{
				return Symbol::Type::COMMON;
			}
			else
			{
				return Symbol::Type::EXTERN;
			}
		case N_PBUD:
			return Symbol::Type::EXTERN;
		case N_ABS:
			return Symbol::Type::ABSOLUTE_SYM;
		case N_INDR:
			return Symbol::Type::WEAK;
		default:
			return Symbol::Type::UNDEFINED_SYM;
	}

	return Symbol::Type::UNDEFINED_SYM;
}

/**
 * Get symbol usage type
 * @return Symbol usage type
 */
Symbol::UsageType MachOSymbol::getSymbolUsageType() const
{
	if (isFunction)
	{
		return Symbol::UsageType::FUNCTION;
	}

	return Symbol::UsageType::UNKNOWN;
}

/**
 * Set all values of MachOSymbol
 * @param nList Source structure
 * @param strTable Pointer to string table
 * @param index Index of symbol
 */
template<typename T> void MachOSymbol::setValues(const T &nList, const llvm::StringRef &strTable, unsigned index)
{
	// Convert name and value
	if(nList.n_strx)
	{
		if(nList.n_strx < strTable.size())
		{
			name = strTable.data() + nList.n_strx;
		}
		else
		{
			name.clear();
		}

		if(((nList.n_type & N_TYPE) == N_INDR) && (nList.n_value < strTable.size()))
		{
			altName = strTable.data() + nList.n_value;
		}
		else
		{
			altName.clear();
		}
	}
	value = static_cast<unsigned long long>(nList.n_value);
	// Set fields
	type = nList.n_type;
	section = nList.n_sect;
	description = nList.n_desc;
	this->index = index;
}

/**
 * Set all values of MachOSymbol
 * @param nList Source structure 32-bit
 * @param strTable Pointer to string table
 * @param index Index of symbol
 */
void MachOSymbol::setAllValues(const llvm::MachO::nlist &nList, const llvm::StringRef &strTable, unsigned index)
{
	setValues(nList, strTable, index);
}

/**
 * Set all values of MachOSymbol
 * @param nList Source structure 64-bit
 * @param strTable Pointer to string table
 * @param index Index of symbol
 */
void MachOSymbol::setAllValues(const llvm::MachO::nlist_64 &nList, const llvm::StringRef &strTable, unsigned index)
{
	setValues(nList, strTable, index);
}

/**
 * Get MachOSymbol as Import type
 * @return Import
 */
std::unique_ptr<Import> MachOSymbol::getAsImport() const
{
	auto importSym = std::make_unique<Import>();
	importSym->setName(name);
	importSym->setLibraryIndex(GET_LIBRARY_ORDINAL(description) - 1);
	importSym->invalidateOrdinalNumber();
	return importSym;
}

/**
 * Get MachOSymbol as Export type
 * @return Export
 */
Export MachOSymbol::getAsExport() const
{
	Export exportSym;
	if(name.empty())
	{
		exportSym.setName("exported_function_" + numToStr(value, std::hex));
	}
	else
	{
		exportSym.setName(name);
	}
	exportSym.setAddress(value);
	exportSym.invalidateOrdinalNumber();
	return exportSym;
}

/**
 * Get MachOSymbol as Symbol type
 * @return Symbol
 */
std::shared_ptr<Symbol> MachOSymbol::getAsSymbol() const
{
	auto symbol = std::make_shared<Symbol>();
	symbol->setOriginalName(name);
	symbol->setName(name);
	if(section)
	{
		symbol->setLinkToSection(section - 1);
	}
	else
	{
		symbol->invalidateLinkToSection();
		symbol->invalidateAddress();
	}
	symbol->setType(getSymbolType());

	switch(symbol->getType())
	{
		case Symbol::Type::PRIVATE:
		case Symbol::Type::PUBLIC:
			symbol->setAddress(value);
			symbol->invalidateSize();
			break;
		case Symbol::Type::COMMON:
			symbol->setSize(value);
			symbol->invalidateAddress();
			break;
		case Symbol::Type::WEAK:
			symbol->setName(altName);
			symbol->invalidateAddress();
			symbol->invalidateSize();
			break;
		default:
			symbol->invalidateAddress();
			symbol->invalidateSize();
			symbol->invalidateLinkToSection();
			break;
	}

	symbol->setUsageType(getSymbolUsageType());
	symbol->setIsThumbSymbol(description & N_ARM_THUMB_DEF);
	symbol->setIndex(index);
	return symbol;
}

} // namespace fileformat
} // namespace retdec
