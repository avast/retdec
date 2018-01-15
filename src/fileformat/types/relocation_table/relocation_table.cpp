/**
 * @file src/fileformat/types/relocation_table/relocation_table.cpp
 * @brief Class for relocation table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/relocation_table/relocation_table.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
RelocationTable::RelocationTable()
{

}

/**
 * Destructor
 */
RelocationTable::~RelocationTable()
{

}

/**
 * Get number of relocations in table
 * @return Number of relocations in table
 */
std::size_t RelocationTable::getNumberOfRelocations() const
{
	return table.size();
}

/**
 * Get pointer to relocation from table
 * @param relocationIndex Index of selected relocation (indexed from 0)
 * @return Pointer to selected relocation or @c nullptr if relocation index is invalid
 */
const Relocation* RelocationTable::getRelocation(std::size_t relocationIndex) const
{
	return (relocationIndex < getNumberOfRelocations()) ? &table[relocationIndex] : nullptr;
}

/**
 * Get relocation by name
 * @param name Name of the relocation to get
 * @return Pointer to relocation with the specified name or @c nullptr if such item not found
 */
const Relocation* RelocationTable::getRelocation(const std::string &name) const
{
	for(const auto &i : table)
	{
		if(i.getName() == name)
		{
			return &i;
		}
	}

	return nullptr;
}

/**
 * Get pointer to relocation from table
 * @param addr Address of selected relocation
 * @return Pointer to relocation or @c nullptr if relocation address is invalid
 */
const Relocation* RelocationTable::getRelocationOnAddress(unsigned long long addr) const
{
	for(const auto &r : table)
	{
		if(r.getAddress() == addr)
		{
			return &r;
		}
	}

	return nullptr;
}

/**
 * Returns the link to associated symbol table
 * @return Link to symbol table
 */
unsigned long long RelocationTable::getLinkToSymbolTable() const
{
	return linkToSymbolTable;
}

/**
 * Set the link to associated symbol table
 * @param symbolTableIndex Index of the symbol table
 */
void RelocationTable::setLinkToSymbolTable(std::uint64_t symbolTableIndex)
{
	linkToSymbolTable = symbolTableIndex;
}

/**
 * Get begin iterator
 * @return Begin iterator
 */
RelocationTable::relocationsIterator RelocationTable::begin() const
{
	return table.begin();
}

/**
 * Get end iterator
 * @return End iterator
 */
RelocationTable::relocationsIterator RelocationTable::end() const
{
	return table.end();
}

/**
 * Delete all records from table
 */
void RelocationTable::clear()
{
	table.clear();
}

/**
 * Add new relocation to table
 * @param relocation New relocation
 */
void RelocationTable::addRelocation(Relocation &relocation)
{
	table.push_back(relocation);
}

/**
 * Find out if there are any relocations.
 * @return @c true if there are some relocations, @c false otherwise.
 */
bool RelocationTable::hasRelocations() const
{
	return !table.empty();
}

/**
 * Check if relocation with name @a name exists
 * @param name Name of relocation
 * @return @c true if has relocation with name @a name, @c false otherwise
 */
bool RelocationTable::hasRelocation(const std::string &name) const
{
	return getRelocation(name);
}

/**
 * Check if relocation on address exists
 * @param addr Adress of relocation
 * @return @c true if has relocation on @a address, @c false otherwise
 */
bool RelocationTable::hasRelocation(unsigned long long addr) const
{
	return getRelocationOnAddress(addr);
}

/**
 * Dump information about all relocations in table
 * @param dumpTable Into this parameter is stored dump of relocation table in an LLVM style
 */
void RelocationTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Relocation table ------------\n";
	ret << "; Number of relocations: " << getNumberOfRelocations() << "\n";

	if(hasRelocations())
	{
		unsigned long long aux;
		ret << ";\n";

		for(const auto &item : table)
		{
			ret << "; " << std::hex << item.getName() << " (addr: " << item.getAddress() <<
				", section: " << (item.getLinkToSection(aux) ? numToStr(aux) : "-") <<
				", offset: " << item.getSectionOffset() << ") mask:";

			for (const auto &byteMask : item.getMask())
			{
				ret << " " <<std::hex << std::setw(2) << std::setfill('0') <<
					static_cast<unsigned>(byteMask);
			}
			ret << "\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
