/**
 * @file src/fileinfo/file_information/file_information_types/relocation_table/relocation_table.cpp
 * @brief Class for relocation table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/relocation_table/relocation_table.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
RelocationTable::RelocationTable() : associatedSymbolTableIndex(std::numeric_limits<unsigned long long>::max()),
										appliesSectionIndex(std::numeric_limits<unsigned long long>::max()),
										declaredRelocations(std::numeric_limits<unsigned long long>::max())
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
 *
 * Returned value indicates the number of relocations stored in this instance.
 * This number may not be as large as result of method @a getNumberOfDeclaredRelocations().
 */
std::size_t RelocationTable::getNumberOfStoredRelocations() const
{
	return table.size();
}

/**
 * Get number of stored relocations in table
 * @return Number of relocations in table
 */
std::string RelocationTable::getNumberOfStoredRelocationsStr() const
{
	return getNumberAsString(table.size());
}

/**
 * Get number of declared relocations in table
 * @return Number of relocations in table
 *
 * Returned value indicates the declared number of relocations stored in file table.
 * This number may not be as large as result of method @a getNumberOfStoredRelocations().
 */
std::string RelocationTable::getNumberOfDeclaredRelocationsStr() const
{
	return getNumberAsString(declaredRelocations);
}

/**
 * Get name of relocation table
 * @return Name of relocation table
 */
std::string RelocationTable::getTableName() const
{
	return name;
}

/**
 * Get name of symbol table associated with relocation table
 * @return Name of symbol table associated with relocation table
 */
std::string RelocationTable::getAssociatedSymbolTableName() const
{
	return associatedSymbolTableName;
}

/**
 * Get name of section to which the relocation applies
 * @return Name of section to which the relocation applies
 */
std::string RelocationTable::getAppliesSectionName() const
{
	return appliesSectionName;
}

/**
 * Get index of symbol table (associated with relocation table)
 * @return Index of symbol table associated with relocation table
 */
std::string RelocationTable::getAssociatedSymbolTableIndex() const
{
	return getNumberAsString(associatedSymbolTableIndex);
}

/**
 * Get index of section to which the relocation applies
 * @return Index of section to which the relocation applies
 */
std::string RelocationTable::getAppliesSectionIndex() const
{
	return getNumberAsString(appliesSectionIndex);
}

/**
 * Get name of symbol associated with relocation
 * @param position Position of relocation entry in table (0..x)
 * @return Name of symbol associated with relocation
 */
std::string RelocationTable::getRelocationSymbolName(std::size_t position) const
{
	return table[position].getSymbolName();
}

/**
 * Get relocation offset
 * @param position Position of relocation entry in table (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Relocation offset
 */
std::string RelocationTable::getRelocationOffsetStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[position].getOffsetStr(format);
}

/**
 * Get value of symbol associated with relocation
 * @param position Position of relocation entry in table (0..x)
 * @return Value of symbol associated with relocation
 */
std::string RelocationTable::getRelocationSymbolValueStr(std::size_t position) const
{
	return table[position].getSymbolValueStr();
}

/**
 * Get type of relocation
 * @param position Position of relocation entry in table (0..x)
 * @return Type of relocation
 */
std::string RelocationTable::getRelocationTypeStr(std::size_t position) const
{
	return table[position].getRelocationTypeStr();
}

/**
 * Get relocation addend
 * @param position Position of relocation entry in table (0..x)
 * @return Relocation addend
 */
std::string RelocationTable::getRelocationAddendStr(std::size_t position) const
{
	return table[position].getAddendStr();
}

/**
 * Get relocation calculated value
 * @param position Position of relocation entry in table (0..x)
 * @return Relocation calculated value
 */
std::string RelocationTable::getRelocationCalculatedValueStr(std::size_t position) const
{
	return table[position].getCalculatedValueStr();
}

/**
 * Set name of relocation table
 * @param tableName Name of relocation table
 */
void RelocationTable::setTableName(std::string tableName)
{
	name = tableName;
}

/**
 * Set name of associated symbol table
 * @param symbolTableName Name of associated symbol table
 */
void RelocationTable::setAssociatedSymbolTableName(std::string symbolTableName)
{
	associatedSymbolTableName = symbolTableName;
}

/**
 * Set name of section to which the relocation applies
 * @param sectionName Name of section to which the relocation applies
 */
void RelocationTable::setAppliesSectionName(std::string sectionName)
{
	appliesSectionName = sectionName;
}

/**
 * Set index of associated symbol table
 * @param index Index of associated symbol table
 */
void RelocationTable::setAssociatedSymbolTableIndex(unsigned long long index)
{
	associatedSymbolTableIndex = index;
}

/**
 * Set index of section to which the relocation applies
 * @param index Index of section to which the relocation applies
 */
void RelocationTable::setAppliesSectionIndex(unsigned long long index)
{
	appliesSectionIndex = index;
}

/**
 * Set declared number of relocations in table
 * @param relocations Declared number of relocations in table
 */
void RelocationTable::setNumberOfDeclaredRelocations(unsigned long long relocations)
{
	declaredRelocations = relocations;
}

/**
 * Add relocation
 * @param relocation Relocation
 */
void RelocationTable::addRelocation(Relocation &relocation)
{
	table.push_back(relocation);
}

/**
 * Delete all relocations from table
 */
void RelocationTable::clearRelocations()
{
	table.clear();
}

} // namespace fileinfo
