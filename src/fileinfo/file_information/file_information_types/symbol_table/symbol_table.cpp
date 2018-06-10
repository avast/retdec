/**
 * @file src/fileinfo/file_information/file_information_types/symbol_table/symbol_table.cpp
 * @brief Class for symbol table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/symbol_table/symbol_table.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
SymbolTable::SymbolTable() : offset(std::numeric_limits<unsigned long long>::max()),
								declaredSymbols(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
SymbolTable::~SymbolTable()
{

}

/**
 * Get number of symbols in table
 * @return Number of symbols in table
 *
 * Returned value indicates the number of symbols stored in this instance.
 * This number may not be as large as result of method @a getNumberOfDeclaredSymbols().
 */
std::size_t SymbolTable::getNumberOfStoredSymbols() const
{
	return table.size();
}

/**
 * Get number of symbols in table
 * @return Number of symbols in table
 *
 * Returned value indicates the declared number of symbols stored in file table.
 * This number may not be as large as result of method @a getNumberOfStoredSymbols().
 */
std::string SymbolTable::getNumberOfDeclaredSymbolsStr() const
{
	return getNumberAsString(declaredSymbols);
}

/**
 * Get name of symbol table
 * @return Name of symbol table
 */
std::string SymbolTable::getTableName() const
{
	return name;
}

/**
 * Get offset of symbol table in file
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Offset of symbol table in file
 */
std::string SymbolTable::getTableOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(offset, format);
}

/**
 * Get symbol name
 * @param position Position of symbol in table (0..x)
 * @return Symbol Name
 */
std::string SymbolTable::getSymbolName(std::size_t position) const
{
	return table[position].getName();
}

/**
 * Get symbol type
 * @param position Position of symbol in table (0..x)
 * @return Type of symbol
 */
std::string SymbolTable::getSymbolType(std::size_t position) const
{
	return table[position].getType();
}

/**
 * Get symbol bind
 * @param position Position of symbol in table (0..x)
 * @return Symbol bind
 */
std::string SymbolTable::getSymbolBind(std::size_t position) const
{
	return table[position].getBind();
}

/**
 * Get symbol other information
 * @param position Position of symbol in table (0..x)
 * @return Symbol other information
 */
std::string SymbolTable::getSymbolOther(std::size_t position) const
{
	return table[position].getOther();
}

/**
 * Get symbol link to section
 * @param position Position of symbol in table (0..x)
 * @return Symbol link to section
 */
std::string SymbolTable::getSymbolLinkToSection(std::size_t position) const
{
	return table[position].getLinkToSection();
}

/**
 * Get index of symbol in symbol table
 * @param position Position of symbol in table (0..x)
 * @return Index of symbol in symbol table
 */
std::string SymbolTable::getSymbolIndexStr(std::size_t position) const
{
	return table[position].getIndexStr();
}

/**
 * Get symbol value
 * @param position Position of symbol in table (0..x)
 * @return Symbol value
 */
std::string SymbolTable::getSymbolValueStr(std::size_t position) const
{
	return table[position].getValueStr();
}

/**
 * Get symbol address
 * @param position Position of symbol in table (0..x)
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Symbol address
 */
std::string SymbolTable::getSymbolAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[position].getAddressStr(format);
}

/**
 * Get size associated with symbol
 * @param position Position of symbol in table (0..x)
 * @return Size associated with symbol
 */
std::string SymbolTable::getSymbolSizeStr(std::size_t position) const
{
	return table[position].getSizeStr();
}

/**
 * Get number of stored special information
 * @return Number of special information in table
 */
std::size_t SymbolTable::getNumberOfStoredSpecialInformation() const
{
	return extraInfo.size();
}

/**
 * Get number of stored values of special information
 * @param position Index of special information (0..x)
 * @return Number of values of selected special information
 */
std::size_t SymbolTable::getNumberOfSpecialInformationValues(std::size_t position) const
{
	return extraInfo[position].getNumberOfStoredValues();
}

/**
 * Get description of special information
 * @param position Index of special information (0..x)
 * @return Description of selected special information
 */
std::string SymbolTable::getSpecialInformationDescription(std::size_t position) const
{
	return extraInfo[position].getDescription();
}

/**
 * Get short description of special information
 * @param position Index of special information (0..x)
 * @return Short description of selected special information
 */
std::string SymbolTable::getSpecialInformationAbbreviation(std::size_t position) const
{
	return extraInfo[position].getAbbreviation();
}

/**
 * Get value of one record from special information
 * @param infoIndex Index of special information (0..x)
 * @param recordIndex Index of record in selected special information (0..x)
 * @return Value of selected record
 */
std::string SymbolTable::getSpecialInformationValue(std::size_t infoIndex, std::size_t recordIndex) const
{
	return extraInfo[infoIndex].getValue(recordIndex);
}

/**
 * Set name of symbol table
 * @param tableName Name of table
 */
void SymbolTable::setTableName(std::string tableName)
{
	name = tableName;
}

/**
 * Set declared number of symbols in table
 * @param symbols Declared number of symbols in table
 */
void SymbolTable::setNumberOfDeclaredSymbols(unsigned long long symbols)
{
	declaredSymbols = symbols;
}

/**
 * Set offset of symbol table in file
 * @param tableOffset Offset of symbol table in file
 */
void SymbolTable::setTableOffset(unsigned long long tableOffset)
{
	offset = tableOffset;
}

/**
 * Add symbol
 * @param symbol Symbol
 */
void SymbolTable::addSymbol(Symbol &symbol)
{
	table.push_back(symbol);
}

/**
 * Delete all symbols from table
 */
void SymbolTable::clearSymbols()
{
	table.clear();
}

/**
 * Add special information
 * @param information Instance of class SpecialInformation
 */
void SymbolTable::addSpecialInformation(SpecialInformation &information)
{
	extraInfo.push_back(information);
}

/**
 * Delete all special information from table
 */
void SymbolTable::clearSpecialInformation()
{
	extraInfo.clear();
}

} // namespace fileinfo
