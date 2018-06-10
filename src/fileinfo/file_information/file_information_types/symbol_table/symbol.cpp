/**
 * @file src/fileinfo/file_information/file_information_types/symbol_table/symbol.cpp
 * @brief Class for one symol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/symbol_table/symbol.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
Symbol::Symbol() : index(std::numeric_limits<unsigned long long>::max()),
					value(std::numeric_limits<unsigned long long>::max()),
					address(std::numeric_limits<unsigned long long>::max()),
					size(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
Symbol::~Symbol()
{

}

/**
 * Get symbol name
 * @return Symbol name
 */
std::string Symbol::getName() const
{
	return name;
}

/**
 * Get symbol type
 * @return Symbol type
 */
std::string Symbol::getType() const
{
	return type;
}

/**
 * Get symbol bind
 * @return Symbol bind
 */
std::string Symbol::getBind() const
{
	return bind;
}

/**
 * Get other information
 * @return Other information about symbol
 */
std::string Symbol::getOther() const
{
	return other;
}

/**
 * Get link to associated section
 * @return Link to associated section
 */
std::string Symbol::getLinkToSection() const
{
	return linkToSection;
}

/**
 * Get index of symbol in symbol table
 * @return Index of symbol in symbol table
 */
std::string Symbol::getIndexStr() const
{
	return getNumberAsString(index);
}

/**
 * Get symbol value
 * @return Symbol value
 */
std::string Symbol::getValueStr() const
{
	return getNumberAsString(value);
}

/**
 * Get symbol address
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Symbol address
 */
std::string Symbol::getAddressStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(address, format);
}

/**
 * Get symbol size
 * @return Symbol size
 */
std::string Symbol::getSizeStr() const
{
	return getNumberAsString(size);
}

/**
 * Set symbol name
 * @param symbolName Symbol name
 */
void Symbol::setName(std::string symbolName)
{
	name = symbolName;
}

/**
 * Set symbol type
 * @param symbolType Symbol type
 */
void Symbol::setType(std::string symbolType)
{
	type = symbolType;
}

/**
 * Set symbol bind
 * @param symbolBind Simbol bind
 */
void Symbol::setBind(std::string symbolBind)
{
	bind = symbolBind;
}

/**
 * Set other information about symbol
 * @param otherInformation Other information about symbol
 */
void Symbol::setOther(std::string otherInformation)
{
	other = otherInformation;
}

/**
 * Set link to associated section
 * @param link Link to associated section
 */
void Symbol::setLinkToSection(std::string link)
{
	linkToSection = link;
}

/**
 * Set index of symbol in symbol table
 * @param symbolIndex Index of symbol in symbol table
 */
void Symbol::setIndex(unsigned long long symbolIndex)
{
	index = symbolIndex;
}

/**
 * Set symbol value
 * @param symbolValue Symbol value
 */
void Symbol::setValue(unsigned long long symbolValue)
{
	value = symbolValue;
}

/**
 * Set address of symbol
 * @param addressValue Address of symbol
 */
void Symbol::setAddress(unsigned long long addressValue)
{
	address = addressValue;
}

/**
 * Set size associated with symbol
 * @param symbolSize Size associated with symbol
 */
void Symbol::setSize(unsigned long long symbolSize)
{
	size = symbolSize;
}

} // namespace fileinfo
