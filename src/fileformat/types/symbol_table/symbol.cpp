/**
 * @file src/fileformat/types/symbol_table/symbol.cpp
 * @brief Class for one symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/types/symbol_table/symbol.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
Symbol::Symbol() : type(Type::UNDEFINED_SYM), usageType(UsageType::UNKNOWN),
	index(0), address(0), size(0), linkToSection(0), addressIsValid(false),
	sizeIsValid(false), linkIsValid(false), thumbSymbol(false)
{

}

/**
 * Destructor
 */
Symbol::~Symbol()
{

}

/**
 * @return @c true if symbol is undefined, @c false otherwise
 */
bool Symbol::isUndefined() const
{
	return getType() == Type::UNDEFINED_SYM;
}

/**
 * @return @c true if symbol is private, @c false otherwise
 */
bool Symbol::isPrivate() const
{
	return getType() == Type::PRIVATE;
}

/**
 * @return @c true if symbol is public, @c false otherwise
 */
bool Symbol::isPublic() const
{
	return getType() == Type::PUBLIC;
}

/**
 * @return @c true if symbol is weak, @c false otherwise
 */
bool Symbol::isWeak() const
{
	return getType() == Type::WEAK;
}

/**
 * @return @c true if symbol is extern, @c false otherwise
 */
bool Symbol::isExtern() const
{
	return getType() == Type::EXTERN;
}

/**
 * @return @c true if symbol is absolute, @c false otherwise
 */
bool Symbol::isAbsolute() const
{
	return getType() == Type::ABSOLUTE_SYM;
}

/**
 * @return @c true if symbol is common, @c false otherwise
 */
bool Symbol::isCommon() const
{
	return getType() == Type::COMMON;
}

/**
 * @return @c true if symbol is unkown, @c false otherwise
 */
bool Symbol::isUnknown() const
{
	return getUsageType() == UsageType::UNKNOWN;
}

/**
 * @return @c true if symbol is function, @c false otherwise
 */
bool Symbol::isFunction() const
{
	return getUsageType() == UsageType::FUNCTION;
}

/**
 * @return @c true if symbol is object, @c false otherwise
 */
bool Symbol::isObject() const
{
	return getUsageType() == UsageType::OBJECT;
}

/**
 * @return @c true if symbol is file, @c false otherwise
 */
bool Symbol::isFile() const
{
	return getUsageType() == UsageType::FILE;
}

/**
 * @return @c true if symbol is THUMB symbol, @c false otherwise
 */
bool Symbol::isThumbSymbol() const
{
	return thumbSymbol;
}

/**
 * @return @c true if symbol's address is valid and even, @c false otherwise
 */
bool Symbol::isEven() const
{
	unsigned long long a = 0;
	return getAddress(a) && a % 2 == 0;
}

/**
 * @return @c true if symbol's address is valid and odd, @c false otherwise
 */
bool Symbol::isOdd() const
{
	unsigned long long a = 0;
	return getAddress(a) && a % 2 == 1;
}

/**
 * @return @c true if symbol has empty name, @c false otherwise
 */
bool Symbol::hasEmptyName() const
{
	return name.empty();
}

/**
 * Get symbol name
 * @return Symbol name
 */
const std::string &Symbol::getName() const
{
	return name;
}

/**
 * Get normalized symbol name
 * @return Normalized symbol name
 */
std::string Symbol::getNormalizedName() const
{
	return normalizeName(getName());
}

/**
 * Get original name
 * @return Original name of symbol
 */
std::string Symbol::getOriginalName() const
{
	return originalName;
}

/**
 * Get symbol type
 * @return Symbol type
 */
Symbol::Type Symbol::getType() const
{
	return type;
}

/**
 * Get symbol usage type
 * @return Symbol usage type
 */
Symbol::UsageType Symbol::getUsageType() const
{
	return usageType;
}

/**
 * Get symbol index
 * @return Symbol index
 */
unsigned long long Symbol::getIndex() const
{
	return index;
}

/**
 * Get symbol virtual address
 * @param virtualAddress Into this parameter is stored symbol virtual address
 * @return @c true if symbol virtual address is valid, @c false otherwise
 *
 * If method returns @c false, @a virtualAddress is left unchanged
 */
bool Symbol::getAddress(unsigned long long &virtualAddress) const
{
	if(addressIsValid)
	{
		virtualAddress = address;
	}

	return addressIsValid;
}

/**
 * Get real symbol virtual address -- if symbol is not THUMB, return result of
 * @c getAddress(). If symbol is THUMB, return result of @c getAddress()
 * decremented by one.
 * @param virtualAddress Into this parameter is stored symbol virtual address
 * @return @c true if symbol virtual address is valid, @c false otherwise
 */
bool Symbol::getRealAddress(unsigned long long &virtualAddress) const
{
	if(getAddress(virtualAddress))
	{
		unsigned long long sec = 0;
		if(!virtualAddress && !getLinkToSection(sec))
		{
			return false;
		}

		if(isThumbSymbol())
		{
			--virtualAddress;
		}

		return true;
	}

	return false;
}

/**
 * Get size of symbol
 * @param symbolSize Into this parameter is stored size of symbol
 * @return @c true if symbol size is known and valid, @c false otherwise
 *
 * If method returns @c false, @a symbolSize is left unchanged
 */
bool Symbol::getSize(unsigned long long &symbolSize) const
{
	if(sizeIsValid)
	{
		symbolSize = size;
	}

	return sizeIsValid;
}

/**
 * Get link to associated section
 * @param sectionIndex Parameter for store the result
 * @return @c true if symbol is associated with one of the sections, @c false otherwise
 *
 * If method returns @c false, @a sectionIndex is left unchanged
 */
bool Symbol::getLinkToSection(unsigned long long &sectionIndex) const
{
	if(!linkIsValid || type == Type::EXTERN || type == Type::ABSOLUTE_SYM || type == Type::COMMON)
	{
		return false;
	}

	sectionIndex = linkToSection;
	return true;
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
 * Set original name of symbol
 * @param symbolOriginalName Original name of symbol
 */
void Symbol::setOriginalName(std::string symbolOriginalName)
{
	originalName = symbolOriginalName;
}

/**
 * Set symbol type
 * @param symbolType Symbol type
 */
void Symbol::setType(Symbol::Type symbolType)
{
	type = symbolType;
}

/**
 * Set symbol usage type
 * @param symbolUsageType Symbol usage type
 */
void Symbol::setUsageType(Symbol::UsageType symbolUsageType)
{
	usageType = symbolUsageType;
}

/**
 * Set symbol index
 * @param symbolIndex Index of symbol in symbol table
 */
void Symbol::setIndex(unsigned long long symbolIndex)
{
	index = symbolIndex;
}

/**
 * Set symbol virtual address
 * @param symbolAddress Symbol virtual address
 */
void Symbol::setAddress(unsigned long long symbolAddress)
{
	address = symbolAddress;
	addressIsValid = true;
}

/**
 * Set symbol size
 * @param symbolSize Size of symbol
 */
void Symbol::setSize(unsigned long long symbolSize)
{
	size = symbolSize;
	sizeIsValid = true;
}

/**
 * Set link to associated section
 * @param sectionIndex Link to associated section
 */
void Symbol::setLinkToSection(unsigned long long sectionIndex)
{
	linkToSection = sectionIndex;
	linkIsValid = true;
}

/**
 * Set is THUMB symbol flag
 * @param b Value of is THUMB symbol flag to set
 */
void Symbol::setIsThumbSymbol(bool b)
{
	thumbSymbol = b;
}

/**
 * Invalidate virtual address of symbol
 *
 * Instance method @a getAddress() returns @c false after invocation of
 * this method. Virtual address is possible to revalidate by invocation
 * of method @a setAddress().
 */
void Symbol::invalidateAddress()
{
	addressIsValid = false;
}

/**
 * Invalidate size of symbol
 *
 * Instance method @a getSize() returns @c false after invocation of this
 * method. Size of symbol is possible to revalidate by invocation of method
 * @a setSize().
 */
void Symbol::invalidateSize()
{
	sizeIsValid = false;
}

/**
 * Invalidate link to section
 *
 * Instance method @a getLinkToSection() returns @c false after invocation
 * of this method. Link to section is possible to revalidate by invocation
 * of method @a setLinkToSection().
 */
void Symbol::invalidateLinkToSection()
{
	linkIsValid = false;
}

} // namespace fileformat
} // namespace retdec
