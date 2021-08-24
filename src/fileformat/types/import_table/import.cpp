/**
 * @file src/fileformat/types/import_table/import.cpp
 * @brief Class for one import.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/import_table/import.h"

namespace retdec {
namespace fileformat {

/**
 * Get import name
 * @return Import name
 */
std::string Import::getName() const
{
	return name;
}

/**
 * Get index of library from which is import
 * @return Index of library from which is import
 */
std::uint64_t Import::getLibraryIndex() const
{
	return libraryIndex;
}

/**
 * Get address of import
 * @return Address of import
 */
std::uint64_t Import::getAddress() const
{
	return address;
}

/**
 * Get ordinal number of import
 * @param importOrdinalNumber Into this parameter is stored ordinal number of import
 * @return @c true if ordinal number id valid, @c false otherwise
 *
 * If method returns @c false, @a importOrdinalNumber is left unchanged
 */
bool Import::getOrdinalNumber(std::uint64_t &importOrdinalNumber) const
{
	if(ordinalNumberIsValid)
	{
		importOrdinalNumber = ordinalNumber;
	}

	return ordinalNumberIsValid;
}

/**
 * Get import usage type
 * @return Import usage type
 */
Import::UsageType Import::getUsageType() const
{
	return usageType;
}

/**
 * @return @c true if import is unkown, @c false otherwise
 */
bool Import::isUnknown() const
{
	return getUsageType() == UsageType::UNKNOWN;
}

/**
 * @return @c true if import is function, @c false otherwise
 */
bool Import::isFunction() const
{
	return getUsageType() == UsageType::FUNCTION;
}

/**
 * @return @c true if import is object, @c false otherwise
 */
bool Import::isObject() const
{
	return getUsageType() == UsageType::OBJECT;
}

/**
 * @return @c true if import is file, @c false otherwise
 */
bool Import::isFile() const
{
	return getUsageType() == UsageType::FILE;
}

/**
 * Set import name
 * @param importName Import name
 */
void Import::setName(std::string importName)
{
	name = importName;
}

/**
 * Set library index
 * @param importLibraryIndex Index of library from which is import
 */
void Import::setLibraryIndex(std::uint64_t importLibraryIndex)
{
	libraryIndex = importLibraryIndex;
}

/**
 * Set address of import
 * @param importAddress Address of import
 */
void Import::setAddress(std::uint64_t importAddress)
{
	address = importAddress;
}

/**
 * Set ordinal number of import
 * @param importOrdinalNumber Ordinal number of import
 */
void Import::setOrdinalNumber(std::uint64_t importOrdinalNumber)
{
	ordinalNumber = importOrdinalNumber;
	ordinalNumberIsValid = true;
}

/**
 * Set import usage type
 * @param importUsageType Symbol usage type
 */
void Import::setUsageType(Import::UsageType importUsageType)
{
	usageType = importUsageType;
}

/**
 * Virtual method which indicates whether import should be used
 * for calculating imphash.
 * @return `true` if should be used, otherwise `false`.
 */
bool Import::isUsedForImphash() const
{
	return true;
}

/**
 * Invalidate ordinal number of import
 *
 * Instance method @a getOrdinalNumber() returns @c false after invocation of
 * this method. Ordinal number is possible to revalidate by invocation
 * of method @a setOrdinalNumber().
 */
void Import::invalidateOrdinalNumber()
{
	ordinalNumberIsValid = false;
}

/**
 * @return @c true if import has empty name, @c false otherwise
 */
bool Import::hasEmptyName() const
{
	return name.empty();
}

} // namespace fileformat
} // namespace retdec
