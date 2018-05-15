/**
 * @file src/fileformat/types/import_table/import.cpp
 * @brief Class for one import.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/import_table/import.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
Import::Import() : libraryIndex(0), address(0), ordinalNumber(0), ordinalNumberIsValid(false)
{

}

/**
 * Destructor
 */
Import::~Import()
{

}

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
unsigned long long Import::getLibraryIndex() const
{
	return libraryIndex;
}

/**
 * Get address of import
 * @return Address of import
 */
unsigned long long Import::getAddress() const
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
bool Import::getOrdinalNumber(unsigned long long &importOrdinalNumber) const
{
	if(ordinalNumberIsValid)
	{
		importOrdinalNumber = ordinalNumber;
	}

	return ordinalNumberIsValid;
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
void Import::setLibraryIndex(unsigned long long importLibraryIndex)
{
	libraryIndex = importLibraryIndex;
}

/**
 * Set address of import
 * @param importAddress Address of import
 */
void Import::setAddress(unsigned long long importAddress)
{
	address = importAddress;
}

/**
 * Set ordinal number of import
 * @param importOrdinalNumber Ordinal number of import
 */
void Import::setOrdinalNumber(unsigned long long importOrdinalNumber)
{
	ordinalNumber = importOrdinalNumber;
	ordinalNumberIsValid = true;
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
