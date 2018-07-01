/**
 * @file src/fileformat/types/export_table/export.cpp
 * @brief Class for one export.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/export_table/export.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
Export::Export() : address(0), ordinalNumber(0), ordinalNumberIsValid(false)
{

}

/**
 * Destructor
 */
Export::~Export()
{

}

/**
 * Get export name
 * @return Export name
 */
std::string Export::getName() const
{
	return name;
}

/**
 * Get export address
 * @return Export address
 */
unsigned long long Export::getAddress() const
{
	return address;
}

/**
 * Get ordinal number of export
 * @param exportOrdinalNumber Into this parameter is stored ordinal number of export
 * @return @c true if ordinal number id valid, @c false otherwise
 *
 * If method returns @c false, @a exportOrdinalNumber is left unchanged
 */
bool Export::getOrdinalNumber(unsigned long long &exportOrdinalNumber) const
{
	if(ordinalNumberIsValid)
	{
		exportOrdinalNumber = ordinalNumber;
	}

	return ordinalNumberIsValid;
}

/**
 * Set export name
 * @param exportName Export name
 */
void Export::setName(std::string exportName)
{
	name = exportName;
}

/**
 * Set export address
 * @param exportAddress Export address
 */
void Export::setAddress(unsigned long long exportAddress)
{
	address = exportAddress;
}

/**
 * Set export ordinal number
 * @param exportOrdinalNumber Export ordinal number
 */
void Export::setOrdinalNumber(unsigned long long exportOrdinalNumber)
{
	ordinalNumber = exportOrdinalNumber;
	ordinalNumberIsValid = true;
}

/**
 * Virtual method which indicates whether export should be used
 * for calculating exphash.
 * @return `true` if should be used, otherwise `false`.
 */
bool Export::isUsedForExphash() const
{
	return true;
}

/**
 * Invalidate ordinal number of export
 *
 * Instance method @a getOrdinalNumber() returns @c false after invocation of
 * this method. Ordinal number is possible to revalidate by invocation
 * of method @a setOrdinalNumber().
 */
void Export::invalidateOrdinalNumber()
{
	ordinalNumberIsValid = false;
}

/**
 * @return @c true if export has empty name, @c false otherwise
 */
bool Export::hasEmptyName() const
{
	return name.empty();
}

} // namespace fileformat
} // namespace retdec
