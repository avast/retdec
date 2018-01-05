/**
 * @file src/fileformat/types/dynamic_table/dynamic_entry.cpp
 * @brief Class for dynamic entry.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/dynamic_table/dynamic_entry.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
DynamicEntry::DynamicEntry() : type(0), value(0)
{

}

/**
 * Destructor
 */
DynamicEntry::~DynamicEntry()
{

}

/**
 * Get type of dynamic entry
 * @return Type of dynamic entry
 */
unsigned long long DynamicEntry::getType() const
{
	return type;
}

/**
 * Get value of dynamic entry
 * @return Value of dynamic entry
 */
unsigned long long DynamicEntry::getValue() const
{
	return value;
}

/**
 * Get description of dynamic entry
 * @return Description of dynamic entry
 */
std::string DynamicEntry::getDescription() const
{
	return description;
}

/**
 * Set type of dynamic entry
 * @param entryType Type of dynamic entry
 */
void DynamicEntry::setType(unsigned long long entryType)
{
	type = entryType;
}

/**
 * Set value of dynamic entry
 * @param entryValue Value of dynamic entry
 */
void DynamicEntry::setValue(unsigned long long entryValue)
{
	value = entryValue;
}

/**
 * Set description of dynamic entry
 * @param entryDescription Description of dynamic entry
 */
void DynamicEntry::setDescription(std::string entryDescription)
{
	description = entryDescription;
}

} // namespace fileformat
} // namespace retdec
