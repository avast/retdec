/**
 * @file src/fileinfo/file_information/file_information_types/dynamic_section/dynamic_entry.cpp
 * @brief Class for dynamic entry.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/dynamic_section/dynamic_entry.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
DynamicEntry::DynamicEntry() : value(std::numeric_limits<unsigned long long>::max())
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
std::string DynamicEntry::getType() const
{
	return type;
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
 * Get value of dynamic entry
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Value of dynamic entry
 */
std::string DynamicEntry::getValueStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(value, format);
}

/**
 * Get number of flags
 * @return Number of flags
 */
unsigned long long DynamicEntry::getFlagsSize() const
{
	return flags.getSize();
}

/**
 * Get flags
 * @return Flags as number
 */
unsigned long long DynamicEntry::getFlags() const
{
	return flags.getFlags();
}

/**
 * Get flags
 * @return Flags as string
 */
std::string DynamicEntry::getFlagsStr() const
{
	return flags.getFlagsStr();
}

/**
 * Get number of flags descriptors
 * @return Number of flags descriptors
 */
std::size_t DynamicEntry::getNumberOfFlagsDescriptors() const
{
	return flags.getNumberOfDescriptors();
}

/**
 * Get flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void DynamicEntry::getFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	flags.getDescriptors(desc, abb);
}

/**
 * Set type of dynamic entry
 * @param dynType Type of dynamic entry
 */
void DynamicEntry::setType(std::string dynType)
{
	type = dynType;
}

/**
 * Set description of dynamic entry
 * @param desc Description of dynamic entry
 */
void DynamicEntry::setDescription(std::string desc)
{
	description = desc;
}

/**
 * Set value of dynamic entry
 * @param dynValue Value of dynamic entry
 */
void DynamicEntry::setValue(unsigned long long dynValue)
{
	value = dynValue;
}

/**
 * Set number of flags
 * @param flagsSize Number of flags
 */
void DynamicEntry::setFlagsSize(unsigned long long flagsSize)
{
	flags.setSize(flagsSize);
}

/**
 * Set flags value
 * @param flagsValue Flags value
 */
void DynamicEntry::setFlags(unsigned long long flagsValue)
{
	flags.setFlags(flagsValue);
}

/**
 * Add flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void DynamicEntry::addFlagsDescriptor(std::string descriptor, std::string abbreviation)
{
	flags.addDescriptor(descriptor, abbreviation);
}

/**
 * Delete all flags descriptors
 */
void DynamicEntry::clearFlagsDescriptors()
{
	flags.clearDescriptors();
}

} // namespace fileinfo
