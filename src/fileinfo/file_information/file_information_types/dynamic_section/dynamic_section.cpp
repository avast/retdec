/**
 * @file src/fileinfo/file_information/file_information_types/dynamic_section/dynamic_section.cpp
 * @brief Class for dynamic section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/dynamic_section/dynamic_section.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
DynamicSection::DynamicSection() : declaredEntries(std::numeric_limits<unsigned long long>::max())
{

}

/**
 * Destructor
 */
DynamicSection::~DynamicSection()
{

}

/**
 * Get number of entries in section
 * @return Number of entries in section
 *
 * Returned value indicates the number of entries stored in this instance.
 * This number may not be as large as result of method @a getNumberOfDeclaredEntries().
 */
std::size_t DynamicSection::getNumberOfStoredEntries() const
{
	return table.size();
}

/**
 * Get number of entries in section
 * @return Number of entries in section
 *
 * Returned value indicates the declared number of entries stored in file section.
 * This number may not be as large as result of method @a getNumberOfStoredEntries().
 */
std::string DynamicSection::getNumberOfDeclaredEntriesStr() const
{
	return getNumberAsString(declaredEntries);
}

/**
 * Get name of dynamic section
 * @return Name of dynamic section
 */
std::string DynamicSection::getSectionName() const
{
	return name;
}

/**
 * Get type of selected entry
 * @param position Index of entry in section (0..x)
 * @return Type of selected entry
 */
std::string DynamicSection::getEntryType(std::size_t position) const
{
	return table[position].getType();
}

/**
 * Get description of selected entry
 * @param position Index of entry in section (0..x)
 * @return Description of selected entry
 */
std::string DynamicSection::getEntryDescription(std::size_t position) const
{
	return table[position].getDescription();
}

/**
 * Get value of selected entry
 * @param position Index of entry in section (0..x)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Value of selected entry
 */
std::string DynamicSection::getEntryValueStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	return table[position].getValueStr(format);
}

/**
 * Get number of entry's flags
 * @param position Index of entry in section (0..x)
 * @return Number of flags of selected entry
 */
unsigned long long DynamicSection::getEntryFlagsSize(std::size_t position) const
{
	return table[position].getFlagsSize();
}

/**
 * Get flags of selected entry
 * @param position Index of entry in section (0..x)
 * @return Flags of selected entry in number representation
 */
unsigned long long DynamicSection::getEntryFlags(std::size_t position) const
{
	return table[position].getFlags();
}

/**
 * Get flags of selected entry
 * @param position Index of entry in section (0..x)
 * @return Flags of selected entry in string representation
 */
std::string DynamicSection::getEntryFlagsStr(std::size_t position) const
{
	return table[position].getFlagsStr();
}

/**
 * Get number of flags descriptors of selected entry
 * @param position Index of entry in section (0..x)
 * @return Number of flags descriptors of selected entry
 */
std::size_t DynamicSection::getNumberOfEntryFlagsDescriptors(std::size_t position) const
{
	return table[position].getNumberOfFlagsDescriptors();
}

/**
 * Get flags descriptors of selected entry
 * @param position Index of entry in section (0..x)
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 */
void DynamicSection::getEntryFlagsDescriptors(std::size_t position, std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	table[position].getFlagsDescriptors(desc, abb);
}

/**
 * Set declared number of entries in section
 * @param entries Declared number of entries in section
 */
void DynamicSection::setNumberOfDeclaredEntries(unsigned long long entries)
{
	declaredEntries = entries;
}

/**
 * Set name of dynamic section
 * @param sectionName Name of section
 */
void DynamicSection::setSectionName(std::string sectionName)
{
	name = sectionName;
}

/**
 * Add entry to section
 * @param entry Item to add
 */
void DynamicSection::addEntry(DynamicEntry &entry)
{
	table.push_back(entry);
}

/**
 * Delete all entries from section
 */
void DynamicSection::clearEntries()
{
	table.clear();
}

} // namespace fileinfo
