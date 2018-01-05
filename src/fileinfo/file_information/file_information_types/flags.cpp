/**
 * @file src/fileinfo/file_information/file_information_types/flags.cpp
 * @brief Class for binary flags.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <climits>

#include "fileinfo/file_information/file_information_types/flags.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
Flags::Flags() : size(0), flagsArray(0)
{

}

/**
 * Destructor
 */
Flags::~Flags()
{

}

/**
 * Get number of flags
 * @return Number of binary flags
 */
unsigned long long Flags::getSize() const
{
	return size;
}

/**
 * Get binary flags
 * @return Flags as one number
 */
unsigned long long Flags::getFlags() const
{
	return flagsArray;
}

/**
 * Get flags as string
 * @return Flags in string representation
 */
std::string Flags::getFlagsStr() const
{
	return getBinaryRepresentation(flagsArray, size);
}

/**
 * Get number of descriptors and its abbreviations
 * @return Number of descriptors
 *
 * It is guaranteed that the number of descriptors and abbreviations are the same
 */
std::size_t Flags::getNumberOfDescriptors() const
{
	return descriptors.size();
}

/**
 * Get flags descriptors and its abbreviations
 * @param desc Vector for save descriptors
 * @param abb Vector for save abbreviations of descriptors
 *
 * The first element in @a abb corresponds to the first element in @a desc etc.
 * Before loading descriptors, everything from vectors @a desc and @a abb is deleted.
 * It is guaranteed that the number of stored descriptors and abbreviations are the same.
 */
void Flags::getDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const
{
	desc.clear();
	abb.clear();

	for(std::size_t i = 0, e = descriptors.size(); i < e; ++i)
	{
		desc.push_back(descriptors[i]);
		abb.push_back(abbs[i]);
	}
}

/**
 * Set flags size (number of flags)
 * @param flagsSize Number of binary flags
 *
 * Maximum permissible value of parameter @a flagsSize is bit-width of unsigned long long int type.
 * If value of @a flagsSize is greater, it will be automatically reduce to the maximum permissible value.
 */
void Flags::setSize(unsigned long long flagsSize)
{
	const unsigned long long maxSize = sizeof(unsigned long long) * CHAR_BIT;
	size = std::min(flagsSize, maxSize);
}

/**
 * Set flags
 * @param flags Flags
 */
void Flags::setFlags(unsigned long long flags)
{
	flagsArray = flags;
}

/**
 * Add flag descriptor
 * @param descriptor Descriptor (full description of flag)
 * @param abbreviation Abbreviation (short description of flag)
 */
void Flags::addDescriptor(std::string descriptor, std::string abbreviation)
{
	descriptors.push_back(descriptor);
	abbs.push_back(abbreviation);
}

/**
 * Delete every descriptors and its abbreviations
 */
void Flags::clearDescriptors()
{
	descriptors.clear();
	abbs.clear();
}

} // namespace fileinfo
