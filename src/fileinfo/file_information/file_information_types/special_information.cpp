/**
 * @file src/fileinfo/file_information/file_information_types/special_information.cpp
 * @brief Methods of SpecialInformation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/special_information.h"

namespace fileinfo {

/**
 * Constructor
 * @param desc_ Description of special information
 * @param abbv_ Abbreviation of @a desc_
 */
SpecialInformation::SpecialInformation(std::string desc_, std::string abbv_) : desc(desc_), abbv(abbv_)
{

}

/**
 * Destructor
 */
SpecialInformation::~SpecialInformation()
{

}

/**
 * Get number of stored values
 * @return Number of stored values
 */
std::size_t SpecialInformation::getNumberOfStoredValues() const
{
	return values.size();
}

/**
 * Get description
 * @return Description of special information
 */
std::string SpecialInformation::getDescription() const
{
	return desc;
}

/**
 * Get abbreviation
 * @return Abbreviation of description
 */
std::string SpecialInformation::getAbbreviation() const
{
	return abbv;
}

/**
 * Get value of stored record
 * @param position Position of stored record (0..x)
 */
std::string SpecialInformation::getValue(std::size_t position) const
{
	return values[position];
}

/**
 * Add special information (record)
 * @param value Value of special information
 */
void SpecialInformation::addValue(std::string value)
{
	values.push_back(value);
}

} // namespace fileinfo
