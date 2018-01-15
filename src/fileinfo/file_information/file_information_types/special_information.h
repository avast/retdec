/**
 * @file src/fileinfo/file_information/file_information_types/special_information.h
 * @brief Definition of SpecialInformation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SPECIAL_INFORMATION_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SPECIAL_INFORMATION_H

#include <string>
#include <vector>

namespace fileinfo {

/**
 * Class for special information about file.
 *
 * This information is not part of the file format specification.
 */
class SpecialInformation
{
	private:
		std::string desc;                ///< description of special information
		std::string abbv;                ///< abbreviation of @a desc
		std::vector<std::string> values; ///< values of special information
	public:
		SpecialInformation(std::string desc_, std::string abbv_);
		~SpecialInformation();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStoredValues() const;
		std::string getDescription() const;
		std::string getAbbreviation() const;
		std::string getValue(std::size_t position) const;
		/// @}

		/// Other methods
		/// @{
		void addValue(std::string value);
		/// @}
};

} // namespace fileinfo

#endif
