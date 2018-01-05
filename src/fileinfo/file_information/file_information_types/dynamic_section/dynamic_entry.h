/**
 * @file src/fileinfo/file_information/file_information_types/dynamic_section/dynamic_entry.h
 * @brief Class for dynamic entry.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DYNAMIC_SECTION_DYNAMIC_ENTRY_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DYNAMIC_SECTION_DYNAMIC_ENTRY_H

#include "fileinfo/file_information/file_information_types/flags.h"

namespace fileinfo {

/**
 * Class for dynamic entry
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for unsigned integer types.
 */
class DynamicEntry
{
	private:
		std::string type;         ///< type of dynamic entry
		std::string description;  ///< additional description
		unsigned long long value; ///< value of dynamic entry
		Flags flags;              ///< flags of dynamic entry
	public:
		DynamicEntry();
		~DynamicEntry();

		/// @name Getters
		/// @{
		std::string getType() const;
		std::string getDescription() const;
		std::string getValueStr(std::ios_base &(* format)(std::ios_base &)) const;
		unsigned long long getFlagsSize() const;
		unsigned long long getFlags() const;
		std::string getFlagsStr() const;
		std::size_t getNumberOfFlagsDescriptors() const;
		void getFlagsDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const;
		/// @}

		/// @name Setters
		/// @{
		void setType(std::string dynType);
		void setDescription(std::string desc);
		void setValue(unsigned long long dynValue);
		void setFlagsSize(unsigned long long flagsSize);
		void setFlags(unsigned long long flagsValue);
		/// @}

		///@name Other methods
		/// @{
		void addFlagsDescriptor(std::string descriptor, std::string abbreviation);
		void clearFlagsDescriptors();
		/// @}
};

} // namespace fileinfo

#endif
