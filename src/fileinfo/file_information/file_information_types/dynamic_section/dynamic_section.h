/**
 * @file src/fileinfo/file_information/file_information_types/dynamic_section/dynamic_section.h
 * @brief Class for dynamic section.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DYNAMIC_SECTION_DYNAMIC_SECTION_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_DYNAMIC_SECTION_DYNAMIC_SECTION_H

#include "fileinfo/file_information/file_information_types/dynamic_section/dynamic_entry.h"

namespace fileinfo {

/**
 * Class for dynamic section
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 * Methods with index parameters does not perform control of indexes.
 */
class DynamicSection
{
	private:
		unsigned long long declaredEntries; ///< declared number of entries in section
		std::string name;                   ///< name of dynamic section
		std::vector<DynamicEntry> table;    ///< vector of dynamic entries in section
	public:
		DynamicSection();
		~DynamicSection();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStoredEntries() const;
		std::string getNumberOfDeclaredEntriesStr() const;
		std::string getSectionName() const;
		std::string getEntryType(std::size_t position) const;
		std::string getEntryDescription(std::size_t position) const;
		std::string getEntryValueStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		unsigned long long getEntryFlagsSize(std::size_t position) const;
		unsigned long long getEntryFlags(std::size_t position) const;
		std::string getEntryFlagsStr(std::size_t position) const;
		std::size_t getNumberOfEntryFlagsDescriptors(std::size_t position) const;
		void getEntryFlagsDescriptors(std::size_t position, std::vector<std::string> &desc, std::vector<std::string> &abb) const;
		/// @}

		/// @name Setters
		/// @{
		void setNumberOfDeclaredEntries(unsigned long long entries);
		void setSectionName(std::string sectionName);
		/// @}

		/// @name Other methods
		/// @{
		void addEntry(DynamicEntry &entry);
		void clearEntries();
		/// @}
};

} // namespace fileinfo

#endif
