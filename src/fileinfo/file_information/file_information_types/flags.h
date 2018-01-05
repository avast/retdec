/**
 * @file src/fileinfo/file_information/file_information_types/flags.h
 * @brief Class for binary flags.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_FLAGS_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_FLAGS_H

#include <string>
#include <vector>

namespace fileinfo {

/**
 * Flags class
 */
class Flags
{
	private:
		unsigned long long size;              ///< size of bit array
		unsigned long long flagsArray;        ///< array of flags
		std::vector<std::string> descriptors; ///< descriptors of flags
		std::vector<std::string> abbs;        ///< abbreviations of descriptors
	public:
		Flags();
		~Flags();

		/// @name Getters
		/// @{
		unsigned long long getSize() const;
		unsigned long long getFlags() const;
		std::string getFlagsStr() const;
		std::size_t getNumberOfDescriptors() const;
		void getDescriptors(std::vector<std::string> &desc, std::vector<std::string> &abb) const;
		/// @}

		/// @name Setters
		/// @{
		void setSize(unsigned long long flagsSize);
		void setFlags(unsigned long long flags);
		/// @}

		/// @name Other methods
		/// @{
		void addDescriptor(std::string descriptor, std::string abbreviation);
		void clearDescriptors();
		/// @}
};

} // namespace fileinfo

#endif
