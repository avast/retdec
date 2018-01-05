/**
 * @file src/fileinfo/file_information/file_information_types/strings.h
 * @brief Strings.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_STRINGS_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_STRINGS_H

#include <vector>

#include "retdec/fileformat/types/strings/string.h"

namespace fileinfo {

/**
 * Class for strings
 */
class Strings
{
	private:
		const std::vector<retdec::fileformat::String>* strings;
	public:
		Strings();
		~Strings() = default;

		/// @name Getters
		/// @{
		std::size_t getNumberOfStrings() const;
		std::string getStringFileOffsetStr(std::size_t index, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getStringTypeStr(std::size_t index) const;
		std::string getStringSectionName(std::size_t index) const;
		std::string getStringContent(std::size_t index) const;
		/// @}

		/// @name Setters
		/// @{
		void setStrings(const std::vector<retdec::fileformat::String> *detectedStrings);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		/// @}
};

} // namespace fileinfo

#endif
