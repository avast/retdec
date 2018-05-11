/**
 * @file src/fileinfo/file_information/file_information_types/rich_header.h
 * @brief Rich header.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RICH_HEADER_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RICH_HEADER_H

#include "retdec/fileformat/types/rich_header/rich_header.h"

namespace fileinfo {

/**
 * Class for rich header
 */
class RichHeader
{
	private:
		const retdec::fileformat::RichHeader *header;
	public:
		RichHeader();
		~RichHeader();

		/// @name Getters
		/// @{
		std::size_t getNumberOfStoredRecords() const;
		std::string getSignature() const;
		std::string getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getKeyStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getRecordMajorVersionStr(std::size_t position) const;
		std::string getRecordMinorVersionStr(std::size_t position) const;
		std::string getRecordBuildVersionStr(std::size_t position) const;
		std::string getRecordNumberOfUsesStr(std::size_t position) const;
		std::vector<std::uint8_t> getRawBytes() const;
		/// @}

		/// @name Setters
		/// @{
		void setHeader(const retdec::fileformat::RichHeader *richHeader);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		/// @}
};

} // namespace fileinfo

#endif
