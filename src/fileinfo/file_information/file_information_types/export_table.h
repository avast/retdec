/**
 * @file src/fileinfo/file_information/file_information_types/export_table.h
 * @brief Export table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_EXPORT_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_EXPORT_TABLE_H

#include "retdec/fileformat/types/export_table/export_table.h"

namespace fileinfo {

/**
 * Class for export table
 */
class ExportTable
{
	private:
		const retdec::fileformat::ExportTable *table;
	public:
		ExportTable();
		~ExportTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfExports() const;
		std::string getExphashCrc32() const;
		std::string getExphashMd5() const;
		std::string getExphashSha256() const;
		std::string getExportName(std::size_t position) const;
		std::string getExportAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getExportOrdinalNumberStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setTable(const retdec::fileformat::ExportTable *exportTable);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		/// @}
};

} // namespace fileinfo

#endif
