/**
 * @file src/fileinfo/file_information/file_information_types/import_table.h
 * @brief Import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_IMPORT_TABLE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_IMPORT_TABLE_H

#include "retdec/fileformat/types/import_table/import_table.h"

namespace fileinfo {

/**
 * Class for import table
 */
class ImportTable
{
	private:
		const retdec::fileformat::ImportTable *table;
	public:
		ImportTable();
		~ImportTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfLibraries() const;
		std::size_t getNumberOfImports() const;
		std::string getImphashCrc32() const;
		std::string getImphashMd5() const;
		std::string getImphashSha256() const;
		const retdec::fileformat::Import* getImport(std::size_t position) const;
		std::string getImportName(std::size_t position) const;
		std::string getImportLibraryName(std::size_t position) const;
		std::string getImportAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		std::string getImportOrdinalNumberStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const;
		/// @}

		/// @name Setters
		/// @{
		void setTable(const retdec::fileformat::ImportTable *importTable);
		/// @}

		/// @name Other methods
		/// @{
		bool hasRecords() const;
		/// @}
};

} // namespace fileinfo

#endif
