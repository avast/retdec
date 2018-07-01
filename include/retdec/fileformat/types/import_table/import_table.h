/**
 * @file include/retdec/fileformat/types/import_table/import_table.h
 * @brief Class for import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_IMPORT_TABLE_H
#define RETDEC_FILEFORMAT_TYPES_IMPORT_TABLE_IMPORT_TABLE_H

#include <memory>
#include <vector>

#include "retdec/fileformat/types/import_table/import.h"

namespace retdec {
namespace fileformat {

/**
 * Table of imports
 */
class ImportTable
{
	private:
		using importsIterator = std::vector<std::unique_ptr<Import>>::const_iterator;
		std::vector<std::string> libraries;           ///< name of libraries
		std::vector<std::unique_ptr<Import>> imports; ///< stored imports
		std::string impHashCrc32;                     ///< imphash CRC32
		std::string impHashMd5;                       ///< imphash MD5
		std::string impHashSha256;                    ///< imphash SHA256
	public:
		ImportTable();
		~ImportTable();

		/// @name Getters
		/// @{
		std::size_t getNumberOfLibraries() const;
		std::size_t getNumberOfImports() const;
		std::size_t getNumberOfImportsInLibrary(std::size_t libraryIndex) const;
		std::size_t getNumberOfImportsInLibrary(const std::string &name) const;
		std::size_t getNumberOfImportsInLibraryCaseInsensitive(const std::string &name) const;
		const std::string& getImphashCrc32() const;
		const std::string& getImphashMd5() const;
		const std::string& getImphashSha256() const;
		std::string getLibrary(std::size_t libraryIndex) const;
		const Import* getImport(std::size_t importIndex) const;
		const Import* getImport(const std::string &name) const;
		const Import* getImportOnAddress(unsigned long long address) const;
		/// @}

		/// @name Iterators
		/// @{
		importsIterator begin() const;
		importsIterator end() const;
		/// @}

		/// @name Other methods
		/// @{
		void computeHashes();
		void clear();
		void addLibrary(std::string name);
		void addImport(std::unique_ptr<Import>&& import);
		bool hasLibraries() const;
		bool hasLibrary(const std::string &name) const;
		bool hasLibraryCaseInsensitive(const std::string &name) const;
		bool hasImports() const;
		bool hasImport(const std::string &name) const;
		bool hasImport(unsigned long long address) const;
		bool empty() const;
		void dump(std::string &dumpTable) const;
		void dumpLibrary(std::size_t libraryIndex, std::string &libraryDump) const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
