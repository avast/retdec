/**
 * @file src/fileinfo/file_information/file_information_types/import_table.cpp
 * @brief Import table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/import_table.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace retdec {
namespace fileinfo {

/**
 * Get number of libraries in table
 * @return Number of libraries in table
 */
std::size_t ImportTable::getNumberOfLibraries() const
{
	return table ? table->getNumberOfLibraries() : 0;
}

/**
 * Get number of imports in table
 * @return Number of imports in table
 */
std::size_t ImportTable::getNumberOfImports() const
{
	return table ? table->getNumberOfImports() : 0;
}

/**
 * Get imphash as CRC32
 * @return Imphash as CRC32
 */
std::string ImportTable::getImphashCrc32() const
{
	return table ? table->getImphashCrc32() : "";
}

/**
 * Get imphash as MD5
 * @return Imphash as MD5
 */
std::string ImportTable::getImphashMd5() const
{
	return table ? table->getImphashMd5() : "";
}

/**
 * Get imphash as SHA256
 * @return Imphash as SHA256
 */
std::string ImportTable::getImphashSha256() const
{
	return table ? table->getImphashSha256() : "";
}

std::string ImportTable::getImphashTlsh() const
{
	return table ? table->getImpHashTlsh() : "";
}

/**
 * Get import
 * @param position Index of selected import from table (indexed from 0)
 * @return Import
 */
const retdec::fileformat::Import* ImportTable::getImport(std::size_t position) const
{
	return table ? table->getImport(position) : nullptr;
}

/**
 * Get import name
 * @param position Index of selected import from table (indexed from 0)
 * @return Import name
 */
std::string ImportTable::getImportName(std::size_t position) const
{
	const auto *record = table ? table->getImport(position) : nullptr;
	return record ? record->getName() : "";
}

std::string ImportTable::getImportUsageType(std::size_t position) const
{
	const auto *record = table ? table->getImport(position) : nullptr;
	if (record == nullptr)
	{
		return "";
	}
	switch (record->getUsageType())
	{
		case retdec::fileformat::Import::UsageType::FILE:
			return "FILE";
		case retdec::fileformat::Import::UsageType::FUNCTION:
			return "FUNCTION";
		case retdec::fileformat::Import::UsageType::OBJECT:
			return "OBJECT";
		case retdec::fileformat::Import::UsageType::UNKNOWN:
		default:
			return "UNKNOWN";
	}
}

/**
 * Get import library name
 * @param position Index of selected import from table (indexed from 0)
 * @return Import library name
 */
std::string ImportTable::getImportLibraryName(std::size_t position) const
{
	const auto *record = table ? table->getImport(position) : nullptr;
	return record ? table->getLibrary(record->getLibraryIndex()) : "";
}

/**
 * Get import address
 * @param position Index of selected import from table (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Import address
 */
std::string ImportTable::getImportAddressStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	const auto *record = table ? table->getImport(position) : nullptr;
	return record ? getNumberAsString(record->getAddress(), format) : "";
}

/**
 * Get import ordinal number
 * @param position Index of selected import from table (indexed from 0)
 * @param format Format of resulting string (e.g. std::dec, std::hex)
 * @return Import ordinal number
 */
std::string ImportTable::getImportOrdinalNumberStr(std::size_t position, std::ios_base &(* format)(std::ios_base &)) const
{
	std::uint64_t ordinal;
	const auto *record = table ? table->getImport(position) : nullptr;
	return record && record->getOrdinalNumber(ordinal) ? getNumberAsString(ordinal, format) : "";
}

/**
 * Get n-th missing dependency
 * @param position Index of selected import from table (indexed from 0)
 * @return library name
 */
std::string ImportTable::getMissingDepName(std::size_t position) const
{
	std::string depName = "";

	if(table != NULL)
		depName = table->getMissingDependencies().at(position);
	return depName;
}

/**
 * Get the number of missing dependencies
 * @return number of missing dependencies
 */
std::size_t ImportTable::getNumberOfMissingDeps() const
{
	size_t depsCount = 0;

	if (table != NULL)
		depsCount = table->getMissingDependencies().size();
	return depsCount;
}

/**
 * Set import table data
 * @param importTable Instance of class with original information about import table
 */
void ImportTable::setTable(const retdec::fileformat::ImportTable *importTable)
{
	table = importTable;
}

/**
 * Find out if there are any imports
 * @return @c true if there are some imports, @c false otherwise
 */
bool ImportTable::hasRecords() const
{
	return table ? table->hasImports() : false;
}

} // namespace fileinfo
} // namespace retdec
