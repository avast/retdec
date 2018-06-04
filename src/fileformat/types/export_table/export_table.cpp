/**
 * @file src/fileformat/types/export_table/export_table.cpp
 * @brief Class for export table.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/crypto/crypto.h"
#include "retdec/utils/string.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/types/export_table/export_table.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
ExportTable::ExportTable()
{

}

/**
 * Destructor
 */
ExportTable::~ExportTable()
{

}

/**
 * Get number of stored exports
 * @return Number of stored exports
 */
std::size_t ExportTable::getNumberOfExports() const
{
	return exports.size();
}

/**
 * Get exphash as CRC32
 * @return Exphash as CRC32
 */
const std::string& ExportTable::getExphashCrc32() const
{
	return expHashCrc32;
}

/**
 * Get exphash as MD5
 * @return Exphash as MD5
 */
const std::string& ExportTable::getExphashMd5() const
{
	return expHashMd5;
}

/**
 * Get exphash as SHA256
 * @return Exphash as SHA256
 */
const std::string& ExportTable::getExphashSha256() const
{
	return expHashSha256;
}

/**
 * Get selected export
 * @param exportIndex Index of selected export (indexed from 0)
 * @return Pointer to selected export or @c nullptr if export index is invalid
 */
const Export* ExportTable::getExport(std::size_t exportIndex) const
{
	return (exportIndex < getNumberOfExports()) ? &exports[exportIndex] : nullptr;
}

/**
 * Get export by name
 * @param name Name of the export to get
 * @return Pointer to export with the specified name or @c nullptr if such export not found
 */
const Export* ExportTable::getExport(const std::string &name) const
{
	for(const auto &e : exports)
	{
		if(e.getName() == name)
		{
			return &e;
		}
	}

	return nullptr;
}

/**
 * Get export by address
 * @param address Address of the export to get
 * @return Pointer to export with specified address or @c nullptr if such export not found
 */
const Export* ExportTable::getExportOnAddress(unsigned long long address) const
{
	for(const auto &e : exports)
	{
		if(e.getAddress() == address)
		{
			return &e;
		}
	}

	return nullptr;
}

/**
 * Get begin iterator
 * @return Begin iterator
 */
ExportTable::exportsIterator ExportTable::begin() const
{
	return exports.begin();
}

/**
 * Get end iterator
 * @return End iterator
 */
ExportTable::exportsIterator ExportTable::end() const
{
	return exports.end();
}

/**
 * Compute export hashes - CRC32, MD5, SHA256.
 */
void ExportTable::computeHashes()
{
	std::vector<std::string> funcNames;
	std::vector<std::uint8_t> expHashBytes;

	for(const auto& newExport : exports)
	{
		if(!newExport.isUsedForExphash())
		{
			continue;
		}

		auto funcName = toLower(newExport.getName());

		// convert ordinal to export name
		if(funcName.empty())
		{
			unsigned long long ord;
			if(newExport.getOrdinalNumber(ord))
			{
				funcName = toLower("ord" + std::to_string(ord));
			}
		}

		if(!funcName.empty())
		{
			funcNames.push_back(funcName);
		}
	}

	std::sort(funcNames.begin(), funcNames.end());

	for(const auto& funcName : funcNames)
	{
		// Yara adds comma if there are multiple imports
		if(!expHashBytes.empty())
		{
			expHashBytes.push_back(static_cast<unsigned char>(','));
		}

		for(const auto c : std::string(funcName))
		{
			expHashBytes.push_back(static_cast<unsigned char>(c));
		}
	}

	expHashCrc32 = retdec::crypto::getCrc32(expHashBytes.data(), expHashBytes.size());
	expHashMd5 = retdec::crypto::getMd5(expHashBytes.data(), expHashBytes.size());
	expHashSha256 = retdec::crypto::getSha256(expHashBytes.data(), expHashBytes.size());
}

/**
 * Delete all records from table
 */
void ExportTable::clear()
{
	exports.clear();
}

/**
 * Add export
 * @param newExport Export which will be added
 */
void ExportTable::addExport(Export &newExport)
{
	exports.push_back(newExport);
}

/**
 * Find out if there are any exports
 * @return @c true if there are some exports, @c false otherwise
 */
bool ExportTable::hasExports() const
{
	return !exports.empty();
}

/**
 * Check if export with name @a name exists
 * @param name Name of export
 * @return @c true if has export with name @a name, @c false otherwise
 */
bool ExportTable::hasExport(const std::string &name) const
{
	return getExport(name);
}

/**
 * Check if export on address exists
 * @param address Adress of export
 * @return @c true if has export on @a address, @c false otherwise
 */
bool ExportTable::hasExport(unsigned long long address) const
{
	return getExportOnAddress(address);
}

/**
 * Check if export table is empty
 * @return @c true if no exports are stored in table, @c false otherwise
 */
bool ExportTable::empty() const
{
	return exports.empty();
}

/**
 * Dump information about all exports in table
 * @param dumpTable Into this parameter is stored dump of export table in an LLVM style
 */
void ExportTable::dump(std::string &dumpTable) const
{
	std::stringstream ret;

	ret << "; ------------ Exported functions ------------\n";
	ret << "; Number of exports: " << getNumberOfExports() << "\n";

	if(hasExports())
	{
		unsigned long long aux;
		ret << ";\n";

		for(const auto &exp : exports)
		{
			ret << "; " << std::hex << exp.getName() << " (addr: " << exp.getAddress() << ", ord: " << std::dec << (exp.getOrdinalNumber(aux) ? numToStr(aux, std::dec) : "-") << ")\n";
		}
	}

	dumpTable = ret.str() + "\n";
}

} // namespace fileformat
} // namespace retdec
