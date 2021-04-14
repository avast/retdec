/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/import_table_plain_getter.cpp
 * @brief Methods of ImportTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/import_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 50, 12, 11, 13, 8, 20};
const std::string headerArray[] = {"i", "name", "type", "ordNum", "address", "delayed", "libName"};
const std::string headerDesc[] = {"index", "name of import", "type of symbol", "ordinal number of import",
									"address of import", "delayed import (only PE)", "name of library from which is import imported", };
} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ImportTablePlainGetter::ImportTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredImports());
	numberOfExtraElements.push_back(0);
	title = "Import table";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t ImportTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasImportTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of imports: ");
	desc.push_back("CRC32            : ");
	desc.push_back("MD5              : ");
	desc.push_back("SHA256           : ");
	desc.push_back("TLSH             : ");
	info.push_back(std::to_string(fileinfo.getNumberOfStoredImports()));
	info.push_back(fileinfo.getImphashCrc32());
	info.push_back(fileinfo.getImphashMd5());
	info.push_back(fileinfo.getImphashSha256());
	info.push_back(fileinfo.getImphashTlsh());

	return info.size();
}

bool ImportTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getImportName(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getImportUsageType(recIndex)));
	record.push_back(fileinfo.getImportOrdinalNumberStr(recIndex, std::dec));
	record.push_back(fileinfo.getImportAddressStr(recIndex, hexWithPrefix));
	if (fileinfo.getFileFormatEnum() == Format::PE)
		record.push_back(static_cast<const PeImport*>(fileinfo.getImport(recIndex))->isDelayed() ? "Yes" : "No");
	else
		record.push_back(std::string{});
	record.push_back(replaceNonprintableChars(fileinfo.getImportLibraryName(recIndex)));
	return true;
}

bool ImportTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	desc.clear();
	abbv.clear();

	return true;
}

} // namespace fileinfo
} // namespace retdec
