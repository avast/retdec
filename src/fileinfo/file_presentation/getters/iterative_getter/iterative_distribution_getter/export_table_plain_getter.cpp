/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/export_table_plain_getter.cpp
 * @brief Methods of ExportTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/export_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 40, 11, 11};
const std::string headerArray[] = {"i", "name", "ordNum", "address"};
const std::string headerDesc[] = {"index", "name of export", "ordinal number of export", "address of export"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ExportTablePlainGetter::ExportTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredExports());
	numberOfExtraElements.push_back(0);
	title = "Export table";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

/**
 * Destructor
 */
ExportTablePlainGetter::~ExportTablePlainGetter()
{

}

std::size_t ExportTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasExportTableRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of exports: ");
	desc.push_back("CRC32            : ");
	desc.push_back("MD5              : ");
	desc.push_back("SHA256           : ");
	info.push_back(numToStr(fileinfo.getNumberOfStoredExports()));
	info.push_back(fileinfo.getExphashCrc32());
	info.push_back(fileinfo.getExphashMd5());
	info.push_back(fileinfo.getExphashSha256());

	return info.size();
}

bool ExportTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getExportName(recIndex)));
	record.push_back(fileinfo.getExportOrdinalNumberStr(recIndex, std::dec));
	record.push_back(fileinfo.getExportAddressStr(recIndex, hexWithPrefix));
	return true;
}

bool ExportTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
