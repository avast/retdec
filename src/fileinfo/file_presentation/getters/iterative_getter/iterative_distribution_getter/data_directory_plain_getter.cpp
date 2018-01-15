/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/data_directory_plain_getter.cpp
 * @brief Methods of DataDirectoryPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/data_directory_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t dirDistributionArray[] = {6, 30, 12, 10};
const std::string dirHeaderArray[] = {"i", "type", "address", "size"};
const std::string dirHeaderDesc[] = {"index", "type of directory", "virtual address in memory", "size in bytes"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
DataDirectoryPlainGetter::DataDirectoryPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredDataDirectories());
	numberOfExtraElements.push_back(0);
	title = "Data directories";
	distribution.insert(distribution.begin(), std::begin(dirDistributionArray), std::end(dirDistributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(dirHeaderArray), std::end(dirHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(dirHeaderDesc), std::end(dirHeaderDesc));
	loadRecords();
}

/**
 * Destructor
 */
DataDirectoryPlainGetter::~DataDirectoryPlainGetter()
{

}

std::size_t DataDirectoryPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredDataDirectories())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of data directories: ");
	info.push_back(numToStr(fileinfo.getNumberOfStoredDataDirectories()));

	return info.size();
}

bool DataDirectoryPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(fileinfo.getDataDirectoryType(recIndex));
	record.push_back(fileinfo.getDataDirectoryAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getDataDirectorySizeStr(recIndex, hexWithPrefix));

	return true;
}

bool DataDirectoryPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
