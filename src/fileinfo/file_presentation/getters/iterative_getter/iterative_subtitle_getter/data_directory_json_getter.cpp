/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/data_directory_json_getter.cpp
 * @brief Methods of DataDirectoryJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/data_directory_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
DataDirectoryJsonGetter::DataDirectoryJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredDataDirectories());
	numberOfExtraElements.push_back(0);
	title = "dataDirectories";
	subtitle = "dataDirectoryEntries";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("address");
	commonHeaderElements.push_back("size");
}

/**
 * Destructor
 */
DataDirectoryJsonGetter::~DataDirectoryJsonGetter()
{

}

std::size_t DataDirectoryJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredDataDirectories())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfDataDirectories");
	info.push_back(numToStr(fileinfo.getNumberOfStoredDataDirectories()));

	return info.size();
}

bool DataDirectoryJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
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

bool DataDirectoryJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue.clear();
	desc.clear();

	return true;
}

} // namespace fileinfo
