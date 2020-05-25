/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/version_info_string_table_plain_getter.cpp
 * @brief Definition of VersionInfoStringTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/version_info_string_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 40, 40};
const std::string headerArray[] = {"i", "name", "value"};
const std::string headerDesc[] = {"index", "string name", "string value"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
VersionInfoStringTablePlainGetter::VersionInfoStringTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfVersionInfoStrings());
	numberOfExtraElements.push_back(0);
	title = "Version info strings";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t VersionInfoStringTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfVersionInfoStrings())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of strings: ");
	info.push_back(std::to_string(fileinfo.getNumberOfVersionInfoStrings()));

	return info.size();
}

bool VersionInfoStringTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getVersionInfoStringName(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getVersionInfoStringValue(recIndex)));
	return true;
}

bool VersionInfoStringTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
