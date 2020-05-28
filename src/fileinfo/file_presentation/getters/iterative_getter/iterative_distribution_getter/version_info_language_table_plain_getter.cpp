/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/version_info_language_table_plain_getter.cpp
 * @brief Definition of VersionInfoLanguageTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/version_info_language_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 40, 40};
const std::string headerArray[] = {"i", "lcid", "codePage"};
const std::string headerDesc[] = {"index", "microsoft language identifier", "IBM code page"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
VersionInfoLanguageTablePlainGetter::VersionInfoLanguageTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfVersionInfoLanguages());
	numberOfExtraElements.push_back(0);
	title = "Version info languages";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t VersionInfoLanguageTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfVersionInfoLanguages())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of languages: ");
	info.push_back(std::to_string(fileinfo.getNumberOfVersionInfoLanguages()));

	return info.size();
}

bool VersionInfoLanguageTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(fileinfo.getVersionInfoLanguageLcid(recIndex));
	record.push_back(fileinfo.getVersionInfoLanguageCodePage(recIndex));
	return true;
}

bool VersionInfoLanguageTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
