/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/strings_plain_getter.cpp
 * @brief Methods of StringsPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/strings_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 10, 8, 14, 20};
const std::string headerArray[] = {"i", "Offset", "Type", "Section name", "String"};
const std::string headerDesc[] = {"index", "File offset", "Section name of the section where string resides", "Type of the string (ASCII/Wide)", "String content"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
StringsPlainGetter::StringsPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfDetectedStrings());
	numberOfExtraElements.push_back(0);
	title = "Strings";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

/**
 * Destructor
 */
StringsPlainGetter::~StringsPlainGetter()
{

}

std::size_t StringsPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasStrings())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of strings: ");
	info.push_back(numToStr(fileinfo.getNumberOfDetectedStrings()));

	return info.size();
}

bool StringsPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	const auto& strings = fileinfo.getStrings();

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(strings.getStringFileOffsetStr(recIndex, hexWithPrefix));
	record.push_back(strings.getStringTypeStr(recIndex));
	record.push_back(replaceNonprintableChars(strings.getStringSectionName(recIndex)));
	record.push_back(strings.getStringContent(recIndex));

	return true;
}

bool StringsPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
