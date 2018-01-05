/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/resource_plain_getter.cpp
 * @brief Methods of ResourcePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/resource_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 21, 9, 21, 9, 14, 9, 9, 11, 11, 8};
const std::string headerArray[] = {"i", "name", "nameId", "type", "typeId", "language", "lanId", "slanId", "offset", "size", "crc32"};
const std::string headerDesc[] = {"index", "name of resource", "resource name ID", "type of resource", "resource type ID",
									"language of resource", "resource language ID", "resource sublanguage ID",
									"offset in file", "size in file", "CRC32 of resource content"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ResourcePlainGetter::ResourcePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredResources());
	numberOfExtraElements.push_back(0);
	title = "Resource table";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

/**
 * Destructor
 */
ResourcePlainGetter::~ResourcePlainGetter()
{

}

std::size_t ResourcePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredResources())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of resources: ");
	info.push_back(numToStr(fileinfo.getNumberOfStoredResources()));

	return info.size();
}

bool ResourcePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	auto name = fileinfo.getResourceName(recIndex);
	shrinkAndReplaceNonprintable(name, MAX_NAME_LENGTH);
	const auto nameId = fileinfo.getResourceNameIdStr(recIndex, std::dec);
	if(name.empty() && nameId.empty())
	{
		name = "(none)";
	}
	record.push_back(name);
	record.push_back(nameId);
	auto type = replaceNonprintableChars(fileinfo.getResourceType(recIndex));
	const auto typeId = fileinfo.getResourceTypeIdStr(recIndex, std::dec);
	if(type.empty() && typeId.empty())
	{
		type = "(none)";
	}
	record.push_back(type);
	record.push_back(typeId);
	auto language = replaceNonprintableChars(fileinfo.getResourceLanguage(recIndex));
	const auto languageId = fileinfo.getResourceLanguageIdStr(recIndex, std::dec);
	const auto sublanguageId = fileinfo.getResourceSublanguageIdStr(recIndex, std::dec);
	if(language.empty() && languageId.empty() && sublanguageId.empty())
	{
		language = "(none)";
	}
	record.push_back(language);
	record.push_back(languageId);
	record.push_back(sublanguageId);
	record.push_back(fileinfo.getResourceOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getResourceSizeStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getResourceCrc32(recIndex));

	return true;
}

bool ResourcePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
