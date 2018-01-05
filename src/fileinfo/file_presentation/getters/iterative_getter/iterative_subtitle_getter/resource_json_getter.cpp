/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/resource_json_getter.cpp
 * @brief Methods of ResourceJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/resource_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
ResourceJsonGetter::ResourceJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredResources());
	numberOfExtraElements.push_back(0);
	title = "resourceTable";
	subtitle = "resources";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
	commonHeaderElements.push_back("nameId");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("typeId");
	commonHeaderElements.push_back("language");
	commonHeaderElements.push_back("languageId");
	commonHeaderElements.push_back("sublanguageId");
	commonHeaderElements.push_back("offset");
	commonHeaderElements.push_back("size");
	commonHeaderElements.push_back("crc32");
	commonHeaderElements.push_back("md5");
	commonHeaderElements.push_back("sha256");
}

/**
 * Destructor
 */
ResourceJsonGetter::~ResourceJsonGetter()
{

}

std::size_t ResourceJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredResources())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfResources");
	info.push_back(numToStr(fileinfo.getNumberOfStoredResources()));

	return info.size();
}

bool ResourceJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
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
	record.push_back(fileinfo.getResourceMd5(recIndex));
	record.push_back(fileinfo.getResourceSha256(recIndex));

	return true;
}

bool ResourceJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
