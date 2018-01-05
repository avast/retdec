/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/strings_json_getter.cpp
 * @brief Methods of StringsJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "tl-cpputils/conversion.h"
#include "tl-cpputils/string.h"
#include "fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/strings_json_getter.h"

using namespace tl_cpputils;
using namespace fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
StringsJsonGetter::StringsJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfDetectedStrings());
	numberOfExtraElements.push_back(0);
	title = "strings";
	subtitle = "strings";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("fileOffset");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("sectionName");
	commonHeaderElements.push_back("content");
}

/**
 * Destructor
 */
StringsJsonGetter::~StringsJsonGetter()
{

}

std::size_t StringsJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasStrings())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfStrings");
	info.push_back(numToStr(fileinfo.getNumberOfDetectedStrings()));

	return info.size();
}

bool StringsJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	const auto& strings = fileinfo.getStrings();

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(strings.getStringFileOffsetStr(recIndex, hexWithPrefix));
	record.push_back(toLower(strings.getStringTypeStr(recIndex)));
	record.push_back(replaceNonprintableChars(strings.getStringSectionName(recIndex)));
	record.push_back(strings.getStringContent(recIndex));

	return true;
}

bool StringsJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
