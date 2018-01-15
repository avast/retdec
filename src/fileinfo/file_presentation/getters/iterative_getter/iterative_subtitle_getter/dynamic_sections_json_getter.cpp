/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/dynamic_sections_json_getter.cpp
 * @brief Methods of DynamicSectionsJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/dynamic_sections_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
DynamicSectionsJsonGetter::DynamicSectionsJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredDynamicSections();

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredDynamicEntriesInSection(i));
		numberOfExtraElements.push_back(0);
	}

	header = "dynamicSections";
	title = "dynamicSection";
	subtitle = "dynamicSectionEntries";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("value");
	commonHeaderElements.push_back("description");
}

/**
 * Destructor
 */
DynamicSectionsJsonGetter::~DynamicSectionsJsonGetter()
{

}

std::size_t DynamicSectionsJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("name");
	desc.push_back("numberOfEntries");
	info.push_back(replaceNonprintableChars(fileinfo.getDynamicSectionName(structIndex)));
	info.push_back(fileinfo.getNumberOfDeclaredDynamicEntriesInSectionStr(structIndex));

	return info.size();
}

bool DynamicSectionsJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(toLower(fileinfo.getDynamicEntryType(structIndex, recIndex)));
	record.push_back(fileinfo.getDynamicEntryValueStr(structIndex, recIndex, hexWithPrefix));
	record.push_back(fileinfo.getDynamicEntryDescription(structIndex, recIndex));

	return true;
}

bool DynamicSectionsJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue = fileinfo.getDynamicEntryFlagsStr(structIndex, recIndex);
	std::vector<std::string> optional;
	fileinfo.getDynamicEntryFlagsDescriptors(structIndex, recIndex, desc, optional);

	return true;
}

} // namespace fileinfo
