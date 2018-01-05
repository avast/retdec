/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/section_json_getter.cpp
 * @brief Methods of SectionJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/section_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
SectionJsonGetter::SectionJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSections());
	numberOfExtraElements.push_back(0);
	title = "sectionTable";
	subtitle = "sections";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("offset");
	commonHeaderElements.push_back("line");
	commonHeaderElements.push_back("sizeInFile");
	commonHeaderElements.push_back("address");
	commonHeaderElements.push_back("sizeInMemory");
	commonHeaderElements.push_back("alignmentInMemory");
	commonHeaderElements.push_back("sizeOfOneEntry");
	commonHeaderElements.push_back("relocationEntriesOffset");
	commonHeaderElements.push_back("relocationEntriesLine");
	commonHeaderElements.push_back("numberOfRelocationEntries");
	commonHeaderElements.push_back("lineNumberEntriesOffset");
	commonHeaderElements.push_back("numberOfLineNumberEntries");
	commonHeaderElements.push_back("linkToAnotherSection");
	commonHeaderElements.push_back("other");
	commonHeaderElements.push_back("crc32");
	commonHeaderElements.push_back("md5");
	commonHeaderElements.push_back("sha256");
}

/**
 * Destructor
 */
SectionJsonGetter::~SectionJsonGetter()
{

}

std::size_t SectionJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredSections())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("numberOfSections");
	desc.push_back("crc32");
	desc.push_back("md5");
	desc.push_back("sha256");
	info.push_back(numToStr(fileinfo.getNumberOfStoredSections()));
	info.push_back(fileinfo.getSectionTableCrc32());
	info.push_back(fileinfo.getSectionTableMd5());
	info.push_back(fileinfo.getSectionTableSha256());

	return info.size();
}

bool SectionJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(fileinfo.getSectionIndexStr(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getSectionName(recIndex)));
	record.push_back(fileinfo.getSectionType(recIndex));
	record.push_back(fileinfo.getSectionOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionLineOffsetStr(recIndex, std::dec));
	record.push_back(fileinfo.getSectionSizeInFileStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionSizeInMemoryStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionMemoryAlignmentStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionEntrySizeStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionRelocationsOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionRelocationsLineOffsetStr(recIndex, std::dec));
	record.push_back(fileinfo.getSectionNumberOfRelocationsStr(recIndex));
	record.push_back(fileinfo.getSectionLineNumbersOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSectionNumberOfLineNumbersStr(recIndex));
	record.push_back(fileinfo.getSectionLinkToOtherSectionStr(recIndex));
	record.push_back(fileinfo.getSectionExtraInfoStr(recIndex));
	record.push_back(fileinfo.getSectionCrc32(recIndex));
	record.push_back(fileinfo.getSectionMd5(recIndex));
	record.push_back(fileinfo.getSectionSha256(recIndex));

	return true;
}

bool SectionJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue = fileinfo.getSectionFlagsStr(recIndex);
	std::vector<std::string> optional;
	fileinfo.getSectionFlagsDescriptors(recIndex, desc, optional);

	return true;
}

} // namespace fileinfo
