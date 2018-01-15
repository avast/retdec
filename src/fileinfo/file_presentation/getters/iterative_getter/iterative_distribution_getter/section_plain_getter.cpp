/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/section_plain_getter.cpp
 * @brief Methods of SectionPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/section_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t sectionDistributionArray[] = {5, 17, 14, 8, 11, 7, 11, 12, 11, 11, 11, 11, 11, 11, 11, 12, 11, 9, 8};
const std::string sectionHeaderArray[] = {"i", "name", "type", "flags", "offset", "line", "fsize", "address",
										"memsize", "align", "esize", "relocOff", "relocLine", "relocNum",
										"linesOff", "linesNum", "link", "other", "crc32"};
const std::string sectionHeaderDesc[] = {"index", "name of section", "type of section", "section flags", "offset in file",
										"start line of section", "size in file", "start address in memory", "size in memory",
										"alignment in memory", "size in bytes of each entry in section",
										"offset of relocation entries for section", "start line of relocation entries for section",
										"number of relocation entries for section", "offset of line-number entries for section",
										"number of line-number entries for section", "link to another section",
										"extra information about section (read file format manual)", "CRC32 of section content"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
SectionPlainGetter::SectionPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSections());
	numberOfExtraElements.push_back(0);
	title = "Section table";
	distribution.insert(distribution.begin(), std::begin(sectionDistributionArray), std::end(sectionDistributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(sectionHeaderArray), std::end(sectionHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(sectionHeaderDesc), std::end(sectionHeaderDesc));
	loadRecords();
}

/**
 * Destructor
 */
SectionPlainGetter::~SectionPlainGetter()
{

}

std::size_t SectionPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.getNumberOfStoredSections())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of sections: ");
	desc.push_back("CRC32             : ");
	desc.push_back("MD5               : ");
	desc.push_back("SHA256            : ");
	info.push_back(numToStr(fileinfo.getNumberOfStoredSections()));
	info.push_back(fileinfo.getSectionTableCrc32());
	info.push_back(fileinfo.getSectionTableMd5());
	info.push_back(fileinfo.getSectionTableSha256());

	return info.size();
}

bool SectionPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	std::vector<std::string> desc, abbv;
	fileinfo.getSectionFlagsDescriptors(recIndex, desc, abbv);
	record.clear();
	record.push_back(fileinfo.getSectionIndexStr(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getSectionName(recIndex)));
	record.push_back(fileinfo.getSectionType(recIndex));
	record.push_back(abbvSerialization(abbv));
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

	return true;
}

bool SectionPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	std::vector<std::string> descTmp, abbvTmp;
	desc.clear();
	abbv.clear();

	for(std::size_t i = 0; i < numberOfStoredRecords[structIndex]; ++i)
	{
		fileinfo.getSectionFlagsDescriptors(i, descTmp, abbvTmp);
		addUniqueValues(desc, descTmp);
		addUniqueValues(abbv, abbvTmp);
	}

	return true;
}

} // namespace fileinfo
