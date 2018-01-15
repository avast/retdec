/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/relocation_tables_json_getter.cpp
 * @brief Methods of RelocationTablesJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/relocation_tables_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
RelocationTablesJsonGetter::RelocationTablesJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredRelocationTables();

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredRelocationsInTable(i));
		numberOfExtraElements.push_back(0);
	}

	header = "relocationTables";
	title = "relocationTable";
	subtitle = "relocations";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("offset");
	commonHeaderElements.push_back("symbolName");
	commonHeaderElements.push_back("symbolValue");
	commonHeaderElements.push_back("addend");
	commonHeaderElements.push_back("calculatedValue");
}

/**
 * Destructor
 */
RelocationTablesJsonGetter::~RelocationTablesJsonGetter()
{

}

std::size_t RelocationTablesJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("name");
	desc.push_back("numberOfRelocations");
	desc.push_back("associatedSymbolTableIndex");
	desc.push_back("associatedSymbolTableName");
	desc.push_back("indexOfSectionToWhichTheRelocationApplies");
	desc.push_back("nameOfSectionToWhichTheRelocationApplies");
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableName(structIndex)));
	info.push_back(fileinfo.getNumberOfStoredRelocationsInTableStr(structIndex));
	info.push_back(fileinfo.getRelocationTableAssociatedSymbolTableIndex(structIndex));
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableAssociatedSymbolTableName(structIndex)));
	info.push_back(fileinfo.getRelocationTableAppliesSectionIndex(structIndex));
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableAppliesSectionName(structIndex)));

	return info.size();
}

bool RelocationTablesJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(fileinfo.getRelocationTypeStr(structIndex, recIndex));
	record.push_back(fileinfo.getRelocationOffsetStr(structIndex, recIndex, hexWithPrefix));
	record.push_back(replaceNonprintableChars(fileinfo.getRelocationSymbolName(structIndex, recIndex)));
	record.push_back(fileinfo.getRelocationSymbolValueStr(structIndex, recIndex));
	record.push_back(fileinfo.getRelocationAddendStr(structIndex, recIndex));
	record.push_back(fileinfo.getRelocationCalculatedValueStr(structIndex, recIndex));

	return true;
}

bool RelocationTablesJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
