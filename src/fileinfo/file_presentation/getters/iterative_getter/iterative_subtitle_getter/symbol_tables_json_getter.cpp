/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/symbol_tables_json_getter.cpp
 * @brief Methods of SymbolTablesJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/symbol_tables_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
SymbolTablesJsonGetter::SymbolTablesJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredSymbolTables();

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSymbolsInTable(i));
		const auto noOfSpecInfo = fileinfo.getSymbolTableNumberOfStoredSpecialInformation(i);
		numberOfExtraElements.push_back(noOfSpecInfo);
		std::vector<std::string> abbv;
		for(std::size_t j = 0; j < noOfSpecInfo; ++j)
		{
			abbv.push_back(fileinfo.getSymbolTableSpecialInformationAbbreviation(i, j));
		}
		extraHeaderElements.push_back(abbv);
	}

	header = "symbolTables";
	title = "symbolTable";
	subtitle = "symbols";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("bind");
	commonHeaderElements.push_back("other");
	commonHeaderElements.push_back("associatedSectionIndex");
	commonHeaderElements.push_back("value");
	commonHeaderElements.push_back("address");
	commonHeaderElements.push_back("associatedSize");
}

/**
 * Destructor
 */
SymbolTablesJsonGetter::~SymbolTablesJsonGetter()
{

}

std::size_t SymbolTablesJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("name");
	desc.push_back("offset");
	desc.push_back("numberOfSymbols");
	info.push_back(replaceNonprintableChars(fileinfo.getSymbolTableName(structIndex)));
	info.push_back(fileinfo.getSymbolTableOffsetStr(structIndex, hexWithPrefix));
	info.push_back(fileinfo.getNumberOfDeclaredSymbolsInTableStr(structIndex));

	return info.size();
}

bool SymbolTablesJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(fileinfo.getSymbolIndexStr(structIndex, recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getSymbolName(structIndex, recIndex)));
	record.push_back(fileinfo.getSymbolType(structIndex, recIndex));
	record.push_back(fileinfo.getSymbolBind(structIndex, recIndex));
	record.push_back(fileinfo.getSymbolOther(structIndex, recIndex));
	record.push_back(fileinfo.getSymbolLinkToSection(structIndex, recIndex));
	record.push_back(fileinfo.getSymbolValueStr(structIndex, recIndex));
	record.push_back(fileinfo.getSymbolAddressStr(structIndex, recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSymbolSizeStr(structIndex, recIndex));

	for(std::size_t i = 0, e = numberOfExtraElements[structIndex]; i < e; ++i)
	{
		record.push_back(fileinfo.getSymbolTableSpecialInformationValue(structIndex, i, recIndex));
	}

	return true;
}

bool SymbolTablesJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
