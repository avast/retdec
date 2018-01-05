/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/symbol_tables_plain_getter.cpp
 * @brief Methods of SymbolTablesPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/symbol_tables_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t distArray[] = {6, 34, 13, 12, 21, 11, 11, 12, 7};
const std::string headerAbbvArray[] = {"i", "name", "type", "bind", "other info", "link", "value", "address", "size"};
const std::string headerDescArray[] = {"index", "name of symbol", "type of symbol", "binding attributes",
										"other information (read file format manual)", "link to associated section",
										"value of symbol", "address of symbol", "size associated with symbol"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
SymbolTablesPlainGetter::SymbolTablesPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredSymbolTables();
	std::vector<std::size_t> dist;
	std::string actAbb;
	std::vector<std::string> abbv, desc;

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSymbolsInTable(i));
		const auto noOfSpecInfo = fileinfo.getSymbolTableNumberOfStoredSpecialInformation(i);
		numberOfExtraElements.push_back(noOfSpecInfo);
		dist.clear();
		abbv.clear();
		desc.clear();
		for(std::size_t j = 0; j < noOfSpecInfo; ++j)
		{
			actAbb = fileinfo.getSymbolTableSpecialInformationAbbreviation(i, j);
			dist.push_back(actAbb.length() + 1);
			abbv.push_back(actAbb);
			desc.push_back(fileinfo.getSymbolTableSpecialInformationDescription(i, j));
		}
		extraDistribution.push_back(dist);
		extraHeaderElements.push_back(abbv);
		extraDesc.push_back(desc);
	}

	title = "Symbol table";
	distribution.insert(distribution.begin(), std::begin(distArray), std::end(distArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerAbbvArray), std::end(headerAbbvArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDescArray), std::end(headerDescArray));
	loadRecords();
}

/**
 * Destructor
 */
SymbolTablesPlainGetter::~SymbolTablesPlainGetter()
{

}

std::size_t SymbolTablesPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Name             : ");
	desc.push_back("Offset in file   : ");
	desc.push_back("Number of symbols: ");
	info.push_back(replaceNonprintableChars(fileinfo.getSymbolTableName(structIndex)));
	info.push_back(fileinfo.getSymbolTableOffsetStr(structIndex, hexWithPrefix));
	info.push_back(fileinfo.getNumberOfDeclaredSymbolsInTableStr(structIndex));

	return info.size();
}

bool SymbolTablesPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
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

bool SymbolTablesPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
