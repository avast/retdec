/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/relocation_tables_plain_getter.cpp
 * @brief Methods of RelocationTablesPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/relocation_tables_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t relDistArray[] = {6, 10, 15, 50, 10, 10, 10};
const std::string relHeaderArray[] = {"i", "type", "offset", "symbol name", "symValue", "addend", "calcValue"};
const std::string relHeaderDesc[] = {"index", "type of relocation", "offset of relocation", "name of associated symbol",
									"value of associated symbol", "relocation addend", "calculated value of relocation"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
RelocationTablesPlainGetter::RelocationTablesPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredRelocationTables();

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredRelocationsInTable(i));
		numberOfExtraElements.push_back(0);
	}

	title = "Relocation table";
	distribution.insert(distribution.begin(), std::begin(relDistArray), std::end(relDistArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(relHeaderArray), std::end(relHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(relHeaderDesc), std::end(relHeaderDesc));
	loadRecords();
}

/**
 * Destructor
 */
RelocationTablesPlainGetter::~RelocationTablesPlainGetter()
{

}

std::size_t RelocationTablesPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Name                                            : ");
	desc.push_back("Number of relocations                           : ");
	desc.push_back("Associated symbol table index                   : ");
	desc.push_back("Associated symbol table name                    : ");
	desc.push_back("Index of section to which the relocation applies: ");
	desc.push_back("Name of section to which the relocation applies : ");
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableName(structIndex)));
	info.push_back(fileinfo.getNumberOfStoredRelocationsInTableStr(structIndex));
	info.push_back(fileinfo.getRelocationTableAssociatedSymbolTableIndex(structIndex));
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableAssociatedSymbolTableName(structIndex)));
	info.push_back(fileinfo.getRelocationTableAppliesSectionIndex(structIndex));
	info.push_back(replaceNonprintableChars(fileinfo.getRelocationTableAppliesSectionName(structIndex)));

	return info.size();
}

bool RelocationTablesPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
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

bool RelocationTablesPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
