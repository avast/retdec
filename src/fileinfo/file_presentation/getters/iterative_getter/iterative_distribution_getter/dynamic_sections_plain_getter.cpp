/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/dynamic_sections_plain_getter.cpp
 * @brief Methods of DynamicSectionsPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/dynamic_sections_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t dynDistArray[] = {6, 69, 5, 11, 29};
const std::string dynHeaderArray[] = {"i", "type", "flg", "value", "description"};
const std::string dynHeaderDesc[] = {"index", "type of dynamic entry", "flags of dynamic entry", "value of dynamic entry", "additional description"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
DynamicSectionsPlainGetter::DynamicSectionsPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = fileinfo.getNumberOfStoredDynamicSections();

	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredDynamicEntriesInSection(i));
		numberOfExtraElements.push_back(0);
	}

	title = "Dynamic section";
	distribution.insert(distribution.begin(), std::begin(dynDistArray), std::end(dynDistArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(dynHeaderArray), std::end(dynHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(dynHeaderDesc), std::end(dynHeaderDesc));
	loadRecords();
}

/**
 * Destructor
 */
DynamicSectionsPlainGetter::~DynamicSectionsPlainGetter()
{

}

std::size_t DynamicSectionsPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Name             : ");
	desc.push_back("Number of entries: ");
	info.push_back(replaceNonprintableChars(fileinfo.getDynamicSectionName(structIndex)));
	info.push_back(fileinfo.getNumberOfDeclaredDynamicEntriesInSectionStr(structIndex));

	return info.size();
}

bool DynamicSectionsPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	std::vector<std::string> desc, abbv;
	fileinfo.getDynamicEntryFlagsDescriptors(structIndex, recIndex, desc, abbv);
	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(fileinfo.getDynamicEntryType(structIndex, recIndex));
	record.push_back(abbvSerialization(abbv));
	record.push_back(fileinfo.getDynamicEntryValueStr(structIndex, recIndex, hexWithPrefix));
	record.push_back(fileinfo.getDynamicEntryDescription(structIndex, recIndex));

	return true;
}

bool DynamicSectionsPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
		fileinfo.getDynamicEntryFlagsDescriptors(structIndex, i, descTmp, abbvTmp);
		addUniqueValues(desc, descTmp);
		addUniqueValues(abbv, abbvTmp);
	}

	return true;
}

} // namespace fileinfo
