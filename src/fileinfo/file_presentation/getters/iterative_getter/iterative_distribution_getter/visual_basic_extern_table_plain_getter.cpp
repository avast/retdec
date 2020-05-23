/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/visual_basic_extern_table_plain_getter.cpp
 * @brief Definition of VisualBasicExternTablePlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/visual_basic_extern_table_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 40, 40};
const std::string headerArray[] = {"i", "apiName", "moduleName"};
const std::string headerDesc[] = {"index", "api name of extern", "module name of extern"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
VisualBasicExternTablePlainGetter::VisualBasicExternTablePlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getVisualBasicNumberOfExterns());
	numberOfExtraElements.push_back(0);
	title = "Visual basic extern table";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t VisualBasicExternTablePlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.isVisualBasicUsed()
		|| !fileinfo.getVisualBasicNumberOfExterns())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of externs: ");
	desc.push_back("CRC32            : ");
	desc.push_back("MD5              : ");
	desc.push_back("SHA256           : ");
	info.push_back(std::to_string(fileinfo.getVisualBasicNumberOfExterns()));
	info.push_back(fileinfo.getVisualBasicExternTableHashCrc32());
	info.push_back(fileinfo.getVisualBasicExternTableHashMd5());
	info.push_back(fileinfo.getVisualBasicExternTableHashSha256());

	return info.size();
}

bool VisualBasicExternTablePlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(replaceNonprintableChars(fileinfo.getVisualBasicExternApiName(recIndex)));
	record.push_back(replaceNonprintableChars(fileinfo.getVisualBasicExternModuleName(recIndex)));
	return true;
}

bool VisualBasicExternTablePlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
} // namespace retdec
