/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/rich_header_plain_getter.cpp
 * @brief Methods of RichHeaderPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/rich_header_plain_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::size_t distributionArray[] = {6, 20, 20, 20, 20};
const std::string headerArray[] = {"i", "product_id", "count", "product_name", "vs_version"};
const std::string headerDesc[] = {"index", "product id", "number of uses", "product name", "vs_version"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
RichHeaderPlainGetter::RichHeaderPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredRecordsInRichHeader());
	numberOfExtraElements.push_back(0);
	title = "Rich header records";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t RichHeaderPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasRichHeaderRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("Number of records: ");
	info.push_back(std::to_string(fileinfo.getNumberOfStoredRecordsInRichHeader()));

	return info.size();
}

bool RichHeaderPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	const auto productId = fileinfo.getRichHeaderRecordProductIdStr(recIndex);
	const auto productBuild = fileinfo.getRichHeaderRecordProductBuildStr(recIndex);
	record.push_back(!productId.empty() && !productBuild.empty() ? productId + "." + productBuild : "");
	record.push_back(fileinfo.getRichHeaderRecordNumberOfUsesStr(recIndex));
	record.push_back(fileinfo.getRichHeaderRecordProductNameStr(recIndex));
	record.push_back(fileinfo.getRichHeaderRecordVisualStudioNameStr(recIndex));

	return true;
}

bool RichHeaderPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
