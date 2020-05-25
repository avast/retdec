/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/loader_info_plain_getter.cpp
 * @brief Methods of MissingDepsPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/utils/conversion.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/missing_deps_plain_getter.h"

using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const static std::vector<std::size_t> distributionArray = {6, 20};
const static std::vector<std::string> headerArray = {"i", "name"};
const static std::vector<std::string> headerDesc = {"index", "missing dependency"};

}

/**
 * Constructor
 * @param fileInfo Information about file
 */
MissingDepsPlainGetter::MissingDepsPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfMissingDeps());
	numberOfExtraElements.push_back(0);
	title = "Missing dependencies";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

std::size_t MissingDepsPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.push_back("Number of missing dependencies: ");
	info.push_back(std::to_string(fileinfo.getNumberOfMissingDeps()));
	return info.size();
}

bool MissingDepsPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	record.push_back(retdec::utils::replaceNonprintableChars(fileinfo.getMissingDepName(recIndex)));
	return true;
}

bool MissingDepsPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	static_cast<void>(structIndex);
	static_cast<void>(desc);
	static_cast<void>(abbv);

	return false;
}

} // namespace fileinfo
} // namespace retdec
