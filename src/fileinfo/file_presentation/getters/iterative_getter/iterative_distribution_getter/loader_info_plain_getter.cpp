/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/loader_info_plain_getter.cpp
 * @brief Methods of LoaderInfoPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/loader_info_plain_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const static std::vector<std::size_t> distributionArray = {6, 20, 20, 20};
const static std::vector<std::string> headerArray = {"i", "name", "address", "size"};
const static std::vector<std::string> headerDesc = {"index", "name or symbolic name", "address of loaded segment", "size of loaded segment"};

}

/**
 * Constructor
 * @param fileInfo Information about file
 */
LoaderInfoPlainGetter::LoaderInfoPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfLoadedSegments());
	numberOfExtraElements.push_back(0);
	title = "Loader information";
	distribution.insert(distribution.begin(), std::begin(distributionArray), std::end(distributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(headerArray), std::end(headerArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(headerDesc), std::end(headerDesc));
	loadRecords();
}

/**
 * Destructor
 */
LoaderInfoPlainGetter::~LoaderInfoPlainGetter()
{
}

std::size_t LoaderInfoPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.push_back("Image base address       : ");
	desc.push_back("Number of loaded segments: ");
	info.push_back(fileinfo.getLoadedBaseAddressStr(hexWithPrefix));
	info.push_back(fileinfo.getNumberOfLoadedSegmentsStr(std::dec));
	return info.size();
}

bool LoaderInfoPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	const LoadedSegment &segment = fileinfo.getLoadedSegment(recIndex);
	record.push_back(segment.getIndexStr(std::dec));
	record.push_back(retdec::utils::replaceNonprintableChars(segment.getName()));
	record.push_back(segment.getAddressStr(hexWithPrefix));
	record.push_back(segment.getSizeStr(hexWithPrefix));
	return true;
}

bool LoaderInfoPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	static_cast<void>(structIndex);
	static_cast<void>(desc);
	static_cast<void>(abbv);

	return false;
}

} // namespace fileinfo
