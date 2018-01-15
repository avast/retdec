/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/loader_info_json_getter.cpp
 * @brief Definition of LoaderInfoJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/other.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/loader_info_json_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
LoaderInfoJsonGetter::LoaderInfoJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfLoadedSegments());
	numberOfExtraElements.push_back(0);
	title = "segments";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("name");
	commonHeaderElements.push_back("address");
	commonHeaderElements.push_back("size");
}

/**
 * Destructor
 */
LoaderInfoJsonGetter::~LoaderInfoJsonGetter()
{

}

std::size_t LoaderInfoJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	return info.size();
}

bool LoaderInfoJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
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

bool LoaderInfoJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
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
