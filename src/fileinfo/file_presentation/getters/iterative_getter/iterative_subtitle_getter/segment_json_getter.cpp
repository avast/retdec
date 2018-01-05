/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/segment_json_getter.cpp
 * @brief Methods of SegmentJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/segment_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
SegmentJsonGetter::SegmentJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSegments());
	numberOfExtraElements.push_back(0);
	title = "segmentTable";
	subtitle = "segments";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("type");
	commonHeaderElements.push_back("offset");
	commonHeaderElements.push_back("sizeInFile");
	commonHeaderElements.push_back("virtualAddress");
	commonHeaderElements.push_back("physicalAddress");
	commonHeaderElements.push_back("sizeInMemory");
	commonHeaderElements.push_back("alignmentInMemory");
	commonHeaderElements.push_back("crc32");
	commonHeaderElements.push_back("md5");
	commonHeaderElements.push_back("sha256");
}

/**
 * Destructor
 */
SegmentJsonGetter::~SegmentJsonGetter()
{

}

std::size_t SegmentJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	static_cast<void>(structIndex);
	static_cast<void>(desc);
	static_cast<void>(info);

	return 0;
}

bool SegmentJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(fileinfo.getSegmentIndexStr(recIndex));
	record.push_back(toLower(fileinfo.getSegmentType(recIndex)));
	record.push_back(fileinfo.getSegmentOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentSizeInFileStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentVirtualAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentPhysicalAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentSizeInMemoryStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentAlignmentStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentCrc32(recIndex));
	record.push_back(fileinfo.getSegmentMd5(recIndex));
	record.push_back(fileinfo.getSegmentSha256(recIndex));

	return true;
}

bool SegmentJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue = fileinfo.getSegmentFlagsStr(recIndex);
	std::vector<std::string> optional;
	fileinfo.getSegmentFlagsDescriptors(recIndex, desc, optional);

	return true;
}

} // namespace fileinfo
