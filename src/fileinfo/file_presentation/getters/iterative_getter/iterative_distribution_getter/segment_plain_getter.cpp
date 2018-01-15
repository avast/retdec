/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/segment_plain_getter.cpp
 * @brief Methods of SegmentPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/format.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/segment_plain_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t segmentDistributionArray[] = {6, 20, 10, 11, 11, 11, 11, 11, 10, 8};
const std::string segmentHeaderArray[] = {"i", "type", "flags", "offset", "fsize", "vaddr", "paddr", "memsize", "align", "crc32"};
const std::string segmentHeaderDesc[] = {"index", "type of segment", "segment flags", "offset in file", "size in file",
										"virtual address in memory", "physical address in memory", "size in memory",
										"alignment in memory and in file", "CRC32 of segment content"};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
SegmentPlainGetter::SegmentPlainGetter(FileInformation &fileInfo) : IterativeDistributionGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredSegments());
	numberOfExtraElements.push_back(0);
	title = "Segment table";
	distribution.insert(distribution.begin(), std::begin(segmentDistributionArray), std::end(segmentDistributionArray));
	commonHeaderElements.insert(commonHeaderElements.begin(), std::begin(segmentHeaderArray), std::end(segmentHeaderArray));
	commonHeaderDesc.insert(commonHeaderDesc.begin(), std::begin(segmentHeaderDesc), std::end(segmentHeaderDesc));
	loadRecords();
}

/**
 * Destructor
 */
SegmentPlainGetter::~SegmentPlainGetter()
{

}

std::size_t SegmentPlainGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	static_cast<void>(structIndex);
	static_cast<void>(desc);
	static_cast<void>(info);

	return 0;
}

bool SegmentPlainGetter::loadRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	std::vector<std::string> desc, abbv;
	fileinfo.getSegmentFlagsDescriptors(recIndex, desc, abbv);
	record.clear();
	record.push_back(fileinfo.getSegmentIndexStr(recIndex));
	record.push_back(fileinfo.getSegmentType(recIndex));
	record.push_back(abbvSerialization(abbv));
	record.push_back(fileinfo.getSegmentOffsetStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentSizeInFileStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentVirtualAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentPhysicalAddressStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentSizeInMemoryStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentAlignmentStr(recIndex, hexWithPrefix));
	record.push_back(fileinfo.getSegmentCrc32(recIndex));

	return true;
}

bool SegmentPlainGetter::getFlagDescriptors(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
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
		fileinfo.getSegmentFlagsDescriptors(i, descTmp, abbvTmp);
		addUniqueValues(desc, descTmp);
		addUniqueValues(abbv, abbvTmp);
	}

	return true;
}

} // namespace fileinfo
