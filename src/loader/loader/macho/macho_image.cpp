/**
 * @file src/loader/loader/macho/macho_image.cpp
 * @brief Implementation  of loadable Mach-O image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/sec_seg/macho_section.h"
#include "retdec/loader/loader/macho/macho_image.h"

namespace retdec {
namespace loader {

MachOImage::MachOImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat)
{
}

MachOImage::~MachOImage()
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool MachOImage::load()
{
	// No segments to load.
	if (getFileFormat()->getSegments().empty())
		return false;

	bool ret = false;
	if (getFileFormat()->isObjectFile())
		ret = loadObjectFile();
	else
		ret = loadExecutableFile();

	if (!ret)
		return false;

	return true;
}

bool MachOImage::loadObjectFile()
{
	// Object file usually just contain one segment with multiple sections that
	//   would belong to different segments according to their segment name.
	//   We just need to load sections and completely ignore segments.
	auto sections = getFileFormat()->getSections();
	if (sections.empty())
		return false;

	for (const auto& sec : sections)
	{
		if (addSegment(sec) == nullptr)
			return false;
	}

	return true;
}

bool MachOImage::loadExecutableFile()
{
	// Find mapping of sections to segments.
	SegmentToSectionsTable segToSecTable = mapSegmentsToSections();
	auto segments = getFileFormat()->getSegments();

	for (const auto& seg : segments)
	{
		// Skip __PAGEZERO segment, it does not contain anything and Mach-O loader in Mac OS X ignores it too.
		// Regular loader also identifies this segment by its name, there is no other way.
		if (seg->getName() == "__PAGEZERO")
			continue;

		// Find mapped sections.
		SectionList sections = segToSecTable[seg->getName()];

		// If there are any sections in this segment.
		if (!sections.empty())
		{
			for (const auto& sec : sections)
			{
				if (addSegment(sec) == nullptr)
					return false;
			}
		}
		else
		{
			if (addSegment(seg) == nullptr)
				return false;
		}
	}

	return true;
}

MachOImage::SegmentToSectionsTable MachOImage::mapSegmentsToSections() const
{
	SegmentToSectionsTable segToSecTable;

	// First, iterate over all segments and insert them into the table as keys with empty values.
	// This way, we don't have to iterate over sections multiple times.
	auto segments = getFileFormat()->getSegments();
	for (const auto& seg : segments)
		segToSecTable.insert({seg->getName(), {}});

	// Now, try to find the segments the section falls into.
	auto sections = getFileFormat()->getSections();
	for (const auto& sec : sections)
	{
		auto machoSec = static_cast<const retdec::fileformat::MachOSection*>(sec);

		// Every section should have its segment set, but skip the section if not.
		SegmentToSectionsTable::iterator itr = segToSecTable.find(machoSec->getSegmentName());
		if (itr == segToSecTable.end())
			continue;

		// Add section to this segment.
		itr->second.push_back(machoSec);
	}

	return segToSecTable;
}

const Segment* MachOImage::addSegment(const retdec::fileformat::SecSeg* secSeg)
{
	std::unique_ptr<SegmentDataSource> dataSource;
	if (!secSeg->isBss())
	{
		llvm::StringRef secSegContent = secSeg->getBytes();
		dataSource.reset(new SegmentDataSource(secSegContent));
	}

	unsigned long long size;
	secSeg->getSizeInMemory(size);
	std::uint64_t address = secSeg->getAddress();

	return insertSegment(std::make_unique<Segment>(secSeg, address, size, std::move(dataSource)));
}

} // namespace loader
} // namespace retdec
