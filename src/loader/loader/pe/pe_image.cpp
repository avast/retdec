/**
 * @file src/loader/loader/pe/pe_image.cpp
 * @brief Implementation  of loadable PE image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

#include "retdec/utils/file_io.h"
#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/pe/pe_image.h"
#include "retdec/loader/utils/overlap_resolver.h"

using namespace retdec::utils;

namespace retdec {
namespace loader {

PeImage::PeImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat), _singleSegment(nullptr)
{
}

PeImage::~PeImage()
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool PeImage::load()
{
	const retdec::fileformat::PeFormat* peFormat = static_cast<const retdec::fileformat::PeFormat*>(getFileFormat());

	// Load image base address from fileformat and store it into loader image
	unsigned long long imageBase;
	peFormat->getImageBaseAddress(imageBase);
	setBaseAddress(imageBase);

	const auto& sections = peFormat->getSections();
	for (const auto& section : sections)
	{
		unsigned long long virtualSize;
		section->getSizeInMemory(virtualSize);
		std::uint64_t virtualAddress = section->getAddress();
		std::uint64_t rawSize = section->getLoadedSize();

		// If VirtualSize is 0, then use SizeOfRawData as virtual size
		if (virtualSize == 0)
			virtualSize = rawSize;

		// If SizeOfRawData is greater than VirtualSize, only VirtualSize is used
		if (rawSize > virtualSize)
			rawSize = virtualSize;

		if (addSegment(section, virtualAddress, virtualSize) == nullptr)
			return false;
	}

	// If no sections found, map the whole file into one big segment.
	if (sections.empty())
	{
		std::vector<std::uint8_t> bytes;
		if (!readFile(peFormat->getPathToFile(), bytes))
			return false;

		if (addSingleSegment(imageBase, bytes) == nullptr)
			return false;
	}

	// Sort segments by their address
	sortSegments();

	loadNonDecodableAddressRanges();

	return true;
}

Segment* PeImage::addSegment(const retdec::fileformat::Section* section, std::uint64_t address, std::uint64_t memSize)
{
	if (!canAddSegment(address, memSize))
		return nullptr;

	std::unique_ptr<SegmentDataSource> dataSource;
	// Do not load BSS sections from file
	if (!section->isBss())
	{
		llvm::StringRef sectionContent = section->getBytes();
		dataSource.reset(new SegmentDataSource(sectionContent));
	}

	return insertSegment(std::make_unique<Segment>(section, address, memSize, std::move(dataSource)));
}

Segment* PeImage::addSingleSegment(std::uint64_t address, std::vector<std::uint8_t>& content)
{
	// This is used in case when PE file has no sections. It this case, PE loader loads the whole file into the memory as one segment
	//    at the address of ImageBase.
	// We need to store pointer to dynamically allocated vector, because we use llvm::StringRef everywhere and it requires the memory it point to
	//    to be available anytime during the runtime.
	_singleSegment = std::make_unique<std::vector<std::uint8_t>>(std::move(content));

	auto dataRef = llvm::StringRef(reinterpret_cast<const char*>(_singleSegment->data()), _singleSegment->size());
	auto dataSource = std::make_unique<SegmentDataSource>(dataRef);

	return insertSegment(std::make_unique<Segment>(nullptr, address, dataRef.size(), std::move(dataSource)));
}

bool PeImage::canAddSegment(std::uint64_t address, std::uint64_t memSize) const
{
	retdec::utils::Range<std::uint64_t> newSegRange(address, memSize ? address + memSize : address + 1);
	for (const auto& seg : getSegments())
	{
		auto overlapResult = OverlapResolver::resolve(retdec::utils::Range<std::uint64_t>(seg->getAddress(), seg->getEndAddress()), newSegRange);
		if (overlapResult.getOverlap() != Overlap::None)
			return false;
	}

	return true;
}

void PeImage::loadNonDecodableAddressRanges()
{
	auto ranges = getFileFormat()->getNonDecodableAddressRanges();
	for (const auto& range : ranges)
	{
		Range<uint64_t> rebasedRange(
				getBaseAddress() + range.getStart(),
				getBaseAddress() + range.getEnd());

		for (auto& seg : getSegments())
		{
			seg->addNonDecodableRange(rebasedRange);
		}
	}
}

} // namespace loader
} // namespace retdec
