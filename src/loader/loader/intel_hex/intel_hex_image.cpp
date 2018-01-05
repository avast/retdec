/**
 * @file src/loader/loader/intel_hex/intel_hex_image.cpp
 * @brief Implementation of loadable Intel HEX image class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>
#include <sstream>
#include <vector>

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/intel_hex/intel_hex_image.h"
#include "retdec/loader/utils/range.h"

namespace retdec {
namespace loader {

IntelHexImage::IntelHexImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat)
{
}

IntelHexImage::~IntelHexImage()
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool IntelHexImage::load()
{
	const auto& sections = getFileFormat()->getSections();

	// No sections - nothing to load.
	if (sections.empty())
		return false;

	for (const auto& section : sections)
	{
		unsigned long long virtualSize;
		section->getSizeInMemory(virtualSize);
		std::uint64_t virtualAddress = section->getAddress();

		if (addSegment(section, virtualAddress, virtualSize) == nullptr)
			return false;
	}

	return true;
}

Segment* IntelHexImage::addSegment(const retdec::fileformat::Section* section, std::uint64_t address, std::uint64_t memSize)
{
	llvm::StringRef sectionContent = section->getBytes();
	auto dataSource = std::make_unique<SegmentDataSource>(sectionContent);

	return insertSegment(std::make_unique<Segment>(section, address, memSize, std::move(dataSource)));
}

} // namespace loader
} // namespace retdec
