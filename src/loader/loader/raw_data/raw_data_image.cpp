/**
 * @file src/loader/loader/raw_data/raw_data_image.cpp
 * @brief Implementation of loadable raw data image class for testing.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/raw_data/raw_data_image.h"

namespace retdec {
namespace loader {

RawDataImage::RawDataImage(const std::shared_ptr<retdec::fileformat::FileFormat>& fileFormat) : Image(fileFormat)
{
}

RawDataImage::~RawDataImage()
{
}

/**
 * Virtual method overridden from retdec::loader::Image, which is used in image factory.
 * Loads the image using @c fileformat.
 *
 * @return True if loading was successful, otherwise false.
 */
bool RawDataImage::load()
{
	const auto& sections = getFileFormat()->getSections();

	// No sections - nothing to load.
	if (sections.empty())
		return false;

	const auto* section = sections[0];

	llvm::StringRef sectionContent = section->getBytes();
	auto dataSource = std::make_unique<SegmentDataSource>(sectionContent);

	unsigned long long memSize;
	section->getSizeInMemory(memSize);

	insertSegment(std::make_unique<Segment>(section, section->getAddress(), memSize, std::move(dataSource)));

	return true;
}

/**
 * Reload segment after configuration change.
 * @return True if reloading was successful, otherwise false.
 */
bool RawDataImage::reload()
{
	removeSegment(getSegment(0));
	return this->load();
}

} // namespace loader
} // namespace retdec
